#!/usr/bin/env python3
"""
Realtime WAF Flag Leak Monitor
Connects to BunkerWeb Trafficlog API (or tails Docker traffic.log) and alerts
immediately via WebUI (SSE) whenever a response contains FHACKER2026{<64hex>}.
"""

from __future__ import annotations

import argparse
import base64
import functools
import gzip
import json
import os
import queue
import re
import secrets
import shlex
import subprocess
import threading
import time
import urllib.parse
import zlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import requests
from flask import Flask, Response, jsonify, redirect, render_template, request, render_template_string, session, url_for
from requests.adapters import HTTPAdapter

from rule_engine import generate_waf_rules, validate_rules_text
from exploit_engine import generate_exploit_script

DEFAULT_WAF_URL = os.environ.get("WAF_URL", "http://localhost:9110")
DEFAULT_WAF_USER = os.environ.get("WAF_USER", "admin")
DEFAULT_WAF_PASS = os.environ.get("WAF_PASS", "ChangeMe_Bw_2026!")
DEFAULT_PATTERN = os.environ.get("FLAG_PATTERN", r"FHACKER2026\{[0-9a-fA-F]{64}\}")
DEFAULT_DOCKER_CONTAINER = os.environ.get("WAF_CONTAINER", "b_notevault-fuap_bunkerweb-1")

app = Flask(__name__)


def _decompress_bytes(raw: bytes, content_encoding: str = "") -> bytes:
    """Decompress gzip or deflate bytes if compressed (handles truncated streams)."""
    enc = content_encoding.lower()
    if "gzip" in enc or raw.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(raw)
        except Exception:
            try:
                dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                return dec.decompress(raw)
            except Exception:
                return raw
    if "deflate" in enc:
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(raw, wbits)
            except Exception:
                pass
    return raw


def decode_body(body: Any, encoding: str | None, headers: list[list[str]] | None) -> str:
    """Decode request/response body from BunkerWeb trafficlog record."""
    if body is None or body == "":
        return ""
    if not isinstance(body, str):
        return json.dumps(body, ensure_ascii=False, indent=2)

    content_encoding = ""
    if headers:
        for pair in headers:
            if len(pair) >= 2 and str(pair[0]).lower() == "content-encoding":
                content_encoding = str(pair[1])
                break

    if encoding == "base64":
        try:
            raw = base64.b64decode(body)
            raw = _decompress_bytes(raw, content_encoding)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return body
    return body


def format_headers(headers: list[list[str]] | None) -> str:
    if not headers:
        return ""
    return "\n".join(f"{pair[0]}: {pair[1]}" for pair in headers if len(pair) >= 2)


def build_curl(record: dict[str, Any], req_body: str) -> str:
    """Build a reproducible curl command from a trafficlog record."""
    method = record.get("method", "GET")
    host = record.get("host", "localhost")
    uri = record.get("uri", "/")
    req_headers = record.get("request_headers") or []

    scheme = "http"
    host_hdr = host
    parts = [f"curl -i -sS -X {shlex.quote(method)}"]
    for pair in req_headers:
        if len(pair) < 2:
            continue
        k, v = str(pair[0]), str(pair[1])
        kl = k.lower()
        if kl in ("content-length", "connection"):
            continue
        if kl == "host":
            host_hdr = v
            continue
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if req_body:
        parts.append(f"--data-raw {shlex.quote(req_body)}")
    url = f"{scheme}://{host_hdr}{uri}"
    parts.append(shlex.quote(url))
    return " \\\n  ".join(parts)


STATIC_EXTS = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
)
SKIP_STATUSES = {400, 403, 405, 413, 414, 429, 431, 304}
SKIP_CT_PREFIXES = ("image/", "font/", "text/css", "audio/", "video/")


def should_skip_summary(item: dict[str, Any]) -> bool:
    """Fast pre-filter on /trafficlog/api/history summary items before fetching detail."""
    status = item.get("status")
    if status in SKIP_STATUSES:
        return True
    ct = str(item.get("response_content_type") or "").lower().split(";")[0].strip()
    if ct.startswith(SKIP_CT_PREFIXES):
        return True
    uri_path = str(item.get("uri") or "").split("?", 1)[0].lower()
    if uri_path.endswith(STATIC_EXTS) and status in (200, 304, 404):
        return True
    return False


class RangeUnsupportedError(RuntimeError):
    """Raised when the WAF UI does not support HTTP Range log tailing."""


RANGE_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB max per Range request


class BunkerWebClient:
    """Authenticated HTTP client for BunkerWeb UI /trafficlog/api/history."""

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._lock = threading.Lock()
        self.session = self._make_session()
        self._logged_in = False

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = self.verify_ssl
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def login(self) -> None:
        with self._lock:
            self.session = self._make_session()
            r = self.session.get(f"{self.base_url}/login", timeout=self.timeout)
            r.raise_for_status()
            m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text)
            if not m:
                raise RuntimeError("Could not find csrf_token on /login page")
            payload = {
                "csrf_token": m.group(1),
                "username": self.username,
                "password": self.password,
            }
            r2 = self.session.post(
                f"{self.base_url}/login",
                data=payload,
                allow_redirects=True,
                timeout=self.timeout,
            )
            r2.raise_for_status()
            if "/login" in r2.url and "csrf_token" in r2.text:
                raise RuntimeError("Login failed: invalid username or password")
            self._logged_in = True

    def _ensure_login(self) -> None:
        if not self._logged_in:
            self.login()

    def _get_json(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        self._ensure_login()
        url = f"{self.base_url}{path}"
        for attempt in range(2):
            r = self.session.get(
                url,
                params=params,
                headers={"Accept": "application/json"},
                allow_redirects=False,
                timeout=self.timeout,
            )
            if r.status_code in (301, 302, 303, 401, 403) or "application/json" not in r.headers.get("Content-Type", ""):
                if attempt == 0:
                    self.login()
                    continue
                raise RuntimeError(f"Authentication failed or non-JSON response (HTTP {r.status_code})")
            r.raise_for_status()
            return r.json()
        raise RuntimeError("Failed to fetch JSON from BunkerWeb")

    def list_history(self, page: int = 1, page_size: int = 100, q: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q
        return self._get_json("/trafficlog/api/history", params)

    def get_detail(self, request_id: str) -> dict[str, Any] | None:
        data = self._get_json("/trafficlog/api/history", {"request_id": request_id, "page_size": 1})
        items = data.get("items") or []
        return items[0] if items else None

    def get_log_size(self, filename: str = "traffic.log") -> int:
        self._ensure_login()
        url = f"{self.base_url}/logs/download"
        for attempt in range(2):
            with self.session.get(
                url,
                params={"file": filename},
                headers={"Range": "bytes=0-0"},
                allow_redirects=False,
                stream=True,
                timeout=self.timeout,
            ) as r:
                if r.status_code in (301, 302, 303, 401, 403):
                    if attempt == 0:
                        self.login()
                        continue
                    raise RuntimeError(f"Authentication failed (HTTP {r.status_code})")
                if r.status_code == 404:
                    raise RangeUnsupportedError("/logs/download endpoint not found (404)")
                cr = r.headers.get("Content-Range", "")
                m = re.search(r"/(\d+)$", cr)
                if m:
                    return int(m.group(1))
                if r.status_code == 416:
                    return 0
                r.raise_for_status()
                if r.status_code != 206:
                    raise RangeUnsupportedError("Server ignored Range header (HTTP 200)")
                return 0
        raise RuntimeError("Failed to get traffic.log size")

    def fetch_log_range(self, start: int, filename: str = "traffic.log", max_bytes: int = RANGE_CHUNK_SIZE) -> tuple[bytes, int, int]:
        """Fetch up to `max_bytes` from `start` onwards. Returns (raw_bytes, next_offset, total_size)."""
        self._ensure_login()
        url = f"{self.base_url}/logs/download"
        end_req = start + max_bytes - 1
        for attempt in range(2):
            with self.session.get(
                url,
                params={"file": filename},
                headers={"Range": f"bytes={start}-{end_req}"},
                allow_redirects=False,
                stream=True,
                timeout=self.timeout,
            ) as r:
                if r.status_code in (301, 302, 303, 401, 403):
                    if attempt == 0:
                        self.login()
                        continue
                    raise RuntimeError(f"Authentication failed (HTTP {r.status_code})")
                if r.status_code == 404:
                    raise RangeUnsupportedError("/logs/download endpoint not found (404)")
                cr = r.headers.get("Content-Range", "")
                if r.status_code == 416:
                    m = re.search(r"/(\d+)$", cr)
                    total = int(m.group(1)) if m else start
                    return b"", start, total
                r.raise_for_status()
                if r.status_code == 206:
                    m = re.match(r"bytes\s+(\d+)-(\d+)/(\d+)", cr)
                    if m:
                        end_pos = int(m.group(2))
                        total = int(m.group(3))
                        return r.content, end_pos + 1, total
                raise RangeUnsupportedError(f"Unexpected non-206 status ({r.status_code}) for Range request")
        raise RuntimeError("Failed to fetch log range")


class MonitorEngine:
    """Background monitor that watches WAF logs and broadcasts flag-leak alerts."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.config: dict[str, Any] = {
            "mode": "range",  # "range", "http", or "docker"
            "waf_url": DEFAULT_WAF_URL,
            "username": DEFAULT_WAF_USER,
            "password": DEFAULT_WAF_PASS,
            "docker_container": DEFAULT_DOCKER_CONTAINER,
            "pattern": DEFAULT_PATTERN,
            "poll_interval": 1.0,
            "verify_ssl": True,
            "smart_filter": True,
        }
        self._compiled_re = re.compile(DEFAULT_PATTERN)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._docker_proc: subprocess.Popen[str] | None = None

        self._seen_deque: deque[str] = deque(maxlen=25000)
        self._seen_set: set[str] = set()
        self.alerts: deque[dict[str, Any]] = deque(maxlen=500)
        self._subscribers: list[queue.Queue[str]] = []

        self.stats: dict[str, Any] = {
            "status": "stopped",
            "mode": "http",
            "total_scanned": 0,
            "total_skipped": 0,
            "total_alerts": 0,
            "last_poll_at": None,
            "last_error": None,
            "started_at": None,
        }

    def subscribe(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue(maxsize=200)
        with self.lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[str]) -> None:
        with self.lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast(self, event_type: str, payload: Any) -> None:
        msg = f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
        with self.lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    def _mark_seen(self, request_id: str) -> bool:
        """Return True if newly seen, False if already seen."""
        with self.lock:
            if request_id in self._seen_set:
                return False
            if len(self._seen_deque) == self._seen_deque.maxlen:
                oldest = self._seen_deque.popleft()
                self._seen_set.discard(oldest)
            self._seen_deque.append(request_id)
            self._seen_set.add(request_id)
            return True

    def inspect_record(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Inspect a full trafficlog record; return an alert dict if flag found in response."""
        resp_headers = record.get("response_headers") or []
        resp_body = decode_body(
            record.get("response_body"),
            record.get("response_body_encoding"),
            resp_headers,
        )
        req_headers = record.get("request_headers") or []
        req_body = decode_body(
            record.get("request_body"),
            record.get("request_body_encoding"),
            req_headers,
        )

        pattern = self._compiled_re
        matches: list[str] = []
        locations: list[str] = []

        for pair in resp_headers:
            if len(pair) >= 2:
                hname, hval = str(pair[0]), str(pair[1])
                found = pattern.findall(hval)
                if found:
                    matches.extend(found)
                    locations.append(f"Header: {hname}")

        body_found = pattern.findall(resp_body)
        if body_found:
            matches.extend(body_found)
            locations.append("Response Body")

        if not matches:
            return None

        # Deduplicate preserving order
        unique_flags = list(dict.fromkeys(matches))
        unique_locs = list(dict.fromkeys(locations))

        modsec = record.get("modsec") or []
        modsec_ids = record.get("modsec_ids") or [str(m.get("id")) for m in modsec if m.get("id")]

        http_ver = str(record.get("http_version") or "HTTP/1.1")
        if not http_ver.startswith("HTTP/"):
            http_ver = f"HTTP/{http_ver}"

        req_line = f"{record.get('method', 'GET')} {record.get('uri', '/')} {http_ver}"
        resp_line = f"{http_ver} {record.get('status', '')}"

        alert = {
            "id": record.get("request_id") or f"ts-{time.time_ns()}",
            "detected_at": datetime.now().isoformat(timespec="seconds"),
            "time": record.get("time") or "",
            "source_ip": record.get("source_ip") or "",
            "host": record.get("host") or "",
            "method": record.get("method") or "GET",
            "uri": record.get("uri") or "/",
            "status": record.get("status"),
            "request_time_ms": round(record.get("request_time", 0) * 1000) if record.get("request_time") is not None else None,
            "flags": unique_flags,
            "locations": unique_locs,
            "modsec_ids": modsec_ids,
            "modsec": modsec,
            "request_line": req_line,
            "request_headers_text": format_headers(req_headers),
            "request_body": req_body,
            "response_line": resp_line,
            "response_headers_text": format_headers(resp_headers),
            "response_body": resp_body,
            "response_body_truncated": bool(record.get("response_body_truncated")),
            "curl": build_curl(record, req_body),
        }
        return alert

    def _emit_alert(self, alert: dict[str, Any]) -> None:
        with self.lock:
            # Avoid duplicate alerts for same request_id
            if any(a["id"] == alert["id"] for a in self.alerts):
                return
            self.alerts.appendleft(alert)
            self.stats["total_alerts"] += 1
        self._broadcast("alert", alert)

    def start(self, new_config: dict[str, Any] | None = None) -> None:
        self.stop()
        with self.lock:
            if new_config:
                self.config.update(new_config)
            self._compiled_re = re.compile(self.config["pattern"])
            self._seen_deque.clear()
            self._seen_set.clear()
            self.stats.update({
                "status": "starting",
                "mode": self.config["mode"],
                "last_error": None,
                "started_at": datetime.now().isoformat(timespec="seconds"),
            })
        self._stop_event.clear()
        mode = self.config["mode"]
        if mode == "docker":
            target = self._run_docker
        elif mode == "range":
            target = self._run_range
        else:
            target = self._run_http
        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._docker_proc and self._docker_proc.poll() is None:
            try:
                self._docker_proc.terminate()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        with self.lock:
            self.stats["status"] = "stopped"
        self._broadcast("stats", self.get_stats())

    def scan_recent_http(self, count: int = 100) -> dict[str, Any]:
        """Manually scan the latest `count` records from BunkerWeb (fast Range or HTTP API)."""
        cfg = dict(self.config)
        client = BunkerWebClient(
            cfg["waf_url"], cfg["username"], cfg["password"],
            verify_ssl=bool(cfg.get("verify_ssl", True)),
        )
        if cfg.get("mode") == "range":
            try:
                total = client.get_log_size("traffic.log")
                if total <= 0:
                    return {"scanned": 0, "skipped": 0, "alerts_found": 0}
                start = max(0, total - 1024 * 1024)  # last 1 MiB
                raw_bytes, _, _ = client.fetch_log_range(start, "traffic.log", max_bytes=1024 * 1024)
                lines = raw_bytes.split(b"\n")
                if start > 0 and lines:
                    lines = lines[1:]  # drop partial first line
                lines = [ln for ln in lines if ln.strip()][-count:]
                use_filter = bool(cfg.get("smart_filter", True))
                found_alerts = 0
                scanned = 0
                skipped = 0
                for ln_b in lines:
                    try:
                        rec = json.loads(ln_b.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        continue
                    if use_filter and should_skip_summary(rec):
                        skipped += 1
                        continue
                    scanned += 1
                    alert = self.inspect_record(rec)
                    if alert:
                        self._emit_alert(alert)
                        found_alerts += 1
                with self.lock:
                    self.stats["total_scanned"] += scanned
                    self.stats["total_skipped"] += skipped
                self._broadcast("stats", self.get_stats())
                return {"scanned": scanned, "skipped": skipped, "alerts_found": found_alerts}
            except RangeUnsupportedError:
                pass  # fallback to /trafficlog/api/history below

        data = client.list_history(page=1, page_size=min(max(count, 1), 200))
        items = data.get("items") or []
        use_filter = bool(cfg.get("smart_filter", True))
        target_items = [it for it in items if it.get("request_id") and not (use_filter and should_skip_summary(it))]
        skipped = len(items) - len(target_items)
        found_alerts = 0
        scanned = 0
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(client.get_detail, it["request_id"]): it for it in target_items}
            for fut in as_completed(futures):
                scanned += 1
                try:
                    rec = fut.result()
                    if rec:
                        alert = self.inspect_record(rec)
                        if alert:
                            self._emit_alert(alert)
                            found_alerts += 1
                except Exception:
                    pass
        with self.lock:
            self.stats["total_scanned"] += scanned
            self.stats["total_skipped"] += skipped
        self._broadcast("stats", self.get_stats())
        return {"scanned": scanned, "skipped": skipped, "alerts_found": found_alerts}

    def _run_range(self) -> None:
        """Tail /logs/download?file=traffic.log via HTTP Range requests (near-zero WAF CPU)."""
        cfg = dict(self.config)
        client = BunkerWebClient(
            cfg["waf_url"], cfg["username"], cfg["password"],
            verify_ssl=bool(cfg.get("verify_ssl", True)),
        )
        poll_interval = max(0.3, float(cfg.get("poll_interval", 1.0)))
        use_filter = bool(cfg.get("smart_filter", True))
        offset = 0
        partial = b""
        initialized = False

        def _fallback_to_http(reason: str) -> None:
            with self.lock:
                self.config["mode"] = "http"
                self.stats["mode"] = "http"
                self.stats["last_error"] = f"Range không khả dụng ({reason}), tự chuyển sang HTTP API."
            self._broadcast("stats", self.get_stats())
            self._run_http()

        try:
            client.login()
            offset = client.get_log_size("traffic.log")
            initialized = True
            with self.lock:
                self.stats["status"] = "running"
                self.stats["last_poll_at"] = datetime.now().isoformat(timespec="seconds")
                self.stats["last_error"] = None
            self._broadcast("stats", self.get_stats())
        except RangeUnsupportedError as exc:
            _fallback_to_http(str(exc))
            return
        except Exception as exc:
            with self.lock:
                self.stats["status"] = "error"
                self.stats["last_error"] = str(exc)
            self._broadcast("stats", self.get_stats())

        while not self._stop_event.is_set():
            t0 = time.monotonic()
            try:
                if not initialized:
                    offset = client.get_log_size("traffic.log")
                    initialized = True

                scanned_now = 0
                skipped_now = 0
                # Catch up in bounded 4 MiB chunks so memory stays flat even under huge bursts
                for _ in range(16):
                    if self._stop_event.is_set():
                        break
                    raw_bytes, next_offset, total = client.fetch_log_range(offset, "traffic.log")
                    if total < offset:
                        # Log rotated: start from beginning of new file
                        offset = 0
                        partial = b""
                        continue
                    offset = next_offset
                    if raw_bytes:
                        chunk = partial + raw_bytes
                        if chunk.endswith(b"\n"):
                            lines = chunk.split(b"\n")
                            partial = b""
                        else:
                            parts = chunk.split(b"\n")
                            lines = parts[:-1]
                            partial = parts[-1]
                        for ln_b in lines:
                            ln_b = ln_b.strip()
                            if not ln_b:
                                continue
                            try:
                                rec = json.loads(ln_b.decode("utf-8", errors="replace"))
                            except json.JSONDecodeError:
                                continue
                            rid = rec.get("request_id")
                            if rid and not self._mark_seen(rid):
                                continue
                            if use_filter and should_skip_summary(rec):
                                skipped_now += 1
                                continue
                            scanned_now += 1
                            alert = self.inspect_record(rec)
                            if alert:
                                self._emit_alert(alert)
                    if offset >= total or not raw_bytes:
                        break

                with self.lock:
                    self.stats["status"] = "running"
                    self.stats["total_scanned"] += scanned_now
                    self.stats["total_skipped"] += skipped_now
                    self.stats["last_poll_at"] = datetime.now().isoformat(timespec="seconds")
                    self.stats["last_error"] = None
                self._broadcast("stats", self.get_stats())
            except RangeUnsupportedError as exc:
                _fallback_to_http(str(exc))
                return
            except Exception as exc:
                client._logged_in = False
                with self.lock:
                    self.stats["status"] = "error"
                    self.stats["last_error"] = str(exc)
                self._broadcast("stats", self.get_stats())

            elapsed = time.monotonic() - t0
            sleep_for = max(0.1, poll_interval - elapsed)
            self._stop_event.wait(sleep_for)

    def _run_http(self) -> None:
        cfg = dict(self.config)
        client = BunkerWebClient(
            cfg["waf_url"], cfg["username"], cfg["password"],
            verify_ssl=bool(cfg.get("verify_ssl", True)),
        )
        poll_interval = max(0.3, float(cfg.get("poll_interval", 1.0)))
        use_filter = bool(cfg.get("smart_filter", True))

        # Initial baseline: mark current page 1 as seen so we only alert on NEW responses
        try:
            client.login()
            init_data = client.list_history(page=1, page_size=200)
            for it in init_data.get("items") or []:
                rid = it.get("request_id")
                if rid:
                    self._mark_seen(rid)
            with self.lock:
                self.stats["status"] = "running"
                self.stats["last_poll_at"] = datetime.now().isoformat(timespec="seconds")
                self.stats["last_error"] = None
            self._broadcast("stats", self.get_stats())
        except Exception as exc:
            with self.lock:
                self.stats["status"] = "error"
                self.stats["last_error"] = str(exc)
            self._broadcast("stats", self.get_stats())

        with ThreadPoolExecutor(max_workers=12) as pool:
            while not self._stop_event.is_set():
                t0 = time.monotonic()
                try:
                    data = client.list_history(page=1, page_size=200)
                    items = data.get("items") or []
                    # Newest items are first; process oldest-new first
                    new_ids = []
                    skipped = 0
                    for it in reversed(items):
                        rid = it.get("request_id")
                        if rid and self._mark_seen(rid):
                            if use_filter and should_skip_summary(it):
                                skipped += 1
                            else:
                                new_ids.append(rid)

                    if new_ids:
                        futures = [pool.submit(client.get_detail, rid) for rid in new_ids]
                        for fut in as_completed(futures):
                            if self._stop_event.is_set():
                                break
                            try:
                                rec = fut.result()
                                if rec:
                                    alert = self.inspect_record(rec)
                                    if alert:
                                        self._emit_alert(alert)
                            except Exception:
                                pass

                    with self.lock:
                        self.stats["status"] = "running"
                        self.stats["total_scanned"] += len(new_ids)
                        self.stats["total_skipped"] += skipped
                        self.stats["last_poll_at"] = datetime.now().isoformat(timespec="seconds")
                        self.stats["last_error"] = None
                    self._broadcast("stats", self.get_stats())
                except Exception as exc:
                    with self.lock:
                        self.stats["status"] = "error"
                        self.stats["last_error"] = str(exc)
                    self._broadcast("stats", self.get_stats())

                elapsed = time.monotonic() - t0
                sleep_for = max(0.1, poll_interval - elapsed)
                self._stop_event.wait(sleep_for)

    def _run_docker(self) -> None:
        container = self.config["docker_container"]
        cmd = ["docker", "exec", container, "tail", "-n", "0", "-F", "/var/log/bunkerweb/traffic.log"]
        try:
            self._docker_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            with self.lock:
                self.stats["status"] = "running"
                self.stats["last_error"] = None
            self._broadcast("stats", self.get_stats())

            assert self._docker_proc.stdout is not None
            for line in self._docker_proc.stdout:
                if self._stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rid = rec.get("request_id")
                if rid and not self._mark_seen(rid):
                    continue
                with self.lock:
                    self.stats["total_scanned"] += 1
                    self.stats["last_poll_at"] = datetime.now().isoformat(timespec="seconds")
                alert = self.inspect_record(rec)
                if alert:
                    self._emit_alert(alert)
                if self.stats["total_scanned"] % 10 == 0:
                    self._broadcast("stats", self.get_stats())
        except Exception as exc:
            with self.lock:
                self.stats["status"] = "error"
                self.stats["last_error"] = str(exc)
            self._broadcast("stats", self.get_stats())

    def get_stats(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.stats)

    def get_alerts(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.alerts)

    def clear_alerts(self) -> None:
        with self.lock:
            self.alerts.clear()
        self._broadcast("cleared", {})


engine = MonitorEngine()

app.secret_key = os.environ.get("WAF_MONITOR_SECRET") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

LOGIN_HTML = """<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Đăng nhập — WAF Flag Leak Monitor</title>
<style>
  :root {
    --bg: #0b0f17; --panel: #121826; --border: #253047;
    --text: #e6edf7; --muted: #8b9bb4; --blue: #3b82f6; --red: #ff4d5e;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, sans-serif;
  }
  .card {
    width: min(380px, 92vw); padding: 24px; border-radius: 12px;
    background: var(--panel); border: 1px solid var(--border);
    box-shadow: 0 20px 50px rgba(0,0,0,0.5);
  }
  h1 { margin: 0 0 6px; font-size: 18px; }
  p { margin: 0 0 18px; font-size: 13px; color: var(--muted); }
  .err {
    margin-bottom: 14px; padding: 8px 10px; border-radius: 6px; font-size: 12px;
    background: rgba(255,77,94,0.14); color: #fda4af; border: 1px solid rgba(255,77,94,0.35);
  }
  label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; font-weight: 600; }
  input[type="password"] {
    width: 100%; padding: 9px 12px; border-radius: 6px; border: 1px solid var(--border);
    background: var(--bg); color: var(--text); font-size: 14px; outline: none; margin-bottom: 14px;
  }
  input[type="password"]:focus { border-color: var(--blue); }
  button {
    width: 100%; padding: 9px 12px; border-radius: 6px; border: none;
    background: var(--blue); color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  button:hover { background: #2563eb; }
</style>
</head>
<body>
  <div class="card">
    <h1>🛡️ WAF Flag Leak Monitor</h1>
    <p>Nhập mật khẩu để truy cập bảng cảnh báo.</p>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <form method="post" action="{{ url_for('login') }}">
      <label for="password">Mật khẩu</label>
      <input id="password" name="password" type="password" autofocus required placeholder="Nhập mật khẩu...">
      <button type="submit">Đăng nhập</button>
    </form>
  </div>
</body>
</html>
"""


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        entered = request.form.get("password", "")
        expected = app.config.get("UI_PASSWORD", "")
        if expected and secrets.compare_digest(entered, expected):
            session["authenticated"] = True
            return redirect(url_for("index"))
        error = "Mật khẩu không đúng."
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/state")
@login_required
def api_state():
    return jsonify({
        "stats": engine.get_stats(),
        "config": {k: v for k, v in engine.config.items() if k != "password"},
        "alerts": engine.get_alerts(),
    })


@app.route("/api/config", methods=["POST"])
@login_required
def api_config():
    body = request.get_json(force=True) or {}
    new_cfg: dict[str, Any] = {}
    for key in ("mode", "waf_url", "username", "password", "docker_container", "pattern", "poll_interval"):
        if key in body and body[key] != "":
            new_cfg[key] = body[key]
    for bkey in ("verify_ssl", "smart_filter"):
        if bkey in body:
            new_cfg[bkey] = bool(body[bkey])
    try:
        re.compile(new_cfg.get("pattern", engine.config["pattern"]))
    except re.error as exc:
        return jsonify({"error": f"Invalid regex: {exc}"}), 400
    engine.start(new_cfg)
    return jsonify({"ok": True, "stats": engine.get_stats()})


@app.route("/api/scan-recent", methods=["POST"])
@login_required
def api_scan_recent():
    body = request.get_json(silent=True) or {}
    count = int(body.get("count", 100))
    try:
        res = engine.scan_recent_http(count=count)
        return jsonify({"ok": True, **res})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/alerts/clear", methods=["POST"])
@login_required
def api_clear():
    engine.clear_alerts()
    return jsonify({"ok": True})


@app.route("/api/generate-rules", methods=["POST"])
@login_required
def api_generate_rules():
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    base_id = int(body.get("base_rule_id", 27200))
    action_mode = body.get("action_mode", "pass")
    scope_host = bool(body.get("scope_host", False))
    legit_flag_routes_raw = body.get("legit_flag_routes", "")
    if isinstance(legit_flag_routes_raw, list):
        legit_flag_routes = [str(r) for r in legit_flag_routes_raw]
    else:
        legit_flag_routes = [r.strip() for r in str(legit_flag_routes_raw or "").split(",") if r.strip()]
    alert = next((a for a in engine.get_alerts() if a["id"] == alert_id), None)
    if not alert:
        return jsonify({"error": "Không tìm thấy alert này"}), 404
    res = generate_waf_rules(
        alert,
        base_rule_id=base_id,
        flag_pattern=engine.config["pattern"],
        action_mode=action_mode,
        scope_host=scope_host,
        legit_flag_routes=legit_flag_routes,
    )
    return jsonify({"ok": True, **res})


@app.route("/api/validate-rules", methods=["POST"])
@login_required
def api_validate_rules():
    body = request.get_json(silent=True) or {}
    rules_text = body.get("rules", "")
    alert_id = body.get("alert_id")
    alert = next((a for a in engine.get_alerts() if a["id"] == alert_id), None) if alert_id else None
    res = validate_rules_text(rules_text, alert=alert)
    return jsonify(res)


@app.route("/api/generate-exploit", methods=["POST"])
@login_required
def api_generate_exploit():
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    alert = next((a for a in engine.get_alerts() if a["id"] == alert_id), None)
    if not alert:
        return jsonify({"error": "Không tìm thấy alert này"}), 404
    res = generate_exploit_script(alert, flag_pattern=engine.config["pattern"])
    return jsonify({"ok": True, **res})


@app.route("/api/stream")
@login_required
def api_stream():
    q = engine.subscribe()

    def gen():
        try:
            yield f"event: stats\ndata: {json.dumps(engine.get_stats())}\n\n"
            while True:
                try:
                    msg = q.get(timeout=15.0)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            engine.unsubscribe(q)

    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


def main() -> None:
    parser = argparse.ArgumentParser(description="Realtime WAF Flag Leak Monitor")
    parser.add_argument("--host", default="127.0.0.1", help="WebUI bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9555, help="WebUI port (default: 9555)")
    parser.add_argument("--waf-url", default=DEFAULT_WAF_URL, help="BunkerWeb UI URL")
    parser.add_argument("--waf-user", "--user", dest="waf_user", default=DEFAULT_WAF_USER, help="BunkerWeb username")
    parser.add_argument("--waf-password", "--waf-pass", dest="waf_password", default=DEFAULT_WAF_PASS, help="BunkerWeb password")
    parser.add_argument("--mode", choices=["range", "http", "docker"], default="range", help="Log source mode (default: range)")
    parser.add_argument("--container", default=DEFAULT_DOCKER_CONTAINER, help="Docker container name for docker mode")
    parser.add_argument("--pattern", default=DEFAULT_PATTERN, help="Flag regex pattern")
    parser.add_argument("--interval", type=float, default=1.0, help="HTTP poll interval in seconds")
    parser.add_argument("--insecure", action="store_true", help="Ignore SSL certificate errors for HTTPS WAF URL")
    parser.add_argument("--no-smart-filter", action="store_true", help="Disable skipping 403/404/static requests in HTTP mode")
    parser.add_argument("--password", "--ui-password", dest="ui_password", default=os.environ.get("WAF_MONITOR_PASSWORD", ""), help="Password to access WebUI (default: auto-generated)")
    args = parser.parse_args()

    ui_password = args.ui_password or secrets.token_urlsafe(12)
    app.config["UI_PASSWORD"] = ui_password

    engine.start({
        "mode": args.mode,
        "waf_url": args.waf_url,
        "username": args.waf_user,
        "password": args.waf_password,
        "docker_container": args.container,
        "pattern": args.pattern,
        "poll_interval": args.interval,
        "verify_ssl": not args.insecure,
        "smart_filter": not args.no_smart_filter,
    })

    print(f"[*] WAF Flag Monitor WebUI: http://{args.host}:{args.port}")
    print(f"[*] WebUI Password: {ui_password}")
    print(f"[*] Target WAF: {args.waf_url} (mode={args.mode})")
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()

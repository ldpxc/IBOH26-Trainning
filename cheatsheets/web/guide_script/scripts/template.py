#!/usr/bin/env python3
"""Template A/D siêu gọn - copy file này thành bai1.py rồi sửa solve_one()."""
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

import requests

# ===== CẤU HÌNH NHANH =====
TARGETS_FILE = Path(__file__).with_name("targets.txt")
USE_PROXY = False  # Bật True khi debug qua Burp
PROXY_URL = "http://127.0.0.1:8080"
TIMEOUT = 4
DELAY = 0.5        # nghỉ giữa các bước trong 1 đội
WORKERS = 4
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")
OWN_FLAGS = {
    # "FHACKER2026{...}",  # thêm cờ đội nhà để không in/lưu nhầm
}
OUT_FILE = Path(__file__).resolve().parents[1] / "results" / "flags.txt"


def load_targets(path=TARGETS_FILE):
    targets, our = [], set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.upper().startswith("@OUR_TEAM"):
            line = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if line:
                our.add(normalize(line))
            continue
        targets.append(normalize(line))
    blocked = {"127.0.0.1", "localhost", "::1"} | {u.split("//", 1)[-1].split("/", 1)[0].lower() for u in our}
    return [t for t in targets if t.split("//", 1)[-1].split("/", 1)[0].lower() not in blocked]


def normalize(url):
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url.rstrip("/")


def make_session():
    s = requests.Session()
    s.verify = False
    if USE_PROXY:
        s.proxies.update({"http": PROXY_URL, "https": PROXY_URL})
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except Exception:
            pass
    return s


def save_flags(team, flags):
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    if OUT_FILE.exists():
        seen = {x.strip() for x in OUT_FILE.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()}
    with OUT_FILE.open("a", encoding="utf-8") as f:
        for flag in flags:
            if flag in OWN_FLAGS or flag in seen:
                continue
            f.write(flag + "\n")
            seen.add(flag)
            print(f"[+] {team} {flag}")


def solve_one(session, base_url):
    """TODO: dán logic Burp vào đây. Trả về list flag tìm được."""
    url = urljoin(base_url + "/", "/")  # sửa path
    r = session.get(url, timeout=TIMEOUT)
    time.sleep(DELAY)
    return FLAG_RE.findall(r.text)


def worker(base_url):
    try:
        flags = solve_one(make_session(), base_url) or []
        save_flags(base_url, flags)
        return base_url, flags, None
    except Exception as e:
        return base_url, [], str(e)


if __name__ == "__main__":
    targets = load_targets()
    print(f"[*] Targets: {len(targets)} | proxy={USE_PROXY} | workers={WORKERS}")
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(worker, t) for t in targets]
        for fut in as_completed(futs):
            team, flags, err = fut.result()
            if err:
                print(f"[-] {team} ERR {err}")

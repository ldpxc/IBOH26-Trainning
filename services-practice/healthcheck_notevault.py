#!/usr/bin/env python3
"""healthcheck_notevault.py -- mô phỏng bot SLA (SVC) của BTC cho notevault.

Gửi request "như người dùng thật" (login hợp lệ -> vào trang của mình -> đọc
đúng note của mình) mỗi N giây, qua đúng cổng WAF của 1 team (BW_PORT từ
spin.sh). Phân loại lỗi đúng 3 nguyên nhân quy chế liệt kê ở Điều 5:
  - "SAP/QUA TAI"     : không kết nối được / timeout / lỗi 5xx
  - "WAF CHAN NHAM"   : request hợp lệ bị trả 403 (hoặc mã 4xx khác thường)
  - "KHONG DOC DUOC CO": status 200 nhưng thiếu đúng nội dung mong đợi
      (bao gồm cả trường hợp admin xem note của CHÍNH MÌNH mà không thấy
      flag -- đây là dấu hiệu rule chặn-theo-nội-dung-response đã tự
      chặn luôn người dùng hợp lệ, xem lại cuộc trò chuyện về SVC/DEF).

Dùng (chỉ dùng cho ĐÚNG team của mình -- mật khẩu admin/alice giờ random
riêng theo từng team, tự đọc từ file .env của chính team đó, KHÔNG hard-code
nữa -- xem lại cuộc trò chuyện về việc không nên dùng credential có sẵn để
"tấn công" team kia):
    spwn   # activate venv trước
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000 --env-file .runtime/a_notevault/.env
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9010 --env-file .runtime/b_notevault/.env --interval 30
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000 --env-file .runtime/a_notevault/.env --once   # test nhanh

Mặc định --base-url là cổng team "a" (9000) theo đúng spin.sh. Team "b" dùng
9010 (notevault), xem `./spin.sh ps` để lấy đúng cổng -- --env-file cũng phải
đổi theo đúng team đang chạy (file do chính `spin.sh up` sinh ra).
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
from datetime import datetime

import requests

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")
NOTE_LINK_RE = re.compile(r'/note\.php\?id=(\d+)"[^>]*>([^<]*)')


def seed_password(secret: str, role: str) -> str:
    """Y hệt công thức trong notevault/app/seed.php -- không được đổi 1 bên
    mà quên đổi bên kia, nếu không mật khẩu tính ra sẽ sai."""
    return hmac.new(secret.encode(), f"seed:{role}".encode(), hashlib.sha256).hexdigest()[:16]


def read_seed_secret(env_file: str) -> str:
    try:
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith("SEED_PASSWORD_SECRET="):
                    return line.split("=", 1)[1].strip()
    except FileNotFoundError:
        print(f"[!] Không thấy file {env_file} -- phải chạy `./spin.sh up <team> notevault` trước, "
              f"hoặc trỏ --env-file đúng vào .runtime/<team>_notevault/.env của team mình.", file=sys.stderr)
        sys.exit(1)
    print(f"[!] File {env_file} không có dòng SEED_PASSWORD_SECRET= -- bản spin.sh có thể cũ, "
          f"chạy `./spin.sh up <team> notevault` lại để sinh dòng này.", file=sys.stderr)
    sys.exit(1)


class CheckResult:
    def __init__(self, name, ok, reason=""):
        self.name = name
        self.ok = ok
        self.reason = reason


def classify_http_error(exc) -> str:
    if isinstance(exc, requests.exceptions.Timeout):
        return "SAP/QUA TAI (timeout)"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "SAP/QUA TAI (connection refused/reset)"
    return f"SAP/QUA TAI ({exc.__class__.__name__}: {exc})"


def check_uptime(base_url: str, timeout: float) -> CheckResult:
    """Request kiểu người dùng thật đầu tiên ghé thăm app: GET /."""
    try:
        r = requests.get(base_url + "/", timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return CheckResult("uptime (GET /)", False, classify_http_error(e))
    if r.status_code >= 500:
        return CheckResult("uptime (GET /)", False, f"SAP/QUA TAI (status {r.status_code})")
    if r.status_code == 403:
        return CheckResult("uptime (GET /)", False, "WAF CHAN NHAM (trang chủ, request chưa có gì bất thường, bị chặn 403)")
    return CheckResult("uptime (GET /)", True)


def check_user_flow(base_url: str, username: str, password: str, expect_flag: bool, timeout: float) -> CheckResult:
    """Login hợp lệ -> vào trang của mình (index.php) -> mở đúng note của
    chính mình, LẤY ID TỪ LINK THẬT trên trang (không đoán id), giống hệt
    thao tác 1 người dùng thật sẽ làm bằng trình duyệt."""
    name = f"luồng hợp lệ: {username}"
    s = requests.Session()
    s.verify = False
    try:
        r = s.post(
            base_url + "/login.php",
            data={"username": username, "password": password},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return CheckResult(name, False, classify_http_error(e))
    if r.status_code == 403:
        return CheckResult(name, False, "WAF CHAN NHAM (login hợp lệ bị chặn 403)")
    if r.status_code >= 500:
        return CheckResult(name, False, f"SAP/QUA TAI (login status {r.status_code})")
    if r.status_code not in (200, 302):
        return CheckResult(name, False, f"LOI BAT THUONG (login status {r.status_code})")
    if r.status_code == 302 and "login.php" in (r.headers.get("Location") or ""):
        return CheckResult(name, False, "LOI UNG DUNG (login đúng user/pass nhưng bị đá về login.php -- tài khoản mẫu có thể đã bị đổi/xoá)")

    try:
        r2 = s.get(base_url + "/", timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return CheckResult(name, False, classify_http_error(e))
    if r2.status_code == 403:
        return CheckResult(name, False, "WAF CHAN NHAM (trang chủ sau khi login bị chặn 403)")
    if r2.status_code >= 500:
        return CheckResult(name, False, f"SAP/QUA TAI (trang chủ status {r2.status_code})")

    m = NOTE_LINK_RE.search(r2.text)
    if not m:
        return CheckResult(name, False, "KHONG DOC DUOC CO (không thấy link note nào trên trang chủ -- có thể bị chặn nhầm phần hiển thị, hoặc seed dữ liệu bị mất)")
    note_id, note_title = m.group(1), m.group(2)

    try:
        r3 = s.get(base_url + f"/note.php?id={note_id}", timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return CheckResult(name, False, classify_http_error(e))
    if r3.status_code == 403:
        return CheckResult(name, False, f"WAF CHAN NHAM (note id={note_id} của CHÍNH {username} bị chặn 403 -- rule đang chặn nhầm chủ sở hữu hợp lệ)")
    if r3.status_code >= 500:
        return CheckResult(name, False, f"SAP/QUA TAI (note status {r3.status_code})")
    if note_title and note_title not in r3.text:
        return CheckResult(name, False, f"KHONG DOC DUOC CO (mở note '{note_title}' của {username} nhưng nội dung không khớp, có thể bị cắt/sửa response)")

    if expect_flag:
        if not FLAG_RE.search(r3.text):
            return CheckResult(name, False, "KHONG DOC DUOC CO (admin tự xem note của chính mình nhưng KHÔNG thấy flag -- rất có thể rule WAF đang chặn theo nội dung response chứa 'FHACKER2026{', tự hại chính service)")

    return CheckResult(name, True)


def check_benign_search(base_url: str, alice_password: str, timeout: float) -> CheckResult:
    """Tìm kiếm bằng 1 từ khoá hoàn toàn bình thường (không ký tự SQL) --
    bài test false-positive cho rule chặn SQLi trên search.php."""
    name = "tìm kiếm bình thường (search.php?q=note)"
    s = requests.Session()
    s.verify = False
    try:
        s.post(base_url + "/login.php", data={"username": "alice", "password": alice_password}, timeout=timeout)
        r = s.get(base_url + "/search.php", params={"q": "note"}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return CheckResult(name, False, classify_http_error(e))
    if r.status_code == 403:
        return CheckResult(name, False, "WAF CHAN NHAM (tìm kiếm từ khoá thường 'note' bị chặn 403 -- rule SQLi đang quá tay)")
    if r.status_code >= 500:
        return CheckResult(name, False, f"SAP/QUA TAI (search status {r.status_code})")
    return CheckResult(name, True)


def run_cycle(base_url: str, users: list, timeout: float):
    checks = [check_uptime(base_url, timeout)]
    for u in users:
        checks.append(check_user_flow(base_url, u["username"], u["password"], u["expect_flag"], timeout))
    checks.append(check_benign_search(base_url, users[0]["password"], timeout))
    return checks


def main():
    ap = argparse.ArgumentParser(description="Mô phỏng bot SLA (SVC) cho notevault -- dùng khi luyện tập A/D không có dashboard thật.")
    ap.add_argument("--base-url", default="http://127.0.0.1:9000", help="URL app qua WAF, vd http://127.0.0.1:9000 (team a) hoặc :9010 (team b)")
    ap.add_argument("--env-file", default=None,
                     help="File .env do spin.sh sinh (vd .runtime/a_notevault/.env) -- tự đọc SEED_PASSWORD_SECRET "
                          "để tính đúng mật khẩu admin/alice của CHÍNH team này. Bắt buộc trừ khi dùng --admin-password/--alice-password.")
    ap.add_argument("--admin-password", default=None, help="Ghi đè mật khẩu admin thay vì tự tính từ --env-file")
    ap.add_argument("--alice-password", default=None, help="Ghi đè mật khẩu alice thay vì tự tính từ --env-file")
    ap.add_argument("--interval", type=float, default=30.0, help="Giây giữa mỗi lần check, mặc định 30s giống quy chế thật")
    ap.add_argument("--timeout", type=float, default=6.0, help="Timeout mỗi request (giây)")
    ap.add_argument("--once", action="store_true", help="Chạy đúng 1 vòng rồi thoát (test nhanh)")
    ap.add_argument("--log-file", default=None, help="Nếu đặt, ghi thêm (append) mỗi dòng kết quả dạng chữ vào file này")
    ap.add_argument("--json-log", default=None,
                     help="File JSONL ghi lịch sử mỗi vòng check (1 dòng JSON/vòng) cho dashboard.py đọc. "
                          "Mặc định: cùng thư mục với --env-file, tên healthcheck.jsonl. Đặt rỗng ('') để tắt.")
    ap.add_argument("--team", default=None, help="Nhãn team hiển thị trên dashboard (mặc định tự đoán từ tên thư mục --env-file)")
    args = ap.parse_args()

    if args.admin_password and args.alice_password:
        admin_pw, alice_pw = args.admin_password, args.alice_password
    elif args.env_file:
        secret = read_seed_secret(args.env_file)
        admin_pw = args.admin_password or seed_password(secret, "admin")
        alice_pw = args.alice_password or seed_password(secret, "alice")
    else:
        print("[!] Thiếu --env-file (hoặc đủ cả --admin-password và --alice-password). "
              "Trỏ đúng vào .runtime/<team>_notevault/.env của CHÍNH team đang chạy, "
              "xem `./spin.sh up <team> notevault` để biết đường dẫn.", file=sys.stderr)
        sys.exit(1)

    users = [
        {"username": "alice", "password": alice_pw, "expect_flag": False},
        {"username": "admin", "password": admin_pw, "expect_flag": True},
    ]

    # Đường dẫn JSONL mặc định: cùng thư mục với --env-file (chỗ spin.sh đã
    # quản lý sẵn, vd .runtime/a_notevault/healthcheck.jsonl) -- dashboard.py
    # tự tìm đúng file này theo --team/--service, không cần truyền tay.
    json_log_path = args.json_log
    if json_log_path is None and args.env_file:
        json_log_path = os.path.join(os.path.dirname(args.env_file), "healthcheck.jsonl")
    team_label = args.team
    if team_label is None and args.env_file:
        base = os.path.basename(os.path.dirname(args.env_file).rstrip("/"))
        team_label = base.split("_", 1)[0] if "_" in base else base

    base_url = args.base_url.rstrip("/")
    total, failed = 0, 0
    logf = open(args.log_file, "a", encoding="utf-8") if args.log_file else None
    jsonf = open(json_log_path, "a", encoding="utf-8") if json_log_path else None

    print(f"[*] Healthcheck notevault -- target: {base_url}  (Ctrl+C để dừng)")
    if jsonf:
        print(f"[*] Ghi lịch sử cho dashboard vào: {json_log_path}")
    try:
        while True:
            now = datetime.now()
            ts = now.strftime("%H:%M:%S")
            checks = run_cycle(base_url, users, args.timeout)
            ok_count = sum(1 for c in checks if c.ok)
            total += len(checks)
            failed += len(checks) - ok_count
            pct_cycle = 100.0 * ok_count / len(checks) if checks else 100.0
            pct_cum = 100.0 * (total - failed) / total if total else 100.0

            lines = [f"[{ts}] vòng check: {ok_count}/{len(checks)} OK"]
            for c in checks:
                status = "OK  " if c.ok else "FAIL"
                line = f"    [{status}] {c.name}" + (f" -- {c.reason}" if c.reason else "")
                lines.append(line)
            lines.append(f"    => SVC ước lượng từ lúc chạy script: {pct_cum:.1f}% ({total - failed}/{total} check qua)")
            if pct_cum <= 50.0:
                lines.append("    !!! Đã lỗi >= 50% check -- theo quy chế Điều 5, mức này coi như SVC = 0.")

            out = "\n".join(lines)
            print(out)
            if logf:
                logf.write(out + "\n")
                logf.flush()
            if jsonf:
                record = {
                    "event": "check",
                    "ts": now.timestamp(),
                    "time": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "team": team_label,
                    "ok_count": ok_count,
                    "total": len(checks),
                    "svc_cycle_pct": round(pct_cycle, 1),
                    "svc_cum_pct": round(pct_cum, 1),
                    "checks": [{"name": c.name, "ok": c.ok, "reason": c.reason} for c in checks],
                }
                jsonf.write(json.dumps(record, ensure_ascii=False) + "\n")
                jsonf.flush()

            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Dừng healthcheck.")
    finally:
        if logf:
            logf.close()
        if jsonf:
            jsonf.close()


if __name__ == "__main__":
    main()

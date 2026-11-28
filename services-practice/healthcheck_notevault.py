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

Dùng:
    spwn   # activate venv trước
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9010 --interval 30
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000 --once   # test nhanh, chạy 1 lần rồi thoát

Mặc định --base-url là cổng team "a" (9000) theo đúng spin.sh. Team "b" dùng
9010 (notevault), xem `./spin.sh ps` để lấy đúng cổng.
"""
import argparse
import re
import sys
import time
from datetime import datetime

import requests

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")
NOTE_LINK_RE = re.compile(r'/note\.php\?id=(\d+)"[^>]*>([^<]*)')

# 2 tài khoản hợp lệ do seed.php tạo sẵn (xem services-practice/notevault/app/seed.php)
USERS = [
    {"username": "alice", "password": "alice_demo_pw_2026", "expect_flag": False},
    {"username": "admin", "password": "admin_demo_pw_2026", "expect_flag": True},
]


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


def check_benign_search(base_url: str, timeout: float) -> CheckResult:
    """Tìm kiếm bằng 1 từ khoá hoàn toàn bình thường (không ký tự SQL) --
    bài test false-positive cho rule chặn SQLi trên search.php."""
    name = "tìm kiếm bình thường (search.php?q=note)"
    s = requests.Session()
    s.verify = False
    try:
        s.post(base_url + "/login.php", data={"username": "alice", "password": "alice_demo_pw_2026"}, timeout=timeout)
        r = s.get(base_url + "/search.php", params={"q": "note"}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return CheckResult(name, False, classify_http_error(e))
    if r.status_code == 403:
        return CheckResult(name, False, "WAF CHAN NHAM (tìm kiếm từ khoá thường 'note' bị chặn 403 -- rule SQLi đang quá tay)")
    if r.status_code >= 500:
        return CheckResult(name, False, f"SAP/QUA TAI (search status {r.status_code})")
    return CheckResult(name, True)


def run_cycle(base_url: str, timeout: float):
    checks = [check_uptime(base_url, timeout)]
    for u in USERS:
        checks.append(check_user_flow(base_url, u["username"], u["password"], u["expect_flag"], timeout))
    checks.append(check_benign_search(base_url, timeout))
    return checks


def main():
    ap = argparse.ArgumentParser(description="Mô phỏng bot SLA (SVC) cho notevault -- dùng khi luyện tập A/D không có dashboard thật.")
    ap.add_argument("--base-url", default="http://127.0.0.1:9000", help="URL app qua WAF, vd http://127.0.0.1:9000 (team a) hoặc :9010 (team b)")
    ap.add_argument("--interval", type=float, default=30.0, help="Giây giữa mỗi lần check, mặc định 30s giống quy chế thật")
    ap.add_argument("--timeout", type=float, default=6.0, help="Timeout mỗi request (giây)")
    ap.add_argument("--once", action="store_true", help="Chạy đúng 1 vòng rồi thoát (test nhanh)")
    ap.add_argument("--log-file", default=None, help="Nếu đặt, ghi thêm (append) mỗi dòng kết quả vào file này")
    args = ap.parse_args()

    base_url = args.base_url.rstrip("/")
    total, failed = 0, 0
    logf = open(args.log_file, "a", encoding="utf-8") if args.log_file else None

    print(f"[*] Healthcheck notevault -- target: {base_url}  (Ctrl+C để dừng)")
    try:
        while True:
            ts = datetime.now().strftime("%H:%M:%S")
            checks = run_cycle(base_url, args.timeout)
            ok_count = sum(1 for c in checks if c.ok)
            total += len(checks)
            failed += len(checks) - ok_count

            lines = [f"[{ts}] vòng check: {ok_count}/{len(checks)} OK"]
            for c in checks:
                status = "OK  " if c.ok else "FAIL"
                line = f"    [{status}] {c.name}" + (f" -- {c.reason}" if c.reason else "")
                lines.append(line)
            pct = 100.0 * (total - failed) / total if total else 100.0
            lines.append(f"    => SVC ước lượng từ lúc chạy script: {pct:.1f}% ({total - failed}/{total} check qua)")
            if pct <= 50.0:
                lines.append("    !!! Đã lỗi >= 50% check -- theo quy chế Điều 5, mức này coi như SVC = 0.")

            out = "\n".join(lines)
            print(out)
            if logf:
                logf.write(out + "\n")
                logf.flush()

            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Dừng healthcheck.")
    finally:
        if logf:
            logf.close()


if __name__ == "__main__":
    main()

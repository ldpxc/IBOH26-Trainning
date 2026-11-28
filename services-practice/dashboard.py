#!/usr/bin/env python3
"""dashboard.py -- xem SVC của CHÍNH team mình theo thời gian (dùng cùng dữ
liệu healthcheck_notevault.py đã ghi), qua từng lần check VÀ từng round.

Chỉ đọc file `healthcheck.jsonl` trong .runtime/<team>_<service>/ -- đúng 1
team, không thấy được dữ liệu của team kia (dashboard này KHÔNG phải "mắt
thần" nhìn cả 2 bên, giữ đúng tinh thần ROUND_GUIDE.md: mỗi team tự theo dõi
dịch vụ của chính mình). Không cần cài thêm gì (chỉ thư viện chuẩn Python).

Dùng:
    spwn
    # chạy healthcheck trước (cửa sổ terminal riêng, để nó liên tục ghi log):
    python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000 --env-file .runtime/a_notevault/.env

    # rồi mở dashboard ở 1 cửa sổ khác:
    python3 dashboard.py --team a
    # team b: python3 dashboard.py --team b --port 8810

Mở trình duyệt: http://127.0.0.1:8800/ (team a) hoặc :8810 (team b, mặc định
tự lệch cổng theo team giống spin.sh).
"""
import argparse
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MAX_BARS = 120  # số vòng check gần nhất hiển thị trên timeline


def team_offset(team: str) -> int:
    if len(team) == 1 and team.isalpha():
        return ord(team.lower()) - ord("a")
    return sum(team.encode()) % 20


def read_records(path: str):
    checks, markers = [], []
    if not os.path.isfile(path):
        return checks, markers
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("event") == "check":
                checks.append(r)
            elif r.get("event") in ("up", "rotate"):
                markers.append(r)
    checks.sort(key=lambda r: r["ts"])
    markers.sort(key=lambda r: r["ts"])
    return checks, markers


def round_of(ts: float, rotate_markers: list) -> int:
    return 1 + sum(1 for m in rotate_markers if m["ts"] <= ts)


def svc_color(pct: float) -> str:
    if pct >= 80:
        return "#2f7d4f"  # xanh -- khớp màu "ok" trong cheatsheet đã dùng trước đó
    if pct > 50:
        return "#c9a227"  # vàng
    return "#c0392b"  # đỏ


def render_svg_timeline(checks: list, rotate_markers: list) -> str:
    recent = checks[-MAX_BARS:]
    if not recent:
        return '<p class="muted">Chưa có dữ liệu -- chạy healthcheck_notevault.py trỏ đúng --json-log/--env-file của team này trước.</p>'

    bar_w, gap, chart_h, pad_top = 6, 2, 90, 10
    width = len(recent) * (bar_w + gap) + 20
    height = chart_h + pad_top + 30
    bars = []
    for i, c in enumerate(recent):
        pct = c.get("svc_cycle_pct", 0.0)
        h = max(2, chart_h * pct / 100.0)
        x = 10 + i * (bar_w + gap)
        y = pad_top + (chart_h - h)
        color = svc_color(pct)
        title = f"{c.get('time','')} -- {c.get('ok_count')}/{c.get('total')} check qua ({pct:.0f}%)"
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w}" height="{h:.1f}" fill="{color}"><title>{title}</title></rect>')

    # Mốc round: vẽ đường đứt tại vị trí vòng check đầu tiên của round đó
    marker_lines = []
    seen_rounds = set()
    rotate_only = [m for m in rotate_markers if m["event"] == "rotate"]
    for i, c in enumerate(recent):
        rnd = round_of(c["ts"], rotate_only)
        if rnd in seen_rounds:
            continue
        seen_rounds.add(rnd)
        x = 10 + i * (bar_w + gap)
        marker_lines.append(
            f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{chart_h + pad_top}" stroke="#888" stroke-dasharray="3,2"/>'
            f'<text x="{x+2:.1f}" y="{chart_h + pad_top + 14}" font-size="10" fill="#555">R{rnd}</text>'
        )

    svg = (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
        + "".join(marker_lines)
        + "".join(bars)
        + "</svg>"
    )
    return svg


def render_page(team: str, service: str, checks: list, markers: list) -> str:
    now = datetime.now()
    last = checks[-1] if checks else None
    rotate_only = [m for m in markers if m["event"] == "rotate"]
    current_round = round_of(last["ts"], rotate_only) if last else (1 + len(rotate_only))

    if last is None:
        status_html = '<div class="status unknown">CHƯA CÓ DỮ LIỆU</div><p class="muted">Chạy healthcheck_notevault.py trỏ đúng team này trước.</p>'
    else:
        age = now.timestamp() - last["ts"]
        stale = age > 90
        pct = last["svc_cycle_pct"]
        color = svc_color(pct) if not stale else "#888"
        label = "KHÔNG RÕ (healthcheck có thể đã dừng)" if stale else (
            "KHOẺ MẠNH" if pct >= 80 else ("ĐANG GIẢM" if pct > 50 else "NGUY CẤP (SVC ~ 0 theo Điều 5)")
        )
        fails = [c for c in last["checks"] if not c["ok"]]
        fail_html = ""
        if fails:
            items = "".join(f'<li><b>{f["name"]}</b>: {f["reason"]}</li>' for f in fails)
            fail_html = f'<div class="fails"><b>Lỗi vòng gần nhất:</b><ul>{items}</ul></div>'
        status_html = (
            f'<div class="status" style="color:{color}">{label}</div>'
            f'<p>Vòng gần nhất ({last["time"]}, {int(age)}s trước): '
            f'<b>{last["ok_count"]}/{last["total"]}</b> check qua ({pct:.0f}%) · '
            f'SVC tích luỹ từ đầu phiên: <b>{last["svc_cum_pct"]:.1f}%</b></p>'
            f'{fail_html}'
        )

    svg = render_svg_timeline(checks, markers)

    return f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="0">
<title>Dashboard {team}/{service}</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 16px;color:#222;background:#f7f6f2}}
 h1{{font-size:20px}} .muted{{color:#777;font-size:13px}}
 .status{{font-size:28px;font-weight:700;margin:6px 0}}
 .status.unknown{{color:#888}}
 .card{{background:#fff;border:1px solid #ddd;border-radius:10px;padding:16px;margin:12px 0}}
 .fails{{margin-top:8px;font-size:13px;background:#fdecea;border-radius:8px;padding:8px 12px;color:#842029}}
 .fails ul{{margin:4px 0 0 18px;padding:0}}
 .round-badge{{display:inline-block;background:#eee;border-radius:999px;padding:2px 10px;font-size:13px}}
 svg{{display:block;margin-top:8px}}
 footer{{font-size:12px;color:#999;margin-top:18px}}
</style>
</head>
<body>
<h1>Dashboard SVC -- team <code>{team}</code> / <code>{service}</code>
  <span class="round-badge">Round hiện tại: {current_round}</span></h1>
<p class="muted">Chỉ hiển thị dữ liệu của <b>team {team}</b> -- không thấy được team kia (đúng tinh thần ROUND_GUIDE.md).
Trang tự load lại mỗi 5 giây.</p>
<div class="card">{status_html}</div>
<div class="card"><b>Timeline SVC theo từng vòng check</b> (cột xanh/vàng/đỏ, đường đứt = mốc round mới)<br>{svg}</div>
<footer>Cập nhật lúc {now.strftime('%H:%M:%S')} -- dừng bằng Ctrl+C ở cửa sổ đang chạy dashboard.py</footer>
<script>setTimeout(()=>location.reload(), 5000);</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    team = "a"
    service = "notevault"
    jsonl_path = ""

    def log_message(self, *args):
        pass  # im lặng, đỡ rối terminal

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            checks, markers = read_records(self.jsonl_path)
            payload = {
                "team": self.team,
                "service": self.service,
                "checks": checks[-MAX_BARS:],
                "markers": markers,
            }
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        checks, markers = read_records(self.jsonl_path)
        html = render_page(self.team, self.service, checks, markers).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def main():
    ap = argparse.ArgumentParser(description="Dashboard xem SVC của CHÍNH team mình theo thời gian (notevault).")
    ap.add_argument("--team", required=True, help="Tên team (vd a, b) -- đúng tên đã dùng với spin.sh")
    ap.add_argument("--service", default="notevault")
    ap.add_argument("--runtime-dir", default=".runtime", help="Thư mục .runtime của services-practice (chạy script từ đúng thư mục services-practice/)")
    ap.add_argument("--port", type=int, default=None, help="Mặc định 8800 + lệch theo team (a=8800, b=8810...)")
    ap.add_argument("--bind", default="0.0.0.0",
                     help="Địa chỉ lắng nghe -- mặc định 0.0.0.0 để đồng đội mở được từ laptop khác qua IP LAN "
                          "của máy host. Đặt 127.0.0.1 nếu chỉ muốn xem trên chính máy đang chạy.")
    args = ap.parse_args()

    port = args.port if args.port is not None else 8800 + team_offset(args.team) * 10
    jsonl_path = os.path.join(args.runtime_dir, f"{args.team}_{args.service}", "healthcheck.jsonl")

    Handler.team = args.team
    Handler.service = args.service
    Handler.jsonl_path = jsonl_path

    print(f"[*] Dashboard team {args.team}/{args.service} -- đọc: {jsonl_path}")
    print(f"[*] Trên máy này mở: http://127.0.0.1:{port}/")
    if args.bind != "127.0.0.1":
        print(f"[*] Đồng đội mở từ laptop khác (cùng LAN/Wi-Fi): http://<IP-LAN-cua-may-nay>:{port}/")
    print("[*] Ctrl+C để dừng.")
    if not os.path.isfile(jsonl_path):
        print(f"[!] Chưa thấy {jsonl_path} -- chạy `./spin.sh up {args.team} {args.service}` và "
              f"healthcheck_notevault.py trước, dashboard sẽ tự cập nhật khi có dữ liệu.")

    server = ThreadingHTTPServer((args.bind, port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dừng dashboard.")


if __name__ == "__main__":
    main()

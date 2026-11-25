#!/usr/bin/env python3
"""
IBOH 2026 AD — File Share Server  (chỉ dùng thư viện chuẩn, KHÔNG cần cài gì)

Chạy trên MÁY BẠN (laptop) để:
  1) Đồng đội trong VPN truyền/nhận file cho nhau (thay cho app nhắn tin bị CẤM).
  2) Vulnbox `curl` LÊN để lấy file vá / exploit đưa lên máy chủ.
  3) Vulnbox `curl -T` ĐẨY NGƯỢC file (binary/service cần phân tích) VỀ máy bạn.

==========================  BẢO MẬT (ĐỌC KỸ)  ==========================
VPN giải đấu DÙNG CHUNG với đối thủ: bạn reach 10.10.x.x của họ  =>  họ
cũng reach được máy bạn. Vì vậy server NÀY bắt buộc có TOKEN bí mật.
  - KHÔNG đặt flag, private key, hay writeup nhạy cảm lên thư mục share.
  - TÁCH QUYỀN: mặc định sinh RIÊNG "token ĐỌC" (tải về/liệt kê) và "token GHI"
    (upload). Vulnbox CHỈ cần token ĐỌC -> nếu vulnbox bị chiếm, token lộ cũng
    KHÔNG upload/đầu độc được file vá. Chạy --read-only để cấm upload hẳn.
  - OPSEC: tốt nhất vulnbox dùng SSH (cat/base64), ĐỪNG để token chạm vulnbox.
    Token lộ qua `ps`/`/proc/<pid>/cmdline` và history khi curl trên box.
  - Giới hạn IP đồng đội bằng --allow (CIDR/IP) -> token lộ cũng khó dùng từ máy lạ.
  - Token in ra khi khởi động; chia qua kênh an toàn; đổi token khi nghi box bị thủng.
=======================================================================

VÍ DỤ CHẠY (chọn IP của card VPN, ví dụ tun0):
  python3 fileshare.py --host 10.10.1.50 --port 8000 --dir ./share
  # hoặc nghe mọi card rồi tự giới hạn bằng --allow:
  python3 fileshare.py --host 0.0.0.0 --port 8000 --allow 10.10.1.0/24

VÍ DỤ DÙNG (thay <H>=host, <P>=port, <T>=token):
  # Vulnbox LẤY file vá về:   (chạy TRÊN vulnbox)
  curl -s "http://<H>:<P>/f/patch.py?t=<T>" -o patch.py
  # Vulnbox ĐẨY binary VỀ máy bạn để phân tích:   (chạy TRÊN vulnbox)
  curl -s -T /path/to/svc "http://<H>:<P>/u/svc?t=<T>"
  # Đồng đội tải lên từ laptop khác:
  curl -s -T exploit.py "http://<H>:<P>/u/exploit.py?t=<T>"
  # Liệt kê file:
  curl -s "http://<H>:<P>/ls?t=<T>"
  # Hoặc mở trình duyệt:  http://<H>:<P>/?t=<T>
"""
import argparse
import hmac
import html
import ipaddress
import os
import re
import secrets
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAFE_NAME = re.compile(r'^[A-Za-z0-9._-]{1,128}$')
CHUNK = 256 * 1024


def sanitize(name: str):
    """Chỉ cho phép tên file an toàn, chặn path traversal."""
    name = os.path.basename((name or '').strip())
    if not name or name in ('.', '..') or not SAFE_NAME.match(name):
        return None
    return name


def human(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f}{unit}' if unit == 'B' else f'{n/1 if unit=="B" else n:.1f}{unit}'
        n /= 1024
    return f'{n:.1f}GB'


class Handler(BaseHTTPRequestHandler):
    server_version = 'ADShare/1.0'
    protocol_version = 'HTTP/1.1'

    # ---- helpers ----
    def cfg(self):
        return self.server  # type: ignore[attr-defined]

    def client_allowed(self) -> bool:
        allow = self.cfg().allow_nets
        if not allow:
            return True
        try:
            ip = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        return any(ip in net for net in allow)

    def provided_token(self) -> str:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        return (qs.get('t', [''])[0]) or self.headers.get('X-Token', '')

    def token_ok(self, need_write: bool) -> bool:
        tok = self.provided_token()
        cfg = self.cfg()
        if need_write:
            return cfg.write_token is not None and hmac.compare_digest(tok, cfg.write_token)
        # Đọc: chấp nhận token-đọc HOẶC token-ghi.
        if hmac.compare_digest(tok, cfg.read_token):
            return True
        return cfg.write_token is not None and hmac.compare_digest(tok, cfg.write_token)

    def guard(self, need_write: bool = False) -> bool:
        """Trả True nếu được phép đi tiếp; nếu không, đã tự gửi lỗi."""
        if not self.client_allowed():
            self.send_text(403, 'IP khong nam trong danh sach cho phep (--allow).\n')
            return False
        if need_write and self.cfg().read_only:
            self.send_text(403, 'Server dang READ-ONLY (--read-only): cam upload.\n')
            return False
        if not self.token_ok(need_write):
            self.send_text(401, 'Thieu hoac sai token' + (' GHI (write)' if need_write else '')
                           + '. Them ?t=TOKEN hoac header X-Token.\n')
            return False
        return True

    def send_text(self, code: int, body: str, ctype='text/plain; charset=utf-8'):
        data = body.encode('utf-8', 'replace')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def path_for(self, name: str):
        """Trả đường dẫn tuyệt đối an toàn trong thư mục share, hoặc None."""
        safe = sanitize(name)
        if not safe:
            return None, None
        base = self.cfg().share_dir
        full = os.path.realpath(os.path.join(base, safe))
        if os.path.commonpath([full, base]) != base:
            return None, None
        return safe, full

    # ---- routing ----
    def do_GET(self):
        if not self.guard():
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path.rstrip('/') or '/'
        if route == '/ping':
            return self.send_text(200, 'ok\n')
        if route == '/ls':
            return self.list_text()
        if route == '/':
            return self.index_html(parsed.query)
        if route.startswith('/f/'):
            return self.download(route[len('/f/'):])
        self.send_text(404, 'Khong co route. Dung /, /ls, /f/<ten>, /u/<ten>\n')

    def do_PUT(self):
        if not self.guard(need_write=True):
            return
        route = urllib.parse.urlparse(self.path).path.rstrip('/')
        if route.startswith('/u/'):
            return self.upload(route[len('/u/'):])
        self.send_text(404, 'Upload dung PUT/POST toi /u/<ten>\n')

    do_POST = do_PUT  # cho phép POST --data-binary luôn

    # ---- actions ----
    def list_text(self):
        base = self.cfg().share_dir
        rows = []
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            if os.path.isfile(p):
                rows.append(f'{name}\t{os.path.getsize(p)}')
        self.send_text(200, ('\n'.join(rows) + '\n') if rows else '(trong)\n')

    def download(self, name: str):
        safe, full = self.path_for(name)
        if not full or not os.path.isfile(full):
            return self.send_text(404, 'Khong tim thay file.\n')
        size = os.path.getsize(full)
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(size))
        self.send_header('Content-Disposition', f'attachment; filename="{safe}"')
        self.end_headers()
        try:
            with open(full, 'rb') as f:
                while True:
                    buf = f.read(CHUNK)
                    if not buf:
                        break
                    self.wfile.write(buf)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.log_action('GET', safe, size)

    def upload(self, name: str):
        safe, full = self.path_for(name)
        if not full:
            return self.send_text(400, 'Ten file khong hop le (chi [A-Za-z0-9._-], toi da 128).\n')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = -1
        if length < 0:
            return self.send_text(411, 'Can Content-Length.\n')
        if length > self.cfg().max_bytes:
            return self.send_text(413, f'File qua lon (toi da {self.cfg().max_bytes} byte).\n')
        tmp = full + f'.part-{secrets.token_hex(4)}'
        got = 0
        try:
            with open(tmp, 'wb') as f:
                remaining = length
                while remaining > 0:
                    buf = self.rfile.read(min(CHUNK, remaining))
                    if not buf:
                        break
                    f.write(buf)
                    got += len(buf)
                    remaining -= len(buf)
            os.replace(tmp, full)
        except Exception as exc:  # noqa: BLE001
            try:
                os.remove(tmp)
            except OSError:
                pass
            return self.send_text(500, f'Loi ghi file: {exc}\n')
        self.log_action('PUT', safe, got)
        self.send_text(200, f'OK {safe} ({got} byte)\n')

    def index_html(self, query: str):
        base = self.cfg().share_dir
        tok = urllib.parse.parse_qs(query).get('t', [''])[0]
        qt = '?t=' + urllib.parse.quote(tok) if tok else ''
        files = sorted(n for n in os.listdir(base) if os.path.isfile(os.path.join(base, n)))
        rows = ''.join(
            f'<li><a href="/f/{html.escape(urllib.parse.quote(n))}{qt}">{html.escape(n)}</a> '
            f'<small>({human(os.path.getsize(os.path.join(base, n)))})</small></li>'
            for n in files
        ) or '<li><em>(chưa có file)</em></li>'
        page = f'''<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Share</title>
<style>body{{font-family:system-ui,sans-serif;max-width:720px;margin:24px auto;padding:0 14px;background:#0d1117;color:#e6edf3}}
a{{color:#58a6ff}}h2{{margin:18px 0 6px}}li{{margin:4px 0}}code{{background:#161b22;padding:2px 6px;border-radius:5px}}
input,button{{font:inherit;padding:6px 10px;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#e6edf3}}
button{{cursor:pointer}}#log{{color:#7ee787;font-size:13px;margin-top:8px}}</style></head>
<body><h2>📁 AD File Share (nội bộ VPN)</h2>
<p>Share qua token. <b>Đừng đặt flag/secret ở đây.</b></p>
<h2>Tải lên</h2>
<input type="file" id="file"><button onclick="up()">Gửi lên</button><div id="log"></div>
<h2>File hiện có</h2><ul>{rows}</ul>
<h2>Dùng bằng curl (trên vulnbox)</h2>
<p>Lấy về: <code>curl "http://HOST:PORT/f/TÊN{html.escape(qt)}" -o TÊN</code><br>
Đẩy lên: <code>curl -T FILE "http://HOST:PORT/u/FILE{html.escape(qt)}"</code></p>
<script>
const qt={tok!r};
async function up(){{
  const f=document.getElementById('file').files[0]; if(!f){{return}}
  const r=await fetch('/u/'+encodeURIComponent(f.name)+(qt?'?t='+encodeURIComponent(qt):''),
    {{method:'PUT',body:f}});
  document.getElementById('log').textContent=await r.text();
  if(r.ok) setTimeout(()=>location.reload(),600);
}}
</script></body></html>'''
        self.send_text(200, page, 'text/html; charset=utf-8')

    # ---- logging ----
    def log_action(self, verb: str, name: str, size: int):
        sys.stderr.write(f'[{self.client_address[0]}] {verb} {name} {size}B\n')

    def log_message(self, *args):  # tắt log mặc định (ồn)
        pass


def detect_ips():
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def main():
    ap = argparse.ArgumentParser(description='IBOH 2026 AD file share (stdlib).')
    ap.add_argument('--host', default='0.0.0.0', help='IP để nghe (nên là IP card VPN, vd 10.10.1.50)')
    ap.add_argument('--port', type=int, default=8000)
    ap.add_argument('--dir', default='./share', help='Thư mục share (tự tạo)')
    ap.add_argument('--token', default='', help='Token DÙNG CHUNG đọc+ghi (bỏ trống = sinh RIÊNG mỗi loại)')
    ap.add_argument('--read-token', default='', help='Token chỉ TẢI VỀ/liệt kê (đưa cho vulnbox kéo patch)')
    ap.add_argument('--write-token', default='', help='Token để UPLOAD (chỉ đồng đội giữ)')
    ap.add_argument('--read-only', action='store_true', help='Cấm upload hoàn toàn (chỉ phục vụ tải về)')
    ap.add_argument('--allow', action='append', default=[], metavar='CIDR',
                    help='Giới hạn IP nguồn (CIDR/IP), lặp nhiều lần. Bỏ trống = mọi IP (vẫn cần token).')
    ap.add_argument('--max-mb', type=int, default=300, help='Dung lượng tối đa mỗi upload (MB)')
    args = ap.parse_args()

    share = os.path.realpath(args.dir)
    os.makedirs(share, exist_ok=True)
    # Mặc định: token đọc và token ghi KHÁC NHAU (tách quyền). --token để dùng chung (cũ).
    read_token = args.read_token or args.token or secrets.token_urlsafe(12)
    write_token = None if args.read_only else (args.write_token or args.token or secrets.token_urlsafe(12))
    nets = []
    for c in args.allow:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            print(f'[!] Bỏ qua --allow không hợp lệ: {c}', file=sys.stderr)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.share_dir = share           # type: ignore[attr-defined]
    httpd.read_token = read_token     # type: ignore[attr-defined]
    httpd.write_token = write_token   # type: ignore[attr-defined]
    httpd.read_only = args.read_only  # type: ignore[attr-defined]
    httpd.allow_nets = nets           # type: ignore[attr-defined]
    httpd.max_bytes = args.max_mb * 1024 * 1024  # type: ignore[attr-defined]

    shown = args.host if args.host not in ('0.0.0.0', '') else (detect_ips()[0] if detect_ips() else '<IP-VPN>')
    bar = '=' * 62
    print(bar)
    print(' AD FILE SHARE đang chạy')
    print(f'  Thư mục : {share}')
    print(f'  Nghe tại: {args.host}:{args.port}   (max {args.max_mb}MB/upload)')
    print(f'  TOKEN ĐỌC (tải về/liệt kê — có thể đưa vulnbox): {read_token}')
    if write_token is None:
        print('  TOKEN GHI : (READ-ONLY — cấm upload)')
    else:
        print(f'  TOKEN GHI (upload — chỉ đồng đội giữ)        : {write_token}')
    if nets:
        print(f'  Cho phép: {", ".join(str(n) for n in nets)}')
    else:
        print('  Cho phép: MỌI IP (chỉ chặn bằng token — nhớ VPN có cả đối thủ!)')
    print(bar)
    print(' Mở trình duyệt :  http://%s:%d/?t=%s   (token GHI để upload được)' % (shown, args.port, write_token or read_token))
    print(' LẤY (token đọc):  curl "http://%s:%d/f/TÊN?t=%s" -o TÊN' % (shown, args.port, read_token))
    print(' Liệt kê (đọc)  :  curl "http://%s:%d/ls?t=%s"' % (shown, args.port, read_token))
    if write_token is not None:
        print(' ĐẨY (token ghi):  curl -T FILE "http://%s:%d/u/FILE?t=%s"' % (shown, args.port, write_token))
    print(bar)
    print(' Mẹo OPSEC: vulnbox CHỈ cần TOKEN ĐỌC; chạy read-only cho vulnbox:')
    print('   python3 fileshare.py --host %s --read-only --read-token %s' % (args.host, read_token))
    print(bar)
    print(' Ctrl+C để dừng.')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nĐã dừng.')
        httpd.shutdown()


if __name__ == '__main__':
    main()

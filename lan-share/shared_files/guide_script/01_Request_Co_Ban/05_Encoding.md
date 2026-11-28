# Encoding / Decoding

## Snippet copy-là-chạy

```python
import base64
import binascii
from urllib.parse import quote, quote_plus, unquote, unquote_plus
from requests.models import PreparedRequest
import requests

s = "a+b c/=?&"
print(quote(s))        # a%2Bb%20c/%3D%3F%26  (path/query an toàn)
print(quote_plus(s))   # a%2Bb+c%2F%3D%3F%26  (form style, space -> +)
print(unquote("a%2Bb%20c"))

# Base64 / Hex
raw = b"admin:password"
b64 = base64.b64encode(raw).decode()
hx = binascii.hexlify(raw).decode()
print(b64, hx)
print(base64.b64decode(b64))
print(binascii.unhexlify(hx))

# Tránh encode 2 lần: payload đã encode sẵn thì gửi raw URL
payload = "%27%20OR%201=1--%20"
req = requests.Request("GET", f"http://target/search?q={payload}").prepare()
r = requests.Session().send(req, timeout=5)
print(r.request.url)
```

## Giải thích cho người mới
- "Encode" = đổi ký tự đặc biệt (dấu cách, `+`, `&`...) thành dạng `%XX` an toàn để nhét vào URL — giống việc Burp tự hiển thị `%20` thay cho dấu cách. `quote()`/`quote_plus()` làm việc đó; `unquote()`/`unquote_plus()` làm ngược lại (giải mã).
- `quote_plus` encode dấu cách thành `+` (kiểu query/form); `quote` giữ dấu cách thành `%20` (kiểu path) — nhìn vào Burp xem URL dùng `+` hay `%20` để chọn đúng hàm.
- Base64/Hex không phải để "ẩn giấu" mà là 2 cách biểu diễn dữ liệu nhị phân bằng chữ — hay gặp khi cookie/token/param là chuỗi base64, hoặc cần encode payload trước khi gửi.
- **Khối cuối**: nếu payload bạn copy từ Burp **đã chứa sẵn** `%27`, `%20`... (đã encode rồi), đừng đưa nó vào `params={"q": payload}` — vì requests sẽ encode thêm 1 lần nữa, biến `%27` thành `%2527` (sai). Cách đúng là ghép thẳng vào URL rồi gửi qua `Request(...).prepare()` như snippet trên, để giữ nguyên y những gì bạn đã có.

## Lưu ý nhanh
- `quote_plus` cho form/query kiểu `+`; `quote` an toàn hơn cho path segment.
- Nếu bạn đã có `%2f` mà truyền vào `params=`, requests có thể encode dấu `%` thành `%252f`.
- Khi nghi encode lỗi: in `r.request.url` và `r.request.body` rồi so với Burp.
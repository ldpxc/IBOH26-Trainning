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

## Lưu ý nhanh
- `quote_plus` cho form/query kiểu `+`; `quote` an toàn hơn cho path segment.
- Nếu bạn đã có `%2f` mà truyền vào `params=`, requests có thể encode dấu `%` thành `%252f`.
- Khi nghi encode lỗi: in `r.request.url` và `r.request.body` rồi so với Burp.
# Burp được, Python không

## Snippet copy-là-chạy

```python
import requests
from requests.models import PreparedRequest

s = requests.Session()
s.verify = False
s.headers.update({"User-Agent": "Mozilla/5.0"})  # copy từ Burp nếu cần

# So URL/body đúng từng byte
req = PreparedRequest()
req.prepare_method("GET")
req.prepare_url("http://target/search?q=a%2Bb", None)  # raw query
req.prepare_headers({"Accept": "*/*"})
resp = s.send(req, timeout=5)

print(resp.status_code)
print(resp.request.method, resp.request.url)
print(resp.request.headers)
print(resp.request.body)
```

## Lưu ý nhanh
- Kiểm tra theo thứ tự: URL, method, headers, cookie, body, redirect, TLS/proxy.
- Burp thường tự thêm/sửa header; Python cũng vậy. So raw request thực tế.
- Nếu body là form/JSON/multipart, chênh 1 ký tự `Content-Type` cũng có thể gây khác.
# Gặp WAF 403

## Snippet copy-là-chạy

```python
import requests
from requests.models import PreparedRequest

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Thử đổi User-Agent/header
headers = {"User-Agent": "Mozilla/5.0"}
r = s.get(f"{base}/vuln?id=1", headers=headers, timeout=4)
print(r.status_code)

# 2) Thử đổi format body (form <-> json) nếu backend chấp nhận
r = s.post(f"{base}/login", json={"username": "admin", "password": "admin"}, timeout=4)
print("json", r.status_code)
r = s.post(f"{base}/login", data={"username": "admin", "password": "admin"}, timeout=4)
print("form", r.status_code)

# 3) Raw URL khi nghi encode bị xử lý khác
req = PreparedRequest()
req.prepare("GET", f"{base}/search?q=test%2F..", headers=headers)
r = s.send(req, timeout=4)
print(r.request.url, r.status_code)
```

## Lưu ý nhanh
- Đổi **1 biến mỗi lần**: header, Content-Type, encoding, vị trí param. So với request baseline.
- `403` có thể do WAF parser khác app parser (form/json/HPP/encode). Không retry spam.
- Đối chiếu request Python với Burp Repeater; giữ `timeout` ngắn và `workers` nhỏ khi mass.
# POST Form / JSON / Raw

## Snippet copy-là-chạy

```python
import json
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) POST form (application/x-www-form-urlencoded)
r = s.post(f"{base}/login", data={"username": "admin", "password": "admin"}, timeout=5)
print(r.status_code)

# 2) POST JSON
r = s.post(f"{base}/api/login", json={"username": "admin", "password": "admin"}, timeout=5)
print(r.status_code, r.headers.get("Content-Type"))

# 3) POST raw body (tự kiểm soát đúng từng byte/chuỗi)
raw = '{"id":1,"role":"admin"}'
r = s.post(
    f"{base}/api/update",
    data=raw.encode("utf-8"),
    headers={"Content-Type": "application/json"},
    timeout=5,
)
print(r.status_code, r.text[:200])
```

## Lưu ý nhanh
- Dùng `data=` cho form/raw bytes/string; dùng `json=` cho JSON (requests tự set header + serialize).
- Nếu Burp chạy được mà Python không: copy đúng `Content-Type` và body y hệt từ Burp.
- Muốn gửi JSON “xấu/không chuẩn” để test parser, dùng `data=` thay vì `json=`.
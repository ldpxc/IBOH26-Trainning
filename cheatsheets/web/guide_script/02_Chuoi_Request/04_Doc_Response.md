# Đọc Response

## Snippet copy-là-chạy

```python
import json
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False
r = s.get(f"{base}/api/me", allow_redirects=False, timeout=5)

# Status / headers
print(r.status_code)
print(r.headers.get("Location"))
print(r.headers.get("Content-Type"))

# JSON
try:
    data = r.json()
    print(data.get("username"))
except json.JSONDecodeError:
    data = None

# Text / regex / flag
print(r.text[:300])
m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r.text)
if m:
    print("FLAG", m.group(0))

# Cookie do server set
print(r.cookies.get_dict())
print(r.headers.get("Set-Cookie"))
```

## Lưu ý nhanh
- `r.json()` sẽ lỗi nếu body không phải JSON; luôn bọc `try/except` khi không chắc.
- Flag/token đôi khi nằm ở header, redirect, hoặc HTML comment, không chỉ body.
- Khi debug, xem `r.request.headers` và `r.request.body` để chắc Python gửi đúng.
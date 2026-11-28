# Lấy CSRF Token

## Snippet copy-là-chạy

```python
import re
import requests
from bs4 import BeautifulSoup

base = "http://target"
s = requests.Session()
s.verify = False

# 1) GET trang chứa form
r = s.get(f"{base}/login", timeout=5)

# 2) Cách nhanh bằng regex
m = re.search(r'name=["\']csrf(?:_token)?["\'][^>]*value=["\']([^"\']+)', r.text, re.I)
token = m.group(1) if m else None

# 3) Cách chắc hơn bằng BeautifulSoup
soup = BeautifulSoup(r.text, "html.parser")
inp = soup.select_one('input[name="csrf"], input[name="csrf_token"], input[name="csrfmiddlewaretoken"]')
token = token or (inp.get("value") if inp else None)
print(token)

# 4) Dán token vào request POST
r = s.post(f"{base}/login", data={"username": "admin", "password": "admin", "csrf": token}, timeout=5)
print(r.status_code)
```

## Lưu ý nhanh
- Phải GET bằng **cùng session** sẽ dùng để POST, vì token thường gắn với cookie/session.
- Tên field hay gặp: `csrf`, `csrf_token`, `_token`, `csrfmiddlewaretoken`.
- Nếu token nằm trong JS/meta/header, dùng regex tìm đúng key trong response.
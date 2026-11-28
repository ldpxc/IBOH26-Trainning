# GET + Query

## Snippet copy-là-chạy

```python
import requests
from urllib.parse import urlencode
from requests.models import PreparedRequest

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Query thường
r = s.get(f"{base}/search", params={"q": "test", "page": 1}, timeout=5)
print(r.status_code, r.url)

# 2) Tham số trùng tên / giữ nguyên thứ tự query
query = urlencode([("id", "1"), ("id", "2"), ("debug", "true")])
url = f"{base}/api/item?{query}"
r = s.get(url, timeout=5)
print(r.url)

# 3) Gửi raw URL đã encode sẵn (tránh requests tự xử lý lại)
req = requests.Request("GET", f"{base}/search?q=a%2Bb%20c").prepare()
r = s.send(req, timeout=5)
print(r.request.url)
```

## Lưu ý nhanh
- `params=dict` không giữ thứ tự/trùng key tốt; dùng `list[tuple]` + `urlencode(...)`.
- Khi payload đã encode sẵn, đừng đưa vào `params=` lần nữa nếu không muốn encode hai lần.
- So URL cuối ở `r.url` / `r.request.url` với Burp.
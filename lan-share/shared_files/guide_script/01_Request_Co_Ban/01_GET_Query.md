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

## Giải thích cho người mới
- **Khối 1**: `s.get(url, params={...})` = gửi GET tới `url` kèm query string; `requests` tự ghép thành `?q=test&page=1` và tự encode ký tự đặc biệt. `r.url` là URL thật đã gửi, dùng để so với Burp.
- **Khối 2**: dict không giữ được 2 key trùng tên (`id=1&id=2`), nên dùng `list[("id","1"),("id","2")]` rồi tự ghép chuỗi query bằng `urlencode(...)`, cuối cùng nối vào URL bằng f-string.
- **Khối 3**: khi bạn đã có payload encode sẵn (copy thẳng từ Burp), đưa trực tiếp vào chuỗi URL rồi dùng `requests.Request(...).prepare()` + `s.send(...)` để requests gửi đúng y chuỗi đó, không tự encode thêm lần nữa.

## Lưu ý nhanh
- `params=dict` không giữ thứ tự/trùng key tốt; dùng `list[tuple]` + `urlencode(...)`.
- Khi payload đã encode sẵn, đừng đưa vào `params=` lần nữa nếu không muốn encode hai lần.
- So URL cuối ở `r.url` / `r.request.url` với Burp.
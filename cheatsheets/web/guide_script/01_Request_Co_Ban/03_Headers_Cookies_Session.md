# Headers / Cookies / Session

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False
s.headers.update({"User-Agent": "Mozilla/5.0", "Accept": "*/*"})

# 1) Header riêng cho request này
r = s.get(f"{base}/profile", headers={"X-Debug": "1"}, timeout=5)
print(r.status_code)

# 2) Cookie trong session (tự giữ qua các request)
s.get(f"{base}/", timeout=5)
print(s.cookies.get_dict())

# 3) Set cookie thủ công khi cần
s.cookies.set("session", "abc123", domain="target")
r = s.get(f"{base}/admin", timeout=5)
print(r.status_code)

# 4) Tắt redirect để bắt Set-Cookie / Location
r = s.post(f"{base}/login", data={"u": "a", "p": "b"}, allow_redirects=False, timeout=5)
print(r.status_code, r.headers.get("Location"), r.headers.get("Set-Cookie"))
```

## Lưu ý nhanh
- `Session()` giữ cookie tự động; đừng tạo `requests.get()` rời nếu cần đăng nhập.
- `allow_redirects=False` để quan sát response 302/303 thật từ server.
- Header `Host`, `Content-Length` thường để requests tự xử lý; đừng set bừa.
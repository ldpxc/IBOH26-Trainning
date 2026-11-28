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

## Giải thích cho người mới
- `s = requests.Session()` tạo 1 "phiên làm việc" nhớ cookie giữa các request, giống việc Burp tự giữ cookie xuyên suốt các tab — dùng `s.get/s.post` (không dùng `requests.get` rời) suốt cả bài.
- `s.headers.update({...})` đặt header dùng chung cho **mọi** request gửi từ `s` về sau (ví dụ User-Agent); `headers={...}` truyền riêng vào 1 lệnh `s.get(...)` chỉ áp dụng cho request đó.
- **Khối 2**: sau khi gọi `s.get(...)`, cookie server set (`Set-Cookie`) tự động nằm trong `s.cookies` — không cần tự đọc header rồi set lại.
- **Khối 3**: `s.cookies.set(...)` dùng khi bạn muốn tự gán cookie (ví dụ copy thẳng giá trị session từ Burp để tái hiện 1 phiên đã đăng nhập, không cần login lại).
- **Khối 4**: `allow_redirects=False` để requests **không tự đi theo** redirect 302 — nhờ đó bạn thấy đúng status 302 gốc và header `Location`/`Set-Cookie` của chính response đó, giống hệt những gì Burp hiển thị khi tắt "follow redirects".

## Lưu ý nhanh
- `Session()` giữ cookie tự động; đừng tạo `requests.get()` rời nếu cần đăng nhập.
- `allow_redirects=False` để quan sát response 302/303 thật từ server.
- Header `Host`, `Content-Length` thường để requests tự xử lý; đừng set bừa.
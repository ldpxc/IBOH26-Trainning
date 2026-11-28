# Login + Giữ phiên

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Login form
r = s.post(f"{base}/login", data={"username": "admin", "password": "admin"}, timeout=5)
print(r.status_code, s.cookies.get_dict())

# 2) Dùng lại session đã có cookie cho request sau
r = s.get(f"{base}/dashboard", timeout=5)
print(r.status_code, "FLAG" in r.text)

# 3) Nếu app trả token JSON thay vì cookie
resp = s.post(f"{base}/api/login", json={"username": "admin", "password": "admin"}, timeout=5).json()
token = resp["token"]  # sửa key theo response thật
s.headers["Authorization"] = f"Bearer {token}"
r = s.get(f"{base}/api/me", timeout=5)
print(r.status_code, r.text[:200])
```

## Giải thích cho người mới
- **Khối 1**: gửi POST login giống hệt bài [`01_Request_Co_Ban/02_POST_Form_JSON.md`](../01_Request_Co_Ban/02_POST_Form_JSON.md). Sau lệnh này, nếu login đúng, server trả `Set-Cookie` và `s.cookies.get_dict()` sẽ có giá trị khác rỗng (ví dụ `session=...`) — in ra để tự kiểm chứng login thật sự thành công, đừng chỉ tin status 200.
- **Khối 2**: vẫn dùng **cùng biến `s`** cho request tiếp theo — cookie login ở bước 1 tự được gửi kèm, không cần set tay. Đây là lý do mọi bài trong `02_Chuoi_Request/` đều dùng 1 `Session()` xuyên suốt, không tạo session mới giữa các bước.
- **Khối 3**: một số app không dùng cookie mà trả `token` trong JSON (xem trong tab Response của Burp) — khi đó phải tự đọc `resp["token"]` rồi gắn vào header `Authorization` cho các request sau, vì `Session()` không tự làm việc này.

## Lưu ý nhanh
- Luôn dùng chung một `requests.Session()` cho toàn bộ chuỗi request.
- Login xong phải kiểm tra: status, cookie/token, và có truy cập được trang sau login không.
- Nếu có CSRF, lấy token trước khi POST login (xem `02_Lay_CSRF_Token.md`).
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

## Giải thích cho người mới
- **Khối 1**: `data={...}` gửi body dạng `username=admin&password=admin` với header `Content-Type: application/x-www-form-urlencoded` — đúng với form HTML thường (`<form method="post">`).
- **Khối 2**: `json={...}` tự chuyển dict thành chuỗi JSON và tự thêm header `Content-Type: application/json` — dùng khi Burp cho thấy body request là `{"key": "value"}`.
- **Khối 3**: khi cần gửi body chính xác từng ký tự (ví dụ test JSON lỗi cú pháp có chủ đích, hoặc copy nguyên body từ Burp), dùng `data=chuoi.encode(...)` kèm tự set `headers=` — khi đó requests không tự sửa gì cả, gửi đúng y bạn viết.
- Việc chọn `data=` hay `json=` phụ thuộc đúng 1 thứ: **Content-Type trong request của Burp** — thấy `application/json` thì dùng `json=`, thấy `application/x-www-form-urlencoded` thì dùng `data=`.

## Lưu ý nhanh
- Dùng `data=` cho form/raw bytes/string; dùng `json=` cho JSON (requests tự set header + serialize).
- Nếu Burp chạy được mà Python không: copy đúng `Content-Type` và body y hệt từ Burp.
- Muốn gửi JSON “xấu/không chuẩn” để test parser, dùng `data=` thay vì `json=`.
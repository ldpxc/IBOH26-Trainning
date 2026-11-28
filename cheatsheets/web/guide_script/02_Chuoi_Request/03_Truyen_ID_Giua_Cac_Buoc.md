# Truyền ID giữa các bước

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# Bước 1: tạo object / lấy ID từ JSON
r = s.post(f"{base}/api/jobs", json={"name": "test"}, timeout=5)
job = r.json()
job_id = job["id"]          # sửa key theo response thật
print(job_id)

# Bước 2: dùng ID ở request sau
r = s.get(f"{base}/api/jobs/{job_id}", timeout=5)
print(r.status_code, r.text[:200])

# Bước 3: nếu ID nằm trong HTML/redirect
r = s.get(f"{base}/profile", allow_redirects=False, timeout=5)
loc = r.headers.get("Location", "")
m = re.search(r"/users/(\d+)", loc or r.text)
user_id = m.group(1) if m else None
print(user_id)
```

## Giải thích cho người mới
- Nhiều bài có 2+ bước phụ thuộc nhau: bước 1 tạo ra 1 ID (của job, order, user...), bước 2 phải dùng đúng ID đó. Trên Burp bạn copy ID bằng tay từ response bước 1 dán vào URL bước 2 — trong script phải làm việc đó tự động.
- **Bước 1**: `r.json()` chuyển response JSON thành dict Python; `job["id"]` lấy giá trị theo đúng key tên `id` — key này phải khớp với response thật (xem trong Burp, có thể là `id`, `job_id`, `data.id`...).
- **Bước 2**: dùng f-string `f"{base}/api/jobs/{job_id}"` để nhúng ID vừa lấy vào URL, giống việc bạn tự sửa URL trong Burp Repeater rồi bấm gửi lại.
- **Bước 3**: nếu ID không nằm trong JSON mà nằm trong HTML hoặc header `Location` (redirect sau khi tạo object), dùng `re.search(...)` để trích số/ID ra từ chuỗi đó.
- Luôn in giá trị vừa lấy ra (`print(job_id)`) trước khi dùng ở bước sau — nếu `job_id` sai (`None`, rỗng, hoặc nhầm key), bước sau sẽ lỗi nhưng lỗi hiện ra lại nằm ở bước sau, dễ làm bạn tưởng nhầm chỗ.

## Lưu ý nhanh
- In `r.text[:300]` hoặc `r.json()` ngay sau bước 1 để xác nhận đúng key/đường dẫn ID.
- ID có thể nằm ở JSON, HTML, header `Location`, hoặc `Set-Cookie`.
- Nếu ID là UUID/token dài, copy nguyên chuỗi, đừng ép `int()`.
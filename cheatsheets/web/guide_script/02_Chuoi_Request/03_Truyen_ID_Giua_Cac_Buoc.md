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

## Lưu ý nhanh
- In `r.text[:300]` hoặc `r.json()` ngay sau bước 1 để xác nhận đúng key/đường dẫn ID.
- ID có thể nằm ở JSON, HTML, header `Location`, hoặc `Set-Cookie`.
- Nếu ID là UUID/token dài, copy nguyên chuỗi, đừng ép `int()`.
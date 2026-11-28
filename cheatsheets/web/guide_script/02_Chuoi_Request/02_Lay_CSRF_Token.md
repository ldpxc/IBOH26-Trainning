# Lấy CSRF Token

## Snippet copy-là-chạy

```python
import re
import requests
from bs4 import BeautifulSoup

base = "http://target"
s = requests.Session()
s.verify = False

# 1) GET trang chứa form
r = s.get(f"{base}/login", timeout=5)

# 2) Cách nhanh bằng regex
m = re.search(r'name=["\']csrf(?:_token)?["\'][^>]*value=["\']([^"\']+)', r.text, re.I)
token = m.group(1) if m else None

# 3) Cách chắc hơn bằng BeautifulSoup
soup = BeautifulSoup(r.text, "html.parser")
inp = soup.select_one('input[name="csrf"], input[name="csrf_token"], input[name="csrfmiddlewaretoken"]')
token = token or (inp.get("value") if inp else None)
print(token)

# 4) Dán token vào request POST
r = s.post(f"{base}/login", data={"username": "admin", "password": "admin", "csrf": token}, timeout=5)
print(r.status_code)
```

## Giải thích cho người mới
- CSRF token là 1 giá trị ẩn trong trang HTML (thường trong `<input type="hidden" name="csrf" value="xxxx">`), server sinh ra mỗi lần tải trang và yêu cầu gửi lại đúng giá trị đó khi submit form — nếu thiếu/sai, server trả lỗi 403/400 dù username/password đúng.
- **Khối 1**: phải GET trang login trước để **lấy** token mới, vì token đổi mỗi lần tải trang; không thể dùng lại token cũ từ lần chạy trước.
- **Khối 2-3**: 2 cách đọc token ra khỏi HTML — `re.search(...)` (regex, nhanh, dễ vỡ nếu HTML đổi cấu trúc) và `BeautifulSoup` (parse HTML đúng cấu trúc, ổn định hơn). `m.group(1)` nghĩa là lấy phần nằm trong `(...)` đầu tiên của regex (chính là giá trị token).
- **Khối 4**: dán `token` vừa lấy vào field tương ứng trong body POST login — đúng field name mà form HTML dùng (xem trong tab HTML/Burp request thật, không phải đoán).

## Lưu ý nhanh
- Phải GET bằng **cùng session** sẽ dùng để POST, vì token thường gắn với cookie/session.
- Tên field hay gặp: `csrf`, `csrf_token`, `_token`, `csrfmiddlewaretoken`.
- Nếu token nằm trong JS/meta/header, dùng regex tìm đúng key trong response.
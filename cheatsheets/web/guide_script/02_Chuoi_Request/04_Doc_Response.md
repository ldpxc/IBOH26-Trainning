# Đọc Response

## Snippet copy-là-chạy

```python
import json
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False
r = s.get(f"{base}/api/me", allow_redirects=False, timeout=5)

# Status / headers
print(r.status_code)
print(r.headers.get("Location"))
print(r.headers.get("Content-Type"))

# JSON
try:
    data = r.json()
    print(data.get("username"))
except json.JSONDecodeError:
    data = None

# Text / regex / flag
print(r.text[:300])
m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r.text)
if m:
    print("FLAG", m.group(0))

# Cookie do server set
print(r.cookies.get_dict())
print(r.headers.get("Set-Cookie"))
```

## Giải thích cho người mới
- Sau mỗi `r = s.get(...)`/`s.post(...)`, object `r` chứa toàn bộ response — tương đương toàn bộ những gì bạn thấy trong panel Response của Burp.
- `r.status_code` = số trạng thái (200, 302, 403...); `r.headers.get("Ten-Header")` = lấy 1 header, trả về `None` nếu không có (không lỗi) — an toàn hơn `r.headers["Ten-Header"]` (sẽ lỗi `KeyError` nếu thiếu).
- `r.json()` chỉ dùng được khi body **là JSON thật** — vì vậy luôn bọc `try/except`: nếu body là HTML (ví dụ trang lỗi 403 của WAF), `r.json()` sẽ raise lỗi, `except` bắt lại để script không dừng.
- `r.text[:300]` in 300 ký tự đầu của body — đủ để biết server trả HTML, JSON, hay trang lỗi, không cần in cả trang dài.
- `re.search(r"FHACKER2026\{...\}", r.text)` quét toàn bộ text tìm đúng định dạng flag; nếu tìm thấy, `m` là 1 object chứa kết quả, `m.group(0)` là chuỗi flag khớp được — nếu không tìm thấy, `m` là `None` (phải kiểm tra `if m:` trước khi gọi `.group()`, xem mục lỗi `NoneType` ở [`00_Bat_Dau_Tu_Zero.md`](../00_Bat_Dau_Tu_Zero.md)).
- `r.cookies.get_dict()` và `r.headers.get("Set-Cookie")` để xem server có set cookie mới không — hữu ích khi nghi flag/token nằm trong cookie thay vì body.

## Lưu ý nhanh
- `r.json()` sẽ lỗi nếu body không phải JSON; luôn bọc `try/except` khi không chắc.
- Flag/token đôi khi nằm ở header, redirect, hoặc HTML comment, không chỉ body.
- Khi debug, xem `r.request.headers` và `r.request.body` để chắc Python gửi đúng.
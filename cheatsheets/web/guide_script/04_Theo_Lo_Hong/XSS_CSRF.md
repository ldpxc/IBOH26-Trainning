# XSS / CSRF

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# XSS reflected test nhanh
payload = "<script>alert(1)</script>"
r = s.get(f"{base}/search", params={"q": payload}, timeout=5)
print(payload in r.text, r.status_code)

# CSRF: kiểm tra request nhạy cảm có cần token/cookie/origin không
r = s.get(f"{base}/profile", timeout=5)
has_csrf = "csrf" in r.text.lower()
print("has_csrf_hint", has_csrf)

# Gửi request đổi email/mật khẩu như PoC (chỉ trên mục tiêu được phép)
r = s.post(f"{base}/profile", data={"email": "a@b.com"}, timeout=5, allow_redirects=False)
print(r.status_code, r.headers.get("Location"))
```

## Lưu ý nhanh
- XSS: xác nhận reflection/context/encoding; payload phải phù hợp HTML/attr/JS.
- CSRF: so sánh request có/không có token, kiểm tra SameSite/cookie, Origin/Referer.
- Trong A/D, ưu tiên PoC ngắn gọn, không tự gây tác động phá người chơi khác.
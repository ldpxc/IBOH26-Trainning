# SSTI

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# Payload nhận diện an toàn, không phá hệ
probes = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
for p in probes:
    r = s.get(f"{base}/render", params={"name": p}, timeout=5)
    if "49" in r.text and p not in r.text:
        print("POSSIBLE SSTI", p)
        print(r.text[:200])
        break
    print(p, r.status_code)
```

## Lưu ý nhanh
- Bắt đầu bằng probe tính toán đơn giản; chỉ leo thang khi xác nhận engine.
- `49` xuất hiện nguyên trong input chưa chắc SSTI; cần thấy được đánh giá biểu thức.
- Payload khai thác RCE phụ thuộc engine (Jinja2/Twig/ERB...), copy đúng mẫu cho engine đó.
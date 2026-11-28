# Trích flag

## Snippet copy-là-chạy

```python
import re
import requests

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")
s = requests.Session(); s.verify = False
r = s.get("http://target/page", timeout=5)

# Từ text
flags = FLAG_RE.findall(r.text)

# Từ JSON/headers nếu flag không nằm ở body text thuần
blob = "\n".join([r.text, str(r.headers), str(r.cookies.get_dict())])
flags += FLAG_RE.findall(blob)

# Dedupe giữ thứ tự
flags = list(dict.fromkeys(flags))
print(flags)
```

## Lưu ý nhanh
- Luôn `re.findall`, không chỉ tìm 1 flag.
- Dùng regex đúng format flag giải đấu; có thể thêm fallback pattern khi cần.
- Lọc `OWN_FLAGS` trước khi in/lưu/nộp.
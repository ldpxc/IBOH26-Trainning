# Đọc WAF / Traffic Log

## Snippet copy-là-chạy

```python
from pathlib import Path
import re

LOG = Path("logs/waf.log")
bad = []

for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
    if re.search(r"\.(css|js|png|jpg|ico|woff2?)\b", line, re.I):
        continue
    if re.search(r"\b(403|POST|/admin|/login|union|select|\.\./)\b", line, re.I):
        bad.append(line)

for line in bad[-30:]:  # 30 dòng gần nhất đáng chú ý
    print(line)
```

## Lưu ý nhanh
- Khi DEF tụt, lọc 30s gần nhất hoặc 30 dòng cuối; ưu tiên path lạ, 403/200 bất thường, UA lạ, body có payload.
- Bỏ static assets (`.css .js .png ...`) và healthcheck để giảm nhiễu.
- Lấy request đáng ngờ đem replay qua Burp/`http_client` thủ công; không replay sang đội khác.
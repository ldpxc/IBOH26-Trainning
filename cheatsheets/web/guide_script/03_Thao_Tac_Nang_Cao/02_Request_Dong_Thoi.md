# Request đồng thời

## Snippet copy-là-chạy

```python
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

targets = ["http://10.0.2.1:8000", "http://10.0.3.1:8000"]
TIMEOUT = 4
WORKERS = 4

def hit(base):
    s = requests.Session()
    s.verify = False
    r = s.get(base + "/health", timeout=TIMEOUT)
    time.sleep(0.5)
    return base, r.status_code

with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futs = [ex.submit(hit, t) for t in targets]
    for fut in as_completed(futs):
        team, code = fut.result()
        print(team, code)
```

## Lưu ý nhanh
- Mỗi thread nên dùng `Session()` riêng để tránh lẫn cookie/header.
- A/D giữ `workers` nhỏ (3-5), có `timeout` và `sleep` để không làm sập service.
- Gặp 403/429/timeout: log rồi bỏ qua, đừng retry liên tục.
# Lặp danh sách đội từ targets.txt

## Snippet copy-là-chạy

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests

def load_targets(path="scripts/targets.txt"):
    out = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.upper().startswith("@OUR_TEAM"):
            continue
        if "://" not in line:
            line = "http://" + line
        host = line.split("//", 1)[-1].split("/", 1)[0].lower()
        if host in {"127.0.0.1", "localhost", "::1"}:
            continue
        out.append(line.rstrip("/"))
    return out

def hit(base):
    s = requests.Session(); s.verify = False
    r = s.get(base + "/", timeout=4)
    return base, r.status_code

targets = load_targets()
with ThreadPoolExecutor(max_workers=4) as ex:
    for fut in as_completed([ex.submit(hit, t) for t in targets]):
        print(fut.result())
```

## Lưu ý nhanh
- Luôn giữ `@OUR_TEAM` trong `targets.txt` và lọc localhost để không tự bắn đội nhà.
- Mỗi đội dùng `Session()` riêng; đừng share cookie.
- Dùng `workers=4`, `timeout=4`, `sleep` nhẹ để tránh quá tải.
# Gửi request cho nhiều đội cùng lúc (chạy song song)

Khi đã có script chạy đúng cho 1 đội, nếu chạy lần lượt (xong đội này mới sang đội kia) cho 20 đội sẽ rất chậm. Cách nhanh hơn: nhờ Python **mở nhiều "luồng" chạy cùng lúc** (gọi là thread — hiểu đơn giản là "nhiều bản sao của đoạn code đang chạy song song, mỗi bản lo 1 đội"), giống việc bạn mở 4-5 tab Repeater trong Burp và bấm Send gần như cùng lúc.

## Snippet copy-là-chạy

```python
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

targets = ["http://10.0.2.1:8000", "http://10.0.3.1:8000"]
TIMEOUT = 4
WORKERS = 4   # số "luồng" chạy cùng lúc, tức số đội được xử lý đồng thời

def hit(base):
    s = requests.Session()        # mỗi luồng tự tạo session riêng, không dùng chung
    s.verify = False
    r = s.get(base + "/health", timeout=TIMEOUT)
    time.sleep(0.5)
    return base, r.status_code

with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futs = [ex.submit(hit, t) for t in targets]   # giao việc "hit(target)" cho từng đội
    for fut in as_completed(futs):                 # lấy kết quả ngay khi đội nào xong trước
        team, code = fut.result()
        print(team, code)
```

## Giải thích cho người mới
- `ThreadPoolExecutor(max_workers=4)` tạo ra 1 "nhóm 4 người làm việc cùng lúc" — tối đa 4 đội được xử lý đồng thời, đội thứ 5 phải đợi 1 trong 4 xong trước.
- `ex.submit(hit, t)` = giao cho nhóm làm việc 1 việc cụ thể: "chạy hàm `hit` với tham số `t`" (chính là URL của 1 đội). Mỗi lần `submit` là giao thêm 1 việc, không chờ việc đó xong mới submit tiếp.
- `as_completed(futs)` = lấy kết quả theo thứ tự **đội nào xong trước thì lấy trước** (không phải thứ tự bạn giao việc) — vì mỗi đội phản hồi nhanh/chậm khác nhau.
- **Quan trọng**: mỗi luồng (mỗi lần gọi `hit(base)`) phải tự tạo `requests.Session()` riêng bên trong hàm, không dùng 1 session chung cho tất cả — nếu dùng chung, cookie của đội A có thể bị lẫn sang request gửi cho đội B, làm sai kết quả.
- `WORKERS = 4` và `time.sleep(0.5)` giữ tốc độ gửi ở mức vừa phải — không nên tăng `WORKERS` lên quá cao (ví dụ 50), vì gửi quá nhiều request cùng lúc dễ làm service (dịch vụ/trang web) của đối thủ bị quá tải hoặc sập, và có thể vi phạm luật thi.

## Lưu ý nhanh
- Mỗi luồng tự tạo `Session()` riêng — không chia sẻ 1 session cho nhiều đội, tránh lẫn cookie/header.
- Giữ `WORKERS` nhỏ (3-5), luôn có `timeout` và `time.sleep(...)` — không làm sập dịch vụ đang thi.
- Gặp lỗi 403 (bị chặn)/429 (gửi quá nhanh)/timeout (không phản hồi): in ra để biết đội nào lỗi rồi bỏ qua, đừng tự gửi lại liên tục — gửi lại nhiều lần dễ làm tình hình tệ hơn.

# Polling / Callback

## Snippet copy-là-chạy

```python
import time
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Polling job/result cho đến khi có kết quả
job_id = "123"
for _ in range(20):
    r = s.get(f"{base}/api/jobs/{job_id}", timeout=5)
    data = r.json()
    if data.get("status") == "done":
        print(data.get("result"))
        break
    time.sleep(1)
else:
    print("timeout")

# 2) Nhận callback/token rồi dùng tiếp
# Ví dụ: bạn đã có link/callback URL từ log/local listener
callback_url = "http://target/callback?token=abc"
r = s.get(callback_url, timeout=5)
print(r.status_code, r.text[:200])
```

## Lưu ý nhanh
- Polling phải có giới hạn vòng lặp và `sleep`; đừng `while True` không phanh.
- Kiểm tra status code + field `status/state/result` vì API thường trả 200 cả khi chưa xong.
- Nếu callback có token một lần, log lại ngay trước khi dùng.
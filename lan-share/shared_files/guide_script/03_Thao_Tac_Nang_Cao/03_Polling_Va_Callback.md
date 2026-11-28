# Hỏi lại nhiều lần chờ kết quả (polling) / dùng link được gửi về sau (callback)

Một số bài không trả kết quả ngay: bạn gửi 1 request để "tạo việc" (ví dụ tạo 1 job xử lý ảnh, tạo 1 report), server trả về ngay 1 mã số, nhưng phải **hỏi lại nhiều lần** sau đó mới biết việc đã xong chưa và lấy được kết quả — gọi là polling (hỏi đi hỏi lại). Một số bài khác thì server tự gửi 1 đường link/mã riêng về sau (gọi là callback) để bạn dùng tiếp.

## Snippet copy-là-chạy

```python
import time
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Hỏi lại liên tục cho tới khi job xong (polling)
job_id = "123"
for _ in range(20):                      # tối đa hỏi 20 lần, không hỏi mãi vô hạn
    r = s.get(f"{base}/api/jobs/{job_id}", timeout=5)
    data = r.json()
    if data.get("status") == "done":     # sửa "status"/"done" theo đúng tên field response thật trả về
        print(data.get("result"))
        break
    time.sleep(1)                        # chờ 1 giây rồi hỏi lại
else:
    print("hỏi 20 lần mà chưa xong, bỏ cuộc")

# 2) Dùng 1 link/mã được gửi về sau (callback) -- ví dụ bạn đã thấy mã này trong log hệ thống
callback_url = "http://target/callback?token=abc"
r = s.get(callback_url, timeout=5)
print(r.status_code, r.text[:200])
```

## Giải thích cho người mới
- `for _ in range(20):` nghĩa là "lặp lại tối đa 20 lần" (dấu `_` chỉ là chỗ chứa, ta không dùng tới số lần thứ mấy nên đặt tên `_` cho gọn).
- Mỗi lần lặp: gửi 1 request hỏi tình trạng job, đọc field `status` trong JSON trả về — nếu đúng giá trị báo xong (ví dụ `"done"`), lấy `result` rồi `break` (dừng vòng lặp ngay).
- `time.sleep(1)` = chờ 1 giây trước khi hỏi lại lần tiếp, tránh hỏi liên tục quá nhanh.
- Dòng `else:` sau `for` (thụt lề ngang với `for`, không nằm trong vòng lặp) chỉ chạy khi vòng lặp chạy **hết** 20 lần mà không có lần nào `break` — tức là đợi mãi không xong, nên in ra "bỏ cuộc" để bạn biết cần xem lại (có thể sai field, hoặc job thật sự không bao giờ xong).
- **Phải luôn có giới hạn số lần** (`range(20)`) và `time.sleep(...)`. Viết `while True:` không có gì chặn lại là lỗi hay gặp nhất ở phần này — script sẽ treo mãi nếu job không bao giờ báo xong.
- Khối 2 là trường hợp bạn đã có sẵn 1 đường link/mã (token dùng 1 lần) từ 1 nguồn khác (ví dụ xem được trong log, hoặc 1 công cụ nghe cục bộ trên máy bạn) — chỉ cần gửi GET tới đúng link đó.

## Lưu ý nhanh
- Luôn giới hạn số lần hỏi lại (`range(N)`) và có `time.sleep(...)` — không viết `while True:` không có điểm dừng.
- Server có thể trả status 200 (thành công) cả khi việc **chưa xong** — đừng chỉ tin status code, phải đọc đúng field báo tình trạng (`status`/`state`/`result`...) trong JSON.
- Nếu link/mã (token) chỉ dùng được 1 lần, hãy in nó ra (lưu lại) trước khi dùng — dùng xong là mất, dùng sai 1 lần phải quay lại từ đầu.

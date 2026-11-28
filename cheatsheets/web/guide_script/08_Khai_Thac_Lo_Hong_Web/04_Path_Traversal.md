# Path Traversal / LFI

> Chỉ test trên hệ thống/lab được phép.

## Lỗ hổng này là gì

Nhiều web có chức năng "tải file theo tên", ví dụ `?file=report.pdf` để lấy file `report.pdf` trong 1 thư mục cho phép. Nếu server chỉ nối chuỗi `"thư mục cho phép/" + tên_file_bạn_gõ` mà không kiểm tra, bạn có thể gõ vào đó `../../etc/passwd` — dấu `../` nghĩa là "lùi ra 1 cấp thư mục". Lùi đủ nhiều lần, bạn thoát hẳn ra khỏi thư mục cho phép và đọc được bất kỳ file nào trên máy chủ.

Giống như thủ thư chỉ cho bạn mượn sách trong 1 kệ, nhưng khi bạn đưa ra tấm phiếu ghi "lùi ra khỏi phòng này, sang phòng bên, lên tầng trên, vào phòng lưu trữ hồ sơ mật", thủ thư vẫn cứ đi theo đúng chỉ dẫn trên phiếu mà không hỏi lại "ơ sao lại đi ra ngoài kệ sách vậy".

## Nhìn vào đâu để nghi ngờ có lỗ hổng này

- URL có `?file=...`, `?page=...`, `?path=...`, `?doc=...`, `?template=...`, `?name=...` — bất kỳ chỗ nào tham số là tên file hoặc tên trang để web "mở file" ra đọc.
- Chức năng tải file, xem ảnh, xem log, xem báo cáo, preview document, chọn ngôn ngữ (`?lang=vi` có thể là `lang.php` được include).
- Đặc biệt nghi khi giá trị tham số trông giống tên file có đuôi (`.pdf`, `.txt`, `.php`, `.html`).

## Cách test nhanh bằng tay trên Burp

1. Thử giá trị gốc hoạt động bình thường trước, ghi lại response.
2. Đổi giá trị thành `../../../../etc/passwd` (trên Linux) hoặc `..\..\..\..\windows\win.ini` (trên Windows) — nếu response hiện ra nội dung file hệ thống (trên Linux sẽ thấy chữ `root:` ở đầu dòng), đã khai thác được.
3. Nếu server có vẻ lọc chuỗi `../`, thử bản đã encode: `..%2f..%2f..%2f..%2fetc%2fpasswd` (encode 1 lần) hoặc `..%252f...` (encode 2 lần, dùng khi server decode 2 lần). Cũng có thể thử đưa thẳng đường dẫn tuyệt đối `/etc/passwd` nếu server không ngăn.

## Script copy-paste có sẵn

Xem [`Path_Traversal_LFI.md`](../04_Theo_Lo_Hong/Path_Traversal_LFI.md) trong `04_Theo_Lo_Hong/` — có sẵn script thử nhiều dạng `../` và encode khác nhau, tự dò chữ `root:` trong response.

## Cách sửa (nếu bạn là người phòng thủ/DEF)

Tốt nhất: không nhận tên file từ người dùng — nhận 1 ID, server tự tra ra đường dẫn thật trong database. Nếu buộc phải nhận tên file, chỉ lấy đúng phần tên file (không cho chứa `/` hay `\`), rồi sau khi ghép đường dẫn, kiểm tra lại đường dẫn cuối cùng có còn nằm trong đúng thư mục cho phép không (dùng hàm chuẩn hóa đường dẫn của ngôn ngữ, ví dụ `Path(...).resolve()` trong Python, đừng tự viết `replace("../", "")` vì dễ bị lách qua các cách encode khác).

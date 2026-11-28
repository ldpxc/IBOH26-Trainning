# Nhận ra lỗ hổng web bằng mắt

Thư mục này **không dạy quy trình kiểm thử an toàn kiểu chuyên gia bảo mật**. Mục đích duy nhất: nhìn vào 1 trang web / 1 request trong Burp, bạn đoán ra được "chỗ này có khả năng dính lỗ hổng gì" và biết gõ gì vào đâu để kiểm tra nhanh. Ai chưa học an ninh mạng ngày nào cũng đọc hiểu được.

Code Python chạy thật (copy-paste chạy ngay) để nằm ở [`04_Theo_Lo_Hong/`](../04_Theo_Lo_Hong/) — các file trong thư mục này **không lặp lại code đó**, chỉ nói "lỗ hổng này là gì" và "thấy dấu hiệu gì thì nghi".

> Chỉ test trên hệ thống/lab bạn được phép (máy của bạn, lab dựng sẵn, hoặc đội trong trận CTF).

## Mục lục

| File | Lỗ hổng | Tóm tắt 1 câu |
|---|---|---|
| [01_SQLi.md](01_SQLi.md) | SQL Injection | Gõ chữ vào ô mà server đưa thẳng vào câu lệnh hỏi database, không kiểm tra |
| [02_XSS.md](02_XSS.md) | XSS | Đưa code JavaScript vào chỗ web in lại dữ liệu bạn gửi cho người khác xem |
| [03_SSRF.md](03_SSRF.md) | SSRF | Nhờ server tự gửi request tới chỗ bạn chỉ định, kể cả chỗ chỉ server mới vào được |
| [04_Path_Traversal.md](04_Path_Traversal.md) | Path Traversal / LFI | Dùng `../` để đọc file ngoài thư mục server định cho đọc |
| [05_Deserialization.md](05_Deserialization.md) | Deserialization | Server mở 1 gói dữ liệu (object đóng gói) do bạn gửi lên mà không kiểm tra trước khi dùng |
| [06_Auth_Logic_Flaw.md](06_Auth_Logic_Flaw.md) | Auth / Logic Flaw (IDOR...) | Server quên kiểm "dữ liệu/quyền này đúng là của người đang gửi request không" |

Đọc xong 1 file, bạn sẽ biết: lỗ hổng đó giống cái gì ngoài đời, nhìn dấu hiệu nào trong URL/form/Burp thì nên nghi, test tay bằng cách gõ gì, và nếu bạn là người phòng thủ (DEF) thì nên sửa ở đâu.

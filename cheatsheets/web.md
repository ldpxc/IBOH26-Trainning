# Web — Lane P2

> Mở giao diện bài giảng: [HTML](web.html) · [Markdown](web.md)

> Tài liệu này có hai lớp: **Combat** để dò nhanh source → sink → PoC, và **Giảng sâu** để hiểu nguyên nhân, cách vá, cùng kiểm tra hồi quy. Các ví dụ dùng Python/Flask, dữ liệu giả, chỉ nhắm `127.0.0.1`; chưa chạy trong repo. Chỉ dùng trên lab cô lập mà bạn sở hữu hoặc được phép kiểm thử.

## Combat Card — nhận diện nhanh

| # | Lỗi | Dấu hiệu trong code | Bản vá gốc |
|---|---|---|---|
| 01 | SQL injection | request data nối vào SQL string | prepared statement / parameter binding |
| 02 | XSS | dữ liệu không tin cậy đi vào HTML/DOM sink | output encoding theo context; safe DOM API |
| 03 | IDOR/BOLA | object lấy theo ID request nhưng thiếu policy/owner check | authorization server-side trên từng object/action |
| 04 | Auth/session/JWT | token/claims dùng trước khi verify; session không đổi sau login | verifier cấu hình cố định; vòng đời session an toàn |
| 05 | CSRF | cookie-auth state change không đòi CSRF proof | framework CSRF middleware/token |
| 06 | SSRF | request URL tùy chỉnh tới HTTP client phía server | đích allowlist + egress policy |
| 07 | Path traversal/LFI | input tên file đi tới `open`/include | opaque ID → path server-owned; containment |
| 08 | Upload không an toàn | tin filename/MIME/extension; lưu vào webroot | validate nội dung server-side; tên ngẫu nhiên; vùng lưu riêng |
| 09 | OS command injection | request data đi vào shell command | bỏ shell; dùng API/argv cố định và validation |
| 10 | SSTI | input được biên dịch như template source | template cố định; input truyền như biến |
| 11 | XXE | XML parser cho phép DTD/entity ngoài | tắt/reject DTD và external entities |
| 12 | Deserialization | bytes người dùng vào `pickle`/`unserialize`/`readObject` | định dạng data-only + schema/limits |

## Giảng sâu

- [Injection: SQLi, XSS, OS command injection, SSTI](web/injection.html) · [Markdown](web/injection.md)
- [Authorization, authentication, CSRF, deserialization](web/access.html) · [Markdown](web/access.md)
- [SSRF, path traversal, upload, XXE](web/files_protocol.html) · [Markdown](web/files_protocol.md)
- [Bản tổng hợp nghiên cứu và nguồn tham khảo](reports/Web%20security%20lab%2012%20flaws.md)

## Quy ước thực hành

Mỗi mục trong ba bài con có nhận diện 30 giây, code lỗi, PoC vô hại khóa vào loopback, code vá, lý do bản vá chặn PoC và checklist hồi quy. Mã trong tài liệu là ví dụ minh họa, không phải xác nhận đã chạy. Khi biến thành lab dùng thật, tạo user/file/token giả, bind service ở loopback, pin phiên bản thư viện, rồi kiểm tra kết quả trước/sau vá.

**Luồng review chung:** tìm source (request, cookie, upload, token) → lần qua biến đổi → xác định sink (query, quyền, shell, template, file, XML parser, HTTP client) → xem check nào chạy ngay trước sink → viết regression test thể hiện dữ liệu phải còn là dữ liệu.

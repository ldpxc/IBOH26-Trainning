# Tài liệu lỗ hổng ứng dụng web

Thư mục này tập trung vào **bản chất, cách nhận diện, cách kiểm chứng có kiểm soát và cách khắc phục** các nhóm lỗ hổng web phổ biến. Đây là tài liệu học tập/tham chiếu, không phải hướng dẫn tấn công hệ thống không được phép.

> **Phạm vi sử dụng:** chỉ thực hành trên máy của bạn, lab được dựng sẵn, CTF hoặc chương trình kiểm thử có phạm vi và ủy quyền rõ ràng. Không quét, thử payload hoặc truy cập dữ liệu trên hệ thống của bên thứ ba khi chưa được phép. Các ví dụ dùng `http://target`, `http://127.0.0.1` hoặc dữ liệu giả định; hãy thay bằng môi trường lab của bạn.

## 1. Cách đọc tài liệu

Mỗi bài có cùng cấu trúc:

1. **Bản chất** — điều kiện làm lỗ hổng xuất hiện và ranh giới giữa dữ liệu/điều khiển.
2. **Nhận diện** — vị trí cần quan sát, dấu hiệu trong request/response và cách loại trừ dương tính giả.
3. **Kiểm chứng trong lab** — quy trình từng bước, bắt đầu bằng input vô hại và tăng dần mức độ.
4. **Khai thác có kiểm soát** — mục tiêu là chứng minh tác động tối thiểu, không lấy dữ liệu thật hoặc phá hoại.
5. **Khắc phục** — thay đổi ở thiết kế, code, cấu hình và kiểm thử hồi quy.

Các payload minh họa là **chuỗi thử nghiệm kinh điển trong môi trường được phép**, không phải cam kết sẽ hoạt động trên mọi ứng dụng. Nếu một bước có thể làm thay đổi dữ liệu hoặc ảnh hưởng người dùng khác, hãy dùng bản sao dữ liệu và tài khoản thử nghiệm.

## 2. Danh mục

| Bài | Nội dung chính |
|---|---|
| [01_SQLi.md](01_SQLi.md) | SQL Injection: union/error/boolean/time-based, ngữ cảnh tham số, filter cơ bản, tham số hóa truy vấn |
| [02_XSS.md](02_XSS.md) | Reflected/Stored/DOM XSS, ngữ cảnh HTML/attribute/JavaScript/URL, encoding và CSP |
| [03_SSRF.md](03_SSRF.md) | Server-Side Request Forgery: URL fetch, parser khác biệt, redirect, allowlist và network boundary |
| [04_Path_Traversal.md](04_Path_Traversal.md) | Directory traversal/LFI: canonicalization, encoding, đường dẫn tuyệt đối, cách giới hạn thư mục |
| [05_Deserialization.md](05_Deserialization.md) | Deserialization không an toàn: nhận diện định dạng, gadget chain theo ngôn ngữ, thiết kế thay thế |
| [06_Auth_Logic_Flaw.md](06_Auth_Logic_Flaw.md) | IDOR/BOLA, login/session/JWT, lỗi nghiệp vụ, state machine và kiểm thử 2 tài khoản |

## 3. Quy trình kiểm thử an toàn

### Bước 1: Xác định phạm vi

Ghi lại trước khi bắt đầu:

- Host/port/đường dẫn được phép.
- Tài khoản và dữ liệu thử nghiệm.
- Thời gian kiểm thử và giới hạn request.
- Hành vi bị cấm: xóa dữ liệu, đổi mật khẩu người khác, gửi email thật, truy cập dữ liệu nhạy cảm.

### Bước 2: Tạo baseline

Dùng Burp Repeater hoặc `curl` để lưu một request bình thường:

- Method, URL, query, header, cookie.
- Status, `Content-Type`, chiều dài body.
- Nội dung/JSON field quan trọng.
- Thời gian phản hồi trung bình.

Baseline giúp phân biệt **thay đổi do payload** với thay đổi do session, cache, CSRF hoặc dữ liệu ngẫu nhiên.

### Bước 3: Thay đổi một biến mỗi lần

Không đồng thời đổi payload, header, cookie và encoding. Nếu response khác, bạn cần biết chính xác thay đổi nào gây ra.

### Bước 4: Dùng tín hiệu vô hại

Ưu tiên:

- Chuỗi marker duy nhất như `sheatch_probe_01`.
- Tài khoản và object do bạn tạo.
- File mẫu trong thư mục lab.
- Callback endpoint do bạn kiểm soát trong lab.
- Độ trễ nhỏ, có giới hạn, không làm quá tải dịch vụ.

Không dùng dữ liệu thật để chứng minh lỗ hổng nếu một marker vô hại đã đủ.

### Bước 5: Ghi bằng chứng tối thiểu

Một báo cáo tốt cần:

- Mô tả điều kiện tiên quyết.
- Request/response đã che thông tin nhạy cảm.
- Các bước tái hiện trên bản dựng mới.
- Tác động thực tế và giới hạn đã kiểm chứng.
- Đề xuất sửa và test hồi quy.

## 4. Ranh giới giữa "phát hiện" và "khai thác"

| Mức | Mục tiêu | Ví dụ bằng chứng |
|---|---|---|
| Phát hiện | Xác định input có thể ảnh hưởng hành vi | Marker xuất hiện ở vị trí bất thường |
| Xác nhận | Loại trừ lỗi ứng dụng/cache/encoding | Đối chứng có/không có điều kiện, lặp lại được |
| Chứng minh tác động | Chứng minh quyền hoặc dữ liệu tối thiểu bị vượt kiểm soát | Đọc object test của tài khoản B bằng tài khoản A |
| Dừng lại | Không mở rộng sang dữ liệu người dùng thật | Không dump database, không leo quyền tiếp |

Nếu đã đủ bằng chứng ở mức trước, không cần tiếp tục mở rộng.

## 5. Công cụ và tài liệu liên quan trong repo

- `01_Request_Co_Ban/` — query, form/JSON, header/cookie, upload, encoding.
- `02_Chuoi_Request/` — giữ phiên, CSRF, truyền ID giữa các bước, đọc response.
- `03_Thao_Tac_Nang_Cao/` — vòng lặp payload, concurrency, polling/callback.
- `04_Theo_Lo_Hong/` — ví dụ chuyển thao tác Burp thành Python.
- `06_Debug/` — so request Python với Burp, timeout/TLS/JSON/token.
- `scripts/` — helper gửi request, debug và lưu kết quả.

## 6. Checklist chung trước khi kết luận

- [ ] Có request baseline và request thay đổi.
- [ ] Đã kiểm tra lại với input đối chứng.
- [ ] Đã loại trừ encoding, cache, session và redirect.
- [ ] Không dựa vào một lần response khác biệt duy nhất.
- [ ] Tác động được mô tả đúng mức đã chứng minh.
- [ ] Có phương án sửa ở tầng gốc, không chỉ thêm blacklist.
- [ ] Có test hồi quy sau khi sửa.

# Server-Side Request Forgery (SSRF)

> Chỉ test trên hệ thống/lab được phép.

## Lỗ hổng này là gì

Một số web có chức năng "nhập URL rồi web tự đi lấy nội dung URL đó về" — ví dụ dán link ảnh đại diện, dán link để web tự tải thumbnail, webhook, "import từ URL". Việc **đi lấy URL** là do **server** làm, không phải trình duyệt của bạn. Nếu web không kiểm tra URL bạn đưa vào, bạn có thể bắt server đi tới những nơi mà **chỉ server mới vào được** — ví dụ các dịch vụ nội bộ chỉ chạy trong mạng riêng của server, hoặc `127.0.0.1` (chính là server đó).

Giống như việc bạn không được vào 1 khu vực cấm, nhưng bạn thuê được 1 người bảo vệ (server) đang có thẻ ra vào khu đó đi lấy hộ 1 thứ gì trong đó cho bạn — bạn chưa bao giờ bước chân vào, nhưng vẫn lấy được thông tin từ trong đó ra.

## Nhìn vào đâu để nghi ngờ có lỗ hổng này

- Tham số tên `url=`, `uri=`, `link=`, `image=`, `avatar=`, `webhook=`, `callback=`, `feed=`, `path=`, `target=`, `endpoint=`, `next=` — bất kỳ chỗ nào bạn đưa vào 1 địa chỉ (URL) và web có vẻ "tự đi lấy nó về".
- Chức năng: tải ảnh từ URL ngoài, xem preview link, import dữ liệu từ URL, PDF/report generator, tích hợp webhook, "ping URL để kiểm tra còn sống không".
- Dấu hiệu rõ nhất: khi bạn đổi URL, response (hoặc thời gian phản hồi) thay đổi theo — chứng tỏ server có thật sự đi gọi URL đó.

## Cách test nhanh bằng tay trên Burp

1. Đưa 1 URL bạn kiểm soát được (ví dụ 1 trang do bạn dựng, hoặc dùng `http://requestbin`-kiểu dịch vụ nếu có mạng, hoặc trong lab tự dựng 1 HTTP server nhỏ) vào tham số đó, gửi đi — xem server đó có "gõ cửa" tới chỗ bạn kiểm soát không (xem log server của bạn).
2. Thử đưa `http://127.0.0.1/` hoặc `http://localhost/` vào tham số — nếu response khác hẳn (ví dụ hiện ra nội dung trang quản trị nội bộ mà bình thường không truy cập được từ ngoài), đó là SSRF đã khai thác được.
3. Thử `http://169.254.169.254/latest/meta-data/` nếu đoán server chạy trên cloud (AWS/GCP...) — địa chỉ này chỉ trả dữ liệu cho chính máy chủ đang chạy, có thể lộ thông tin nhạy cảm của server.

## Script copy-paste có sẵn

Xem [`SSRF.md`](../04_Theo_Lo_Hong/SSRF.md) trong `04_Theo_Lo_Hong/` — có sẵn script thử 1 danh sách địa chỉ nội bộ hay gặp.

## Cách sửa (nếu bạn là người phòng thủ/DEF)

Không để khách gửi URL tùy ý nếu không cần thiết — tốt nhất là cho khách chọn trong 1 danh sách cố định, hoặc gửi 1 cái ID rồi server tự tra ra URL thật. Nếu buộc phải nhận URL tùy ý, chặn các địa chỉ nội bộ (`127.0.0.1`, `localhost`, các dải IP riêng như `10.x.x.x`, `192.168.x.x`, `169.254.x.x`) ngay trước khi gửi request, và kiểm tra lại địa chỉ IP thật sau khi phân giải tên miền (vì tên miền có thể trỏ tới IP nội bộ). Không để server tự động theo chuyển hướng (redirect) tới nơi chưa kiểm tra lại.

# Cross-Site Scripting (XSS)

> Chỉ test trên hệ thống/lab được phép.

## Lỗ hổng này là gì

Khi bạn gõ gì vào 1 ô (ô tìm kiếm, bình luận, tên hiển thị...), web thường **in lại chính cái bạn vừa gõ** ra màn hình — ví dụ trang tìm kiếm hiện "Kết quả cho: <cái bạn gõ>". Nếu web in nguyên văn mà không kiểm tra, và bạn gõ vào đó 1 đoạn code JavaScript (`<script>...</script>`), trình duyệt của **người xem trang đó** (có thể là chính bạn, có thể là admin, có thể là người chơi khác) sẽ chạy đoạn code đó như thể nó là 1 phần hợp pháp của trang.

Giống như việc bạn viết lên 1 tấm bảng thông báo chung ("Khách abc muốn nhắn: ...") rồi ai đi qua đọc bảng cũng tin đó là thông báo thật của quán, không phải lời bạn chèn vào. XSS là chèn được "lệnh" vào chỗ lẽ ra chỉ nên hiện "chữ".

## Nhìn vào đâu để nghi ngờ có lỗ hổng này

- Chỗ nào gõ gì vào thì thấy **đúng y nguyên chữ đó hiện lại** trên trang: ô tìm kiếm có câu "Không tìm thấy kết quả cho '...'"‚ trang lỗi 404 hiện lại đường dẫn bạn gõ, ô bình luận/review/tên hiển thị/profile bio.
- Thông báo lỗi có nhắc lại giá trị bạn gửi lên.
- Chức năng cho người khác xem lại nội dung bạn tạo (bình luận, bài viết, tên file upload, tin nhắn) — đặc biệt nguy hiểm nếu admin/người khác sẽ mở xem nó.

## Cách test nhanh bằng tay trên Burp

1. Gõ vào ô đó 1 chuỗi vô hại dễ nhận ra, ví dụ `test123abc`, gửi đi — xem nó hiện lại ở đâu trong response (view source, không chỉ nhìn trang render).
2. Gõ `<script>alert(1)</script>` vào đúng chỗ đó rồi gửi lại. Mở trang đó trên trình duyệt (không chỉ xem trong Burp) — nếu hiện ra 1 popup alert, chắc chắn là XSS.
3. Nếu bước 2 không ăn (do nó nằm trong attribute HTML như `value="..."` chứ không nằm giữa 2 thẻ), thử `"><script>alert(1)</script>` hoặc `" onmouseover="alert(1)` — mục đích là thoát ra khỏi dấu nháy của attribute trước khi chèn code.

## Script copy-paste có sẵn

Xem [`XSS_CSRF.md`](../04_Theo_Lo_Hong/XSS_CSRF.md) trong `04_Theo_Lo_Hong/` — có sẵn script kiểm tra payload có bị phản chiếu (reflect) ra response hay không.

## Cách sửa (nếu bạn là người phòng thủ/DEF)

Khi in dữ liệu người dùng ra HTML, phải "escape" (chuyển các ký tự đặc biệt như `<`, `>`, `"` thành dạng vô hại `&lt;`, `&gt;`, `&quot;`) trước khi in — hầu hết template engine (Jinja2, EJS...) tự làm việc này nếu bạn không tắt tính năng đó đi. Không tự nối chuỗi HTML tay. Nếu đưa dữ liệu vào JavaScript bằng `innerHTML`, đổi sang dùng `textContent` (chỉ in chữ, không bao giờ tạo ra thẻ HTML mới).

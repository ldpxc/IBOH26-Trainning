<?php
// notevault — cấu hình chung. Cố ý KHÔNG có input validation/escaping ở đây,
// mỗi endpoint tự chịu trách nhiệm (và một vài endpoint cố tình làm sai —
// xem services-practice/README.md hoặc plan để biết lỗ hổng nào ở đâu).
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
ini_set('display_errors', '1');   // service luyện tập: hiện lỗi để dễ debug, KHÔNG làm vậy ở app thật
session_start();

define('UPLOAD_DIR', __DIR__ . '/../uploads');
define('TEMPLATE_DIR', __DIR__ . '/../templates');

// === BEGIN_EXPORT_STRIP: dark_mode ===
// LỖ HỔNG: "debug flag theo theme" — dev từng bật 1 cờ debug tạm thời để so
// sánh response giữa 2 theme sáng/tối lúc làm UI dark mode, quên gỡ. Không
// có nút bật dark mode nào trên giao diện (cố ý không đổi UI) — cờ debug
// này chỉ đọc qua cookie `theme`, không liên quan gì tới việc trang có đổi
// màu hay không. Vì chỉ thêm 1 header response (không in ra HTML), người
// dùng bấm/xem trang bình thường KHÔNG thấy gì khác — chỉ lộ ra khi soi
// response thô bằng Burp/curl (`curl -i -b "theme=dark" ...` hoặc tab
// Response trong Burp), đúng kiểu sự cố thật: để sót debug flag không có
// dấu hiệu gì trên UI.
//
// KHÔNG đưa đoạn này vào bản source xuất gửi team (xem export_source.py) --
// nếu đọc được code sẽ thấy ngay dòng if(), mất hết yếu tố bất ngờ.
if (($_COOKIE['theme'] ?? '') === 'dark') {
    require_once __DIR__ . '/flag.php';
    header('X-Theme-Debug: ' . flag('dark_mode'));
}
// === END_EXPORT_STRIP: dark_mode ===

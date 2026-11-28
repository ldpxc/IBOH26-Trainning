<?php
// notevault — cấu hình chung. Cố ý KHÔNG có input validation/escaping ở đây,
// mỗi endpoint tự chịu trách nhiệm (và một vài endpoint cố tình làm sai —
// xem services-practice/README.md hoặc plan để biết lỗ hổng nào ở đâu).
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
ini_set('display_errors', '1');   // service luyện tập: hiện lỗi để dễ debug, KHÔNG làm vậy ở app thật
session_start();

define('UPLOAD_DIR', __DIR__ . '/../uploads');
define('TEMPLATE_DIR', __DIR__ . '/../templates');

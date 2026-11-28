<?php
// LỖ HỔNG: Insecure Deserialization — nhận "gói note chia sẻ" dạng chuỗi
// base64(serialize(object)) qua ?data=, rồi unserialize() thẳng mà không
// kiểm tra/giới hạn class nào được phép dựng (allowed_classes). Class
// NoteExporter (inc/gadget.php) có __destruct() ghi file từ 2 property do
// chính attacker set -> arbitrary file write -> ghi webshell vào uploads/.
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
require_login();
require __DIR__ . '/inc/gadget.php';

$msg = '';
$data = $_GET['data'] ?? '';
if ($data !== '') {
    $raw = base64_decode($data, true);
    if ($raw === false) {
        $msg = 'Dữ liệu base64 không hợp lệ.';
    } else {
        $obj = @unserialize($raw);   // không giới hạn allowed_classes
        $msg = 'Đã xử lý gói note chia sẻ.';
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Note được chia sẻ cho bạn</h1>
<p>Dán gói dữ liệu (base64) người khác gửi cho bạn qua link
<code>?data=...</code> vào thanh địa chỉ để mở.</p>
<?php if ($msg): ?><p><?= h($msg) ?></p><?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

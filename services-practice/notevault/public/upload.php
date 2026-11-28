<?php
// LỖ HỔNG: Unrestricted File Upload — không kiểm tra đuôi file/MIME type,
// lưu đúng tên gốc vào thư mục uploads/ (được Apache serve + thực thi PHP
// bình thường) -> upload 1 file .php làm webshell là có RCE ngay.
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
$uid = require_login();

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $f = $_FILES['avatar'];
    $dest = UPLOAD_DIR . '/' . basename($f['name']);   // basename() chỉ chặn path traversal, KHÔNG chặn đuôi file
    if (move_uploaded_file($f['tmp_name'], $dest)) {
        $msg = "Đã lưu tại /uploads/" . h(basename($f['name']));
    } else {
        $msg = "Upload thất bại.";
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Avatar</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="avatar" required>
  <button type="submit">Upload</button>
</form>
<?php if ($msg): ?><p><?= $msg ?></p><?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

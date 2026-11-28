<?php
// LỖ HỔNG: Command Injection — tên file người dùng nhập được nối thẳng vào
// shell_exec() để gọi "trình xuất PDF" (ở đây giả lập bằng cách ghi text ra
// file thay vì cài thật wkhtmltopdf, không đổi bản chất lỗ hổng).
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
$uid = require_login();

$output = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $filename = $_POST['filename'] ?? 'export';
    $out = '/tmp/export_' . $uid . '.txt';
    // CỐ TÌNH không escape $filename trước khi đưa vào shell.
    $cmd = "echo 'Xuất note: $filename' > $out 2>&1 && cat $out";
    $output = shell_exec($cmd);
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Xuất note ra "PDF"</h1>
<p>Nhập tên file muốn xuất (demo: chỉ ghi ra text, không cần cài PDF thật).</p>
<form method="post">
  <input name="filename" placeholder="ten-file" value="my-notes">
  <button type="submit">Xuất</button>
</form>
<?php if ($output !== ''): ?><pre><?= h($output) ?></pre><?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

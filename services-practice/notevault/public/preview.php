<?php
// LỖ HỔNG: LFI / Path Traversal — tham số tpl ghép thẳng vào đường dẫn, không
// lọc "../", không giới hạn trong TEMPLATE_DIR. file_get_contents() vẫn hiểu
// stream wrapper (vd php://filter/convert.base64-encode/resource=...) nên kỹ
// thuật đọc source code qua base64 trong bài giảng lfi.html cũng dùng được.
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
require_once __DIR__ . '/inc/flag.php';
require_login();

$tpl = $_GET['tpl'] ?? 'welcome.txt';
$path = TEMPLATE_DIR . '/' . $tpl;   // KHÔNG dùng realpath()/basename() để chặn traversal
$content = @file_get_contents($path);
if ($content !== false) {
    $content = render_flags($content);
}

require __DIR__ . '/inc/layout_top.php';
?>
<h1>Xem trước template</h1>
<form method="get">
  <input name="tpl" value="<?= h($tpl) ?>" placeholder="welcome.txt">
  <button type="submit">Xem</button>
</form>
<?php if ($content !== false): ?>
  <pre><?= h($content) ?></pre>
<?php else: ?>
  <p class="err">Không đọc được template.</p>
<?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

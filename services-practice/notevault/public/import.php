<?php
// LỖ HỔNG: XXE — parse XML người dùng gửi lên bằng DOMDocument với
// LIBXML_NOENT (tự động thay thế entity) + DTDLOAD (cho phép DOCTYPE ngoài),
// không tắt entity loader -> DOCTYPE tự định nghĩa entity đọc file hệ thống
// là bị XXE. Định dạng mong đợi: <note><title>...</title><body>...</body></note>
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
$uid = require_login();

$result = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xml = $_POST['xml'] ?? '';
    if ($xml !== '') {
        libxml_use_internal_errors(true);
        if (function_exists('libxml_disable_entity_loader')) {
            @libxml_disable_entity_loader(false);
        }
        $doc = new DOMDocument();
        if (@$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD)) {
            $title = $doc->getElementsByTagName('title')->item(0)->nodeValue ?? '(no title)';
            $body  = $doc->getElementsByTagName('body')->item(0)->nodeValue ?? '';
            $stmt = db()->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
            $stmt->execute([$uid, $title, $body]);
            $result = "Đã import note mới — <a href='/index.php'>xem ở trang chủ</a>.";
        } else {
            $result = "XML không hợp lệ.";
        }
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Import note (XML/OPML)</h1>
<p>Định dạng: <code>&lt;note&gt;&lt;title&gt;...&lt;/title&gt;&lt;body&gt;...&lt;/body&gt;&lt;/note&gt;</code></p>
<form method="post">
  <textarea name="xml" rows="8" placeholder="&lt;note&gt;&lt;title&gt;Tiêu đề&lt;/title&gt;&lt;body&gt;Nội dung&lt;/body&gt;&lt;/note&gt;"></textarea>
  <button type="submit">Import</button>
</form>
<?php if ($result): ?><p><?= $result ?></p><?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

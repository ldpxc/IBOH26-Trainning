<?php
// LỖ HỔNG: SQL Injection cổ điển — nối chuỗi thẳng vào mysqli_query(), không
// dùng prepared statement (khác hẳn phần còn lại của app dùng PDO đúng cách —
// style lỗi thực tế: 1 endpoint "quên", không phải cả app sai).
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
require_once __DIR__ . '/inc/flag.php';
require_login();

$q = $_GET['q'] ?? '';
$results = [];
$error = '';
if ($q !== '') {
    $sql = "SELECT id, title FROM notes WHERE title LIKE '%$q%'";
    $res = raw_mysqli()->query($sql);
    if ($res === false) {
        $error = raw_mysqli()->error;   // lộ lỗi SQL -- giúp dò bằng error-based cũng được
    } else {
        while ($row = $res->fetch_assoc()) {
            $results[] = $row;
        }
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Kết quả tìm kiếm: <?= h($q) ?></h1>
<?php if ($error): ?><p class="err">SQL error: <?= h($error) ?></p><?php endif; ?>
<?php foreach ($results as $r): ?>
  <div class="note"><?= h(render_flags((string)$r['title'])) ?></div>
<?php endforeach; ?>
<?php if ($q !== '' && !$results && !$error): ?><p>Không có kết quả.</p><?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

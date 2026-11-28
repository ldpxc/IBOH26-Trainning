<?php
// LỖ HỔNG: IDOR — note_id tăng dần, KHÔNG kiểm tra note có thuộc user đang
// đăng nhập không. Đổi ?id= sang số khác (vd note của admin) là xem được.
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
require_once __DIR__ . '/inc/flag.php';
require_login();

$id = (int)($_GET['id'] ?? 0);
$stmt = db()->prepare('SELECT title, body FROM notes WHERE id = ?');  // thiếu "AND user_id = ?"
$stmt->execute([$id]);
$note = $stmt->fetch(PDO::FETCH_ASSOC);

require __DIR__ . '/inc/layout_top.php';
?>
<h1><?= $note ? h($note['title']) : 'Không tìm thấy' ?></h1>
<?php if ($note): ?>
  <pre><?= h(render_flags($note['body'])) ?></pre>
<?php endif; ?>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

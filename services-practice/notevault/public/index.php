<?php
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
$uid = require_login();

$stmt = db()->prepare('SELECT id, title FROM notes WHERE user_id = ? ORDER BY id DESC');
$stmt->execute([$uid]);
$notes = $stmt->fetchAll(PDO::FETCH_ASSOC);

require __DIR__ . '/inc/layout_top.php';
?>
<h1>Note của bạn</h1>
<form action="/search.php" method="get">
  <input name="q" placeholder="Tìm note theo tiêu đề...">
  <button type="submit">Tìm</button>
</form>
<?php foreach ($notes as $n): ?>
  <div class="note">
    <a href="/note.php?id=<?= (int)$n['id'] ?>"><?= h($n['title']) ?></a>
  </div>
<?php endforeach; ?>
<?php if (!$notes): ?><p>Chưa có note nào. <a href="/new_note.php">Tạo note mới</a>.</p><?php endif; ?>
<p><a href="/share.php">Note được chia sẻ cho bạn</a> ·
   <a href="/export.php">Xuất note ra PDF</a> ·
   <a href="/preview.php">Xem trước template</a></p>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

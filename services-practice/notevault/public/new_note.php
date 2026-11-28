<?php
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
$uid = require_login();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = trim($_POST['title'] ?? '');
    $body = $_POST['body'] ?? '';
    if ($title !== '') {
        $stmt = db()->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
        $stmt->execute([$uid, $title, $body]);
        header('Location: /index.php');
        exit;
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Note mới</h1>
<form method="post">
  <input name="title" placeholder="Tiêu đề" required>
  <textarea name="body" rows="6" placeholder="Nội dung"></textarea>
  <button type="submit">Lưu</button>
</form>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

<?php
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $stmt = db()->prepare('SELECT id, password_hash FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = (int)$user['id'];
        header('Location: /index.php');
        exit;
    }
    $error = 'Sai username hoặc password';
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Đăng nhập</h1>
<?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
<form method="post">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">Đăng nhập</button>
</form>
<p><a href="/register.php">Đăng ký tài khoản mới</a> ·
   <a href="/reset_password.php">Quên mật khẩu?</a></p>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

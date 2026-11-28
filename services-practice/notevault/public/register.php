<?php
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    if ($username === '' || $password === '') {
        $error = 'Thiếu username/password';
    } else {
        $stmt = db()->prepare('SELECT id FROM users WHERE username = ?');
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            $error = 'Username đã tồn tại';
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            // reset_token là NOT NULL (xem seed.php) -- phải cấp 1 giá trị ngẫu nhiên khi tạo
            // user mới, nếu không PDO sẽ throw PDOException: "reset_token doesn't have a
            // default value" và cả trang register.php chết trắng (lỗi thật đã gặp khi test).
            $resetToken = bin2hex(random_bytes(8));
            $stmt = db()->prepare('INSERT INTO users (username, password_hash, is_admin, reset_token) VALUES (?, ?, 0, ?)');
            $stmt->execute([$username, $hash, $resetToken]);
            header('Location: /login.php');
            exit;
        }
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Đăng ký</h1>
<?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
<form method="post">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">Đăng ký</button>
</form>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

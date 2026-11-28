<?php
// LỖ HỔNG: PHP Type Juggling — so khớp token bằng strcmp() rồi so với 0
// bằng toán tử lỏng (==). strcmp(array, string) trả về NULL (cảnh báo,
// không phải lỗi fatal, ở PHP 7.x) và NULL == 0 là TRUE -> bypass hoàn
// toàn mà không cần biết token thật, chỉ cần gửi token[]=bất_kỳ.
require __DIR__ . '/inc/config.php';
require __DIR__ . '/inc/db.php';
require __DIR__ . '/inc/auth.php';
require __DIR__ . '/inc/flag.php';

$result = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $token = $_POST['token'] ?? '';

    $stmt = db()->prepare('SELECT id, reset_token, username FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // @ để nuốt warning "strcmp() expects parameter 1 to be string, array given"
        if (@strcmp($token, $user['reset_token']) == 0) {
            $result = "Xác thực token thành công cho '" . h($user['username']) . "'.";
            if ($user['username'] === 'admin') {
                $result .= "<br>Reset mật khẩu admin thành công — " . h(flag('type_juggling'));
            } else {
                $result .= " (không phải admin, không có gì đặc biệt ở đây)";
            }
        } else {
            $result = "Token không đúng.";
        }
    } else {
        $result = "Không tìm thấy username.";
    }
}
require __DIR__ . '/inc/layout_top.php';
?>
<h1>Quên mật khẩu</h1>
<p>Nhập username và token được gửi qua email để xác thực trước khi đổi mật khẩu.</p>
<?php if ($result): ?><p><?= $result ?></p><?php endif; ?>
<form method="post">
  <input name="username" placeholder="username" required>
  <input name="token" placeholder="token (6 ký tự, nhận qua email)" required>
  <button type="submit">Xác thực</button>
</form>
<?php require __DIR__ . '/inc/layout_bottom.php'; ?>

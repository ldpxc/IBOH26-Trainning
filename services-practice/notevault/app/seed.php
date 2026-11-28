<?php
// Chạy 1 lần khi container khởi động (xem entrypoint.sh). Idempotent: chạy
// lại bao nhiêu lần cũng không tạo trùng dữ liệu (CREATE TABLE IF NOT EXISTS
// + kiểm tra tồn tại trước khi INSERT).
$host = getenv('DB_HOST') ?: 'db';
$name = getenv('DB_NAME') ?: 'notevault';
$user = getenv('DB_USER') ?: 'notevault';
$pass = getenv('DB_PASS') ?: 'notevault_pw';

$pdo = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin TINYINT NOT NULL DEFAULT 0,
    reset_token VARCHAR(64) NOT NULL
) ENGINE=InnoDB");

$pdo->exec("CREATE TABLE IF NOT EXISTS notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT
) ENGINE=InnoDB");

$pdo->exec("CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    value VARCHAR(255) NOT NULL
) ENGINE=InnoDB");

function ensure_user(PDO $pdo, string $username, string $password, int $isAdmin): int {
    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        return (int)$row['id'];
    }
    $hash = password_hash($password, PASSWORD_BCRYPT);
    $token = bin2hex(random_bytes(8));
    $stmt = $pdo->prepare('INSERT INTO users (username, password_hash, is_admin, reset_token) VALUES (?, ?, ?, ?)');
    $stmt->execute([$username, $hash, $isAdmin, $token]);
    return (int)$pdo->lastInsertId();
}

function ensure_note(PDO $pdo, int $userId, string $title, string $body): void {
    $stmt = $pdo->prepare('SELECT id FROM notes WHERE user_id = ? AND title = ?');
    $stmt->execute([$userId, $title]);
    if ($stmt->fetch()) {
        return;
    }
    $stmt = $pdo->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
    $stmt->execute([$userId, $title, $body]);
}

// Mật khẩu admin/alice sinh RIÊNG theo từng team, dẫn xuất từ
// SEED_PASSWORD_SECRET (khác FLAG_SECRET -- cái này KHÔNG đổi theo
// `spin.sh rotate`, để không làm mất đăng nhập giữa các round). Nhờ vậy
// team B không biết trước mật khẩu admin của team A (và ngược lại) --
// buộc phải tự tìm đường khai thác (SQLi/IDOR/deserialization/type
// juggling...) thay vì chỉ đăng nhập thẳng bằng mật khẩu demo công khai.
function seed_password(string $role): string {
    $secret = getenv('SEED_PASSWORD_SECRET') ?: 'dev-seed-secret-change-me';
    return substr(hash_hmac('sha256', "seed:$role", $secret), 0, 16);
}

$adminId = ensure_user($pdo, 'admin', seed_password('admin'), 1);
$aliceId = ensure_user($pdo, 'alice', seed_password('alice'), 0);

// {{FLAG:idor}} được thay bằng flag thật lúc hiển thị (xem inc/flag.php) --
// không cần sửa DB khi rotate flag, chỉ cần đổi FLAG_SECRET + restart.
ensure_note($pdo, $adminId, 'Ghi chú riêng của admin', "Đừng cho ai xem note này.\n{{FLAG:idor}}");
ensure_note($pdo, $aliceId, 'Danh sách việc cần làm', "Mua cà phê\nHọp nhóm lúc 14h");

$stmt = $pdo->prepare('SELECT id FROM secrets WHERE name = ?');
$stmt->execute(['app_secret']);
if (!$stmt->fetch()) {
    $pdo->prepare('INSERT INTO secrets (name, value) VALUES (?, ?)')->execute(['app_secret', '{{FLAG:sqli}}']);
}

echo "Seed xong (admin_id=$adminId, alice_id=$aliceId).\n";

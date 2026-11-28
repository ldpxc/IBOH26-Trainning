<?php
// Kết nối PDO chuẩn (dùng prepared statement ở hầu hết nơi).
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DB_HOST') ?: 'db';
        $name = getenv('DB_NAME') ?: 'notevault';
        $user = getenv('DB_USER') ?: 'notevault';
        $pass = getenv('DB_PASS') ?: 'notevault_pw';
        $pdo = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    return $pdo;
}

// Kết nối mysqli THÔ — chỉ search.php dùng, CỐ TÌNH không dùng prepared
// statement ở đó để tái hiện lỗi SQLi kinh điển (1 endpoint "quên" làm đúng
// dù chỗ khác trong app đã làm đúng — rất thực tế).
function raw_mysqli(): mysqli {
    static $conn = null;
    if ($conn === null) {
        $host = getenv('DB_HOST') ?: 'db';
        $name = getenv('DB_NAME') ?: 'notevault';
        $user = getenv('DB_USER') ?: 'notevault';
        $pass = getenv('DB_PASS') ?: 'notevault_pw';
        $conn = new mysqli($host, $user, $pass, $name);
    }
    return $conn;
}

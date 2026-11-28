<?php
function current_user_id(): ?int {
    return $_SESSION['user_id'] ?? null;
}

function require_login(): int {
    $uid = current_user_id();
    if (!$uid) {
        header('Location: /login.php');
        exit;
    }
    return $uid;
}

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

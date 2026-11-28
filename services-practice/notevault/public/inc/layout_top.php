<?php
$uid = current_user_id();
$dark = ($_COOKIE['theme'] ?? '') === 'dark';
?>
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>NoteVault</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:30px auto;padding:0 16px;color:#222;background:#fff}
nav a{margin-right:12px}
input,textarea{width:100%;padding:6px;margin:4px 0;box-sizing:border-box}
.note{border:1px solid #ccc;border-radius:6px;padding:10px;margin:8px 0}
.err{color:#b00}
body.dark{background:#1b1b1b;color:#eee}
body.dark .note{border-color:#444;background:#262626}
body.dark a{color:#8ab4f8}
body.dark input,body.dark textarea{background:#2a2a2a;color:#eee;border:1px solid #444}
</style>
</head>
<body class="<?= $dark ? 'dark' : '' ?>">
<nav>
  <a href="/index.php">Trang chủ</a>
  <a href="/new_note.php">Note mới</a>
  <a href="/upload.php">Avatar</a>
  <a href="/import.php">Import</a>
  <?php if ($uid): ?><a href="/logout.php">Đăng xuất</a><?php else: ?><a href="/login.php">Đăng nhập</a><?php endif; ?>
  <?php if ($dark): ?>
    <a href="/theme.php?mode=light">☀️ Light mode</a>
  <?php else: ?>
    <a href="/theme.php?mode=dark">🌙 Dark mode</a>
  <?php endif; ?>
</nav>
<hr>

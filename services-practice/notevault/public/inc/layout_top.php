<?php $uid = current_user_id(); ?>
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>NoteVault</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:30px auto;padding:0 16px;color:#222}
nav a{margin-right:12px}
input,textarea{width:100%;padding:6px;margin:4px 0;box-sizing:border-box}
.note{border:1px solid #ccc;border-radius:6px;padding:10px;margin:8px 0}
.err{color:#b00}
</style>
</head>
<body>
<nav>
  <a href="/index.php">Trang chủ</a>
  <a href="/new_note.php">Note mới</a>
  <a href="/upload.php">Avatar</a>
  <a href="/import.php">Import</a>
  <?php if ($uid): ?><a href="/logout.php">Đăng xuất</a><?php else: ?><a href="/login.php">Đăng nhập</a><?php endif; ?>
</nav>
<hr>

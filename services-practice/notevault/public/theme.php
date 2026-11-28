<?php
require __DIR__ . '/inc/config.php';

$mode = ($_GET['mode'] ?? '') === 'dark' ? 'dark' : 'light';
setcookie('theme', $mode, time() + 86400 * 30, '/');

$back = $_SERVER['HTTP_REFERER'] ?? '/index.php';
header('Location: ' . $back);

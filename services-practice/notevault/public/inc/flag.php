<?php
// Sinh flag đúng khuôn FHACKER2026{64 hex} từ 1 "slug" cố định mỗi lỗ hổng,
// dựa trên FLAG_SECRET (env, đổi được để rotate toàn bộ flag cùng lúc —
// xem services-practice/spin.sh rotate).
function flag(string $slug): string {
    $secret = getenv('FLAG_SECRET') ?: 'dev-secret-change-me';
    $hex = hash_hmac('sha256', $slug, $secret);
    return "FHACKER2026{" . $hex . "}";
}

// Thay marker {{FLAG:slug}} (lưu tĩnh trong DB/file) bằng flag thật tại thời
// điểm hiển thị — nhờ vậy rotate flag chỉ cần đổi FLAG_SECRET + restart,
// không phải sửa lại dữ liệu đã seed.
function render_flags(string $text): string {
    return preg_replace_callback('/\{\{FLAG:([a-z_]+)\}\}/', function ($m) {
        return flag($m[1]);
    }, $text);
}

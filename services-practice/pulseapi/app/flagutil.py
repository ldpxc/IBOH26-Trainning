"""Sinh flag đúng khuôn FHACKER2026{64 hex} từ 1 slug cố định mỗi lỗ hổng.

Rotate flag: đổi biến môi trường FLAG_SECRET rồi restart container -- không
cần sửa code/dữ liệu gì khác (xem services-practice/spin.sh).
"""
import hashlib
import hmac
import os


def flag(slug: str) -> str:
    secret = os.environ.get("FLAG_SECRET", "dev-secret-change-me")
    digest = hmac.new(secret.encode(), slug.encode(), hashlib.sha256).hexdigest()
    return f"FHACKER2026{{{digest}}}"

"""
pulseapi -- service luyện tập F-Hacker 2026 (CHỈ dùng nội bộ, nhiều lỗ hổng cố
ý). Xem services-practice/README.md / plan để biết danh sách đầy đủ.

State lưu trong RAM (dict Python) cho gọn -- không cần DB riêng cho service
luyện tập này. KHÔNG dùng pattern này cho app thật.
"""
import base64
import hashlib
import os
import threading
import time

import requests
import yaml
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from flask import Flask, jsonify, redirect, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from flagutil import flag

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev-flask-secret-change-me")

AES_KEY = os.environ.get("APP_AES_KEY", "0123456789abcdef").encode()[:16].ljust(16, b"0")
BLOCK = 16

# Flag dạng file cho các lỗ hổng dẫn tới RCE trực tiếp (SSTI/eval/YAML/Werkzeug
# console) -- ghi lại mỗi lần tiến trình khởi động nên rotate chỉ cần đổi
# FLAG_SECRET + restart container, không cần sửa code.
for _slug, _path in {
    "ssti": "/tmp/flag_ssti.txt",
    "eval": "/tmp/flag_eval.txt",
    "yaml": "/tmp/flag_yaml.txt",
    "werkzeug_pin": "/tmp/flag_werkzeug.txt",
}.items():
    with open(_path, "w") as _f:
        _f.write(flag(_slug) + "\n")

# ============================================================
# "DATABASE" trong RAM
# ============================================================
USERS = {
    "alice": {
        "password_hash": generate_password_hash("alice_demo_pw_2026"),
        "bio": "Xin chào, tôi là Alice. Thích cà phê và CTF.",
        "role": "user",
        "points": 100,
        "redeemed_codes": {},
    },
    "guest": {
        "password_hash": generate_password_hash("guest_demo_pw_2026"),
        "bio": "Tài khoản khách demo.",
        "role": "user",
        "points": 10,
        "redeemed_codes": {},
    },
}
WALLET_LOCK_NOTE = "cố ý KHÔNG dùng threading.Lock() ở /redeem -- xem mục Race Condition"


# ============================================================
# Internal-only service (giả lập hệ thống nội bộ) -- dùng cho bài SSRF.
# Chỉ bind 127.0.0.1, KHÔNG public ra ngoài -- nhưng app chính (public) có thể
# tự gọi tới nó qua endpoint /webhook/preview -- đó chính là lỗ hổng SSRF.
# ============================================================
internal_app = Flask("pulseapi-internal")


@internal_app.route("/internal/status")
def internal_status():
    return jsonify({"service": "internal-admin-panel", "status": "ok"})


@internal_app.route("/internal/flag")
def internal_flag():
    return jsonify({"flag": flag("ssrf")})


def _run_internal_service():
    internal_app.run(host="127.0.0.1", port=7001, debug=False, use_reloader=False)


# ============================================================
# AUTH helpers
# ============================================================
def current_user():
    return session.get("user")


def require_login():
    if not current_user():
        return jsonify({"error": "login required"}), 401
    return None


# ============================================================
# Auth routes
# ============================================================
@app.route("/register", methods=["POST"])
def register():
    data = request.form or request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "missing username/password"}), 400
    if username in USERS:
        return jsonify({"error": "username exists"}), 400
    USERS[username] = {
        "password_hash": generate_password_hash(password),
        "bio": "Chưa có giới thiệu.",
        "role": "user",
        "points": 10,
        "redeemed_codes": {},
    }
    return jsonify({"status": "registered"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({"hint": "POST username, password (form hoặc JSON). "
                                 "Thêm ?next=<url> để redirect sau khi đăng nhập."})
    data = request.form or request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "sai username hoặc password"}), 401
    session["user"] = username

    # LỖ HỔNG: Open Redirect -- ?next= không được kiểm tra có cùng domain
    # không trước khi redirect.
    next_url = request.args.get("next")
    if next_url:
        resp = redirect(next_url)
        if next_url.startswith("http") and not next_url.startswith(request.host_url):
            # "Phát hiện" redirect ra ngoài domain -- chèn flag vào body kèm
            # response redirect làm bằng chứng khai thác thành công (xem
            # bằng curl -v hoặc view-source, trình duyệt thật sẽ không hiện).
            resp.set_data(resp.get_data() + f"<!-- {flag('open_redirect')} -->".encode())
        return resp
    return jsonify({"status": "logged in", "user": username})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "logged out"})


# ============================================================
# 1) LỖ HỔNG: SSTI -- bio người dùng được render thẳng bằng
# render_template_string() thay vì chỉ truyền làm biến cho 1 template cố định.
# ============================================================
from flask import render_template_string  # noqa: E402

PROFILE_WRAPPER = """
<h1>Hồ sơ của {{ username }}</h1>
<div class="bio">{{ bio_html|safe }}</div>
"""


@app.route("/profile/<username>")
def view_profile(username):
    user = USERS.get(username)
    if not user:
        return jsonify({"error": "not found"}), 404
    bio_html = render_template_string(user["bio"])  # <-- lỗ hổng SSTI ở đây
    return render_template_string(PROFILE_WRAPPER, username=username, bio_html=bio_html)


@app.route("/profile/edit", methods=["POST"])
def edit_profile():
    err = require_login()
    if err:
        return err
    data = request.form or request.get_json(silent=True) or {}
    USERS[current_user()]["bio"] = data.get("bio", "")
    return jsonify({"status": "bio updated"})


# ============================================================
# 2) LỖ HỔNG: SSRF -- webhook preview fetch URL tuỳ ý, không giới hạn
# domain/IP đích, kể cả 127.0.0.1 (chạm được internal_app ở cổng 7001).
# ============================================================
@app.route("/webhook/preview", methods=["POST"])
def webhook_preview():
    err = require_login()
    if err:
        return err
    data = request.get_json(silent=True) or request.form
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "missing url"}), 400
    try:
        r = requests.get(url, timeout=3)
        return jsonify({"status_code": r.status_code, "body_snippet": r.text[:2000]})
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


# ============================================================
# 3) LỖ HỔNG: Code Injection qua eval() -- "máy tính công thức giá"
# ============================================================
@app.route("/calc", methods=["POST"])
def calc():
    err = require_login()
    if err:
        return err
    data = request.form or request.get_json(silent=True) or {}
    formula = data.get("formula", "0")
    try:
        result = eval(formula)  # noqa: S307 -- CỐ Ý, xem bài code_injection_eval.html
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})


# ============================================================
# 4) LỖ HỔNG: Werkzeug Debug Console -- debug=True còn bật ở production,
# PIN tính được qua thông tin máy (xem lang_tricks_misc.html mục 08).
# /crash-test ném lỗi có chủ đích để lộ trang debug.
# ============================================================
@app.route("/crash-test")
def crash_test():
    x = int(request.args.get("x", "1"))
    return jsonify({"result": 100 // x})  # x=0 -> ZeroDivisionError -> trang debug


# ============================================================
# 5) LỖ HỔNG: YAML RCE -- yaml.load() với Loader không an toàn trên input
# người dùng (import file cấu hình).
# ============================================================
@app.route("/config/import", methods=["POST"])
def config_import():
    err = require_login()
    if err:
        return err
    raw = request.get_data(as_text=True)
    try:
        parsed = yaml.load(raw, Loader=yaml.Loader)  # noqa: S506 -- CỐ Ý
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"status": "imported", "parsed_repr": repr(parsed)[:500]})


# ============================================================
# 6) LỖ HỔNG: Mass Assignment -- update profile merge thẳng JSON người dùng
# gửi lên vào record, không allowlist field (role, points đều ghi đè được).
# ============================================================
@app.route("/profile/update", methods=["POST"])
def profile_update():
    err = require_login()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    USERS[current_user()].update(data)  # <-- không lọc field nào được phép
    return jsonify({"status": "updated", "profile": {
        k: v for k, v in USERS[current_user()].items() if k != "password_hash"
    }})


@app.route("/admin/flag")
def admin_flag():
    err = require_login()
    if err:
        return err
    user = USERS[current_user()]
    if user.get("role") != "admin":
        return jsonify({"error": "forbidden, cần role=admin"}), 403
    return jsonify({"flag": flag("mass_assignment")})


# ============================================================
# 7) LỖ HỔNG: Race Condition -- redeem code cộng điểm, kiểm tra "đã dùng
# chưa" rồi MỚI ghi nhận (check-then-act), không khoá -- gửi đồng thời nhiều
# request là redeem được nhiều lần.
# ============================================================
REWARD_CODES = {"WELCOME2026": 50}


@app.route("/redeem", methods=["POST"])
def redeem():
    err = require_login()
    if err:
        return err
    data = request.get_json(silent=True) or request.form
    code = data.get("code", "")
    reward = REWARD_CODES.get(code)
    if reward is None:
        return jsonify({"error": "mã không hợp lệ"}), 400

    user = USERS[current_user()]
    if code in user["redeemed_codes"]:
        return jsonify({"error": "mã đã dùng rồi"}), 400

    # Mô phỏng độ trễ xử lý thật (gọi service khác, ghi log...) --
    # khoảng hở giữa "check" và "act" chính là race window.
    time.sleep(0.05)
    user["points"] += reward
    user["redeemed_codes"][code] = True

    resp = {"status": "redeemed", "points": user["points"]}
    if user["points"] >= 500:
        resp["flag"] = flag("race_condition")
    return jsonify(resp)


# ============================================================
# 8) LỖ HỔNG: Padding Oracle -- cookie "remember me" tự chế AES-CBC, endpoint
# check trả lỗi KHÁC NHAU giữa padding sai và padding đúng.
# ============================================================
def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK != 0:
        raise ValueError("invalid length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return data[:-pad_len]


def encrypt_remember(username: str) -> str:
    iv = get_random_bytes(BLOCK)
    ct = AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(_pkcs7_pad(username.encode()))
    return (iv + ct).hex()


def decrypt_remember(token_hex: str) -> str:
    raw = bytes.fromhex(token_hex)
    iv, ct = raw[:BLOCK], raw[BLOCK:]
    pt = AES.new(AES_KEY, AES.MODE_CBC, iv).decrypt(ct)
    return _pkcs7_unpad(pt).decode(errors="replace")


@app.route("/remember/sample")
def remember_sample():
    # Cấp 1 token hợp lệ mẫu để tham khảo cấu trúc (giống tiền đề trong
    # combat card bài Padding Oracle) -- username "guest", không phải admin.
    return jsonify({"token": encrypt_remember("guest")})


@app.route("/remember/check")
def remember_check():
    token = request.args.get("token", "")
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return jsonify({"error": "token không phải hex hợp lệ"}), 400
    try:
        name = decrypt_remember(token)
    except ValueError:
        # Padding sai -- CỐ Ý trả mã lỗi khác với trường hợp padding đúng.
        return jsonify({"error": "invalid padding"}), 400
    if name == "admin":
        return jsonify({"status": "ok", "user": name, "flag": flag("padding_oracle")})
    return jsonify({"status": "ok", "user": name})


# ============================================================
# 9) LỖ HỔNG: Hash Length Extension -- link export ký bằng
# sha256(secret + data), không dùng HMAC chuẩn.
# ============================================================
EXPORT_SECRET = os.environ.get("EXPORT_SECRET", "export-signing-secret-2026").encode()


@app.route("/export/sample")
def export_sample():
    data = b"user=alice&role=user"
    sig = hashlib.sha256(EXPORT_SECRET + data).hexdigest()
    return jsonify({"data_hex": data.hex(), "sig": sig})


@app.route("/export")
def export_data():
    data_hex = request.args.get("data", "")
    sig = request.args.get("sig", "")
    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        return jsonify({"error": "data không phải hex hợp lệ"}), 400

    expected = hashlib.sha256(EXPORT_SECRET + data).hexdigest()
    if sig != expected:
        return jsonify({"error": "chữ ký không hợp lệ"}), 403

    resp = {"status": "exported", "data": data.decode(errors="replace")}
    if b"role=admin" in data:
        resp["flag"] = flag("hash_length_ext")
    return jsonify(resp)


# ============================================================
# Trang chủ
# ============================================================
@app.route("/")
def index():
    return jsonify({
        "service": "pulseapi",
        "endpoints": [
            "/register", "/login", "/logout",
            "/profile/<username>", "/profile/edit", "/profile/update",
            "/webhook/preview", "/calc", "/crash-test",
            "/config/import", "/admin/flag", "/redeem",
            "/remember/sample", "/remember/check",
            "/export/sample", "/export",
        ],
    })


if __name__ == "__main__":
    threading.Thread(target=_run_internal_service, daemon=True).start()
    # use_reloader=False: tránh Werkzeug fork lại tiến trình (sẽ cố bind cổng
    # 7001 2 lần cho internal_app) -- debug=True vẫn giữ nguyên debugger/PIN.
    app.run(host="0.0.0.0", port=80, debug=True, use_reloader=False)

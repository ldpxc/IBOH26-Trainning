# Sheatchee - Burp -> Python Copy-Paste Cookbook

Kho code mẫu để chuyển thao tác đã làm được trên **Burp Suite** sang **Python** thật nhanh khi thi offline (không AI, không Internet).

## Chưa biết Python / chưa biết khai thác web (hack web)?

Đọc [`00_Bat_Dau_Tu_Zero.md`](00_Bat_Dau_Tu_Zero.md) trước — 15-20 phút, dạy từ con số 0: cú pháp Python tối thiểu, Burp request map sang Python ra sao, và 1 bài ví dụ đầy đủ từ "giải tay" đến "script chạy được", giải thích từng dòng.

## Quy trình dùng trong phòng thi

1. **Giải tay trên Burp** cho 1 đội/mục tiêu.
2. **Copy file mẫu**: `cp scripts/template.py bai1.py` (hoặc Copy-Item trên Windows).
3. **Mở cheatsheet**: [`CHEATSHEET_NHANH.md`](CHEATSHEET_NHANH.md) -> chọn đúng snippet.
4. **Dán logic vào `solve_one()`** trong `bai1.py`, sửa `TARGETS_FILE/USE_PROXY/FLAG_RE/OWN_FLAGS` nếu cần.
5. **Chạy**: `python bai1.py`.

## Bắt đầu nhanh

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install requests beautifulsoup4
```

Chuẩn bị targets:

```bash
# Windows
Copy-Item scripts\targets.example.txt scripts\targets.txt
# Linux/macOS
# cp scripts/targets.example.txt scripts/targets.txt
```

Sửa `scripts/targets.txt`, rồi chạy template:

```bash
python scripts/template.py
```

## Cấu trúc gọn

| Đường dẫn | Dùng để làm gì |
|---|---|
| [`00_Bat_Dau_Tu_Zero.md`](00_Bat_Dau_Tu_Zero.md) | Học từ 0: Python tối thiểu + Burp->Python + 1 ví dụ đầy đủ có giải thích |
| [`CHEATSHEET_NHANH.md`](CHEATSHEET_NHANH.md) | Mục lục tra cứu 5 giây: cần gì -> mở file nào |
| [`scripts/template.py`](scripts/template.py) | File độc lập 1-file, copy ra thành `baiX.py` rồi sửa `solve_one()` |
| [`scripts/targets.txt`](scripts/targets.txt) | Danh sách mục tiêu dùng khi chạy thật (để trên máy bạn, không đưa lên git) |
| [`scripts/targets.example.txt`](scripts/targets.example.txt) | Mẫu targets, có `@OUR_TEAM` và comment `#` |
| `01_Request_Co_Ban/` | GET/POST/Header-Cookie/Upload/Encoding |
| `02_Chuoi_Request/` | Login, CSRF, truyền ID, đọc response, tính toán cục bộ (JWT/hash/brute-force) |
| `03_Thao_Tac_Nang_Cao/` | Vòng lặp Intruder, song song, polling, WebSocket |
| `04_Theo_Lo_Hong/` | 28 bài theo từng lỗ hổng: SQLi/NoSQLi, Command/Code Injection, IDOR, Mass Assignment, LFI, Upload, SSRF, SSTI, XSS/CSRF, CORS, Open Redirect, XXE, GraphQL, HTTP Smuggling, Deserialization, JWT/Session Forge/OAuth-SAML, Crypto (hash length ext/padding oracle), Race Condition, PHP Type Juggling, Prototype Pollution, WAF Bypass, Recon/Source Leak, mẹo theo ngôn ngữ |
| `05_Nhieu_Doi_Va_Flag/` | Lặp targets, trích flag, lưu flag |
| `06_Debug/` | Python qua Burp, khác biệt Burp/Python, 403/WAF, lỗi thường gặp |
| `07_Chall_Kiem_Chung/` | Tự dựng lab nhỏ để kiểm chứng script chạy đúng |
| `08_Khai_Thac_Lo_Hong_Web/` | Nhận ra lỗ hổng bằng mắt (ví dụ đời thường + dấu hiệu), code mẫu nằm ở `04_` |

## Quy ước snippet

- Mỗi file `01_`-`06_` có đoạn Python ngắn, **độc lập**, có đủ `import`, copy vào `solve_one()` là chạy.
- Host mẫu: `http://target`. Thay bằng mục tiêu thật.
- Luôn có `timeout`; khi quét nhiều đội cùng lúc dùng `workers=4`, nghỉ `delay=0.5` giây giữa mỗi lần gửi.
- Chỉ dùng trên hệ thống/lab/CTF được phép.

## Tài liệu chi tiết

- Cấu trúc dự án: [`CAU_TRUC_DU_AN.md`](CAU_TRUC_DU_AN.md)
- Đánh giá mô hình trước khi đơn giản hóa (lưu sử, các script nhắc tới trong đó đã bị gỡ): [`DANH_GIA_MO_HINH_HIEN_TAI.md`](DANH_GIA_MO_HINH_HIEN_TAI.md)

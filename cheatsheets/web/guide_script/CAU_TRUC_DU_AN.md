# Cấu trúc dự án Sheatchee

Sheatchee là **Kho Code Mẫu (Copy-Paste Cookbook)** để chuyển thao tác từ Burp Suite sang Python nhanh khi thi offline. Ưu tiên: snippet ngắn, độc lập, copy-là-chạy.

> Phạm vi: chỉ dùng trên hệ thống/lab/CTF được phép kiểm thử.

## 1. Cây thư mục

```text
Sheatchee/
├── README.md
├── 00_Bat_Dau_Tu_Zero.md        # Học từ 0: Python tối thiểu + Burp->Python + ví dụ đầy đủ
├── CHEATSHEET_NHANH.md          # Mục lục tra cứu 5 giây
├── CAU_TRUC_DU_AN.md
├── DANH_GIA_MO_HINH_HIEN_TAI.md # Đánh giá trước khi đơn giản hóa (lưu sử)
├── requirements.txt
├── .gitignore
│
├── scripts/
│   ├── template.py              # File độc lập: copy thành baiX.py, sửa solve_one()
│   ├── targets.txt              # Runtime local (gitignored)
│   └── targets.example.txt      # Mẫu targets
│
├── 01_Request_Co_Ban/           # GET/POST/Header-Cookie/Upload/Encoding
├── 02_Chuoi_Request/            # Login, CSRF, truyền ID, đọc response
├── 03_Thao_Tac_Nang_Cao/        # Vòng lặp, song song, polling
├── 04_Theo_Lo_Hong/             # SQLi, IDOR, LFI, CMDi, SSTI, SSRF, Upload, XSS/CSRF
├── 05_Nhieu_Doi_Va_Flag/        # Lặp targets, trích flag, lưu flag
├── 06_Debug/                    # Python qua Burp, Burp!=Python, 403/WAF, lỗi thường gặp
├── 07_Chall_Kiem_Chung/         # Ý tưởng lab tự kiểm chứng
├── 08_Khai_Thac_Lo_Hong_Web/    # Tài liệu nền tảng lỗ hổng web
│
├── logs/                        # Runtime (gitignored)
└── results/                     # Runtime, flags.txt... (gitignored)
```

## 2. Thành phần cốt lõi

### `scripts/template.py`
- **Độc lập 100%**: chỉ `requests` + stdlib, không import `common.py`, không đọc `config.yaml`.
- Có: `load_targets()` (bỏ `@OUR_TEAM`, localhost, dòng `#`), `USE_PROXY/PROXY_URL`, `solve_one(session, base_url)`, regex flag `FHACKER2026\{[0-9a-fA-F]{64}\}`, `OWN_FLAGS`, `ThreadPoolExecutor(max_workers=4)`, `timeout=4`, `DELAY=0.5`, ghi `results/flags.txt` không trùng.
- Cách dùng: copy thành `bai1.py`, chỉ sửa `solve_one()`.

### `scripts/targets.txt`
```text
@OUR_TEAM http://10.0.1.1:8000
http://10.0.2.1:8000
# 10.0.3.1:8000   # tắt tạm
10.0.4.1:8000      # tự thêm http://
```

## 3. Quy ước snippet (01-06)

- Mỗi file có code Python ngắn (10-25 dòng), **đủ import, chạy độc lập**.
- Copy vào `solve_one()` trong `template.py` hoặc chạy như script nhỏ.
- Trọng tâm: cú pháp hay quên khi không có AI (raw URL/PreparedRequest, multipart tuple, CSRF, Session, proxy Burp, ThreadPoolExecutor, regex flag).
- Không phụ thuộc `from scripts.common import ...`.

## 4. Điểm vào nhanh

| Nhu cầu | Mở |
|---|---|
| Chưa biết Python/exploit web, cần học từ 0 | [`00_Bat_Dau_Tu_Zero.md`](00_Bat_Dau_Tu_Zero.md) |
| Tra cứu 5 giây | [`CHEATSHEET_NHANH.md`](CHEATSHEET_NHANH.md) |
| Bắt đầu exploit nhiều đội | [`scripts/template.py`](scripts/template.py) |
| Request cơ bản | `01_Request_Co_Ban/` |
| Chuỗi login/CSRF/ID | `02_Chuoi_Request/` |
| Song song/polling | `03_Thao_Tac_Nang_Cao/` |
| Payload theo lỗ hổng | `04_Theo_Lo_Hong/` |
| Lặp đội/trích/lưu flag | `05_Nhieu_Doi_Va_Flag/` |
| Debug Burp vs Python / 403 | `06_Debug/` |

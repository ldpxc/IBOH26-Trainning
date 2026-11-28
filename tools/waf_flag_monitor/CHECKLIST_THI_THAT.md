# Checklist nhanh lúc thi thật — đừng quên

File này chỉ để đọc nhanh lúc thi, không giải thích dài — lý do/bằng chứng xem
`HANDOVER.md` mục 6 (đã kiểm chứng thật trên 3 service x 2 team, 2026-11-29).

> 🛡️ **Chưa biết app thật của BTC?** Add ngay bộ rule nền tảng
> [`baseline_ruleset_pass.conf`](baseline_ruleset_pass.conf) từ đầu giải
> (chế độ Detect) — xem [`CHECKLIST_VAN_HANH_BASELINE.md`](CHECKLIST_VAN_HANH_BASELINE.md)
> để biết cách quan sát/xử lý trước khi chuyển Prevent.

---

## A. Đẩy rule WAF lên UI BunkerWeb — làm đúng thứ tự

1. **Service (phạm vi) = Global.** **KHÔNG chọn tên service cụ thể**, kể cả
   khi chỉ có 1 service. Chọn theo tên service → rule bị lưu vào chỗ nginx
   không include tới → **không bao giờ chạy, không báo lỗi gì cả.**
2. **Config Type**: `MODSEC` cho `SecRule` thường. `SERVER_HTTP` chỉ khi cần
   ẩn header lộ flag (`proxy_hide_header <Header>;`).
3. **Action trong rule: để `pass,log` trước.** Không đổi `deny` ngay.
4. Lưu xong → **tự gửi lại đúng payload đã dùng để sinh rule** → mở lại
   traffic log, xác nhận **rule ID của mình xuất hiện** trong `modsec_ids`.
   Không thấy = rule chưa thật sự nạp, quay lại bước 1 kiểm tra Service scope.
5. Chắc ăn rồi mới đổi action rule đó sang `deny,status:403,log`.
6. Gửi lại payload tấn công → phải thấy `403`. Gửi thêm vài request bình
   thường (tiếng Việt, có dấu nháy `'`, JSON thường) → phải vẫn `200`.

### Lưu ý dễ nhầm: 2 công tắc khác nhau

- **`SecRuleEngine` toàn WAF** (Cài đặt chung → ModSecurity): `DetectionOnly`
  (mặc định, chỉ ghi log) hay `On` (chặn thật). Đây là **công tắc tổng**.
- **Action của từng rule** (`pass`/`deny`): chỉ có tác dụng khi công tắc tổng
  đang `On`. Rule để `deny` mà công tắc tổng vẫn `DetectionOnly` → **không
  chặn gì cả**, dù rule đã nạp đúng và khớp payload.

→ Workflow thật: viết rule ở `pass,log`, xác nhận khớp (bước 4) — **luôn an
toàn** vì chưa đụng tới công tắc tổng. Chỉ khi đội **quyết định bật chặn thật
sự** mới: (a) bật `SecRuleEngine = On` nếu chưa bật, và (b) đổi action rule
cụ thể đó sang `deny`.

---

## B. Sinh xong Exploit Script rồi làm gì

1. Tải script (`.py`) từ modal "⚔️ Sinh Exploit Script".
2. **Copy file vào `cheatsheets/web/guide_script/scripts/`, đặt cạnh
   `template.py`** — dùng chung `targets.txt` và `results/flags.txt` đã có
   sẵn, không tạo lại.
3. Mở `targets.txt`, kiểm tra đúng dòng `@OUR_TEAM <IP đội mình>` và danh
   sách đội khác đã cập nhật đúng (BTC công bố IP/domain gì thì dán nguyên
   dòng đó, chấp nhận cả domain/URL, không bắt buộc IP:port).
4. Đọc đoạn `GHI CHÚ TỰ ĐỘNG` ngay đầu file:
   - Nếu nói **"không cần đăng nhập"** → bỏ qua bước 5, chạy luôn.
   - Nếu nói **"cần đăng nhập"** → mở `solve_one()`, điền 1 trong 2 mẫu có
     sẵn (form login / API JSON login), rồi **xoá dòng
     `headers.update(SESSION_PLACEHOLDERS)`** (nếu không xoá, cookie cũ của
     đối thủ sẽ đè lên session mới vừa đăng nhập).
5. Nếu lỗ hổng **2 bước** (vd: POST lưu payload, phải GET lại trang khác mới
   render/trả flag — kiểu SSTI) → thêm 1 dòng gọi request tiếp theo vào cuối
   `solve_one()`, sau dòng replay chính. Script không tự phát hiện ca này.
6. Dán (các) cờ ĐỘI MÌNH vào `OWN_FLAGS` ở đầu file **trước khi chạy** —
   tránh tự lưu/nộp nhầm cờ nhà.
7. Chạy: `python3 <ten_file>.py`
8. Kết quả nằm trong `results/flags.txt`. **Script KHÔNG tự nộp cờ** — tự đối
   chiếu đúng IP ↔ tên đội rồi mới nộp tay (nộp nhầm cờ nhà bị trừ gấp đôi
   điểm DEF — Điều 5 Quy chế).

---

## Vị trí các file liên quan

- Công cụ monitor + sinh rule/exploit: `tools/waf_flag_monitor/` (chạy
  `./waf_monitor.sh start --password ...`)
- Khuôn script tấn công nhiều đội: `cheatsheets/web/guide_script/scripts/`
  (`template.py`, `targets.txt`, `targets.example.txt`)
- Quy chế gốc: `docs/fhacker26/QuyChe BangC.pdf`
- Chi tiết kỹ thuật/lý do của checklist này: `tools/waf_flag_monitor/HANDOVER.md` mục 5-6

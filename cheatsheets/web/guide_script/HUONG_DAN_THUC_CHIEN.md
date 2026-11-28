# Hướng dẫn thực chiến A/D

Tài liệu này dành cho CTF Attack-Defense offline (10 round, giới hạn 30 lần nộp cờ/phút, WAF BunkerWeb có UI traffic log). Mọi lệnh chạy từ thư mục gốc repo.

> Chỉ dùng trên hệ thống bạn được phép kiểm thử. Tuyệt đối không tấn công/nộp cờ đội nhà.

## 1. Thử nghiệm trước ngày thi trên `2026-waf-practice`

### 1.1. Bật môi trường luyện tập

Trong repo `2026-waf-practice`:

```bash
make up
# App: http://localhost:8000
# WAF UI: http://localhost:8005
```

Kiểm tra nhanh:

```bash
curl http://localhost:8000
# Mở browser: http://localhost:8005
```

### 1.2. Tạo file targets test riêng (không dùng targets thi đấu)

```powershell
Copy-Item scripts\targets.example.txt scripts\targets.local.txt
```

Sửa `scripts/targets.local.txt` chỉ còn mục tiêu local:

```text
# File test local - KHÔNG dùng trong giờ thi
local http://localhost:8000 prio=1
```

> `load_targets()` mặc định lọc `localhost/127.0.0.1` để an toàn. Khi test local, dùng file test riêng và **chỉ chạy có chủ đích**; nếu cần test thực sự vào localhost, tạm chỉnh host trong file test thành IP máy lab được phép hoặc dùng `http_client.py` trực tiếp với `--base-url http://localhost:8000`. Không đưa file local test vào `targets.txt` thi đấu.

Cách test an toàn hơn (không bypass bộ lọc localhost của mass mode): dùng `http_client.py`/`exploit_template.py` với `--base-url http://localhost:8000`, và dùng `waf_log_helper.py` để đọc log WAF.

### 1.3. Chạy thử luồng debug + WAF log

Terminal debug (Burp bật):

```bash
python scripts/http_client.py GET / --base-url http://localhost:8000 --proxy http://127.0.0.1:8080 --insecure -v
```

Giả lập log WAF hoặc export log từ UI/cổng 8005 ra file `logs/waf.log`, sau đó:

```bash
python scripts/waf_log_helper.py --file logs/waf.log --since-seconds 30
python scripts/waf_log_helper.py --file logs/waf.log --status 403 --to-http-client
```

Kiểm tra `manage_targets.py`:

```bash
python scripts/manage_targets.py --targets scripts/targets.example.txt --list
```

## 2. 30 phút trước giờ thi (`08h00 – 08h30`, chưa gửi request vào đối thủ)

### 2.1. Chuẩn bị file

```powershell
Copy-Item scripts\config.example.yaml scripts\config.yaml
Copy-Item scripts\targets.example.txt scripts\targets.txt
```

Chỉnh `scripts/config.yaml`:

- `flag_patterns` có `FHACKER2026\{[0-9a-fA-F]{64}\}`.
- `dashboard.submit_url`, `interval_sec: 2.15`, `payload_format`, `flag_field`.
- `proxy` trỏ Burp nếu debug, nhưng **run_teams A/D sẽ tự bỏ qua proxy** trừ khi `--use-proxy`.

### 2.2. Điền targets

Sửa `scripts/targets.txt`:

```text
@OUR_TEAM http://10.0.1.1:8000

team_02 http://10.0.2.1:8000 prio=1
team_03 http://10.0.3.1:8000 prio=1
10.0.4.1:8000 prio=1
# team_05 http://10.0.5.1:8000 prio=1  # tắt nhanh nếu cần
```

Kiểm tra:

```bash
python scripts/manage_targets.py --list
python scripts/run_teams.py --targets scripts/targets.txt --dry-run
```

Xác nhận: có `@OUR_TEAM`, không có IP đội nhà trong danh sách active.

### 2.3. Khóa cờ nhà

Khi có cờ đội nhà (hoặc trước khi submit), thêm ngay:

```bash
python scripts/manage_targets.py --add-own-flag FHACKER2026{...64hex...}
# hoặc
python scripts/submit_flags.py --add-own FHACKER2026{...64hex...}
```

Kiểm tra dry-run submit:

```bash
python scripts/submit_flags.py --config scripts/config.yaml --dry-run --once
```

## 3. Vận hành mô hình 2 cửa sổ xuyên suốt 10 Round (`08h30 – 11h30`)

### Cửa sổ 1 - Debug/Burp/WAF

Mục đích: tìm lỗ hổng, test payload, replay request lạ, xử lý 403.

```bash
# Test request đơn qua Burp
python scripts/http_client.py GET /vuln --base-url http://10.0.2.1:8000 --proxy http://127.0.0.1:8080 --insecure -v

# Chạy exploit template debug 1 đội
python scripts/my_exploit.py --base-url http://10.0.2.1:8000 --proxy http://127.0.0.1:8080 --insecure -v

# Đọc log WAF đội nhà
python scripts/waf_log_helper.py --file logs/waf.log --since-seconds 30 --to-http-client
```

Khi gặp 403: mở [`06_Debug/04_Khi_Gap_WAF_403.md`](06_Debug/04_Khi_Gap_WAF_403.md). Đổi **một biến mỗi lần** (header, content-type, encoding, HPP), không spam retry.

### Cửa sổ 2 - Mass exploit (không phụ thuộc proxy debug)

Mục đích: quét targets.txt, thu flag, lưu JSONL. **Không bật Burp proxy** trừ khi thật sự cần `--use-proxy`.

Đầu mỗi round:

```bash
# Khóa cờ nhà mới nếu có
python scripts/manage_targets.py --add-own-flag FHACKER2026{...}

# Reset ưu tiên vì đầu round DEF đầy lại
python scripts/manage_targets.py --reset-round
python scripts/manage_targets.py --list
```

Chạy trong round:

```bash
# Round 1-3: tối đa 2 flag/đội/round
python scripts/run_teams.py --targets scripts/targets.txt --workers 4 --delay 0.5 --max-flags-per-team 2 --round-id R1

# Round 4-10: đổi sang 3 flag/đội/round
python scripts/run_teams.py --targets scripts/targets.txt --workers 4 --delay 0.5 --max-flags-per-team 3 --round-id R4
```

Chạy lặp tự động:

```bash
python scripts/run_teams.py --targets scripts/targets.txt --loop --interval 60 --workers 4 --delay 0.5 --max-flags-per-team 2 --round-id R1
```

Khi đội đã về `DEF = 0`:

```bash
python scripts/manage_targets.py --set-def0 team_02
```

`load_targets()` hot-reload, nên vòng tiếp theo sẽ hạ ưu tiên đội đó. Flag mới in ra theo thứ tự `DEF>0` trước.

### Cửa sổ 3 (tuỳ chọn) - Submitter

```bash
python scripts/submit_flags.py --config scripts/config.yaml
```

Submitter chạy độc lập, cách nhau tối thiểu 2.15s, không nộp cờ nhà, lưu state.

## 4. Bảng xử lý sự cố nhanh

| Sự cố | Cơ chế chặn/xử lý | Việc cần làm |
|---|---|---|
| Lỡ dán IP đội mình vào `targets.txt` | `load_targets()` lọc cứng `@OUR_TEAM`, `localhost`, `127.0.0.1`, `::1`; `FlagStore` + `submit_flags.py` chặn cờ trong `results/own_flags.txt` | Khai báo `@OUR_TEAM`; thêm cờ nhà bằng `manage_targets.py --add-own-flag`; chạy `--dry-run` trước |
| Quên tắt Burp proxy trong `config.yaml` | `run_teams.py` ở A/D mode mặc định bỏ proxy config, chỉ bật khi có `--use-proxy` | Không cần sửa config gấp; nếu muốn dùng proxy thật sự thì thêm `--use-proxy` có chủ đích |
| Gặp `403 Forbidden` khi exploit | `request()` không tự retry 403/429; run_teams giữ `workers/delay/timeout` an toàn | Mở [`06_Debug/04_Khi_Gap_WAF_403.md`](06_Debug/04_Khi_Gap_WAF_403.md); replay qua Burp; đổi 1 biến/lần; kiểm tra UA/body/encoding/HPP |
| DEF đội mình tụt | Có `waf_log_helper.py` và quy trình đọc log | Mở [`06_Debug/05_Doc_WAF_Traffic_Log.md`](06_Debug/05_Doc_WAF_Traffic_Log.md); lọc 30s gần nhất; replay local; chuyển phòng thủ |
| Cờ nhà bị lộ vào pipeline | `FlagStore.save()` và `submit_flags.py` đều chặn `results/own_flags.txt` | Thêm flag vào own list ngay; kiểm tra `results/submitted_flags.json` |
| Mass chạy làm chậm/đối thủ WAF quá tải | Mặc định `workers=4`, `delay=0.5`, `timeout=4`, no-retry 403/429, `max-flags-per-team` | Giảm workers, tăng delay, giảm max-flags-per-team, tắt đội không cần |

## 5. Checklist nhanh

- [ ] `scripts/config.yaml` đã có regex flag, dashboard, timeout hợp lý.
- [ ] `scripts/targets.txt` có `@OUR_TEAM`.
- [ ] `python scripts/manage_targets.py --list` ra đúng thứ tự.
- [ ] `results/own_flags.txt` đã có cờ nhà.
- [ ] `python scripts/submit_flags.py --dry-run --once` pass.
- [ ] Cửa sổ debug dùng proxy Burp; cửa sổ mass không dùng proxy.
- [ ] Round 1-3: `--max-flags-per-team 2`; Round 4+: `3`.
- [ ] Không retry 403/429, không spam request.
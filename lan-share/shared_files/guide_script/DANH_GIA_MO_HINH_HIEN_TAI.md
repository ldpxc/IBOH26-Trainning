# Đánh giá mô hình hiện tại - Sheatchee A/D

> Phạm vi đánh giá: cấu trúc repo và các công cụ trong `scripts/` tại thời điểm 2026-11-28.  
> Mục tiêu: tối ưu cho CTF Attack-Defense offline (10 round, WAF/BunkerWeb, giới hạn nộp cờ, ưu tiên DEF>0).

## 1. Phạm vi và phương pháp

- Đã đọc: `README.md`, `CAU_TRUC_DU_AN.md`, `requirements.txt`, `.gitignore`, `scripts/common.py`, `scripts/http_client.py`, `scripts/run_teams.py`, `scripts/submit_flags.py`, `scripts/manage_targets.py`, `scripts/waf_log_helper.py`, `scripts/exploit_template.py`, `scripts/config.example.yaml`, `scripts/targets.example.txt`.
- Đã kiểm tra:
  - `python -m py_compile scripts/*.py` -> PASS.
  - Smoke `load_targets()` / `run_teams.py --dry-run` / `manage_targets.py --list` / `waf_log_helper.py --status 403 --to-http-client` / `submit_flags.py --dry-run --once` -> PASS bằng shim tối thiểu vì môi trường hiện tại thiếu `requests/bs4/yaml` thật. Trên máy thi cần `pip install -r requirements.txt`.

## 2. Tổng quan kiến trúc

Mô hình hiện tại là **toolkit A/D dạng script Python**, tách rõ debug 1 mục tiêu, mass exploit, submit cờ, quản lý targets và đọc WAF log.

| Thành phần | Vai trò chính | Đánh giá nhanh |
|---|---|---|
| `scripts/common.py` | Config, session, request, login/CSRF, extract flag, `FlagStore`, targets/own-flag helpers | Lõi tốt, tái dùng được |
| `scripts/http_client.py` | Gửi request đơn kiểu Repeater | Phù hợp debug |
| `scripts/exploit_template.py` | Template exploit cho challenge mới | Dễ copy, rõ TODO |
| `scripts/run_teams.py` | Chạy nhiều đội/targets, loop, round, worker, delay, prio | Đúng hướng A/D |
| `scripts/submit_flags.py` | Tail `flags.jsonl`, kiểm tra flag, rate-limit, submit độc lập | Đúng yêu cầu tách tiến trình |
| `scripts/manage_targets.py` | List/set-def0/reset-round/disable/enable/add-own-flag | Tiện vận hành trong giờ thi |
| `scripts/waf_log_helper.py` | Lọc traffic log, sinh lệnh replay qua `http_client.py` | Hữu ích cho DEF/WAF |
| `scripts/config.yaml` / `scripts/targets.txt` | Tách config debug và danh sách mục tiêu runtime | Quyết định thiết kế tốt |

## 3. Điểm mạnh

### 3.1. Tách luồng debug và mass exploit
- `targets.txt` tách khỏi `config.yaml`, giảm rủi ro sửa config debug làm hỏng danh sách quét.
- `run_teams.py` ở A/D mode mặc định bỏ proxy config trừ khi có `--use-proxy` (`run_teams.py:201-214`). Điều này phù hợp mô hình 2 cửa sổ: Burp debug và mass chạy sạch.

### 3.2. Quản lý mục tiêu có ý thức an toàn
- `load_targets()` đọc lại mỗi lần gọi (hot-reload), hỗ trợ `@OUR_TEAM`, comment `#`, IP trần, `prio=1|2` (`common.py:247-347`).
- Lọc cứng `@OUR_TEAM`, `127.0.0.1`, `localhost`, `::1`, target trùng netloc.
- Sắp xếp `prio=1` (DEF>0) trước `prio=2` (DEF=0), giữ thứ tự trong cùng prio.
- `manage_targets.py` cho phép thao tác nhanh trong giờ thi: hạ prio đội DEF=0, reset round, disable/enable.

### 3.3. Có lớp chặn cờ nhà
- `FlagStore.save()` reload own flags và **không lưu** cờ nhà vào `flags.jsonl/csv` (`common.py:659-675`).
- `submit_flags.py` kiểm tra lại own flags trước khi gửi (`submit_flags.py:225-229`).
- Có CLI `--add-own-flag` / `--add-own` để cập nhật nhanh `results/own_flags.txt`.

### 3.4. Kiểm soát tải và rate-limit cơ bản
- A/D defaults: `workers=4`, `delay=0.5`, `max_flags_per_team=2`, timeout hạ về 4s khi chưa override và config timeout >=10 (`run_teams.py:201-211`).
- `request()` không tự retry `403/429` (`common.py:390-394`), tránh làm nặng WAF/đối thủ.
- `submit_flags.py` ép interval tối thiểu `2.15s`, có state `submitted_flags.json`, `429` backoff 10s, `--dry-run/--once` (`submit_flags.py:194-273`).

### 3.5. Khả năng quan sát và tái hiện
- `FlagStore` ghi JSONL/CSV, có dedupe, lock trong process.
- `waf_log_helper.py` bỏ static assets, lọc theo `--since-seconds`, `--status`, `--ignore-path`, trích time/method/path/status/UA/body, sinh lệnh replay qua `http_client.py` với proxy Burp.
- `describe_response()` hỗ trợ debug request/response, có redaction cơ bản cho header nhạy cảm.

### 3.6. Tương thích ngược tương đối tốt
- Giữ `--teams-file`, `--dry-run`, `run_teams()`, chữ ký `example_exploit(team, session, cfg, store)`.
- `add_common_args()`/`config_from_args()` giữ hành vi override CLI cũ.
- `common.py` có guard import `requests/bs4` để các tiện ích parse/list không chết ngay kiểu import khó hiểu.

## 4. Hạn chế và rủi ro

### P0 - Cần xử lý sớm

| Vấn đề | Mô tả | Ảnh hưởng | Đề xuất |
|---|---|---|---|
| `run_teams.py` hardcode `example_exploit` | Main loop gọi `run_teams(..., example_exploit, ...)` (`run_teams.py:261`) | Muốn chạy exploit thật phải sửa runner; dễ lỗi khi đổi bài/round | Thêm `--exploit module:function` hoặc `--exploit-file`; fallback `example_exploit` |
| Cờ nhà bị chặn lưu nhưng vẫn có thể bị đếm round | `FlagStore.save()` trả `False` khi own-flag (`common.py:672-675`), nhưng `run_teams` lấy `flags` từ exploit và cộng vào `flags_per_team_round` (`run_teams.py:92-94,263-285`) | Flag nhà có thể hiện “New flags”, làm đội bị coi là đủ `max-flags-per-team` trong round; không bị lưu/submit nhưng gây nhầm vận hành | Chỉ đếm flag đã được chấp nhận hợp lệ/không phải own-flag; hoặc để exploit nhận kết quả save |

### P1 - Nên cải thiện trước giờ thi

| Vấn đề | Mô tả | Ảnh hưởng | Đề xuất |
|---|---|---|---|
| Không có lock liên tiến trình | `FlagStore` chỉ có `_LOCK` trong process (`common.py:36,671`); `run_teams/submit_flags` không có pid/file lock | Chạy trùng terminal có thể tấn công trùng, ghi trùng, gây tải | Dùng lock file `results/.run_teams.lock`, `results/.submit.lock` |
| Submit chưa phân loại trạng thái terminal từ dashboard | `submit_flags` retry `request_error/rate_limited`, các trạng thái khác lưu theo response nhưng không có chuẩn accepted/duplicate/expired/invalid (`submit_flags.py:254-266`) | Flag hết hạn/đã nộp/invalid từ dashboard có thể bị retry hoặc xử lý chưa tối ưu | Parse response, map thành terminal vs retryable; không retry terminal failures |
| Không có cooldown per-team | Đội lỗi/403/timeout vẫn có thể bị quét lại mỗi cycle | Tốn tài nguyên, tăng dấu vết WAF | Thêm backoff/cooldown theo team; tạm skip N cycle sau lỗi liên tiếp |

### P2 - Cải thiện chất lượng vận hành

| Vấn đề | Mô tả | Ảnh hưởng | Đề xuất |
|---|---|---|---|
| Tên target nhiều token | `load_targets()` chấp nhận name nhiều token (`common.py:302-304`) nhưng `manage_targets.py` ưu tiên name đơn giản/2 token (`manage_targets.py:109-119`) | Khó thao tác CLI với tên có khoảng trắng | Chuẩn hoá name không có khoảng trắng hoặc hỗ trợ quote trong parser/manage CLI |
| Telemetry còn mỏng | Chỉ log text/print | Khó đánh giá hiệu quả vòng quét | Ghi summary mỗi cycle: ok/err, 403/429/timeout, flags mới, thời gian trung bình |
| `tenacity` chưa dùng | Có trong `requirements.txt` nhưng code chưa dùng | Phụ thuộc thừa nhỏ | Dùng cho retry có chính sách rõ ràng, hoặc loại khỏi requirements nếu muốn tối giản |
| Bảo vệ localhost chặn cứng | `load_targets()` lọc localhost/127.0.0.1/::1 | Test local WAF practice cần workaround | Giữ mặc định an toàn; thêm cờ riêng rất rõ ràng như `--allow-local-test` chỉ cho file test, không dùng trong thi |

## 5. Đánh giá theo mục tiêu A/D

| Mục tiêu | Mức độ | Nhận xét |
|---|---:|---|
| Tách targets khỏi config debug | Tốt | Có `targets.txt`, hot-reload, CLI quản lý |
| Tránh tấn công đội nhà / localhost | Tốt | Có lọc target + chặn own-flag 2 lớp |
| Ưu tiên đội còn DEF>0 | Tốt | Có `prio`, sort, set-def0/reset-round |
| Giảm tải/WAF risk | Khá | Có giới hạn cơ bản; thiếu cooldown per-team và lock chạy trùng |
| Nộp cờ an toàn, độc lập | Khá-Tốt | Có rate-limit, state, dry-run; cần phân loại response terminal tốt hơn |
| Dễ đổi exploit khi thi | Trung bình | Template tốt nhưng `run_teams` chưa có cơ chế load exploit động |
| Tương thích ngược debug 1 mục tiêu | Khá | API chính giữ được; cần chú ý default A/D khi có `targets.txt` |

## 6. Kết luận

Mô hình hiện tại **đã đủ khung để vận hành A/D cơ bản**: tách targets/config, có runner mass an toàn hơn mặc định, có submitter độc lập, có quản lý prio/own-flag và helper đọc WAF log. Đây là nền tốt cho thực chiến offline.

Điểm cần hoàn thiện để “chắc tay” hơn trong giờ thi là **khả năng cắm exploit động vào runner**, **khóa chống chạy trùng**, và **xử lý trạng thái flag/đội theo vòng đời thực tế** (own-flag không được đếm round, dashboard terminal responses, cooldown đội lỗi). Sau khi bổ sung các điểm P0/P1, mô hình sẽ chuyển từ “toolkit tốt” sang “pipeline vận hành A/D ổn định”.
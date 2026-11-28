# Tài Liệu Bàn Giao — WAF Flag Leak Monitor & Defense Rule Generator

> 📋 **Đi thi cần tra nhanh?** Đọc [`CHECKLIST_THI_THAT.md`](CHECKLIST_THI_THAT.md) thay vì đọc lại cả file này.

Tài liệu này bàn giao toàn bộ công cụ **WAF Flag Leak Monitor** đặt tại `tools/waf_flag_monitor/`, giúp theo dõi log từ BunkerWeb WAF theo thời gian thực, phát hiện response làm lộ flag, phân tích nguyên nhân và sinh/kiểm định rule ModSecurity v3 / NGINX an toàn trước khi triển khai lên WAF UI.

---

## 1. Cấu trúc thư mục

```text
tools/waf_flag_monitor/
├── app.py              # Flask backend, auth (/login), BunkerWeb client, MonitorEngine & SSE (/api/stream)
├── rule_engine.py      # Bộ phân tích request/response -> sinh rule & kiểm định offline (syntax, ReDoS, FP)
├── templates/
│   └── index.html      # WebUI hoàn toàn offline (không CDN): danh sách alert, inspector Pretty/Raw/Render, Rule modal
├── exploit_engine.py   # Sinh script Python replay request đã bắt được sang các đội khác (khuôn scripts/template.py)
├── waf_monitor.sh      # Script chạy nền/quản lý tiến trình (tương tự lanshare.sh)
├── baseline_ruleset_pass.conf   # Bộ rule nền tảng 51 rule (route-agnostic), add từ đầu giải — xem CHECKLIST_VAN_HANH_BASELINE.md
├── CHECKLIST_THI_THAT.md        # Checklist thao tác nhanh lúc thi (đẩy rule, dùng exploit script)
├── CHECKLIST_VAN_HANH_BASELINE.md  # Hướng dẫn vận hành chi tiết bộ rule nền tảng (Detect -> Prevent)
├── README.md           # Hướng dẫn chạy nhanh
└── HANDOVER.md         # File bàn giao này
```

*(Khi chạy nền qua `waf_monitor.sh`, hệ thống sẽ tạo thêm `.waf_monitor.pid` và `.waf_monitor.log` trong cùng thư mục.)*

---

## 2. Hướng dẫn khởi chạy & vận hành

### 2.1. Các lệnh quản lý (`waf_monitor.sh`)

```bash
cd /home/ld/hoc/CTF/training/AD/iboh26/tools/waf_flag_monitor

# Chạy nền và đặt mật khẩu đăng nhập WebUI
./waf_monitor.sh start --password "MatKhauWebUI"

# Mở ra mạng LAN (0.0.0.0) và trỏ tới WAF UI của đội
./waf_monitor.sh start --host 0.0.0.0 --port 9555 --password "MatKhauWebUI" \
  --waf-url "http://<IP_HOAC_DOMAIN>:<PORT_WAF_UI>" \
  --waf-user "admin" --waf-pass "<MAT_KHAU_WAF_UI>"

# Kiểm tra trạng thái, xem log, restart, dừng
./waf_monitor.sh status
./waf_monitor.sh logs -f
./waf_monitor.sh restart --password "MatKhauWebUI"
./waf_monitor.sh stop
./waf_monitor.sh fg --password "MatKhauWebUI"   # Chạy trực tiếp trên terminal hiện tại
```

### 2.2. Tham số CLI hỗ trợ trong `app.py`

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--host` | `127.0.0.1` | IP bind của WebUI monitor (`0.0.0.0` để chia sẻ trong team) |
| `--port` | `9555` | Cổng WebUI monitor |
| `--password` / `--ui-password` | Tự sinh ngẫu nhiên | Mật khẩu vào WebUI monitor (hoặc qua biến môi trường `WAF_MONITOR_PASSWORD`) |
| `--waf-url` | `http://localhost:9110` | URL giao diện quản trị BunkerWeb WAF UI (hoặc env `WAF_URL`) |
| `--waf-user` / `--user` | `admin` | Tài khoản đăng nhập BunkerWeb UI (hoặc env `WAF_USER`) |
| `--waf-password` / `--waf-pass` | `ChangeMe_Bw_2026!` | Mật khẩu đăng nhập BunkerWeb UI (hoặc env `WAF_PASS`) |
| `--mode` | `range` | Nguồn đọc log: `range` (khuyên dùng), `http`, hoặc `docker` |
| `--container` | `b_notevault-fuap_bunkerweb-1` | Tên container Docker nếu dùng `--mode docker` (hoặc env `WAF_CONTAINER`) |
| `--pattern` | `FHACKER2026\{[0-9a-fA-F]{64}\}` | Regex nhận diện flag trong response (hoặc env `FLAG_PATTERN`) |
| `--interval` | `1.0` | Chu kỳ poll (giây, tối thiểu `0.3`, step `0.1`) cho mode `range`/`http` |
| `--insecure` | `False` | Bỏ qua lỗi kiểm tra SSL khi WAF UI dùng `https://` chứng chỉ tự ký |
| `--no-smart-filter` | `False` | Tắt lọc nhanh (`403`, `429`, `304`, file tĩnh) |

> **Lưu ý quan trọng về Port:** Luôn điền cổng **WAF Admin UI** (ví dụ `9100` hoặc `9110`, nơi có `/login` của BunkerWeb), **không** điền nhầm cổng ứng dụng web (`9000` hoặc `9010`), nếu không sẽ báo `404 Not Found for url: .../login`.

---

## 3. Ba chế độ đọc log (`--mode`) & Lưu ý hiệu năng WAF (2 CPU / 3GB RAM)

1. **`range` — HTTP Range Tail (MẶC ĐỊNH — Khuyên dùng khi chỉ có URL WAF UI):**
   - Dùng endpoint `/logs/download?file=traffic.log` với header `Range: bytes=<offset>-` (`HTTP 206 Partial Content`).
   - Mỗi nhịp poll chỉ gửi **1 request** để tải đúng phần byte mới nối thêm ở cuối file (giới hạn mỗi chunk tối đa `4 MiB`), giữ buffer dòng dở dang ở mức `bytes` để không cắt đôi ký tự UTF-8, tự reset `offset = 0` khi file rotate, và **tự động chuyển sang `http` (`RangeUnsupportedError`)** nếu máy chủ không hỗ trợ `Range` hoặc trả `404`.
   - Không bắt WAF parse lại 50MB JSON trên server nên tốn rất ít CPU trên máy WAF 2 CPU / 3GB RAM.
   - *(Đánh đổi nhỏ: file `traffic.log` thô không gắn sẵn `modsec_ids` như API `/trafficlog/api/history`).*
2. **`http` — HTTP API (`/trafficlog/api/history`):**
   - Poll danh sách `page_size=200` rồi gọi chi tiết từng `request_id` chưa xem bằng tối đa 12 luồng. Có sẵn thông tin rule ModSecurity đã khớp (`modsec_ids`).
   - **Cẩn thận tải:** Mỗi request chi tiết khiến backend BunkerWeb đọc lại đuôi `traffic.log` (~`0.88s`/call trong benchmark thực tế), nên chỉ dùng khi traffic thấp hoặc cần đối chiếu `modsec_ids`, và bật sẵn `smart_filter` + tăng `Poll Interval` lên `2–5s` nếu WAF đang tải cao.
3. **`docker` — Docker Tail:**
   - Chạy `docker exec <container> tail -n 0 -F /var/log/bunkerweb/traffic.log`. Độ trễ `< 10ms`, chỉ dùng được khi chạy tool trên cùng host có quyền Docker.

### Cách phát hiện Flag (`decode_body` + `inspect_record`)
- Nhiều response của app được nén `gzip`/`deflate` nên trong `traffic.log` lưu dạng `base64(gzip_bytes)`. Hàm `decode_body` trong `app.py` tự động decode `base64` và giải nén `gzip`/`deflate` (kể cả stream bị cắt ngắn) trước khi khớp regex flag trên **cả `response_headers` lẫn `response_body`**.

---

## 4. Chức năng WebUI (`templates/index.html`)

- **Xác thực phiên đăng nhập (`/login`, `/logout`):** Chặn toàn bộ trang `/` và `/api/*` nếu chưa nhập mật khẩu WebUI; kiểm tra bằng `secrets.compare_digest`, cookie session `HttpOnly`, `SameSite=Lax`.
- **Cột danh sách Alert bên trái:**
  - Hiển thị thanh thống kê **`Chưa xem: <N>`** và **`Tổng: <M>`**, kèm nút **`✓ Đã xem hết`**.
  - Alert chưa click xem có nền hổ phách, viền trái dày màu vàng (`#ffb020`) và nhãn **`CHƯA XEM`**; sau khi click xem sẽ tự dịu xuống (`opacity: 0.72`). Trạng thái đã xem lưu vào `localStorage`.
  - Ô lọc nhanh theo URI, IP, status hoặc chuỗi flag.
- **Cảnh báo Realtime (SSE `/api/stream`):**
  - Tự bật âm thanh cảnh báo (Web Audio API, bật/tắt bằng nút `🔊 Sound`), hỗ trợ Desktop Notification (`🔔 Desktop`) và tự chọn alert mới nhất (`🎯 Auto-select`).
  - Nút **`🔍 Scan Recent (100)`** cho phép quét lại 100 request gần nhất trong log bất kỳ lúc nào.
- **Trình xem Request / Response kiểu Burp Suite:**
  - **Request:** Tab `Pretty` (tô màu Method, Query params, Header, tự format JSON / Form URL-encoded kèm decode comment / HTML) và `Raw`, kèm nút **`Copy cURL`** & **`Copy Raw`**.
  - **Response:** Tab `Pretty`, `Raw`, và **`Render`** (hiển thị HTML bên trong `<iframe sandbox="">` vô hiệu hóa script để an toàn tuyệt đối), kèm **`Jump to Flag`** để cuộn thẳng tới đoạn flag được highlight.

---

## 5. Bộ sinh & kiểm định Rule phòng thủ (`rule_engine.py`)

Từ bất kỳ alert nào, bấm **`🛡️ Tạo Rule WAF`** để mở trình phân tích & sinh rule (`generate_waf_rules` -> `/api/generate-rules`).

### 5.1. Nguyên tắc an toàn đã thiết kế cứng trong `rule_engine.py`
1. **Không chặn theo IP (`REMOTE_ADDR`):** Trong mô hình có reverse proxy chung, chặn IP sẽ chặn nhầm healthcheck bot. Validator (`validate_rules_text`) sẽ báo lỗi ngay nếu phát hiện `REMOTE_ADDR`.
2. **Mặc định xuất ở chế độ `pass,log`:** Cho phép chọn `pass,log (An toàn — test 30s trước)` hoặc `deny,status:403,log (Chặn ngay)` kèm `logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'` để kiểm tra qua 1 chu kỳ healthcheck trước khi bật chặn.
3. **Rule ID mặc định dải `27200–29999`:** Tránh đụng dải `10000–10099` (rule mẫu), `20001–27107` (các bộ rule sẵn có) và `900000+` (OWASP CRS).
4. **Đúng chuẩn `libmodsecurity3` / BunkerWeb 1.6.16:**
   - So khớp route bằng `@rx (?i)^/route/?$` + `t:none,t:normalizePath` (tránh bypass hoa/thường hoặc dấu `/` cuối).
   - Hỗ trợ đồng thời tham số thường và JSON body qua tiền tố `json.` (`ARGS:param|ARGS:json.param`, nhận diện cả mảng `json.param.array_0`); **tuyệt đối không** dùng `|` trong regex tên biến (`ARGS:/a|b/`).
   - Thứ tự transform chuẩn: luôn bắt đầu `t:none`, dùng 2 lần `t:urlDecodeUni,t:urlDecodeUni` để chống double URL-encode, thêm `t:utf8toUnicode` cho LFI và `t:htmlEntityDecode,t:jsDecode` cho XSS/SSTI; **không** dùng `t:normalizePath` trên `ARGS` cho rule tìm `../`.
   - **Tách Config Type rõ ràng:**
     - `MODSEC`: cho `SecRule ...` thông thường.
     - `SERVER_HTTP`: khi flag lộ qua **Response Header** (ví dụ `X-Theme-Debug`), ưu tiên đề xuất `proxy_hide_header <Header>;` để xóa header mà vẫn giữ app trả `200`/`302` bình thường.
   - **Xử lý 2 bẫy đặc thù của BunkerWeb:**
     - **Upload Webshell:** Soi thẳng `REQUEST_BODY` (dấu hiệu `<?php`, `<script`,...) và collection `FILES` (đuôi `.php/.jsp/.asp`) trên `multipart/form-data`, không gợi ý bật `SecTmpSaveUploadedFiles On`, đồng thời tự bỏ qua `cmdi`/`crlf` trên raw multipart/XML `REQUEST_BODY` để tránh chặn nhầm file upload/XML sạch.
     - **XXE XML:** Tự sinh kèm rule Phase 1 `ctl:requestBodyProcessor=URLENCODED` khi nhận `application/xml` / `text/xml` để vượt qua rule nội bộ `id:200000`.
     - **Base64 / Base64URL (`libmodsecurity3`):** Dùng `t:none,t:base64DecodeExt` (không chạy thêm `t:urlDecodeUni` để không biến `+` thành khoảng trắng) cho Cookie/SAML Base64, và tách phần header `eyJ...` bằng `capture` + `TX:1` trước khi giải mã JWT `jku`/`x5u`/`kid`.
   - **Tùy chọn `Khóa theo Host`:** Chèn thêm điều kiện cha `REQUEST_HEADERS:Host` nếu nhiều service dùng chung 1 instance WAF.
   - **Chống ReDoS:** Toàn bộ regex phát hiện đều dùng quantifier có giới hạn độ dài (`{0,200}`, `{0,300}`, `\z`).

### 5.2. Các nhóm rule & kỹ thuật `generate_waf_rules` hỗ trợ
- **Khuôn 1 (Allowlist `!@rx`):** Tự gợi ý allowlist cho tên tham số quen thuộc: số nguyên (`id`, `page`, `limit`...), `uuid`, `sort/order`, `lang/locale`, `host/ip`, `filename`, đường dẫn nội bộ (`next`, `redirect`...), biểu thức toán (`expr`, `calc`...).
- **Khuôn 2 (`@detectSQLi` / `@detectXSS` C libinjection):** Nhẹ CPU cho ô tìm kiếm/comment tự do.
- **Khuôn 3 (Mass Assignment)** & **Guard HPP / JSON Array** (`&ARGS:<p> "@gt 1"`, `json.<p>.array_N`).
- **Khuôn 5 (Phase 4 Flag DLP):** `REQUEST_FILENAME "!@rx ..."` + `RESPONSE_BODY "@rx <flag_pattern>"` (luôn xuất ở `pass,log` kèm nhắc nhở điền đúng route cờ hợp lệ vì Phase 4 chạy sau khi gửi header sẽ cắt TCP). **Từ bản vá 2026-11-29:** `generate_waf_rules` nhận thêm tham số `legit_flag_routes: list[str]` (ô "Route cờ hợp lệ (Phase 4)" trên UI, lưu localStorage) — **không còn tự đoán** route `^/api/flag(?:/|$)` nữa; nếu để trống, tool chỉ cảnh báo bằng chữ (không sinh rule), vì route đoán sai sẽ tự chặn bot SVC = vi phạm Điều 3.5 + trừ SVC gấp đôi. `validate_rules_text` cũng chặn cứng (error) bất kỳ rule `tag:'flag-leak'` nào ở chế độ `deny` như một lời nhắc bắt buộc xác nhận route trước khi bật chặn thật.
- **Chữ ký tấn công (`ATTACK_PATTERNS` & phân tích sâu):** SQLi (auth/boolean/union/comment `/**/`/time-based/error-based), NoSQLi (`ARGS_NAMES`, JSON lồng ở auth fields, `$where` JS), LFI & `php://filter` chain (`convert.iconv.`) & overlong UTF-8, Command Injection & Argument Injection (`^-`), Code Injection (PHP/Python/Node/Java), SSTI, XSS, SSRF (internal/metadata/obfuscated IP + `gopher://`/`file://`), XXE & SAML Base64 XXE, Deserialization (PHP `O:+4:`, Java, Python Pickle `gASV`, NodeJS `_$$ND_FUNC$$_`, cookie Base64), JWT (`alg:none`, empty signature `header.payload.`, `jku`/`x5u`/`kid`), Prototype Pollution, GraphQL (Introspection, Array Batching, Nesting >= 7 tầng), PHP Type Juggling (`password[]`, JSON non-string, magic hash `0e`), HTTP Smuggling (`CL+TE`, `Transfer-Encoding` obfuscated), CORS `Origin: null`, CRLF, Log4Shell, Hash Length Extension, Recon / Override Headers.
- **Chống rule "byte-to-byte" (Anti-Mutation):** Với mỗi chữ ký, `rule_engine.py` tự động sinh thêm các companion rule chống biến thể:
  - **`sqli_split`**: dùng `t:removeComments` → bắt `UN/**/ION SE/**/LECT`, `/*!50000UNION*/`.
  - **`sqli_cmt`**: dùng `t:replaceComments` → bắt `'/**/OR/**/1=1`, scientific notation `1e0UNION(SELECT...)`.
  - **`cmdi_cmdline`**: dùng `t:cmdLine` → bắt `c'a't`, `c\at`, `c^at`, `${IFS}`, `$'...'`.
  - **`xss_scheme`**: dùng `t:removeWhitespace` → bắt `java&#x09;script:`, tab/newline-broken scheme.
  - **Charset lạ (IBM037, UTF-16, UTF-7):** Rule `unusual_charset` chặn `charset=` khác UTF-8/Latin-1 trên mọi route POST/PUT.
  - **Route generalization:** Path có ID (`/api/notes/123`) → rule khớp `^/api/notes/\d+` nên `124`, `124;jsessionid=1`, `/api/notes/124/extra` đều bị chặn.
  - **SQLi versioned comment:** `_SQLI_KW_RX` nhận thêm `/*!50000UNION*/`, `/*!50000SELECT*/`.
  - **GraphQL Alias Batching:** Pattern `gql_alias_batch` khớp `a1:u(id:1){id} a2:u(id:2){id}...` (>= 5 alias có subselection), không nhầm query thông thường.
- **Kiểm chứng toàn diện 2026-11-29 (3 fork song song, payload thật từ `cheatsheets/web/lecture`, `cheatsheets/web/waf/html-docs-defend/rule-theo-25-lo-hong`, `~/hoc/CTF/Tools/web`):** test mutation/bypass/FP/compliance cho toàn bộ ATTACK_PATTERNS. Đa số PASS (generalize đúng, chịu bypass, không FP). 4 bug thật đã vá:
  - **JWT `alg:none`** từng đoán cứng 4 chuỗi base64 (byte-to-byte, bypass được chỉ bằng đổi thứ tự key/thêm khoảng trắng trong JSON header) → sửa dùng `capture` + `t:base64DecodeExt` rồi regex trên JSON đã giải mã (`\x22alg\x22\s*:\s*\x22none\x22`), giống kỹ thuật rule `jku/x5u/kid` ngay cạnh.
  - **Allowlist `safe_filename`** tự mâu thuẫn với chính `BENIGN_SAMPLES` (`report.v2.pdf` bị từ chối vì không cho dấu `.` trong tên) → nới regex cho nhiều dấu chấm, vẫn chặn `..`.
  - **`hash_len_ext`** chết hoàn toàn khi payload nằm trong query/form param vì `urllib.parse.parse_qs` tự URL-decode trước khi so khớp (byte `%80` đứng lẻ không phải UTF-8 hợp lệ nên bị thay bằng U+FFFD) → thêm nhánh so khớp trên chuỗi query/body THÔ (chưa decode) riêng cho pattern này.
  - Khuôn 5 Phase 4 Flag DLP: xem ghi chú ở trên (bỏ auto-đoán route, bắt buộc `legit_flag_routes`).

### 5.3. Bộ kiểm định Offline tích hợp (`🧪 Kiểm tra Rule` -> `/api/validate-rules`)
Ngay trên giao diện (trong cả modal sinh rule lẫn giỏ `📦 Rules`), nhân sự mới có thể bấm kiểm tra trước khi copy lên WAF UI:
- Kiểm tra lỗi cú pháp `libmodsecurity3` (khoảng trắng sau `\`, comment trong `chain`, `id:/phase:/deny` đặt nhầm ở dòng con `chain`, trùng Rule ID, `ARGS` ở Phase 1, `t:normalizePath` chung với `..`).
- Đo thời gian chạy regex trên 12 chuỗi stress ReDoS (`REDOS_TEST_INPUTS`).
- Kiểm tra False Positive trên 24 mẫu sạch (`BENIGN_SAMPLES`, gồm cả tên có dấu nháy `"O'Brien"`, `"Select Comfort Mattress"`, `"laptop gaming"`, tiếng Việt).
- Xác nhận rule vừa chỉnh sửa có khớp đúng payload của alert đang xem hay không (`attack_matched`).

### 5.4. Bộ rule nền tảng (`generate_baseline_ruleset()`) — thêm 2026-11-29

Khác với `generate_waf_rules` (phân tích 1 alert/route cụ thể đã biết), hàm
`generate_baseline_ruleset(action_mode, base_rule_id)` sinh **51 rule
route-agnostic** (không khoá theo `REQUEST_FILENAME`/route cụ thể) tái dùng
nguyên vẹn mọi `ATTACK_PATTERNS` + companion anti-mutation đã kiểm chứng, để
**add vào WAF ngay từ đầu giải lúc còn `DetectionOnly`**, trước khi biết rõ
app thật của BTC. File sẵn dùng: [`baseline_ruleset_pass.conf`](baseline_ruleset_pass.conf).
Hướng dẫn vận hành chi tiết (quan sát, xử lý FP, khi nào bật Prevent): xem
[`CHECKLIST_VAN_HANH_BASELINE.md`](CHECKLIST_VAN_HANH_BASELINE.md).

**KHÔNG gồm** (cần biết app thật, chỉ thêm sau bằng `generate_waf_rules`):
Allowlist Khuôn 1, Guard HPP/JSON Array theo tên tham số, Phase 3/4 Flag DLP
(bắt buộc `legit_flag_routes`, không đoán route), GraphQL Array Batching.

**4 bug thật tìm được khi test live trên 3 service (notevault/pulseapi/socialhub),
đã vá trong `ATTACK_PATTERNS`/helper — ảnh hưởng cả `generate_waf_rules` cũ, không riêng baseline:**
1. `_escape_modsec_msg()` không escape `%` — bất kỳ rule nào có msg/name chứa
   `%` trần (vd pattern `hash_len_ext` có "(%80%00...)" trong tên) khiến
   ModSecurity hiểu nhầm là mở biến `%{...}`, **vỡ cú pháp TOÀN BỘ file config,
   không rule nào nạp được, không báo lỗi rõ ràng trên UI**. Đã sửa: thay `%`
   không theo sau `{` bằng `pct`.
2. `_CMDI_PRIMARY_RX` từng bare-match `;`/`|`/CRLF không cần ngữ cảnh — bất kỳ
   văn bản thường nào có dấu chấm phẩy hoặc xuống dòng (textarea bình thường!)
   bị chặn nhầm là Command Injection. Đã sửa: bắt buộc đi kèm tên lệnh thật
   ngay sau (`id`, `whoami`, `cat`...).
3. Pattern `lfi` từng bare-match 1 lần `../` dạng ASCII thuần — ghi chú nhắc
   đường dẫn tương đối trong văn bản (`xem thêm ../docs/x.md`) bị chặn nhầm.
   Đã sửa: dạng ASCII thuần phải lặp **>= 2 lần** mới khớp (biến thể
   encode/obfuscate vẫn khớp từ 1 lần vì hiếm gặp trong văn bản thường).
4. Pattern `deser` từng bare-match `H4sI` (magic bytes gzip đã base64-hoá) —
   bất kỳ dữ liệu nén base64 hợp lệ nào (export/share/cache) bị chặn nhầm là
   Deserialization. Đã bỏ hẳn `H4sI` khỏi pattern (không giải nén thật được ở
   tầng regex nên không thể phân biệt độc hại hay không).

**Phát hiện vận hành quan trọng (không phải bug code) khi test trên BunkerWeb thật:**
- **Phải dùng `--force-recreate`** khi reload WAF sau khi đổi Custom Config,
  **không được chỉ `stop` + `up -d`** — container cũ bị tái sử dụng nguyên
  filesystem local (còn chứa config cũ), khiến scheduler tự "phát hiện" file
  lạ trên đĩa và đăng ký ngược lại vào DB (`method='manual'`), gây trùng Rule
  ID ở lần sửa tiếp theo, làm nginx reload thất bại âm thầm.
- Luôn tự `grep -oa 'id:XXXXX' /etc/bunkerweb/configs/modsec/*.conf` xác nhận
  đúng rule đã nạp sau MỌI thay đổi — đừng chỉ tin trạng thái container
  "healthy" hay UI báo "đã lưu".
- Rủi ro FP đã biết, không tự động hoá được (cần biết app thật mới loại trừ
  đúng): OAuth/webhook có `redirect_uri` trỏ về chính IP nội bộ của app sẽ bị
  cả rule SSRF lẫn Open Redirect baseline chặn nhầm cùng lúc — xem ví dụ chi
  tiết trong `CHECKLIST_VAN_HANH_BASELINE.md` mục 3.3.

---

## 6. Lưu ý thực tế & Xử lý sự cố nhanh

1. **Ô Password trong Settings bị tự điền dấu chấm (`••••••••`):**
   - Đã gắn `autocomplete="new-password"`, nhưng nếu trình duyệt vẫn tự điền mật khẩu WebUI monitor vào ô Password của BunkerWeb rồi báo `401 Unauthorized`, hãy xóa trắng ô Password (nếu không đổi) hoặc nhập lại đúng mật khẩu BunkerWeb UI rồi lưu.
2. **Mở Settings không lưu được ô `Poll Interval`:**
   - Đã đặt `step="0.1"` (`min="0.3"`), nhập bình thường `0.5`, `1`, `2`, `3`...
3. **Không thấy alert mới dù vừa có request ra flag:**
   - Kiểm tra xem `WAF URL` trong Settings đang trỏ đúng instance (`9100` hay `9110`) và trạng thái trên header đang là `RUNNING` (chữ xanh) hay `ERROR`.
   - Lưu ý công cụ mặc định chỉ theo dõi **traffic mới từ thời điểm khởi động/áp dụng cấu hình** (giống `tail -n 0`). Muốn quét ngược lịch sử gần nhất thì bấm **`🔍 Scan Recent (100)`**.
4. **Kiểm tra chéo file `.conf` bằng script độc lập trước khi đưa lên WAF (nếu có lab):**
   - Trong repo có sẵn [`tools/test_rules_waf/waf_rule_tester.py`](../test_rules_waf/waf_rule_tester.py) hỗ trợ chạy offline/live/load test cho file `.conf` đã xuất từ giỏ **`📦 Rules` (`defense_rules.conf`)**.
5. **(Quan trọng — phát hiện từ test thật 2026-11-29) Thêm Custom Config trên UI BunkerWeb: PHẢI chọn Service = Global, KHÔNG chọn đúng tên service cụ thể:**
   - Đã kiểm chứng trực tiếp trên `services-practice/notevault` (ảnh `custom_waf26`): khi lưu 1 config `type:modsec` với `service_id` là tên service (vd `localhost`), BunkerWeb lưu file vào thư mục con `/etc/bunkerweb/configs/modsec/<service>/*.conf`, nhưng dòng `include` trong `modsecurity-rules.conf.modsec` của instance 1-service lại chỉ là `include /etc/bunkerweb/configs/modsec/*.conf` (glob phẳng, **không** quét vào thư mục con) — rule **lặng lẽ không bao giờ được nạp**, không có lỗi gì báo ra cả UI lẫn log để biết. Phải lưu ở scope **Global** (không chọn service cụ thể) thì rule mới thực sự chạy. Đã verify bằng `modsec_ids` thật trong trafficlog (rule ID xuất hiện sau khi chuyển Global, biến mất khi để scope theo service).
   - Rủi ro thực tế: đội tưởng đã bật rule (UI không báo lỗi, rule vẫn hiện trong danh sách Configs) nhưng thực chất chưa chặn gì cả — chỉ phát hiện khi tự tay gửi lại payload kiểm tra. **Luôn tự gửi lại đúng payload đã dùng để sinh rule sau khi lưu, xác nhận có bị chặn/log thật trước khi yên tâm.**
   - Lưu ý thêm: rule `deny` trên từng SecRule KHÔNG có tác dụng chặn nếu `SecRuleEngine` toàn WAF vẫn đang `DetectionOnly` (mặc định lúc mới `spin.sh up`/lúc thi thật theo Điều 3.4) — phải tự vào UI bật chế độ chặn tổng thể (hoặc đổi `MODSECURITY_SEC_RULE_ENGINE` thành `On`) thì rule mới thực sự chặn, dù rule đã nạp đúng và khớp payload (thấy trong `modsec_ids`).
6. **Giới hạn của `exploit_engine.py` với lỗ hổng nhiều bước (multi-step):** script sinh ra chỉ replay ĐÚNG 1 request đã bắt được. Nếu lỗ hổng cần 2 bước trở lên (vd: bước 1 lưu payload qua POST, bước 2 mới GET lại trang để payload thực sự chạy/trả kết quả — kiểu SSTI lưu bio rồi mới xem profile), phải tự thêm 1-2 dòng gọi request tiếp theo vào cuối `solve_one()` sau dòng replay chính (đã verify thực tế: thêm đúng 1 dòng `session.get(...)` là đủ). Ghi chú tự động trong script không tự phát hiện được trường hợp này.

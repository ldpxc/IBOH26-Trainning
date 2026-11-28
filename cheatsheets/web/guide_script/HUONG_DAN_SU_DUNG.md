# Hướng dẫn sử dụng code Sheatchee

Tài liệu này hướng dẫn cách dùng bộ script trong `scripts/` để chuyển thao tác Burp Suite thành code Python chạy được, dễ debug, và dễ nhân rộng ra nhiều đội.

> **Phạm vi an toàn:** chỉ dùng trên hệ thống/lab/CTF mà bạn được phép kiểm thử.

## 1. Tổng quan nhanh

| File | Vai trò | Khi nào dùng |
|---|---|---|
| `scripts/common.py` | Thư viện dùng chung | Không chạy trực tiếp; các script khác import |
| `scripts/http_client.py` | CLI gửi 1 request giống Repeater | Test nhanh request, so với Burp, debug |
| `scripts/exploit_template.py` | Template viết exploit/request | Copy ra file mới cho từng bài/challenge |
| `scripts/run_teams.py` | Chạy exploit trên nhiều đội | Khi exploit chạy được 1 đội, cần nhân rộng |
| `scripts/config.example.yaml` | Mẫu cấu hình | Copy thành `config.yaml` rồi sửa |
| `scripts/README.md` | Tóm tắt nhanh scripts | Tra cứu lệnh thường dùng |

## 2. Cài đặt

### 2.1. Yêu cầu

- Python 3.10+ (khuyến nghị 3.11+)
- `pip`
- Burp Suite (tuỳ chọn, để debug/proxy)

Kiểm tra:

```bash
python --version
pip --version
```

### 2.2. Tạo môi trường ảo và cài dependencies

Tại thư mục gốc repo (`E:\Sheatchee`):

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Windows CMD**

```bat
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Linux/macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2.3. Gói được cài

`requirements.txt` cài các gói cốt lõi:

- `requests` - gửi HTTP.
- `beautifulsoup4`, `lxml` - parse HTML/trích CSRF/token.
- `PyYAML` - đọc config/teams YAML.
- `tenacity` - có sẵn nếu bạn muốn retry nâng cao (script hiện có retry nhẹ tích hợp).

Gói tuỳ chọn (bỏ comment trong `requirements.txt` khi cần):

- `aiohttp` - async concurrency.
- `playwright` - mô phỏng trình duyệt cho XSS/CSRF.

## 3. Cấu hình

### 3.1. Tạo file config

```powershell
Copy-Item scripts\config.example.yaml scripts\config.yaml
```

```bash
cp scripts/config.example.yaml scripts/config.yaml
```

`scripts/config.yaml` đã được thêm vào `.gitignore` vì có thể chứa credential.

### 3.2. Tạo file targets cho A/D (khuyến nghị)

```powershell
Copy-Item scripts\targets.example.txt scripts\targets.txt
```

```bash
cp scripts/targets.example.txt scripts/targets.txt
```

`scripts/targets.txt` là file text phẳng, tách khỏi `config.yaml` để debug 1 mục tiêu và quét hàng loạt không ảnh hưởng nhau. File này cũng đã được `.gitignore`.

Định dạng:

```text
@OUR_TEAM http://10.0.1.1:8000      # khóa cứng đội nhà (bắt buộc kiểm tra)
team_02 http://10.0.2.1:8000        # kiểu đầy đủ: name + url
10.0.3.1:8000                       # kiểu IP trần: tự thêm http://, tên tự sinh
# team_04 http://10.0.4.1:8000      # comment để tắt nhanh
```

### 3.3. Các trường quan trọng

```yaml
base_url: "http://target"          # Host lab/CTF debug 1 mục tiêu
proxy: "http://127.0.0.1:8080"     # Burp proxy; A/D mass mode mặc định bỏ qua
verify_tls: false                   # false khi dùng Burp self-signed cert trong lab
timeout: 10                         # Timeout mặc định (giây)
allow_redirects: true               # false nếu muốn quan sát 302 như Repeater

headers:
  User-Agent: "Mozilla/5.0 (compatible; Sheatchee/1.0)"

auth:
  type: "form"                      # form | json | bearer | none
  login_path: "/login"
  username_field: "username"
  password_field: "password"
  username: "admin"
  password: "admin"

flag_patterns:
  - 'FHACKER2026\{[0-9a-fA-F]{64}\}'
  - 'FLAG\{[^}]+\}'

dashboard:
  submit_url: "http://dashboard.ctf/submit"
  interval_sec: 2.15
  payload_format: "json"            # json | form
  flag_field: "flag"
  headers: {}
  verify_tls: true

teams: []                            # Legacy; A/D ưu tiên scripts/targets.txt

output:
  dir: "results"
  jsonl: "flags.jsonl"
  csv: "flags.csv"
  dedupe: true
```

### 3.4. Nguyên tắc config

- **Không hard-code secret** trong script. Để trong `config.yaml`.
- **Mỗi môi trường một config**: tạo `config.lab.yaml`, `config.local.yaml`, rồi truyền `--config ...`
- **Proxy chỉ bật khi debug**. A/D mass mode mặc định bỏ qua proxy config; dùng `--use-proxy` khi thật sự cần.
- **Tách targets**: debug 1 mục tiêu dùng `config.yaml`/`--base-url`; quét nhiều đội dùng `scripts/targets.txt`.

## 4. Dùng `http_client.py` như Burp Repeater

Script: `scripts/http_client.py`

### 4.1. Cú pháp

```bash
python scripts/http_client.py [OPTIONS_CHUNG] METHOD PATH [OPTIONS_REQUEST]
```

- `METHOD`: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, ...
- `PATH`: `/path` hoặc URL đầy đủ.

### 4.2. Options chung

| Option | Ý nghĩa |
|---|---|
| `--config PATH` | File config YAML |
| `--base-url URL` | Ghi đè `base_url` |
| `--proxy URL` | Ghi đè proxy, ví dụ `http://127.0.0.1:8080`; dùng `--proxy ''` để tắt |
| `--timeout N` | Timeout giây |
| `--insecure` | Tắt verify TLS (lab/Burp cert) |
| `--no-redirect` | Không follow redirect |
| `-v, --verbose` | Log DEBUG |
| `--log-file PATH` | Ghi log ra file |

### 4.3. Options request

| Option | Tương đương Burp | Ví dụ |
|---|---|---|
| `-q K=V` | Query param | `-q q=test -q page=1` |
| `-d K=V` | Form body | `-d username=admin -d password=admin` |
| `--json '{...}'` | JSON body | `--json '{"id":1}'` |
| `--json @file.json` | JSON từ file | `--json @body.json` |
| `--raw '...'` | Raw body | `--raw '<xml/>'` |
| `--raw @file.bin` | Raw body từ file | `--raw @body.bin` |
| `-H 'K: V'` | Header | `-H 'Authorization: Bearer ...'` |
| `--out FILE` | Lưu response body | `--out logs/resp.html` |
| `--show-flags` | Trích flag theo regex config | `--show-flags` |

### 4.4. Ví dụ thực tế

**GET + query trùng tên**

```bash
python scripts/http_client.py GET /search -q role=user -q role=admin --base-url http://127.0.0.1:8000
```

**POST form login**

```bash
python scripts/http_client.py POST /login -d username=admin -d password=admin
```

**POST JSON**

```bash
python scripts/http_client.py POST /api/login --json '{"username":"admin","password":"admin"}' -H "Accept: application/json"
```

**Gửi qua Burp để so sánh**

```bash
python scripts/http_client.py GET /profile --proxy http://127.0.0.1:8080 --insecure -v
```

**Không follow redirect (giống Repeater nhìn 302)**

```bash
python scripts/http_client.py GET /old --no-redirect
```

**Lưu response để xem**

```bash
python scripts/http_client.py GET /download --out logs/download.bin
```

## 5. Viết exploit/script mới từ template

### 5.1. Copy template

```powershell
Copy-Item scripts\exploit_template.py scripts\my_challenge.py
```

```bash
cp scripts/exploit_template.py scripts/my_challenge.py
```

### 5.2. Quy trình chuẩn

1. **Làm tay trong Burp** đến khi có request/chuỗi request thắng.
2. **Xác định dữ liệu cần giữ**: URL, method, header, cookie, token, body, encoding.
3. **Copy template** thành file mới.
4. **Sửa TODO** trong `exploit()`:
   - Login/session.
   - Request chính.
   - Parse response.
   - Trích flag/kết quả.
   - Lưu evidence.
5. **Chạy qua Burp proxy** để so request.
6. **Tắt proxy**, chạy sạch, lưu kết quả.

### 5.3. Cấu trúc tối thiểu của một exploit tốt

```python
from scripts.common import (
    FlagStore, add_common_args, build_session, config_from_args,
    extract_flags_from_response, login, merge_url, request, save_text, setup_logging,
)

# ... parse args, setup_logging, config_from_args, build_session ...

def exploit(session, cfg, args):
    base = cfg.base_url
    login(session, cfg, base_url=base)  # nếu cần

    resp = request(
        session,
        "GET",
        merge_url(base, "/vuln"),
        params={"id": "1"},
        timeout=cfg.timeout,
        allow_redirects=cfg.allow_redirects,
    )

    flags = extract_flags_from_response(resp, cfg.flag_patterns)
    save_text("logs/vuln_response.html", resp.text)

    store = FlagStore(cfg.output_dir, cfg.jsonl_name, cfg.csv_name, dedupe=cfg.dedupe)
    for flag in flags:
        store.save(team=args.team, flag=flag, challenge=args.challenge, url=resp.url, source="my_challenge.py")

    return flags
```

### 5.4. Những thứ nên có trong script

- `timeout` cho mọi request.
- `Session` khi có login/cookie/token.
- Log rõ ràng (`-v`).
- Lưu response/evidence khi exploit thành công hoặc thất bại.
- Không `raise_for_status()` quá sớm nếu response lỗi vẫn chứa flag/data.
- Regex flag cấu hình được, không hard-code cứng nếu contest có thể đổi.

## 6. Dùng `common.py` đúng cách

### 6.1. Load config + session

```python
from scripts.common import load_config, build_session, setup_logging

setup_logging(verbose=True)
cfg = load_config("scripts/config.yaml")
session = build_session(cfg)
```

Hoặc dùng CLI args:

```python
import argparse
from scripts.common import add_common_args, config_from_args, build_session, setup_logging

parser = argparse.ArgumentParser()
add_common_args(parser)
args = parser.parse_args()
setup_logging(args.verbose, args.log_file)
cfg = config_from_args(args)
session = build_session(cfg)
```

### 6.2. Gửi request

```python
from scripts.common import request, merge_url

resp = request(
    session,
    "POST",
    merge_url(cfg.base_url, "/api/login"),
    json={"username": "admin", "password": "admin"},
    timeout=cfg.timeout,
    allow_redirects=cfg.allow_redirects,
)
```

Tham số hữu ích:

- `expected_status=[200, 302]` - fail sớm khi status lạ.
- `retries=2, retry_backoff=0.5` - retry lỗi mạng/429/5xx.
- `raise_for_status=True` - chỉ bật khi chắc response lỗi không chứa dữ liệu cần.

### 6.3. Debug response

```python
from scripts.common import describe_response

print(describe_response(resp))
```

`describe_response` redact các header nhạy cảm (`Authorization`, `Cookie`, ...).

### 6.4. CSRF token

```python
from scripts.common import extract_csrf_token

token = extract_csrf_token(resp.text, name="csrf")
```

### 6.5. Login

```python
from scripts.common import login

login(session, cfg)  # theo auth trong config
```

Override khi cần:

```python
login(session, cfg, auth_override={"username": "u", "password": "p"})
```

### 6.6. Trích flag

```python
from scripts.common import extract_flags_from_response

flags = extract_flags_from_response(resp, cfg.flag_patterns)
```

### 6.7. Lưu flag

```python
from scripts.common import FlagStore

store = FlagStore(cfg.output_dir, cfg.jsonl_name, cfg.csv_name, dedupe=cfg.dedupe)
store.save(team="team1", flag="FLAG{...}", challenge="sqli", url=resp.url, source="my.py")
```

Kết quả:

- `results/flags.jsonl` - mỗi dòng 1 JSON, dễ xử lý bằng script.
- `results/flags.csv` - mở nhanh bằng Excel/Sheets.

## 7. Chạy nhiều đội / A/D

### 7.1. Legacy (config/teams-file, tương thích ngược)

```yaml
teams:
  - name: team1
    base_url: http://10.10.1.10
    auth: {username: admin, password: p1}
```

```bash
python scripts/run_teams.py --dry-run
python scripts/run_teams.py --workers 5 --teams-file teams.yaml
```

### 7.2. A/D dùng `targets.txt` (khuyến nghị)

```text
@OUR_TEAM http://10.0.1.1:8000
team_02 http://10.0.2.1:8000
10.0.3.1:8000
```

```bash
python scripts/run_teams.py --targets scripts/targets.txt --dry-run
python scripts/run_teams.py --targets scripts/targets.txt --workers 4 --delay 0.5
python scripts/run_teams.py --targets scripts/targets.txt --loop --interval 60 --max-flags-per-team 2 --round-id R1
```

Mặc định an toàn A/D:

- `workers=4`, `delay=0.5`, timeout hạ xuống `4s` nếu chưa override và config đang >=10.
- Bỏ qua proxy config trừ khi có `--use-proxy`.
- `request()` không tự retry `403/429`.
- `load_targets()` hot-reload mỗi vòng, tự lọc `@OUR_TEAM`, `localhost`, `127.0.0.1`, trùng lặp.

### 7.3. Viết exploit cho 1 đội

Trong `scripts/run_teams.py`, sửa `example_exploit`:

```python
def example_exploit(team, session, cfg, store):
    base = team.get("base_url") or team.get("web") or cfg.base_url
    resp = request(session, "GET", merge_url(base, "/vuln?id=1"), timeout=cfg.timeout)
    flags = extract_flags_from_response(resp, cfg.flag_patterns)
    for flag in flags:
        store.save(team=team["name"], flag=flag, challenge="sqli", url=resp.url, source="run_teams")
    return flags
```

### 7.4. Quy tắc quan trọng

- **Mỗi đội một `Session`**. Không dùng chung cookie/token.
- **Lỗi 1 đội không được làm chết cả batch**.
- **Không tấn công/nộp cờ đội nhà**: khai báo `@OUR_TEAM` và giữ `results/own_flags.txt`.
- **Giới hạn tải**: giữ `workers/delay/timeout` an toàn; không retry 403/429.
- **Dùng lock/dedupe khi lưu**. `FlagStore` chặn cờ nhà và chống trùng.

## 8. Debug khi script khác Burp

Khi Python chạy khác Burp, kiểm tra theo thứ tự:

1. **Method/URL/path/query** - `resp.request.method`, `resp.request.url`.
2. **Headers** - đặc biệt `Content-Type`, `User-Agent`, `Origin`, `Referer`, `Authorization`.
3. **Cookie/session** - có dùng chung `Session` không?
4. **Body** - `data=` vs `json=` vs raw bytes.
5. **Encoding** - payload đã encode sẵn có bị encode lần 2 không?
6. **Redirect** - Burp thấy 302, Python có follow không?
7. **TLS/proxy** - cert self-signed, proxy sai port.

### 8.1. Đưa request Python qua Burp

```bash
python scripts/http_client.py GET /path --proxy http://127.0.0.1:8080 --insecure -v
```

Hoặc trong config:

```yaml
proxy: "http://127.0.0.1:8080"
verify_tls: false
```

### 8.2. Bật log DEBUG

```bash
python scripts/my_challenge.py -v --log-file logs/my_challenge.log
```

### 8.3. Lưu response để soi

```python
from scripts.common import save_text
save_text("logs/resp.html", resp.text)
```

## 9. Lỗi thường gặp

| Triệu chứng | Nguyên nhân hay gặp | Cách xử lý |
|---|---|---|
| `ModuleNotFoundError: requests` | Chưa cài deps/venv | Kích hoạt venv, `pip install -r requirements.txt` |
| 403 nhưng Burp 200 | Thiếu header/cookie/CSRF/Origin | So Raw request trong Burp, thêm header/cookie |
| 415/400 | Sai `Content-Type` hoặc body format | Dùng `json=` cho JSON, `data=` cho form, `--raw` cho raw |
| Login xong vẫn bị redirect về login | Session không giữ, cookie `Secure`, login sai | Dùng `requests.Session()`, kiểm tra `cookies`, `verify_tls` |
| `%2527` xuất hiện | Encode 2 lần | Payload đã encode thì đưa thẳng vào URL/raw, không qua `params=` |
| `JSONDecodeError` | Response không phải JSON | In `resp.text[:300]`, kiểm tra status/Content-Type |
| Request qua Burp treo | Intercept đang bật | Forward hoặc tắt Intercept |
| SSL cert lỗi khi qua Burp | Burp self-signed cert | `--insecure` hoặc `verify_tls: false` trong lab |
| Race test không ổn định | Proxy serialize, dùng chung session, timing | Tắt proxy, dùng Barrier/thread, mỗi thread session riêng |

## 10. Mẫu quy trình làm 1 bài

1. Bắt request trong Burp.
2. Repeater chạy tay thành công.
3. Ghi lại: endpoint, method, params, body, header, cookie, token, dấu hiệu thành công.
4. Dùng `http_client.py` để tái hiện 1 request.
5. Copy `exploit_template.py` thành `scripts/<bai>.py`.
6. Viết hàm `exploit()`.
7. Chạy với `-v --proxy http://127.0.0.1:8080 --insecure`.
8. So với Burp, sửa khác biệt.
9. Bỏ proxy, chạy sạch.
10. Nếu cần nhiều đội: chuyển logic vào `run_teams.py` hoặc gọi từ đó.

## 11. Submit cờ độc lập

`run_teams.py` chỉ khai thác và lưu flag vào `results/flags.jsonl`. Nộp cờ chạy terminal riêng bằng `scripts/submit_flags.py`.

```bash
# Thêm cờ nhà vào danh sách chặn
python scripts/submit_flags.py --add-own FHACKER2026{...64hex...}

# Dry-run kiểm tra luồng, không gửi thật
python scripts/submit_flags.py --config scripts/config.yaml --dry-run --once

# Chạy thật
python scripts/submit_flags.py --config scripts/config.yaml
```

Luật an toàn:

- Regex mặc định: `^FHACKER2026\{[0-9a-fA-F]{64}\}$`.
- Không submit flag nằm trong `results/own_flags.txt`.
- Khoảng cách tối thiểu `2.15s` giữa 2 lần gửi.
- Trạng thái lưu tại `results/submitted_flags.json` để restart không nộp trùng.
- HTTP `429` -> backoff 10s, thử lại vòng sau.

## 12. Cấu trúc kết quả

Mặc định lưu vào `results/`:

- `flags.jsonl` - append-only, mỗi flag 1 dòng JSON.
- `flags.csv` - dễ mở nhanh.
- `own_flags.txt` - danh sách cờ nhà cần chặn tuyệt đối.
- `submitted_flags.json` - trạng thái submit của `submit_flags.py`.

Ví dụ dòng JSONL:

```json
{"time":"2026-11-27T10:00:00+0700","team":"team1","challenge":"sqli","flag":"FHACKER2026{...}","url":"http://team1.target/result","source":"my_challenge.py"}
```

Nên giữ `results/`, `logs/`, `scripts/config.yaml`, `scripts/targets.txt` ngoài git (đã có trong `.gitignore`).

## 13. Checklist trước khi chạy hàng loạt

- [ ] Đã chạy thành công 1 đội/mục tiêu.
- [ ] Có `timeout` cho mọi request.
- [ ] Có log và evidence.
- [ ] Mỗi đội có session/config riêng.
- [ ] Có chống trùng flag và chặn cờ nhà (`results/own_flags.txt`).
- [ ] Có `@OUR_TEAM` trong `scripts/targets.txt`.
- [ ] Có xử lý lỗi theo đội; không retry 403/429.
- [ ] Đã tắt proxy nếu không cần debug (`--use-proxy` chỉ khi cần).
- [ ] Submit chạy ở terminal riêng với `submit_flags.py` và dry-run trước.
- [ ] Chỉ chạy trên mục tiêu được phép.

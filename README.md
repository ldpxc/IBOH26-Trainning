# Lộ trình luyện tập IBOH 2026 Attack-Defense

15 ngày (28/10 → 10/11), thi ~11/11 · trung bình 7h/ngày · 6 phiên mô phỏng.

## Cấu trúc kho & cách dùng

File này (`README.md`) là lộ trình. Mỗi thứ học/làm được lưu vào đúng thư mục để lật ra dùng ngay và cả đội xem chung:

| Thư mục | Lưu gì |
| --- | --- |
| [`cheatsheets/`](cheatsheets/) | cheatsheet theo mảng: docker, infra, pwn, web, crypto, rev, ad, patching |
| [`exploits/<lane>/`](exploits/) | exploit đã chạy được (chuẩn farm) |
| [`templates/`](templates/) | khung exploit (pwn/web/crypto) + mẫu writeup |
| [`writeups/<lane>/`](writeups/) | ghi lại sau khi giải xong / bỏ dở chall |
| [`infra/`](infra/) | lab hạ tầng HT1–HT7 (Tuần 1) |
| [`services/`](services/) · [`checkers/`](checkers/) · [`forcad/`](forcad/) | dựng sân chơi AD (Tuần 2) |
| [`farm/`](farm/) · [`ops/`](ops/) · [`patches/`](patches/) | farm/replay, mạng & nộp flag, bản vá |
| [`progress/`](progress/) | báo cáo cuối ngày + Gate 1/2 |
| [`docs/`](docs/) | briefing chính thức, handoff, bản HTML của lộ trình |

**Cách dùng (ngắn):** học/giải xong → ghi cheatsheet (`cheatsheets/`) + lưu exploit (`exploits/`) + viết writeup nếu chall khó (`writeups/`) → cuối ngày cập nhật `progress/progress.md`. Mỗi thư mục có `README.md` nói rõ bỏ gì vào. **Không commit** flag/token/credential thật (đã chặn trong `.gitignore`).

## Luật thi (tóm tắt, từ briefing chính thức)

- Thi **6 giờ**, **tick = 5 phút**, flag đổi mỗi tick, **sống 5 tick** (~25 phút). 5 đội, IP `10.10.<team>.10`, VPN = **OpenVPN** (mang mobile data phòng venue chặn).
- **White box** (có source, `/home/player/challengeN/`): vá được trước khi bị pwn. **Black box** (không source, `/home/challengeN/`): **phải pwn trước mới vá được**.
- Chỉ vá được **code/binary** (`app.py`…); **`Dockerfile`/`docker-compose.yml` KHÔNG vá được**. `restart_docker.sh` **cooldown 10 phút**. Flag ở `/home/user/flag.txt`.
- Nộp flag: `nc gameserver 6666` (chỉ tính từ máy đội mình). Điểm: **SLA** (động) + **Attack +2**/flag + **Defence −1**/lần bị nộp.

**Trục chiến lược:** exploit là nền cho cả công lẫn thủ (black box bắt buộc pwn mới vá; Attack +2 > Defence −1). Dồn luyện vào khai thác sâu; trong trận vẫn giữ SLA sống. Biết exploit thì chỗ vá hiển nhiên — cái khó là **thao tác vá không làm chết dịch vụ**.

---

# PHẦN I — KỸ NĂNG CẦN LUYỆN

## 1. Hạ tầng & vận hành — BẢNG NHIỆM VỤ (bắt buộc, cả đội, không chia tier)

> Giống tier khai thác ("giải được = xong"), mỗi nhiệm vụ dưới có **việc cụ thể + tiêu chí đạt đo được + sản phẩm để lại**. Làm **thật** trên máy, không chỉ đọc. "Xong" = đạt cột giữa **và** có sản phẩm cột phải. Các ngày Tuần 1 tham chiếu theo mã **HT1–HT7**.

| Mã | Việc cụ thể | Đạt khi (đo được) | Sản phẩm để lại |
| --- | --- | --- | --- |
| **HT1** | Docker-hoá 1 app nhỏ tự viết (vd Flask "hello" đọc 1 file flag): viết `Dockerfile`, build image, chạy container map cổng | `curl localhost:<port>` trả đúng · `docker ps` thấy container · kill rồi chạy lại bằng 1 lệnh | `Dockerfile` chạy được + cheatsheet "Docker: build/run/exec/logs/rm/cp" |
| **HT2** | Dựng stack nhiều container bằng Compose (app + DB redis/postgres), có `healthcheck` + `restart: unless-stopped` | `docker compose up -d` lên cả stack · app gọi được DB · `compose ps` báo healthy · `down` rồi `up` lại ra đúng trạng thái | `docker-compose.yml` mẫu + cheatsheet "Compose: up/down/logs/ps/exec/build" |
| **HT3** | Deploy theo version + rollback: build image gắn tag `v1`/`v2`, đổi qua lại | Đổi `v1`↔`v2` mỗi lần 1 lệnh · service gián đoạn ≤ vài giây | `deploy.sh` + `rollback.sh` + ghi chú quy ước tag |
| **HT4** | Backup/restore 1 lệnh: nén thư mục challenge + volume/DB ra 1 file; script phục hồi | Cố ý xoá/hỏng 1 service → `restore` về bản sống **< 1 phút thao tác**, dữ liệu nguyên | `infra/backup.sh` + `infra/restore.sh` (đã test khôi phục thật) |
| **HT5** | Theo dõi + cảnh báo: script poll cổng/endpoint mỗi N giây, in UP/DOWN, kêu khi chết; biết `docker stats`/`logs -f`/`htop` | Chủ động kill 1 service → script báo **DOWN trong 1 chu kỳ** | `infra/watch.sh` + cheatsheet "monitor: stats/logs/htop/ss" |
| **HT6** | Bắt & đọc traffic: `tcpdump` lưu traffic 1 service ra `.pcap`, mở bằng `tshark`/Wireshark, lọc ra 1 request đầy đủ | Trích được payload 1 request từ `.pcap` + đọc hiểu nó (nền cho replay Tuần 2) | 1 `.pcap` mẫu + cheatsheet "tcpdump/tshark filter" |
| **HT7** | Quy trình **vá + restart không rớt SLA**: backup → sửa code/binary → test local → deploy → verify sống (dưới ràng buộc cooldown) | Chạy trọn chu trình: service xanh lại + exploit hết ăn (xem mục 3) | cheatsheet "quy trình vá-deploy-verify 6 bước" |

**Lưu ý theo luật thi:** không vá được container config → **bỏ** hướng gia cố `read_only`/`cap_drop`/seccomp qua compose. Cooldown restart 10 phút → **test vá offline cho chắc rồi deploy một lần, không thử-sai trên máy thi**. HT1-2-5-6 vẫn cần để *dựng hệ thống luyện* và *hiểu môi trường*; HT7 là nhiệm vụ quan trọng nhất.

**Cả đội đều làm HT1-HT7** (đây là kỹ năng phòng thủ chung), P1 dẫn và xong sớm nhất.

### Sổ tay lab HT1–HT7 (làm trên máy cá nhân, mỗi người tự chạy)

**Môi trường chung:** Ubuntu 22.04/24.04 hoặc VM Ubuntu (4 GB RAM, 10 GB trống), Docker Engine + Compose plugin, Python 3, `curl`, `git`, `tcpdump`, `tshark`, `jq`. Làm trong repo riêng `iboh-labs/`; mỗi người dùng nhánh/thư mục riêng, không chạy lab trên vulnbox thi thật. Trước HT1 kiểm tra `docker version`, `docker compose version`, `python3 --version`; ghi phiên bản vào `infra/ENV.md`. Nếu không có quyền cài Docker trên máy, dùng Ubuntu VM; Play with Docker chỉ đủ cho HT1–HT2 vì phiên làm việc tạm thời.

**Ứng dụng xuyên suốt HT1–HT6:** một Flask app có `GET /health` trả `{"ok":true}`, `GET /note/<id>` đọc note trong Redis, `POST /note` ghi note. Tạo thêm `GET /version` trả `v1` hoặc `v2`. Redis là dữ liệu cần backup/restore. Dùng cùng một app qua các lab để thời gian dành cho thao tác vận hành, không phải viết ứng dụng mới. Đặt cấu trúc `infra/app/app.py`, `infra/app/requirements.txt`, `infra/Dockerfile`, `infra/compose.yaml`, `infra/scripts/`, `infra/evidence/`.

| Lab | Làm ở đâu / thao tác theo thứ tự | Kiểm tra và bằng chứng phải lưu |
| --- | --- | --- |
| **HT1 — Docker** (Ngày 1, 90–120') | Trong `infra/`: viết `Dockerfile` từ `python:3.12-slim`, copy requirements, cài dependency, copy app, `CMD` chạy Flask trên `0.0.0.0:8000`. Chạy `docker build -t iboh-lab:v1 .`, `docker run -d --name iboh-app -p 127.0.0.1:18080:8000 iboh-lab:v1`. Thực hành `docker ps`, `docker logs iboh-app`, `docker exec iboh-app ...`, `docker stop/rm`; chạy lại bằng đúng lệnh đã ghi. | `curl -fsS localhost:18080/health` thành công trước và sau khi tạo lại container. Lưu `Dockerfile`, `app.py`, lệnh đã chạy và output ngắn trong `infra/evidence/HT1.md`. Một thành viên khác làm lại theo README, không cần hỏi tác giả. |
| **HT2 — Compose** (Ngày 2, 90–120') | Thêm Redis vào `compose.yaml`, volume có tên cho dữ liệu, app dùng hostname `redis` trên mạng Compose. Redis healthcheck bằng `redis-cli ping`; app healthcheck bằng HTTP/Python; app chờ Redis healthy bằng `depends_on`. Chạy `docker compose up -d --build`, tạo note qua API, `docker compose ps`, `docker compose logs --tail=30 app`, `docker compose exec redis redis-cli ping`, rồi `down` và `up -d`. | `/health` xanh; note còn sau `down`/`up` **không dùng `down -v`**; `compose ps` báo healthy. Lưu `compose.yaml` và transcript kiểm tra trong `HT2.md`. Ghi rõ volume bị xoá nếu dùng `down -v`. |
| **HT3 — deploy/rollback** (Ngày 3, 45') | Tạo v2 trả `/version = v2`; build `iboh-lab:v2`. `deploy.sh v1\|v2` đổi tag image app trong Compose rồi `docker compose up -d --no-deps app`; `rollback.sh` gọi lại tag trước. Đo gián đoạn bằng vòng `curl` mỗi giây trong lúc đổi v1→v2→v1. | `/version` đúng từng lần; Redis note còn nguyên; ghi số request thất bại và thời gian gián đoạn vào `HT3.md`. **Không đặt ngưỡng vài giây cứng cho Compose một container**: mục tiêu là biết số đo thực tế và rollback được bằng 1 lệnh; trước khi áp dụng vào trận phải test với checker. |
| **HT4 — backup/restore** (Ngày 3, 45') | `backup.sh` nhận thư mục đầu ra: lưu bản code/config, tag image đang chạy và export dữ liệu Redis bằng `redis-cli --rdb` hoặc `SAVE` rồi copy `dump.rdb`; tạo archive có timestamp + checksum. `restore.sh <archive>` dừng stack, phục hồi code/dump, lên stack và gọi `/health` + đọc note mẫu. Diễn tập: tạo note `marker-123`, backup, sửa/xoá note và làm hỏng app, restore. | Note `marker-123` trở lại, `/health` xanh; lưu thời gian thao tác thực đo, checksum và transcript `HT4.md`. Không coi việc nén mỗi thư mục source là đã backup DB. Bản backup đặt ngoài thư mục sẽ xoá. |
| **HT5 — giám sát** (Ngày 4, 40') | `watch.sh <url> <interval>` gọi `curl --max-time 2` theo chu kỳ, ghi timestamp, HTTP status, `UP/DOWN` vào log, kêu một lần khi chuyển UP→DOWN. Mở terminal khác chạy `docker stats`, `docker compose logs -f app`, `ss -ltnp`. `docker compose stop app`, quan sát, rồi `start app`. | Log chỉ ra DOWN trong ≤1 chu kỳ + timeout, sau đó UP; lưu log và lệnh chẩn đoán vào `HT5.md`. Phân biệt container đang chạy với endpoint thật sự hoạt động. |
| **HT6 — traffic** (Ngày 4, 40') | Chỉ bắt traffic **lab của mình**. Tạo request có marker `LAB-REQUEST-123`; bắt `sudo tcpdump -i any -s 0 -w infra/evidence/HT6.pcap 'tcp port 18080'`, gửi request, dừng capture. Đọc `tshark -r ... -Y http -V` hoặc mở Wireshark → Follow TCP Stream; tìm marker và xác định method/path/body. Nếu Docker không xuất hiện trên `any`, bắt interface bridge/container tương ứng (`ip route`, `docker network inspect`). | `HT6.md` chứa đúng 1 request đã trích, filter đã dùng, và ý nghĩa từng trường. `.pcap` có thể chứa token/flag: chỉ giữ dữ liệu giả và không commit capture thật từ trận. |
| **HT7 — vá và xác minh** (Ngày 6, 2–3h) | Dùng **một service web tự tạo có path traversal** hoặc binary C nhỏ có `read` quá độ dài (không dùng challenge có điều khoản cấm sửa). Lưu exploit PoC và request hợp lệ trước vá; copy code/binary ra backup. Vá đúng điểm lỗi trong code/binary, build/chạy **bản clone offline**; chạy PoC (phải thất bại) và request hợp lệ (phải thành công). Sau đó mới chép file được phép sửa lên service lab, restart một lần; ghi thời gian và rollback nếu request hợp lệ hỏng. Mô phỏng cooldown 10 phút bằng log thời điểm restart, không restart lần hai trong 10 phút. | `patches/<service>/` gồm `before`, `after` hoặc diff, PoC, request hợp lệ, kết quả trước/sau và `HT7.md` ghi 6 mốc: backup → vá → test exploit → test chức năng → deploy/restart → verify. Với binary, xác nhận hash/file/kiến trúc của file chạy sau deploy. |

**Quy tắc chấm lab:** người làm tự demo từ repo sạch; người còn lại chạy lại các lệnh từ README. Mỗi `HTx.md` ghi người làm, ngày, lệnh, output quan trọng, lỗi gặp và cách xử lý. Nếu chưa chạy được thực tế, đánh dấu `CHƯA ĐẠT`; không tính chỉ vì đã viết script.

## 2. Kỹ thuật khai thác theo tier — BẢNG THAM CHIẾU

> Bảng tra cứu đầy đủ, **không phải việc-cần-làm-hết**. Mỗi người leo lane mình từ Tier thấp lên, **không giới hạn trên** — ai làm tới đâu hay tới đó. Trần mục tiêu mặc định: P1 → PWN T4, P2 → WEB T5, P3 → CRYPTO T4; phần cao hơn là *stretch* (leo tự do nếu dư sức). Mỗi tier chỉ tính "xong" khi **tự viết/chạy được ≥1 exploit thật**; lưu script vào `exploits/<lane>/` để tái dùng làm farm.
>
> Cột **Dạng hay gặp** giúp nhận diện nhanh class lỗi khi nhìn một challenge lạ.

### PWN — khai thác nhị phân (P1 chính, P2 phụ)

| Tier | Kỹ thuật | Dạng hay gặp |
| --- | --- | --- |
| 1 | Stack BOF: ret2win, ghi đè saved RIP, đổi biến local; ret2shellcode khi stack RWX (`jmp rsp`) | Binary nhỏ, hàm `win()`, `gets`/`read` quá cỡ |
| 2 | Format string: leak stack (`%p`/`%x`), arbitrary read (`%s`), arbitrary write (`%n`/`%hn`/`%hhn`), ghi đè GOT, leak canary/PIE/libc | `printf(buf)` không format |
| 3 | ROP bypass NX: ret2libc, ret2plt, ret2syscall, ROP chain, ret2csu (điều khiển tham số), one-gadget, stack pivot, ret2dlresolve (no leak) | NX bật, có/không PIE |
| 4 | Bypass mitigation: leak + rewrite canary, leak PIE/ASLR → tính offset libc, partial overwrite, **SROP**, format-string→ROP | Full mitigation, cần leak trước |
| 5 | Shellcoding: viết shellcode tay (x64/x86), hạn chế ký tự/alphanumeric, egghunter, **ORW seccomp** (open-read-write khi execve bị chặn), SROP-shellcode | Sandbox seccomp, shellcode runner |
| 6 | Heap intro: cấu trúc chunk/bin/tcache, UAF, double free, **tcache poisoning/dup**, off-by-one & null-byte poison, chunk overlap | Menu heap (add/edit/free/show) |
| 7 | Heap trung cấp: fastbin dup (+consolidate), unsorted-bin leak (libc), unsafe unlink, tcache stashing unlink, house of spirit, **large bin attack** | Menu heap, libc leak qua unsorted |
| 8 | Heap nâng cao (glibc 2.32+ safe-linking & key): bypass safe-linking, tcache-key bypass, house of botcake/einherjar/lore/force | glibc mới, không có hook |
| 9 | **FILE/FSOP**: `_IO_FILE` + fake vtable, `_IO_str_jumps`, house of orange/apple2/cat/banana, FSOP qua stdout | Không free hook, có arbitrary write |
| 10 | Hijack control-flow hiện đại: `__free_hook`/`__malloc_hook` (glibc cũ), **exit handlers** (`__exit_funcs`, `tls_dtor_list`, pointer-guard), largebin→write target | Tùy phiên bản glibc |
| 11 (stretch) | Kernel pwn: LKM char-device bug, ret2usr, bypass KASLR/SMEP/SMAP, `modprobe_path`/cred overwrite, kernel UAF + heap spray, dirtypipe/cross-cache | File `.ko`, `bzImage`, `initramfs` |
| 12 (stretch) | Integer overflow/underflow, type confusion, race/TOCTOU & double-fetch, uninitialized memory, arch khác (ARM/MIPS/RISC-V), Windows pwn | — |

**Công cụ PWN:** pwntools, `cyclic`/pattern offset, ROPgadget/ropper/angrop, one_gadget, libc-database/libc.rip, GDB + pwndbg/gef, `checksec`, Ghidra/IDA.

### WEB — khai thác ứng dụng web (P2 chính)

| Tier | Kỹ thuật | Dạng hay gặp |
| --- | --- | --- |
| 1 | SQLi (union/error/boolean-blind/time-blind/stacked), NoSQLi cơ bản, auth bypass (login SQLi, default cred), IDOR, path traversal, LFI, info disclosure (`.git`/`.env`/backup) | Login, search, `?id=`, `?file=` |
| 2 | XSS (reflected/stored/DOM), CSRF, clickjacking, open redirect, CRLF/response-splitting, upload bypass (ext/MIME/magic/double-ext/`.htaccess`/SVG/polyglot) | Comment, profile, form upload |
| 3 | RCE qua injection: command/OS injection, **SSTI** (Jinja2/Twig/Freemarker/Smarty/ERB/Velocity), code injection (`eval`/`exec`), LDAP/XPath/SSI/ESI injection | Template render, ping/convert tool |
| 4 | **SSRF** (blind, cloud metadata 169.254, gopher/dict/file scheme, redirect bypass), **XXE** (in-band/OOB/blind), RFI, LFI→RCE (log/session/PHP wrapper/filter-chain/`/proc`) | Fetch URL, XML parser, import |
| 5 | **Deserialization**: PHP object injection + POP chain (phpggc), Python pickle/PyYAML, Java (ysoserial, JNDI/log4shell), .NET ViewState, Ruby Marshal, Node | Cookie/param dạng serialize |
| 6 | Auth/token: **JWT** (none, HS/RS confusion, weak secret, `kid`-inject, `jku`/`x5u`/`jwk`), OAuth/OIDC/SAML flaw, session fixation/prediction, reset poisoning, 2FA bypass | API có Bearer token |
| 7 | Logic/JS hiện đại: **prototype pollution** (client & server → RCE sink), **race condition** (limit-overrun/TOCTOU/multi-step), business logic (giá/số lượng/coupon), mass assignment, HTTP parameter pollution | Giỏ hàng, chuyển tiền, Node app |
| 8 | Chaining & bypass: WAF/filter bypass (encoding/case/comment/charset), **HTTP request smuggling** (CL.TE/TE.CL/H2), web cache poisoning/deception, DOM clobbering, mutation XSS, XS-Leaks | Có proxy/CDN/WAF trước app |
| 9 (stretch) | GraphQL abuse (introspection/batching/injection), WebSocket/gRPC attack, dependency confusion, client-side path traversal, CVE framework (Spring4Shell…) | — |

**Công cụ WEB:** Burp Suite, ffuf/gobuster, sqlmap, HackTricks + PayloadsAllTheThings, jwt_tool, phpggc/ysoserial. Lang bẫy riêng: **PHP / Python / Go / Node/Vue**.

### CRYPTO — mật mã (P3 chính)

| Tier | Kỹ thuật | Dạng hay gặp |
| --- | --- | --- |
| 1 | Encoding (base16/32/64/85, URL/HTML), XOR (single/repeating-key, known-plaintext, crib-drag), cổ điển (Caesar/ROT/Vigenère/Affine/substitution/rail-fence), frequency analysis, nhận diện mã | Chuỗi lạ, "giải mã này" |
| 2 | AES mode sai: ECB (pattern leak, byte-at-a-time, cut-paste), CBC (**bit-flip**, **padding oracle**, IV=key, IV reuse), CTR/OFB/CFB keystream reuse (many-time pad), **GCM nonce reuse** (forbidden attack) | Oracle encrypt/decrypt |
| 3 | Hash & PRNG: **length extension** (MD/SHA1/2), collision (MD5 chosen-prefix, SHA1), khôi phục **MT19937** (untemper), LCG/`random` predict, nonce reuse, HMAC/timing | Token/cookie sinh từ hash/rand |
| 4 | RSA cơ bản: factor (**Fermat** p≈q, Pollard p−1/ρ, batch-GCD shared prime, FactorDB), e nhỏ (cube root, **Håstad** broadcast), **Wiener** (d nhỏ), common modulus, **LSB/parity oracle**, forge e=3, Franklin-Reiter | Cho `n,e,c`; nhiều ciphertext |
| 5 | RSA nâng cao: **Coppersmith** (stereotyped msg, known high/low bits p, short-pad), **Boneh-Durfee**, partial key exposure, multi-prime/power, CRT fault (Bellcore), Manger (OAEP) | Lộ một phần p/d/m |
| 6 | Discrete log / DH: BSGS, **Pohlig-Hellman** (order smooth), Pollard-rho DLP, small-subgroup confinement, invalid param, DH MITM, ElGamal nonce reuse | Cho `g,p,g^x` |
| 7 | ECC: ECDLP smooth-order, **invalid curve**, **singular curve** (node/cusp), anomalous (**Smart's**), MOV/pairing, **ECDSA nonce reuse/biased** → private key, twist attack | Chữ ký/điểm trên đường cong |
| 8 | **Lattice**: LLL/BKZ, Hidden Number Problem (biased-nonce DSA/ECDSA), knapsack (Merkle-Hellman), Coppersmith-qua-lattice, modular inequalities | "nghe mùi" lattice, nonce lệch |
| 9 (stretch) | Pairing-based (BLS/IBE), isogeny (SIDH/CSIDH toy), post-quantum toy (LWE), side-channel, RC4 bias/LFSR (Berlekamp-Massey), AES white-box | — |

**Công cụ CRYPTO:** SageMath, PyCryptodome, `sympy`/`gmpy2`, RsaCtfTool, z3, `pwntools` (kết nối oracle), lattice: fpylll.

### REV — dịch ngược (P1/P2 chia nhau)

| Tier | Kỹ thuật | Dạng hay gặp |
| --- | --- | --- |
| 1 | Static+dynamic: đọc asm x86/x64, Ghidra/IDA/Binja, gdb/pwndbg, `strings`/`strace`/`ltrace`/`file`/`binwalk`, khôi phục logic keygen/crackme, patch nhảy điều kiện | "nhập đúng key", flag check |
| 2 | Anti-analysis: anti-debug (ptrace, `/proc`, timing/rdtsc, int3-scan), anti-disasm, string obfuscation (XOR/stack-string/RC4), unpack UPX & packer tự chế, self-modifying code, TLS callback | Binary "chống xem" |
| 3 | Obfuscation nâng cao: control-flow flattening (OLLVM), opaque predicate, **VM/bytecode interpreter** (devirtualization), MBA simplification, instruction substitution | Vòng lặp fetch-decode-execute |
| 4 | Tooling & nền tảng: **angr/symbolic & concolic**, **Z3/claripy**, qiling/unicorn emulate, .NET (dnSpy/de4dot), Java/Android (jadx/apktool/Frida), Go/Rust/Nim stripped, Python (pyc/PyInstaller) | Constraint phức tạp, managed code |
| 5 (stretch) | Firmware (binwalk/QEMU), kernel module, eBPF, bootloader, arch lạ (MIPS/ARM/RISC-V/AVR), hardware/JTAG, custom ISA | — |

**Công cụ REV:** Ghidra/IDA/Binary Ninja, pwndbg/gef, angr, Z3, dnSpy, jadx, qiling/unicorn.

> **Ghi chú:** forensics / stego / misc / OSINT có thể xuất hiện nhưng **ưu tiên thấp trong AD** (briefing chỉ cho thấy app code + binary). Không luyện sâu, chỉ nắm công cụ cơ bản (`binwalk`, `zsteg`, `volatility`, `exiftool`) để không bí nếu lạc vào.

### Khai thác đặc thù AD (cross-category — ai cũng nắm)

1. **Exploit farm**: biến mỗi script thành vũ khí tự chạy mọi IP đối thủ mỗi tick, tự nộp flag (DestructiveFarm / tự viết).
2. **Đọc traffic → steal exploit**: bắt gói đối thủ đánh mình (`tcpdump`/`tshark`/pcap), tách payload.
3. **Replay & modify**: bắn lại payload bắt được, chỉnh flag-id/tham số để đánh đội khác.
4. **Flag-ID handling**: lấy danh sách target/flag-id từ gameserver mỗi tick, nạp vào farm.
5. **Khai thác song song nhiều dịch vụ** không để lỗi 1 cái làm chết cả farm.
6. **Tốc độ first-blood**: nhận diện class lỗi quen → ra exploit trong vài phút đầu.

## 3. Thao tác VÁ (phần khó thật — vá thế nào, không phải vá ở đâu)

Mỗi kỹ thuật vá luyện tới mức: **vá xong exploit hết ăn + checker vẫn xanh**. Vá mà chết dịch vụ = tệ hơn không vá.

**Ràng buộc bắt buộc:** chỉ sửa được code/binary (không `Dockerfile`/`compose`) → không dùng `LD_PRELOAD`/seccomp/proxy qua compose, phải vá thẳng vào code/binary. Cooldown restart 10 phút → test offline chắc rồi deploy một lần. Black box: pwn trước mới vá được.

**Vá binary (pwn/rev — khó nhất):**
- Giữ nguyên kích thước & offset: sửa hằng số (vd giảm size `read`), NOP đoạn nguy hiểm, đổi nhánh nhảy, vá hex tại chỗ.
- **Code cave**: nhét logic kiểm tra mới vào vùng trống rồi nhảy tới.
- Công cụ: `pwntools`, **LIEF**, `patchelf`, **keystone**, Ghidra patch, `objcopy`.
- Hook trong binary: ghi đè GOT/PLT trỏ hàm nguy hiểm sang wrapper an toàn; seccomp qua code cave (chỉ khi vá thẳng binary).
- Quy trình: tải về máy cá nhân → vá → test exploit hết ăn + chức năng còn sống → đẩy lên → restart → xác nhận checker xanh. Luôn giữ backup.

**Vá web/source:**
- Vá đúng điểm vào, không chặn request hợp lệ của checker: parameterized query, whitelist input, output-encoding, tắt hàm nguy hiểm, ép kiểu, giới hạn độ dài.
- Middleware/filter trước app (mini-WAF) mà vẫn cho checker đi qua.
- Vá config lộ: tắt debug, bịt `.git`/backup, sửa quyền file flag, bỏ endpoint thừa.
- Rủi ro lớn nhất: chặn nhầm checker → mất SLA. **Test mỗi rule với checker trước khi bật.**

**Kỷ luật chung:** backup trước khi đụng → vá nhỏ nhất có thể → test 2 mặt (exploit hết ăn + checker sống) → rollback nhanh nếu checker đỏ.

---

# PHẦN II — LỊCH 15 NGÀY (2 GIAI ĐOẠN)

- **Giai đoạn 1 — Tuần 1 (Ngày 1-7): luyện kỹ năng & kiến thức** kiểu jeopardy. Học Docker/Compose/vận hành + leo tier khai thác từng mảng + viết cheatsheet khi học. **Chưa dựng AD, chưa mô phỏng.**
- **Giai đoạn 2 — Tuần 2 (Ngày 8-15): dựng hệ thống Attack-Defense & thực chiến.** Dựng ForcAD + mạng, cắm service/checker, rồi mô phỏng lặp đi lặp lại.

## Quy ước lặp lại mỗi ngày

- **[BB]** = bắt buộc · **[BĐ]** = bỏ được nếu trễ/stretch. Giờ ghi là giờ tập trung phần chính (~7h/ngày).
- **"Xong" đo được**: tier xong = tự chạy ≥1 exploit thật; infra xong = tự dựng lại được không cần hướng dẫn; script xong = chạy ra kết quả đúng, đã lưu repo.
- **Vừa học vừa viết cheatsheet**: mỗi kỹ thuật/lệnh học được ghi ngay vào `cheatsheet.md` — chỉ ghi thứ **đã tự chạy thật**.
- **Báo cáo cuối ngày (10 phút, [BB])**: mỗi người 3 ý vào `progress.md` — *làm được gì / kẹt ở đâu / mai cần gì*.
- **2 cổng kiểm**: **Gate 1** cuối Tuần 1 (kỹ năng), **Gate 2** trước dress rehearsal (Ngày 14).

**Tier: đặt mục tiêu theo lớp, KHÔNG giới hạn trên — ai làm tới đâu hay tới đó.** Trần mục tiêu mặc định, phần cao hơn leo tự do:

| Người | Lane | Trần mục tiêu | Stretch (leo tự do) |
| --- | --- | --- | --- |
| P1 | PWN + infra | PWN T4 (BOF/fmt/ROP/bypass canary+PIE) | PWN T5+ (shellcode/heap/FSOP…) |
| P2 | WEB | WEB T5 (tới deserialization/JWT) | WEB T6+ |
| P3 | CRYPTO | CRYPTO T4 (tới RSA cơ bản) | CRYPTO T5+ |
| REV | P1+P2 chia | REV T2 (static+patch, anti-debug) | REV T3+ |

---

## GIAI ĐOẠN 1 — TUẦN 1: LUYỆN KỸ NĂNG (Ngày 1-7)

Mỗi ngày chạy **2 mạch song song**:
- **Mạch Hạ tầng** (P1 dẫn, cả đội học đủ để vận hành) — Docker/Compose/deploy/monitor, học tuần tự, front-load Ngày 1-4 rồi nhẹ dần.
- **Mạch Khai thác** (theo lane) — giải challenge jeopardy thật (pwn.college, PortSwigger, CryptoHack, crackmes, CTF cũ).

> **Cách chạy mạch khai thác:** số giờ ghi mỗi ngày là **giờ chuẩn** — luyện thêm ngoài giờ thoải mái. Mỗi ngày **bắt đầu từ tier hiện tại của mỗi người**, không cố định tier theo ngày. Cuối ngày cập nhật tiến độ (xong tier nào) vào `progress.md`; **tier bắt đầu hôm sau = tier kế tiếp**. Mỗi tier tính "xong" khi tự chạy ≥1 exploit thật, lưu script vào `exploits/<lane>/`. Đi theo tốc độ thật của từng người.

Ô "tier bắt đầu" dưới đây để **điền sau mỗi ngày** (ban đầu = Tier 1, hoặc tier mỗi người tự đánh giá đang ở).

### Ngày 1 — Docker căn bản + mở màn khai thác · hạ tầng ~2h · khai thác ~3h · [BB]

- **Hạ tầng — P1 dẫn (~2h): làm `HT1`** (Docker-hoá 1 app). Đạt khi + sản phẩm: xem bảng HT ở Part I.
- **Khai thác (~3h, bắt đầu từ Tier 1):** P1 ▸ Tier __ · P2 ▸ Tier __ · P3 ▸ Tier __.
- **Đầu ra:** sản phẩm `HT1` (`Dockerfile` + cheatsheet Docker); `progress.md` ghi tier mỗi người đạt.

### Ngày 2 — Docker Compose + khai thác · hạ tầng ~2h · khai thác ~4h · [BB]

- **Hạ tầng (~2h): làm `HT2`** (Compose stack nhiều container + healthcheck).
- **Khai thác (~4h, bắt đầu từ tier hiện tại):** P1 ▸ Tier __ · P2 ▸ Tier __ · P3 ▸ Tier __.
- **Đầu ra:** sản phẩm `HT2` (`docker-compose.yml` + cheatsheet Compose) + mỗi exploit vừa làm (script `exploits/<lane>/`).

### Ngày 3 — Deploy/rollback/backup + khai thác + REV mở màn · hạ tầng ~1.5h · khai thác ~4h · [BB]

- **Hạ tầng (~1.5h): làm `HT3` + `HT4`** (deploy/rollback theo version; backup/restore 1 lệnh).
- **Khai thác (~4h, bắt đầu từ tier hiện tại):** P1 ▸ Tier __ · P2 ▸ Tier __ · P3 ▸ Tier __. **REV Tier 1** (P1/P2 chia): đọc Ghidra + patch nhảy điều kiện.
- **Đầu ra:** sản phẩm `HT3`+`HT4` (`deploy.sh`/`rollback.sh`/`backup.sh`/`restore.sh`).

### Ngày 4 — Monitor/traffic + khai thác · hạ tầng ~1.5h · khai thác ~4.5h · [BB]

- **Hạ tầng (~1.5h): làm `HT5` + `HT6`** (theo dõi/cảnh báo health; bắt & đọc traffic ra `.pcap`).
- **Khai thác (~4.5h, bắt đầu từ tier hiện tại):** P1 ▸ Tier __ · P2 ▸ Tier __ · P3 ▸ Tier __.
- **Đầu ra:** sản phẩm `HT5`+`HT6` (`watch.sh`, `.pcap` mẫu, cheatsheet tcpdump/monitor).

### Ngày 5 — Ngày exploit-nặng + REV tier 2 · khai thác ~6h · [BB]

- **Hạ tầng:** chỉ ôn qua cheatsheet, không học mới.
- **Khai thác (~6h, bắt đầu từ tier hiện tại):** P1 ▸ Tier __ · P2 ▸ Tier __ · P3 ▸ Tier __. **REV Tier 2** (anti-debug) nếu P1/P2 đã qua REV T1.
- **Đầu ra:** mỗi người ≥1 exploit mới lưu repo + cheatsheet cập nhật.

### Ngày 6 — Luyện kỹ năng VÁ (cầu nối sang Tuần 2) + khai thác · vá ~3h · khai thác ~3h · [BB]

- **Kỹ năng vá (~3h): làm `HT7`** trên **chính binary/web vừa exploit ở Tuần 1** → vá tối thiểu (binary giữ offset; web không chết chức năng) → tự kiểm *exploit hết ăn + chức năng còn chạy* (test thủ công, chưa cần ForcAD). P1 dẫn vá binary, P2 vá web.
- **Khai thác (~3h, bắt đầu từ tier hiện tại):** P1 ▸ Tier __ · P2 ▸ Tier __ · P3 ▸ Tier __.
- **Đầu ra:** sản phẩm `HT7` (cheatsheet quy trình vá 6 bước) + `patches/` (bản vá + ghi chú chỗ sửa).

### Ngày 7 — Tổng kết Tuần 1 + Gate 1 + chuẩn bị Tuần 2 · ~5h · [BB]

- **Gate 1 (điều kiện sang Tuần 2):** mỗi người đạt (hoặc gần) **trần mục tiêu** của lane + tự chạy exploit thật mỗi tier đã học · Docker/Compose/deploy/backup/monitor tự vận hành · bắt+đọc được traffic · cheatsheet đủ các mục đã học.
- **Chuẩn bị Tuần 2 — bắt đầu `DW0`:** gom/đóng gói **3-5 service phủ 4 mảng** (web/pwn/crypto/rev), mỗi service đọc flag từ `/home/user/flag.txt`; với pwn/rev xoá source chỉ để binary. P1 đọc trước tài liệu **ForcAD** + **Tailscale/OpenVPN**.
- **Ai chưa đạt trần:** ghi rõ còn thiếu gì → tranh thủ khoảng trống Tuần 2 bù (ngày đệm Ngày 11).

---

## GIAI ĐOẠN 2 — TUẦN 2: DỰNG AD & THỰC CHIẾN (Ngày 8-15)

**Hai cơ chế dùng xuyên suốt các phiên mô phỏng:**

- **Drill Vá-Sống** (lặp mỗi sim): 1 service đang bị exploit ăn → vá đạt khi (a) exploit hết ăn, (b) checker xanh 3 tick, (c) chỉ sửa code/binary, (d) ≤1 lần restart (cooldown 10'). **Ghi thời gian mỗi lần, mục tiêu giảm dần.**
- **Đường lui khi KHÔNG exploit được black box** (thứ tự ưu tiên mỗi tick): (1) giữ service sống trước — SLA là điểm chắc; (2) có exploit sẵn → chạy farm nộp flag; (3) đang bị đánh → P3 bắt payload, **replay** (không cần hiểu) + xem payload lộ chỗ nào để vá; (4) bí thật → bỏ qua, chuyển service khác. **Không đốt cả tick vào 1 black box.**

### Bảng nhiệm vụ dựng Tuần 2 (có sản phẩm) — DW1–DW5

> Giống bảng HT: mỗi nhiệm vụ có **việc cụ thể + tiêu chí đạt + sản phẩm**. Các ngày dưới tham chiếu theo mã.

| Mã | Việc cụ thể | Đạt khi (đo được) | Sản phẩm để lại |
| --- | --- | --- | --- |
| **DW0** | Đóng gói service có ghi/đọc flag: bắt đầu 1 web service, sau đó mở rộng 3–5 service phủ web/pwn/crypto/rev | mỗi service chạy được, lưu/đọc flag và có checker riêng trước khi đưa vào sim | `services/<tên>/` (mã + Dockerfile + README) |
| **DW1** | Dựng **ForcAD** 3 đội, tick 300 giây, flag lifetime 5 nếu phiên bản hỗ trợ; cắm service đầu tiên | scoreboard lên · ≥1 service checker **xanh 3 tick liên tục** | `forcad/` (config đúng phiên bản + VERSION.md + README) |
| **DW2** | Nối 3 máy bằng **Tailscale** + cài/test **OpenVPN client** | 3 máy ping nhau bằng IP tailscale + ssh được vào nhau | ghi chú IP mỗi máy + cheatsheet "tailscale/openvpn up" |
| **DW3** | Thử nộp flag bằng giao thức ForcAD thực tế (dùng `nc` nếu là line protocol) | nộp 1 flag hợp lệ → scoreboard ghi điểm; flag sai bị từ chối | `ops/submit.md` (host/port/định dạng đã kiểm chứng) |
| **DW4** | Viết **checker ForcAD** cho các service ở DW0 (PUT flag `/home/user/flag.txt`, GET qua chức năng bình thường, CHECK liveness) | mỗi checker **xanh 5 tick liên tục**, tự đặt+đọc được flag | `checkers/<service>/` |
| **DW5** | **Exploit farm** tự động, dựng dần 5 bước: ① bắt traffic → ② script nộp flag auto → ③ lấy flag-id/target mỗi tick → ④ ghép exploit bắn mọi IP → ⑤ replay payload bắt được | Trong 1 sim: farm **tự nộp flag mọi IP không cần tay** + **replay ≥1 payload** | `farm/` (`submit.py`, `get_targets.py`, `run.py`, `replay.py`) |

### Sổ tay lab DW0–DW5 (chỉ trong sân chơi do đội dựng)

**Cấu trúc bàn giao:** `services/`, `checkers/`, `forcad/`, `farm/`, `ops/`, `evidence/`, `README.md`. P1 sở hữu host và runbook, P2 làm service web + checker chức năng, P3 làm flag pipeline/farm; **mỗi người phải tự chạy lại một lần phần của người khác**. Dùng 3 VM Ubuntu hoặc 3 máy thật nối LAN/Tailscale. Mỗi đội có một service instance riêng; không dùng chung volume flag. Host ForcAD cần truy cập được IP/port của cả 3 instance. Ghi sơ đồ IP/port thật vào `ops/network.md`; không đưa token thật vào repo.

| Lab | Bài thực hành cụ thể | Điều kiện nghiệm thu / file bàn giao |
| --- | --- | --- |
| **DW0 — service** (Ngày 7–8) | **Bắt đầu bằng 1 web service** có chức năng lưu và đọc note hợp lệ, thêm một endpoint lỗi để attacker đọc flag giả. Cho checker đặt flag qua chức năng hợp lệ và lấy lại bằng ID; flag lưu bền qua restart. Clone cùng image thành 3 instance, mỗi instance có DB/volume riêng. Sau khi pipeline chạy, thêm 1 TCP binary pwn và 1 service crypto/rev có giao thức rõ ràng; mục tiêu 3–5 service là phần mở rộng, **không chặn việc bắt đầu sim**. Viết `services/<name>/README.md` gồm port, cách chạy, lệnh request bình thường, vị trí flag và PoC khai thác. | Mỗi service có 3 phép thử thủ công: ghi flag giả → đọc lại bằng ID → exploit lấy flag trên bản chưa vá. Restart rồi đọc lại flag. `docker compose config` hợp lệ. Với binary, chỉ giao binary cho vai defender trong sim; source giữ ở thư mục người tổ chức, không xoá bản gốc. |
| **DW1 — trọng tài** (Ngày 8) | Clone repo ForcAD vào thư mục riêng, đọc **README/config mẫu đúng phiên bản đã clone**, pin commit trong `forcad/VERSION.md`; chạy ví dụ đi kèm trước, sau đó cấu hình 3 team + 1 service + checker DW0, tick 300 giây, flag lifetime 5 nếu phiên bản hỗ trợ đúng tên trường. Mở scoreboard từ máy host, theo dõi log một tick PUT/GET/CHECK. | `forcad/README.md` ghi commit, lệnh setup/start/stop thực chạy, tên field cấu hình đã xác minh, ảnh hoặc log 3 tick xanh liên tục. **Đừng giả định** `config.yml`, cổng 8080 hay giao thức nộp của một phiên bản ForcAD chưa kiểm tra. Nếu ForcAD ngốn thời gian, dùng harness local nhỏ gọi checker mỗi 300 giây để luyện HT7/DW4 rồi tích hợp lại ngày 9. |
| **DW2 — mạng** (Ngày 8) | Mỗi người cài Tailscale trên máy/VM của mình, đăng nhập cùng tailnet, ghi IP qua `tailscale ip -4`; test từ P1 tới P2/P3 bằng `ping`, `ssh`, `curl <IP>:<service-port>`. P1 giới hạn firewall chỉ cho mạng lab. Riêng OpenVPN: dùng profile test của đội hoặc server lab **do đội kiểm soát**, chạy client rồi xác nhận route/IP; không cần dựng OpenVPN server nếu sân chơi đã chạy qua Tailscale. | `ops/network.md` có bảng host, Tailscale IP, port, lệnh kết nối, kết quả test hai chiều và cách ngắt VPN. Không commit `.ovpn` chứa credential/key. |
| **DW3 — submit** (Ngày 8–9) | Tạo flag giả qua checker, lấy flag đúng của tick hiện tại, kiểm tra cổng và giao thức submit **từ tài liệu/source ForcAD đúng commit**, thử thủ công bằng client phù hợp; nếu là line protocol thì dùng `printf '%s\n' "$FLAG" \| nc <host> <port>`. Thử lại với flag sai và flag hết hạn. | `ops/submit.md` ghi host/port thực, định dạng input, nguyên văn phản hồi đã che flag, trường hợp valid/invalid/expired. Chỉ đặt mục tiêu chữ `ACCEPT` nếu server thực trả đúng chữ đó; tiêu chí chính là scoreboard tăng điểm cho flag hợp lệ. |
| **DW4 — checker** (Ngày 9) | Đọc interface checker của đúng phiên bản ForcAD; triển khai `check`, `put`, `get` (hoặc tên hàm thật của phiên bản đó). `put` gọi chức năng hợp lệ để lưu flag mới và trả ID; `get` dùng ID để đọc đúng flag; `check` dùng dữ liệu bình thường, không phụ thuộc exploit. Test độc lập với 2 flag khác nhau, restart service giữa PUT và GET, rồi nối với trọng tài. | `checkers/<name>/README.md` mô tả giao thức và câu lệnh test. 5 tick liên tục xanh, hai flag khác nhau không bị lẫn; vá lỗ hổng xong checker vẫn xanh. Nếu chưa đủ thời gian viết mọi checker, chỉ đưa service đã có checker vào sim. |
| **DW5 — farm/replay** (Ngày 10–12) | `farm/submit.py` nhận flag từ stdin và trả trạng thái; `get_targets.py` đọc danh sách target/flag-id từ **API hoặc file thực tế của sân chơi** (nếu chưa có, dùng fixture JSON rõ nhãn giả lập); `run.py` mỗi tick gọi exploit cho từng target với timeout, tách lỗi từng target, loại flag trùng, submit từ đúng máy đội mình, log tick/service/target/result. `replay.py` nhận request **đã bắt trong lab**, thay target và ID, gửi lại rồi submit flag. Test bằng 2 instance cố ý có lỗi và 1 instance đã vá. | `farm/README.md` có sơ đồ input/output và lệnh chạy. Log một phiên cho thấy ≥2 target bị thử, flag hợp lệ được nộp tự động, target đã vá không làm farm dừng, và 1 payload replay thành công. Không hardcode flag, token hoặc IP của giải thật; mọi request có timeout để không lấn sang tick sau. |

**Mốc quyết định:** cuối Ngày 8 phải có *1 service + checker + trọng tài chạy được* trước khi mở rộng số service. Cuối Ngày 9 mới tăng lên 3–5 service nếu pipeline đầu tiên xanh; nếu chưa, giữ 1–2 service nhưng chạy sim đúng tick. Điều này giúp các buổi mô phỏng rèn thao tác vận hành thực sự, thay vì dành hết thời gian dựng sân chơi.

### Ngày 8 — hoàn tất DW0 + DW1 + DW2 + DW3 (dựng sân chơi) · ~7h · [BB]

- **Hoàn tất pipeline `DW0` tối thiểu** nếu Ngày 7 chưa xong: 1 service web có ghi/đọc flag; mở rộng 4 mảng sau khi checker đầu tiên xanh.
- **P1+P3 (~5h): làm `DW1` + `DW2` + `DW3`** (ForcAD + Tailscale/OpenVPN + test nộp flag nc). Đạt khi + sản phẩm: xem bảng DW.
- **P2 (~2h):** tiếp tục leo tier / ôn.
- **Đầu ra:** sản phẩm DW0-DW1-DW2-DW3 (service đóng gói, ForcAD chạy, mạng nối, cheatsheet nộp flag).

### Ngày 9 — DW4 (viết checker) + Drill Vá-Sống #1 + smoke test · ~7-8h · [BB]

- **P1+P3 (~4h, việc nặng): làm `DW4`** (viết checker cho các service đã chuẩn bị ở DW0).
- **P1+P2 (~2h):** **Drill Vá-Sống #1** trên 1 binary (lần đầu có checker thật).
- **Cuối ngày:** smoke sim ~1h chạy thử trọn pipeline tick→flag→SLA.
- **[BĐ]:** binary thứ 2 có thể lùi sang Ngày 11.

### Ngày 10 — Mô phỏng #1 + farm bước đầu · ~7h (sim 2-3h) · [BB]

- **Cấu hình phiên:** các service đã chuẩn bị (DW0), `round_time: 300`, 3 đội, chưa cooldown. Vai: P1 uptime/deploy, P2 exploit+vá web, P3 farm.
- **P3: `DW5` bước ①-③** (bắt traffic → script nộp flag auto → lấy flag-id/target mỗi tick).
- **Debrief [BB]:** chốt **đúng 2 điểm yếu** (tên service/bước/người) vào `progress.md`.

### Ngày 11 — Sửa 2 điểm yếu + farm/replay + Mô phỏng #2 · ~7h (sim 3h) · [BB]; ngày đệm mềm

- **Sửa 2 điểm yếu** sim#1 (và bù Gate 1 nếu ai còn nợ từ Tuần 1).
- **P3: `DW5` bước ④-⑤** (ghép exploit bắn mọi IP, tự nộp + **replay** payload bắt được) → hoàn tất DW5.
- **Mô phỏng #2:** **bắt đầu tự áp cooldown restart 10'**, trọng tâm giữ uptime khi vá. **Drill Vá-Sống #2** (so thời gian với #1). Debrief chốt 2 điểm yếu.

### Ngày 12 — Mô phỏng #3 (replay + farm live) + sửa · ~7h (sim 4h) · [BB]

- **Cấu hình:** đủ service, `round_time: 300`, cooldown 10', **farm + replay chạy thật** cả phiên (có người cố tình đánh để P3 có traffic mà bắt).
- **Mục tiêu đo được:** farm tự nộp flag không cần can thiệp tay; P3 replay ≥1 payload.
- **Debrief:** chốt 2 điểm yếu cho Ngày 13.

### Ngày 13 — Mô phỏng #4 (dài, sát thi) + xoay vai + sửa · ~7h (sim 4-5h) · [BB]; #5 [BĐ]

- **Cấu hình:** sát thật nhất — 3 vai song song, cooldown 10', áp đúng "đường lui khi không exploit được".
- **Xoay vai:** mỗi người cầm thử khâu người khác 1 lượt (không ai là điểm chết đơn).
- **[BĐ]:** chạy thêm phiên #5 nếu còn sức. Debrief + sửa nhanh.

### Ngày 14 — Gate 2 + dress rehearsal + đóng băng + cheatsheet + hậu cần · ~6h (sim 4h) · [BB]

- **Rà Gate 2 (điều kiện chạy dress rehearsal):** mỗi category exploit sống ≥1 service · farm tự nộp flag · P3 replay được · vá 1 binary + 1 web không rớt SLA dưới cooldown 10' · backup/restore 1 lệnh. Thiếu gì bù ngay.
- **Dress rehearsal** đúng độ dài & tick thật (300s), cooldown 10', không can thiệp ngoài vai. Sau đó **đóng băng tooling**.
- **Hoàn thiện cheatsheet offline** + hậu cần: OpenVPN config đã test, SSH key, **mobile data/hotspot**, phân công **ai làm gì 15 phút đầu trận**, tải trước writeup/công cụ.

### Ngày 15 — Đệm/thi · 1-2h · [BB]

- Khởi động nhẹ 1 service quen cho ấm tay. **Không học thứ mới.**

> Rủi ro mất mạng khi thi: venue có thể chặn VPN/internet. AI chỉ rút ngắn phần học kiến thức, **không rút ngắn phản xạ**. Cheatsheet offline là bảo hiểm.

---

# PHẦN III — CHUẨN BỊ & NGUỒN HỌC

## Việc chuẩn bị (ưu tiên giảm dần)

1. **Chuẩn bị service để luyện (`DW0`)**: 3-5 service phủ 4 mảng (web/pwn/crypto/rev), mỗi service đọc flag từ `/home/user/flag.txt` hoặc DB. Nguồn: tự viết app nhỏ · đóng gói lại challenge jeopardy cũ thành service có lưu/đọc flag · tải service A-D công bố sau giải. pwn/rev: xoá source, chỉ để binary.
2. Bộ script: backup/restore 1 lệnh, khung exploit farm, script bắt+tách flag từ traffic.
3. Cài & test **OpenVPN client** (cái dùng thật) song song Tailscale (hạ tầng luyện).
4. Chuẩn bị mobile data/hotspot phòng venue chặn VPN.

## Nguồn học theo mảng

**PWN** — "Học PWN cùng JHT" (tiếng Việt): https://youtube.com/playlist?list=PLEvZsp0uc3SFuVi6TtcahxqsEbV29lXAM · pwn.college: https://pwn.college/ · how2heap (T6→T10): https://github.com/shellphish/how2heap · ir0nstone: https://ir0nstone.gitbook.io/

**WEB** — PortSwigger Academy (T1→T8): https://portswigger.net/web-security · HackTricks: https://book.hacktricks.xyz/ · PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

**CRYPTO** — CryptoHack: https://cryptohack.org/ · Cryptopals (T2→T4): https://cryptopals.com/ · RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool

**REV** — Ghidra + angr (T4): https://docs.angr.io/ · crackmes.one: https://crackmes.one/

**AD** — DestructiveFarm: https://github.com/DestructiveVoice/DestructiveFarm · ForcAD: https://github.com/pomo-mondreganto/ForcAD

> Tải trước writeup/notes/công cụ về máy vì thi thật có thể bị chặn mạng.

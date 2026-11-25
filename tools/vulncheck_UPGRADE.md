# vulncheck.py — KẾ HOẠCH NÂNG CẤP (tự động, resume được qua các lần tự gọi lại)

> Mục tiêu (yêu cầu user): scan NHIỀU lỗ hổng nhất ở 4 mảng (ưu tiên pwn→rev→crypto→web),
> chỉ rõ vị trí + lỗ gì + cách vá (đổi thành gì), lên kịch bản exploit (ret2win/ret2libc/
> stack pivot/shellcode/house of spirit...) + sinh script pwnld / payload, hiển thị rõ ràng.
> THÊM: nhận file nhị phân → dump asm → phân tích theo OFFSET như source → mã giả (IDA-like).
> Làm tự động, không hỏi. Chạm giới hạn output → ScheduleWakeup ~100s rồi làm tiếp (đọc file này).

## Kiến trúc hiện có (giữ, không phá)
- `Finding` (model giàu: rule_id/sev/cwe/tier/techniques/fix/category/scenario/location).
- `BinaryProfile` (checksec qua pwntools/checksec CLI + interesting_symbols). BUG: `@staticmethod` đúp ~dòng 234.
- `ScenarioCorrelator.correlate` (per-finding scenario theo category).
- `BaseScanner`→`PwnScanner` (pattern_rules + read/recv buffer + struct + condition OOB).
- Reporting đa định dạng (Rich/GCC/JSON/Markdown) + main().

## HẠNG MỤC (đánh dấu khi xong)
### A. PWN source — mở rộng pattern (ƯU TIÊN 1)
- [ ] Thêm rule: strcpy/strcat/sprintf/vsprintf/gets/scanf("%s")/`%[`/alloca/VLA/memcpy-user-len/
      realloc-size/calloc-overflow/snprintf-retval/fscanf/getwd/realpath/strncpy-no-null/
      off-by-one loop `<=`/`a[i]` không biên/format `printf(user)`/`syslog(user)`/`system(user)`/
      `popen`/`execlp`/`setuid`-logic/`rand()` seed/`atoi`-neg/double-free/UAF(free rồi dùng).
- [ ] Mỗi rule: location, CWE, tier, fix cụ thể (đổi thành gì), technique list.

### B. BINARY analysis mode (ƯU TIÊN 1 — tính năng cờ)
- [ ] `BinaryAnalyzer` dùng radare2 (r2pipe có trong venv pwn) + fallback objdump/pwntools.
- [ ] Liệt kê imports nguy hiểm (gets/system/strcpy/printf-fmt/...) + call-site theo OFFSET + hàm chứa.
- [ ] Phát hiện win()/backdoor (hàm gọi system/execve/ chứa "/bin/sh"/"cat flag") → ret2win.
- [ ] Phát hiện /bin/sh string, format-string (printf reg fmt), vuln theo offset.
- [ ] Mã giả: r2 `pdc` (pseudo-C) hoặc `pdg` (r2ghidra nếu có) cho hàm liên quan.
- [ ] Trả Finding với location = "offset (hàm)" thay cho dòng.

### C. ExploitPlanner (ƯU TIÊN 1)
- [ ] Tổng hợp findings + checksec → KỊCH BẢN exploit có thứ tự (ret2win→ret2libc→ret2syscall→
      stack pivot→shellcode(ret2shellcode nếu RWX/NX off)→ROP→fmt arbitrary write→heap house).
- [ ] Giải thích vì sao chọn (dựa NX/PIE/RELRO/Canary + có win/system/gets...).

### D. Exploit script generator (pwnld) (ƯU TIÊN 2)
- [ ] Sinh skeleton theo pwnld.py: ret2win / ret2libc / fmtstr / ret2shellcode / rop template.
- [ ] Nếu không sinh full → in payload quan trọng (offset, pop_rdi, flat(...)).

### E. REV (ƯU TIÊN 3) → F. CRYPTO (4) → G. WEB (5): mở rộng pattern + binary (anti-debug, xor loop, strcmp flag, RC4, ECB, nonce reuse, small-e RSA, SQLi, cmdi, SSTI, deserialize, path traversal, ...).

### H. Hoàn thiện: fix bug @staticmethod đúp; CLI `--asm`/`--decompile`/`--exploit`/`--plan`; test với test_vuln1.c, test_vuln2(.c/ELF).

## TIẾN ĐỘ (cập nhật mỗi lần)
- ✅ ĐÃ XONG (pass 1):
  - B. BinaryAnalyzer (r2): imports nguy hiểm + call-site theo OFFSET + win-func + /bin/sh + has_fmt/overflow. TEST OK trên test_vuln2 (8 findings offset).
  - Mã giả: `.pseudocode()` dùng `pdc` (không cần r2ghidra). `--decompile`/`--asm`. TEST OK.
  - C. ExploitPlanner: kịch bản theo checksec+findings (ret2win/ret2shellcode/ret2libc/ROP/stack pivot/SROP/fmt/heap). TEST OK (test_vuln2 → ret2shellcode+fmt).
  - D. Script gen pwnld: `_script()` + `--exploit OUT`. TEST OK.
  - main(): nhận ELF target trực tiếp (bỏ source-scan ELF), merge binary+source findings, auto-detect sibling binary. Fix bug @staticmethod đúp.
  - A. +12 rule pwn source: system/popen-exec/vsprintf/fprintf-syslog-fmt/memcpy-len/alloca/VLA/off-by-one<=/alloc-int-overflow/strncpy-no-null/free-UAF-double-free. TEST OK.
  - CLI: --decompile/--asm, --exploit[OUT], --no-plan. json/md/gcc vẫn chạy.
- ✅ ĐÃ XONG (pass 2):
  - E. REV +6 rule: fork/LD_PRELOAD, SIGTRAP/alarm, XOR encode/decode (^=), strcmp/memcmp so flag (+gợi ý angr find/avoid & patch jcc), srand(time/getpid) seed, bảng mã tuỳ biến base64/sub. TEST OK (rev.c → ANTI/CMP/SEED/XOR).
  - F. CRYPTO +7 rule: RSA e nhỏ (cube/Håstad), getPrime nhỏ (factordb/Fermat), nonce/IV reuse (two-time pad), key hardcode, MT19937 (randcrack), single-byte XOR (range 256), padding oracle. TEST OK (crypto.py → 7).
  - G. WEB +7 rule: os.system/popen(user), eval/exec(user), render_template_string SSTI, open(user) traversal, yaml.load, XXE (etree/lxml/XMLParser), flask debug=True. TEST OK (web.py → 8).
  - ScenarioCorrelator: xử lý PWN-BIN-*/PWN-CMD/PWN-INT (hết generic; binary = 0 dòng generic).
  - Doc vulncheck.md → v3.0 (section 1b binary+exploit, CLI flags --decompile/--exploit/--no-plan). Banner code → v3.0.
  - TEST TỔNG: mọi target (ELF/.c/.py) × mọi format (term/gcc/json/md) = 0 lỗi. JSON hợp lệ.
- ✅ ĐÃ XONG (pass 3 — mở rộng sâu):
  - F. CRYPTO +5 rule: repeating-key XOR, timing-unsafe MAC compare (==), AES-CBC malleable, length-extension (MD5/SHA1 MAC). (CRYPTO-XOR-002/TIMING-001/CBC-001/LENEXT-001).
  - G. WEB +10 rule mới: XSS reflected PHP (echo $_GET), XSS Flask Markup(), JWT verify=False/alg none (WEB-JWT-001), JWT thiếu algorithms → alg confusion (WEB-JWT-002), NoSQL injection (Mongo $ne/$gt), open redirect, file upload không secure_filename, PHP type juggling magic hash `==` (WEB-TYPEJUGGLE-001/002), SSRF PHP cURL, path traversal send_file, CORS `*`. TEST OK (vulnweb.py+.php → 10 rule fire, không trùng lặp).
- HOÀN TẤT E/F/G (pass 2) + mở rộng crypto/web (pass 3). CÒN (tuỳ chọn): REV binary analysis (hàm check flag + gợi ý angr find/avoid).
- (lưu trữ) CÒN LẠI (pass kế):
  - E. REV: rule source (anti-debug ptrace/IsDebuggerPresent, xor/sub decrypt loop, strcmp/memcmp flag, time()-seed, custom base64 table, ptrace self-debug) + binary (hàm check flag, chuỗi "Correct/Wrong", vòng xor) + gợi ý angr (find/avoid theo chuỗi).
  - F. CRYPTO: RSA e nhỏ/n chung/Wiener, AES-ECB, nonce/IV reuse, PRNG yếu (random/mt19937), key hardcode, MD5/SHA1, padding oracle, XOR single-byte.
  - G. WEB: SQLi (concat query), cmdi (os.system/subprocess shell=True), SSTI (render_template_string), path traversal (open(user)), pickle/yaml.load, XXE, SSRF (requests(user_url)), eval/exec.
  - Cải thiện ScenarioCorrelator cho PWN-BIN-* (hiện generic). Cập nhật vulncheck.md. Test lại toàn bộ.

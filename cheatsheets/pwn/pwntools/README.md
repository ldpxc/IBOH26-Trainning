# pwntools — sổ tay tiện ích viết exploit

Tập hợp các hàm/lớp pwntools **thay thế việc làm tay** khi viết exploit: đóng gói dữ liệu,
IO với tiến trình/remote, đọc ELF/libc, dựng ROP/SROP, format string, shellcode, context.

> Verify trên **pwntools 4.15** (một số chữ ký khác bản cũ — đã ghi chú tại chỗ).
> Mỗi mục theo khuôn: **công dụng → dạng bài → tham số → ví dụ (mọi case + mọi tham số) → bản làm tay để so sánh**.

## Các trang

| Trang | Nội dung |
|-------|----------|
| [packing.md](packing.md) | `p64/u64`, `flat/fit`, `cyclic/cyclic_find`, `hexdump`, `xor`, `pack/unpack`, `bits`, `b64e` |
| [tubes.md](tubes.md) | `process/remote/ssh/listen`, họ `send*/recv*`, `clean`, `interactive`, timeout |
| [elf.md](elf.md) | `ELF()`, `sym/got/plt/address`, `.search/.read`, `checksec`, `libc`, `Core()` |
| [rop.md](rop.md) | `ROP()`, `call/setregs/find_gadget/chain/dump/migrate`, **SROP** `SigreturnFrame`, **ret2dlresolve** |
| [fmt.md](fmt.md) | `fmtstr_payload`, `FmtStr`, `fmtstr_split` (+ trỏ sang [`pwnld` fmtstr_pos](../../../tools/pwnld.md#5-ghi-bằng-format-string-fmt)) |
| [shellcode.md](shellcode.md) | `shellcraft.*`, `asm/disasm`, `constants`, `make_elf` |
| [context.md](context.md) | `context(...)`, `gdb.debug/attach`, `log`, `pause/align/more` |

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
| **Debug tại chỗ** | `gdb.debug/gdb.attach` ([context](context.md)) |
| **Core dump leak thanh ghi** | `Core()` ([elf](elf.md#core--đọc-core-dump)) |

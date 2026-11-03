# setcontext / magic gadget — biến "1 con trỏ hàm" thành "điều khiển TẤT CẢ thanh ghi"

> **Bài giảng tự chứa.** Đọc hết là hiểu: `setcontext` là gì, vì sao nó là "SROP của heap", nó
> **nạp từng thanh ghi từ offset nào** trong một buffer ta kiểm soát, **khác biệt rdi↔rdx giữa các
> bản glibc**, cái **"magic gadget"** `mov rdx,[rdi+8]` dùng để làm gì, cách **tìm gadget + offset
> trong GDB**, và **khi nào áp dụng**. Đây là mắt xích thiếu của hầu hết heap→shell hiện đại
> (glibc 2.34+ không còn hook). Nền: [hook_overwrite.md](hook_overwrite.md), [fsop.md](fsop.md),
> [exit_handlers.md](exit_handlers.md).

---

## 0. Vấn đề: ta chỉ chiếm được MỘT con trỏ, mà cần NHIỀU thanh ghi

Khi khai thác heap/FSOP, primitive cuối thường là: *"ép chương trình gọi một con trỏ hàm `f(arg)`
với `arg` ta kiểm soát"* — ví dụ `__free_hook(ptr)`, `fp->vtable->__overflow(fp)`. Nhưng để ra
shell qua **`execve("/bin/sh",0,0)`** hay **`mprotect(page, len, 7)` rồi nhảy shellcode** (khi
seccomp cấm execve → ORW), ta cần set **nhiều thanh ghi cùng lúc** (`rdi, rsi, rdx, rsp, rip`). Một
lời gọi `f(arg)` chỉ cho ta **một tham số**.

**`setcontext`** giải đúng bài này. Nó là hàm libc dùng để **khôi phục toàn bộ CPU context** (giống
`sigreturn` của SROP, xem [srop.md](srop.md)) — nạp `rsp, rip, rdi, rsi, rdx, rbx, rbp, r8..r15...`
**từ một vùng nhớ**. Nếu ta cho con trỏ hàm bị hijack **trỏ vào giữa `setcontext`** và cho nó đọc
**buffer ta dựng**, ta set được **cả dàn thanh ghi** → pivot sang ROP/`mprotect`/`execve` tuỳ ý.

> **Nói ngắn:** *setcontext = SROP không cần syscall. Hijack control → nhảy vào `setcontext+<off>` →
> nó nạp mọi thanh ghi từ buffer ta kiểm soát → ta nhảy đi đâu/làm gì cũng được.*

---

## 1. setcontext nạp thanh ghi từ đâu (bố cục buffer)

`setcontext(ucp)` đọc struct `ucontext_t` mà `ucp` trỏ tới; phần `uc_mcontext.gregs` chứa giá trị
các thanh ghi. Khi dùng làm gadget, ta thường **nhảy vào giữa hàm** (bỏ phần đầu xử lý signal mask)
tới đoạn nạp thanh ghi. Offset các field trong buffer (x86-64, cố định qua nhiều bản):

| Offset trong buffer | Thanh ghi được nạp |
|--------------------:|--------------------|
| `+0x68` | `rdi` |
| `+0x70` | `rsi` |
| `+0x80` | `rbx` |
| `+0x88` | `rdx` |
| `+0x98` | `rcx` |
| **`+0xa0`** | **`rsp`** |
| **`+0xa8`** | **`rip`** (nạp vào `rcx` rồi `push rcx; ret`) |
| `+0x78`,`+0x48..0x60` | `rbp`, `r12..r15` |

Hai field quan trọng nhất: **`rsp = [buf+0xa0]`** và **`rip = [buf+0xa8]`**. Set hai cái này =
**pivot sang một stack/ROP-chain mới** (đặt tại `rsp`, bắt đầu chạy tại `rip`). Đặt thêm
`rdi/rsi/rdx` để gọi thẳng `mprotect`/`execve`.

> ⚠️ **Một ô GOT trong libc phải bằng 0**: đoạn đầu gadget có `ldmxcsr [buf+0xe0]`-kiểu thao tác /
> hoặc một ô dùng làm toán hạng — thực tế đặt vùng buffer `0` ở các offset chưa dùng cho an toàn.

---

## 2. ⚠️ Khác biệt theo glibc: rdi (cũ) → rdx (2.29+)

Đây là chỗ **dễ sai nhất**, phải xác định bản libc:

| glibc | setcontext đọc buffer qua thanh ghi nào | Hệ quả |
|-------|------------------------------------------|--------|
| **< 2.29** | **`rdi`** (buffer = `rdi`) | hijack cho `rdi = &buffer` là xong (vd `__free_hook(ptr)` → `ptr=&buffer`) |
| **≥ 2.29** | **`rdx`** (buffer = `rdx`) | hijack chỉ cho `rdi`/`fp` → cần **magic gadget** bắc cầu `rdi → rdx` (§3) |

Vì `__free_hook(ptr)` gọi với `ptr` nằm ở **`rdi`**, trên glibc cũ ta trỏ `rdi` thẳng vào buffer →
dùng `setcontext+53`. Trên glibc mới setcontext đọc `rdx` mà ta lại chỉ control `rdi` → phải chuyển
`rdi` thành `rdx` trước.

---

## 3. "Magic gadget" — bắc cầu `rdi → rdx` (glibc 2.29+)

Gadget kinh điển (có sẵn trong libc, pwntools/one_gadget giúp tìm):
```asm
mov rdx, [rdi+8]        ; rdx <- [rdi+8]  (ta đặt [rdi+8] = &buffer)
mov [rsp], rax          ; (phụ)
call [rdx+0x20]         ; nhảy tới [buffer+0x20]  -> đặt = setcontext (phần đọc rdx)
```
Luồng: hijack → nhảy **magic gadget** với `rdi = &fake` → nó lấy `rdx = [rdi+8]` (ta set trỏ về
buffer) → `call [rdx+0x20]` = `setcontext` (phần nạp từ rdx) → setcontext nạp mọi thanh ghi từ
buffer. **Đây chính là chuỗi mà house of apple2** ([fsop.md §6](fsop.md)) dùng:
`_IO_wfile_jumps → ... → call qua _wide_data` trỏ vào gadget này.

Nói cách khác: trên glibc mới, "setcontext" thực chiến = **magic gadget + setcontext(rdx)** ghép lại.

---

## 4. Tìm gadget + offset trong GDB / pwntools (kỹ năng cốt lõi)

**a) Địa chỉ `setcontext` và điểm nhảy:**
```gdb
p/x &setcontext
disass setcontext           # tìm đoạn: mov rsp,[rXX+0xa0]; ... đó là điểm nhảy
```
Trong pwntools: `libc.sym.setcontext`. Điểm nhảy thường là `setcontext+53` (rdi, cũ) hoặc một offset
đọc `rdx` (mới) — **đọc disass để chốt**, vì offset đổi theo bản.

**b) Tìm magic gadget trong libc:**
```python
# pwntools: tìm chuỗi 'mov rdx,[rdi+8] ; ... ; call [rdx+0x20]'
gadget = next(libc.search(asm("mov rdx,[rdi+8]"), executable=True))
# hoặc dùng ROPgadget/one_gadget:
```
```bash
ROPgadget --binary libc.so.6 | grep -E "mov rdx, qword ptr \[rdi \+ 8\].*call"
```

**c) Kiểm buffer nạp đúng chưa:** đặt breakpoint tại điểm nhảy setcontext, rồi single-step xem
`rsp`/`rip` lấy từ `[buf+0xa0]`/`[buf+0xa8]`:
```gdb
b *setcontext+53
x/40gx $rdi            # (hoặc $rdx) soi buffer; đối chiếu offset bảng §1
```

---

## 5. Nhận diện: khi nào dùng setcontext?

| Dấu hiệu | Kết luận |
|---------|----------|
| Đã hijack được **1 con trỏ hàm** (hook/FSOP/vtable) nhưng cần **nhiều thanh ghi** | ✅ setcontext |
| Cần **`mprotect` rồi shellcode** hoặc **`execve`** (không chỉ `system`) | ✅ setcontext (set rdi/rsi/rdx) |
| **seccomp cấm execve** → cần ORW bằng ROP | ✅ setcontext pivot sang ROP-chain ORW ([seccomp_orw.md](seccomp_orw.md)) |
| glibc **≥ 2.29** | ⚠️ cần **magic gadget** `rdi→rdx` (§3) |
| Chỉ cần `system("/bin/sh")` + đã control `rdi` | ❌ khỏi cần setcontext — gọi `system` thẳng cho gọn |

**Phản xạ:** *"đã có control flow + cần hơn một tham số / cần pivot ROP"* → setcontext. Nó là bước
**nối** giữa "chiếm 1 con trỏ" và "chạy ROP-chain tuỳ ý", đặc biệt sống còn với **2.34+** (không
hook) và **seccomp** (phải ORW).

---

## 6. Luồng khai thác tiêu biểu (glibc 2.31+, seccomp → ORW)

1. **Có:** leak libc + một primitive ghi (tcache/largebin/FSOP) + chỗ trigger.
2. **Dựng buffer** (trên heap ta control) theo bố cục §1: `rsp = &ROP_chain`, `rip = &(ret gadget)`,
   hoặc set thẳng `rdi/rsi/rdx` cho `mprotect`.
3. **Ghi con trỏ hijack:** `__free_hook = magic_gadget` (2.31) hoặc FSOP `_wide_data→vtable` trỏ
   magic gadget (2.34+); đặt `[rdi+8] = &buffer`, `[buffer+0x20] = setcontext(+off)`.
4. **Trigger** (`free`/`exit`/flush) → magic gadget → setcontext → **nạp mọi thanh ghi** → pivot
   sang **ROP-chain ORW** (`open/read/write`) hoặc `mprotect`+shellcode.
5. **Kết quả:** đọc flag (ORW) hoặc shell.

---

## 7. Writeup rút gọn (tham khảo)
- **glibc 2.31 + `__free_hook`:** `__free_hook = magic_gadget`; `free(&fake)` với `fake[8]=&buffer`
  → setcontext(rdx) → ROP ORW. (lkmidas *heap-seccomp-rop* là bản mẫu rõ.)
- **glibc 2.34+ (không hook):** ghép [house of apple2](fsop.md) → `_wide_data` trỏ magic gadget →
  setcontext. Rất nhạy libc → verify offset bằng GDB (§4).

---

## 8. Bài tập + lộ trình

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| lkmidas — *Heap + Seccomp + ROP (2.31)* | ⭐⭐⭐ | `__free_hook`→magic gadget→setcontext→ORW |
| house of apple2 (ghép) | ⭐⭐⭐⭐ | setcontext qua FSOP 2.34+ |
| pwn.college sandbox/ORW level | ⭐⭐⭐ | setcontext để dựng ORW khi cấm execve |

**Lộ trình:** hiểu bố cục buffer (§1) → rdi/rdx theo version (§2) → magic gadget (§3) → tìm gadget
trong GDB (§4) → ghép với [hook_overwrite.md](hook_overwrite.md) (2.31) rồi [fsop.md](fsop.md) (2.34+).

---

## Nguồn tham khảo
- lkmidas — *Glibc 2.31 Heap + Seccomp Exploitation using ROP*: <https://lkmidas.github.io/posts/20210103-heap-seccomp-rop/>
- 4xura — *ORW: Pwn A Sandbox Using Magic Gadgets*: <https://4xura.com/binex/orw-open-read-write-pwn-a-sandbox-using-magic-gadgets/>
- Liên quan: [srop.md](srop.md) (ý tưởng "nạp mọi thanh ghi") · [fsop.md](fsop.md) · [hook_overwrite.md](hook_overwrite.md) · [seccomp_orw.md](seccomp_orw.md)

# Leak taxonomy — rò địa chỉ để đánh bại ASLR/PIE (libc · PIE · stack · heap · canary)

> **Bài giảng tự chứa.** Đọc hết là hiểu: vì sao gần như mọi bài phải **leak** trước, bốn loại địa
> chỉ cần leak (**libc / PIE / stack / heap**) + **canary**, mỗi loại **lấy từ nguồn nào**, công
> thức **rebase** (suy base từ 1 giá trị), và **mẹo đo offset trong GDB**. Đây là kỹ năng **xuyên
> suốt** mọi tier — không phải một kỹ thuật riêng mà là bước chung. Chi tiết từng hướng nằm ở các
> bài liên quan (trỏ link).

---

## 0. Vì sao phải leak: ASLR/PIE random địa chỉ

**ASLR** random địa chỉ **libc, stack, heap, mmap** mỗi lần chạy. **PIE** random cả **base của
binary**. Nên ta **không biết trước** `system` ở đâu, `win` ở đâu, buffer ở đâu. Nhưng ASLR chỉ
random **base** (địa chỉ trang đầu); **offset bên trong một ảnh là cố định**. Vậy chỉ cần **lộ một
địa chỉ thật** thuộc ảnh đó là suy ra **toàn bộ** ảnh:

```
base = leak - offset_của_cái_vừa_leak_trong_ảnh
→ mọi địa chỉ khác = base + offset_của_nó
```
Đây gọi là **rebase**. pwntools làm tự động khi bạn gán `libc.address = base` / `exe.address = base`
→ sau đó `libc.sym.system`, `exe.got.puts` tự đúng.

> **Nói ngắn:** *leak 1 địa chỉ thật của một ảnh → trừ offset đã biết → ra base → cộng offset khác
> → ra mọi địa chỉ trong ảnh đó. Bốn ảnh (libc/PIE/stack/heap) random ĐỘC LẬP → cần leak riêng.*

---

## 1. Bốn loại địa chỉ + nguồn lấy

| Leak cái gì | Để làm gì | Nguồn lấy phổ biến |
|-------------|-----------|--------------------|
| **libc base** | gọi `system`/`one_gadget`, tìm `/bin/sh`, `__free_hook`, setcontext | in **GOT** (`puts@got`), **unsorted-bin fd** (`main_arena`), symbol `environ` |
| **PIE base** (binary) | dùng `win`/gadget/`.fini_array`/GOT của binary khi PIE | leak **return address** trên stack, **partial overwrite**, con trỏ hàm rò |
| **stack address** | pivot, ghi ROP lên stack, biết vị trí buffer | symbol libc **`environ`**, format string `%p`, con trỏ stack rò |
| **heap base** | safe-linking (2.32+), tcache poisoning, địa chỉ chunk | in con trỏ heap (UAF read), leak chunk `fd` |
| **canary** | ghi lại đúng để vượt stack-protector | format string `%N$p`, đè byte `\0` (xem [canary.md](canary.md)) |

**Điểm mấu chốt:** 4 ảnh random **độc lập** — leak libc **không** cho bạn stack, leak PIE **không**
cho heap. Bài khó thường phải leak **2–3 loại** riêng.

---

## 2. Leak libc — ba đường chính

**a) In một ô GOT** (cần hàm in: `puts`/`printf`/`write`):
```python
rop.call("puts", [exe.got.puts]); rop.call(exe.sym.main)   # in địa chỉ libc của puts, rồi quay lại
libc.address = leak - libc.sym.puts                         # rebase
```
Chi tiết: [ret2libc.md §2](ret2libc.md).

**b) Unsorted-bin fd** (bài heap, không có hàm in sẵn): free một chunk đủ lớn (> tcache) → `fd`/`bk`
của nó trỏ `main_arena` trong libc → đọc (UAF/overflow). Chi tiết: [heap.md §4](heap.md).

**c) Qua `environ`** (khi đã có libc nhưng cần... thực ra `environ` để leak **stack** — xem §4).

## 3. Leak PIE base

- **Leak return address / saved rip trên stack** (format string `%p`, hoặc in buffer tràn): một
  địa chỉ trả về trỏ vào `.text` của binary → `exe.address = leak - offset_biết`.
- **Partial overwrite** (không leak, ghi 1–2 byte thấp): xem [partial_overwrite.md](partial_overwrite.md).
- Con trỏ hàm/`__libc_csu`/vtable của binary rò trên stack cũng dùng được.

**Cách đo offset:** trong GDB lúc dừng, `p/x $addr_leak - exe.address` (pwndbg hiện `exe.address`
qua `vmmap`) → ra offset cố định, hardcode.

## 4. Leak stack address — mẹo `environ` (kỹ thuật hay thiếu)

Khi **đã có libc base** mà cần một **địa chỉ stack** (để pivot, để biết buffer/saved-rip ở đâu):
libc xuất symbol **`environ`** — một biến **chứa con trỏ tới mảng biến môi trường, vốn nằm trên
stack**. Đọc `environ` = **lấy một địa chỉ stack thật**:
```python
rop.call("puts", [libc.sym.environ]); rop.call(exe.sym.main)   # in [environ] = 1 địa chỉ stack
stack_leak = u64(p.recvline().strip().ljust(8, b"\x00"))
ret_addr   = stack_leak - OFFSET     # OFFSET = khoảng cách từ environ-stack tới ô ta cần (đo GDB 1 lần)
```
Đây là cách **chuẩn** để có stack address khi chỉ bị format-string/ROP mà không rò stack trực tiếp.
Đo `OFFSET`:
```gdb
p/x *(void**)&environ        # giá trị environ (1 địa chỉ stack cao)
p/x &<ô_bạn_cần>             # vd &saved_rip của frame đích
# OFFSET = environ_value - địa_chỉ_ô_cần   (hằng số trong cùng lần chạy)
```
Format string cũng leak stack trực tiếp bằng `%p` (xem [fmtstr.md](fmtstr.md)) — dùng khi chưa có libc.

## 5. Leak heap base

- **UAF read** một con trỏ heap (vd `fd` của chunk tcache đã free, hoặc con trỏ struct) → ra địa
  chỉ heap → suy heap base (`& ~0xfff` nhiều lần / trừ offset chunk đầu).
- Cần cho **safe-linking (2.32+)**: phải biết `pos` (địa chỉ chunk) mới `mangle(fd)`. Xem
  [heap_advanced.md §1](heap_advanced.md).

## 6. Rebase bằng pwntools (gọn)
```python
libc.address = leak_libc  - libc.sym.puts        # giờ libc.sym.system/… tự đúng
exe.address  = leak_pie   - 0x1234               # giờ exe.sym.win/got/… tự đúng
# stack/heap KHÔNG phải ELF -> tự lưu biến, cộng offset tay (xem pwnld leak_stack_p)
```
Lưu ý thực chiến: **luôn `assert base & 0xfff == 0`** sau rebase — base phải page-aligned; lệch =
leak sai (đọc nhầm byte, dính `\n`), bắt lỗi ngay thay vì để chain chạy loạn.

---

## 7. Nhận diện: thiếu địa chỉ gì → leak đường nào?

| Bạn cần | Random độc lập? | Leak đường |
|---------|-----------------|-----------|
| `system`/`one_gadget`/`__free_hook` | libc | GOT / unsorted fd |
| `win`/gadget binary khi **PIE** | PIE base | return addr / partial |
| pivot / vị trí buffer / saved-rip | stack | **`environ`** / `%p` |
| safe-linking / poison fd | heap | UAF read con trỏ heap |
| vượt canary | (canary riêng) | `%N$p` / đè `\0` |

**Phản xạ:** trước khi viết payload, liệt kê **mình cần địa chỉ thuộc ảnh nào**, rồi chọn nguồn
leak tương ứng. Bài cho **1 lần in** → ưu tiên leak cái mở được nhiều nhất (thường **libc**). Không
có đường in nào → [ret2dlresolve](ret2dlresolve.md)/[SROP](srop.md) (khỏi leak).

---

## Nguồn tham khảo
- ir0nstone — *ASLR / leaking*: <https://ir0nstone.gitbook.io/notes/binexp/stack/aslr>
- Liên quan: [ret2libc.md](ret2libc.md) (GOT leak) · [heap.md](heap.md) (unsorted/heap leak) · [fmtstr.md](fmtstr.md) (`%p`) · [canary.md](canary.md) · [partial_overwrite.md](partial_overwrite.md) · [stack_pivot.md](stack_pivot.md)

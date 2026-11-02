# Exit handlers & largebin→write (T10) — hijack khi không còn hook

> Tài liệu học sâu. Bổ sung cho [hook_overwrite.md](hook_overwrite.md) (phần `__free_hook` cổ).
> Đây là **đường thay thế hook cho glibc ≥ 2.34**. Công thức PTR_MANGLE là chuẩn glibc (x86-64).

---

## 1. Vì sao exit handlers?

Từ **glibc 2.34** bỏ `__free_hook`/`__malloc_hook`. Nhưng **mọi chương trình đều gọi `exit()`**
(hoặc `main` return → `exit`). `exit` chạy danh sách các hàm đã đăng ký qua `atexit`/destructor →
nếu **ghi đè được một con trỏ trong danh sách đó**, ta chiếm control flow khi chương trình kết thúc.

---

## 2. `__exit_funcs` & PTR_MANGLE

`atexit(f)` lưu `f` vào struct `exit_function` trong danh sách `__exit_funcs` (initial block là
`initial` trong libc). Khi `exit` → `__run_exit_handlers` duyệt và gọi từng hàm.

**Chốt chặn:** con trỏ hàm trong đó **bị mã hoá PTR_MANGLE** (pointer guard):
```
mangled = ROL( ptr XOR guard, 0x11 )        # guard = fs:0x30 (pointer_guard của TLS)
ptr     = ROR( mangled, 0x11 ) XOR guard     # demangle
```
```python
def mangle(ptr, guard): return rol((ptr ^ guard) & (2**64-1), 0x11, 64)
```
→ Muốn ghi một hàm giả (vd `system`) vào entry: cần **leak `guard` (fs:0x30)** rồi ghi
`mangle(system, guard)`. Không leak được guard → không forge trực tiếp entry.

**Hai hướng tấn công:**
1. **Ghi đè entry hiện có** (cần leak guard): sửa `fn_ptr = mangle(&win/system, guard)` và `arg`.
2. **Ghi đè con trỏ `__exit_funcs`** trỏ tới **struct giả ta dựng** (trong vùng ta control): đặt
   `type = 4` (cxa), `fn = mangle(target, guard)`… — vẫn cần guard. Một số bài để lộ guard = 0
   (TLS không set) → khỏi mangle.

Tham khảo rõ nhất: **HackTricks — www2exec (atexit)** (giải thích `__exit_funcs` + `tls_dtor_list`
+ bypass pointer-guard).

---

## 3. `tls_dtor_list` (`__call_tls_dtors`)

Danh sách destructor TLS, cũng gọi khi thoát; con trỏ `func` cũng **PTR_MANGLE**. Dựng một
`dtor_list` giả + ghi `__call_tls_dtors` gọi nó → tương tự. Dùng khi tới được `__cxa_thread_atexit`.

---

## 4. largebin attack → ghi target cho exit/FSOP

[heap_intermediate.md §5](heap_intermediate.md#5-large-bin-attack--large_bin_attackc) cho primitive
**ghi một con trỏ heap vào 1 địa chỉ tuỳ ý**. Kết hợp:
- ghi `&fake_struct (heap)` vào **`__exit_funcs`** hoặc **`_IO_list_all`** (FSOP) → khi `exit`
  duyệt, nó dùng struct giả của ta.
- largebin chỉ ghi được **giá trị là heap-ptr** → đặt sẵn struct giả tại heap đó.

Đây là mắt xích hay gặp ở heap note hiện đại: **tcache/largebin → ghi `_IO_list_all`/`__exit_funcs`
→ FSOP/exit-handler → shell** (không đụng hook).

---

## 5. Mức verify (trung thực)

- Công thức **PTR_MANGLE** là chuẩn glibc x86-64 (ROL 0x11 XOR `fs:0x30`) — dùng để forge khi có
  guard leak.
- **Full exit-handler→shell** cần binary đích + leak guard → luyện trên bài CTF cụ thể (HackTricks
  www2exec có PoC). Phần `__free_hook` (glibc cũ) đã **verify ra shell** ở
  [hook_overwrite.md §5](hook_overwrite.md#5-writeup-bài-hook_overwrite-libc-223-verify-ra-shell).

---

## 6. Danh sách bài tập + gợi ý

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| **`advance/Hook_Overwrite`** (2.23) | ⭐⭐ | `__free_hook` (local) — [hook_overwrite.md](hook_overwrite.md) |
| **HackTricks www2exec (atexit)** | ⭐⭐⭐ | `__exit_funcs`/`tls_dtor_list` + bypass pointer-guard |
| **largebin → `__exit_funcs`/`_IO`** | ⭐⭐⭐⭐ | ghép [heap_intermediate.md](heap_intermediate.md) + [fsop.md](fsop.md) |

**Lộ trình:** `__free_hook` 2.23 (verify) → hiểu PTR_MANGLE → exit-handler/tls_dtor (2.34+) →
largebin→`__exit_funcs`/`_IO_list_all` → FSOP apple2.

---

## Nguồn tham khảo

- HackTricks — *www2exec (atexit)*:
  <https://book.hacktricks.xyz/binary-exploitation/arbitrary-write-2-exec/www2exec-atexit>
- glibc `stdlib/exit.c`, `__run_exit_handlers`; PTR_MANGLE trong `sysdeps/x86_64`.
- Nền: [hook_overwrite.md](hook_overwrite.md), [heap_intermediate.md](heap_intermediate.md), [fsop.md](fsop.md)

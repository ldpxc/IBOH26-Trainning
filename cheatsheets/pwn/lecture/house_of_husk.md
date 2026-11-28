# House of Husk — hijack qua bảng xử lý `printf` (`__printf_arginfo_table`)

> **Bài giảng tự chứa.** Đọc hết là hiểu: glibc cho phép đăng ký "custom format specifier" cho
> `printf` như thế nào, hai bảng `__printf_function_table`/`__printf_arginfo_table` làm gì, vì sao
> ghi đè chúng khiến **một lời `printf` bất kỳ gọi con trỏ của ta**, **cách tìm/ghi chúng**, và
> **khi nào dùng** (đường hijack khi hook + FSOP bị khoá). Nền: [heap_advanced.md](heap_advanced.md)
> (largebin attack để ghi), [hook_overwrite.md](hook_overwrite.md), [fmtstr.md](fmtstr.md).

---

## 0. Bạn cần nắm trước: `printf` có "custom specifier"

Ít ai biết glibc cho phép **tự định nghĩa specifier mới** cho `printf` qua
`register_printf_function(spec, func, arginfo)`. Khi đăng ký, glibc lưu:
- **`__printf_function_table[spec]`** = hàm in cho specifier đó.
- **`__printf_arginfo_table[spec]`** = hàm mô tả tham số của specifier.

Bình thường cả hai bảng là **NULL** (không ai đăng ký) → `printf` đi đường thường. Nhưng trong
`vfprintf`/`printf_positional`, glibc kiểm: **nếu `__printf_function_table != NULL`** thì nó đi vào
**nhánh xử lý custom** — và với mỗi specifier gặp phải, nó **gọi `__printf_arginfo_table[spec](...)`**
rồi `__printf_function_table[spec](...)`. Hai bảng này nằm trong **libc, vùng ghi được**.

> **Nói ngắn:** *làm `__printf_function_table` khác NULL + trỏ một ô `__printf_arginfo_table[spec]`
> vào gadget/`system` → lần `printf` kế có specifier đó sẽ GỌI con trỏ của ta. Đây là FSOP phiên
> bản "printf" — không cần hook, không cần `exit`, chỉ cần chương trình còn gọi `printf`.*

---

## 1. Kỹ thuật tập trung vào cái gì

| Thành phần | Vai trò | Ở đâu |
|-----------|---------|-------|
| `__printf_function_table` | **cờ bật nhánh custom**: chỉ cần ≠ NULL | biến libc, ghi được |
| `__printf_arginfo_table` | mảng con trỏ; `[spec]` được **gọi** khi xử lý specifier | biến libc, ghi được |
| specifier `spec` | ký tự format (vd `%s`→`'s'`=0x73) quyết định index vào bảng | trong chuỗi `printf` |
| primitive ghi | để đặt 2 bảng | thường **largebin attack** ([heap_advanced.md](heap_advanced.md)) hoặc arbitrary write |

Chuỗi kích hoạt: `printf("...%s...")` → thấy `__printf_function_table != NULL` → vào
`printf_positional` → `__printf_arginfo_table['s'](...)` **được gọi** → nếu ô đó = `system` và tham
số dàn trúng `"/bin/sh"` → shell. (Thực tế thường trỏ vào một **gadget/one_gadget** vì kiểm soát
tham số của nhánh này hạn chế.)

---

## 2. Điều kiện

1. **Leak libc** (biết `&__printf_function_table`, `&__printf_arginfo_table`, `&system`/gadget).
2. **Primitive ghi vào libc**: thường **largebin attack** để ghi `__printf_function_table` (chỉ cần
   ≠ NULL, nên ghi heap-ptr cũng được) + ghi một ô `__printf_arginfo_table[spec] = target`. Hoặc
   arbitrary write.
3. **Chương trình gọi `printf`/`fprintf`** (có format specifier) **sau đó** — rất dễ thoả vì printf
   ở khắp nơi.

---

## 3. Tìm trong GDB
```gdb
p/x &__printf_function_table      # cờ: đặt ≠ NULL
p/x &__printf_arginfo_table       # mảng con trỏ hàm theo specifier
# index của specifier: ký tự ASCII, vd 's' = 0x73 -> ô &__printf_arginfo_table + 0x73*8
p/x &__printf_arginfo_table + 's'
```
Đặt breakpoint tại `printf_positional` (hoặc `vfprintf`) rồi xem nó rẽ nhánh custom khi bảng ≠ NULL,
và `call` ô arginfo nào.

---

## 4. Nhận diện: khi nào dùng House of Husk?

| Dấu hiệu | Kết luận |
|---------|----------|
| Có **largebin attack / arbitrary write vào libc** + leak libc | ✅ ứng viên |
| **Không còn hook** (2.34+) **và** FSOP bất tiện/bị chặn | ✅ Husk là đường thay thế |
| Chương trình **chắc chắn gọi `printf`** với specifier sau khi ghi | ✅ có trigger |
| glibc **quá mới** đã gỡ nhánh custom table | ❌ kiểm lại — kỹ thuật này thuộc nhóm **đã bị vá** ở bản rất mới |
| Không ghi được vào libc | ❌ |

**Phản xạ:** *có largebin/arbitrary-write + leak libc + chương trình dùng printf, mà hook/FSOP không
tiện* → thử House of Husk. Nó đặc biệt hợp khi bạn **đã có sẵn largebin attack** (ghi con trỏ vào
địa chỉ tuỳ ý) vì vừa hay dùng để bật `__printf_function_table`.

> **Lưu ý version:** House of Husk nằm trong nhóm kỹ thuật **đã bị vá ở glibc rất mới** (đường custom
> table bị siết). Luôn xác nhận trên đúng libc của đề (kiểm `__printf_function_table` còn được dùng
> trong `vfprintf` không).

---

## 5. Luồng khai thác (tổng quát)
1. Leak libc.
2. **largebin attack #1:** ghi `__printf_function_table = <giá trị ≠ 0>` (chỉ cần khác NULL).
3. **largebin attack #2 / arbitrary write:** ghi `__printf_arginfo_table[spec] = gadget/one_gadget`.
4. **Trigger:** chương trình `printf("...%<spec>...")` → gọi `__printf_arginfo_table[spec]` → gadget.
5. Shell (hoặc pivot setcontext — xem [setcontext.md](setcontext.md)).

---

## 6. Writeup rút gọn
Dùng khi bài cho **largebin attack** (hoặc arbitrary write libc) + còn `printf`. Thực tế thường kết
với **one_gadget** (ràng buộc) hoặc trỏ vào **magic gadget → setcontext** cho chắc. Rất nhạy libc →
verify từng offset trong GDB (§3). PoC chi tiết: Maxwell Dulin & 4xura (nguồn).

---

## 7. Bài tập + lộ trình

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| Maxwell Dulin — *House of Husk In-Depth* | ⭐⭐⭐⭐ | cơ chế bảng printf + PoC |
| CTF có largebin + printf (vd Lit CTF) | ⭐⭐⭐⭐ | áp dụng thực chiến |

**Lộ trình:** nắm [largebin attack](heap_advanced.md) + [leak libc](leak_techniques.md) trước → hiểu
2 bảng printf (§1) → ghép Husk → so sánh với [FSOP](fsop.md)/[exit handlers](exit_handlers.md) để
chọn đường phù hợp libc.

---

## Nguồn tham khảo
- Maxwell Dulin — *House of Husk In Depth*: <https://maxwelldulin.com/BlogPost/House-of-Husk-In-Depth-Explanation>
- 4xura — *House of Husk*: <https://4xura.com/binex/house-of-husk/>
- Liên quan: [heap_advanced.md](heap_advanced.md) (largebin) · [setcontext.md](setcontext.md) · [hook_overwrite.md](hook_overwrite.md) · [fmtstr.md](fmtstr.md)

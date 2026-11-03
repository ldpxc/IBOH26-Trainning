# OOB — truy cập ngoài biên mảng (out-of-bounds read/write) qua chỉ số

> **Bài giảng tự chứa.** Đọc hết là hiểu: truy cập mảng bằng chỉ số được tính địa chỉ thế nào, vì
> sao **chỉ số âm hoặc quá lớn** cho đọc/ghi ra vùng nhớ khác, cách biến OOB thành **leak** và
> **arbitrary write**, **cách đo offset chỉ số trong GDB**, và **nhìn challenge thế nào thì biết
> áp dụng**. Thường đi kèm [integer_bugs.md](integer_bugs.md) (chỉ số signed không kiểm `>=0`).

---

## 0. Bạn cần nắm trước: `arr[i]` thực chất là gì?

`arr[i]` trong C = **`*(arr + i * sizeof(phần_tử))`**. Trình biên dịch lấy **địa chỉ gốc của mảng**
cộng `i * cỡ_phần_tử`. **Không có kiểm tra biên** ở tầng ngôn ngữ — nếu `i` ngoài `[0, n)` thì nó
vẫn tính ra một địa chỉ và đọc/ghi ở đó, chỉ là địa chỉ **thuộc biến/cấu trúc khác**.

Hai chiều vượt biên:
- **`i` quá lớn** (≥ `n`): truy cập **sau mảng** → metadata, con trỏ, biến kế tiếp.
- **`i` âm** (`i < 0`): truy cập **trước mảng** → thường trúng **con trỏ/GOT/biến toàn cục** nằm
  dưới mảng trong `.bss`/`.data`.

> **Nói ngắn:** *mảng không kiểm biên + chỉ số do ta điều khiển = đọc/ghi một địa chỉ = base_mảng +
> i*cỡ. Chọn `i` (âm hoặc lớn) để trỏ tới GOT/con trỏ hàm/biến nhạy → leak hoặc ghi tuỳ ý.*

---

## 1. OOB cho ra primitive gì?

| Thao tác OOB | Cho ta |
|--------------|--------|
| **OOB read** `print(arr[i])` | **leak**: đọc GOT (→ libc), con trỏ stack/heap, PIE base |
| **OOB write** `arr[i] = v` | **arbitrary write** (trong tầm `i` cho phép): ghi GOT, con trỏ hàm, biến `is_admin`, saved RIP |
| **mảng con trỏ** `ptr_arr[i]` | nếu rồi **dereference** → đọc/ghi **qua con trỏ ngoài biên** = write-what-where mạnh hơn |

Mảng con trỏ (mảng các `char*`/struct*) là **ngon nhất**: `obj[i]->field = v` với `i` ngoài biên →
`obj[i]` là một địa chỉ ta chọn (nếu kiểm soát được vùng đó), biến thành **ghi tới địa chỉ tuỳ ý**.

---

## 2. Tính địa chỉ đích theo chỉ số (phần phải tự làm)

Muốn OOB trúng một biến đích ở địa chỉ `T`, với mảng gốc ở `A`, phần tử cỡ `s`:
```
i = (T - A) / s        # có thể ÂM nếu T nằm trước A
```
Ví dụ bài local: mảng con trỏ ở `.bss`, hàm `get_shell` và con trỏ GOT nằm **trước** mảng → dùng
**chỉ số âm** (`-5`, `-9`…) để trỏ tới chúng. Cách đo:
```gdb
p/x &arr                 # A = địa chỉ mảng
p/x &target_var          # T = biến đích (hoặc exe.got.xxx)
# i = (T - A) / cỡ_phần_tử     (nhớ chia đúng sizeof; con trỏ = 8)
```
Trong pwntools: `i = (exe.sym.target - exe.sym.arr)//8` (No PIE). PIE thì cộng base sau khi leak.

---

## 3. Tìm/đo trong GDB (kỹ năng cốt lõi)

```gdb
b *<chỗ truy cập arr[i]>
p/x &arr                     # địa chỉ gốc mảng
# nhập i thử, xem địa chỉ truy cập thực:
p/x &arr + i                 # (gdb tự nhân sizeof theo kiểu con trỏ)
x/gx &arr + i                # soi giá trị ở ô OOB đó
info address get_shell       # địa chỉ hàm muốn gọi (No PIE)
```
Xác nhận **chiều** (âm hay dương) bằng cách so `&arr` với `&biến_đích`: đích **nhỏ hơn** → index
âm; **lớn hơn** → index dương. Đây là bước quyết định dấu của `i`.

---

## 4. Luồng khai thác tiêu biểu (mẫu bài local)

Menu có: (1) chọn index, (4) in tên (OOB **read**), (3) nhập số vào ô (OOB **write**), (2) kích hoạt.
1. **Leak:** chọn index âm trỏ vào **GOT/con trỏ nhị phân** → đọc ra → rebase binary/libc.
   ```python
   slna('> ', 1); slna('Index: ', -5); slna('> ', 4)
   exe_leak, exe.address = leak_bin(0x35b0, 'Name: ')   # OOB read -> PIE base
   ```
2. **Write:** chọn index âm trỏ vào một **con trỏ hàm/ô điều khiển** → ghi địa chỉ `get_shell`.
   ```python
   slna('> ', 1); slna('Index: ', -9); slna('> ', 3)
   sla('Enter amount: ', str(exe.sym.get_shell).encode())   # OOB write
   ```
3. **Trigger:** gọi hành động dùng con trỏ vừa ghi → `get_shell()` → shell.

Điểm then chốt: **đo đúng index** cho từng đích (leak slot vs write slot thường khác nhau).

---

## 5. Nhận diện challenge: khi nào là OOB?

| Dấu hiệu | Kết luận |
|---------|----------|
| Menu "chọn index/slot" + **không kiểm `idx < 0`** (hoặc `idx >= n`) | ✅ OOB qua chỉ số |
| Index là `signed int` | ✅ thử **index âm** (ghép [integer_bugs.md](integer_bugs.md)) |
| Có mảng con trỏ (list object) + thao tác đọc/ghi theo index | ✅ OOB mạnh (write-what-where) |
| Đọc/ghi được một ô cạnh mảng (leak được libc/PIE) | ✅ dùng để leak trước |
| Có kiểm `0 <= idx < n` đầy đủ | ❌ không OOB qua index (tìm hướng khác) |

**Phản xạ:** thấy **thao tác theo index mà thiếu kiểm biên (nhất là thiếu `idx >= 0`)** → OOB. Đo
`(T-A)/s` để trỏ tới GOT (leak) rồi tới con trỏ hàm/`__free_hook`/saved-RIP (write) → shell.

---

## 6. Writeup rút gọn
Bài `advance/Out_of_Bounds_Bug`: mảng ở `.bss`, index **không kiểm âm** → index âm trỏ vào GOT để
**leak PIE/libc**, rồi index âm khác để **ghi `get_shell`** vào con trỏ bị gọi. Script mẫu §4. Video
có sẵn (xem roadmap).

---

## 7. Bài tập + lộ trình

| Bài | Mức | Học gì |
|-----|-----|--------|
| `advance/Out_of_Bounds_Bug` (mp4) | ⭐⭐⭐ | index âm → leak + OOB write → shell |
| bài heap có OOB index (vd tcache note) | ⭐⭐⭐ | OOB vào `fd` chunk — xem [heap.md §4](heap.md) |
| CTF "array/vector" không kiểm biên | ⭐⭐ | đo `(T-A)/s`, chọn dấu index |

**Lộ trình:** OOB read (leak GOT/PIE) → OOB write (con trỏ hàm/GOT) → mảng con trỏ (write-what-where)
→ ghép [integer_bugs.md](integer_bugs.md) khi index signed mở đường.

---

## Nguồn tham khảo
- CTF Wiki — *Array Index Out of Bounds*: <https://ctf-wiki.mahaloz.re/pwn/linux/>
- Liên quan: [integer_bugs.md](integer_bugs.md) (index âm/signed) · [ret2libc.md](ret2libc.md) · [heap.md](heap.md)

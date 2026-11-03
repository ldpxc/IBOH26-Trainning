# Exit hijack — chiếm điều khiển lúc chương trình THOÁT (`.fini_array` · `__exit_funcs` · tls_dtor)

> **Bài giảng tự chứa.** Đọc hết là hiểu: khi một chương trình kết thúc (`main` return hoặc gọi
> `exit`), glibc lần lượt gọi những **danh sách con trỏ hàm** nào, chúng **nằm ở vùng nhớ nào**,
> **tìm chúng trong GDB/readelf ra sao**, cái nào **ghi đè thẳng được** và cái nào **bị mã hoá
> PTR_MANGLE**, và **nhìn challenge thế nào thì biết dùng được hướng này**. Đây là đường thay thế
> khi `__malloc_hook`/`__free_hook` đã bị bỏ (glibc ≥ 2.34). Nền hook cũ: [hook_overwrite.md](hook_overwrite.md).

---

## 0. Bạn cần nắm trước: điều gì xảy ra khi chương trình THOÁT?

Khi `main` `return`, nó không nhảy thẳng ra kernel. Nó quay về `__libc_start_main`, hàm này gọi
`exit(ret)`. `exit()` (trong `stdlib/exit.c`) chạy **`__run_exit_handlers`**, thực hiện **theo thứ
tự**:

1. **Các handler đăng ký qua `atexit()`/`__cxa_atexit()`** — lưu trong danh sách **`__exit_funcs`**.
2. **Destructor TLS** — danh sách **`tls_dtor_list`** (gọi bởi `__call_tls_dtors`).
3. **Destructor của từng object (ELF)** — chạy **`.fini_array`** của binary và các thư viện
   (qua `_dl_fini` / `__libc_csu_fini`). Đây là nơi code toàn cục `__attribute__((destructor))`
   và dọn dẹp C++ được gọi.
4. Cuối cùng mới `_exit` (syscall) ra kernel.

**Ý tưởng khai thác chung:** nếu ta **ghi đè được một con trỏ** trong một trong các danh sách trên
thì tới lúc thoát, glibc sẽ **gọi địa chỉ ta chọn**. Hấp dẫn vì **mọi chương trình đều thoát** —
không cần hàm `win`, không cần `malloc/free` xảy ra, chỉ cần nó kết thúc.

> **Nói ngắn:** *thoát chương trình = glibc tự gọi một loạt con trỏ hàm. Sửa một con trỏ trong số
> đó (`.fini_array` thì ghi thẳng; `__exit_funcs`/`tls_dtor` thì bị mã hoá) → khi thoát, nó chạy
> code của ta.*

Hai nhóm rất khác nhau về độ khó, chia theo **có bị mã hoá không**:
- **`.fini_array`**: con trỏ **thô, KHÔNG mã hoá** → dễ nhất, chỉ cần arbitrary write + ghi được.
- **`__exit_funcs` / `tls_dtor_list`**: con trỏ **bị PTR_MANGLE** → cần leak "guard" (xem §3).

---

## 1. `.fini_array` — đường dễ nhất (ưu tiên học trước)

### 1.1. `.fini_array` là gì?
Là một **mảng con trỏ hàm** trong binary, chứa các "destructor" chạy **khi thoát**. `_dl_fini`
(hoặc `__libc_csu_fini` ở glibc cổ) duyệt mảng này **từ cuối về đầu** và `call` từng phần tử.
Thường mảng chỉ có 1 phần tử (`__do_global_dtors_aux`). Vì nó nằm trong **vùng data của binary**,
nó **ghi được** trừ khi Full RELRO.

### 1.2. Khai thác: ghi đè phần tử thành `main`/`win`/one-gadget
Có một **arbitrary write** (hay gặp nhất: **format string `%n`**) + binary **No PIE + Partial
RELRO** → ghi đè `.fini_array[0]`:
- `= &win` / `= &(system call-site)` → khi thoát, nhảy thẳng vào đó.
- `= &main` (hoặc `&_start`) → **chương trình chạy lại main** sau khi "thoát" → cho ta **lặp vô
  hạn lần khai thác** (cực mạnh với format string: mỗi vòng ghi thêm được một ít). Đây là mẹo
  **"loop main qua fini_array"** rất phổ biến.

> Vì `_dl_fini` duyệt mảng **từ cuối**, nếu muốn gọi **hai** hàm bạn đặt `.fini_array[0]=func_chạy_sau`,
> `.fini_array[1]=func_chạy_trước`. Mẹo kinh điển: `[0]=__libc_csu_fini` (hoặc `main`), `[1]=main`
> để vừa chạy lại vừa tự duy trì vòng lặp.

### 1.3. TÌM `.fini_array` trong GDB / readelf (kỹ năng cốt lõi bạn hỏi)
Lấy **địa chỉ** mảng:
```bash
readelf -S ./chall | grep fini_array      # ra: [NN] .fini_array  ... Addr=0x403e10  Size=0x8
objdump -s -j .fini_array ./chall          # in nội dung: con trỏ destructor hiện tại
```
Trong GDB:
```gdb
info files                 # tìm dòng: 0x403e10 - 0x403e18 is .fini_array
x/2gx 0x403e10             # xem con trỏ đang nằm trong mảng (destructor mặc định)
```
`info files` là cách lấy nhanh ranh giới `.fini_array` lúc runtime (đã rebase nếu PIE). Với **No
PIE** địa chỉ này **cố định** → ghi đè được mà không cần leak.

**Quan sát nó bị gọi (để tin chắc cơ chế):**
```gdb
b _dl_fini                 # hoặc:  b __run_exit_handlers
run                        # cho chương trình thoát
# bước tới chỗ 'call' phần tử .fini_array; xem rip nhảy vào con trỏ bạn vừa ghi
```

### 1.4. Biến thể "đổi base trên stack" (dạng PIE, đúng mô tả thường gặp)
Ở một số binary, `__libc_csu_fini`/`_dl_fini` tính địa chỉ `.fini_array` bằng cách lấy **một giá
trị base đang lưu trên stack** cộng một **offset cố định** rồi `call`. Nếu lỗ hổng của bạn cho
**sửa giá trị base đó trên stack** (vd BOF trúng đúng ô, hoặc partial overwrite), thì bạn **đổi
được chỗ mà nó coi là `.fini_array`** → trỏ sang mảng giả bạn dựng. Cách nhận biết trong GDB:
```gdb
b __libc_csu_fini          # (glibc cổ) hoặc b _dl_fini
# single-step tới lệnh tính 'lea rax,[rbx+offset]' / 'add' rồi 'call [rax+...]'
# xem base (vd rbx) lấy từ đâu — thường là một ô đã push lên stack lúc vào hàm
```
Tìm ô stack chứa base đó (`p $rbx`, rồi `search` giá trị đó trong khung stack) → đó là nơi bạn cần
ghi đè. Đây là lý do GDB quan trọng: **bạn phải nhìn tận mắt base được nạp từ ô stack nào** rồi mới
biết đổi ô nào để chuyển hướng `.fini_array`.

---

## 2. `__exit_funcs` — danh sách `atexit` (bị mã hoá)

### 2.1. Cấu trúc
`atexit(f)` / `__cxa_atexit(f, arg, dso)` lưu `f` vào một **`struct exit_function`** trong khối
`initial` (biến `__exit_funcs` trong libc). Khi `exit` → `__run_exit_handlers` duyệt và gọi.

```c
struct exit_function {
    long int flavor;        // 4 = ef_cxa (gọi fn(arg, status)); 3 = ef_on; ...
    union {
        struct { void (*fn)(int, void*); void *arg; void *dso_handle; } cxa;
        ...
    } func;
};
```

### 2.2. Lá chắn PTR_MANGLE (pointer guard)
Con trỏ `fn` **không lưu thô**, mà bị **mã hoá** bằng *pointer guard* lấy từ TLS (`fs:0x30`):
```
mangled = ROL( ptr XOR guard, 0x11 )        # mã hoá khi đăng ký
ptr     = ROR( mangled, 0x11 ) XOR guard     # giải mã khi gọi
```
```python
def rol(v, r, b=64): return ((v << r) | (v >> (b-r))) & (2**b-1)
def mangle(ptr, guard): return rol(ptr ^ guard, 0x11)
```
→ Muốn ghi một hàm giả (vd `system`, one-gadget) vào entry: phải ghi **`mangle(system, guard)`**,
tức **cần leak `guard` (giá trị tại `fs:0x30`)** trước. Không leak được guard → không forge được
entry hiện có.

### 2.3. Hai hướng
1. **Ghi đè entry có sẵn** (cần guard): sửa `fn = mangle(target, guard)` + `arg = "/bin/sh"`.
2. **Ghi đè con trỏ `__exit_funcs`** trỏ tới **struct giả** ta dựng (vùng ta control): set
   `flavor=4 (cxa)`, `fn=mangle(target,guard)`, `arg=...`. Vẫn cần guard, trừ khi bài để lộ
   **guard = 0** (TLS chưa set, hiếm nhưng có) → khỏi mangle.

### 2.4. Tìm trong GDB
```gdb
p (void*) &__exit_funcs        # con trỏ tới khối initial
p initial                      # (nếu có symbol) xem struct
# guard:
p/x *(unsigned long*)($fs_base + 0x30)    # pointer_guard; hoặc leak bằng %p/arbitrary-read
```
Trong pwndbg: `tls` in `fs_base`. Guard chính là ô `fs_base+0x30`.

---

## 3. `tls_dtor_list` (`__call_tls_dtors`)

Danh sách destructor TLS (dùng cho C++ `thread_local`), cũng chạy lúc thoát. Mỗi node có `func`
và `obj`, **`func` cũng PTR_MANGLE** như §2. Dựng một `dtor_list` giả + ghi `tls_dtor_list` trỏ
vào nó → khi `__call_tls_dtors` chạy sẽ gọi `func(obj)`. Dùng khi đường `__exit_funcs` bất tiện
nhưng vẫn leak được guard. Cơ chế giống hệt, chỉ khác biến gốc.

---

## 4. largebin / arbitrary-write → ghi vào các target trên

Các danh sách trên là **đích**, còn **primitive** để ghi vào chúng thường tới từ heap:
- **largebin attack** ([heap_intermediate.md §5](heap_intermediate.md)) ghi **một con trỏ heap**
  vào một địa chỉ tuỳ ý → ghi `&fake_struct(heap)` vào **`__exit_funcs`** (hoặc `_IO_list_all` cho
  [FSOP](fsop.md)). Vì largebin chỉ ghi được **giá trị là heap-ptr**, ta đặt sẵn struct giả tại
  đúng heap đó.
- **format string** `%n` ghi thẳng `.fini_array` (giá trị tuỳ ý) — đường dễ nhất, không cần heap.

Chuỗi hiện đại hay gặp: *tcache/largebin → ghi `__exit_funcs`/`_IO_list_all` → exit-handler/FSOP →
shell* (không đụng hook).

---

## 5. Nhận diện challenge: khi nào dùng hướng exit-hijack?

| Dấu hiệu | Gợi hướng |
|---------|-----------|
| **No PIE + Partial RELRO + arbitrary write (format string)** + **không có win rõ** | ✅ **`.fini_array`** (ghi `=main` để loop, hoặc `=target`) |
| Chương trình **thoát sạch** (main return / gọi exit) và bạn cần "một lần nữa" | ✅ `.fini_array = main` (loop) |
| glibc **≥ 2.34** (không còn hook) + có arbitrary write + **leak được pointer-guard** | ✅ `__exit_funcs`/`tls_dtor` (mangle) |
| Có **largebin/arbitrary write** nhưng target hook đã mất | ✅ ghi `__exit_funcs`/`_IO_list_all` |
| **Full RELRO** | ❌ `.fini_array` **read-only** → không ghi được; chuyển `__exit_funcs`/FSOP |
| Không leak được guard, guard ≠ 0 | ❌ không forge `__exit_funcs`/`tls_dtor` → quay lại `.fini_array`/FSOP |

**Phản xạ:** *format string + No PIE + Partial RELRO + không có win* → nghĩ ngay **`.fini_array =
main`** để lặp rồi dần dần leo thang. *Heap note glibc mới, hook đã mất* → **largebin → `__exit_funcs`
hoặc FSOP**.

> **Vì sao `.fini_array` cần Partial RELRO:** Full RELRO đánh dấu `.fini_array` (và GOT) **read-only**
> sau khi load → không ghi đè được. Partial/No RELRO để nó ghi được.

---

## 6. Luồng khai thác tiêu biểu (`.fini_array` loop — dễ nhất)

1. **Xác nhận:** No PIE, Partial RELRO, có arbitrary write (format string), chương trình sẽ thoát.
2. **Lấy địa chỉ** `.fini_array` (`readelf -S` / `info files`) và `main`.
3. **Vòng 1:** dùng format string ghi `.fini_array[0] = main`. Khi hàm hiện tại kết thúc →
   `exit` → `_dl_fini` gọi `.fini_array[0] = main` → **main chạy lại**.
4. **Các vòng sau:** mỗi lần quay lại main, format string lại cho ta một lần ghi/leak nữa → leak
   libc, rồi ghi tiếp `.fini_array[0] = one_gadget`/`system`.
5. **Vòng cuối:** thoát → gọi target → shell.

Điểm then chốt: `.fini_array` **chỉ chạy khi thoát**, nên phải để chương trình đi tới `exit` (không
crash giữa chừng).

---

## 7. Writeup rút gọn (tham khảo)

- **`.fini_array` loop:** bài format-string nào có No PIE + Partial RELRO. Dùng
  `fmtstr_payload(off, {exe.sym.__fini_array_addr: exe.sym.main})` (lấy địa chỉ từ `readelf -S`),
  lặp tới khi leak xong rồi đổi target thành shell. Chi tiết format string: [fmtstr.md](fmtstr.md).
- **`__exit_funcs` (2.34+):** cần leak `fs:0x30`; ghi `mangle(target, guard)` vào entry. PoC đầy đủ
  rất nhạy binary → xem HackTricks *www2exec (atexit)* ở nguồn.
- Phần `__free_hook` glibc cổ (2.23) đã **verify ra shell** ở [hook_overwrite.md §5](hook_overwrite.md).

---

## 8. Bài tập + lộ trình

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| Bài format-string No-PIE/Partial-RELRO | ⭐⭐ | **`.fini_array = main`** loop (dễ, làm trước) |
| `advance/Hook_Overwrite` (2.23) | ⭐⭐ | hook cổ, đối chiếu — [hook_overwrite.md](hook_overwrite.md) |
| HackTricks *www2exec (atexit)* | ⭐⭐⭐ | `__exit_funcs`/`tls_dtor` + bypass pointer-guard |
| largebin → `__exit_funcs`/`_IO` | ⭐⭐⭐⭐ | ghép [heap_intermediate.md](heap_intermediate.md) + [fsop.md](fsop.md) |

**Lộ trình:** `.fini_array` loop (ghi thô, dễ) → hiểu PTR_MANGLE → `__exit_funcs`/`tls_dtor`
(2.34+, cần guard) → largebin → `__exit_funcs`/`_IO_list_all` → FSOP apple2.

---

## Nguồn tham khảo
- HackTricks — *www2exec (atexit)*: <https://book.hacktricks.xyz/binary-exploitation/arbitrary-write-2-exec/www2exec-atexit>
- glibc `stdlib/exit.c` (`__run_exit_handlers`), `_dl_fini`; PTR_MANGLE trong `sysdeps/x86_64`.
- Nền: [hook_overwrite.md](hook_overwrite.md) · [fsop.md](fsop.md) · [heap_intermediate.md](heap_intermediate.md) · [fmtstr.md](fmtstr.md)

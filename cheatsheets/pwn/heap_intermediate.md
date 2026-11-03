# Heap trung cấp — biến bug nhỏ thành primitive mạnh (fastbin/tcache/unlink/largebin)

> **Bài giảng tự chứa.** Với MỖI kỹ thuật, đọc hết là hiểu: **bug nguồn** là gì, allocator làm gì
> khiến ta lợi dụng được, **kiểm tra (check) nào phải lách**, **quan sát nó trong GDB bằng lệnh
> gì**, và **nhìn challenge thế nào thì biết áp được**. Nền chunk/bin + phiên bản glibc: đọc
> [heap.md](heap.md) trước (§1 layout chunk, §3 version nuances). Thực hành:
> [`how2heap`](https://github.com/shellphish/how2heap) (`local/refs/how2heap/glibc_<ver>`, chọn khớp
> `ldd --version`). Nâng cao hơn: [heap_advanced.md](heap_advanced.md).

---

## 0. Bức tranh chung: các primitive này cho RA cái gì

[heap.md](heap.md) cho bug cơ bản (overflow/UAF/double-free → đọc/ghi chunk). Tier này **nâng cấp**
bug đó thành primitive mạnh:

| Primitive | Bug cần | Biến thành | "Đích" tiếp theo |
|-----------|---------|-----------|------------------|
| fastbin dup / tcache poisoning | double-free / sửa `fd` | **malloc trả địa chỉ tuỳ ý** | ghi vào `__free_hook`/GOT/`_IO`/exit-handler |
| unsafe unlink | heap overflow + con trỏ global | **ghi qua một con trỏ ta kiểm soát** | arbitrary write |
| tcache stashing unlink | control `bk` chunk smallbin | **ghi 1 libc-ptr + alloc tuỳ ý** | write + leak |
| large bin attack | control metadata largebin | **ghi 1 heap-ptr vào target tuỳ ý** | `_IO_list_all`/`__exit_funcs` → [FSOP](fsop.md)/[exit](exit_handlers.md) |
| house of spirit | control con trỏ truyền `free` | **free chunk GIẢ (stack/bss)** → malloc trả nó | alloc lên stack/bss |

**Trực giác xuyên suốt:** hầu hết là *lừa cơ chế nối danh sách (linked list) của allocator* — sửa
`fd`/`bk`/metadata để lần cấp phát kế trả về **nơi ta chọn**, rồi ghi vào chỗ nhạy.

---

## 1. fastbin dup — `fastbin_dup.c`, `fastbin_dup_consolidate.c`

**Bug:** double-free vào **fastbin** (chunk cỡ ≤ 0x80, tức request ≤ 0x78).

**Cơ chế:** fastbin là **single-linked LIFO**. `free` đẩy chunk lên đầu bin qua `fd`. Nếu cùng một
chunk vào bin **2 lần**, hai lần `malloc` kế trả **cùng địa chỉ** → lần 2 ta ghi vào vùng "đang
còn dùng", đặc biệt **ghi `fd`** để lần malloc sau trỏ tới đích tuỳ ý (fastbin poisoning).

**Check phải lách:** glibc chặn **double-free liền kề** — khi `free`, nó so chunk với **đỉnh
fastbin**; trùng → `"double free or corruption (fasttop)"`. Lách bằng **free xen kẽ**:
`free(a); free(b); free(a)`. `fastbin_dup_consolidate` dùng `malloc` lớn ép **consolidate** để qua
check này cho cả chunk cỡ tcache. Khi malloc từ fastbin, glibc còn **so size** chunk với bin (2.26+)
→ chunk giả phải có `size` khớp.

**Quan sát GDB (pwndbg):**
```gdb
fastbins                 # liệt kê từng fastbin + chuỗi fd (thấy chunk lặp 2 lần)
malloc_chunk <addr>      # xem header size/fd của một chunk
```
**Nhận diện:** có **double-free** hoặc **UAF-write** trên chunk nhỏ (≤0x78) + glibc ≤2.31 (hoặc
tcache đã đầy nên rơi xuống fastbin). **Verify how2heap 2.39:** `p2 == p3`. ✅

---

## 2. tcache poisoning — `tcache_poisoning.c` (workhorse hiện đại)

**Bug:** sửa được trường `next` (chính là `fd`, offset 0x00 của chunk đã free) của một chunk trong
**tcache** (UAF/overflow).

**Cơ chế:** tcache là **single-linked LIFO**, malloc trả `e->next`. Ghi `next = target` → **malloc
thứ 2 trả thẳng `target`** = arbitrary alloc → ghi đâu cũng được (`__free_hook`, GOT, `_IO`, stack).

**Check phải lách:**
- **safe-linking (2.32+):** `next` bị mã hoá `mangle(pos, ptr) = (pos>>12) ^ ptr` → phải **leak một
  địa chỉ heap** trước (biết `pos`) rồi ghi `fd = mangle(pos, target)`. Xem [heap.md §3](heap.md),
  [heap_advanced.md §1](heap_advanced.md).
- **alignment (2.33+):** `target` trả về phải **căn 0x10** (16) → chọn địa chỉ đích aligned.
- **tcache key (2.29+):** double-free vào tcache bị bắt (xem [heap_advanced.md §1](heap_advanced.md)).

**Quan sát GDB:**
```gdb
tcache                   # (pwndbg) in các tcache bin + count + chuỗi next
heap ; vis_heap_chunks   # sơ đồ heap, thấy fd đã bị sửa
```
**Nhận diện:** UAF/overflow + chunk cỡ tcache (≤0x410) — **đường chính của gần như mọi heap note
hiện đại**. Đã có writeup verify ra shell (2.31) ở [heap.md §6](heap.md). **Verify 2.39:** malloc
thứ 2 trả địa chỉ ta chọn. ✅

---

## 3. unsafe unlink — `unsafe_unlink.c`

**Bug:** heap overflow **và** tồn tại **một con trỏ tới chunk, nằm ở vùng ghi-được đã biết địa
chỉ** (ví dụ biến global `chunk0_ptr`).

**Cơ chế:** khi một chunk free được **gộp (consolidate) backward** với chunk trước đang-free, glibc
gọi **`unlink`** để rút chunk trước khỏi bin: `FD->bk = BK; BK->fd = FD`. Ta dựng **fake chunk**
ngay trong data của chunk0 với `fd`, `bk` sao cho phép unlink **ghi đè `chunk0_ptr`** thành
`&chunk0_ptr - 0x18`. Sau đó dùng chính `chunk0_ptr` để **ghi tuỳ ý** (write-what-where).

**Check phải lách:** unlink hiện đại kiểm **`FD->bk == P && BK->fd == P`** → dùng chính địa chỉ con
trỏ global để thoả: đặt `fd = &chunk0_ptr - 0x18`, `bk = &chunk0_ptr - 0x10`. Còn kiểm
`chunksize(P) == prev_size(next_chunk)` → phải set `prev_size`/`prev_inuse` của chunk kế đúng.

**Quan sát GDB:** trước/sau `free`, `p chunk0_ptr` để thấy nó bị đổi; `vis_heap_chunks` xem fake
chunk + prev_size.
**Nhận diện:** có **con trỏ heap ở global/bss biết địa chỉ** + overflow sửa được header chunk kế +
chunk đủ lớn (không vào fastbin/tcache để nó đi đường consolidate). **Verify 2.39:** `chunk0_ptr`
bị trỏ về vùng ta chọn. ✅

---

## 4. tcache stashing unlink — `tcache_stashing_unlink_attack.c`

**Bug:** control được `bk` của một chunk trong **small bin**.

**Cơ chế:** `calloc` **bỏ qua tcache**, lấy từ small bin. Khi lấy, cơ chế **stashing** đổ các chunk
small-bin còn lại vào tcache. Nếu `bk` giả trỏ **fake chunk**, quá trình stashing vừa **ghi một
địa chỉ libc** (`main_arena`-related) vào `fake->bk->fd`, vừa khiến **malloc kế trả fake chunk** →
arbitrary alloc + một mồi leak.

**Check phải lách:** cần số chunk trong small bin hợp lệ và `fake->bk->fd` trỏ vùng ghi-được (để
không crash khi stashing ghi vào).
**Quan sát GDB:** `bins` xem small bin + chain `bk`; sau `calloc` kiểm tcache nhận fake.
**Nhận diện:** bài có **`calloc`** + control được smallbin metadata (ít gặp hơn, thường combo). 
**Verify 2.39:** fake vào tcache[0xa0], `malloc(0x90)` kế trả vùng fake. ✅

---

## 5. large bin attack — `large_bin_attack.c`

**Bug:** control được metadata chunk trong **large bin** (overflow/UAF).

**Cơ chế:** large bin có thêm `fd_nextsize`/`bk_nextsize` để sắp theo size. Khi một chunk mới chèn
vào large bin, glibc cập nhật các con trỏ này; khéo đặt `bk_nextsize` của victim → glibc **ghi một
con trỏ heap vào `target = bk_nextsize->fd_nextsize+0x20`** (địa chỉ tuỳ ý). **Chỉ ghi được giá
trị là heap-ptr** (địa chỉ chunk mới), không ghi được giá trị tùy ý.

**Dùng để:** ghi `&fake_struct(heap)` vào **`_IO_list_all`** → [FSOP](fsop.md), hoặc **`__exit_funcs`**
→ [exit handlers](exit_handlers.md). Vì chỉ ghi heap-ptr, ta **đặt sẵn struct giả tại heap đó**.

**Quan sát GDB:** `bins` / `largebins`; đặt watchpoint tại `target` để thấy nó bị ghi heap-ptr.
**Nhận diện:** glibc **mới** (hook đã mất) + có chunk large (>0x400) điều khiển được metadata → đây
là cầu nối tới FSOP/exit-handler. **Verify 2.39:** `target` bị ghi = heap-ptr. ✅

---

## 6. house of spirit — `house_of_spirit.c`, `tcache_house_of_spirit.c`

**Bug:** control được con trỏ truyền cho `free`, và có **vùng ta kiểm soát** (stack/bss) để dựng
**chunk giả**.

**Cơ chế:** `free(fake)` nhét chunk giả vào bin → `malloc` cùng cỡ kế **trả con trỏ tới stack/bss
của ta** → ghi/thực thi vùng đó (vd đưa ROP/shellcode-addr lên stack bằng một malloc).

**Check phải lách:** chunk giả phải có **`size` hợp lệ** (căn 0x10, trong dải fastbin/tcache đang
nhắm), **và chunk KẾ TIẾP** (tại fake+size) phải có `size` hợp lệ (`2*SZ ≤ size ≤ av->system_mem`)
để qua kiểm. `prev_inuse` phải set.
**Quan sát GDB:** dựng fake chunk rồi `malloc_chunk <fake>` kiểm size hợp lệ trước khi free.
**Nhận diện:** chương trình **`free` một con trỏ bạn kiểm soát** + có 2 vùng ghi-được cạnh nhau.
**Verify 2.39:** `malloc` trả fake chunk trên stack. ✅

---

## 7. unsorted bin attack — `unsorted_bin_attack.c` (⚠️ ĐÃ CHẾT từ 2.29)

Trước 2.29: free chunk lớn → sửa `bk` → khi malloc dọn unsorted bin, nó ghi `&main_arena+0x60`
(một libc-ptr) vào `target`. **Từ 2.29 thêm kiểm `bk`/`fd` → bị chặn**; how2heap 2.39 **không còn
file này**. Chỉ gặp ở libc cũ (≤2.28). Thay thế hiện đại: **large bin attack** (§5).

---

## 8. Chạy & quan sát (how2heap)

```bash
cd local/refs/how2heap/glibc_2.39        # chọn thư mục KHỚP ldd --version
gcc fastbin_dup.c -o /tmp/x && /tmp/x    # các file TỰ in địa chỉ chứng minh primitive
# khác glibc: dùng glibc_2.31/... hoặc ./glibc_run.sh để chạy dưới đúng loader
```
> File how2heap **không spawn shell** — nó in địa chỉ để bạn thấy primitive hoạt động. Học =
> đọc comment trong `.c` + chạy + **tự viết lại** vào `exploits/pwn/` (đừng copy nguyên). Luôn mở
> pwndbg (`heap`, `bins`, `vis_heap_chunks`) để **nhìn metadata đổi theo từng bước**.

---

## 9. Lộ trình luyện

`fastbin_dup` (hiểu LIFO + double-free) → `tcache_poisoning` (đường chính) →
(`unsorted_bin_attack` chỉ nếu libc ≤2.28) → `unsafe_unlink` (unlink + check FD/BK) →
`tcache_stashing_unlink` (calloc/smallbin) → `house_of_spirit` (fake chunk) →
`large_bin_attack` (cầu nối FSOP/exit). Mỗi bài: chạy trên **đúng glibc**, nắm **check nào phải
lách**, rồi áp vào 1 CTF heap thật. Lá chắn hiện đại (safe-linking, tcache-key) + house-of-*:
[heap_advanced.md](heap_advanced.md).

---

## Nguồn tham khảo
- **how2heap** (Shellphish): <https://github.com/shellphish/how2heap> — kho chuẩn, bản mỗi glibc.
- ir0nstone *Heap*: <https://ir0nstone.gitbook.io/notes/types/heap>
- Nền chunk/bin + version: [heap.md](heap.md) · đích cuối: [fsop.md](fsop.md), [exit_handlers.md](exit_handlers.md), [hook_overwrite.md](hook_overwrite.md)

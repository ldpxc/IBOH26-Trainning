# Heap trung cấp (T7) — các primitive corruption qua how2heap

> Tài liệu học sâu. Mỗi kỹ thuật **đã compile + chạy how2heap trên glibc 2.39** của máy (xác nhận
> primitive hoạt động). Đây là tier **không có bài local** → luyện bằng
> [`shellphish/how2heap`](https://github.com/shellphish/how2heap) (clone sẵn ở `local/refs/how2heap`,
> dùng `glibc_<version>/` khớp `ldd --version`). Nguồn ở cuối.

---

## 0. Các primitive này cho ra cái gì

T6 ([heap.md](heap.md)) cho **ghi/đọc chunk tuỳ ý** (UAF/overflow/tcache poisoning). T7 là các
chiêu **biến một bug nhỏ thành primitive mạnh hơn**:

| Primitive T7 | Biến bug thành |
|--------------|----------------|
| fastbin dup / tcache poisoning | **malloc trả địa chỉ tuỳ ý** (arbitrary alloc) |
| unsafe unlink | **ghi con trỏ về chính nó** → arbitrary write qua con trỏ đó |
| tcache stashing unlink | **ghi 1 giá trị libc** + alloc chunk tuỳ ý |
| large bin attack | **ghi 1 heap-ptr vào 1 target tuỳ ý** (global/`_IO`) |
| house of spirit | **free chunk GIẢ** (stack/bss) → malloc trả nó |

Đích cuối vẫn là: malloc/ghi ra chỗ nhạy (`__free_hook`/exit-handler/`_IO`) → control flow.

---

## 1. fastbin dup (+ consolidate) — `fastbin_dup.c`, `fastbin_dup_consolidate.c`

**Bug:** double-free vào **fastbin** (chunk ≤ 0x80). **Được:** cùng một chunk nằm trong bin 2
lần → 2 lần `malloc` trả **cùng địa chỉ** → lần 2 ta control vùng đang "còn dùng".

- glibc chặn double-free **liền kề** (so `fastbin[0]`), nên free xen: `free(a); free(b); free(a)`.
- `fastbin_dup_consolidate`: dùng `malloc` lớn ép **consolidate** để lách kiểm tra, dup cả chunk
  cỡ tcache. **Verify 2.39:** `p2 == p3` (hai con trỏ trùng). ✅
```
free(a); free(b); free(a);          // a vào fastbin 2 lần (xen b)
x=malloc(); y=malloc(); z=malloc(); // z == x  -> dùng x khi đang giữ z
```

## 2. tcache poisoning — `tcache_poisoning.c` (workhorse hiện đại)

Sửa `fd` của chunk trong tcache → `malloc` kế trả **địa chỉ tuỳ ý**. Đã có writeup verify ra shell
ở [heap.md §6](heap.md#6-writeup-b--tcache-poisoning-libc-231-verify-ra-shell). **Lưu ý 2.32+:**
`fd` bị **safe-linking** → `mangle(pos, ptr) = (pos>>12) ^ ptr` (xem `decrypt_safe_linking.c`,
[heap.md §3](heap.md#3-️-khác-biệt-theo-phiên-bản-glibc-quyết-định-payload)). **Verify 2.39:** malloc
thứ 2 trả địa chỉ stack ta chọn. ✅

## 3. unsafe unlink — `unsafe_unlink.c`

**Bug:** heap overflow + có **một con trỏ tới chunk nằm ở vùng ghi được đã biết** (vd global
`chunk0_ptr`). Dựng **fake chunk** với `fd/bk` trỏ sao cho khi `free` chunk kế gây **consolidate
backward → unlink**, phép unlink `fd->bk = bk; bk->fd = fd` **ghi đè `chunk0_ptr` = &chunk0_ptr-0x18`**.
Sau đó dùng `chunk0_ptr` để **ghi tuỳ ý**. Cần qua kiểm `fd->bk == p && bk->fd == p` (dùng chính
địa chỉ con trỏ global để thoả). **Verify 2.39:** `chunk0_ptr` bị trỏ về vùng ta muốn rồi ghi đè
victim string. ✅

## 4. tcache stashing unlink attack — `tcache_stashing_unlink_attack.c`

**Bug:** control được `bk` của một chunk trong **small bin**. Khi `calloc` lấy từ small bin, cơ
chế **stashing** đổ các chunk còn lại vào tcache; nếu `bk` giả trỏ fake chunk, ta vừa **ghi một
địa chỉ libc** vào `fake->bk->fd`, vừa khiến `malloc` kế **trả fake chunk** (ghi tuỳ ý). **Verify
2.39:** fake chunk vào tcache[0xa0], `malloc(0x90)` kế trả vùng fake. ✅

## 5. large bin attack — `large_bin_attack.c`

**Bug:** control được metadata chunk trong **large bin**. Khi một chunk mới chèn vào large bin,
glibc cập nhật `bk_nextsize`/`fd_nextsize`; khéo sắp → **ghi một con trỏ heap vào 1 địa chỉ tuỳ
ý (`target`)**. Thường dùng để ghi đè **global / `_IO_list_all` / struct** rồi dẫn tới FSOP.
**Verify 2.39:** `target` bị ghi = con trỏ heap. ✅ (chỉ ghi được **giá trị là heap-ptr**, không
tuỳ ý giá trị → thường kết hợp FSOP.)

## 6. house of spirit — `house_of_spirit.c`, `tcache_house_of_spirit.c`

**Bug:** control được một con trỏ truyền cho `free`, và có **2 vùng ta kiểm soát** (stack/bss) để
dựng **chunk giả** (size hợp lệ + chunk kế có size hợp lệ để qua kiểm). `free(fake)` nhét fake vào
bin → `malloc` kế **trả con trỏ tới stack/bss của ta**. **Verify 2.39:** `malloc` trả fake chunk
trên stack. ✅

## 7. unsorted bin attack — `unsorted_bin_attack.c` (⚠️ đã chết)

Trước 2.29: free chunk lớn → sửa `bk` → khi malloc dọn unsorted bin, ghi `&main_arena+0x60` (một
libc-ptr) vào `target`. **Từ glibc 2.29 thêm kiểm `bk`/`fd` → bị chặn**, nên **how2heap 2.39
KHÔNG còn file này**. Chỉ gặp ở bài libc cũ (≤2.28). Thay thế hiện đại: **large bin attack** (§5).

---

## 8. Cách chạy & verify (how2heap)

```bash
cd local/refs/how2heap/glibc_2.39        # chọn thư mục KHỚP ldd --version
gcc fastbin_dup.c -o /tmp/x && /tmp/x    # chạy, đọc log minh hoạ primitive
# bản khác glibc: dùng glibc_2.31/ ... hoặc ./glibc_run.sh để chạy dưới đúng loader
```
> Các file này **tự minh hoạ** (in địa chỉ chứng minh primitive), không spawn shell. Học = đọc
> comment trong .c + chạy + **tự viết lại** vào `exploits/pwn/` (đừng copy nguyên).

---

## 9. Lộ trình luyện (bám roadmap T7)

`fastbin_dup` → `fastbin_dup_consolidate` → (`unsorted_bin_attack` nếu libc ≤2.28) → `unsafe_unlink`
→ `tcache_stashing_unlink_attack` → `house_of_spirit` → `large_bin_attack`.
Mỗi bài: chạy trên **đúng glibc**, hiểu *điều kiện* (cỡ chunk, bin nào, kiểm tra nào phải lách),
rồi áp vào 1 CTF heap thật. T8 (safe-linking bypass, house of botcake/einherjar/lore/force) xem
[heap_advanced.md] *(đang viết)*.

---

## Nguồn tham khảo

- **how2heap** (Shellphish): <https://github.com/shellphish/how2heap> — kho chuẩn, có bản mỗi glibc.
- ir0nstone *Heap*: <https://ir0nstone.gitbook.io/notes/types/heap>
- Nền tảng chunk/bin + version nuances: [heap.md](heap.md)

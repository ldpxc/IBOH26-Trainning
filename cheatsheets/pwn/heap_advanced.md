# Heap nâng cao (T8) — safe-linking, tcache-key & house of…

> Tài liệu học sâu. Các kỹ thuật **đã compile + chạy how2heap trên glibc 2.39** của máy. Không có
> bài local → luyện bằng [`how2heap`](https://github.com/shellphish/how2heap) (`local/refs/how2heap`,
> chọn `glibc_<version>` khớp `ldd --version`). Nền tảng: [heap.md](heap.md), [heap_intermediate.md](heap_intermediate.md).

---

## 1. Hai lá chắn hiện đại phải vượt

| Lá chắn | Từ glibc | Làm gì | Vượt thế nào |
|---------|----------|--------|--------------|
| **tcache key** | 2.29 | mỗi chunk free vào tcache ghi `key = tcache_struct`; free lại thấy key → báo "double free detected" | **xoá/sửa `key`** (nếu ghi được), hoặc double-free **không qua tcache** (fastbin/unsorted), hoặc đẩy tcache đầy (7) rồi chơi fastbin |
| **safe-linking** | 2.32 | `fd` trong tcache/fastbin bị **mã hoá**: `fd_lưu = (địa_chỉ_chunk >> 12) XOR fd_thật` | **giải mã** khi đọc leak, **mã hoá** khi ghi fd (cần biết địa chỉ chunk, tức leak heap trước) |

**Safe-linking — công thức (verify bằng `decrypt_safe_linking.c`):**
```python
def mangle(pos, ptr):            # GHI fd: pos = địa chỉ chunk chứa fd
    return (pos >> 12) ^ ptr

def demangle(val):               # GIẢI leak fd (không cần biết pos): lộ dần 12 bit/lần
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val                   # = fd_thật
```
`decrypt_safe_linking.c` của how2heap là bản chuẩn — đã verify `demangle` khôi phục đúng con trỏ.
→ Muốn poison tcache trên 2.32+: **leak một địa chỉ heap** trước (để biết `pos`), rồi ghi
`fd = mangle(pos, target)`. **Verify 2.39:** `decrypt_safe_linking` khôi phục đúng con trỏ gốc. ✅

> **Lưu ý `__free_hook` bỏ từ 2.34** → sau khi có arbitrary alloc/write, đích không còn là hook mà
> là **exit handlers / FSOP** (xem [hook_overwrite.md](hook_overwrite.md), FSOP tier T9).

---

## 2. house of botcake — `house_of_botcake.c`

**Dạng:** có UAF/double-free + tcache. Lợi dụng **tcache + unsorted bin** để tạo **chunk chồng
lấn (overlap)** rồi **arbitrary alloc**. Ý tưởng: làm đầy tcache (7), free thêm 2 chunk vào
unsorted để chúng consolidate, rồi double-free qua đường unsorted (lách tcache-key) → malloc trả
chunk chồng lên chunk đang dùng. **Verify 2.39:** `target == stack_var` (alloc trúng stack). ✅
Dùng khi tcache-key chặn double-free thẳng.

## 3. house of einherjar — `house_of_einherjar.c`

**Dạng:** **off-by-one null byte** (poison null byte) ghi đè byte thấp `size`/xoá `prev_inuse` của
chunk kế → glibc tưởng chunk trước **đang free** → khi free chunk kế, **consolidate backward** vào
`prev_size` ta điều khiển → chunk mới **trùm lên vùng ta chọn** (kể cả stack). **Verify 2.39:** new
chunk nằm trên stack. ✅ Kinh điển cho bug **1-byte overflow**.

## 4. house of lore — `house_of_lore.c`

**Dạng:** sửa **`bk` của chunk trong small bin** → chèn **fake chunk** vào small bin → `malloc`
kế trả fake (thường trỏ **stack**). Cần qua kiểm `bck->fd == victim`. **Verify 2.39:** `p4` nằm
trên stack. ✅ Hữu ích khi control được smallbin metadata.

## 5. house of force — `house_of_force.c` (⚠️ chết từ 2.29)

**Dạng:** overflow ghi đè **size của top chunk** = `0xffff...` → `malloc(size_lớn)` dời top tới
**địa chỉ tuỳ ý** → `malloc` kế trả đó. **Từ 2.29 glibc kiểm size top → chặn.** Chỉ còn ở
`glibc_2.23/house_of_force.c` (đã xác nhận). Gặp ở bài libc ≤2.28.

## 6. Các house khác (tham khảo)

`house_of_mind_fastbin`, `house_of_tangerine`, `house_of_water` (trong 2.39) — biến thể dựng
primitive khi các đường trên bị chặn; đọc khi gặp bài cụ thể. **house of apple/orange/cat/banana**
thuộc **FSOP** (tier T9) — xem tài liệu FSOP.

---

## 7. Cách chạy & verify

```bash
cd local/refs/how2heap/glibc_2.39
gcc house_of_botcake.c -o /tmp/b && /tmp/b    # đọc log minh hoạ overlap/alloc
# bug 1-byte -> house_of_einherjar; smallbin bk -> house_of_lore; top chunk (libc cũ) -> house_of_force (glibc_2.23)
```
Tự minh hoạ (in địa chỉ chứng minh), không spawn shell. Học = đọc .c + chạy + **viết lại**.

---

## 8. Lộ trình (bám roadmap T8)

Hiểu **safe-linking + tcache-key** (lá chắn) → `house_of_botcake` (double-free lách key) →
`house_of_einherjar` (off-by-one null) → `house_of_lore` (smallbin) → `house_of_force` (chỉ libc
cũ). Sau đó sang **T9 FSOP** (house of apple2/orange → control flow khi không còn hook).

---

## Nguồn tham khảo

- how2heap: <https://github.com/shellphish/how2heap> (xem `glibc_ChangeLog.md` cho kỹ thuật nào
  chết ở bản nào).
- safe-linking: `decrypt_safe_linking.c`, `safe_link_double_protect.c` trong how2heap.
- Nền tảng: [heap.md](heap.md), [heap_intermediate.md](heap_intermediate.md)

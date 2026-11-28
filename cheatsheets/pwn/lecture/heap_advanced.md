# Heap nâng cao — vượt lá chắn hiện đại & các "house of…"

> **Bài giảng tự chứa.** Đọc hết là hiểu: hai lá chắn **tcache-key** và **safe-linking** chặn gì
> và **vượt thế nào**, rồi mỗi "house" hoạt động ra sao (**bug nguồn → cơ chế → check phải lách →
> quan sát GDB → nhận diện**). Nền: [heap.md](heap.md) (chunk/bin + version), [heap_intermediate.md](heap_intermediate.md)
> (fastbin/tcache/unlink/largebin). Thực hành: [`how2heap`](https://github.com/shellphish/how2heap)
> (`local/refs/how2heap/glibc_<ver>`, khớp `ldd --version`).

---

## 0. Vì sao cần tier này

glibc hiện đại thêm hai lá chắn làm các primitive cổ (tcache/fastbin poisoning, double-free) **không
còn chạy thẳng**. Tier này dạy cách **vượt lá chắn** + các kỹ thuật "house of…" dựng primitive khi
đường thường bị chặn. Quy tắc số 1 của heap vẫn đúng: **xác định phiên bản glibc trước** (nó quyết
định check nào bật).

---

## 1. Hai lá chắn phải vượt

| Lá chắn | Từ glibc | Nó làm gì | Vượt thế nào |
|---------|----------|-----------|--------------|
| **tcache key** | 2.29 | mỗi chunk free vào tcache ghi `key = &tcache_perthread` ở offset +0x08; free lần 2 thấy `key` khớp → báo **"double free detected in tcache"** | **xoá/sửa `key`** (nếu ghi được 8 byte tại +0x08), hoặc double-free **không qua tcache** (đẩy tcache đầy 7 chunk rồi chơi **fastbin/unsorted**), hoặc dùng **house of botcake** (§2) |
| **safe-linking** | 2.32 | `fd`/`next` trong tcache & fastbin bị **mã hoá**: `fd_lưu = (địa_chỉ_chunk >> 12) XOR fd_thật` | **giải mã** khi đọc leak; **mã hoá** khi ghi fd — mà muốn mã hoá phải **biết địa chỉ chunk** → **leak một địa chỉ heap trước** |

### 1.1. safe-linking — công thức (verify `decrypt_safe_linking.c`)
```python
def mangle(pos, ptr):            # GHI fd: pos = ĐỊA CHỈ chunk đang chứa fd
    return (pos >> 12) ^ ptr

def demangle(val):               # GIẢI leak fd (không cần biết pos): lộ dần 12 bit mỗi vòng
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val                   # = fd_thật
```
Nhận xét quan trọng: **đọc leak** không cần biết `pos` (vì 12 bit cao của địa chỉ heap ~0 nên tự
lộ dần), nhưng **ghi** thì cần `pos` → **luôn leak heap base trước** khi poison trên 2.32+.

### 1.2. Quan sát trong GDB
```gdb
tcache                   # (pwndbg) in count + chuỗi next (đã mã hoá) của từng bin
p/x <chunk>+0x8          # xem tcache key (so với &tcache_perthread)
# tự kiểm mangle:  p/x (<chunk_addr> >> 12) ^ <fd_muốn_ghi>
```
> **Lưu ý version:** `__free_hook`/`__malloc_hook` **bỏ từ 2.34** → sau khi có arbitrary alloc/write,
> đích không còn là hook mà là **[exit handlers](exit_handlers.md) / [FSOP](fsop.md)**.

---

## 2. house of botcake — `house_of_botcake.c`

**Bug nguồn:** UAF/double-free + tcache, nhưng **tcache-key chặn double-free thẳng**.

**Cơ chế:** lợi dụng **tcache + unsorted bin** để tạo **chunk chồng lấn (overlap)**: làm **đầy
tcache (7 chunk)**, rồi free thêm 2 chunk vào **unsorted** cho chúng **consolidate**, rồi
double-free **qua đường unsorted** (không đụng tcache-key) → malloc trả chunk **chồng lên** chunk
đang dùng → đọc/ghi chéo → arbitrary alloc.

**Check lách:** double-free đi qua unsorted/consolidate nên **né kiểm tcache-key**; cần quản lý
đúng số chunk (7 để đầy tcache).
**Quan sát GDB:** `bins` thấy tcache đầy + unsorted; `vis_heap_chunks` thấy hai con trỏ cùng trỏ
vùng overlap.
**Nhận diện:** glibc ≥2.29 (tcache-key) + có double-free/UAF + cấp phát được chunk 0x80–0x100.
**Verify 2.39:** `target == stack_var`. ✅

---

## 3. house of einherjar — `house_of_einherjar.c`

**Bug nguồn:** **off-by-one null byte** (poison-null-byte) — ghi tràn **1 byte 0** vào `size` của
chunk kế, xoá bit `prev_inuse`.

**Cơ chế:** xoá `prev_inuse` khiến glibc tưởng **chunk trước đang free**. Khi free chunk kế, nó
**consolidate backward** dùng `prev_size` (ta điều khiển) để tính "đầu chunk trước" → chunk mới
**trùm lên vùng ta chọn** (kể cả stack/bss nếu đặt `prev_size` trỏ tới đó).

**Check lách:** cần `prev_size` khớp để `chunksize(P)==prev_size`; và vùng đích có `size` giả hợp
lệ. Trên tcache phải tránh chunk rơi vào tcache (dùng cỡ lớn).
**Quan sát GDB:** `vis_heap_chunks` trước/sau free thấy chunk mới trùm; kiểm `prev_size`.
**Nhận diện:** bug **1-byte overflow (null byte)** — dấu hiệu kinh điển của einherjar.
**Verify 2.39:** new chunk nằm trên stack. ✅

---

## 4. house of lore — `house_of_lore.c`

**Bug nguồn:** sửa được **`bk` của chunk trong small bin**.

**Cơ chế:** chèn **fake chunk** vào small bin qua `bk` giả → `malloc` kế **trả fake chunk** (thường
trỏ **stack**) → ghi/thực thi vùng stack.

**Check lách:** small bin lấy chunk kiểm **`bck->fd == victim`** → fake chunk phải có `fd` trỏ lại
đúng. Cần sắp 2 tầng con trỏ (victim→fake→victim).
**Quan sát GDB:** `bins` xem small bin chain; sau malloc kiểm con trỏ trả về nằm trên stack.
**Nhận diện:** control được **smallbin metadata** (`bk`) + muốn alloc lên stack. Ít gặp, thường combo.
**Verify 2.39:** `p4` nằm trên stack. ✅

---

## 5. house of force — `house_of_force.c` (⚠️ CHẾT từ 2.29)

**Bug nguồn:** overflow ghi đè **`size` của top chunk** = `0xffffffffffffffff`.

**Cơ chế:** top chunk size khổng lồ → `malloc(size_lớn)` **dời top tới địa chỉ tuỳ ý** → malloc kế
trả đúng đó. **Từ 2.29 glibc kiểm size top (`assert`) → chặn.** Chỉ còn ở `glibc_2.23/house_of_force.c`.
**Nhận diện:** chỉ libc **≤2.28** + overflow trúng top-chunk size.

---

## 6. Các house khác (tham khảo nhanh)

`house_of_mind_fastbin`, `house_of_tangerine`, `house_of_water` (có trong how2heap 2.39): biến thể
dựng primitive khi các đường trên bị chặn — đọc khi gặp bài cụ thể. **house of apple/orange/cat/
banana** thuộc **[FSOP](fsop.md)** (tấn công `_IO_FILE`), không nằm ở đây.

---

## 7. Nhận diện: bug nào → house nào

| Dấu hiệu bug | Hướng |
|--------------|-------|
| double-free bị **tcache-key** chặn | house of botcake (§2) / đẩy tcache đầy rồi fastbin |
| **1-byte null overflow** | house of einherjar (§3) |
| control **smallbin `bk`**, muốn alloc stack | house of lore (§4) |
| overflow **top-chunk size**, libc ≤2.28 | house of force (§5) |
| libc **2.32+**, poison tcache/fastbin | phải **leak heap** + `mangle(fd)` (§1) |
| libc **2.34+**, cần control flow | arbitrary alloc/write → **[exit handlers](exit_handlers.md)/[FSOP](fsop.md)** (không còn hook) |

**Phản xạ:** luôn hỏi 3 câu — *(1) glibc bản mấy?* (quyết check nào bật) *(2) bug cho primitive
gì?* (double-free/off-by-one/smallbin…) *(3) đích control flow ở đâu?* (hook nếu ≤2.33, else
exit/FSOP).

---

## 8. Chạy & quan sát
```bash
cd local/refs/how2heap/glibc_2.39
gcc house_of_botcake.c -o /tmp/b && /tmp/b    # đọc log minh hoạ overlap/alloc
```
Các file tự in địa chỉ chứng minh (không spawn shell). Học = đọc `.c` + chạy + mở pwndbg
(`heap`/`bins`/`vis_heap_chunks`) nhìn metadata đổi + **tự viết lại**.

---

## 9. Lộ trình
Hiểu **safe-linking + tcache-key** (§1) → `house_of_botcake` (double-free lách key) →
`house_of_einherjar` (off-by-one null) → `house_of_lore` (smallbin) → `house_of_force` (chỉ libc
cũ). Sau đó sang **[FSOP](fsop.md)** (house of apple2/orange) + **[exit handlers](exit_handlers.md)**
để lấy control flow khi không còn hook.

---

## Nguồn tham khảo
- how2heap: <https://github.com/shellphish/how2heap> (xem `glibc_ChangeLog.md` — kỹ thuật nào chết ở bản nào).
- safe-linking: `decrypt_safe_linking.c`, `safe_link_double_protect.c` trong how2heap.
- Nền: [heap.md](heap.md), [heap_intermediate.md](heap_intermediate.md) · đích: [fsop.md](fsop.md), [exit_handlers.md](exit_handlers.md)

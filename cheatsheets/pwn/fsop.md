# FSOP (T9) — tấn công `_IO_FILE` & fake vtable

> Tài liệu học sâu. **`FileStructure` của pwntools đã verify** (dựng fake `_IO_FILE` 224 byte).
> FSOP **rất nhạy binary/libc** → full-exploit luyện bằng how2heap (`house_of_io`/`house_of_orange`)
> + pwn.college. Nền tảng: [heap_advanced.md](heap_advanced.md), [hook_overwrite.md](hook_overwrite.md).

---

## 1. Vì sao FSOP?

glibc ≥ 2.34 **bỏ `__free_hook`/`__malloc_hook`** → sau khi có arbitrary write/alloc, đích mới là
**cấu trúc `_IO_FILE`** (của `stdin/stdout/stderr` hoặc file tự tạo). Mỗi FILE có một con trỏ
**vtable** (bảng hàm). Khi chương trình gọi `fflush/fclose/fwrite/puts/exit` (exit flush mọi
stream), glibc gọi **`file->vtable->xsputn(...)`** v.v. → **ghi đè vtable (hoặc chính FILE) = chiếm
control flow** mà không cần hook.

> Nói ngắn: *giả mạo một `_IO_FILE` + vtable sao cho lần flush/exit kế gọi vào gadget/`system` của ta.*

---

## 2. Cơ chế & lá chắn `_IO_vtable_check`

Luồng: `exit()` → `_IO_cleanup` → duyệt **`_IO_list_all`** (danh sách mọi FILE) → mỗi file gọi
`_IO_OVERFLOW(fp,...)` = `fp->vtable->__overflow(fp, ...)`.

- **Trước 2.24:** vtable trỏ đâu cũng được → trỏ vào gadget → **house of orange** (ghi
  `_IO_list_all` qua unsorted-bin/top-chunk → fake file → vtable giả → `system`).
- **Từ 2.24:** **`_IO_vtable_check`** bắt vtable phải nằm trong vùng `__libc_IO_vtables` → không trỏ
  bậy được. Vượt bằng cách dùng **vtable hợp lệ nhưng lệch**: `_IO_str_jumps`/`_IO_wstr_jumps`, hoặc
  **house of apple2** (dùng `_IO_wfile_jumps` + `_wide_data` để `_IO_wdoallocbuf` gọi
  `_wide_data->vtable->doallocate` — con trỏ này **không bị check**).

| Kỹ thuật | libc | Ý tưởng |
|----------|------|---------|
| **house of orange** | ≤ 2.23 (path chết ~2.26) | top-chunk→unsorted→`_IO_list_all`→fake file→vtable cũ |
| **`_IO_str_overflow`/`_str_jumps`** | 2.24–2.3x | vtable hợp lệ nhưng ép tính toán gọi `system` |
| **house of apple2** | **2.34+** (hiện đại) | `_IO_wfile_jumps` + `_wide_data` → qua `_IO_vtable_check` |
| **house of cat/banana** | 2.35+ | biến thể apple, dùng `_IO_wdefault_xsputn`/`setcontext` |

---

## 3. Dựng fake `_IO_FILE` bằng pwntools (đã verify)

Tự tính offset từng field (`_flags`, `_IO_read_ptr`, `_lock`, `vtable`, `_wide_data`…) rất dễ sai
→ **`FileStructure`** gói sẵn (verify: `bytes(FileStructure())` = **224 byte**, có `.write/.read/.orange`):

```python
from pwnlib.filepointer import FileStructure
fs = FileStructure(null=0)                 # null = địa chỉ vùng NULL hợp lệ (để qua vài kiểm)
payload = fs.write(addr=target, size=0x100)  # dựng FILE sao cho flush -> write(fd, target, size) (LEAK)
# hoặc:
fs.read(addr=target, size=0x100)             # flush -> đọc vào target (arbitrary write)
fs.orange(io_list_all=.., vtable=..)         # hỗ trợ dựng house-of-orange
p = bytes(fs)                                 # bytes để ghi vào stdout/FILE giả
```
Gán field thủ công cũng được: `fs.flags`, `fs.vtable`, `fs._IO_buf_base`… rồi `bytes(fs)`.

---

## 4. Khung house of orange (cổ điển, hiểu luồng)

```
1) overflow 'size' của top chunk -> malloc lớn -> top cũ bị free vào unsorted bin
2) unsorted-bin attack ghi &fake_file vào _IO_list_all
3) fake_file: _flags = "/bin/sh"; vtable -> bảng giả có __overflow = system
4) trigger (malloc lỗi / exit) -> _IO_flush_all -> fake->vtable->__overflow(fake) = system("/bin/sh")
```
> Path "malloc lỗi → flush" bị gỡ ở **2.26**; bản mới dùng apple2 qua `exit`/`_IO_cleanup`.

---

## 5. Mức verify (trung thực)

- **`FileStructure`**: ✅ verify dựng struct 224 byte + `.write/.read/.orange` chạy.
- **how2heap**: `glibc_2.23/house_of_orange.c`, `glibc_2.31..33/house_of_io.c` — compile được; chạy
  cần **đúng loader/libc** (dùng `how2heap/glibc_run.sh`). (house_of_orange tự in chú thích: path
  bị đổi từ 2.26.)
- **Full FSOP→shell**: cần một binary đích cụ thể → luyện trên pwn.college (File Struct Exploits).

---

## 6. Danh sách bài tập + gợi ý

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| **pwn.college — File Struct Exploits** | ⭐⭐⭐ | FSOP từ 0, có hint — <https://pwn.college> |
| **how2heap `house_of_orange` / `house_of_io`** | ⭐⭐⭐ | luồng `_IO_list_all`/vtable (chạy `glibc_run.sh`) |
| **pwntools `filepointer` docs** | ⭐⭐ | `FileStructure` dựng fake FILE — <https://docs.pwntools.com/en/stable/filepointer.html> |
| **angelboy — "Play with FILE Structure"** | ⭐⭐⭐⭐ | tài liệu gốc house of orange/apple2/cat/banana (Slideshare) |

**Lộ trình:** hiểu `_IO_FILE`+vtable → `FileStructure` dựng FILE → house of orange (cổ, hiểu luồng)
→ `_IO_vtable_check` → **house of apple2** (2.34+, thực chiến hiện đại) → cat/banana.

---

## Nguồn tham khảo

- angelboy — *Play with FILE Structure* (Slideshare) — kinh điển cho house of orange/apple2/cat/banana.
- pwntools filepointer: <https://docs.pwntools.com/en/stable/filepointer.html>
- how2heap `house_of_io.c`/`house_of_orange.c`; pwn.college File Struct Exploits.
- Nền: [hook_overwrite.md](hook_overwrite.md) (vì sao chuyển sang FSOP từ 2.34), [heap_advanced.md](heap_advanced.md)

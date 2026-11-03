# FSOP — tấn công `_IO_FILE` & fake vtable (chiếm control flow khi không còn hook)

> **Bài giảng tự chứa.** Đọc hết là hiểu: một `FILE*` thật ra là struct gì, **từng field quan
> trọng nằm ở offset nào**, con trỏ **vtable** ở đâu và được gọi thế nào khi `fflush/exit/puts`,
> vì sao từ glibc 2.24 không trỏ vtable bậy được nữa (**`_IO_vtable_check`**) và cách **house of
> apple2** lách nó, **cách tìm mọi thứ trong GDB**, và **nhìn challenge thế nào thì biết dùng
> FSOP**. Nền: [heap_advanced.md](heap_advanced.md), [exit_handlers.md](exit_handlers.md),
> [hook_overwrite.md](hook_overwrite.md).

---

## 0. Bạn cần nắm trước: `FILE*` thực chất là gì?

Khi bạn dùng `stdout`, `stdin`, hay `fopen(...)`, cái bạn cầm là `FILE*` — con trỏ tới một struct
**`_IO_FILE`** trong glibc. Mọi hàm I/O cấp cao (`printf`, `puts`, `fwrite`, `fflush`, `fclose`)
cuối cùng gọi tới các **hàm ảo (virtual function)** của FILE đó thông qua một bảng con trỏ gọi là
**vtable**. Nghĩa là `puts(s)` ≈ *"gọi hàm `xsputn` trong vtable của `stdout`"*.

Điều then chốt: **glibc gọi hàm qua con trỏ lưu trong struct FILE**. Nếu ta **giả mạo struct FILE
+ vtable** sao cho con trỏ đó trỏ vào gadget/`system` của ta, thì lần I/O (hoặc lúc `exit` flush
mọi stream) kế tiếp sẽ **nhảy vào code ta chọn** — **không cần `__malloc_hook`/`__free_hook`**
(vốn đã bị bỏ từ glibc 2.34). Đây là lý do FSOP là đích chính của heap hiện đại.

> **Nói ngắn:** *I/O của glibc = gọi hàm qua `FILE->vtable->...`. FSOP = dựng FILE giả + vtable giả
> (hoặc sửa `_IO_list_all` trỏ tới FILE giả) để lần flush/exit kế gọi vào gadget của ta.*

---

## 1. Cấu trúc `_IO_FILE_plus` — các field QUAN TRỌNG và offset (x86-64)

`_IO_FILE_plus` = `_IO_FILE` (phần dữ liệu) + **con trỏ `vtable`** ở cuối. Offset glibc 64-bit
(có thể lệch chút theo version — luôn xác nhận bằng GDB ở §3):

| Offset | Field | Vai trò trong khai thác |
|-------:|-------|-------------------------|
| `+0x00` | `_flags` | cờ; house-of-orange nhét luôn chuỗi `"/bin/sh"` vào đây (vì được truyền làm arg) |
| `+0x08` | `_IO_read_ptr` | con trỏ đệm đọc |
| `+0x20` | `_IO_write_base` | khi flush: `write(fd, _IO_write_base, _IO_write_ptr-_IO_write_base)` |
| `+0x28` | `_IO_write_ptr` | → điều khiển 2 field này = **leak/arbitrary write** qua flush |
| `+0x38` | `_IO_buf_base` | vùng đệm |
| `+0x68` | `_chain` | con trỏ **FILE kế** trong danh sách `_IO_list_all` (linked list) |
| `+0x70` | `_fileno` | file descriptor |
| `+0x88` | `_lock` | con trỏ lock; **phải trỏ vùng ghi-được chứa 0** nếu không kẹt/deadlock |
| `+0xa0` | `_wide_data` | con trỏ `_IO_wide_data` — **mấu chốt của house of apple2** (§4) |
| `+0xd8` | `vtable` | **con trỏ bảng hàm ảo** — tim của FSOP |

**vtable** trỏ tới một `_IO_jump_t`: mảng con trỏ hàm `__finish, __overflow, __underflow, __xsputn,
...`. Hàm hay bị gọi nhất:
- **`__overflow`** (offset +0x18 trong vtable): gọi khi flush/`exit` qua macro `_IO_OVERFLOW(fp) =
  fp->vtable->__overflow(fp, EOF)`.
- **`__xsputn`** (+0x38): gọi bởi `puts/fwrite`.

> Tự tính offset từng field rất dễ sai → pwntools `FileStructure` gói sẵn (§5). Nhưng **phải hiểu
> field nào làm gì** mới debug được khi payload lỗi.

---

## 2. Cơ chế bị gọi + lá chắn `_IO_vtable_check`

### 2.1. Luồng lúc `exit`
```
exit() → _IO_cleanup → _IO_flush_all_lockp
        → duyệt danh sách _IO_list_all (nối nhau qua _chain, offset +0x68)
        → với mỗi fp:  _IO_OVERFLOW(fp, EOF) = fp->vtable->__overflow(fp, EOF)
```
Nên nếu ta kiểm soát `_IO_list_all` (trỏ tới FILE giả) hoặc kiểm soát vtable của một FILE có thật,
thì `__overflow` ta đặt sẽ được gọi với **`rdi = fp`** (con trỏ FILE giả). Đặt `_flags = "/bin/sh"`
+ `vtable->__overflow = system` → `system("/bin/sh")`.

### 2.2. Lá chắn (vì sao bản mới khó hơn)
- **Trước glibc 2.24:** vtable trỏ **đâu cũng được** → trỏ thẳng vào bảng giả → **house of orange**.
- **Từ 2.24:** thêm **`_IO_vtable_check`** — trước khi gọi, glibc kiểm tra con trỏ vtable phải nằm
  **trong vùng `__libc_IO_vtables`** (section chứa các vtable hợp lệ). Trỏ ra ngoài → abort
  (`"Fatal error: glibc detected an invalid stdio handle"`). → **không dựng vtable tùy ý** được nữa.

### 2.3. Cách lách (tổng quan các "house")
| Kỹ thuật | libc | Ý tưởng lách |
|----------|------|--------------|
| **house of orange** | ≤ 2.23 | vtable chưa bị check → trỏ bảng giả; ghi `_IO_list_all` qua top-chunk/unsorted |
| **`_IO_str_overflow`/`_str_jumps`** | 2.24–2.3x | dùng **vtable hợp lệ** (`_IO_str_jumps`) nhưng ép phép tính trong `_IO_str_overflow` gọi tới `system` |
| **house of apple2** | **2.34+** | dùng vtable hợp lệ `_IO_wfile_jumps` → `_IO_wdoallocbuf` gọi `_wide_data->vtable->doallocate`, mà **con trỏ này KHÔNG bị `_IO_vtable_check`** |
| **house of cat/banana** | 2.35+ | biến thể apple, dẫn tới `setcontext`/gadget để control nhiều thanh ghi |

**Trực giác house of apple2:** thay vì ghi đè vtable chính (bị check), ta để vtable chính = một
vtable **hợp lệ** là `_IO_wfile_jumps`. Khi gọi hàm overflow của nó, nó đi tới `_IO_wdoallocbuf`,
hàm này lại gọi `fp->_wide_data->vtable->doallocate`. Con trỏ `_wide_data` (+0xa0) và vtable bên
trong nó **do ta kiểm soát và không bị kiểm tra** → trỏ vào gadget/`setcontext` → control flow.

---

## 3. Tìm mọi thứ trong GDB (kỹ năng cốt lõi)

**a) Xem một FILE thật và vtable của nó:**
```gdb
p _IO_2_1_stdout_              # struct FILE của stdout
p/x &_IO_2_1_stdout_          # địa chỉ của nó (libc + offset)
x/32gx &_IO_2_1_stdout_       # soi toàn bộ field; ô ở +0xd8 = con trỏ vtable
p/x *(void**)((char*)&_IO_2_1_stdout_ + 0xd8)   # lấy thẳng con trỏ vtable
```
Trong pwndbg/gef có lệnh đẹp hơn: **`p *(struct _IO_FILE_plus*)&_IO_2_1_stdout_`** để thấy tên
field + offset chính xác cho **đúng version libc** của bạn (đừng tin offset cứng — xác nhận ở đây).

**b) Tìm `_IO_list_all` (đầu danh sách FILE):**
```gdb
p/x &_IO_list_all             # biến libc, trỏ tới FILE đầu tiên (thường _IO_2_1_stdout_)
x/gx &_IO_list_all
```

**c) Tìm vùng vtable hợp lệ `__libc_IO_vtables` + các jump hợp lệ:**
```gdb
p/x &_IO_file_jumps           # vtable chuẩn của FILE thường
p/x &_IO_wfile_jumps          # vtable "wide" dùng cho house of apple2
p/x &_IO_str_jumps            # cho _IO_str_overflow
info symbol <vtable_ptr>      # kiểm con trỏ vtable đang trỏ vào symbol nào
```
Các symbol này cho bạn **địa chỉ vtable hợp lệ** để đặt (qua `_IO_vtable_check`), thay vì dựng bảng
giả bị chặn.

**d) Đặt watchpoint để thấy nó bị gọi:**
```gdb
b _IO_flush_all_lockp         # hoặc b *_IO_OVERFLOW ... ; rồi để chương trình exit
```

---

## 4. Dựng fake `_IO_FILE` bằng pwntools `FileStructure`

Tự đặt từng field rất dễ sai → `FileStructure` lo offset (`bytes(FileStructure())` = **224 byte**):
```python
from pwnlib.filepointer import FileStructure
fs = FileStructure(null=heap_or_writable_zero)   # null = địa chỉ vùng chứa 0 (cho _lock...)
payload = fs.write(addr=target, size=0x100)       # dựng FILE sao cho flush → write(fd,target,size) = LEAK
#   hoặc:
fs.read(addr=target, size=0x100)                  # flush → read vào target = arbitrary write
fs.orange(io_list_all=.., vtable=..)              # hỗ trợ dựng house of orange
p = bytes(fs)
```
Gán field thủ công cũng được: `fs.flags`, `fs.vtable`, `fs._IO_buf_base`, `fs._lock`,
`fs._wide_data`… rồi `bytes(fs)`. Dùng chính các field §1.

---

## 5. Nhận diện challenge: khi nào dùng FSOP?

| Dấu hiệu | Gợi ý |
|---------|-------|
| glibc **≥ 2.34** (không còn `__free_hook`/`__malloc_hook`) + có **arbitrary write / largebin** | ✅ FSOP là đích chính |
| Có thể ghi đè **con trỏ `_IO_list_all`** hoặc **vtable của một FILE** | ✅ |
| Chương trình **gọi `exit`/`fflush`/`puts`/`fclose`** sau khi ta ghi xong | ✅ có chỗ trigger |
| Cần **leak** mà không có hàm in: điều khiển `_IO_write_base/_ptr` của stdout | ✅ FSOP để **leak** (không chỉ để ra shell) |
| glibc **2.24–2.33** | ✅ nhưng vtable bị check → dùng `_IO_str_jumps` thay vì bảng giả |
| glibc **≤ 2.23** | ✅ house of orange (dễ nhất, vtable chưa bị check) |
| Không leak được libc | ⚠️ FSOP cần biết địa chỉ libc (vtable/_IO_list_all nằm trong libc) → leak trước |

**Phản xạ:** *heap note, glibc mới, hook đã mất, có arbitrary write* → **largebin/arbitrary write →
ghi `_IO_list_all` = fake FILE (heap) → house of apple2 → shell**. Nếu bài **≤2.23** → house of
orange cho nhẹ.

> **Vì sao FSOP cần leak libc:** cả `_IO_list_all`, các vtable hợp lệ (`_IO_wfile_jumps`...),
> `system`/`setcontext` đều nằm **trong libc** → phải có libc base trước mới điền đúng.

---

## 6. Luồng khai thác (house of apple2 — thực chiến hiện đại)

1. **Điều kiện:** glibc 2.34+, có leak libc + một primitive ghi (largebin/arbitrary write), và có
   `exit`/flush để trigger.
2. **Dựng fake FILE** (trên heap ta control): `_flags` hợp lệ, `vtable = _IO_wfile_jumps` (hợp lệ,
   qua check), `_wide_data = &fake_wide_data`, trong `fake_wide_data` đặt `vtable->doallocate =
   gadget/setcontext`. `_lock` trỏ vùng 0.
3. **Ghi `_IO_list_all = &fake_FILE`** (largebin ghi heap-ptr vào `&_IO_list_all`).
4. **Trigger:** `exit` → `_IO_flush_all` duyệt `_IO_list_all` → gọi chuỗi `_IO_wfile_overflow →
   _IO_wdoallocbuf → _wide_data->vtable->doallocate` = gadget của ta (thường `setcontext` để nạp
   full thanh ghi → `execve("/bin/sh")`).
5. **Kết quả:** shell, không đụng hook.

Điểm then chốt: vtable chính phải là **hợp lệ** (`_IO_wfile_jumps`) để qua `_IO_vtable_check`; chỗ
trỏ bậy nằm ở **vtable của `_wide_data`** (không bị check).

---

## 7. Writeup rút gọn (tham khảo)

- **`FileStructure` leak:** điều khiển stdout (`_flags`, `_IO_write_base/_ptr`) để flush in ra vùng
  `target` → leak. Nhẹ, hay dùng để lấy libc/heap base ngay trong bài.
- **house of orange (≤2.23):** top-chunk→unsorted→unsorted-bin-attack ghi `_IO_list_all=&fake` →
  vtable giả `__overflow=system`, `_flags="/bin/sh"`.
- **house of apple2 (2.34+):** §6. Rất nhạy binary/libc → luyện full trên pwn.college *File Struct
  Exploits* và how2heap. Tài liệu gốc: angelboy *Play with FILE Structure*.

---

## 8. Bài tập + lộ trình

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| pwntools `filepointer` docs | ⭐⭐ | `FileStructure` dựng fake FILE — <https://docs.pwntools.com/en/stable/filepointer.html> |
| how2heap `house_of_orange.c` | ⭐⭐⭐ | luồng `_IO_list_all`/vtable cổ điển |
| pwn.college — *File Struct Exploits* | ⭐⭐⭐ | FSOP từ 0, có hint — <https://pwn.college> |
| angelboy — *Play with FILE Structure* | ⭐⭐⭐⭐ | orange/apple2/cat/banana (tài liệu gốc) |

**Lộ trình:** hiểu struct `_IO_FILE` + vtable (§1) → `FileStructure` dựng FILE để **leak** (dễ, làm
trước) → house of orange (≤2.23, hiểu luồng `_IO_list_all`) → `_IO_vtable_check` → **house of
apple2** (2.34+, thực chiến) → cat/banana + `setcontext`.

---

## Nguồn tham khảo
- angelboy — *Play with FILE Structure* (Slideshare) — kinh điển orange/apple2/cat/banana.
- pwntools filepointer: <https://docs.pwntools.com/en/stable/filepointer.html>
- how2heap `house_of_orange.c`; pwn.college *File Struct Exploits*.
- Nền: [hook_overwrite.md](hook_overwrite.md) (vì sao chuyển sang FSOP từ 2.34) · [exit_handlers.md](exit_handlers.md) · [heap_advanced.md](heap_advanced.md)

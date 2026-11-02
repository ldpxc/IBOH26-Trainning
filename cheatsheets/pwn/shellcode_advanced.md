# Shellcode nâng cao (T5 lẻ) — egghunter & alphanumeric

> Tài liệu học sâu. Alphanumeric **verify bằng `encoders` pwntools**; egghunter theo bài local
> `advance/Egg_Hunter`. Nền: [shellcode.md](pwntools/shellcode.md), [seccomp_orw.md](seccomp_orw.md).

---

## 1. Egghunter — khi chỗ nhồi shellcode quá nhỏ

**Vấn đề:** chỉ inject được **vài chục byte**, nhưng **stage-2 (shellcode dài / flag)** nằm ở
**địa chỉ KHÔNG biết** trong bộ nhớ. **Egghunter** = shellcode nhỏ **quét bộ nhớ tìm một "egg"**
(tag 4–8 byte, vd `HTB{`/`egg0egg0`) rồi nhảy/đọc stage-2 ngay sau tag.

**Cơ chế (an toàn, không SIGSEGV khi quét):** dùng **syscall để thử page** — nếu page chưa map,
syscall trả **`EFAULT`** thay vì làm crash:
```asm
; i386 egghunter (bài hunting): quét bằng write(1, ptr, 1), gặp EFAULT (al==0xf2) -> sang page kế
init:  mov edi, 0x60000000
run:   mov eax,4; mov ebx,1; mov ecx,edi; mov edx,1; int 0x80   ; write(1, edi, 1)
       cmp al, 0xf2            ; -EFAULT? -> page chưa map
       je  next_page
check: cmp byte [edi], 'H'     ; so tag "HTB{"
       jne next_page
       ... khớp đủ 4 byte tag -> get_flag (write cả vùng ra)
next_page: add edi, 0x1000 (hoặc 0x10000); jmp run
```
**Biến thể chuẩn (Skape, x64):** dùng `access(ptr, 0)` kiểm page, so tag 8 byte (lặp tag để chắc
không trùng chính egghunter). **Dạng bài:** buffer nhỏ + đã ghi được stage-2 ở đâu đó (bss/heap/
env) kèm tag. Bài local: `advance/Egg_Hunter` (`hunting`, NX off, PIE) — quét tìm `HTB{`.

> Điều kiện chạy: vùng chứa egghunter phải **thực thi được** (NX off / mprotect). Trên kernel mới,
> buffer `.data` có thể không exec → cần môi trường đề (như [seccomp_orw.md §4](seccomp_orw.md#4-cạm-bẫy-quan-trọng)).

---

## 2. Alphanumeric shellcode — khi input lọc ký tự

**Vấn đề:** input qua `scanf("%s")`/bộ lọc chỉ nhận **chữ-số in được** (hoặc cấm `\x00`,`\n`,space).
Shellcode thường chứa byte tuỳ ý → bị chặn. **Giải:** **encode** shellcode thành chuỗi chỉ gồm byte
cho phép, kèm **decoder stub** tự giải mã tại runtime.

**pwntools làm sẵn (đã verify):**
```python
context.arch = 'amd64'
sc  = asm(shellcraft.amd64.linux.sh())
enc = encoders.encode(sc, avoid=b'\x00\x0a\x20')     # tự chọn encoder né null/newline/space
#   verify: len(enc)=48, b'\x00' not in enc  ✅

# i386 TOÀN ký tự alphanumeric in được (qua bộ lọc alnum):
from pwnlib.encoders.i386.ascii_shellcode import ascii_shellcode
asc = ascii_shellcode.encode(asm(shellcraft.i386.linux.sh()))
```
- `encode(raw, avoid=...)` → ném lỗi nếu **không encoder nào** né hết `avoid` cho arch đó (vài
  arch chưa hỗ trợ alnum-only).
- Kỹ thuật gốc: XOR/`sub`-encoding, tự sinh byte bằng các lệnh chỉ dùng opcode in được (`push/pop`,
  `xor`, `imul`...). Hiểu để tự viết khi pwntools bí.

**Bẫy:** decoder stub cũng phải **nằm trong tập ký tự cho phép**; shellcode phải **tự định vị**
(get PC) vì vị trí random — alnum encoders lo phần này.

---

## 3. Shellcode viết tay & SROP-shellcode (liên kết)

- Viết tay x64/x86 cơ bản + né byte xấu: [shellcode.md](pwntools/shellcode.md).
- **SROP-shellcode:** thay vì SROP gọi hàm libc, trỏ `frame.rip` vào **shellcode tự viết** (khi có
  vùng exec) — xem [srop.md](srop.md).
- ORW (seccomp cấm execve): [seccomp_orw.md](seccomp_orw.md).

---

## 4. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **`advance/Egg_Hunter`** (hunting) | ⭐⭐⭐ | egghunter quét page tìm tag | **§1** (có `exploit.py`), chạy trong env NX-off |
| **alphanumeric trên bof5/bof6** | ⭐⭐⭐ | tự ra đề: ép alnum rồi encode | `ascii_shellcode` / `encode(avoid=...)` |
| **Phrack — ia32 Alphanumeric Shellcodes** | ⭐⭐⭐⭐ | kỹ thuật gốc XOR/encode | áp dụng ý tưởng sang x64 |
| **ENS — ABC of Next-Gen Shellcoding** | ⭐⭐⭐⭐ | constraint khó dần | <https://securite.di.ens.fr/?p=289> |

**Lộ trình:** viết tay x64 (shellcode.md) → né byte xấu (`encode`) → alphanumeric (`ascii_shellcode`)
→ egghunter (buffer nhỏ + stage-2 xa) → SROP-shellcode.

---

## Nguồn tham khảo

- pwntools `encoders`/`shellcraft`: [shellcode.md](pwntools/shellcode.md), [advanced.md](pwntools/advanced.md#encoders--né-byte-xấu--shellcode-ascii)
- Skape — *Safely Searching Process Virtual Address Space* (egghunter gốc).
- Phrack *Writing ia32 Alphanumeric Shellcodes*; ENS *The ABC of Next-Gen Shellcoding*.

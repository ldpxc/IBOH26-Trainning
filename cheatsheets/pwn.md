# PWN — bản đồ (lane P1)

> **Trang điều hướng.** Mọi thứ pwn trong repo nằm rải rác nhiều chỗ — đây là nơi **tra ra đường**
> thay vì phải nhớ. Cần gì bấm vào đó. Cuối trang là roadmap theo tier.

---

## 1. Sổ tay tra cứu (cheatsheets)

| Cần gì | Mở |
|--------|-----|
| **Hàm tiện ích pwntools** (packing/tubes/ELF/ROP/fmt/shellcode/context + DynELF/libcdb/ret2csu/SROP/ret2dlresolve…) — có ví dụ mọi case **+ bản làm tay để so sánh** | [`pwn/pwntools/`](pwn/pwntools/) |
| → "dùng hàm nào cho **dạng bài** nào" (bảng tra nhanh) | [`pwn/pwntools/README.md`](pwn/pwntools/README.md#dùng-gì-cho-dạng-bài-nào) |
| **Wrapper tự viết của repo** (`from pwnld import *`: `start/GDB/set_*`, macro IO, `leak_*_p/s`, `fmtstr_pos` short/full/consumed) | [`pwn/pwntools/pwnld.md`](pwn/pwntools/pwnld.md) |
| **Format string** chuyên sâu (cơ chế `%n`, biến tấu, template mọi tình huống, short-vs-full) | [`pwn/fmtstr.md`](pwn/fmtstr.md) |

### 📚 Tài liệu học sâu theo kỹ thuật (đọc là nắm bài bản, có writeup verify)

| Kỹ thuật | Tier | Nội dung | Mở |
|----------|------|----------|-----|
| **Format string** | T2 | cơ chế `%n`, biến tấu, template mọi tình huống | [`pwn/fmtstr.md`](pwn/fmtstr.md) |
| **ret2csu** | T3 | 2 gadget csu, mapping, ràng buộc + **writeup pwnld verify ra shell** + bài tập | [`pwn/ret2csu.md`](pwn/ret2csu.md) |

> Khác với `pwn/pwntools/` (tra nhanh API): mục này là **bài giảng** — hiểu *tại sao*, dựng chain
> tay, cạm bẫy, và bài luyện kèm writeup. Giải xong kỹ thuật nào → thêm 1 dòng vào bảng này.

## 2. Công cụ trong repo

| Công cụ | Vai trò | Đường dẫn |
|---------|---------|-----------|
| `pwnld.py` | lớp mỏng bọc pwntools; `python3 pwnld.py --help <topic>` | [`tools/pwnld.py`](../tools/pwnld.py) · [tham chiếu](pwn/pwntools/pwnld.md) |
| `genscr` | sinh nhanh `exploit.py` (+symlink pwnld/pwnretry), mở nvim | [`tools/`](../tools/) · [README](../tools/README.md) |
| `retry/` | chạy lại tới khi trúng (ASLR, partial overwrite, brute canary, race) — viết `attempt(i)` → `retry()`; template flag/shell/parallel | [`exploits/pwn/retry/`](../exploits/pwn/retry/) |
| `shellcode/` | catalog shellcode đã test: `from shellcodes import SC` | [`exploits/pwn/shellcode/`](../exploits/pwn/shellcode/) |
| **bản đồ phụ thuộc** (sửa mảnh nào phải động tới đâu) | khi nâng cấp tool | [`exploits/pwn/MAINTAINING.md`](../exploits/pwn/MAINTAINING.md) |

## 3. Template & nơi để bài giải

- **Template exploit farm** (in flag ra stdout, chuẩn A/D): [`templates/exploit_pwn.py`](../templates/exploit_pwn.py)
- **Exploit đã giải** lưu vào: [`exploits/pwn/<tên>/`](../exploits/pwn/) · **Writeup**: [`writeups/pwn/`](../writeups/pwn/)
- *(máy cá nhân, không push)* lộ trình luyện tập & bài tutorial: `local/labs/PWN-roadmap.md`, `local/refs/pwn/`

## 4. Công cụ ngoài (nhớ sẵn vài lệnh)

```bash
checksec ./bin                              # NX/PIE/canary/RELRO
cyclic 200 ;  cyclic -l 0x6161616161616164  # tìm offset BOF
ROPgadget --binary ./bin | grep 'pop rdi'   # (hoặc ropper, angrop)
one_gadget ./libc.so.6                       # magic gadget execve(/bin/sh)
seccomp-tools dump ./bin                     # xem filter trước khi làm ORW
```
Thêm: GDB + pwndbg/gef, libc-database / libc.rip (nhận libc từ leak), Ghidra/IDA.

---

## 5. Roadmap theo tier

> Trần mục tiêu P1 = **Tier 4** (T5+ là stretch). Giải xong tier nào → dán snippet + link `exploits/pwn/<tên>/` vào đây.

| Tier | Chủ đề | Tra ở đâu |
|------|--------|-----------|
| **T1** | Stack BOF (ret2win, ret2shellcode) | [rop](pwn/pwntools/rop.md), [shellcode](pwn/pwntools/shellcode.md), [packing `cyclic/flat`](pwn/pwntools/packing.md) |
| **T2** | Format string (leak, GOT overwrite) | **[fmtstr.md](pwn/fmtstr.md)** · [fmt](pwn/pwntools/fmt.md) · [pwnld `fmtstr_pos`](pwn/pwntools/pwnld.md) |
| **T3** | ROP / NX (ret2libc/plt/syscall, ret2csu, stack pivot) | [rop](pwn/pwntools/rop.md), **[ret2csu.md](pwn/ret2csu.md)** (học sâu), [advanced](pwn/pwntools/advanced.md) |
| **T4** | Bypass mitigation (leak canary/PIE, **SROP**) | [rop SROP](pwn/pwntools/rop.md#srop--sigreturnframe), [retry (brute)](../exploits/pwn/retry/) |
| **T5** | Shellcoding (ORW seccomp, alphanumeric) | [shellcode](pwn/pwntools/shellcode.md), [encoders](pwn/pwntools/advanced.md), [`shellcode/`](../exploits/pwn/shellcode/) |
| **T6** | Heap intro (UAF, double free, tcache poisoning) | *(chưa có — điền khi giải)* |
| **T7** | Heap trung cấp (fastbin dup, unsorted leak, large bin) | *(chưa có)* |
| **T8** | Heap nâng cao (safe-linking, house of …) | *(chưa có)* |
| **T9** | FILE / FSOP | *(chưa có)* |
| **T10** | Hijack control-flow (exit handlers, largebin→write) | *(chưa có)* |
| **T11+** | Kernel / misc (stretch) | *(chưa có)* |

<!-- Giải xong 1 tier: thêm dòng link exploits/pwn/<tên>/ vào cột "Tra ở đâu" -->

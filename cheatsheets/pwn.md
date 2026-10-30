# Cheatsheet — PWN

> Lane P1. Khung theo tier trong README mục 2. Mỗi kỹ thuật ghi: *nhận diện → cách làm → gadget/lệnh → link exploit thật*.

**Công cụ:** pwntools, `cyclic`, ROPgadget/ropper/angrop, one_gadget, libc-database/libc.rip, GDB + pwndbg/gef, `checksec`, Ghidra/IDA.

```bash
checksec ./bin
cyclic 200 ; cyclic -l 0x6161...   # tìm offset
ROPgadget --binary ./bin | grep 'pop rdi'
one_gadget ./libc.so.6
```

## T1 — Stack BOF (ret2win, ret2shellcode)
## T2 — Format string (leak, GOT overwrite)
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

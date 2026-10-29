# Cheatsheet — REV

> P1/P2 chia nhau. Khung theo tier trong README mục 2.

**Công cụ:** Ghidra/IDA/Binary Ninja, pwndbg/gef, angr, Z3, dnSpy, jadx, qiling/unicorn.

```bash
file ./bin ; strings -n 6 ./bin
ltrace ./bin ; strace ./bin
```

## T1 — Static+dynamic (đọc asm, Ghidra, patch nhảy điều kiện, keygen)
## T2 — Anti-analysis (anti-debug, unpack UPX, string obfuscation)
## T3 — Obfuscation nâng cao (CFG flattening, VM/bytecode)
## T4 — Tooling (angr/symbolic, Z3/claripy, .NET/Java/Go)
## T5+ — Firmware / kernel / arch lạ (stretch)

<!-- Dán snippet + link exploits/rev/ hoặc writeups/rev/ -->

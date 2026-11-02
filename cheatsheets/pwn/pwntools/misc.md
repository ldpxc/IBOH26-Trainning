# misc — vá ELF, tube-to-tube, context sâu, atexit, adb

Những thứ còn lại ít gặp hơn nhưng vẫn hữu ích, gom một chỗ.

---

## Vá / dựng ELF

**Công dụng:** sửa binary (vá điều kiện, NOP check), hoặc tạo ELF từ asm/shellcode để test.
**Dạng bài:** patch-and-run, test shellcode, bài yêu cầu sửa binary.

```python
e = ELF("./chall")
e.asm(0x401234, "nop; nop")         # ghi đè code tại địa chỉ bằng asm
e.write(e.sym.flag_check, b"\x90"*5)# NOP thô
e.save("./patched"); os.chmod("./patched", 0o755)

# tạo ELF chạy được từ asm / shellcode
elf = ELF.from_assembly("mov rdi, 1; mov al, 60; syscall")   # exit(1)
elf = ELF.from_bytes(asm(shellcraft.sh()))
elf.save("sc"); 
```

---

## Tube ↔ tube: nối hai kênh

**Công dụng:** làm **proxy/relay** giữa hai tube (vd nối client tới server qua mình để sửa gói).
**Dạng bài:** MITM/relay, bài nối nhiều service.

```python
a = remote("svc", 1337)
b = process("./local")
a.connect_both(b)        # nối 2 chiều: output a -> input b và ngược lại
# hoặc 1 chiều:
a.connect_input(b)       # a.recv -> b.send
```

---

## listen — làm server (nhận reverse)

**Công dụng:** mở cổng chờ kết nối (reverse shell, bài connect-back). **Dạng bài:** exploit khiến
mục tiêu connect về mình.

```python
l = listen(4444)
# ... kích hoạt reverse shell trên mục tiêu ...
l.wait_for_connection()
l.interactive()
```

---

## context — thuộc tính sâu hơn

```python
context.aslr = False          # tắt ASLR cho process() con (debug tất định)
context.randomize = False     # tắt mọi ngẫu nhiên hoá pwntools thêm vào
context.noptrace = True       # bỏ qua ptrace (môi trường không cho attach)
context.kernel = 'amd64'      # cho vài shellcraft phụ thuộc kernel
context.cache_dir             # nơi cache (asm/libcdb)
context.cyclic_size           # n mặc định của cyclic (đặt 8 cho 64-bit toàn cục)
with context.quiet:           # tắt log trong khối (gọn output)
    rop = ROP(exe)
```

> Đặt `context.cyclic_size = 8` một lần đầu script → khỏi truyền `n=8` mỗi lần `cyclic`.

---

## atexit — dọn dẹp khi thoát

**Công dụng:** đăng ký hành động chạy khi script kết thúc (đóng kết nối, in log, kill process).

```python
import pwnlib.atexit as atexit
atexit.register(lambda: log.info("script kết thúc"))
# pwntools tự đóng tube khi thoát; dùng khi cần dọn thêm (file tạm, ssh...)
```

---

## flag — nộp flag (vài nền tảng)

```python
from pwnlib.flag import submit_flag
# submit_flag("CTF{...}")   # nếu cấu hình endpoint của giải (ít dùng, tuỳ nền tảng)
```

Thường chỉ cần `print` flag; module này cho giải có API nộp.

---

## adb — Android (bài mobile pwn)

```python
import pwnlib.adb as adb
adb.wait_for_device()
adb.push("./exploit", "/data/local/tmp/")
p = adb.process("/data/local/tmp/exploit")   # tube tới process trên thiết bị
adb.pull("/data/.../flag", "./flag")
```

**Dạng bài:** pwn binary ARM/Android qua `adb`. Cần thiết bị/emulator + `adb`.

---

## serialtube — qua cổng COM (bài hardware/embedded)

```python
from pwnlib.tubes.serialtube import serialtube
p = serialtube("/dev/ttyUSB0", baudrate=115200)   # tube như mọi tube khác
```

---

## Còn nữa ở đâu

pwntools còn module hiếm dùng cho CTF phổ thông: `pwnlib.rop.srop` (SROP các arch khác),
`pwnlib.runner`, `pwnlib.replacements`, `pwnlib.commandline` (lệnh CLI `pwn template`,
`pwn checksec`, `pwn cyclic`, `pwn shellcraft`, `pwn disasm`...).

```bash
pwn template ./chall > exploit.py   # sinh khung exploit
pwn cyclic 200 ; pwn cyclic -l 0x6161616161616166
pwn checksec ./chall
pwn shellcraft -f asm amd64.linux.sh
pwn disasm '4831ff'
```

---

## Mẹo nhanh

- `pwn template ./chall` tạo khung exploit chuẩn (process/remote/gdb + args) — khởi đầu nhanh.
- Debug tất định: `context.aslr=False` + `gdb.debug`.
- `context.cyclic_size=8` đầu script cho bài 64-bit.
- Lệnh CLI `pwn ...` tiện khi không muốn mở Python (cyclic/checksec/shellcraft/disasm).

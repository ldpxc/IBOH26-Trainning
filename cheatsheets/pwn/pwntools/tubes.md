# tubes — IO với tiến trình / remote

`tube` là kênh IO chung cho `process`, `remote`, `ssh`, `listen`. Mọi hàm `send*/recv*`
dùng **như nhau** bất kể local hay remote → viết 1 lần, đổi mục tiêu bằng 1 dòng.

---

## Mở kênh: `process / remote / ssh / listen`

| Hàm | Dùng khi | Ví dụ |
|-----|----------|-------|
| `process(argv, ...)` | chạy binary local | `process("./chall")` |
| `remote(host, port)` | đánh server qua TCP | `remote("1.2.3.4", 1337)` |
| `ssh(user, host, ...)` | chạy binary trên server qua SSH | `ssh('u','h',password='p')` |
| `listen(port)` | làm server (bài reverse / nhận kết nối) | `listen(4444)` |

```python
# process: tham số hữu ích
p = process("./chall",
            env={"LD_PRELOAD": "./libc.so.6"},  # nạp libc riêng
            aslr=False,                           # tắt ASLR để debug
            stdin=PTY)                            # cấp pty (bài đòi tty)
# remote + SSL
io = remote("host", 443, ssl=True, sni="host")
# ssh: lấy process trên server
sh = ssh("ctf", "host", password="pw")
p  = sh.process("/home/ctf/chall")
```

**Đổi local↔remote 1 dòng** (mẫu hay dùng):
```python
p = remote(*sys.argv[1:3]) if args.REMOTE else process(exe.path)
# chạy:  python3 x.py REMOTE host port
```

---

## Gửi: `send / sendline / sendafter / sendlineafter`

| Hàm | Làm gì |
|-----|--------|
| `send(x)` | gửi thô |
| `sendline(x)` | gửi + `\n` |
| `sendafter(delim, x)` | đợi thấy `delim` rồi `send(x)` |
| `sendlineafter(delim, x)` | đợi `delim` rồi `sendline(x)` ← **hay dùng nhất** |
| `sendthen(delim, x)` | gửi `x` rồi đọc tới `delim` |

`x` nhận `bytes`/`str`/`int` (pwntools tự `str`→bytes; **nên tự `p64` số** khi là địa chỉ).

```python
p.sendlineafter(b"Name: ", b"admin")
p.sendafter(b"> ", payload)                 # không thêm \n (payload nhị phân)
p.sendlineafter(b"choice: ", str(2))        # số -> gửi "2\n"
```

**Bản làm tay:**
```python
p.recvuntil(b"Name: "); p.send(b"admin\n")  # == sendlineafter(b"Name: ", b"admin")
```

---

## Nhận: `recv*`

| Hàm | Làm gì |
|-----|--------|
| `recv(n)` | đọc **tối đa** n byte (có thể ít hơn) |
| `recvn(n)` | đọc **đúng** n byte (đợi đủ) |
| `recvline(keepends=True)` | đọc 1 dòng (tới `\n`) |
| `recvuntil(delim, drop=False)` | đọc tới khi gặp `delim`; `drop=True` bỏ `delim` |
| `recvlines(n)` | đọc n dòng → list |
| `recvall(timeout)` | đọc tới EOF |
| `recvregex(pat, capture=False)` | đọc tới khi khớp regex |
| `recvline_contains(s)` / `recvline_startswith(s)` | đọc tới dòng chứa/bắt đầu bằng `s` |
| `recvpred(f)` | đọc tới khi `f(buffered)` đúng |
| `clean(timeout)` | vét sạch buffer đang chờ (bỏ rác) |

**Leak địa chỉ** — khuôn chuẩn:
```python
# "Leak: 0x7f...."  -> số hex dạng CHỮ
p.recvuntil(b"Leak: ")
libc_leak = int(p.recvline().strip(), 16)

# "...\x7f..." -> 6 byte địa chỉ dạng BYTE thô
p.recvuntil(b"data: ")
stack = u64(p.recv(6).ljust(8, b"\x00"))

# dùng regex bắt số hex bất kỳ
addr = int(p.recvregex(rb"0x[0-9a-f]+", capture=True).group(), 16)
```

> Mẹo: dùng `drop=True` để khỏi tự `.strip()`:
> `leak = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))`.

**Bản làm tay (dễ sai):**
```python
buf = p.recv(1000)                    # đọc mò, canh timing -> hay lệch
leak = int(buf.split(b"Leak: ")[1][:14], 16)
```

---

## `interactive()` — giao shell gõ tay

**Công dụng:** sau khi có shell/điều khiển, trả I/O cho bạn gõ trực tiếp. Luôn đặt **cuối**.

```python
p.interactive()
# gõ: cat flag.txt
```

---

## Timeout & context

```python
p.recvline(timeout=1)                 # giới hạn 1 giây rồi trả rỗng
with context.local(timeout=0.5):      # đặt timeout cho cả khối
    data = p.recvall()
context.log_level = "debug"           # IN mọi byte gửi/nhận (debug cực mạnh)
context.log_level = "error"           # tắt log ồn
```

---

## Tiện ích trên tube

```python
p.pid                     # PID tiến trình local
p.libs()                  # map thư viện + base (đọc /proc/pid/maps) -> lấy libc base khi debug
gdb.attach(p, "b *main")  # gắn gdb vào tube đang chạy (xem context.md)
p.close()
```

---

## Mẹo nhanh

- `recvuntil(delim)` **phải** khớp đúng chuỗi prompt, sai 1 ký tự là **treo**. Dùng
  `context.log_level="debug"` để copy prompt chính xác.
- Số là địa chỉ → `p64(...)` trước khi `send`; `sendline(str(n))` chỉ cho input số kiểu text.
- Bài đòi tty (`isatty`) → `process(..., stdin=PTY, stdout=PTY)`.
- Prompt lẫn rác → `p.clean(0.1)` trước khi gửi bước tiếp theo.

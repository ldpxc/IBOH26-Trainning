# ssh — chạy & khai thác binary trên server qua SSH

**Công dụng:** khi đề cho tài khoản SSH (nhiều wargame: pwnable.kr, pwn.college, HTB), pwntools
cho bạn chạy binary từ xa, upload/download file, lấy libc server, port-forward — **như local**.
**Dạng bài:** challenge host qua SSH, cần libc/đường dẫn thật của server.

---

## Mở phiên & chạy process

```python
sh = ssh(user="ctf", host="host", port=22, password="pw")   # hoặc keyfile="~/.ssh/id"
p  = sh.process("/challenge/bin", env={"X": "1"})            # chạy binary trên server -> tube
# dùng p.send/recv như process local
p.sendline(payload); p.interactive()
```

| Tham số `ssh(...)` | Ý nghĩa |
|---|---|
| `user`, `host`, `port` | đăng nhập |
| `password` / `keyfile` | mật khẩu hoặc khoá |
| `proxy_command` / `proxy_sock` | qua bastion |

| Phương thức | Làm gì |
|-------------|--------|
| `sh.process(argv, env=, cwd=)` | chạy binary → tube (hay dùng nhất) |
| `sh.run(cmd)` / `sh.system(cmd)` | chạy lệnh shell |
| `sh[...]` / `sh('id')` | chạy nhanh 1 lệnh, trả output |
| `sh.download(remote, local)` | tải file server về (lấy **libc/binary** thật) |
| `sh.upload(local, remote)` | đẩy file lên |
| `sh.libs(path)` | map thư viện của binary trên server |
| `sh.set_working_directory()` | tạo thư mục tạm + cd vào (ghi file) |
| `sh.interactive()` | shell SSH thủ công |

---

## Lấy libc THẬT của server (ret2libc remote)

```python
sh = ssh("ctf", "host", password="pw")
# tải libc server về để có đúng offset
sh.download("/lib/x86_64-linux-gnu/libc.so.6", "./libc_server.so.6")
libc = ELF("./libc_server.so.6", checksec=False)
# hoặc lấy map luôn
libs = sh.libs("/challenge/bin")     # {path: base}
```

> **Cơ chế khớp offset (hay sai nhất ở ret2libc remote):** offset `system/binsh` tính theo
> **đúng file libc server**. Muốn chạy *local* mà khớp server thì phải tải **cả `libc.so.6` lẫn
> `ld-linux.so`** của server rồi ép binary dùng chúng:
> ```python
> sh.download("/lib/x86_64-linux-gnu/libc.so.6", "./libc.so.6")
> sh.download("/lib64/ld-linux-x86-64.so.2", "./ld.so")
> # chạy local với đúng loader+libc của server:
> p = process([ "./ld.so", "./chall" ], env={"LD_PRELOAD": os.path.abspath("./libc.so.6")})
> # (hoặc patchelf --set-interpreter ./ld.so --set-rpath . ./chall)
> ```
> Chạy thẳng `sh.process` trên server thì khỏi lo khớp — nhưng khi debug local phải làm bước này.

**Bản làm tay:** `scp` tay rồi nhớ đường dẫn — pwntools gộp vào script, 1 chỗ.

---

## Chạy binary cục bộ nhưng nhạ tầng của server (upload exploit)

```python
sh = ssh("ctf", "host", password="pw")
d = sh.set_working_directory()        # /tmp/xxxx trên server, đã cd
sh.upload("./exploit_helper", "./h")  # đẩy công cụ
p = sh.process("./h")
```

---

## Port forward (service sau SSH)

```python
sh = ssh("ctf", "host", password="pw")
# mở cổng local 9000 -> localhost:1337 trên server
l = sh.connect_remote("localhost", 1337)   # tube tới service nội bộ server
```

---

## Mẹo nhanh

- `sh.process(path)` cho tube **y hệt** `process` local → viết exploit 1 lần, đổi `process`↔
  `sh.process` là xong.
- Luôn `sh.download` libc + ld của server để offset khớp (ret2libc remote).
- `sh.set_working_directory()` khi cần ghi file (binary đọc file cạnh nó).
- Prompt SSH chậm → tăng `context.timeout` hoặc dùng `recvuntil` đúng mốc.

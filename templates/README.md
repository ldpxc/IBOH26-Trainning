# Templates exploit

Khung sẵn để copy khi bắt đầu một exploit mới. Tất cả theo **chuẩn farm**: nhận target qua tham số, **in flag ra stdout** (mỗi dòng 1 flag) để `farm/run.py` gom và nộp.

| File | Dùng cho |
| --- | --- |
| [exploit_pwn.py](exploit_pwn.py) | pwn (pwntools, local/remote) |
| [exploit_web.py](exploit_web.py) | web (requests) |
| [exploit_crypto.py](exploit_crypto.py) | crypto (oracle qua pwntools) |
| [writeup.md](writeup.md) | mẫu writeup (dùng cho `writeups/`) |

**Chuẩn gọi:** `python3 exploit.py <HOST> [FLAG_ID]` → in flag ra stdout, exit 0 nếu có flag. Lỗi 1 target không được làm sập cả farm (bọc try/except, có timeout).

Copy vào `exploits/<lane>/<tên-chall>/` khi dùng thật.

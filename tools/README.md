# tools/ — công cụ cá nhân (bản lưu trữ)

Bản sao để dành. Bản đang chạy thật nằm ở `~/hoc/CTF/Tools/pwnld/` và được symlink
vào `~/.local/bin/`. Sửa bản chạy → nhớ copy lại vào đây.

## [`adflag.py`](adflag.py) / [`adflag.md`](adflag.md)

Thư viện siêu nhẹ dành cho toàn đội (**Web / Crypto / Rev / Misc**) để tự động lấy target và nộp flag tức thì về Attack Console theo chuẩn `[FLAG] <flag>`.
- Xem hướng dẫn chi tiết từng trường hợp tại: **[`adflag.md`](adflag.md)**.
- Dùng nhanh: `from adflag import submit; submit(r.text)`.

## [`pwnld.py`](pwnld.py)

Lớp helper mỏng bọc pwntools (`from pwnld import *`). Tra cứu nhanh trong terminal:
`python3 pwnld.py --help` (theo chủ đề: `--help start|modes|io|leaks|fmt|retry`, hoặc
`--help all`). Bản tham chiếu đầy đủ: [`cheatsheets/pwn/pwntools/pwnld.md`](../cheatsheets/pwn/pwntools/pwnld.md).

## [`genscr`](genscr)

Sinh nhanh `exploit.py` + symlink `pwnld.py` (và `pwnretry.py` ở chế độ retry) vào
thư mục hiện tại, rồi mở nvim.

```bash
genscr <chall>                         # exploit.py 1-shot thường
genscr -c <name>                       # pwncollege mode
genscr -x <chall>                      # preset pwnable.xyz

genscr <binary> retry [shell|flag|parallel]   # khung retry sạch
genscr <exploit.py> retry [shell|flag]        # convert bản 1-shot sang retry
```

Chế độ retry dùng khung [`exploits/pwn/retry/pwnretry.py`](../exploits/pwn/retry/) — xem
README ở đó để biết chọn loại nào. `convert` giữ bản cũ thành `exploit_not_retry.py`,
tự tách setup/`attempt`, chỗ khó để lại `# TODO(retry)`.

### Phụ thuộc / cần chỉnh khi mang sang máy khác
Trong file có vài đường dẫn tuyệt đối (sửa cho khớp máy):

- `PWNLD_SRC_DEFAULT` → đường dẫn `pwnld.py` nguồn.
- `PWNRETRY_SRC_DEFAULT` → mặc định `pwnretry.py` cùng thư mục với `genscr`.
- Cùng thư mục `genscr` cần có `pwnld.py`, `pwnretry.py` (và `pwncollege.py` nếu dùng `-c`).

Cài nhanh: để `genscr`, `pwnld.py`, `pwnretry.py` chung một thư mục rồi
`ln -s <thư-mục>/genscr ~/.local/bin/genscr`.

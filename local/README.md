# local/ — sân chơi cá nhân (không push)

`local/.gitignore` chặn mọi thứ trong đây trừ 2 file `.gitignore` và `README.md` này. Làm bừa gì cũng được — xong thì copy tay phần đáng giữ ra repo chính.

```
local/
  labs/         # hướng dẫn lab step-by-step để tự học & làm theo (HT1.md, HT2.md, ...)
  infra/        # nơi thực hành Docker/Compose/deploy/backup/monitor (mirror infra/ ở repo chính)
  exploits/     # nháp exploit theo lane, chưa chắc chạy ổn
    pwn/ web/ crypto/ rev/
  refs/         # symlink tới tài liệu/tutorial NGOÀI đã có sẵn trên máy (đọc, không sửa)
    pwn/ -> /home/ld/hoc/CTF/learn/pwnable  (tutorial BOF/FSB/heap/advance + CheatSheet/Tools.pdf)
  scratch/      # mọi thứ khác không rõ xếp đâu — test lệnh, note rời, binary đang nghịch
```

**Quy ước copy ra ngoài khi xong:**

| Từ `local/...` | Ra repo chính |
| --- | --- |
| `infra/*` | `infra/` (sau khi đạt tiêu chí HT_x) |
| `exploits/<lane>/<tên>/` | `exploits/<lane>/<tên>/` (khi exploit chạy ổn) |
| ghi chú trong `labs/` | không copy — đây là guide để đọc, không phải sản phẩm |
| `refs/` | không copy — chỉ là symlink đọc tutorial, không thuộc repo này |
| bài học/snippet đáng nhớ | gõ tay vào `cheatsheets/<mảng>.md` ở repo chính |

Đang luyện: xem [`labs/HT1.md`](labs/HT1.md).

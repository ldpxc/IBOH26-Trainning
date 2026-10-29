# farm — exploit farm & replay (DW5)

Tự động hoá công: chạy exploit mọi IP đối thủ mỗi tick, gom & nộp flag.

```
farm/
  submit.py        # nhận flag từ stdin → nộp (nc gameserver 6666) → trả trạng thái
  get_targets.py   # đọc target/flag-id mỗi tick từ API/file sân chơi (fixture JSON nếu chưa có)
  run.py           # mỗi tick gọi exploit từng target (timeout, tách lỗi, loại flag trùng, log)
  replay.py        # bắn lại request đã bắt trong lab, đổi target/ID rồi submit
  README.md
```

- Exploit lấy từ `exploits/<lane>/` (chuẩn: in flag ra stdout).
- Lỗi/vá 1 target **không** được làm farm dừng; mọi request có timeout để không lấn tick sau.
- Nộp flag chỉ tính từ máy đội mình. **Không hardcode** flag/token/IP giải thật.
- Tham khảo: DestructiveFarm.

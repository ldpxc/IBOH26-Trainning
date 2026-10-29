# Cheatsheet — Attack-Defense (đặc thù)

> Cross-category, ai cũng nắm. Nền cho `farm/` và các phiên mô phỏng Tuần 2.

## Nộp flag
```bash
nc gameserver 6666            # chỉ tính từ máy đội mình
# định dạng flag + phản hồi: ghi vào ops/submit.md sau khi kiểm chứng
```

## Bắt traffic đối thủ → steal exploit
```bash
sudo tcpdump -i <iface> -s 0 -w steal.pcap 'tcp port <PORT>'
tshark -r steal.pcap -Y http -V        # tách payload
```

## Farm & replay (xem farm/)
- Lấy target/flag-id mỗi tick từ gameserver → nạp vào farm.
- Mỗi exploit chạy mọi IP đối thủ mỗi tick, tự nộp flag; lỗi 1 target không làm chết farm.
- `replay.py`: bắn lại payload bắt được, đổi target/flag-id — không cần hiểu exploit.

## Đường lui khi KHÔNG pwn được black box (ưu tiên mỗi tick)
1. Giữ service sống trước (SLA là điểm chắc).
2. Có exploit sẵn → chạy farm nộp flag.
3. Đang bị đánh → bắt payload, replay + xem chỗ lộ để vá.
4. Bí thật → bỏ qua, chuyển service khác. **Không đốt cả tick vào 1 black box.**

<!-- Thêm mẹo vận hành của đội bên dưới -->

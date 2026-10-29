# Cheatsheet — Deploy / Backup / Monitor / Traffic

> HT3–HT6. Giữ SLA sống khi vận hành.

## Deploy / rollback (HT3)
```bash
./deploy.sh <v1|v2>     # đổi tag image rồi: docker compose up -d --no-deps app
./rollback.sh           # quay lại tag trước
# đo gián đoạn:
while true; do curl -s -o /dev/null -w "%{http_code}\n" localhost:PORT; sleep 1; done
```

## Backup / restore (HT4)
```bash
./backup.sh <outdir>    # code/config + tag image + dump.rdb + checksum + timestamp
./restore.sh <archive>  # dừng stack → phục hồi → up → /health
```
- Nén thư mục source **chưa phải** backup DB → phải export Redis/DB riêng.
- Để bản backup **ngoài** thư mục sẽ xoá khi restore.

## Monitor (HT5)
```bash
./watch.sh <url> <interval>   # poll, in UP/DOWN, kêu khi chết
docker stats                  # CPU/RAM theo container
ss -ltnp                      # cổng đang nghe
```
- Container "running" ≠ endpoint sống → luôn check `/health` thật.

## Traffic (HT6)
```bash
sudo tcpdump -i any -s 0 -w cap.pcap 'tcp port <PORT>'
tshark -r cap.pcap -Y http -V
# Wireshark → Follow TCP Stream
```
- Docker không ra `any` → bắt interface bridge (`ip route`, `docker network inspect`).
- **Không commit** capture thật của trận (chứa flag/token) — xem `.gitignore`.

<!-- Thêm mục của đội bên dưới -->

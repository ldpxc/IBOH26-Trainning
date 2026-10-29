# Cheatsheet — Docker & Compose

> Nền cho HT1–HT2. Chỉ ghi lệnh đã tự chạy thật.

## Docker cơ bản
```bash
docker build -t <img>:<tag> .
docker run -d --name <name> -p 127.0.0.1:<host>:<cont> <img>:<tag>
docker ps                     # container đang chạy
docker logs -f <name>         # xem log
docker exec -it <name> sh     # vào trong container
docker cp <name>:/path ./     # copy file ra/vào
docker stop <name> && docker rm <name>
```

## Compose
```bash
docker compose up -d --build
docker compose ps             # trạng thái + health
docker compose logs --tail=50 -f <svc>
docker compose exec <svc> <cmd>
docker compose down           # giữ volume
docker compose down -v        # XOÁ volume (mất dữ liệu!) — cẩn thận
```

## Bẫy hay gặp
- `down -v` xoá volume → mất flag/DB. Mặc định chỉ dùng `down`.
- Map cổng ra `127.0.0.1` khi test local để không lộ ra ngoài.
- `restart: unless-stopped` + `healthcheck` để service tự sống lại.

## HT1 — recreate nhanh (đã test thật 29/10)
```bash
docker stop <name> && docker rm <name>
docker run -d --name <name> -p 127.0.0.1:<host>:<cont> <img>:<tag>   # không cần build lại
```
- Sau khi `rm`, request cũ sẽ `connection refused` — bình thường, không phải lỗi.
- Xem bài mẫu: `infra/Dockerfile` + `infra/app/app.py` + `infra/evidence/HT1.md`.

<!-- Thêm mục của đội bên dưới -->

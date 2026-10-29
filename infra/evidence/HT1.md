# HT1 — Docker

- **Người làm:** <điền tên> · **Ngày:** 29/10/2026
- **File:** `infra/Dockerfile`, `infra/app/app.py`, `infra/app/requirements.txt`

## Lệnh đã chạy

```bash
cd infra
docker build -t iboh-lab:v1 .
docker run -d --name iboh-app -p 127.0.0.1:18080:8000 iboh-lab:v1
docker ps --filter name=iboh-app
curl -fsS localhost:18080/health      # {"ok":true}
curl -fsS localhost:18080/version     # v1
curl -fsS localhost:18080/flag        # {"flag":"IBOH{demo_flag_ht1}"}
docker logs iboh-app
docker exec iboh-app cat /app/flag.txt
docker stop iboh-app && docker rm iboh-app
curl -fsS --max-time 2 localhost:18080/health   # connection refused — đúng
docker run -d --name iboh-app -p 127.0.0.1:18080:8000 iboh-lab:v1   # chạy lại = đúng 1 lệnh ban đầu
curl -fsS localhost:18080/health      # {"ok":true} — sống lại
```

## Kết quả
- `curl /health` trả `{"ok":true}` **trước và sau** khi tạo lại container. ✅
- `docker ps` thấy container khi đang chạy, mất khi đã `rm`. ✅
- Kill rồi chạy lại bằng **đúng 1 lệnh** `docker run ...` (không cần build lại vì image `iboh-lab:v1` đã có). ✅

## Lỗi gặp & cách xử lý
- Không gặp lỗi. Image build sạch từ `python:3.12-slim`, không cache stale (test build từ đầu).

## Trạng thái
**ĐẠT.**

# infra — lab hạ tầng HT1–HT7 (Tuần 1)

Nơi làm các lab vận hành trong README mục 1. Cấu trúc gợi ý:

```
infra/
  ENV.md              # phiên bản docker/compose/python đã kiểm
  app/                # Flask app dùng xuyên suốt HT1–HT6
  Dockerfile
  compose.yaml
  scripts/            # deploy.sh rollback.sh backup.sh restore.sh watch.sh
  evidence/           # HT1.md ... HT7.md (lệnh đã chạy + output + bằng chứng)
```

Mỗi `HTx.md` ghi: người làm, ngày, lệnh, output quan trọng, lỗi & cách xử lý. Chưa chạy thật = `CHƯA ĐẠT`.

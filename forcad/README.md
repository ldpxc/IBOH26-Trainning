# forcad — trọng tài (DW1)

Cấu hình ForcAD của đội.

```
forcad/
  VERSION.md    # commit/tag ForcAD đã pin + ngày clone
  config.*      # config đúng phiên bản (3 team, tick 300s, flag lifetime 5 nếu hỗ trợ)
  README.md     # lệnh setup/start/stop thực chạy + tên field đã xác minh
```

- **Đừng giả định** `config.yml`, cổng 8080 hay giao thức submit — đọc README/source đúng commit rồi mới ghi.
- ForcAD ngốn thời gian → tạm dùng harness local gọi checker mỗi 300s để luyện HT7/DW4, tích hợp lại sau.
- **Không commit token/credential.**

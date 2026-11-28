# Dữ liệu đội

Thư mục này chứa dữ liệu đội dùng cho kịch bản nhiều mục tiêu/lab.

## `teams.yaml`

Mỗi đội có tối thiểu:

- `name`: tên đội.
- `ip`: IP của đội.
- `web`: link web chính của đội.

Ví dụ:

```yaml
teams:
  - name: "team01"
    ip: "10.10.1.1"
    web: "http://10.10.1.1:8080"
```

## Cách dùng

Xem trước danh sách đội:

```bash
python scripts/run_teams.py --teams-file data/teams.yaml --dry-run
```

Chạy exploit trên nhiều đội:

```bash
python scripts/run_teams.py --teams-file data/teams.yaml --workers 5
```

## Mở rộng

Bạn có thể thêm field theo nhu cầu, ví dụ:

```yaml
  - name: "team01"
    ip: "10.10.1.1"
    web: "http://10.10.1.1:8080"
    base_url: "http://10.10.1.1:8080"
    auth:
      username: "admin"
      password: "password"
    note: "target chính"
```

> Chỉ dùng dữ liệu này trên hệ thống bạn được phép kiểm thử.

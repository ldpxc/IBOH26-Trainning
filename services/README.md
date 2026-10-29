# services — service để luyện AD (DW0)

Service đội tự dựng để cắm vào ForcAD (Tuần 2). Mỗi service một thư mục:

```
services/<tên>/
  Dockerfile / compose
  <mã nguồn>
  README.md     # port, cách chạy, request bình thường, vị trí flag, PoC khai thác
```

- Bắt đầu 1 web service (lưu/đọc flag hợp lệ + 1 endpoint lỗi), rồi mở rộng 3–5 service phủ web/pwn/crypto/rev.
- Mỗi đội một instance riêng, **không dùng chung volume flag**.
- Binary pwn/rev: chỉ giao binary cho defender trong sim; **giữ bản gốc source** ở chỗ người tổ chức.

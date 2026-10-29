# patches — bản vá (HT7 + Drill Vá-Sống)

Lưu bản vá cho từng service/binary để tái dùng và kiểm tra lại.

```
patches/<service>/
  before            # bản gốc (hoặc diff)
  after             # bản đã vá
  poc.*             # exploit phải THẤT BẠI sau vá
  legit_request.*   # request hợp lệ phải THÀNH CÔNG sau vá
  NOTES.md          # 6 mốc: backup → vá → test exploit → test chức năng → deploy → verify
```

- Chỉ sửa code/binary (không `Dockerfile`/`compose`). Binary: giữ offset, xác nhận hash sau deploy.
- Xem quy trình chi tiết: [`cheatsheets/patching.md`](../cheatsheets/patching.md).

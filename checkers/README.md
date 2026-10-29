# checkers — checker ForcAD (DW4)

Checker cho từng service ở `services/`. Mỗi service một thư mục:

```
checkers/<service>/
  checker.py    # check / put / get (đúng tên hàm của phiên bản ForcAD đang dùng)
  README.md     # giao thức + câu lệnh test
```

- `put`: lưu flag mới qua chức năng hợp lệ, trả ID. `get`: đọc lại flag bằng ID. `check`: liveness bằng dữ liệu bình thường, **không** phụ thuộc exploit.
- Nghiệm thu: 5 tick xanh liên tục, 2 flag khác nhau không lẫn, vá lỗ hổng xong checker vẫn xanh.

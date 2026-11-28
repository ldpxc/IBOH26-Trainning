# LAN File Share

Dịch vụ web chia sẻ file trong mạng LAN (chạy trên Linux, client Windows/macOS/Linux đều truy cập được qua trình duyệt).

## Cách chạy bằng script quản lý

```bash
cd /home/ld/hoc/CTF/training/AD/iboh26/lan-share

# Khởi động chạy nền (tự sinh mật khẩu nếu không truyền --password)
./lanshare.sh start --password "MatKhauCuaBan"

# Kiểm tra trạng thái & xem lại IP/Port/Mật khẩu
./lanshare.sh status

# Xem log
./lanshare.sh logs

# Khởi động lại hoặc dừng
./lanshare.sh restart --password "MatKhauCuaBan"
./lanshare.sh stop
```

Nếu không truyền `--password`, chương trình sẽ tự tạo một mật khẩu ngẫu nhiên và in ra màn hình khi khởi động.

### Các tùy chọn

- `--host`: Địa chỉ bind (mặc định `0.0.0.0` để mọi máy trong LAN truy cập được).
- `--port`: Cổng web (mặc định `27491`).
- `--dir`: Thư mục làm kho lưu trữ file (mặc định `./shared_files`, tự tạo nếu chưa có).
- `--password`: Mật khẩu xác thực (hoặc dùng biến môi trường `LAN_SHARE_PASSWORD`).

## Lưu ý tường lửa trên Linux

Nếu máy Windows trong cùng LAN không kết nối được, hãy mở cổng trên Linux (ví dụ cổng `27491`):

```bash
sudo ufw allow 27491/tcp
```

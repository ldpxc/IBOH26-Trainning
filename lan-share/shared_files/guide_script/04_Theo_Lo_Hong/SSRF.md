# SSRF (lừa server tự gửi request hộ mình)

Một số trang có chức năng "nhập 1 URL để server tải giúp" — ví dụ dán link ảnh vào để làm avatar, hoặc 1 webhook báo cho server khác khi có việc mới. Server sẽ tự gửi 1 request HTTP tới URL bạn đưa, rồi trả kết quả về cho bạn xem. Nếu server không kiểm tra URL đó trỏ tới đâu, bạn có thể đưa vào `http://127.0.0.1/` hoặc `http://localhost/` — 2 địa chỉ này luôn nghĩa là "chính máy server đó" — thế là bạn lừa được server tự gửi request tới **chính nó** hoặc tới các máy nội bộ khác mà bình thường bạn không thể truy cập trực tiếp từ ngoài Internet. Đây gọi là SSRF — Server-Side Request Forgery (server bị lừa tự giả mạo request thay cho mình).

Trên Burp bạn nhận ra lỗi này khi: trang có tham số kiểu `url=`, `image=`, `callback=`, `webhook=`... và khi bạn đổi giá trị thành địa chỉ nội bộ (`127.0.0.1`, `localhost`, hoặc địa chỉ 1 service nội bộ khác), response trả về nội dung khác hẳn so với 1 URL bên ngoài thật (ví dụ thấy trang quản trị nội bộ, hoặc service nào đó đang chạy ở đó) — nghĩa là server đã thật sự gửi request tới chỗ bạn muốn.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Các địa chỉ hay dùng để thử SSRF:
    # 127.0.0.1 / localhost -> chính máy server đang chạy app web
    # 169.254.169.254       -> địa chỉ đặc biệt chỉ có ý nghĩa trên cloud (AWS/GCP...), đọc được thông tin cấu hình máy
    targets = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",  # chỉ thử nếu nghi target chạy trên cloud
    ]
    for t in targets:
        r = session.post(f"{base_url}/fetch", data={"url": t}, timeout=5)
        print(t, "->", r.status_code, "len=", len(r.text))
        print(r.text[:150])
        # so sánh độ dài/nội dung giữa các target -- cái nào khác hẳn (ví dụ dài hơn, có chữ lạ) là nghi vấn
    return None


if __name__ == "__main__":
    solve_one(s, base)
```

## Giải thích cho người mới

- `targets` là danh sách các địa chỉ "nội bộ" hay được thử đầu tiên khi test SSRF — vì chúng gần như luôn có mặt (mọi server đều có `127.0.0.1` là chính nó), không cần biết trước mạng nội bộ thật của target trông như thế nào.
- Mỗi lần gửi, in cả `status_code`, `len(r.text)` (độ dài response) và 150 ký tự đầu — vì SSRF thường không trả về flag ngay, mà trả về *nội dung của trang khác* mà server đã âm thầm tải hộ bạn; so sánh độ dài/nội dung giữa các địa chỉ khác nhau giúp nhận ra "chỗ nào có gì đó" để đi sâu tiếp.
- Hàm chỉ in ra, không tự tìm flag — vì bước tiếp theo (đọc được gì ở `127.0.0.1`, service nào đang chạy ở đó) cần nhìn response thật rồi mới quyết định bước kế tiếp là gì (ví dụ nếu có service nội bộ chạy ở cổng khác, thử đổi `t` thành `http://127.0.0.1:8080/` v.v.).

## Lưu ý nhanh

- Thử các tên tham số khác nhau nếu `url=` không đúng: `path=`, `image=`, `endpoint=`, `webhook=`, hoặc field trong JSON body — xem đúng tên Burp đã bắt được.
- Dòng `169.254.169.254` chỉ có ý nghĩa khi target thật sự chạy trên dịch vụ cloud (AWS/GCP/Azure) — nếu target chạy local/VM thường thì bỏ qua dòng này, không cần lo không hiểu.
- Kết quả SSRF không nhất thiết hiện ngay trong response (có thể "out-of-band" — server gửi request đi nhưng không trả kết quả về cho bạn thấy); nếu nghi vậy, cần 1 server lắng nghe riêng để nhận callback (nằm ngoài phạm vi file này).
- Trong thi Attack-Defense, không quét dải địa chỉ nội bộ quá rộng (ví dụ thử hết 256 địa chỉ liên tiếp) vì gây tải nặng, ồn, dễ bị phát hiện — chỉ thử các địa chỉ có mục đích rõ ràng.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

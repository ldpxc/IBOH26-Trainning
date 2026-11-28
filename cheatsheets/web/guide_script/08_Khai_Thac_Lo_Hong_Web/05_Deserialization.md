# Deserialization (giải nén gói dữ liệu không an toàn)

> Chỉ test trên hệ thống/lab được phép.

## Lỗ hổng này là gì

"Serialize" là đóng gói 1 object (1 cục dữ liệu có cấu trúc, trong code) thành 1 chuỗi để gửi đi hoặc lưu lại (ví dụ lưu vào cookie, gửi qua mạng). "Deserialize" là mở gói đó ra, dựng lại đúng object ban đầu để dùng tiếp. Một số cách đóng gói (ví dụ `pickle` trong Python, `unserialize` trong PHP, Java serialization) không chỉ phục hồi dữ liệu thường — chúng còn cho phép **chạy code** trong lúc mở gói, tùy vào những gì nằm bên trong gói.

Nếu server nhận 1 gói dữ liệu từ bạn (cookie, token, field ẩn trong form) và mở nó ra mà không kiểm tra trước, bạn có thể tự tạo 1 gói giả — như gói quà dán kín ghi "đồ chơi trẻ em dùng pin", nhưng người nhận không mở ra xem trước, cứ cắm pin vào theo đúng như nhãn ghi. Nếu bên trong thực ra là thứ khác (ví dụ có dây nối ra ổ điện), người mở gói đã bị bạn điều khiển làm theo ý bạn muốn mà không hề biết.

## Nhìn vào đâu để nghi ngờ có lỗ hổng này

- Cookie/token có vẻ là 1 chuỗi dài, không phải JWT (JWT thường có dạng `xxx.yyy.zzz`, 3 đoạn base64 nối bằng dấu chấm, decode ra là JSON đọc được).
- Giá trị dạng base64 dài, giải mã ra thấy ký tự lạ không giống JSON/text bình thường — ví dụ bắt đầu bằng `O:` hoặc `a:` (PHP serialize), hay có các byte không in được xen giữa (Python pickle, Java serialization thường có 1 "header" đặc trưng ở đầu).
- Field ẩn trong form (`<input type="hidden" name="state" value="...">`), tham số tên `data=`, `state=`, `object=`, `view=`.
- Bất kỳ nơi nào server "lưu lại trạng thái" và gửi ngược về cho bạn, rồi bạn gửi nó lại ở request sau.

## Cách test nhanh bằng tay trên Burp

1. Tìm được giá trị nghi là gói dữ liệu, thử decode base64 (nếu có) rồi nhìn nội dung bên trong — có thấy format giống PHP serialize (`O:8:"ClassName":...`) hay Python pickle (ký tự lạ, không phải text) không.
2. Sửa 1 ký tự nhỏ trong gói đó (không hiểu rõ cấu trúc cũng cứ sửa thử) rồi gửi lại — nếu server trả lỗi 500 kiểu "parse error"/"unserialize failed" thay vì từ chối gọn gàng, chứng tỏ nó đang thực sự cố mở gói ra, không chỉ so sánh chuỗi.
3. Nếu biết đúng định dạng và ngôn ngữ server dùng (đoán qua header `Server`, lỗi, hoặc đề bài CTF cho biết), có thể tự tạo 1 gói giả chứa lệnh muốn chạy — phần này cần công cụ chuyên dụng theo ngôn ngữ (ví dụ `ysoserial` cho Java), không làm tay được.

## Script copy-paste có sẵn

Xem [`Deserialization.md`](../04_Theo_Lo_Hong/Deserialization.md) trong `04_Theo_Lo_Hong/` — có code Python đầy đủ cho Python `pickle` (tự viết `__reduce__()`, không cần công cụ ngoài), và hướng dẫn dùng công cụ sinh sẵn (`phpggc` cho PHP, `ysoserial` cho Java) khi bài không phải Python.

## Cách sửa (nếu bạn là người phòng thủ/DEF)

Cách sửa chắc nhất: đừng gửi object đã đóng gói cho client giữ, chỉ gửi 1 ID ngẫu nhiên (session ID), còn dữ liệu thật giữ ở server. Nếu buộc phải gửi trạng thái ra ngoài, chỉ dùng JSON (chỉ phục hồi dữ liệu thường, không chạy được code) và luôn kiểm tra chữ ký (ký bằng khóa bí mật của server) **trước khi** mở gói ra đọc, không phải sau. Tuyệt đối không dùng `pickle.loads`/`unserialize` trên dữ liệu đến từ người dùng.

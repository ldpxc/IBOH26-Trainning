# Auth / Logic Flaw (IDOR, session, JWT, lỗi quy trình)

> Chỉ test trên hệ thống/lab được phép.

## Lỗ hổng này là gì

Nhóm lỗi này không phải "chèn code lạ vào", mà là server **quên kiểm tra** 1 điều hiển nhiên: "dữ liệu/hành động này có đúng là của người đang gửi request không?". Phổ biến nhất gọi là IDOR (Insecure Direct Object Reference): web cho bạn xem đơn hàng bằng `?order_id=1001`, bạn chỉ cần đổi số thành `1002` là xem được đơn hàng của người khác — vì server chỉ kiểm tra "có đơn hàng số 1002 không", chứ không kiểm tra "đơn hàng 1002 có phải của bạn không".

Giống việc bạn đến nhận phòng khách sạn, lẽ ra nhân viên phải kiểm tra thẻ phòng của bạn đúng số phòng bạn đặt; nhưng ở đây nhân viên chỉ hỏi "anh muốn vào phòng số mấy?" rồi đưa chìa khóa đúng số đó cho bất kỳ ai hỏi, không kiểm tra người hỏi có đặt phòng đó hay không.

## Nhìn vào đâu để nghi ngờ có lỗ hổng này

- URL/API có số ID lộ ra: `/api/orders/1001`, `/users/42/profile`, `/invoice?id=55` — thử đổi số đó sang số khác (của người khác, hoặc +1/-1) xem có đọc được dữ liệu không phải của mình không.
- Request login, quên mật khẩu: token reset password nằm trong URL, hoặc không hết hạn, hoặc không gắn với đúng user.
- Cookie/token session không đổi sau khi login, hoặc vẫn dùng được sau khi logout/đổi mật khẩu.
- JWT trong cookie/header `Authorization: Bearer ...` — token dạng `xxx.yyy.zzz`, decode phần giữa (base64) ra thấy JSON có field như `"role":"user"`, `"user_id":5`.
- Form nhiều bước (giỏ hàng → thanh toán → hoàn tất) — thử gọi thẳng bước cuối mà bỏ qua bước giữa.
- Field ẩn/field trong JSON body có tên nhạy cảm: `role`, `is_admin`, `price`, `balance`, `owner_id` mà client tự gửi lên.

## Cách test nhanh bằng tay trên Burp

1. **IDOR**: đăng nhập 2 tài khoản (A và B) trong lab. Lấy request của A xem 1 object của chính A, rồi sửa ID trong request đó (vẫn dùng cookie của A) thành ID thuộc về B, gửi lại — nếu đọc được dữ liệu của B, đó là IDOR.
2. **JWT**: decode phần giữa token (chạy `echo <phần_giữa> | base64 -d` hoặc dùng tab JWT trong Burp/jwt.io offline), sửa `"role":"user"` thành `"role":"admin"`, encode lại, gửi token mới lên — nếu server không kiểm chữ ký mà vẫn tin, bạn vừa leo quyền.
3. **Bỏ bước quy trình**: ghi lại URL của bước cuối cùng (ví dụ `/order/complete`), gọi trực tiếp URL đó với 1 đơn hàng mới tạo mà chưa thanh toán — nếu đơn hàng vẫn chuyển sang "đã hoàn tất", server đang tin client thay vì tự kiểm tra trạng thái.

## Script copy-paste có sẵn

Xem [`IDOR_Access_Control.md`](../04_Theo_Lo_Hong/IDOR_Access_Control.md) trong `04_Theo_Lo_Hong/` — có sẵn script thử đổi ID theo 1 danh sách và kiểm tra response có lộ dữ liệu không. Phần sửa JWT tự tay có ví dụ code đầy đủ ở [`00_Bat_Dau_Tu_Zero.md`](../00_Bat_Dau_Tu_Zero.md) mục 5, ví dụ 2.

## Cách sửa (nếu bạn là người phòng thủ/DEF)

Mọi chỗ server trả dữ liệu theo 1 ID, phải kiểm tra thêm "ID này có thuộc về người đang đăng nhập không" ngay trong câu truy vấn (ví dụ `WHERE id = %s AND owner_id = %s`), không chỉ kiểm tra "ID này có tồn tại không". Với JWT, server phải tự kiểm tra chữ ký của token mỗi lần nhận, không bao giờ tin nội dung bên trong token khi chưa xác minh chữ ký đúng. Với quy trình nhiều bước (thanh toán, duyệt đơn...), server phải tự lưu và kiểm tra trạng thái hiện tại trước khi cho sang bước tiếp theo, không chỉ dựa vào thứ tự client gọi API.

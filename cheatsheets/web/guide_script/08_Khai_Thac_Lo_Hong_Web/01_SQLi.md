# SQL Injection (SQLi)

> Chỉ test trên hệ thống/lab được phép.

## Lỗ hổng này là gì

Database lưu dữ liệu bằng các câu lệnh gọi là SQL, ví dụ "lấy sản phẩm có id = 5". Nhiều web lười làm đúng cách: lấy số bạn gõ vào ô tìm kiếm rồi **dán thẳng** vào câu lệnh đó.

Giống việc bạn điền vào mẫu đơn in sẵn: "Tìm khách hàng có mã số: ______". Nhân viên cứ đọc nguyên văn bạn viết gì vào đó rồi làm theo, không kiểm tra bạn có viết đúng "mã số" hay không. Nếu bạn viết vào ô đó dòng chữ "5; và xóa luôn hồ sơ của mọi khách khác", nhân viên vẫn cứ làm theo đúng như thế vì không ai dạy họ phải nghi ngờ. SQL Injection là y như vậy, chỉ khác người "nhân viên" ở đây là database.

## Nhìn vào đâu để nghi ngờ có lỗ hổng này

- URL có dạng `?id=5`, `?product=12`, `?category=3` — bất kỳ chỗ nào lấy 1 con số hoặc 1 tên để **tra cứu** dữ liệu (xem chi tiết sản phẩm, tìm kiếm user, lọc theo category...).
- Có ô tìm kiếm (search box), ô lọc, ô sắp xếp (`?sort=name`).
- Trang login — ô username/password.
- Bất kỳ chỗ nào web đọc dữ liệu ra "theo 1 điều kiện" mà điều kiện đó là thứ bạn gõ vào.

## Cách test nhanh bằng tay trên Burp

Bắt request đó trong Burp Repeater, rồi sửa giá trị tham số đó và gửi lại, so sánh response:

1. Gửi giá trị bình thường, ví dụ `id=5` — nhớ response (status, độ dài, nội dung).
2. Gửi `id=5'` (thêm 1 dấu nháy đơn) — nếu trang trả lỗi 500, trang trắng, hoặc thông báo lỗi liên quan SQL (nhắc tới "syntax", "mysql", "query"...) thì rất đáng nghi.
3. Gửi `id=5' OR '1'='1` — nếu kết quả trả về **nhiều hơn** bình thường (ví dụ hiện toàn bộ sản phẩm thay vì 1 sản phẩm), đó gần như chắc chắn là SQLi: bạn vừa thêm điều kiện "hoặc 1=1 (luôn đúng)" vào và server tin theo.

Nếu web dùng số mà không có dấu nháy (ví dụ `id=5` không bọc trong `'...'`), đổi sang gõ `id=5 OR 1=1` (không cần dấu nháy) rồi so sánh tương tự.

## Script copy-paste có sẵn

Xem [`SQLi.md`](../04_Theo_Lo_Hong/SQLi.md) trong `04_Theo_Lo_Hong/` — có sẵn script Python test 1 loạt payload và script UNION để đọc dữ liệu.

## Cách sửa (nếu bạn là người phòng thủ/DEF)

Không ghép chuỗi vào câu SQL. Dùng "câu lệnh có chỗ trống" (prepared statement / parameterized query): bạn viết sẵn câu lệnh với dấu `%s` hoặc `?` ở chỗ cần điền, rồi đưa giá trị người dùng gõ vào riêng — thư viện sẽ tự đảm bảo giá trị đó chỉ được hiểu là dữ liệu, không bao giờ biến thành 1 phần câu lệnh mới. Nếu web có chức năng sắp xếp theo tên cột (`?sort=name`), đừng cho khách tự gõ tên cột tùy ý — chỉ cho chọn trong 1 danh sách cố định (ví dụ chỉ "name" hoặc "created_at") rồi mới ghép vào câu lệnh.

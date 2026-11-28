# SQL Injection (SQLi)

## 1. Bản chất

SQL Injection xảy ra khi dữ liệu do người dùng kiểm soát được đưa vào câu lệnh SQL mà **không được tách khỏi phần cú pháp truy vấn**. Ứng dụng mong muốn nhận một giá trị như `42`, nhưng chuỗi nhập vào lại làm thay đổi cấu trúc câu SQL.

Điều kiện thường gặp:

1. Có input từ query, form, JSON, header, cookie hoặc giá trị lưu trước đó.
2. Input được ghép vào SQL bằng string concatenation/formatting.
3. Không có parameterized query/prepared statement đúng cách, hoặc có nhưng dùng sai ở một số nhánh.
4. Tài khoản database của ứng dụng có quyền lớn hơn mức cần thiết.

Ví dụ nguy hiểm:

```python
# Chỉ minh họa lỗi, không dùng trong ứng dụng thật
user_id = request.args["id"]
query = "SELECT id, name FROM products WHERE id = " + user_id
```

Cách đúng:

```python
cursor.execute(
    "SELECT id, name FROM products WHERE id = %s",
    (user_id,),
)
```

Parameterized query không chỉ là escape chuỗi: **giá trị và cú pháp được truyền theo hai kênh khác nhau**.

## 2. Các dạng chính

| Dạng | Dấu hiệu quan sát được | Cách kiểm chứng trong lab |
|---|---|---|
| Error-based | Thông báo lỗi SQL, stack trace, khác biệt rõ khi cú pháp sai | So sánh input hợp lệ, input làm cú pháp sai và input đối chứng |
| Union-based | Dữ liệu từ truy vấn bổ sung được ghép vào response | Xác định số cột và kiểu cột bằng dữ liệu mẫu, không dump dữ liệu thật |
| Boolean-based blind | Response khác nhau theo điều kiện đúng/sai, không hiện lỗi | Hai điều kiện biết trước TRUE/FALSE, đo nhiều lần |
| Time-based blind | Thời gian phản hồi thay đổi theo điều kiện | Baseline nhiều lần, độ trễ nhỏ, loại trừ nhiễu mạng |
| Out-of-band | Server tạo kết nối phụ khi truy vấn chạy | Chỉ dùng listener do bạn kiểm soát trong lab |
| Second-order | Input lưu ở một request, được đưa vào SQL ở request sau | Theo dõi vòng đời dữ liệu từ create/update đến màn hình/report khác |

Không phải SQLi nào cũng trả dữ liệu trực tiếp. Blind SQLi thường chỉ cho một bit thông tin qua trạng thái response.

## 3. Vị trí cần kiểm tra

- Query: `id`, `sort`, `filter`, `search`, `category`.
- Form/JSON: đăng nhập, tìm kiếm, report, import.
- Path: `/product/123`, `/users/{name}`.
- Header/cookie: `X-User-Id`, `Referer`, cookie preference nếu được đưa vào truy vấn.
- Tham số điều khiển câu SQL ở mức khác: tên cột sắp xếp, chiều `ASC/DESC`, tên bảng/report.

Lưu ý: **tham số hóa giá trị không tự động tham số hóa tên cột, tên bảng hoặc toán tử**. Các phần này cần allowlist riêng.

## 4. Quy trình nhận diện có kiểm chứng

### Bước 1: Lưu baseline

Chọn input hợp lệ và ghi:

- Status code.
- Nội dung và chiều dài body.
- Các field JSON/HTML liên quan.
- Thời gian phản hồi.
- Cookie/CSRF nếu có.

Ví dụ baseline trong lab:

```http
GET /product?id=1 HTTP/1.1
Host: target
```

### Bước 2: Thử thay đổi cú pháp tối thiểu

Trong lab, các chuỗi kinh điển thường được dùng để quan sát parser:

```text
1
1'
1"
1)
1' AND '1'='1
1' AND '1'='2
```

Mục đích của cặp cuối là tạo hai truy vấn có cùng hình thức nhưng điều kiện khác nhau. Không kết luận chỉ vì một dấu `'` gây lỗi: lỗi có thể đến từ validation, framework hoặc proxy.

### Bước 3: Đối chứng

Một kết quả đáng tin thường có:

- Input hợp lệ → response A.
- Điều kiện TRUE → gần response A.
- Điều kiện FALSE → response B khác có hệ thống.
- Lặp lại nhiều lần vẫn giữ xu hướng.

Nếu chỉ thấy `500` một lần, hãy kiểm tra log ứng dụng trong lab trước khi gọi là SQLi.

### Bước 4: Xác định ngữ cảnh

Cùng một payload không dùng được cho mọi ngữ cảnh:

- Giá trị số: `id = 1`.
- Chuỗi: `name = 'alice'`.
- Có ngoặc: `WHERE id IN (...)`.
- `LIKE '%input%'`.
- Câu lệnh có nhiều điều kiện và comment khác nhau giữa MySQL/PostgreSQL/SQLite/MSSQL.

Hãy suy ra truy vấn từ hành vi, thông báo lỗi trong lab và tài liệu schema; không thử hàng loạt payload khi chưa hiểu ngữ cảnh.

## 5. Khai thác có kiểm soát trong lab

### 5.1. Union-based

Quy trình khái niệm:

1. Xác định truy vấn gốc trả bao nhiêu cột.
2. Tìm kiểu dữ liệu tương thích cho từng cột.
3. Đưa một **bảng dữ liệu giả** do bạn tạo vào kết quả.
4. Chứng minh có thể thay đổi tập kết quả, rồi dừng.

Ví dụ chuỗi thường gặp trong bài lab (chỉ minh họa):

```text
1' ORDER BY 2-- -
1' UNION SELECT NULL,NULL-- -
1' UNION SELECT 'probe_a','probe_b'-- -
```

Cần điều chỉnh số cột, quote và comment cho DBMS cụ thể. Không dùng bước này để liệt kê bảng hoặc lấy dữ liệu người dùng thật.

### 5.2. Error-based

Trong lab có thể bật log SQL và so sánh:

- Input hợp lệ.
- Input làm mất cân bằng quote.
- Input đã được sửa lại cú pháp.

Bằng chứng tốt là log cho thấy input xuất hiện trong câu SQL ở vị trí cú pháp, không chỉ một thông báo lỗi chung.

Không nên đưa lỗi SQL chi tiết ra production: ngoài rò rỉ schema, nó còn giúp kẻ tấn công tinh chỉnh payload.

### 5.3. Boolean-based blind

Giả sử lab trả trang "có sản phẩm" khi điều kiện đúng và trang rỗng khi sai:

```text
1' AND '1'='1'-- -
1' AND '1'='2'-- -
```

Nên đo:

- Một marker xuất hiện/không xuất hiện.
- Trạng thái HTTP.
- Chiều dài body sau khi loại bỏ phần ngẫu nhiên.
- Nhiều mẫu lặp lại để tránh cache.

Không suy diễn nội dung database ngoài phạm vi bài lab. Một bit TRUE/FALSE đã đủ để chứng minh cơ chế.

### 5.4. Time-based blind

Cú pháp delay khác nhau tùy DBMS; chỉ dùng hàm delay của lab với thời gian nhỏ và timeout rõ ràng. Cách kiểm chứng:

1. Gửi baseline ít nhất 5 lần.
2. Gửi điều kiện không delay và có delay xen kẽ.
3. So median, không so một request duy nhất.
4. Loại trừ cold start, connection pool, rate limit và tải nền.

Nếu ứng dụng có timeout ngắn hơn delay, kết quả có thể không đáng tin. Không tăng delay để "cho chắc" trên hệ thống dùng chung.

## 6. Filter và bypass: cách hiểu đúng

Filter thường chặn từ khóa, dấu nháy, khoảng trắng hoặc comment. Khi tài liệu nói "bypass filter", trước hết cần phân loại:

- **Canonicalization:** ứng dụng decode một hay nhiều lần trước khi kiểm tra.
- **Parser khác biệt:** WAF, web server và DBMS hiểu chuỗi khác nhau.
- **Ngữ cảnh:** filter chỉ áp dụng cho một field hoặc một method.
- **Blacklist thiếu:** chặn một từ khóa nhưng vẫn cho phép thay đổi cú pháp bằng cách khác.

Trong lab, ghi lại **dạng input trước khi gửi, dạng sau mỗi lớp decode và dạng trong SQL log**. Không nên học bypass như một danh sách chuỗi ma thuật.

Double encoding là ví dụ về pipeline:

```text
%2527
  -- decode lần 1 --> %27
  -- decode lần 2 --> '
```

Nếu ứng dụng chỉ decode một lần thì không được tự decode thêm trong client rồi kết luận sai.

## 7. Bằng chứng cần lưu

- Endpoint, tham số và giá trị baseline.
- Request đã che cookie/token.
- Cặp TRUE/FALSE hoặc request gây lỗi và request đối chứng.
- DBMS và phiên bản nếu được phép xác định trong lab.
- Tác động tối thiểu: thay đổi kết quả, vượt điều kiện, đọc được bản ghi test.
- Những gì **chưa** kiểm tra: không dump toàn bộ DB, không ghi/xóa, không leo quyền OS.

Ví dụ mô tả tốt:

> Tham số `id` tại `GET /product` được đưa vào truy vấn mà không tham số hóa. Trên bản dựng lab, cặp điều kiện TRUE/FALSE tạo hai response khác biệt lặp lại 5/5 lần. Chỉ kiểm chứng với bảng `products` và dữ liệu mẫu; không truy cập bảng khác.

## 8. Khắc phục

### Bắt buộc

- Prepared statement/parameterized query cho mọi giá trị.
- ORM đúng cách; tránh raw SQL nếu không cần.
- Allowlist cho tên cột, hướng sort, toán tử.
- Kiểm tra kiểu dữ liệu trước khi truy vấn, nhưng không coi validation là thay thế tham số hóa.

Ví dụ allowlist cho sort:

```python
sort_columns = {"name": "name", "created_at": "created_at"}
directions = {"asc": "ASC", "desc": "DESC"}
column = sort_columns.get(request.args.get("sort"), "id")
direction = directions.get(request.args.get("dir"), "ASC")
# Chỉ hai giá trị đã allowlist mới được ghép vào câu lệnh.
query = f"SELECT id, name FROM products ORDER BY {column} {direction} LIMIT %s"
cursor.execute(query, (50,))
```

### Bổ sung

- Tài khoản DB tối thiểu quyền.
- Tách quyền đọc/ghi theo service.
- Không trả lỗi SQL cho client.
- Log an toàn, không log mật khẩu/token.
- Test cả REST, GraphQL, export/report và code path cũ.
- Rà soát stored procedure và dynamic SQL bên trong DB.

## 9. Checklist

- [ ] Có baseline và cặp đối chứng.
- [ ] Đã xác định ngữ cảnh số/chuỗi/ngoặc/LIKE.
- [ ] Không nhầm lỗi validation với SQL error.
- [ ] Blind có đủ mẫu và kiểm soát nhiễu.
- [ ] Không encode hai lần khi tái hiện bằng Python.
- [ ] Không lấy dữ liệu thật để làm bằng chứng.
- [ ] Sửa bằng parameterized query + allowlist phần định danh.
- [ ] Có test hồi quy cho endpoint và code path tương tự.

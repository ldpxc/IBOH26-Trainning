# Lỗi xác thực, phân quyền và nghiệp vụ (Auth / Logic Flaw)

## 1. Bản chất

Nhóm này xảy ra khi ứng dụng xác định sai **ai đang thực hiện hành động**, **được phép làm gì**, **trên tài nguyên nào**, hoặc **ở trạng thái nào của quy trình**.

Cần tách ba câu hỏi:

1. **Authentication:** bạn là ai?
2. **Authorization:** bạn có quyền thực hiện hành động này không?
3. **Business logic/state:** hành động này có hợp lệ ở thời điểm và ngữ cảnh hiện tại không?

Một request đã đăng nhập vẫn có thể vi phạm authorization. Một request đúng quyền vẫn có thể vi phạm logic nghiệp vụ, ví dụ đổi trạng thái đơn hàng theo thứ tự không hợp lệ.

## 2. IDOR / BOLA

### 2.1. Khái niệm

IDOR/BOLA xảy ra khi server dựa vào ID do client cung cấp để truy cập object mà không kiểm tra object đó có thuộc quyền của principal hiện tại không.

Ví dụ khái niệm:

```http
GET /api/orders/1001
Cookie: session=user_a
```

Nếu `1001` thuộc user B và server trả dữ liệu cho user A, đó là dấu hiệu BOLA. ID không nhất thiết là số tăng dần: UUID, slug, email, hash hoặc tên file vẫn có thể bị IDOR nếu biết/đoán được.

### 2.2. Cách kiểm chứng an toàn bằng hai tài khoản

Trong lab:

1. Tạo user A và user B.
2. User A tạo object `order_A` với dữ liệu giả.
3. User B tạo object `order_B`.
4. User B request object của A bằng ID đã biết.
5. So với request object của chính B và request không đăng nhập.

Ma trận tối thiểu:

| Request | Kỳ vọng an toàn |
|---|---|
| A đọc A | Cho phép |
| B đọc B | Cho phép |
| B đọc A | Từ chối |
| Anonymous đọc A | Từ chối |
| B sửa/xóa A | Từ chối |

Dùng dữ liệu marker vô hại như `ORDER_A_LAB`; không đọc object của người dùng thật.

### 2.3. Không chỉ GET

Kiểm tra:

- GET/POST/PUT/PATCH/DELETE.
- Export, download, share, preview.
- GraphQL query/mutation.
- WebSocket/subscription.
- Endpoint admin và API nội bộ.
- ID nằm trong body thay vì URL.
- Quan hệ lồng nhau: `order_id` + `item_id`.

### 2.4. Sửa đúng

- Authorization ở server cho **mọi object và mọi action**.
- Truy vấn gắn với owner/tenant ngay từ đầu.
- Kiểm tra cả quan hệ parent-child.
- Dùng policy thống nhất, không dựa vào UI ẩn nút.
- Không cho rằng UUID khó đoán là authorization.

Ví dụ khái niệm:

```python
order = db.query(
    "SELECT * FROM orders WHERE id = %s AND tenant_id = %s",
    (order_id, current_tenant_id),
)
if order is None:
    return not_found()
# Sau đó vẫn kiểm tra action có được phép với role/trạng thái không.
```

`404` hay `403` là lựa chọn chính sách; quan trọng là không trả dữ liệu hoặc thực hiện action trái quyền.

## 3. Bypass đăng nhập và account recovery

### 3.1. Dấu hiệu cần kiểm tra

- So sánh response đúng/sai có làm lộ user tồn tại không.
- Có nhánh code bỏ qua password/MFA khi thiếu field hoặc đổi kiểu dữ liệu không.
- Login có rate limit, lockout và chống automation hợp lý không.
- Reset token có entropy, expiry, single-use và gắn với đúng user không.
- Đổi email/password có yêu cầu xác thực lại không.
- MFA có bị bỏ qua ở API/mobile/legacy flow không.

Không thử credential stuffing hoặc brute force trên tài khoản thật. Dùng tài khoản lab và giới hạn số request.

### 3.2. Lỗi thường gặp trong quên mật khẩu

- Token trong URL không hết hạn.
- Token dùng lại được sau khi reset.
- Có thể thay `user_id` trong request reset.
- Reset link dự đoán được.
- Host header ảnh hưởng link reset mà không kiểm soát.
- Sau reset, session cũ vẫn có hiệu lực ngoài chính sách.

Bằng chứng tối thiểu nên dùng hai tài khoản test và token do bạn nhận được hợp lệ trong lab.

## 4. Session và cookie

### 4.1. Nhận diện

- Session ID đổi sau login/privilege change không?
- Logout có invalidate server-side không?
- Session có timeout idle/absolute không?
- Cookie có `HttpOnly`, `Secure`, `SameSite` phù hợp không?
- Session cũ còn dùng sau đổi mật khẩu/reset không?
- Có session cố định trước login được nâng quyền sau login không?

### 4.2. Sửa đúng

- Tạo session ID mới sau xác thực và thay đổi đặc quyền.
- ID ngẫu nhiên đủ entropy, không chứa thông tin nhạy cảm.
- Invalidate khi logout, reset password, thu hồi quyền.
- Cookie scope tối thiểu, không đưa session vào URL/log.
- Có cơ chế revoke khi cần, không chỉ dựa vào expiry dài.

## 5. JWT

JWT là format token, không tự động an toàn. Ba phần gồm header, payload, signature; payload thường chỉ được encode, **không mặc nhiên được mã hóa**.

### 5.1. Điểm kiểm tra

- Verify signature ở mọi endpoint dùng token.
- Allowlist algorithm phía server; không tin algorithm do token tự khai báo.
- Kiểm tra `iss`, `aud`, `exp`, `nbf`, `iat` theo chính sách.
- Không nhầm decode payload với xác thực token.
- Key rotation/kid có kiểm soát.
- Secret đủ mạnh, không hard-code.
- Access token và refresh token có mục đích/thời hạn/revocation phù hợp.
- Quyền trong claim có được kiểm tra lại với trạng thái hiện tại khi cần.

### 5.2. Cách kiểm chứng an toàn

Trong lab, dùng token của chính bạn:

1. Lưu request với token hợp lệ.
2. Thử token hết hạn do lab tạo.
3. Thử token của user khác trong cùng lab.
4. Thay đổi claim và quan sát có bị từ chối do chữ ký không.
5. Kiểm tra thuật toán/khóa qua cấu hình, không brute force secret thật.

Không dùng token thật để đăng lên công cụ online; payload có thể chứa thông tin nhạy cảm.

## 6. Lỗi logic nghiệp vụ

### 6.1. Bỏ qua bước xử lý

Ví dụ quy trình:

```text
cart -> shipping -> payment -> review -> complete
```

Lỗi có thể là gọi trực tiếp `complete` mà server không kiểm tra payment đã thành công. Client-side wizard không phải state machine bảo mật.

Cách kiểm chứng:

- Tạo object test ở trạng thái ban đầu.
- Gọi bước hợp lệ làm baseline.
- Gọi bước sau khi bỏ bước giữa.
- Kiểm tra state/database/log trong lab.
- Đảm bảo không tạo giao dịch thật.

### 6.2. Thao túng giá trị

Các field cần đặc biệt xem xét:

- `price`, `total`, `discount`, `tax`, `currency`.
- `quantity`, `stock`, `points`, `balance`.
- `role`, `is_admin`, `owner_id`, `tenant_id`.
- `status`, `approved`, `paid`, `verified`.

Giá trị nhạy cảm phải được tính hoặc xác nhận ở server từ dữ liệu tin cậy. Không nhận `is_admin=true` chỉ vì client gửi lên.

Kiểm tra số âm, zero, giá trị rất lớn, số thập phân, tràn kiểu, currency khác và giá đã thay đổi giữa các bước — tất cả trên dữ liệu giả trong lab.

### 6.3. Race condition

Nếu hai request đồng thời có thể cùng vượt qua kiểm tra "chỉ một lần", đó là lỗi nguyên tắc:

```text
read state -> check -> write state
```

Ví dụ: redeem coupon, chuyển điểm, vote, claim reward.

Cách sửa:

- Transaction và row/record locking phù hợp.
- Unique constraint idempotency key.
- Atomic compare-and-set/update.
- Kiểm tra kết quả commit, không chỉ check trước.
- Retry an toàn cho client để không tạo tác dụng phụ.

Race test phải giới hạn số request, dùng tài nguyên test, reset state sau mỗi lần và không gây quá tải.

### 6.4. Replay và idempotency

Một request hợp lệ bị gửi lại có tạo thêm hiệu ứng không? Cần:

- Nonce/idempotency key cho thao tác nhạy cảm.
- Ràng buộc key với user/action/payload.
- Lưu kết quả xử lý để retry trả cùng kết quả.
- Không dùng chống replay làm lý do bỏ authorization.

## 7. Mass assignment và parameter pollution

Hai lỗi hay đi cùng logic/auth:

- **Mass assignment:** framework bind toàn bộ JSON/form vào model, cho phép sửa field nhạy cảm như `role`, `owner_id`.
- **Parameter pollution:** nhiều giá trị cùng key khiến các lớp chọn giá trị khác nhau.

Cách phòng thủ:

- DTO/allowlist field cho từng action.
- Không bind trực tiếp request vào entity.
- Xác định rõ semantics khi key trùng và validate lại ở lớp authorization.
- Kiểm tra cả JSON body, form và nested object.

## 8. Ma trận kiểm thử đề xuất

| Kịch bản | Tài khoản | Object | Kỳ vọng |
|---|---|---|---|
| Đọc object của mình | A | A | Cho phép nếu đúng policy |
| Đọc object người khác | A | B | Từ chối |
| Sửa quyền của mình qua field ẩn | A | A | Không được đổi role/owner |
| Gọi bước sau khi bỏ bước trước | A | A | State không đổi |
| Gửi lại request một lần | A | A | Không tạo hiệu ứng lặp ngoài thiết kế |
| Token hết hạn/thu hồi | A | A | Từ chối |
| Không đăng nhập | Anonymous | A/B | Từ chối |

Mỗi test cần reset state và ghi request/response tối thiểu. Không dùng tài khoản/object của người khác ngoài lab.

## 9. Khắc phục ở thiết kế

- Centralized authorization policy.
- Default deny.
- Tenant/owner check trong data access layer.
- State machine server-side cho workflow.
- Server tính giá trị nhạy cảm.
- Transaction/constraint cho invariant.
- Idempotency và audit log.
- Test authorization cho mọi endpoint, không chỉ test chức năng thành công.
- Review API cũ/mobile/GraphQL/admin vì thường bỏ sót policy.

Audit log nên ghi actor, object, action, kết quả và thời gian; không log password/token/secret.

## 10. Báo cáo tối thiểu

Mô tả rõ:

- Principal A/B và quyền từng bên.
- Object test và quan hệ sở hữu.
- Request được phép và request vượt quyền.
- Response/state thay đổi chứng minh tác động.
- Có thể lặp lại hay phụ thuộc race.
- Phạm vi chưa kiểm tra và dữ liệu đã dùng là dữ liệu giả.
- Sửa ở policy/data query/state machine, không chỉ ẩn UI hoặc đổi ID khó đoán.

## 11. Checklist

- [ ] Dùng hai tài khoản và object test.
- [ ] Kiểm tra cả đọc, sửa, xóa, export và action phụ.
- [ ] Anonymous, user thường, user khác tenant và admin được tách rõ.
- [ ] Session/JWT kiểm tra expiry, revoke, algorithm/claim.
- [ ] Workflow được enforce ở server.
- [ ] Giá trị nhạy cảm không tin từ client.
- [ ] Race/replay có transaction/constraint/idempotency.
- [ ] Không giao dịch thật, không lấy dữ liệu thật.
- [ ] Có test hồi quy cho từng endpoint và policy.

# Authorization, phiên đăng nhập, CSRF và deserialization

> **Tóm tắt 1 phút:** Đăng nhập chỉ xác nhận danh tính; ứng dụng vẫn phải kiểm tra quyền trên từng object và từng hành động. Cookie/JWT là credential nên phải xác minh, quản lý vòng đời và chống request giả mạo phù hợp. Không giải tuần tự hóa object native từ dữ liệu người dùng. OWASP Top 10:2025 xếp Broken Access Control ở A01; API Security Top 10:2023 gọi lỗi quyền theo object là BOLA. ([OWASP A01:2025](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/))

Tất cả ví dụ dùng hai principal giả lập (Alice/Bob), token lab và service loopback. Snippet cố ý lỗi để review/lab; chưa chạy trong repo.

## 03 — Broken access control: IDOR/BOLA

**Combat ·** Dấu hiệu: request ID tra object toàn cục; không thấy owner/tenant/ACL/policy trước khi đọc, sửa hay xóa. PoC: Alice gọi object của Bob bằng ID local. Vá: object query hoặc service policy ràng buộc principal với hành động. UUID khó đoán không phải bản vá.

### Code lỗi và cách nhận ra

```python
@app.get("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)  # BUG: lookup toàn bảng
    return jsonify(invoice.to_public_dict())
```

Tìm `get(id)`, `findById`, query bằng request ID, nested resource và bulk IDs; lần xem authorization có kiểm tra đúng **object + action** không. Endpoint middleware cho phép role `user` không chứng minh user có quyền với mọi hóa đơn. ([OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html))

### PoC lab cục bộ

Giả sử DB lab seed invoice 101 của Alice và invoice 202 của Bob; endpoint dùng bearer token Alice:

```python
import requests
r = requests.get(
    "http://127.0.0.1:5000/api/invoices/202",
    headers={"Authorization": "Bearer ALICE_LAB_TOKEN"}, timeout=3,
)
print(r.status_code, r.text)  # bản lỗi trả hóa đơn giả của Bob
```

### Vá và vì sao

```python
@app.get("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id, owner_id=current_user.id
    ).first_or_404()
    return jsonify(invoice.to_public_dict())
```

Với chia sẻ/tenant, thay `owner_id` bằng authorization service đúng ACL. Principal phải đến từ session/token đã xác minh, không nhận `owner_id` từ body. Query ràng buộc object trong phạm vi user giúp mọi nhánh trả dữ liệu đi sau check. ([OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/))

**Hồi quy:** test ma trận Alice/Bob × GET/PATCH/DELETE, gồm object của mình, người khác và tenant khác; Alice không được đọc hoặc làm đổi invoice 202. Kiểm tra cả bulk/nested routes. Dùng 403 hoặc 404 theo chính sách app nhưng không rò data.

## 04 — Lỗi xác thực, session và JWT

**Combat ·** Dấu hiệu: `verify_signature=False`, algorithm lấy từ header token, bỏ qua `exp`/issuer/audience, claims dùng trước khi verify; session ID không xoay sau login. PoC: token `alg=none` chỉ hỏi route giả trên localhost. Vá: thuật toán allowlist cố định, verify claims bắt buộc, rồi mới tải principal; xoay/vô hiệu session.

### Code lỗi và cách nhận ra

```python
@app.get("/admin/whoami")
def whoami():
    token = request.headers["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})  # BUG
    return jsonify({"subject": claims.get("sub"), "role": claims.get("role")})
```

Đây là ví dụ bỏ xác minh rõ ràng. Trong code thật, kiểm tra verifier thực sự nhận key/algorithm đã cấu hình server-side và xác thực claim cần cho nghiệp vụ. JWT payload chỉ Base64URL-encode; đừng xem token là bí mật. PyJWT cảnh báo không lấy algorithm từ `alg` trong input. ([OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html))

### PoC lab cục bộ

```python
import base64, json, requests

def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "alice-lab", "role": "admin"}).encode())
token = header + "." + payload + "."
r = requests.get("http://127.0.0.1:5000/admin/whoami",
                 headers={"Authorization": "Bearer " + token}, timeout=3)
print(r.status_code, r.text)  # bản lỗi trả claims giả do client tự dựng
```

### Vá và vì sao

```python
claims = jwt.decode(
    token,
    key=JWT_PUBLIC_KEY,                 # key cấu hình phía server
    algorithms=["RS256"],              # allowlist cố định, không lấy từ token
    issuer="https://issuer.lab",
    audience="web-api",
    options={"require": ["exp", "sub"]},
)
user = db.session.get(User, claims["sub"])
if user is None or not user.is_active:
    abort(401)
# Áp dụng authorization riêng; không dùng claims chưa verify.
```

Verifier từ chối token không có chữ ký hợp lệ, token hết hạn/sai issuer/audience; sau đó app tải account đang hoạt động. Cấu hình `Secure`, `HttpOnly`, `SameSite` cho cookie session; xoay session ID sau login/đổi quyền và hủy ID cũ. JWT cần cơ chế revoke nếu cần logout tức thời. ([PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html), [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html))

```python
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
# Nếu dùng server-side session, gọi API regenerate/rotate của backend sau login
# và hủy session ID cũ; API cụ thể phụ thuộc thư viện session đang dùng.
```

**Hồi quy:** kiểm tra token hợp lệ, chữ ký sai, `alg=none`, thiếu/hết `exp`, sai `iss`/`aud` đều bị từ chối; session ID pre-login không dùng được sau login/logout. Đừng lưu credential nhạy cảm trong `localStorage`; XSS cùng origin có thể đọc.

## 05 — Cross-site request forgery (CSRF)

**Combat ·** Dấu hiệu: `POST/PUT/PATCH/DELETE` thay đổi trạng thái bằng cookie session nhưng không xác nhận token/nguồn request. PoC: HTML form trên origin loopback khác submit thay đổi email giả. Vá: CSRF middleware/token; SameSite và kiểm tra Origin là defense-in-depth, không thay token tổng quát.

### Code lỗi và cách nhận ra

```python
@app.post("/profile/email")
@login_required
def change_email():
    current_user.email = request.form["email"]
    db.session.commit()  # BUG: browser tự gửi cookie, route không check CSRF
    return "updated"
```

Tìm mọi state-changing route dùng cookie; GET không được làm đổi trạng thái. CSRF chủ yếu nhắm credential mà browser tự đính kèm (cookie). API chỉ dùng bearer header không tự gửi bởi browser có mô hình khác, nhưng kiểm tra lại refresh/session cookie và CORS. ([OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html))

### PoC browser lab cục bộ

Đăng nhập Alice giả vào app `127.0.0.1:5000`, rồi phục vụ trang dưới ở `127.0.0.1:8081` và mở bằng cùng browser profile. Hai port khác origin nhưng cùng site loopback; chỉ đổi dữ liệu lab.

```html
<!-- csrf-lab.html: chỉ post tới service loopback của bài lab -->
<form id="f" action="http://127.0.0.1:5000/profile/email" method="post">
  <input name="email" value="csrf-lab@example.test">
</form>
<script>document.getElementById("f").submit()</script>
```

Chạy trang tĩnh trong thư mục fixture riêng: `python3 -m http.server 8081 --bind 127.0.0.1 --directory ./csrf-fixture`. Trước vá, quan sát email Alice đổi thành địa chỉ `.test`; không dùng tài khoản thật.

### Vá và vì sao

```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)  # kiểm tra unsafe methods toàn cục
```

```html
<form method="post" action="/profile/email">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="email">
  <button>Save</button>
</form>
```

Token ngẫu nhiên do server cấp và gắn session; request xuyên site không biết token nên bị middleware từ chối. Dùng framework middleware, tránh tự so cookie với field. Cookie nên cấu hình `Secure`, `HttpOnly`, `SameSite=Lax` hoặc theo nhu cầu. Không exempt route nếu chưa có biện pháp tương đương. ([Flask-WTF CSRF](https://flask-wtf.readthedocs.io/en/latest/api/), [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html))

**Hồi quy:** form thiếu/sai token phải bị từ chối và email không đổi; form có token hợp lệ mới thành công. Test bằng browser để đánh giá cookie/origin thật; `curl` chỉ chứng minh middleware token, không tái tạo hành vi browser. GET không bao giờ đổi email.

## 12 — Insecure deserialization

**Combat ·** Dấu hiệu: bytes từ request/cookie/upload tới `pickle.loads`, `yaml.load` unsafe, PHP `unserialize`, Java `ObjectInputStream.readObject`. PoC harmless gọi `print` khi giải pickle cục bộ. Vá: JSON/data-only DTO, schema allowlist, giới hạn body; pickle không dành cho dữ liệu không tin cậy.

### Code lỗi và cách nhận ra

```python
@app.post("/import")
def import_state():
    raw = base64.b64decode(request.form["state"])
    state = pickle.loads(raw)  # BUG: pickle có thể gọi callable lúc dựng object
    return jsonify({"ok": True, "state": str(state)})
```

Tìm luồng đầu vào có thể bị user sửa đến native object reconstruction. Base64 không tạo tính toàn vẹn hay an toàn. Python cảnh báo pickle có thể thực thi code lúc unpickle; OWASP liệt kê các sink tương tự ở nhiều ngôn ngữ. ([Python pickle](https://docs.python.org/3/library/pickle.html), [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html))

### PoC lab cục bộ

```python
import base64, pickle, requests
class HarmlessProof:
    def __reduce__(self):
        return (print, ("LAB ONLY: pickle object reconstructed",))
blob = base64.b64encode(pickle.dumps(HarmlessProof())).decode("ascii")
r = requests.post("http://127.0.0.1:5000/import",
                  data={"state": blob}, timeout=3)
print("local lab status:", r.status_code)
# Bản lỗi in marker ở stdout process lab; không shell/file/network.
```

### Vá và vì sao

```python
raw = request.get_data(cache=False)
if len(raw) > 16_384:
    abort(413)
state = request.get_json()
if not isinstance(state, dict) or set(state) - {"theme", "page"}:
    abort(400)
if state.get("theme") not in {"light", "dark"}:
    abort(400)
```

JSON parse thành kiểu dữ liệu cơ bản, không dựng Python object từ payload. Schema/type/size check giới hạn input hợp lệ; không đưa dữ liệu parse thành class tùy ý, path hoặc query mà không validate tiếp. Nếu legacy dùng serialization, chỉ chấp nhận blob do server kiểm soát và có integrity protection an toàn; MAC không biến pickle thành format an toàn khi key bị lộ. ([OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html), [Python pickle](https://docs.python.org/3/library/pickle.html))

**Hồi quy:** blob pickle lab không còn được giải; invalid JSON, sai kiểu, field lạ và body quá lớn bị từ chối trước side effect. Kiểm tra stdout/state để chắc marker không xuất hiện.

## Nguồn và giới hạn

Ví dụ dùng Flask, SQLAlchemy, PyJWT và Flask-WTF làm một stack minh họa; tên API cần điều chỉnh theo phiên bản đang học. Source pattern là tín hiệu để review, không luôn chứng minh exploit được nếu một policy/service check chạy trước sink. Sources: [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/), [OWASP JWT](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).

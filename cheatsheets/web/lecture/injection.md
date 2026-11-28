# Injection — SQLi, XSS, command injection, SSTI

> **Tóm tắt 1 phút:** Bốn lỗi này xuất hiện khi dữ liệu do người dùng kiểm soát bị diễn giải thành cú pháp của SQL, trình duyệt, shell hoặc template engine. Hãy lần theo đường đi **source → sink**; vá ngay ở ranh giới bằng API có tham số/cú pháp tách biệt. Tài liệu OWASP Top 10:2025 xếp Injection ở A05; các lớp dưới cần cách vá riêng, không có một bộ lọc chung chữa được tất cả. ([OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/), [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html))

**Ví dụ xuyên suốt:** một service Flask cục bộ có catalog sản phẩm và trang greeting. Snippet cố ý lỗi để code review/lab; mọi PoC bên dưới chỉ gọi `127.0.0.1:5000` và dùng marker vô hại.

## 01 — SQL injection (SQLi)

**Combat ·** Dấu hiệu: `request.args`/JSON nối vào chuỗi đưa tới `execute`, `text()` hay query SQL động. Điều kiện: giá trị request có thể thay đổi cú pháp query. Proof: truy vấn `SELECT` trả thêm hàng seed giả với điều kiện luôn đúng. Bản vá: bind giá trị; tên cột/bảng phải lấy từ allowlist.

### Code lỗi và cách đọc

```python
@app.get("/search")
def search():
    q = request.args.get("q", "")
    sql = f"SELECT id, name FROM products WHERE name = '{q}'"  # BUG: input thành SQL syntax
    return jsonify([dict(r) for r in db.execute(sql).fetchall()])
```

Khi review, tìm f-string/nối chuỗi bên trong `execute()`; kiểm tra cả stored procedure và ORM API nhận raw SQL. Placeholder không thể thay thế tên bảng/cột hay `ORDER BY`, nên vị trí cú pháp động cần map qua allowlist, không lấy tùy ý từ client. ([OWASP SQLi Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [OWASP WSTG SQLi](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection/))

### PoC lab cục bộ

```python
import requests
BASE = "http://127.0.0.1:5000"  # cố định loopback; DB chỉ có hàng giả
r = requests.get(BASE + "/search", params={"q": "' OR '1'='1"}, timeout=3)
print(r.status_code, r.text)  # bản lỗi: thấy cả apple và pear đã seed
```

### Vá và hiểu vì sao

```python
rows = db.execute(
    "SELECT id, name FROM products WHERE name = ?", (q,)
).fetchall()
return jsonify([dict(r) for r in rows])
```

Driver gửi query structure và value riêng; dấu nháy/OR trong `q` trở thành nội dung tìm kiếm thay vì điều kiện SQL. Python `sqlite3` khuyến nghị placeholder và binding tham số. ([Python sqlite3](https://docs.python.org/3/library/sqlite3.html))

**Hồi quy:** seed hai dòng `apple`, `pear`; PoC ở trên không còn trả mọi dòng. Thử Unicode, dấu nháy và input dài; query vẫn không lỗi cú pháp, không phản hồi lỗi DB nội bộ cho client. Nếu order field tùy chọn, test mọi giá trị ngoài allowlist bị từ chối.

## 02 — Cross-site scripting (XSS)

**Combat ·** Dấu hiệu: dữ liệu không tin cậy đi vào `innerHTML`, `document.write`, event handler, template escape hatch (`|safe`, `dangerouslySetInnerHTML`, `v-html`) hoặc HTML dựng bằng nối chuỗi. Proof: marker JavaScript chỉ đặt `data-lab-xss` trong DOM local. Vá bằng autoescape đúng context hoặc DOM `textContent`; sanitizer chỉ khi thật sự cho phép rich HTML.

### Code lỗi và cách đọc

```python
@app.get("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<p>Hello {name}</p>"  # BUG: raw HTML interpolation
```

Trace input tới HTML body, thuộc tính, URL, JS string và DOM sink riêng biệt: một encoder HTML không an toàn cho tất cả context. Tìm luồng từ URL/hash/storage/API tới `innerHTML`/`insertAdjacentHTML`; nếu chỉ cần text, đó là sai sink. ([OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [OWASP DOM XSS](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html))

### PoC lab cục bộ

```python
from urllib.parse import quote
payload = "<script>document.body.dataset.labXss='ran'</script>"
print("Mở URL này trên browser local:")
print("http://127.0.0.1:5000/hello?name=" + quote(payload))
# DevTools trên trang lab: document.body.dataset.labXss === "ran"
```

Payload chỉ đặt marker DOM, không đọc cookie, gửi request hay đổi dữ liệu.

### Vá và hiểu vì sao

```python
# Flask view
return render_template("hello.html", name=name)
```

```html
<!-- templates/hello.html: autoescape mặc định của template HTML -->
<p>Hello {{ name }}</p>
```

Template tĩnh xử lý `name` như text và encode theo HTML context; không dùng `|safe` cho giá trị request. Trên client dùng `textContent`. CSP là lớp phụ trợ, không thay thế escaping. ([Flask templating](https://flask.palletsprojects.com/en/stable/templating/), [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html))

**Hồi quy:** trước vá marker làm `dataset.labXss` được đặt; sau vá payload hiện như chữ và marker không được đặt. Với DOM XSS, kiểm tra kết quả trong browser, không chỉ dò response HTML.

## 09 — OS command injection

**Combat ·** Dấu hiệu: request value tới `os.system`, `popen`, `subprocess(..., shell=True)`, `sh -c`, PHP `system/exec`. Proof: chỉ in `POC_OK` bằng lệnh `printf` thứ hai. Vá: xóa process nếu có API thuần ngôn ngữ; nếu cần process, dùng executable và argv cố định, `shell=False`, validation theo ngữ nghĩa chương trình.

### Code lỗi và cách đọc

```python
@app.get("/label")
def label():
    name = request.args.get("name", "")
    result = subprocess.run(
        f"printf 'label=%s\\n' {name}", shell=True,
        text=True, capture_output=True, timeout=2,
    )
    return result.stdout
```

Không dừng ở “đã quote shell”: dữ liệu có thể bị diễn giải như option của chương trình ngay cả khi shell parser đã bị bỏ. Theo dõi biến tainted tới lệnh và mọi đối số. Python nêu `shell=True` khiến ứng dụng chịu trách nhiệm quoting; OWASP khuyên tránh gọi OS command khi có thư viện. ([OWASP OS Command Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [Python subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations))

### PoC lab cục bộ

```python
import requests
r = requests.get(
    "http://127.0.0.1:5000/label",
    params={"name": "demo; printf POC_OK"}, timeout=3,
)
print(r.text)  # bản lỗi: xuất hiện thêm POC_OK
```

### Vá và hiểu vì sao

Nếu chỉ cần format nhãn, bỏ hẳn process:

```python
return f"label={name}\n"
```

Nếu thực sự cần công cụ, ưu tiên thư viện; nếu không, truyền list argv với tên executable cố định, `shell=False`, validate option/value và quyền process tối thiểu. Tách argv ngăn shell phân tích dấu `;`, nhưng không tự chặn option injection. ([Python subprocess](https://docs.python.org/3/library/subprocess.html#security-considerations), [OWASP OS Command Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html))

**Hồi quy:** trong container lab Linux, cùng marker không còn sinh lệnh thứ hai; input là text hoặc bị validation từ chối. Không dùng `id`, shell, file, mạng hay payload phá hoại trong minh chứng này.

## 10 — Server-side template injection (SSTI)

**Combat ·** Dấu hiệu: dữ liệu request ghép vào template source hoặc truyền vào `render_template_string`/`Environment.from_string`. Proof arithmetic `{{7*7}}` trả `49`. Vá bằng file template cố định và truyền input thành biến; output autoescape giảm XSS nhưng không vá template-source injection.

### Code lỗi và cách đọc

```python
@app.get("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("Hello " + name)  # BUG: user input là template
```

Phân biệt `{{ name }}` trong template cố định với `name` được nối vào chuỗi template trước khi compile. Tìm `from_string`, `render_template_string`, `createTemplate` và tương đương. Tác động tùy engine và object context được lộ. ([OWASP SSTI Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html), [Jinja API](https://jinja.palletsprojects.com/en/stable/api/#jinja2.Environment.from_string))

### PoC lab cục bộ

```python
import requests
r = requests.get(
    "http://127.0.0.1:5000/greet", params={"name": "{{7*7}}"}, timeout=3
)
print(r.text)  # bản lỗi: Hello 49
```

### Vá và hiểu vì sao

```python
# view
return render_template("greet.html", name=name)
```

```html
<!-- templates/greet.html -->
Hello {{ name }}
```

Engine compile source do ứng dụng sở hữu; `name` được truyền sau như data. Nếu sản phẩm thật sự cho phép user tự viết template, cần sandbox/engine ít quyền, context tối thiểu, không đưa secret hoặc object có side effect; không dùng escaping làm cách vá. ([Flask templating](https://flask.palletsprojects.com/en/stable/templating/), [Jinja sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/))

**Hồi quy:** bản lỗi trả `49`; bản vá hiển thị literal `{{7*7}}` sau khi escape. PoC dừng ở arithmetic; không nâng thành file access hoặc thực thi code.

## Mẫu giảng và nguồn

Dạy mỗi mục theo chuỗi: **30 giây nhận diện → code lỗi → PoC marker → code vá → invariant hồi quy**. Đây là bản compact theo Combat Card + giảng sâu trong [_CHUAN_VIET_BAIGIANG.html](../_CHUAN_VIET_BAIGIANG.html); các ví dụ trên minh họa source-to-sink, chưa được chạy. Nguồn chung: [OWASP Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html), [OWASP WSTG Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/).

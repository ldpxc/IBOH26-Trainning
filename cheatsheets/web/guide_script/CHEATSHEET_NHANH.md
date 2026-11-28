# Cheatsheet nhanh (5 giây)

Mở file này khi đang thi: **Burp đã chạy được → copy snippet → dán vào `solve_one()` trong `scripts/template.py`**.

| Đang cần làm gì trong Python? | Mở file | Cú pháp cốt lõi nhớ nhanh |
|---|---|---|
| Chưa biết Python / chưa biết exploit web, cần học trước | [`00_Bat_Dau_Tu_Zero.md`](00_Bat_Dau_Tu_Zero.md) | biến, hàm, dict, `import`, `requests.Session()` |
| Bắt đầu nhanh: quét `targets.txt`, lấy flag, lưu kết quả | [`scripts/template.py`](scripts/template.py) | `solve_one(session, base_url)` + `ThreadPoolExecutor(max_workers=4)` |
| GET query bình thường / sửa param | [`01_Request_Co_Ban/01_GET_Query.md`](01_Request_Co_Ban/01_GET_Query.md) | `s.get(url, params={"q":"test"}, timeout=5)` |
| GET tham số trùng tên / giữ thứ tự query | [`01_Request_Co_Ban/01_GET_Query.md`](01_Request_Co_Ban/01_GET_Query.md) | `urlencode([("id","1"),("id","2")])` rồi ghép vào URL |
| Gửi raw URL, tránh requests encode 2 lần | [`01_Request_Co_Ban/01_GET_Query.md`](01_Request_Co_Ban/01_GET_Query.md), [`01_Request_Co_Ban/05_Encoding.md`](01_Request_Co_Ban/05_Encoding.md) | `req=Request("GET", raw_url).prepare(); s.send(req)` |
| POST form / JSON / raw body | [`01_Request_Co_Ban/02_POST_Form_JSON.md`](01_Request_Co_Ban/02_POST_Form_JSON.md) | `data={...}` / `json={...}` / `data=raw.encode()` |
| Header, cookie, session, tắt redirect | [`01_Request_Co_Ban/03_Headers_Cookies_Session.md`](01_Request_Co_Ban/03_Headers_Cookies_Session.md) | `s=requests.Session(); s.post(..., allow_redirects=False)` |
| Upload file, đổi filename/Content-Type | [`01_Request_Co_Ban/04_Upload_File.md`](01_Request_Co_Ban/04_Upload_File.md) | `files={"file": ("a.php.jpg", b"...", "image/jpeg")}` |
| Encode/decode URL, Base64, Hex | [`01_Request_Co_Ban/05_Encoding.md`](01_Request_Co_Ban/05_Encoding.md) | `quote/unquote`, `base64.b64encode`, `binascii.hexlify` |
| Login giữ phiên / token Bearer | [`02_Chuoi_Request/01_Login_Giu_Phien.md`](02_Chuoi_Request/01_Login_Giu_Phien.md) | dùng chung `Session()`; hoặc `s.headers["Authorization"]=...` |
| Lấy CSRF token từ HTML | [`02_Chuoi_Request/02_Lay_CSRF_Token.md`](02_Chuoi_Request/02_Lay_CSRF_Token.md) | `re.search(...)` hoặc `BeautifulSoup(...).select_one(...)` |
| Lấy ID từ bước trước rồi dùng tiếp | [`02_Chuoi_Request/03_Truyen_ID_Giua_Cac_Buoc.md`](02_Chuoi_Request/03_Truyen_ID_Giua_Cac_Buoc.md) | `job_id=r.json()["id"]; s.get(f".../{job_id}")` |
| Đọc status/header/JSON/regex/flag | [`02_Chuoi_Request/04_Doc_Response.md`](02_Chuoi_Request/04_Doc_Response.md) | `r.status_code`, `r.headers`, `r.json()`, `re.search(...)` |
| Intruder -> vòng lặp payload | [`03_Thao_Tac_Nang_Cao/01_Intruder_Sang_Vong_Lap.md`](03_Thao_Tac_Nang_Cao/01_Intruder_Sang_Vong_Lap.md) | `for p in payloads: r=s.post(...); time.sleep(0.1)` |
| Chạy đồng thời nhiều đội/request | [`03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md`](03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md) | `ThreadPoolExecutor(max_workers=4)` + `timeout=4` |
| Polling job bất đồng bộ | [`03_Thao_Tac_Nang_Cao/03_Polling_Va_Callback.md`](03_Thao_Tac_Nang_Cao/03_Polling_Va_Callback.md) | `for _ in range(N): ...; time.sleep(1)` |
| SQLi/IDOR/LFI/CMDi/SSTI/SSRF/Upload/XSS-CSRF | [`04_Theo_Lo_Hong/`](04_Theo_Lo_Hong/) | Mở đúng file lỗ hổng, copy payload + request mẫu |
| Lặp `targets.txt`, bỏ đội nhà/localhost | [`05_Nhieu_Doi_Va_Flag/01_Lap_Danh_Sach_Doi.md`](05_Nhieu_Doi_Va_Flag/01_Lap_Danh_Sach_Doi.md) | bỏ `@OUR_TEAM`, `127.0.0.1`, dòng `#` |
| Trích flag bằng regex | [`05_Nhieu_Doi_Va_Flag/02_Trich_Flag.md`](05_Nhieu_Doi_Va_Flag/02_Trich_Flag.md) | `re.findall(r"FHACKER2026\{[0-9a-fA-F]{64}\}", text)` |
| Lưu flag không trùng, lọc cờ nhà | [`05_Nhieu_Doi_Va_Flag/03_Luu_Flag_Theo_Doi.md`](05_Nhieu_Doi_Va_Flag/03_Luu_Flag_Theo_Doi.md) | `seen=set(); if flag in OWN_FLAGS: continue` |
| Đẩy Python qua Burp để soi khác biệt | [`06_Debug/Python_Qua_Burp.md`](06_Debug/Python_Qua_Burp.md) | `s.proxies={"http":"http://127.0.0.1:8080","https":"..."}` |
| Burp được, Python không | [`06_Debug/Burp_Duoc_Python_Khong.md`](06_Debug/Burp_Duoc_Python_Khong.md) | so URL/method/header/cookie/body/redirect/encode |
| Gặp 403/WAF hoặc lỗi thường gặp | [`06_Debug/04_Khi_Gap_WAF_403.md`](06_Debug/04_Khi_Gap_WAF_403.md), [`06_Debug/Loi_Thuong_Gap.md`](06_Debug/Loi_Thuong_Gap.md) | đổi 1 biến/lần, không retry spam 403/429 |
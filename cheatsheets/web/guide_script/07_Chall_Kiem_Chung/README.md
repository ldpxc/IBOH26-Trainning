# 07 — Chall kiểm chứng

Mục đích: có vài bài **lab nhỏ do bạn tự dựng** để chạy lại từng file cheatsheet và khẳng định "cách này dùng được". Mỗi bài nên có: request mẫu trong Burp + script Python tương ứng + kết quả đối chiếu.

> Chỉ dựng và chạy trên máy/lab của bạn.

## Bài đề xuất → file cheatsheet tương ứng

| Bài kiểm chứng | Kỹ năng cần chạy lại | File tham khảo |
|----------------|----------------------|----------------|
| Echo query: `/echo?q=...` (tham số trùng tên) | GET, query trùng tên | [`../01_Request_Co_Ban/01_GET_Query.md`](../01_Request_Co_Ban/01_GET_Query.md) |
| Form + JSON + raw body | `data=` / `json=` / `Content-Type` | [`../01_Request_Co_Ban/02_POST_Form_JSON.md`](../01_Request_Co_Ban/02_POST_Form_JSON.md) |
| Trang login có session cookie | `Session`, header, cookie | [`../01_Request_Co_Ban/03_Headers_Cookies_Session.md`](../01_Request_Co_Ban/03_Headers_Cookies_Session.md), [`../02_Chuoi_Request/01_Login_Giu_Phien.md`](../02_Chuoi_Request/01_Login_Giu_Phien.md) |
| Upload ảnh rồi trả đường dẫn | multipart, filename, field | [`../01_Request_Co_Ban/04_Upload_File.md`](../01_Request_Co_Ban/04_Upload_File.md), [`../04_Theo_Lo_Hong/File_Upload.md`](../04_Theo_Lo_Hong/File_Upload.md) |
| Echo đã URL-encode/Base64 | tránh encode 2 lần | [`../01_Request_Co_Ban/05_Encoding.md`](../01_Request_Co_Ban/05_Encoding.md) |
| Form có CSRF token | trích token rồi gửi lại | [`../02_Chuoi_Request/02_Lay_CSRF_Token.md`](../02_Chuoi_Request/02_Lay_CSRF_Token.md) |
| Tạo item → lấy ID → đọc/sửa | truyền ID giữa các bước | [`../02_Chuoi_Request/03_Truyen_ID_Giua_Cac_Buoc.md`](../02_Chuoi_Request/03_Truyen_ID_Giua_Cac_Buoc.md) |
| Trang trả JSON/HTML/302 | đọc response, redirect | [`../02_Chuoi_Request/04_Doc_Response.md`](../02_Chuoi_Request/04_Doc_Response.md) |
| Endpoint ping với wordlist | Intruder → vòng lặp | [`../03_Thao_Tac_Nang_Cao/01_Intruder_Sang_Vong_Lap.md`](../03_Thao_Tac_Nang_Cao/01_Intruder_Sang_Vong_Lap.md) |
| Coupon redeem 1 lần | race condition | [`../03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md`](../03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md) |
| Job async + callback | polling / OOB | [`../03_Thao_Tac_Nang_Cao/03_Polling_Va_Callback.md`](../03_Thao_Tac_Nang_Cao/03_Polling_Va_Callback.md) |
| Mỗi loại lỗ hổng đã giải | theo lỗ hổng | [`../04_Theo_Lo_Hong/`](../04_Theo_Lo_Hong/) |
| 3 đội, mỗi đội 1 flag | nhiều đội + lưu flag | [`../05_Nhieu_Doi_Va_Flag/`](../05_Nhieu_Doi_Va_Flag/) |
| Request Python lệch Burp | dùng Burp làm proxy | [`../06_Debug/`](../06_Debug/) |

## Cách dựng lab tối thiểu

Dùng Flask (cài thêm `flask` nếu chưa có) trong một file `lab_app.py` của riêng bạn:

```python
from flask import Flask, request, jsonify, redirect
app = Flask(__name__)

@app.get("/echo")
def echo():
    return jsonify(query=request.args.to_dict(flat=False))

@app.post("/api")
def api():
    return jsonify(body=request.get_json(silent=True), ctype=request.content_type)

@app.get("/old")
def old():
    return redirect("/echo?q=done", code=302)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
```

Chạy `python lab_app.py`, rồi:

1. Mở Burp → Proxy → truy cập `http://127.0.0.1:8000/echo?q=a&q=b` → thấy request.
2. Chạy script Python tương ứng → so `r.url`, `r.request.headers`, `r.text`.
3. Ghi kết quả vào bảng dưới đây để cheatsheet được "chứng minh".

## Mẫu ghi kết quả kiểm chứng

| Bài | Burp | Python | Khớp? | Ghi chú |
|-----|------|--------|-------|---------|
| Echo query trùng tên | `?q=a&q=b` | `params=[("q","a"),("q","b")]` | ✅ | dùng list of tuples |
| API JSON | `{"x":1}` | `json={"x":1}` | ✅ | `json=` tự set Content-Type |
| Redirect | 302 + Location | `r.history[0]` | ✅ | `allow_redirects=False` |

## Checklist khi thêm bài mới

- [ ] Có request mẫu trong Burp (Raw).
- [ ] Có script Python tối giản chạy được.
- [ ] Có đối chiếu: status / length / header / body.
- [ ] Có link tới file cheatsheet tương ứng.

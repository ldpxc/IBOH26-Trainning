# Khi gặp WAF chặn trả về 403

**Dùng file này khi:** script Python của bạn gửi đúng request như trên Burp (bạn đã so kỹ) nhưng server trả về `403 Forbidden`, trong khi lúc bấm Send trên Burp Repeater thì request y hệt lại đi qua được — hoặc request **đầu tiên** của bạn bị chặn ngay cả khi payload đúng. Đây là dấu hiệu của **WAF** (Web Application Firewall — 1 tầng lọc request đứng trước ứng dụng thật, tự động chặn request "có vẻ" là tấn công dựa trên mẫu/tốc độ, không liên quan gì tới code bạn viết đúng hay sai).

Nguyên tắc chung: **đổi đúng 1 thứ mỗi lần thử**, so với baseline (request bình thường không bị chặn), để biết chính xác WAF đang chặn dựa vào cái gì.

## Snippet copy-là-chạy

```python
import requests
from requests.models import PreparedRequest

base = "http://target"
s = requests.Session()
s.verify = False

# 1) Thử đổi User-Agent -- nhiều WAF chặn thẳng User-Agent mặc định của requests
#    (mặc định requests gửi "python-requests/2.x", rất dễ bị WAF nhận diện là bot)
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
r = s.get(f"{base}/vuln?id=1", headers=headers, timeout=4)
print("UA giả trình duyệt:", r.status_code)

# 2) Thử đổi định dạng body (JSON <-> form) -- app có thể đọc được cả 2,
#    nhưng WAF có thể chỉ hiểu/chặn đúng 1 kiểu
r = s.post(f"{base}/login", json={"username": "admin", "password": "admin"}, timeout=4)
print("gửi json:", r.status_code)
r = s.post(f"{base}/login", data={"username": "admin", "password": "admin"}, timeout=4)
print("gửi form:", r.status_code)

# 3) Thử gửi URL "thô" (raw) khi nghi WAF và app giải mã (decode) ký tự %xx khác nhau
req = PreparedRequest()
req.prepare("GET", f"{base}/search?q=test%2F..", headers=headers)
r = s.send(req, timeout=4)
print("raw url:", r.request.url, r.status_code)
```

## Giải thích cho người mới

- WAF là 1 lớp đứng **trước** ứng dụng thật, đọc request và tự quyết định chặn (trả 403) hay cho đi tiếp vào app — nó không biết gì về logic app, chỉ nhìn "hình dạng" request (header, pattern trong URL/body, tốc độ gửi) rồi so với các mẫu tấn công đã biết.
- Khối 1: WAF thường có danh sách User-Agent "đáng ngờ" (của các thư viện gửi request tự động), trong đó `python-requests/...` (giá trị mặc định khi không tự set) gần như chắc chắn bị để ý — đổi User-Agent giống trình duyệt thật là bước thử đầu tiên, rẻ nhất.
- Khối 2: cùng 1 endpoint app có thể đọc được cả body JSON và body form, nhưng bộ lọc của WAF có khi chỉ "biết đọc" đúng 1 kiểu — nếu kiểu kia né được mà vẫn ra đúng kết quả app xử lý, đó là manh mối rõ: WAF chặn theo định dạng, không phải theo nội dung.
- Khối 3: `PreparedRequest` cho phép bạn tự dựng request với URL encode theo đúng ý mình (không bị `requests` tự "dọn lại" chuỗi URL) — dùng khi nghi WAF giải mã `%2F` (`/` đã encode) khác với cách app thật xử lý, ví dụ WAF thấy `%2F` không nguy hiểm nhưng app decode ra `/../` thì lại là path traversal.

## Bảng triệu chứng → nguyên nhân → cách sửa

| Triệu chứng | Nguyên nhân thường gặp nhất | Cách sửa ngay |
|---|---|---|
| Burp Send ra 200, Python chạy request y hệt ra 403 | `requests` gửi User-Agent mặc định `python-requests/x.x`, Burp gửi UA trình duyệt | Thêm `headers={"User-Agent": "Mozilla/5.0 ..."}` hoặc `s.headers.update({...})` ngay sau khi tạo `Session()` |
| 403 chỉ xảy ra khi gửi payload (SQLi/XSS...), request bình thường thì 200 | WAF có bộ lọc theo mẫu ký tự (`union select`, `<script>`, `../`...) trong URL/body | Thử encode payload khác đi (URL-encode thêm 1 lớp, đổi hoa/thường, chèn comment SQL `/**/`), hoặc gửi qua kênh khác (body JSON thay vì query string) |
| 403 chỉ xảy ra khi chạy mass nhiều đội/nhiều request liên tục, chạy 1 request tay thì vẫn 200 | WAF giới hạn tốc độ gửi (rate-limit — tự chặn khi 1 địa chỉ gửi quá nhiều request trong thời gian ngắn) | Giảm `WORKERS` trong `template.py`, thêm `time.sleep(0.3-1)` giữa các request, không gửi dồn dập |
| 403 xảy ra ngay từ request đầu tiên trong chuỗi (ví dụ bước login), chưa kịp gửi payload gì | Header thiếu so với Burp (thiếu `Accept`, `Referer`, hoặc `Content-Type` sai) | Copy đúng toàn bộ header từ tab Request của Burp, dán vào `headers={...}`, so với [`Burp_Duoc_Python_Khong.md`](Burp_Duoc_Python_Khong.md) |
| Đổi User-Agent xong vẫn 403 | WAF chặn theo pattern trong URL/body, không phải theo header | Chuyển sang thử khối 2/3 ở trên: đổi định dạng body, đổi cách encode URL |
| 403 chỉ xảy ra với 1-2 đội cụ thể, các đội khác bình thường | Đội đó cấu hình WAF chặt hơn/khác bản vá, không phải lỗi script | Bỏ qua đội đó trong lúc này (không retry spam vì dễ bị đánh giá là tấn công DoS), quay lại thử sau khi xử lý xong các đội dễ |

## Lưu ý nhanh

- Đổi **1 biến mỗi lần thử** (chỉ header, hoặc chỉ định dạng body, hoặc chỉ cách encode) — đổi nhiều thứ cùng lúc sẽ không biết chính xác cái nào gây ra khác biệt.
- Không gửi request lặp lại dồn dập để "dò" WAF — vừa tốn thời gian vừa dễ bị tính là hành vi tấn công DoS (ban tổ chức có thể phạt), chỉ thử vài lần có suy nghĩ.
- Giữ `timeout` ngắn (4-5 giây) và `WORKERS` nhỏ (4 trở xuống) khi chạy mass nhiều đội, để không tự biến mình thành nguồn gây quá tải bị WAF/service chặn ngược.
- File này giúp bạn debug khi ĐÃ bị chặn (đổi 1 biến/lần). Nếu muốn né WAF ngay từ đầu bằng nhiều biến thể payload khác nhau (viết hoa/thường, encode, thêm comment...), xem [`04_Theo_Lo_Hong/WAF_Bypass.md`](../04_Theo_Lo_Hong/WAF_Bypass.md).

# Lỗi thường gặp khi chạy script lúc thi

**Dùng file này khi:** script đang chạy thì dừng đột ngột và ném ra 1 dòng đỏ (traceback — đoạn Python in ra khi script gặp lỗi không bắt được) có chữ `Error` ở cuối, hoặc script "treo" không in gì cả — và bạn đang gấp, cần biết ngay dòng nào gây lỗi và sửa gì, không có thời gian đọc cả traceback dài.

Đây là nhóm lỗi xảy ra **trong lúc gửi/nhận request** (khác với lỗi cú pháp Python thuần, xem mục 4 ở [`00_Bat_Dau_Tu_Zero.md`](../00_Bat_Dau_Tu_Zero.md) cho nhóm đó).

## Snippet copy-là-chạy

```python
import requests

s = requests.Session()
s.verify = False   # bỏ qua kiểm tra chứng chỉ TLS, dùng khi target tự ký cert hoặc qua Burp proxy

try:
    r = s.get("http://target", timeout=4, allow_redirects=False)
    r.raise_for_status()   # chỉ dùng khi muốn coi mã 4xx/5xx là lỗi để nhảy vào except -- bỏ dòng này nếu muốn tự xử lý status tay
    print(r.status_code)
except requests.exceptions.SSLError as e:
    print("Lỗi SSL:", e)
except requests.exceptions.Timeout:
    print("Timeout: server không trả lời trong thời gian cho phép")
except requests.exceptions.ConnectionError as e:
    print("Lỗi kết nối:", e)
except requests.exceptions.HTTPError as e:
    print("Server trả mã lỗi 4xx/5xx:", e)
```

## Bảng triệu chứng → nguyên nhân → cách sửa

| Dòng lỗi (cuối traceback) | Nguyên nhân thường gặp nhất | Cách sửa ngay |
|---|---|---|
| `requests.exceptions.SSLError` | Target dùng HTTPS với chứng chỉ (cert) tự ký, hoặc bạn đang gửi qua proxy Burp (Burp tự chèn cert riêng) | Thêm `s.verify = False` ngay sau khi tạo `Session()` |
| `requests.exceptions.ConnectTimeout` / `requests.exceptions.ReadTimeout` | Server không trả lời kịp trong thời gian `timeout=` đã đặt — có thể do service đang chậm/quá tải, hoặc IP/port sai | Tăng `timeout` lên (ví dụ 4 → 8) để loại trừ do chậm thật; nếu vẫn timeout, kiểm tra lại đúng IP:port trong `targets.txt`/Burp |
| `requests.exceptions.ConnectionError` | IP/port sai, service đang down, hoặc bị chặn mạng (tường lửa/VPN) | In rõ URL đang gọi (`print(url)`) để soát lại đúng chính tả; thử `curl` hoặc `ping` thủ công tới IP đó để xác nhận service có sống không |
| `requests.exceptions.TooManyRedirects` | Server redirect lặp vòng (A → B → A → B...), thường do thiếu cookie/token nên app cứ đẩy bạn quay lại trang login | Kiểm tra bạn có đang dùng chung 1 `Session()` xuyên suốt không (xem [`Burp_Duoc_Python_Khong.md`](Burp_Duoc_Python_Khong.md)); thử `allow_redirects=False` để thấy rõ từng bước redirect |
| Script không in gì, đứng yên mãi không báo lỗi, không kết thúc | Thiếu `timeout=` trong `s.get/s.post` — không có timeout, Python sẵn sàng chờ **vô hạn** nếu server không bao giờ trả lời | Luôn thêm `timeout=4` hoặc `timeout=5` vào **mọi** lệnh `s.get(...)`/`s.post(...)`, không bỏ sót dòng nào |
| `requests.exceptions.HTTPError: 403/404/500 Client/Server Error` | Có gọi `r.raise_for_status()` và response trả mã lỗi | Đây không phải lỗi Python — là tín hiệu server trả về mã lỗi thật; bỏ dòng `raise_for_status()` nếu bạn muốn tự đọc `r.status_code` và xử lý tay, không cần bắt bằng `except` |
| Status 200 nhưng flag/kết quả vẫn sai, không báo lỗi Python nào cả | Lỗi logic, không phải lỗi kỹ thuật: response hợp lệ nhưng không phải nội dung bạn mong, hoặc bạn đọc sai key/sai vị trí | In `r.text[:300]`, `r.headers`, `r.url`, `s.cookies.get_dict()` ngay sau dòng gửi request để nhìn thật server trả gì, đừng đoán |
| `json.decoder.JSONDecodeError` | Gọi `r.json()` nhưng body không phải JSON thật (có thể là HTML lỗi, trang 403 của WAF) | In `r.status_code` và `r.text[:300]` trước khi gọi `r.json()` để biết chắc body có đúng là JSON không |

## Lưu ý nhanh

- `verify=False` dùng khi target HTTPS tự ký cert hoặc bạn đang bật proxy Burp — không ảnh hưởng gì khi target chỉ chạy HTTP thường (không có TLS).
- Luôn có `timeout=` ở mọi request — đây là nguyên nhân số 1 khiến script "treo" không rõ lý do khi chạy mass nhiều đội.
- Mẹo chung: khi không chắc lỗi do đâu, in ngay `status_code` và 200-300 ký tự đầu của `r.text` **trước** dòng gây lỗi — gần như mọi lỗi lúc thi là do response không giống bạn tưởng, không phải do Python khó.

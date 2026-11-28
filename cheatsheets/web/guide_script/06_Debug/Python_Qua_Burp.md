# Đẩy request Python qua Burp để soi

**Dùng file này khi:** script Python chạy ra kết quả lạ (403, response khác Burp, hoặc bạn không chắc Python có đang gửi đúng request mình nghĩ không) và bạn muốn **nhìn trực tiếp** request Python vừa gửi trong Burp — giống việc bạn đang dùng trình duyệt nhưng giờ để Python đóng vai "trình duyệt", còn Burp vẫn đứng giữa để bạn xem/sửa như mọi khi.

Về bản chất: "đẩy qua Burp" nghĩa là bảo thư viện `requests` gửi request tới Burp trước (Burp đóng vai proxy — trạm trung chuyển đứng giữa, nhận request rồi mới chuyển tiếp ra ngoài), thay vì gửi thẳng ra target.

## Snippet copy-là-chạy

```python
import requests
import urllib3

# Tắt cảnh báo "Unverified HTTPS request" khi dùng verify=False -- không tắt thì màn hình bị spam cảnh báo
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()

# Trỏ mọi request của session này đi qua Burp đang lắng nghe ở 127.0.0.1:8080
s.proxies.update({"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
s.verify = False   # cần khi target là HTTPS và Burp đang intercept (chặn giữa đường) bằng cert tự ký của nó

r = s.get("https://target", timeout=10)   # timeout dài hơn bình thường vì phải đi qua thêm 1 chặng (Burp)
print(r.status_code)
print(r.request.method, r.request.url)
print(r.request.headers)
```

## Giải thích cho người mới

- "Proxy" ở đây nghĩa là: thay vì Python gửi request thẳng tới server đích, nó gửi tới địa chỉ Burp (`127.0.0.1:8080` — Burp đang mở cổng này trên chính máy bạn), Burp nhận được, hiển thị lên tab HTTP History, rồi mới chuyển tiếp request đó ra server đích thật.
- `s.proxies.update({"http": "...", "https": "..."})`: khai 2 dòng riêng cho HTTP và HTTPS vì về lý thuyết bạn có thể dùng proxy khác nhau cho 2 loại, nhưng trong trường hợp này thường trỏ cả 2 vào cùng 1 địa chỉ Burp.
- `s.verify = False`: khi Burp "intercept" (chặn và đọc được) cả traffic HTTPS, nó phải tự ký 1 chứng chỉ (cert) giả để đóng vai server — Python mặc định không tin cert lạ này nên sẽ báo lỗi `SSLError` nếu không tắt `verify`.
- `urllib3.disable_warnings(...)`: khi `verify=False`, `requests` sẽ in ra 1 dòng cảnh báo mỗi lần gửi request — dòng này tắt cảnh báo đó cho màn hình sạch, không ảnh hưởng tới việc gửi request.
- Sau khi chạy xong, mở Burp lên, vào tab **HTTP History** (hoặc Proxy → HTTP history tuỳ bản Burp) để thấy đúng request Python vừa gửi, so nó với request bạn test tay trước đó.

## Bảng tình huống thường gặp

| Tình huống | Nguyên nhân | Cách xử lý |
|---|---|---|
| Chạy script xong nhưng Burp không thấy request nào mới | Quên bật Burp Proxy listener ở đúng cổng `8080`, hoặc Burp đang tắt "Intercept is on" làm treo request | Kiểm tra Proxy → Options trong Burp có listener `127.0.0.1:8080` đang chạy; tắt "Intercept is on" nếu không cố ý chặn tay từng request |
| Script báo `SSLError` dù đã có `s.proxies` | Thiếu `s.verify = False` | Thêm `s.verify = False` — bắt buộc khi Burp đang intercept HTTPS |
| Script chạy rất chậm hoặc bị treo | Đang bật `Intercept is on` trong Burp, mỗi request bị giữ lại chờ bạn bấm Forward tay | Tắt Intercept khi chỉ cần xem log (HTTP History), chỉ bật Intercept khi thật sự cần sửa tay từng request |
| Chạy mass nhiều đội (10-20 đội) mà quên tắt proxy | Toàn bộ traffic bị dồn qua Burp (1 điểm), làm chậm hẳn so với gửi thẳng, có khi Burp xử lý không kịp | Chỉ bật proxy khi đang debug 1 request cụ thể; tắt `s.proxies`/đặt `USE_PROXY = False` (xem [`scripts/template.py`](../scripts/template.py)) trước khi chạy thật cho nhiều đội |
| Thấy request trong Burp nhưng khác với log Python in ra | Burp có thể tự sửa nhẹ request khi hiển thị (ví dụ thêm dòng trống), hoặc bạn đang nhìn nhầm request cũ trong lịch sử | Lọc theo thời gian gần nhất trong HTTP History, hoặc thêm 1 header riêng để nhận diện (ví dụ `X-Debug: 1`) rồi tìm đúng request đó trong Burp |

## Lưu ý nhanh

- Bật đúng Burp Proxy listener (`127.0.0.1:8080` theo mặc định) **trước khi** chạy script, không chạy trước rồi mới mở Burp.
- Chỉ bật proxy khi cần soi/debug — chạy thật cho nhiều đội nên tắt proxy (đi thẳng) để nhanh và không phụ thuộc Burp còn mở hay không.
- `verify=False` ở đây chỉ phục vụ việc debug qua Burp trong lab/phòng thi, không phải thói quen nên dùng mọi lúc.

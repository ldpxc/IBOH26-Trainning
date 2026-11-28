# Server-Side Request Forgery (SSRF)

## 1. Bản chất

SSRF xảy ra khi ứng dụng nhận một URL/địa chỉ từ input rồi **server tự gửi request** đến đích đó mà không giới hạn đúng. Request được phát ra từ vị trí mạng của server, nên có thể vượt qua giới hạn mà client bên ngoài không với tới.

Điểm quan trọng cần tách:

- **Ai khởi tạo request?** Server, không phải browser của bạn.
- **Request đi từ đâu?** Network/VPC/container của server.
- **Server có quyền gì?** Credential, metadata, service nội bộ, network route.
- **Có response trực tiếp không?** Có thể chỉ quan sát được qua callback hoặc thời gian.

SSRF không đồng nghĩa với "mọi URL nội bộ đều đọc được". Cần chứng minh server thực sự gửi request và tác động cụ thể.

## 2. Vị trí thường gặp

- Fetch avatar/image từ URL.
- Webhook, callback, URL preview.
- Import từ URL, RSS/feed reader.
- PDF/report generator tải tài nguyên ngoài.
- OAuth/OIDC discovery hoặc JWKS URL.
- Integration với API khác.
- File converter, crawler, uptime monitor.
- Tham số `url`, `uri`, `target`, `webhook`, `image`, `feed`, `endpoint`, `next` nếu được server fetch.

Cả dữ liệu gián tiếp cũng cần xem xét: URL lưu trong profile, nội dung XML/JSON, URL trong file upload hoặc redirect do server theo dõi.

## 3. Nhận diện có kiểm soát

### Bước 1: Xác định hành vi fetch

Tạo hai request gần giống nhau:

- URL hợp lệ trỏ tới endpoint test do bạn kiểm soát.
- URL không hợp lệ hoặc không tồn tại.

Quan sát:

- Status và thông báo lỗi khác nhau.
- Response chứa nội dung từ URL đích.
- Độ trễ thay đổi theo kết nối.
- Log tại listener nhận được request.

Không dùng địa chỉ metadata/cloud thật hoặc dịch vụ nội bộ không thuộc phạm vi chỉ để "thử xem có chạy không".

### Bước 2: Dùng listener của lab

Một HTTP server đơn giản trong lab có thể ghi lại:

- Thời điểm request.
- Source IP (trong mạng lab).
- Method/path/header.
- Có redirect hay không.

Nếu server ở internet còn listener ở `localhost` của bạn thì listener không thể nhận callback. Cần một endpoint mà server lab được phép truy cập, không phải mở port tùy tiện trên hệ thống production.

### Bước 3: Phân biệt SSRF với client-side fetch

Nếu request xuất hiện trong browser của bạn, đó có thể là:

- Browser tải ảnh/CSS/JS.
- JavaScript gọi API.
- Redirect client-side.

Chỉ gọi SSRF khi có bằng chứng request xuất phát từ server: log listener, response nội dung server-side, timing hoặc hành vi nội bộ được kiểm chứng.

## 4. Các dạng kết quả

| Dạng | Dấu hiệu | Bằng chứng tối thiểu |
|---|---|---|
| Non-blind | Nội dung URL đích được trả lại | Response chứa nội dung từ endpoint test |
| Blind | Không thấy nội dung nhưng server vẫn gọi | Listener nhận request |
| Semi-blind | Chỉ thấy lỗi/timing/trạng thái | So sánh nhiều điều kiện có kiểm soát |
| Chain | Fetch dẫn tới hành vi khác | Chứng minh chuỗi bằng dữ liệu giả trong lab |

Không suy ra đọc được file hoặc credential chỉ vì một endpoint trả `200`.

## 5. Parser, redirect và bypass

Các kỹ thuật thường được gọi là bypass thực chất liên quan đến **sự khác biệt giữa validator và HTTP client/DNS resolver**:

### 5.1. URL parsing

Cần kiểm tra validator lấy host bằng cách nào:

- String prefix/suffix.
- Regex tự viết.
- URL parser chuẩn.
- Kiểm tra trước hay sau normalization.

Các trường hợp cần hiểu trong lab:

- Userinfo `user@host`.
- Fragment `#...` và query.
- Host dạng IPv4/IPv6.
- Port mặc định/không mặc định.
- Unicode/IDNA và trailing dot.
- URL tương đối và scheme khác nhau.

Không nên dựa vào danh sách payload; hãy so sánh kết quả parse của **validator** và **client thực sự gửi request**.

### 5.2. DNS và IP

Một hostname có thể resolve khác nhau theo thời điểm hoặc theo resolver. Nếu chỉ kiểm tra hostname lúc validate mà client resolve lại lúc connect, có thể xuất hiện TOCTOU.

Cách phòng thủ tốt hơn là:

- Resolve và kiểm tra mọi địa chỉ IP nhận được.
- Chặn dải private/loopback/link-local/multicast/reserved theo chính sách.
- Kiểm tra lại địa chỉ thực tế ở lớp kết nối.
- Không cho phép redirect tự động tới đích chưa được kiểm tra.

### 5.3. Redirect

Nếu URL ban đầu hợp lệ nhưng trả `302` tới đích nội bộ, validator chỉ kiểm tra URL đầu là chưa đủ. Cần kiểm tra từng hop và giới hạn số redirect.

### 5.4. Scheme và protocol

Không phải HTTP client nào cũng chỉ hỗ trợ HTTP. Chính sách nên allowlist scheme rõ ràng, thường chỉ `https` (và `http` nếu lab yêu cầu). Không cho phép scheme tùy ý như file-based hoặc protocol nội bộ nếu không có nhu cầu.

## 6. Kiểm chứng tác động an toàn

Trong lab, dựng các endpoint giả:

```text
/public/probe       -> nội dung công khai
/internal/probe     -> chỉ bind trong mạng lab, trả marker vô hại
/redirect/probe     -> redirect tới /internal/probe
```

Sau đó kiểm chứng:

1. Server fetch được `/public/probe` hay không?
2. Có fetch `/internal/probe` không?
3. Có theo redirect không?
4. Có gửi header/credential nào không?
5. Có thể đọc nội dung hay chỉ tạo kết nối?

Marker nên là chuỗi giả như `SSRF_LAB_OK`, không phải `/etc/passwd`, token cloud hoặc dữ liệu người dùng.

## 7. Khắc phục

### Thiết kế ưu tiên

- Không cho client cung cấp URL tùy ý nếu không cần.
- Dùng ID tài nguyên và map sang URL phía server.
- Tách fetch service vào mạng bị hạn chế.
- Egress firewall chỉ cho phép đích cần thiết.
- Không gắn credential nhạy cảm vào fetch do user kiểm soát.

### Validate đúng lớp

- Parse bằng thư viện URL chuẩn.
- Allowlist scheme, host, port.
- Chặn IP đặc biệt sau khi resolve và tại connection layer.
- Kiểm tra mọi redirect.
- Giới hạn timeout, kích thước response, số redirect và content type.
- Không dùng blacklist đơn thuần cho hostname/IP.

Ví dụ khung kiểm tra khái niệm (cần bổ sung resolver/redirect cho production):

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"images.example.test"}

def validate_fetch_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme != "https":
        raise ValueError("Chỉ cho phép HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("Không chấp nhận userinfo")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host không nằm trong allowlist")
    if parsed.port not in (None, 443):
        raise ValueError("Port không được phép")
    return raw_url
```

Đoạn trên **không phải giải pháp SSRF hoàn chỉnh**: allowlist host là chính sách mạnh hơn nhiều so với chỉ kiểm tra chuỗi, nhưng vẫn cần DNS rebinding/redirect/egress controls.

## 8. Bẫy khi viết script kiểm thử

- `requests` mặc định follow redirect, Burp Repeater có thể hiển thị từng bước khác.
- Proxy trên máy bạn không phải proxy của server.
- Callback tới `127.0.0.1` trỏ vào **server**, không phải máy bạn.
- DNS cache và IPv6 có thể làm kết quả khác giữa các lần chạy.
- Response timing bị ảnh hưởng bởi connection pool, timeout và cache.
- Một 403 từ validator không chứng minh network đã chặn đích.

## 9. Checklist

- [ ] Xác định chính xác server-side fetch.
- [ ] Có listener/log hoặc bằng chứng response.
- [ ] Chỉ dùng endpoint lab do bạn kiểm soát.
- [ ] Kiểm tra parser, DNS, redirect và scheme theo từng biến.
- [ ] Không truy cập metadata/credential thật.
- [ ] Mô tả được blind/non-blind và dữ liệu quan sát được.
- [ ] Có allowlist + network egress + kiểm tra redirect.
- [ ] Có giới hạn timeout/size/redirect và test hồi quy.

# CORS Misconfiguration (cấu hình sai luật "ai được đọc dữ liệu của tôi")

Trình duyệt có 1 luật mặc định: trang web A không được tự lấy và ĐỌC dữ liệu từ trang B, nếu B không đồng ý (luật này gọi là CORS). B đồng ý bằng cách trả về 1 header nói rõ "tôi cho phép A đọc". Nếu B cấu hình ẩu — cho phép "bất kỳ ai" hoặc tự động phản chiếu lại đúng domain mà bạn gửi lên (gửi gì thì "cho phép" đúng cái đó) — bạn có thể tạo 1 trang giả, dụ nạn nhân đã đăng nhập B mở trang giả đó, trang giả âm thầm gọi B bằng cookie của nạn nhân và ĐỌC ĐƯỢC dữ liệu riêng tư của họ. Khác CSRF (chỉ gửi mù, không biết kết quả), CORS cấu hình sai cho phép bạn đọc luôn response.

Trên Burp bạn nhận ra lỗi này khi: gửi 1 request kèm header `Origin: https://domain-la-nao-cung-duoc.com` tới API trả dữ liệu riêng tư — nếu response có header `Access-Control-Allow-Origin` trả về **y hệt** domain lạ bạn vừa gửi (không phải domain cố định của chính app), và kèm thêm `Access-Control-Allow-Credentials: true`, thì lỗ hổng đã xác nhận.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"

def solve_one(session, base_url):
    # Gửi 1 domain "lạ" bất kỳ vào header Origin -- không liên quan gì tới app thật
    fake_origin = "https://evil-test-xyz.com"
    r = session.get(
        f"{base_url}/api/profile",
        headers={"Origin": fake_origin},
        timeout=5,
    )
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    print("Access-Control-Allow-Origin:", acao)
    print("Access-Control-Allow-Credentials:", acac)

    # Lỗ hổng xác nhận khi CẢ 2 điều kiện đúng:
    # 1) server trả lại ĐÚNG domain giả mình gửi (không phải domain cố định/ "*")
    # 2) credentials = true (nếu thiếu, trình duyệt vẫn không cho gửi kèm cookie)
    if acao == fake_origin and acac == "true":
        print("CORS cấu hình sai -- có thể đọc trộm dữ liệu nạn nhân bằng trang giả")
        return True
    return False


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Kết quả:", solve_one(s, base))
```

## Giải thích cho người mới

- Header `Origin` là thứ trình duyệt TỰ gắn vào mọi request cross-origin (gọi sang domain khác) để báo cho server biết "tôi là ai gửi tới" — ở đây mình tự gắn tay 1 giá trị giả để xem server có kiểm tra thật hay không.
- `Access-Control-Allow-Origin` (viết tắt ACAO) là câu trả lời của server: "tôi cho phép domain này đọc response của tôi". Nếu server LÀM ĐÚNG, nó chỉ nên trả về 1 domain cố định đã biết trước (whitelist) — không bao giờ trả lại y hệt domain lạ bạn vừa gửi.
- `Access-Control-Allow-Credentials` (ACAC) quyết định trình duyệt có gửi kèm cookie khi gọi cross-origin không — thiếu header này (hoặc để `false`) thì dù ACAO có sai, trình duyệt vẫn không gửi cookie thật của nạn nhân, nên không khai thác được gì nguy hiểm.
- Script này chỉ XÁC NHẬN lỗ hổng tồn tại bằng Python (dùng cookie giả của chính bạn) — để lấy được dữ liệu THẬT của nạn nhân, bạn cần 1 trang HTML độc dụ nạn nhân (admin bot) mở, giống cách làm với bài XSS/CSRF, vì Python không "mượn" được cookie thật của người khác.

## Lưu ý nhanh

- Nếu ACAO luôn là `*` (dấu sao) bất kể Origin gửi gì — đây là wildcard thật, AN TOÀN hơn phản chiếu, vì chuẩn trình duyệt không cho phép `*` đi kèm credentials, không khai thác qua đường cookie được.
- Nếu ACAO phản chiếu đúng nhưng thiếu ACAC — lỗ hổng chưa đủ điều kiện, không có gì để khai thác thêm.
- Muốn lấy dữ liệu thật của nạn nhân, phải viết 1 trang HTML nhỏ dùng `fetch(url, {credentials: 'include'})` rồi gửi kết quả về 1 listener bạn tự host (`python3 -m http.server`), và dụ admin bot mở trang đó — không phải việc Python tự làm được.
- Lỗi này nằm ở RESPONSE header server tự trả sai, nên hầu như không chặn được bằng WAF thông thường (WAF quen soi request đi vào, không sửa response đi ra) — fix thật phải sửa code server.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

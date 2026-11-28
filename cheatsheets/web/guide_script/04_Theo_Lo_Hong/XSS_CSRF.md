# XSS / CSRF (chèn code chạy ở người xem / giả mạo request thay người khác)

**XSS** (Cross-Site Scripting — chèn được đoạn script của mình vào trang mà người khác xem): nếu trang web hiển thị lại nguyên văn chữ bạn gõ (ví dụ ô tìm kiếm in lại "Bạn vừa tìm: ...") mà không lọc bỏ các ký tự HTML đặc biệt, bạn có thể gõ `<script>alert(1)</script>` — trình duyệt của **người xem trang đó** (không phải của bạn) sẽ hiểu đây là 1 đoạn code JavaScript thật và chạy nó, dù họ không hề muốn chạy gì cả. Trong thi đấu, XSS nguy hiểm vì bạn có thể chèn script đánh cắp cookie của người khác (ví dụ admin) khi họ vô tình mở trang có chứa payload của bạn.

**CSRF** (Cross-Site Request Forgery — lừa trình duyệt người khác tự gửi 1 request thay họ): nếu 1 trang thực hiện hành động quan trọng (đổi email, đổi mật khẩu) chỉ dựa vào cookie đăng nhập mà không kiểm tra thêm gì khác (như 1 token riêng chỉ trang gốc biết), thì 1 trang độc hại khác có thể tự động gửi request đó bằng chính trình duyệt của nạn nhân (trình duyệt tự gắn cookie đăng nhập vào mọi request tới domain đó) — nạn nhân chỉ cần mở 1 trang lạ là vô tình "tự" thực hiện hành động đó mà không biết.

Trên Burp bạn nhận ra XSS khi: gửi `<script>...</script>` vào 1 tham số, và response trả về **nguyên văn** thẻ `<script>` đó (không bị encode thành `&lt;script&gt;`) ngay trong phần HTML sẽ hiển thị. Bạn nhận ra CSRF khi: 1 request đổi dữ liệu quan trọng (POST/PUT) chạy thành công chỉ với cookie, không cần kèm theo 1 token/field riêng nào khác — và server cũng không kiểm tra header `Origin`/`Referer`.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # --- Phần 1: test XSS phản chiếu (reflected -- chữ gõ vào hiện lại ngay trong response) ---
    payload = "<script>alert(1)</script>"
    r1 = session.get(f"{base_url}/search", params={"q": payload}, timeout=5)
    # nếu đúng y nguyên chuỗi payload còn trong response -> server không hề lọc/encode, có XSS
    is_reflected_raw = payload in r1.text
    print("XSS -- payload còn nguyên trong response:", is_reflected_raw, "| status:", r1.status_code)

    # --- Phần 2: kiểm tra trang có dấu hiệu dùng CSRF token không ---
    r2 = session.get(f"{base_url}/profile", timeout=5)
    has_csrf_hint = "csrf" in r2.text.lower()
    print("Trang có nhắc tới csrf/token trong HTML không:", has_csrf_hint)

    # --- Phần 3: thử gửi request đổi email CHỈ bằng cookie, không kèm token ---
    # allow_redirects=False để thấy đúng status/Location gốc, không bị requests tự đi theo redirect
    r3 = session.post(f"{base_url}/profile", data={"email": "a@b.com"}, timeout=5, allow_redirects=False)
    print("đổi email không kèm token ->", r3.status_code, r3.headers.get("Location"))
    # nếu status 200/302 (thành công) mà không cần token -> xác nhận có CSRF
    return is_reflected_raw, r3.status_code


if __name__ == "__main__":
    print(solve_one(s, base))
```

## Giải thích cho người mới

- **Phần 1 (XSS)**: gửi payload `<script>alert(1)</script>` vào query `q`, rồi kiểm tra `payload in r1.text` — nghĩa là "chuỗi này có nằm y nguyên trong response không". Nếu có, server đã in thẳng chữ bạn gõ ra HTML mà không chuyển `<` thành `&lt;` (bước gọi là "encode" — đổi ký tự đặc biệt thành dạng an toàn để trình duyệt không hiểu lầm là code) — đây chính là XSS.
- **Phần 2**: chỉ là 1 bước gợi ý nhanh, tìm chữ `"csrf"` trong HTML (thường nằm trong 1 input ẩn kiểu `<input type="hidden" name="csrf_token" value="...">`) để đoán xem trang này có cơ chế chống CSRF hay không, trước khi test thật ở Phần 3.
- **Phần 3 (CSRF)**: gửi thẳng request đổi email mà **không** kèm bất kỳ token nào, chỉ dựa vào cookie session đang có sẵn trong `session` (giữ từ các request trước nếu đã login). Nếu request này vẫn chạy thành công (status 200 hoặc 302 chuyển hướng, không phải 403/400 báo thiếu token), nghĩa là ai cũng có thể lừa nạn nhân gửi request này hộ họ — chỉ cần nạn nhân đang đăng nhập và mở 1 trang có form tự submit tới đây.
- `allow_redirects=False`: mặc định `requests` sẽ tự "đi theo" redirect (như trình duyệt tự nhảy trang); tắt nó đi để thấy đúng status gốc (ví dụ `302`) và header `Location` thật, giống cách Burp hiển thị response gốc trước khi bạn tự bấm "Follow redirect".

## Dùng tool có sẵn `XSStrike` thay vì tự viết tay (cho XSS)

Script tay chỉ thử đúng 1 payload cố định. `XSStrike` tự phân tích context (payload nằm giữa tag HTML, trong attribute, hay trong JavaScript) rồi tự sinh payload phù hợp đúng chỗ đó — có sẵn tại `~/hoc/CTF/Tools/web/XSStrike/`:

```bash
spwn
cd ~/hoc/CTF/Tools/web/XSStrike

# Tham số nghi dính trong query string
python3 xsstrike.py -u "http://target/search?q=test"

# Tham số dính trong POST form
python3 xsstrike.py -u "http://target/search" --data "q=test"
```

- Không cần tự đoán payload — XSStrike tự gửi `q=test` thường trước để xem nó phản chiếu (reflect) ra ở đâu trong HTML, từ đó tự sinh payload đúng theo context, rồi tự gửi lại kiểm chứng.
- Kết quả in dòng `[VULN]` kèm payload nó xác nhận chạy được (ví dụ chữ in ra "XSS" thật trong môi trường giả lập trình duyệt headless của nó) — copy đúng payload đó dán vào tham số thật trên trình duyệt/Burp để lấy flag (thường flag hiện qua `document.cookie`/`alert()` admin bot đọc được).
- Không cần chạy XSStrike cho mọi tham số nếu đã nghi trước 1 tham số cụ thể từ Burp — chạy đúng tham số đó để tiết kiệm thời gian.

## Lưu ý nhanh

- XSS: luôn kiểm tra payload có bị encode hay không — nếu `&lt;script&gt;` xuất hiện thay vì `<script>`, server đã lọc, không có XSS ở chỗ đó; cũng cần để ý payload nằm trong context nào (giữa tag HTML, trong 1 attribute, trong JavaScript) vì mỗi context cần cách viết payload khác nhau.
- CSRF: dấu hiệu an toàn (không bị CSRF) là server đòi hỏi 1 token riêng (khác cookie) hoặc kiểm tra header `Origin`/`Referer` phải đúng domain — thiếu cả hai thường là có lỗ hổng.
- Trong thi Attack-Defense, không tự ý gửi payload gây hại thật tới người chơi khác ngoài phạm vi kiểm tra của chính đội mình (ví dụ không chủ động gửi link XSS cho đối phương bấm) — chỉ dùng để xác nhận lỗi và lấy flag trên hệ thống được phép kiểm tra.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

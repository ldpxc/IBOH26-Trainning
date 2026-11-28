# Cross-Site Scripting (XSS)

## 1. Bản chất

XSS xảy ra khi dữ liệu do attacker kiểm soát được trình duyệt diễn giải như **markup hoặc mã thực thi**, thay vì chỉ là dữ liệu văn bản. Điểm mấu chốt không phải chuỗi `<script>` cụ thể, mà là **output encoding sai ngữ cảnh** hoặc DOM API đưa dữ liệu vào sink nguy hiểm.

Một chuỗi phản chiếu trong response chưa đủ để kết luận XSS. Cần xác định:

- Nó nằm ở text node, attribute, JavaScript string, URL hay CSS?
- Có bị encode/escape đúng ngữ cảnh không?
- Trình duyệt có thực thi hoặc kích hoạt hành vi không?
- CSP, Trusted Types, sanitizer và cookie `HttpOnly` ảnh hưởng thế nào?

## 2. Ba dạng chính

| Dạng | Nguồn dữ liệu | Vị trí xuất hiện | Đặc điểm |
|---|---|---|---|
| Reflected XSS | Request hiện tại | Response ngay lập tức | Thường cần nạn nhân mở URL/request được chuẩn bị |
| Stored XSS | Dữ liệu lưu trên server | Trang xem sau đó | Có thể ảnh hưởng nhiều người xem; cần dùng dữ liệu test |
| DOM XSS | `location`, `hash`, `postMessage`, storage... | JavaScript/DOM ở client | Response HTML ban đầu có thể không chứa payload |

Ngoài ra cần phân biệt **self-XSS** (chỉ người nhập tự ảnh hưởng chính mình) với lỗ hổng có đường tấn công thực tế tới người dùng khác.

## 3. Nhận diện nguồn và sink

### 3.1. Server-rendered HTML

Tìm input được phản chiếu:

- Query `q`, `search`, `returnUrl`.
- Tên, bio, comment, tên file, nội dung import.
- Thông báo lỗi chứa input.
- Header như `User-Agent` nếu admin xem log qua HTML.

Dùng marker vô hại trước:

```text
sheatch_probe_7f3a
```

Sau đó thêm ký tự có ý nghĩa theo từng ngữ cảnh, một ký tự mỗi lần:

```text
< > " ' & = `
```

So sánh raw response và DOM sau render. HTML escape có thể làm `&lt;` trong source nhưng DOM vẫn hiển thị `<` dưới dạng text; đó là hành vi an toàn nếu không tạo element mới.

### 3.2. DOM source thường gặp

```javascript
location.search
location.hash
location.href
document.URL
document.referrer
window.name
localStorage
sessionStorage
postMessage
```

### 3.3. DOM sink cần rà soát

```javascript
element.innerHTML = value;
element.outerHTML = value;
document.write(value);
eval(value);
new Function(value);
setTimeout(value, 100);
element.setAttribute("onload", value);
element.src = value;
```

Các sink dựa trên HTML/JavaScript nguy hiểm hơn nhiều so với:

```javascript
element.textContent = value;
```

Nhưng `textContent` vẫn không phải câu trả lời cho mọi ngữ cảnh; URL và attribute cần validation riêng.

## 4. Ngữ cảnh và cách kiểm chứng

> Các chuỗi dưới đây chỉ dùng trong lab với trang test do bạn sở hữu. Không gửi payload tới người dùng thật hoặc lấy dữ liệu phiên.

### 4.1. HTML text

Ví dụ dễ bị lỗi:

```html
<div>USER_INPUT</div>
```

Nếu input không được HTML-encode, trình duyệt có thể tạo element mới. Payload chứng minh tối thiểu trong lab thường là một hành vi vô hại, ví dụ `alert(1)`, thay vì đọc cookie hoặc gửi dữ liệu ra ngoài.

Cách sửa: encode `&`, `<`, `>`, và các ký tự cần thiết bằng template engine; không tự viết bộ escape một nửa.

### 4.2. HTML attribute

```html
<input value="USER_INPUT">
<a title="USER_INPUT">x</a>
```

Cần kiểm tra:

- Dấu nháy có được encode không?
- Input có thoát khỏi attribute không?
- Attribute là event handler hay URL không?
- Template có cho phép unquoted attribute không?

Encode theo attribute và luôn dùng dấu nháy quanh giá trị. Không đưa dữ liệu chưa tin cậy vào `on*`, `style` hoặc `srcdoc`.

### 4.3. JavaScript string

```html
<script>
  const name = "USER_INPUT";
</script>
```

HTML-encode không đủ cho ngữ cảnh này. Dấu nháy, backslash, line separator và thẻ đóng script có thể làm thay đổi cấu trúc. Cách đúng là dùng JSON serialization phù hợp và tránh nhúng trực tiếp dữ liệu vào inline script.

Tốt hơn: đưa dữ liệu qua `data-*` đã encode đúng, rồi đọc bằng JavaScript và dùng `textContent`.

### 4.4. URL

```html
<a href="USER_INPUT">open</a>
<iframe src="USER_INPUT"></iframe>
```

Cần kiểm tra scheme và destination. Không chỉ escape HTML: một URL hợp lệ về mặt cú pháp vẫn có thể nguy hiểm nếu dùng scheme scriptable. Nên dùng allowlist scheme (`https`, đôi khi `http`) và xử lý URL tương đối theo chính sách rõ ràng.

### 4.5. DOM XSS

Quy trình:

1. Đặt breakpoint tại sink.
2. Đưa marker vào source.
3. Theo dõi các bước transform/decode.
4. Kiểm tra giá trị ngay trước sink.
5. Dùng hành vi vô hại để chứng minh thực thi trong lab.

Không chỉ grep response cho `<script>`; DOM XSS thường xuất hiện sau khi JavaScript chạy.

## 5. Né filter: phân tích thay vì brute force

Khi filter chặn một chuỗi, hãy trả lời:

- Filter chạy trước hay sau HTML decode?
- Nó kiểm tra raw input hay DOM?
- Nó loại bỏ một lần hay lặp đến khi ổn định?
- Nó chỉ chặn tag name hay cũng xử lý attribute/event/URL?
- Có nhầm "không thấy chuỗi trong response" với "không thực thi" không?

Một blacklist có thể bị sai do:

- Case và canonicalization.
- HTML entity.
- URL decode nhiều lần.
- Parser sửa markup không hợp lệ.
- Input đi qua nhiều component với quy ước khác nhau.

Trong lab, so sánh input ở từng lớp và DOM tree cuối cùng. Không cần tuyển tập payload dài để chứng minh một cơ chế encode sai.

## 6. Stored XSS an toàn khi kiểm thử

1. Dùng tài khoản và nội dung test riêng.
2. Đặt tên object dễ xóa, ví dụ `xss-lab-probe-01`.
3. Chỉ mở bằng browser profile thử nghiệm.
4. Không chèn payload gửi request, đổi dữ liệu hoặc lấy token.
5. Xóa nội dung test sau khi ghi bằng chứng.

Nếu ứng dụng có moderator/admin xem nội dung, **không** dùng tài khoản thật để mở payload ngoài phạm vi được duyệt.

## 7. Xác nhận bằng browser

`requests`/BeautifulSoup chỉ giúp kiểm tra phản chiếu và parse HTML tĩnh. Chúng không chạy JavaScript và không chứng minh XSS thực thi.

Trong lab, dùng browser DevTools hoặc Playwright để bắt một dialog vô hại:

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    dialogs = []
    page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
    page.goto("http://target/xss-lab?q=TEST_PAYLOAD")
    page.wait_for_timeout(500)
    print(dialogs)
    browser.close()
```

URL/payload cần được thay bằng test case của lab. Một alert chứng minh khả năng thực thi JavaScript trong origin; không cần mở rộng thành đánh cắp dữ liệu.

## 8. Tác động cần mô tả đúng

XSS có thể cho phép hành động với quyền của phiên nạn nhân, thay đổi nội dung trang, đọc dữ liệu mà JavaScript được phép truy cập hoặc giả mạo tương tác. Tuy nhiên:

- Cookie `HttpOnly` không đọc được bằng `document.cookie`, nhưng XSS vẫn có thể gửi request trong phiên.
- CSP có thể giảm khả năng khai thác nhưng không phải lớp sửa gốc.
- Self-XSS không nên được báo cáo như stored XSS ảnh hưởng người khác.
- HTML injection không thực thi script cần được gọi đúng tên.

## 9. Khắc phục

### Nguyên tắc chính

1. **Output encoding theo đúng ngữ cảnh**: HTML text, attribute, JavaScript, URL, CSS khác nhau.
2. Dùng template engine auto-escape và không tắt escape cho dữ liệu chưa tin cậy.
3. DOM: ưu tiên `textContent`, `createTextNode`; tránh `innerHTML`, `document.write`, `eval`.
4. Sanitizer đáng tin cậy nếu thực sự cần cho phép HTML; cấu hình allowlist tối thiểu.
5. Validate URL/scheme và xử lý `postMessage` với origin allowlist.

Ví dụ DOM an toàn hơn:

```javascript
const params = new URLSearchParams(location.search);
const name = params.get("name") || "";
const output = document.querySelector("#output");
output.textContent = name; // Không tạo markup từ dữ liệu.
```

### Lớp giảm thiểu

- CSP chặt, tránh `unsafe-inline`, dùng nonce/hash đúng cách.
- Trusted Types cho DOM XSS khi nền tảng hỗ trợ.
- Cookie `HttpOnly`, `Secure`, `SameSite` phù hợp.
- Không hiển thị HTML thô trong admin/log viewer.
- Kiểm thử cả dữ liệu đã lưu từ API/import, không chỉ form chính.

## 10. Checklist

- [ ] Xác định source và sink.
- [ ] Xác định đúng ngữ cảnh output.
- [ ] So raw response với DOM sau render.
- [ ] Không kết luận XSS chỉ từ phản chiếu.
- [ ] Browser xác nhận bằng hành vi vô hại.
- [ ] Stored XSS dùng nội dung test và dọn dẹp sau kiểm thử.
- [ ] Không đọc/gửi dữ liệu phiên thật.
- [ ] Sửa encoding/sanitizer ở gốc; CSP chỉ là lớp bổ sung.

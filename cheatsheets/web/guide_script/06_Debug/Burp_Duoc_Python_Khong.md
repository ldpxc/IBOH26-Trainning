# Burp bấm Send ra kết quả đúng, Python chạy lại thì không

**Dùng file này khi:** bạn đã test tay trên Burp Repeater, request trả về đúng như mong đợi (200, có flag, login thành công...), nhưng copy đúng y logic đó sang Python thì ra kết quả khác (403, 404, 500, hoặc response rỗng/sai) — mặc dù bạn "nghĩ" là đã viết y hệt. Nguyên tắc: **Python không tự hiểu "ý bạn muốn" như Burp** — nó gửi đúng chính xác những gì bạn gõ, không hơn không kém, nên chỉ cần lệch 1 ký tự/1 header là ra request khác.

Cách debug nhanh nhất: in ra request **thật** mà Python vừa gửi, rồi so từng dòng với request trong tab Burp — đừng đoán, hãy nhìn.

## Snippet copy-là-chạy

```python
import requests

s = requests.Session()
s.verify = False
s.headers.update({"User-Agent": "Mozilla/5.0"})   # copy đúng User-Agent từ Burp nếu nghi WAF/app kiểm UA

r = s.get("http://target/search", params={"q": "a+b"}, timeout=5)

# In ra request THẬT mà Python đã gửi đi -- không phải request bạn "nghĩ" là đã gửi
print("URL thật đã gửi:", r.request.url)
print("Method:", r.request.method)
print("Headers đã gửi:", r.request.headers)
print("Body đã gửi:", r.request.body)

# Response nhận về
print("Status:", r.status_code)
print("300 ký tự đầu response:", r.text[:300])
```

## Giải thích cho người mới

- `r.request` là object chứa **đúng những gì Python đã gửi đi thật** (sau khi `requests` tự xử lý encode, thêm header mặc định...) — khác với những gì bạn tưởng là mình đã gõ. Đây là chỗ đầu tiên cần in ra khi nghi request bị lệch so với Burp.
- `r.request.url`: URL cuối cùng thật sự được gửi, sau khi `params={...}` đã được ghép vào thành query string — in ra để chắc query string đúng như Burp (ví dụ dấu `+` trong `"a+b"` có thể bị encode thành `%2B` hoặc giữ nguyên thành dấu cách, tuỳ ngữ cảnh, phải nhìn URL thật để biết).
- `r.request.headers`: toàn bộ header thật đã gửi, bao gồm cả header `requests` **tự thêm** mà bạn không gõ (`Accept-Encoding`, `Connection`...) — so dòng này với tab Request trên Burp để tìm header nào thiếu/khác.
- `r.request.body`: nội dung body thật đã gửi (dạng bytes hoặc chuỗi) — nếu bạn dùng `json=` thì đây sẽ là chuỗi JSON đã được `requests` tự `dumps` (chuyển dict Python thành chuỗi JSON), có thể khác thứ tự key hay cách format so với body bạn gõ tay trên Burp, nhưng về mặt dữ liệu vẫn phải tương đương.

## Bảng triệu chứng → nguyên nhân → cách sửa

| Triệu chứng | Nguyên nhân thường gặp nhất | Cách sửa ngay |
|---|---|---|
| Burp 200, Python 403 | Thiếu header (User-Agent, Referer, Accept) mà app/WAF kiểm tra | Copy **toàn bộ** header từ tab Request trong Burp vào `headers={...}`, xem thêm [`04_Khi_Gap_WAF_403.md`](04_Khi_Gap_WAF_403.md) |
| Burp 200, Python 404 | Sai path (thiếu/dư dấu `/`, viết sai hoa/thường, hoặc URL có query string bị gộp nhầm vào path) | In `r.request.url`, so từng ký tự với dòng đầu request trong Burp |
| Burp login được, Python login xong request sau vẫn bị redirect về trang login | Dùng `requests.get()`/`requests.post()` rời (không qua `Session()`) nên không giữ được cookie giữa các request | Dùng `s = requests.Session()` và gọi `s.get/s.post` cho **mọi** request trong cùng 1 bài, không tạo `requests.post()` riêng lẻ |
| Body JSON gửi đi nhưng app đọc ra giá trị `null`/thiếu field | Dùng `data={...}` (gửi dạng form `a=1&b=2`) trong khi app cần `json={...}` (gửi dạng JSON thật), hoặc ngược lại | Xem Content-Type trong tab Request của Burp: `application/json` → dùng `json=`; `application/x-www-form-urlencoded` → dùng `data=` |
| Request có upload file, Burp OK, Python lỗi hoặc app không nhận file | Thiếu tham số `files=` hoặc đặt sai tên field | Dùng `files={"file": ("ten.ext", open("ten.ext", "rb"), "content-type")}`, tên key (`"file"`) phải khớp đúng tên field app yêu cầu (xem tab Request của Burp, phần `Content-Disposition: name="..."`) |
| Request có nhiều tham số trùng tên (ví dụ `id=1&id=2`) | `dict` trong Python chỉ giữ được 1 giá trị cho mỗi key, không tự nhân đôi được tham số trùng tên | Dùng `list` các tuple: `params=[("id", "1"), ("id", "2")]` thay vì `dict` |
| Mọi thứ nhìn giống nhau nhưng vẫn khác kết quả | Có ký tự đặc biệt (khoảng trắng, dấu `+`, tiếng Việt có dấu) bị encode khác nhau giữa Burp và Python | In `r.request.url` và `r.request.body`, so byte-by-byte (từng ký tự) với giá trị Burp hiển thị ở mode "Raw" |

## Lưu ý nhanh

- Luôn so theo đúng thứ tự: URL → method → headers → cookie → body → có redirect không → có qua proxy/TLS khác không — lệch ở bước nào thì dừng tìm ở bước đó trước, đừng nhảy cóc.
- `requests` tự thêm 1 số header bạn không gõ (`Accept-Encoding`, `Connection`, `Content-Length`) — đây là bình thường, không phải lỗi, không cần cố xoá đi.
- Nếu không chắc Content-Type, mở lại đúng request đó trong Burp, xem dòng `Content-Type` trong tab Request — đây là chỗ quyết định dùng `json=` hay `data=`.

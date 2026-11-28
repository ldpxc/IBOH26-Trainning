# Trích flag ra khỏi response

Bạn đã gửi được request đúng (status 200, không còn lỗi) nhưng giờ cần tự động **lấy đúng chuỗi flag** ra từ response, không phải tự đọc mắt từng dòng HTML/JSON như lúc dùng Burp — vì khi chạy cho 15-20 đội, bạn không có thời gian đọc tay từng response. File này chỉ cách dùng regex (1 kiểu "mẫu tìm chuỗi") để tự động bắt đúng flag, dù nó nằm ở đâu trong response.

## Snippet copy-là-chạy

```python
import re
import requests

# Mẫu flag của giải: FHACKER2026{ + đúng 64 ký tự hex (0-9, a-f) + }
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

s = requests.Session()
s.verify = False
r = s.get("http://target/page", timeout=5)

# 1) Tìm flag trong phần nội dung (body) của response
flags = FLAG_RE.findall(r.text)

# 2) Flag đôi khi không nằm trong body mà nằm ở header hoặc cookie -> ghép hết lại rồi tìm chung
blob = "\n".join([r.text, str(r.headers), str(r.cookies.get_dict())])
flags += FLAG_RE.findall(blob)

# 3) Loại trùng nhưng vẫn giữ đúng thứ tự tìm thấy trước/sau
flags = list(dict.fromkeys(flags))

print(flags)   # list các flag tìm được, có thể là [] nếu không thấy
```

## Giải thích cho người mới

- `re` là thư viện có sẵn trong Python để làm việc với **regex** (biểu thức mẫu để tìm chuỗi theo khuôn, không cần biết chính xác nội dung) — không cần `pip install`, chỉ cần `import re`.
- `re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")`: đây là "khuôn" để tìm flag.
  - `FHACKER2026` và `{`, `}` là chữ/ký tự thật, phải khớp đúng y nguyên.
  - Dấu `\{` và `\}` (có `\` đứng trước) nghĩa là "dấu `{`/`}` thật", vì trong regex `{` `}` thường có nghĩa khác (đếm số lần lặp) — phải thêm `\` để báo "đây là ký tự thật, không phải cú pháp regex".
  - `[0-9a-fA-F]` nghĩa là "1 ký tự bất kỳ trong khoảng 0-9 hoặc a-f hoặc A-F" (ký tự hex).
  - `{64}` (không có `\`) nghĩa là "lặp lại đúng 64 lần" — ghép lại: đúng 64 ký tự hex liên tiếp.
  - Chữ `r` trước dấu `"`  (`r"..."`) là "raw string", báo Python đừng tự hiểu `\{` theo nghĩa khác — luôn dùng `r"..."` khi viết regex.
- `FLAG_RE.findall(r.text)`: quét toàn bộ `r.text` (nội dung response dạng chữ) và trả về **list tất cả chỗ khớp**, không chỉ 1 chỗ đầu tiên — dùng `findall` (không dùng `search`) vì 1 response có thể chứa nhiều flag (ví dụ trang danh sách nhiều bài).
- Khối 2 (`blob = ...`): một số bài giấu flag trong header response (ví dụ `X-Flag: FHACKER2026{...}`) hoặc trong cookie, không nằm trong body — ghép `r.text` + `r.headers` (ép qua `str(...)` để biến object header thành 1 chuỗi) + cookie thành 1 chuỗi dài rồi tìm chung 1 lần cho chắc không bỏ sót.
- Khối 3 (`dict.fromkeys(flags)`): nếu cùng 1 flag xuất hiện 2 lần trong response (ví dụ vừa ở body vừa ở header), `findall` sẽ trả về trùng — `list(dict.fromkeys(flags))` là cách ngắn để **loại trùng** (dedupe — bỏ các giá trị bị lặp lại) mà vẫn giữ đúng thứ tự tìm thấy ban đầu (dùng `set(flags)` cũng loại trùng được nhưng làm mất thứ tự).
- Nếu `flags` in ra `[]` (rỗng): nghĩa là regex không khớp được gì trong response — xem ngay [`06_Debug/Loi_Thuong_Gap.md`](../06_Debug/Loi_Thuong_Gap.md) và in `print(r.status_code, r.text[:300])` để biết response thật trả về gì (có đúng là trang chứa flag không, hay bị 403/trang lỗi).

## Lưu ý nhanh

- Luôn dùng `findall`, không dùng `search` — tránh bỏ sót khi 1 response có nhiều flag.
- Nếu ban tổ chức đổi định dạng flag (ví dụ độ dài khác 64, hoặc tên khác `FHACKER2026`), chỉ cần sửa đúng 1 dòng `FLAG_RE = re.compile(...)`, không cần sửa chỗ khác.
- Flag có thể nằm ở body, header, cookie, hoặc cả HTML comment (`<!-- FHACKER2026{...} -->`) — regex vẫn bắt được vì nó chỉ quét chuỗi, không quan tâm chuỗi đó ở đâu, miễn bạn gộp đủ `r.text` + `r.headers` + `r.cookies` vào chỗ tìm.
- Luôn lọc flag đội nhà ra khỏi `flags` trước khi in/lưu/nộp — xem [`03_Luu_Flag_Theo_Doi.md`](03_Luu_Flag_Theo_Doi.md) phần `OWN_FLAGS`.

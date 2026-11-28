# Đọc log traffic / WAF khi điểm phòng thủ (DEF) tụt

**Dùng file này khi:** điểm phòng thủ (DEF) của đội bạn đang tụt trên bảng điểm, nghĩa là có đội khác đang khai thác thành công dịch vụ của bạn — và bạn cần nhanh chóng tìm **request nào** trong log traffic/WAF là request tấn công thật, giữa hàng ngàn dòng log bình thường (tải ảnh, CSS, healthcheck...), để biết lỗ hổng nằm ở đâu mà vá. Đây không phải lúc đọc tay từng dòng — cần lọc bằng script.

## Snippet copy-là-chạy

```python
from pathlib import Path
import re

LOG = Path("logs/waf.log")   # sửa đúng đường dẫn log thật của hệ thống đang thi
bad = []

for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
    # Bỏ qua các dòng xin tài nguyên tĩnh (ảnh, css, js...) -- gần như không bao giờ là tấn công
    if re.search(r"\.(css|js|png|jpg|ico|woff2?)\b", line, re.I):
        continue

    # Giữ lại dòng có dấu hiệu đáng nghi: mã lỗi 403, POST, path nhạy cảm, hoặc payload SQLi/path traversal
    if re.search(r"\b(403|POST|/admin|/login|union|select|\.\./)\b", line, re.I):
        bad.append(line)

print(f"Tổng dòng đáng nghi: {len(bad)}")
for line in bad[-30:]:   # chỉ in 30 dòng gần nhất -- thường là traffic đang xảy ra lúc này
    print(line)
```

## Giải thích cho người mới

- `LOG.read_text(...).splitlines()`: đọc toàn bộ file log thành 1 chuỗi, rồi tách ra thành list từng dòng (mỗi phần tử trong list là 1 dòng log) để `for` lặp qua xử lý từng dòng.
- `re.search(r"\.(css|js|png|jpg|ico|woff2?)\b", line, re.I)`: kiểm tra dòng log có phải là request xin file tĩnh (ảnh, CSS, JS...) không — `re.I` nghĩa là không phân biệt hoa/thường (ví dụ `.CSS` cũng khớp như `.css`). Các request này chiếm phần lớn log nhưng gần như không liên quan gì tới tấn công, nên bị `continue` bỏ qua ngay để log còn lại ngắn, dễ đọc.
- `re.search(r"\b(403|POST|/admin|/login|union|select|\.\./)\b", line, re.I)`: giữ lại dòng có **ít nhất 1** trong các dấu hiệu đáng nghi — mã trạng thái `403` (có thể là người khác đang dò lỗi bị chặn, hoặc chặn hụt), method `POST` (thường mang payload hơn `GET`), path nhạy cảm (`/admin`, `/login`), hoặc chuỗi gợi SQLi (`union`, `select`) / path traversal (`../`). `\b` là ranh giới từ trong regex, để `select` không vô tình khớp nhầm vào giữa 1 từ khác dài hơn.
- `bad[-30:]`: lấy **30 phần tử cuối cùng** của list — trong Python, `list[-n:]` nghĩa là "n phần tử cuối". Lấy 30 dòng gần nhất vì traffic tấn công đang xảy ra thường nằm ở cuối log (gần với thời điểm hiện tại), không cần đọc từ đầu file dài hàng ngàn dòng.
- Đây chỉ là bước **lọc nhanh** để thu hẹp phạm vi — sau khi thấy vài dòng nghi vấn, bạn vẫn cần đọc tay kỹ nội dung request đó (path, param, body) để xác nhận đúng là lỗ hổng, rồi quay lại vá code hoặc chặn ở tầng WAF.

## Bảng xử lý theo tình huống

| Tình huống | Cách lọc nhanh | Bước tiếp theo |
|---|---|---|
| DEF vừa tụt vài phút trước, chưa biết endpoint nào | Lọc theo khoảng thời gian gần nhất (sửa code lấy N dòng cuối hoặc so cột timestamp) thay vì lọc theo path | Đọc kỹ 10-20 dòng gần nhất còn lại sau khi lọc static asset, tìm path lạ lặp đi lặp lại |
| Log quá dài (hàng trăm MB), đọc hết file bị chậm/treo | `LOG.read_text()` đọc hết 1 lần vào RAM dễ chậm với log rất lớn | Đổi sang đọc theo dòng bằng `with LOG.open() as f: for line in f:` (không load hết file vào RAM 1 lần) |
| Thấy nhiều dòng `403` liên tục từ cùng 1 IP | Có đội đang dò lỗi (fuzz) và bị WAF chặn hụt — chưa chắc đã khai thác thành công | Ghi nhận IP đó, theo dõi thêm; nếu sau đó path đó chuyển sang `200`, khả năng cao họ đã tìm ra cách vượt WAF |
| Thấy dòng có `union`/`select`/`../` nhưng status `200` | Có khả năng cao request tấn công đã lọt qua và thành công | Lấy đúng path + param của dòng đó, kiểm tra code xử lý endpoint này ngay, đây là nơi cần vá trước tiên |
| Không tìm thấy dòng nghi vấn nào dù DEF đang tụt | Log không ghi đủ (thiếu body, thiếu header) hoặc tấn công đi qua kênh không bị log (không qua WAF) | Kiểm tra log ở tầng khác (log của app, log của web server), hoặc log WAF có bật ghi đủ field chưa |

## Lưu ý nhanh

- Luôn bỏ static asset (`.css .js .png .jpg .ico .woff`) và các request healthcheck trước — nếu không, 90% dòng log là nhiễu, rất khó nhìn ra request thật.
- Lấy đúng request đáng ngờ rồi thử lại tay qua Burp hoặc script Python nhỏ để xác nhận — không suy luận chỉ từ 1 dòng log.
- Không replay (gửi lại) request nghi vấn đó sang **đội khác** — bạn chỉ nên tái hiện nó trên chính dịch vụ của mình để kiểm tra, replay sang đội khác là hành vi tấn công, không phải debug.

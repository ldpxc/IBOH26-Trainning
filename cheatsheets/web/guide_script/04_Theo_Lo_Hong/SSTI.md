# SSTI (chèn lệnh vào bộ máy dựng trang web)

Nhiều trang web dùng 1 "khuôn mẫu" (template — bản mẫu HTML có chỗ trống để điền dữ liệu, như thư mời đã in sẵn chỉ cần điền tên khách) để tạo trang động, ví dụ khuôn `<h1>Xin chào {{name}}</h1>` rồi bộ máy dựng trang (template engine — phần mềm đọc khuôn mẫu, điền dữ liệu vào chỗ trống, rồi xuất ra HTML thật) điền `name` bạn gửi vào chỗ trống đó. Vấn đề là cú pháp `{{ ... }}` trong nhiều engine không chỉ dùng để "điền chữ" — nó còn hiểu được cả biểu thức tính toán, thậm chí gọi được hàm, chạy được lệnh hệ thống. Nếu bạn gõ tên của mình là `{{7*7}}` mà trang hiển thị ra số `49` (đã tính toán xong) thay vì hiển thị nguyên chữ `{{7*7}}`, nghĩa là bộ máy đó đã **chạy** đoạn bạn gõ như 1 đoạn lệnh thật, không chỉ in ra như chữ thường. Đây gọi là SSTI — Server-Side Template Injection (chèn lệnh vào khuôn mẫu, chạy luôn trên server).

Trên Burp bạn nhận ra lỗi này khi: 1 tham số được hiển thị lại trên trang (tên, ghi chú, nội dung preview...), và khi bạn gửi `{{7*7}}` (hoặc `${7*7}`, `<%= 7*7 %>` tuỳ engine), response trả về số `49` thay vì trả nguyên chuỗi `{{7*7}}` như bạn đã gõ.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Mỗi cú pháp dưới đây là cách viết biểu thức "7*7" của 1 nhóm engine khác nhau:
    # {{7*7}}    -> Jinja2 (Python), Twig (PHP)
    # ${7*7}     -> 1 số engine Java/Freemarker
    # <%= 7*7 %> -> ERB (Ruby)
    probes = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]

    for p in probes:
        r = session.get(f"{base_url}/render", params={"name": p}, timeout=5)
        # điều kiện quan trọng: phải thấy "49" (kết quả ĐÃ TÍNH), và KHÔNG còn thấy nguyên chuỗi payload p
        # -- nếu còn thấy "{{7*7}}" nguyên văn, nghĩa là engine chỉ in ra chữ, chưa chạy biểu thức
        if "49" in r.text and p not in r.text:
            print("NGHI SSTI với cú pháp:", p)
            print(r.text[:200])
            return p  # biết được cú pháp engine nào -- bước tiếp theo copy payload RCE đúng engine đó
        print(p, "->", r.status_code)
    return None


if __name__ == "__main__":
    engine_hint = solve_one(s, base)
    print("Cú pháp engine nghi vấn:", engine_hint)
```

## Giải thích cho người mới

- `probes` là 3 cách viết "7 nhân 7" theo cú pháp của 3 nhóm engine phổ biến khác nhau — gửi lần lượt để xem engine thật của target là nhóm nào, giống việc bạn tay thử lần lượt từng cú pháp trong Burp Repeater.
- Điều kiện `"49" in r.text and p not in r.text` là phần quan trọng nhất của file này: chỉ thấy số `49` trong response **chưa đủ** để khẳng định SSTI, vì có thể trang vốn đã có số 49 ở đâu đó sẵn hoặc bạn nhầm — phải đồng thời kiểm tra chuỗi payload gốc (`p`, ví dụ `"{{7*7}}"`) **không còn** xuất hiện nguyên văn trong response, tức là nó đã bị "tính toán" đi chứ không phải in ra y nguyên.
- Khi tìm ra đúng cú pháp (ví dụ `{{7*7}}` cho ra 49 đúng điều kiện), bạn biết chắc engine thuộc nhóm Jinja2/Twig — bước tiếp theo (không nằm trong snippet này) là đổi `7*7` thành 1 payload mạnh hơn dành riêng cho đúng engine đó để chạy được lệnh hệ thống thật, ví dụ với Jinja2 có các chuỗi payload riêng dựa trên class Python có sẵn.

## Lưu ý nhanh

- Chỉ dùng phép tính đơn giản (`7*7`) để nhận diện trước — đừng vội gửi payload chạy lệnh hệ thống ngay khi chưa chắc có SSTI, dễ gây lỗi/sập service không cần thiết.
- `"49"` xuất hiện trong response không tự động nghĩa là SSTI — luôn kiểm tra thêm payload gốc đã biến mất (không còn nguyên văn) để chắc chắn đó là kết quả được tính toán, không phải tình cờ.
- Mỗi "engine" (Jinja2, Twig, Freemarker, ERB...) có bộ payload chạy lệnh hệ thống riêng, không dùng chung được — phải xác định đúng engine (qua bước probe này) trước khi copy payload mạnh hơn.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

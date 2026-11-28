# Lặp qua danh sách đội từ targets.txt

Bạn đã có `solve_one()` chạy đúng cho 1 đội (1 IP). Giờ có 10-20 đội khác dính cùng lỗi, và bạn không muốn gõ tay IP từng đội hay sửa code mỗi lần đổi danh sách — file này chỉ cách đọc danh sách đội từ 1 file `.txt`, tự bỏ qua đội nhà và dòng ghi chú, để `solve_one()` chạy lần lượt (hoặc cùng lúc) cho tất cả đội còn lại.

Đây đúng là cách [`scripts/template.py`](../scripts/template.py) đã làm sẵn — file này giải thích từng dòng code đó, để bạn tự viết lại được nếu cần, hoặc hiểu rõ khi sửa `targets.txt`.

## Snippet copy-là-chạy

```python
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

TARGETS_FILE = Path("scripts/targets.txt")  # file danh sách đội, 1 dòng = 1 đội


def normalize(url):
    url = url.strip()
    if "://" not in url:           # nếu chỉ ghi "10.0.2.1:8000" (thiếu http://)
        url = "http://" + url      # thì tự thêm http:// vào trước
    return url.rstrip("/")          # bỏ dấu "/" dư ở cuối, để nối path sau này không bị "//"


def load_targets(path=TARGETS_FILE):
    targets, our = [], set()
    # Đọc từng dòng trong targets.txt
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()   # bỏ phần sau dấu # (ghi chú), rồi bỏ khoảng trắng 2 đầu
        if not line:
            continue                           # dòng trống hoặc dòng toàn ghi chú -> bỏ qua

        if line.upper().startswith("@OUR_TEAM"):
            # Dòng "@OUR_TEAM http://10.0.1.1:8000" đánh dấu IP đội NHÀ, không phải mục tiêu
            rest = line.split(None, 1)
            if len(rest) > 1 and rest[1].strip():
                our.add(normalize(rest[1].strip()))
            continue                           # không đưa đội nhà vào danh sách mục tiêu

        targets.append(normalize(line))        # dòng bình thường còn lại = 1 đội đối thủ

    # Chặn thêm 1 lớp an toàn: loại localhost/127.0.0.1 và chính IP đội nhà (phòng khi quên @OUR_TEAM)
    blocked = {"127.0.0.1", "localhost", "::1"}
    blocked |= {u.split("//", 1)[-1].split("/", 1)[0].lower() for u in our}
    return [t for t in targets if t.split("//", 1)[-1].split("/", 1)[0].lower() not in blocked]


def solve_one(session, base_url):
    # Dán logic đã giải tay (Burp) vào đây, ví dụ tạm:
    r = session.get(f"{base_url}/", timeout=5)
    return r.status_code


if __name__ == "__main__":
    targets = load_targets()
    print(f"[*] Có {len(targets)} đội trong danh sách")

    # Chạy cùng lúc cho nhiều đội (4 đội song song) thay vì chờ từng đội xong mới sang đội kế
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(solve_one, requests.Session(), t) for t in targets]
        for fut in as_completed(futs):
            print(fut.result())
```

## Giải thích cho người mới

- File `targets.txt` là 1 file text thường, mỗi dòng ghi 1 địa chỉ đội, ví dụ `http://10.0.2.1:8000` hoặc chỉ `10.0.2.1:8000`. Xem mẫu thật ở [`scripts/targets.example.txt`](../scripts/targets.example.txt) — copy file đó, đổi tên thành `targets.txt`, sửa lại IP đúng với giải đang thi.
- Dòng bắt đầu bằng `#` là ghi chú thuần, Python bỏ qua hoàn toàn — dùng để note, không ảnh hưởng chạy script.
- Dòng bắt đầu bằng `@OUR_TEAM` (ví dụ `@OUR_TEAM http://10.0.1.1:8000`) là cách đánh dấu **IP đội nhà** ngay trong file — `load_targets()` đọc dòng này để biết IP nào cần loại ra, không đưa vào danh sách bắn, tránh việc bạn tự tấn công/tự xoá dữ liệu đội mình.
- `normalize(url)`: chuẩn hoá 1 dòng thành URL dùng được ngay cho `requests` — nếu bạn chỉ gõ IP:port mà quên `http://`, hàm này tự thêm vào; nó cũng cắt dấu `/` dư ở cuối để lúc nối `f"{base_url}/login"` không ra `http://x.x.x.x//login`.
- `load_targets()` trả về 1 **list** (danh sách) các URL đội đối thủ, đã lọc sạch dòng trống, dòng ghi chú, dòng đội nhà, và cả `localhost`/`127.0.0.1` (lọc thêm lần 2 cho chắc, phòng khi bạn ghi nhầm IP đội nhà mà quên đánh dấu `@OUR_TEAM`).
- `ThreadPoolExecutor(max_workers=4)`: chạy 4 đội cùng lúc ("chạy nhiều việc đồng thời" — thay vì gửi request cho đội 1 xong mới gửi đội 2, máy gửi cho 4 đội song song, nhanh hơn nhiều khi có 15-20 đội). `as_completed(futs)` trả kết quả về ngay khi đội nào xong trước, không bắt chờ theo đúng thứ tự liệt kê.
- `solve_one(session, base_url)` chính là hàm bạn đã viết ở các bài trước (xem [`00_Bat_Dau_Tu_Zero.md`](../00_Bat_Dau_Tu_Zero.md) mục 3.8) — ở đây chỉ cần hiểu: nó được gọi lại **1 lần cho mỗi đội** trong `targets`, với `base_url` là IP đội đó.
- Trong thực tế thi, bạn **không cần viết lại** đoạn này — chỉ cần copy `solve_one()` đã test chạy ra flag (ở bài giải tay 1 đội) dán đè vào hàm `solve_one()` có sẵn trong [`scripts/template.py`](../scripts/template.py), rồi chạy `python scripts/template.py`. `template.py` đã có sẵn đúng `load_targets()`, `normalize()`, cộng thêm phần lưu flag và bắt lỗi từng đội — xem tiếp [`02_Trich_Flag.md`](02_Trich_Flag.md) và [`03_Luu_Flag_Theo_Doi.md`](03_Luu_Flag_Theo_Doi.md).

## Lưu ý nhanh

- Luôn kiểm tra `targets.txt` có đúng dòng `@OUR_TEAM <IP đội nhà>` trước khi chạy — thiếu dòng này script có thể tự bắn vào đội mình.
- Số sau `max_workers=` không nên để quá cao (8-10 trở lên) — gửi dồn dập dễ bị WAF (tường lửa ứng dụng web, công cụ chặn request đáng ngờ) của chính server mục tiêu chặn, hoặc làm sập service của họ (phạm quy).
- Nếu `load_targets()` trả về list rỗng `[]`: kiểm tra đường dẫn `TARGETS_FILE` có đúng, file `targets.txt` có tồn tại, và có dòng nào không bị cả `#` lẫn `@OUR_TEAM` che mất không.
- Mỗi lần ban tổ chức đổi/thêm đội giữa giờ thi, chỉ cần sửa `targets.txt`, không cần sửa code.

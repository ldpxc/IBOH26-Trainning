# Lưu flag ra file, không bị mất/trùng/lộ nhầm

Bạn đã trích được flag từ response (xem [`02_Trich_Flag.md`](02_Trich_Flag.md)), nhưng script chạy cho 15-20 đội suốt nhiều phút/giờ — bạn cần **ghi flag ra file ngay khi tìm được**, không chỉ `print()` ra màn hình (màn hình cuộn mất, script treo giữa đường là mất hết). File này chỉ cách lưu flag ra file kèm theo loại trùng và tránh lưu nhầm flag của chính đội mình.

## Snippet copy-là-chạy

```python
from pathlib import Path

OUT_FILE = Path("results/flags.txt")   # file lưu flag, append thêm mỗi lần tìm được, không ghi đè
OWN_FLAGS = {
    # Dán flag của chính đội mình vào đây để không bao giờ lưu/nộp nhầm
    # "FHACKER2026{" + "0" * 64 + "}",
}


def save_flags(team, flags):
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)   # tự tạo thư mục results/ nếu chưa có

    # Đọc các flag đã lưu từ trước, để không ghi trùng lại lần nữa
    seen = set()
    if OUT_FILE.exists():
        seen = {x.strip() for x in OUT_FILE.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()}

    with OUT_FILE.open("a", encoding="utf-8") as f:   # "a" = append, ghi NỐI vào cuối file, không xoá nội dung cũ
        for flag in flags:
            if flag in OWN_FLAGS or flag in seen:
                continue                               # flag của mình hoặc đã lưu rồi -> bỏ qua, không ghi lại
            f.write(flag + "\n")
            seen.add(flag)
            print(f"[+] {team} {flag}")                # in ra màn hình để biết ngay lúc đang chạy


# Ví dụ gọi: 1 đội tìm được 1 flag
save_flags("http://10.0.2.1:8000", ["FHACKER2026{" + "a" * 64 + "}"])
```

## Giải thích cho người mới

- `Path("results/flags.txt")`: đường dẫn tới file lưu kết quả — dùng thư viện `pathlib` (có sẵn trong Python, không cần cài) vì nó cho nhiều hàm tiện (`.exists()`, `.mkdir()`, `.read_text()`) gọn hơn cách viết đường dẫn kiểu chuỗi thường.
- `OWN_FLAGS`: 1 **set** (giống list nhưng không có thứ tự và tự loại trùng) chứa (các) flag của chính đội mình. Phải tự dán flag đội nhà vào đây **trước khi** chạy mass cho nhiều đội — nếu không, lúc quét dính đúng flag nhà mình, script sẽ tưởng là flag "chiếm được" và lưu/nộp nhầm.
- `OUT_FILE.parent.mkdir(parents=True, exist_ok=True)`: tạo thư mục chứa file (`results/`) nếu nó chưa tồn tại — `exist_ok=True` để không báo lỗi nếu thư mục đã có rồi.
- Khối đọc `seen = {...}`: trước khi ghi thêm, đọc lại toàn bộ flag **đã lưu từ các lần chạy trước** trong cùng file, để không ghi trùng thêm 1 lần nữa nếu bạn chạy lại script (ví dụ chạy lại vì script bị dừng giữa đường).
- `OUT_FILE.open("a", encoding="utf-8")`: mở file ở chế độ `"a"` (append = ghi nối vào cuối). Khác với `"w"` (write) sẽ **xoá sạch nội dung cũ** rồi ghi mới — tuyệt đối không dùng `"w"` ở đây vì mỗi lần script chạy lại sẽ mất hết flag đã lưu trước đó.
- `if flag in OWN_FLAGS or flag in seen: continue`: bỏ qua, không ghi, nếu flag là của đội mình HOẶC đã được ghi từ trước — `continue` nghĩa là "bỏ vòng lặp hiện tại, nhảy sang phần tử tiếp theo trong `for`".
- `print(f"[+] {team} {flag}")`: in ngay ra màn hình kèm tên/IP đội để lúc đang thi bạn biết **ngay lúc đó** vừa lấy được flag của đội nào, không cần mở file ra đọc.
- Hàm `save_flags(team, flags)` này **đã có sẵn y nguyên** trong [`scripts/template.py`](../scripts/template.py) — không cần gõ lại, chỉ cần sửa `OWN_FLAGS` ở đầu file cho đúng flag đội mình trước khi chạy thi thật.

## Lưu ý nhanh

- Luôn dùng `"a"` (append), không bao giờ dùng `"w"` cho file kết quả — `"w"` xoá hết dữ liệu cũ mỗi lần mở.
- Nhớ điền `OWN_FLAGS` **trước** khi bắn mass, không điền sau — điền sau thì các flag nhà đã lưu/nộp nhầm trong lúc chạy trước đó vẫn còn trong file.
- Không `git add -A`/commit file `results/flags.txt` (chứa flag thật) vào repo chung nếu repo có thể bị người khác xem.
- Muốn biết flag nào của đội nào: sửa dòng ghi thành `f.write(f"{team},{flag}\n")` thay vì chỉ ghi `flag`, để mỗi dòng có cả tên đội đi kèm.

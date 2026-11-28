# Path Traversal / Directory Traversal

## 1. Bản chất

Path Traversal xảy ra khi ứng dụng dùng input để xây dựng đường dẫn file mà không đảm bảo kết quả cuối cùng vẫn nằm trong thư mục được phép. Input có thể chứa `..`, dấu phân cách, đường dẫn tuyệt đối hoặc các dạng mã hóa khiến kiểm tra chuỗi ban đầu bị sai.

Điểm cần phân biệt:

- **Path traversal:** vượt ra ngoài thư mục dự kiến.
- **Arbitrary file read:** đọc được file mà ứng dụng không định cho phép.
- **LFI/RFI:** đưa file vào quá trình include/execute, thường gắn với ngôn ngữ/template cụ thể.
- **File download thông thường:** chức năng hợp lệ nếu chỉ truy cập tài nguyên được phép.

Không phải response có nội dung file nào cũng là lỗ hổng; cần chứng minh vượt authorization hoặc vượt thư mục cho phép.

## 2. Vị trí thường gặp

- `GET /download?file=report.pdf`.
- `GET /image?name=avatar.png`.
- Template/include: `page=home`.
- Log viewer, backup viewer.
- Import/export archive.
- Static file route custom.
- File được chỉ định trong JSON, multipart field hoặc cookie.
- Tên file được lưu từ request trước rồi dùng lại ở request sau.

Input có thể chỉ là một phần tên file, nhưng server lại ghép với prefix/suffix:

```python
path = "/var/www/files/" + user_input + ".pdf"
```

## 3. Nhận diện có kiểm chứng

### Bước 1: Xác định file hợp lệ

Trong lab, tạo:

```text
lab/
  allowed/
    report.txt       -> "PUBLIC_REPORT"
    probe.txt        -> "ALLOWED_PROBE"
  private/
    probe.txt        -> "OUTSIDE_ALLOWED"
```

Ứng dụng chỉ được phép đọc `allowed/`. File ngoài thư mục là dữ liệu giả, không dùng `/etc/passwd`, private key hoặc dữ liệu thật.

### Bước 2: Lưu baseline

Ghi request đọc `report.txt`: status, body, content type, header cache, redirect.

### Bước 3: Thử thay đổi path tối thiểu

Các dạng kinh điển để phân tích trong lab:

```text
../private/probe.txt
../../private/probe.txt
..\private\probe.txt
%2e%2e%2fprivate%2fprobe.txt
..%2fprivate%2fprobe.txt
..%252fprivate%252fprobe.txt
```

Không gửi tất cả rồi chọn response dài nhất. Với mỗi trường hợp cần biết:

- Server decode mấy lần?
- Kiểm tra path trước hay sau decode?
- Có normalize `..` không?
- Prefix/suffix nào được thêm?
- Filesystem hiểu separator nào?

### Bước 4: Đối chứng

So sánh:

- Tên file hợp lệ.
- File không tồn tại.
- Path vượt thư mục tới file test.
- Path có cùng độ dài nhưng không chứa traversal.

Điều này giúp tránh nhầm lỗi 404/500 hoặc trang mặc định với nội dung file.

## 4. Encoding và canonicalization

### 4.1. Một lần decode

```text
..%2fprivate%2fprobe.txt
  -> ../private/probe.txt
```

Nếu filter chạy trước decode thì có thể không thấy `../`; nếu filesystem nhận chuỗi sau decode thì path đã thay đổi ý nghĩa.

### 4.2. Double encoding

```text
..%252fprivate%252fprobe.txt
  -> decode 1: ..%2fprivate%2fprobe.txt
  -> decode 2: ../private/probe.txt
```

Không có nghĩa mọi ứng dụng đều decode hai lần. Hãy kiểm chứng pipeline bằng log lab.

### 4.3. Separator và đường dẫn tuyệt đối

Windows và POSIX khác nhau về separator, drive, UNC, reserved names và case. Đường dẫn tuyệt đối có thể làm prefix bị bỏ qua tùy API ghép path. Không nên giả định `base + input` luôn giữ input dưới base.

### 4.4. Suffix và null byte

Một số tài liệu cũ đề cập null byte để cắt suffix. Hành vi này phụ thuộc ngôn ngữ/runtime và thường không áp dụng cho stack hiện đại. Không nên coi đó là kỹ thuật mặc định; hãy kiểm tra phiên bản lab và lỗi thực tế.

## 5. Khai thác có kiểm soát

Mục tiêu chứng minh tối thiểu:

1. Ứng dụng định giới hạn trong `allowed/`.
2. Input được đưa vào path.
3. Sau normalization, path trỏ tới `private/probe.txt`.
4. Response trả marker `OUTSIDE_ALLOWED`.

Dừng ở đây. Không tiếp tục liệt kê thư mục, đọc cấu hình, khóa hoặc dữ liệu người dùng.

Nếu có LFI, phải tách hai câu hỏi:

- Đọc được file ngoài phạm vi không?
- Nội dung có được engine **thực thi/include** không?

Một file text được trả về không đồng nghĩa với code execution. Không chèn mã vào log hoặc tạo web shell ngoài một lab được thiết kế riêng cho bài đó.

## 6. Các lỗi phòng thủ thường gặp

### Chỉ replace chuỗi

```python
unsafe = user_input.replace("../", "")
```

Cách này bỏ qua encoding, separator khác, dạng lồng nhau và canonicalization. Blacklist không đảm bảo tính đúng đắn.

### Chỉ kiểm tra prefix chuỗi

```python
if full_path.startswith("/var/www/files"):
    ...
```

Có thể sai với `..`, symlink, separator, case, hoặc thư mục có cùng prefix như `/var/www/files_backup`.

### Kiểm tra trước khi normalize

Nếu kiểm tra raw input rồi mới decode/resolve, kết quả kiểm tra không mô tả path thực tế được mở.

### Bỏ qua symlink

Ngay cả path canonical nằm trong thư mục lúc kiểm tra, symlink hoặc race vẫn có thể thay đổi mục tiêu. Với hệ thống yêu cầu cao, cần thiết kế filesystem và quyền OS phù hợp.

## 7. Khắc phục

### Ưu tiên không dùng path từ user

- Nhận `file_id`, tra database để lấy path cố định.
- Dùng object storage với key được kiểm soát.
- Chỉ phục vụ file qua danh mục allowlist.

### Nếu bắt buộc nhận tên file

1. Chỉ cho phép basename, không cho phép separator.
2. Reject input có NUL hoặc ký tự không hợp lệ.
3. Canonicalize/resolve path.
4. Kiểm tra path cuối cùng nằm dưới thư mục gốc bằng quan hệ path, không bằng prefix chuỗi.
5. Mở file với quyền tối thiểu và xử lý symlink theo chính sách.

Ví dụ Python mang tính khung:

```python
from pathlib import Path

BASE = Path("/srv/lab/allowed").resolve()

def resolve_allowed(name: str) -> Path:
    if not name or Path(name).name != name:
        raise ValueError("Chỉ chấp nhận tên file, không chấp nhận đường dẫn")
    candidate = (BASE / name).resolve()
    if candidate != BASE and BASE not in candidate.parents:
        raise ValueError("Path nằm ngoài thư mục cho phép")
    if not candidate.is_file():
        raise FileNotFoundError(name)
    return candidate
```

Đoạn này không thay thế kiểm soát quyền OS, chống symlink/race hoặc authorization theo user. Cần kiểm thử trên hệ điều hành triển khai thật.

### Bổ sung

- Chạy service với user ít quyền.
- Không mount toàn bộ filesystem nhạy cảm vào container.
- Không trả path nội bộ trong lỗi.
- Log path đã normalize nhưng tránh lộ dữ liệu nhạy cảm.
- Kiểm tra cả download, preview, thumbnail, export và archive extraction.

## 8. Zip Slip và biến thể liên quan

Khi giải nén archive, tên entry cũng là path do dữ liệu kiểm soát. Cần kiểm tra từng entry sau khi normalize:

- Không ghi ngoài thư mục đích.
- Không cho phép absolute path.
- Không cho phép symlink/hardlink nguy hiểm.
- Giới hạn số file, kích thước giải nén và tổng dung lượng.

Path traversal không chỉ nằm ở tham số HTTP trực tiếp.

## 9. Checklist

- [ ] Có file test trong và ngoài thư mục được phép.
- [ ] Xác định prefix/suffix và số lần decode.
- [ ] Kiểm tra path sau canonicalization.
- [ ] Đối chứng với file không tồn tại và input hợp lệ.
- [ ] Không đọc file nhạy cảm thật.
- [ ] Không nhầm download hợp lệ với traversal.
- [ ] Phân biệt file read với include/execute.
- [ ] Sửa bằng ID/allowlist/canonical path + quyền OS.
- [ ] Kiểm tra symlink, archive và các code path gián tiếp.

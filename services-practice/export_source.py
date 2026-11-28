#!/usr/bin/env python3
"""export_source.py -- đóng gói mã nguồn 1 service thành file .zip để gửi
cho team (mô phỏng Điều 2.3 quy chế thật: "Đội không được sửa mã nguồn
service" -- ngụ ý đội CÓ source để đọc, chỉ không được sửa).

Tự loại bỏ các đoạn đánh dấu `// === BEGIN_EXPORT_STRIP: <tên> ===` ...
`// === END_EXPORT_STRIP: <tên> === ` trước khi đóng gói -- hiện dùng đúng 1
chỗ: đoạn "debug flag theo theme" (dark mode) trong
notevault/public/inc/config.php. ĐỪNG xoá marker đó trong code thật, chỉ
script này mới được phép cắt nó ra khỏi BẢN GỬI ĐI -- bản đang chạy thật vẫn
giữ nguyên để còn khai thác được.

Dùng (chạy từ thư mục services-practice/):
    python3 export_source.py --service notevault
    python3 export_source.py --service pulseapi
    python3 export_source.py --service socialhub
    python3 export_source.py --all          # xuất cả 3

Kết quả: .runtime/export/<service>_source.zip -- gửi file này cho đúng team
(kèm thông tin kết nối ở ROUND_GUIDE.md mục 3). Giống nhau cho cả 2 team
(code "giống hệt các đội khác" đúng Điều 2.3), nên chỉ cần xuất 1 lần/service,
gửi cùng 1 file cho cả team A và team B.
"""
import argparse
import os
import re
import zipfile

# Regex cắt nguyên khối từ dòng BEGIN tới hết dòng END (bao gồm cả 2 dòng
# marker) -- không giả định số dòng ở giữa, không giả định nội dung comment.
STRIP_RE = re.compile(
    r"[ \t]*//\s*===\s*BEGIN_EXPORT_STRIP:.*?===\s*END_EXPORT_STRIP:[^\n]*\n?",
    re.S,
)

# Mỗi service: thư mục gốc (tương đối so với services-practice/) + danh sách
# đường dẫn coi là "mã nguồn" (không gồm Dockerfile/docker-compose*/
# compose.arena.yml -- đó là hạ tầng triển khai của buổi luyện tập, không
# phải mã nguồn app thật).
SERVICE_FILES = {
    "notevault": {
        "root": "notevault",
        "include": ["public", "app/seed.php", "app/write_file_flags.php", "entrypoint.sh"],
    },
    "pulseapi": {
        "root": "pulseapi",
        "include": ["app/app.py", "app/flagutil.py", "requirements.txt"],
    },
    "socialhub": {
        "root": "socialhub",
        "include": ["app/server.js", "app/bot.js", "app/flagutil.js", "package.json"],
    },
}

TEXT_EXT = {".php", ".py", ".js", ".sh", ".txt", ".json", ".md"}


def iter_files(root: str, include: list):
    for item in include:
        full = os.path.join(root, item)
        if os.path.isdir(full):
            for dirpath, _dirnames, filenames in os.walk(full):
                for fn in filenames:
                    p = os.path.join(dirpath, fn)
                    yield p, os.path.relpath(p, root)
        elif os.path.isfile(full):
            yield full, os.path.relpath(full, root)
        else:
            print(f"[!] Không thấy {full}, bỏ qua")


def export_service(service: str, out_dir: str) -> str:
    cfg = SERVICE_FILES[service]
    out_path = os.path.join(out_dir, f"{service}_source.zip")
    os.makedirs(out_dir, exist_ok=True)
    stripped = 0
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for abs_path, rel_path in iter_files(cfg["root"], cfg["include"]):
            ext = os.path.splitext(abs_path)[1].lower()
            if ext in TEXT_EXT:
                with open(abs_path, encoding="utf-8") as f:
                    content = f.read()
                content, n = STRIP_RE.subn("", content)
                stripped += n
                zf.writestr(f"{service}/{rel_path}", content)
            else:
                zf.write(abs_path, f"{service}/{rel_path}")
    note = f" (đã cắt {stripped} đoạn EXPORT_STRIP)" if stripped else ""
    print(f"[*] Đã xuất: {out_path}{note}")
    return out_path


def main():
    ap = argparse.ArgumentParser(description="Xuất mã nguồn 1 service thành .zip để gửi cho team.")
    ap.add_argument("--service", choices=sorted(SERVICE_FILES), help="Service cần xuất")
    ap.add_argument("--all", action="store_true", help="Xuất cả 3 service")
    ap.add_argument("--out-dir", default=".runtime/export", help="Thư mục lưu file zip")
    args = ap.parse_args()

    if not args.service and not args.all:
        print("Cần --service <notevault|pulseapi|socialhub> hoặc --all")
        raise SystemExit(1)

    for svc in (list(SERVICE_FILES) if args.all else [args.service]):
        export_service(svc, args.out_dir)


if __name__ == "__main__":
    main()

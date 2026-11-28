#!/usr/bin/env python3
"""
LAN File Share Web Service
- Binds to 0.0.0.0:<port> for LAN access
- Password-protected session authentication
- Dedicated storage directory with folder navigation, upload, and per-file download
- Cross-platform compatible (Linux server, Windows/macOS/Linux browser clients)
"""

from __future__ import annotations

import argparse
import functools
import ntpath
import os
import posixpath
import re
import secrets
import shutil
import socket
from datetime import datetime
from pathlib import Path
from typing import Callable

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)

# Characters unsafe on Linux/Windows filesystems or control characters
_UNSAFE_FILENAME_RE = re.compile(r'[\x00-\x1f<>:"/\\|?*]')

MAX_PREVIEW_BYTES = 2 * 1024 * 1024  # 2 MB
TRASH_DIR_NAME = "trash"

_NON_VIEWABLE_EXTENSIONS = {
    ".exe", ".elf", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".msi", ".com",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst", ".iso", ".img",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac", ".ogg", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

_HTML_EXTENSIONS = {".html", ".htm"}

LOGIN_HTML = """<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LAN File Share - Đăng nhập</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; display: flex; align-items: center;
      justify-content: center; min-height: 100vh; padding: 16px;
    }
    .card {
      background: #1e293b; border: 1px solid #334155; border-radius: 12px;
      padding: 32px; width: 100%; max-width: 380px; box-shadow: 0 10px 30px rgba(0,0,0,0.4);
    }
    h1 { margin: 0 0 8px; font-size: 22px; color: #f8fafc; }
    p { margin: 0 0 24px; color: #94a3b8; font-size: 14px; }
    label { display: block; font-size: 13px; margin-bottom: 6px; color: #cbd5e1; }
    input[type="password"] {
      width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569;
      background: #0f172a; color: #f8fafc; font-size: 15px; outline: none;
    }
    input[type="password"]:focus { border-color: #38bdf8; }
    button {
      margin-top: 16px; width: 100%; padding: 10px 16px; border: none; border-radius: 8px;
      background: #0284c7; color: #fff; font-size: 15px; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #0369a1; }
    .alert {
      background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5;
      padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>LAN File Share</h1>
    <p>Nhập mật khẩu để truy cập kho chia sẻ file.</p>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, msg in messages %}
        <div class="alert">{{ msg }}</div>
      {% endfor %}
    {% endwith %}
    <form method="post" action="{{ url_for('login') }}">
      <label for="password">Mật khẩu</label>
      <input id="password" name="password" type="password" autofocus required placeholder="Nhập mật khẩu...">
      <button type="submit">Đăng nhập</button>
    </form>
  </div>
</body>
</html>
"""

INDEX_HTML = """<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LAN File Share</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; padding: 24px 16px;
    }
    .container { max-width: 980px; margin: 0 auto; }
    header {
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      gap: 12px; margin-bottom: 20px;
    }
    h1 { margin: 0; font-size: 22px; color: #f8fafc; }
    .btn {
      display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px;
      border-radius: 8px; border: 1px solid transparent; font-size: 14px;
      font-weight: 500; text-decoration: none; cursor: pointer;
    }
    .btn-primary { background: #0284c7; color: #fff; }
    .btn-primary:hover { background: #0369a1; }
    .btn-secondary { background: #1e293b; color: #e2e8f0; border-color: #334155; }
    .btn-secondary:hover { background: #334155; }
    .btn-download { background: #059669; color: #fff; padding: 6px 12px; font-size: 13px; }
    .btn-download:hover { background: #047857; }
    .btn-view { background: #2563eb; color: #fff; padding: 6px 12px; font-size: 13px; margin-right: 6px; }
    .btn-view:hover { background: #1d4ed8; }
    .btn-delete { background: #dc2626; color: #fff; padding: 6px 12px; font-size: 13px; margin-left: 6px; }
    .btn-delete:hover { background: #b91c1c; }
    .inline-form { display: inline; margin: 0; }
    .toolbar {
      display: flex; flex-wrap: wrap; gap: 12px; background: #1e293b;
      border: 1px solid #334155; border-radius: 10px; padding: 16px; margin-bottom: 16px;
      align-items: center; justify-content: space-between;
    }
    .upload-form, .mkdir-form { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    input[type="file"], input[type="text"] {
      background: #0f172a; color: #e2e8f0; border: 1px solid #475569;
      border-radius: 8px; padding: 7px 10px; font-size: 13px;
    }
    .breadcrumb {
      display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
      font-size: 14px; margin-bottom: 12px; color: #94a3b8;
    }
    .breadcrumb a { color: #38bdf8; text-decoration: none; }
    .breadcrumb a:hover { text-decoration: underline; }
    .card {
      background: #1e293b; border: 1px solid #334155; border-radius: 10px; overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }
    th { background: #0f172a; color: #94a3b8; font-weight: 600; font-size: 12px; text-transform: uppercase; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(51, 65, 85, 0.35); }
    .name-link { color: #f8fafc; text-decoration: none; font-weight: 500; word-break: break-all; }
    .name-link:hover { color: #38bdf8; text-decoration: underline; }
    .muted { color: #94a3b8; font-size: 13px; white-space: nowrap; }
    .actions { text-align: right; white-space: nowrap; }
    .alert {
      padding: 10px 14px; border-radius: 8px; margin-bottom: 14px; font-size: 14px;
    }
    .alert-success { background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; }
    .alert-error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }
    .empty { padding: 32px; text-align: center; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>LAN File Share</h1>
      <a class="btn btn-secondary" href="{{ url_for('logout') }}">Đăng xuất</a>
    </header>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, msg in messages %}
        <div class="alert alert-{{ 'error' if category == 'error' else 'success' }}">{{ msg }}</div>
      {% endfor %}
    {% endwith %}

    <div class="toolbar">
      <form class="upload-form" method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
        <input type="hidden" name="dir" value="{{ current_rel }}">
        <input type="file" name="files" multiple required>
        <button class="btn btn-primary" type="submit">Upload</button>
      </form>

      <form class="mkdir-form" method="post" action="{{ url_for('mkdir') }}">
        <input type="hidden" name="dir" value="{{ current_rel }}">
        <input type="text" name="folder_name" placeholder="Tên thư mục mới..." required>
        <button class="btn btn-secondary" type="submit">Tạo thư mục</button>
      </form>
    </div>

    <nav class="breadcrumb" aria-label="Breadcrumb">
      <a href="{{ url_for('index') }}">Kho gốc</a>
      {% for crumb in breadcrumbs %}
        <span>/</span>
        <a href="{{ url_for('index', path=crumb.path) }}">{{ crumb.name }}</a>
      {% endfor %}
    </nav>

    <div class="card">
      {% if parent_rel is not none or items %}
      <table>
        <thead>
          <tr>
            <th>Tên</th>
            <th>Kích thước</th>
            <th>Cập nhật</th>
            <th class="actions">Thao tác</th>
          </tr>
        </thead>
        <tbody>
          {% if parent_rel is not none %}
          <tr>
            <td>
              <a class="name-link" href="{{ url_for('index', path=parent_rel) if parent_rel else url_for('index') }}">.. (Quay lại)</a>
            </td>
            <td class="muted">-</td>
            <td class="muted">-</td>
            <td class="actions"></td>
          </tr>
          {% endif %}
          {% for item in items %}
          <tr>
            <td>
              {% if item.is_dir %}
                <a class="name-link" href="{{ url_for('index', path=item.rel_path) }}">[Thư mục] {{ item.name }}</a>
              {% else %}
                <span class="name-link">{{ item.name }}</span>
              {% endif %}
            </td>
            <td class="muted">{{ item.size_str }}</td>
            <td class="muted">{{ item.mtime_str }}</td>
            <td class="actions">
              {% if not item.is_dir %}
                {% if item.is_viewable %}
                  <a class="btn btn-view" href="{{ url_for('view_file', path=item.rel_path) }}">Xem</a>
                {% endif %}
                <a class="btn btn-download" href="{{ url_for('download', path=item.rel_path) }}">Download</a>
              {% endif %}
              <form class="inline-form" method="post" action="{{ url_for('delete_item') }}"
                    onsubmit="return confirm('Chuyển mục này vào thùng rác?');">
                <input type="hidden" name="path" value="{{ item.rel_path }}">
                <button class="btn btn-delete" type="submit">Xóa</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
        <div class="empty">Thư mục hiện đang trống. Hãy bấm <strong>Upload</strong> để tải file lên.</div>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""

VIEW_HTML = """<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ filename }} - Xem tài liệu</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; padding: 24px 16px;
    }
    .container { max-width: 1080px; margin: 0 auto; }
    header {
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      gap: 12px; margin-bottom: 16px;
    }
    h1 { margin: 0; font-size: 18px; color: #f8fafc; word-break: break-all; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .btn {
      display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px;
      border-radius: 8px; border: 1px solid transparent; font-size: 14px;
      font-weight: 500; text-decoration: none; cursor: pointer;
    }
    .btn-secondary { background: #1e293b; color: #e2e8f0; border-color: #334155; }
    .btn-secondary:hover { background: #334155; }
    .btn-download { background: #059669; color: #fff; }
    .btn-download:hover { background: #047857; }
    .card {
      background: #1e293b; border: 1px solid #334155; border-radius: 10px; overflow: hidden;
    }
    pre {
      margin: 0; padding: 20px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px; line-height: 1.55; color: #e2e8f0; background: #0f172a;
    }
    iframe.html-preview {
      width: 100%; height: 72vh; border: none; background: #ffffff; display: block;
    }
    details { border-top: 1px solid #334155; }
    summary {
      padding: 12px 16px; cursor: pointer; font-size: 13px; font-weight: 600;
      color: #94a3b8; background: #1e293b; user-select: none;
    }
    summary:hover { color: #f8fafc; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{{ filename }}</h1>
      <div class="actions">
        <a class="btn btn-secondary" href="{{ back_url }}">Quay lại</a>
        <a class="btn btn-download" href="{{ url_for('download', path=rel_path) }}">Download</a>
      </div>
    </header>

    <div class="card">
      {% if is_html %}
        <iframe class="html-preview" sandbox="" srcdoc="{{ content }}"></iframe>
        <details>
          <summary>Xem mã nguồn HTML</summary>
          <pre>{{ content }}</pre>
        </details>
      {% else %}
        <pre>{{ content }}</pre>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""


def format_size(size_bytes: int) -> str:
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


def sanitize_filename(raw_name: str) -> str:
    """Extract basename from Windows or POSIX client paths and sanitize unsafe chars."""
    name = ntpath.basename(posixpath.basename(raw_name)).strip()
    name = _UNSAFE_FILENAME_RE.sub("_", name)
    # Trailing dots/spaces are invalid on Windows filesystems
    name = name.rstrip(". ")
    if not name or name in {".", ".."}:
        return ""
    return name


def unique_destination(directory: Path, filename: str) -> Path:
    """Return a non-colliding Path in directory by appending (n) if needed."""
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    counter = 1
    while True:
        candidate = directory / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def resolve_safe_path(root: Path, rel_path: str) -> Path:
    """Resolve rel_path strictly inside root and block access to trash; abort(403) otherwise."""
    cleaned = rel_path.replace("\\", "/").lstrip("/")
    target = (root / cleaned).resolve()
    if target != root and root not in target.parents:
        abort(403)
    if target != root:
        first_part = target.relative_to(root).parts[0]
        if first_part == TRASH_DIR_NAME:
            abort(403)
    return target


def is_viewable_file(path: Path) -> bool:
    """Return True if path is a text/HTML file safe for in-browser preview."""
    if not path.is_file():
        return False
    if path.suffix.lower() in _NON_VIEWABLE_EXTENSIONS:
        return False
    try:
        size = path.stat().st_size
        if size > MAX_PREVIEW_BYTES:
            return False
        with path.open("rb") as f:
            sample = f.read(8192)
    except OSError:
        return False

    if not sample:
        return True
    if sample.startswith((b"\x7fELF", b"MZ")) or b"\x00" in sample:
        return False

    # Trim incomplete trailing UTF-8 sequence at the 8KB boundary before decoding
    for trim in range(4):
        chunk = sample[: len(sample) - trim] if trim else sample
        try:
            chunk.decode("utf-8")
            return True
        except UnicodeDecodeError:
            continue
    return False


def get_lan_ips() -> list[str]:
    ips: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips


def create_app(storage_dir: Path, password: str, secret_key: str | None = None) -> Flask:
    storage_root = storage_dir.resolve()
    storage_root.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__)
    app.secret_key = secret_key or os.environ.get("LAN_SHARE_SECRET") or secrets.token_hex(32)
    app.config["STORAGE_ROOT"] = storage_root
    app.config["SHARE_PASSWORD"] = password

    def login_required(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("authenticated"):
            return redirect(url_for("index"))
        if request.method == "POST":
            entered = request.form.get("password", "")
            if secrets.compare_digest(entered, app.config["SHARE_PASSWORD"]):
                session["authenticated"] = True
                return redirect(url_for("index"))
            flash("Mật khẩu không đúng. Vui lòng thử lại.", "error")
        return render_template_string(LOGIN_HTML)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        rel_path = request.args.get("path", "").strip()
        target_dir = resolve_safe_path(storage_root, rel_path)
        if not target_dir.exists() or not target_dir.is_dir():
            abort(404)

        current_rel = "" if target_dir == storage_root else target_dir.relative_to(storage_root).as_posix()

        breadcrumbs = []
        if current_rel:
            parts = current_rel.split("/")
            for idx, part in enumerate(parts):
                breadcrumbs.append({"name": part, "path": "/".join(parts[: idx + 1])})

        parent_rel = None
        if target_dir != storage_root:
            parent_path = target_dir.parent.relative_to(storage_root).as_posix()
            parent_rel = "" if parent_path == "." else parent_path

        items = []
        entries = sorted(target_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        for entry in entries:
            if target_dir == storage_root and entry.name == TRASH_DIR_NAME:
                continue
            stat = entry.stat()
            is_dir = entry.is_dir()
            items.append(
                {
                    "name": entry.name,
                    "is_dir": is_dir,
                    "is_viewable": False if is_dir else is_viewable_file(entry),
                    "rel_path": entry.relative_to(storage_root).as_posix(),
                    "size_str": "-" if is_dir else format_size(stat.st_size),
                    "mtime_str": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                }
            )

        return render_template_string(
            INDEX_HTML,
            items=items,
            current_rel=current_rel,
            parent_rel=parent_rel,
            breadcrumbs=breadcrumbs,
        )

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        rel_dir = request.form.get("dir", "").strip()
        target_dir = resolve_safe_path(storage_root, rel_dir)
        if not target_dir.exists() or not target_dir.is_dir():
            abort(404)

        uploaded_files = request.files.getlist("files")
        saved_count = 0
        for file_storage in uploaded_files:
            if not file_storage or not file_storage.filename:
                continue
            safe_name = sanitize_filename(file_storage.filename)
            if not safe_name:
                continue
            dest = unique_destination(target_dir, safe_name)
            file_storage.save(dest)
            saved_count += 1

        if saved_count > 0:
            flash(f"Đã tải lên thành công {saved_count} file.", "success")
        else:
            flash("Không có file hợp lệ nào được tải lên.", "error")

        return redirect(url_for("index", path=rel_dir) if rel_dir else url_for("index"))

    @app.route("/mkdir", methods=["POST"])
    @login_required
    def mkdir():
        rel_dir = request.form.get("dir", "").strip()
        target_dir = resolve_safe_path(storage_root, rel_dir)
        if not target_dir.exists() or not target_dir.is_dir():
            abort(404)

        folder_name = sanitize_filename(request.form.get("folder_name", ""))
        if not folder_name or (target_dir == storage_root and folder_name == TRASH_DIR_NAME):
            flash("Tên thư mục không hợp lệ.", "error")
        else:
            new_dir = target_dir / folder_name
            if new_dir.exists():
                flash("Thư mục hoặc file cùng tên đã tồn tại.", "error")
            else:
                new_dir.mkdir(parents=False, exist_ok=False)
                flash(f"Đã tạo thư mục '{folder_name}'.", "success")

        return redirect(url_for("index", path=rel_dir) if rel_dir else url_for("index"))

    @app.route("/view")
    @login_required
    def view_file():
        rel_path = request.args.get("path", "").strip()
        if not rel_path:
            abort(400)
        target_file = resolve_safe_path(storage_root, rel_path)
        if not target_file.exists() or not target_file.is_file():
            abort(404)
        if not is_viewable_file(target_file):
            abort(415)

        content = target_file.read_text(encoding="utf-8", errors="replace")
        parent_rel = target_file.parent.relative_to(storage_root).as_posix()
        back_url = url_for("index") if parent_rel == "." else url_for("index", path=parent_rel)
        is_html = target_file.suffix.lower() in _HTML_EXTENSIONS

        return render_template_string(
            VIEW_HTML,
            filename=target_file.name,
            rel_path=rel_path,
            content=content,
            is_html=is_html,
            back_url=back_url,
        )

    @app.route("/delete", methods=["POST"])
    @login_required
    def delete_item():
        rel_path = request.form.get("path", "").strip()
        if not rel_path:
            abort(400)
        target = resolve_safe_path(storage_root, rel_path)
        if target == storage_root or not target.exists():
            abort(404)

        trash_dir = storage_root / TRASH_DIR_NAME
        trash_dir.mkdir(exist_ok=True)
        dest = unique_destination(trash_dir, target.name)
        shutil.move(str(target), str(dest))
        flash(f"Đã chuyển '{target.name}' vào thư mục trash.", "success")

        parent_rel = target.parent.relative_to(storage_root).as_posix()
        return redirect(url_for("index") if parent_rel == "." else url_for("index", path=parent_rel))

    @app.route("/download")
    @login_required
    def download():
        rel_path = request.args.get("path", "").strip()
        if not rel_path:
            abort(400)
        target_file = resolve_safe_path(storage_root, rel_path)
        if not target_file.exists() or not target_file.is_file():
            abort(404)
        return send_file(target_file, as_attachment=True, download_name=target_file.name)

    return app


def parse_args() -> argparse.Namespace:
    default_dir = Path(__file__).resolve().parent / "shared_files"
    parser = argparse.ArgumentParser(description="LAN File Share Web Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=27491, help="Port to listen on (default: 27491)")
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path(os.environ.get("LAN_SHARE_DIR", default_dir)),
        help="Storage directory path (default: ./shared_files)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("LAN_SHARE_PASSWORD", ""),
        help="Access password (or set LAN_SHARE_PASSWORD; auto-generated if omitted)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    password = args.password or secrets.token_urlsafe(9)
    app = create_app(args.dir, password)

    lan_ips = get_lan_ips()
    print("=" * 60)
    print("LAN File Share đang chạy!")
    print(f"Thư mục kho file : {app.config['STORAGE_ROOT']}")
    print(f"Mật khẩu truy cập: {password}")
    print(f"Truy cập cục bộ  : http://127.0.0.1:{args.port}")
    for ip in lan_ips:
        print(f"Truy cập qua LAN : http://{ip}:{args.port}")
    print("=" * 60)

    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()

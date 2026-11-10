#!/usr/bin/env python3
"""adflag — Thư viện nộp flag siêu nhẹ & tiện ích A/D cho Web, Crypto, Rev, Forensics...

Đặc điểm:
  - 0 dependencies bên ngoài (chỉ dùng thư viện chuẩn os, sys, re).
  - Tự động nhận diện chuỗi flag hoặc tự quét regex trong response HTML/JSON.
  - Tự động bóc tách tiền tố/hậu tố b'...', newline thừa.
  - Giao tiếp tức thời với Attack Console theo chuẩn [FLAG] <flag>.
  - Hỗ trợ lấy IP/port/url của target trong môi trường A/D cực kỳ gọn gàng.

Cách dùng cơ bản:
    from adflag import submit

    # 1. Nộp trực tiếp chuỗi cờ:
    submit("IBOH26_VERIFY_12345")

    # 2. Hoặc nộp thẳng kết quả HTTP response (tự tìm cờ trong HTML/JSON!):
    import requests
    r = requests.get("http://target/flag")
    submit(r.text)

Cách dùng nhanh (callable module):
    import adflag
    adflag("IBOH26_...")

Hỗ trợ Target / URL cho Web/Crypto/Rev:
    from adflag import submit, get_target, get_url

    host = get_target("127.0.0.1")       # sys.argv[1] hoặc TARGET_HOST env
    url  = get_url("/login", default_port=5000) # http://<target>:5000/login
"""

import os
import re
import sys
import types

__all__ = [
    "submit",
    "emit",
    "find_flags",
    "get_target",
    "get_port",
    "get_url",
    "get_targets",
    "target",
    "port",
    "url",
]

# Regex chuẩn cho các định dạng flag phổ biến trong CTF / Attack-Defense:
# 1. IBOH26_xxx
# 2. prefix{content} (như flag{...}, ctf{...}, sec{...})
DEFAULT_FLAG_REGEX = re.compile(
    r"[a-zA-Z0-9_\-]+{[^}\s\r\n]+}|IBOH26_[a-zA-Z0-9_\-+/=]+"
)

_emitted_flags = set()


def _clean_flag_str(s: str) -> str:
    """Làm sạch chuỗi flag khỏi các ký tự rác hoặc byte repr."""
    if not s:
        return ""
    s = s.strip()
    if (s.startswith("b'") and s.endswith("'")) or (s.startswith('b"') and s.endswith('"')):
        s = s[2:-1]
    if s.endswith("\\n'"):
        s = s[:-3]
    elif s.endswith("\\r\\n'"):
        s = s[:-5]
    elif s.endswith("'") and not s.startswith("'"):
        s = s[:-1]
    elif s.endswith('"') and not s.startswith('"'):
        s = s[:-1]
    return s.strip()


def find_flags(data, regex=None) -> list[str]:
    """Tìm tất cả các flag trong chuỗi, bytes, dict hoặc list."""
    if data is None:
        return []

    pat = regex if isinstance(regex, re.Pattern) else re.compile(regex) if regex else DEFAULT_FLAG_REGEX

    if isinstance(data, (bytes, bytearray)):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = str(data)
    elif isinstance(data, str):
        text = data
    elif isinstance(data, (list, tuple, set)):
        results = []
        for item in data:
            results.extend(find_flags(item, regex=pat))
        return results
    elif isinstance(data, dict):
        text = str(data)
    else:
        text = str(data)

    text_clean = _clean_flag_str(text)
    if " " not in text_clean and "\n" not in text_clean and pat.fullmatch(text_clean):
        return [text_clean]

    matches = pat.findall(text)
    cleaned = []
    for m in matches:
        if isinstance(m, tuple):
            m = [x for x in m if x][0] if any(m) else ""
        c = _clean_flag_str(str(m))
        if c and c not in cleaned:
            cleaned.append(c)
    return cleaned


def submit(*flags, regex=None) -> list[str]:
    """Phát cờ theo giao thức chuẩn [FLAG] <flag> ra stdout để Runner bắt tức thời.

    Chấp nhận:
      - 1 hoặc nhiều flag dạng chuỗi / bytes.
      - Toàn bộ nội dung trang web (HTML / JSON) -> tự bóc tách cờ!
      - List / Tuple / Dict chứa cờ.

    Trả về:
      Danh sách các cờ MỚI được phát trong lần gọi này.
    """
    global _emitted_flags
    newly_emitted = []

    for item in flags:
        if not item or isinstance(item, bool):
            continue

        if isinstance(item, (str, bytes, bytearray)):
            s = item.decode("utf-8", errors="replace") if isinstance(item, (bytes, bytearray)) else item
            clean_single = _clean_flag_str(s)
            if clean_single and " " not in clean_single and "\n" not in clean_single:
                pat = regex if isinstance(regex, re.Pattern) else re.compile(regex) if regex else DEFAULT_FLAG_REGEX
                if pat.fullmatch(clean_single) or clean_single.startswith("IBOH26_") or "{" in clean_single:
                    candidate_flags = [clean_single]
                else:
                    candidate_flags = find_flags(s, regex=regex)
            else:
                candidate_flags = find_flags(s, regex=regex)
        else:
            candidate_flags = find_flags(item, regex=regex)

        for f in candidate_flags:
            if not f or f.startswith("__OK_") or (f.startswith("<") and f.endswith(">")):
                continue
            if f in _emitted_flags:
                continue
            _emitted_flags.add(f)
            newly_emitted.append(f)
            sys.stdout.write(f"\n[FLAG] {f}\n")
            sys.stdout.flush()

    return newly_emitted


emit = submit


# ────────────────────────────────────────────────────────────────────────
# Tiện ích target & mạng cho Attack/Defense
# ────────────────────────────────────────────────────────────────────────
def get_target(default: str = "127.0.0.1") -> str:
    """Lấy IP/hostname target của lượt tấn công hiện tại.

    Ưu tiên kiểm tra:
      1. sys.argv[1] (khi chạy từ CLI hoặc Attack Console)
      2. TARGET_HOST / TARGET / HOST trong environment
      3. Giá trị mặc định default
    """
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        return sys.argv[1].strip()
    for env_var in ("TARGET_HOST", "TARGET", "HOST"):
        val = os.environ.get(env_var)
        if val and val.strip():
            return val.strip()
    return default


target = get_target


def get_port(default: int = 80) -> int:
    """Lấy port target của lượt tấn công hiện tại.

    Ưu tiên kiểm tra:
      1. sys.argv[2] (nếu là số nguyên)
      2. TARGET_PORT / PORT trong environment
      3. Giá trị mặc định default
    """
    if len(sys.argv) > 2 and sys.argv[2].isdigit():
        return int(sys.argv[2])
    for env_var in ("TARGET_PORT", "PORT"):
        val = os.environ.get(env_var)
        if val and val.strip().isdigit():
            return int(val.strip())
    return default


port = get_port


def get_url(path: str = "", port: int = None, proto: str = "http", default_port: int = None) -> str:
    """Sinh URL đầy đủ tới target, cực tiện cho các bài Web CTF.

    Ví dụ:
      get_url(default_port=5000)            -> 'http://10.10.1.2:5000'
      get_url('/api/flag', default_port=80) -> 'http://10.10.1.2/api/flag'
    """
    t = get_target()
    p = port if port is not None else get_port(default_port if default_port is not None else (443 if proto == "https" else 80))

    if path and not path.startswith("/"):
        path = "/" + path

    if (proto == "http" and p == 80) or (proto == "https" and p == 443):
        return f"{proto}://{t}{path}"
    return f"{proto}://{t}:{p}{path}"


url = get_url


def get_targets(default: list[str] = None) -> list[str]:
    """Lấy danh sách nhiều target khi chạy standalone qua biến TARGET_HOSTS."""
    raw = os.environ.get("TARGET_HOSTS")
    if raw:
        items = [x.strip() for x in raw.replace(";", ",").split(",") if x.strip()]
        if items:
            return items
    return default if default is not None else [get_target()]


# ────────────────────────────────────────────────────────────────────────
# Hỗ trợ Callable Module: `import adflag; adflag("FLAG_XYZ")`
# ────────────────────────────────────────────────────────────────────────
class _CallableModule(types.ModuleType):
    def __call__(self, *args, **kwargs):
        return submit(*args, **kwargs)


sys.modules[__name__].__class__ = _CallableModule

#!/usr/bin/env python3
"""
WAF Rule Tester — F-Hacker 2026
Test ModSecurity rule trước khi deploy lên WAF UI.

Chế độ:
  1. Offline  : test regex (ReDoS + payload matching) — không cần WAF chạy
  2. Live     : gửi request thật tới WAF, kiểm tra block đúng/sai
  3. Load     : giả lập N đội tấn công đồng thời, đo latency, phát hiện WAF bị nghẽn

Cách dùng:
    # Offline (không cần WAF):
    python3 waf_rule_tester.py rules.conf

    # Live test (WAF đang chạy):
    python3 waf_rule_tester.py rules.conf --waf http://localhost:8000

    # Load test giả lập 16 đội, kéo dài 15 giây:
    python3 waf_rule_tester.py rules.conf --waf http://localhost:8000 --load --teams 16 --duration 15

    # Chỉ load test (bỏ qua offline):
    python3 waf_rule_tester.py rules.conf --waf http://localhost:8000 --load-only

    # Thêm payload thật từ PayloadsAllTheThings/SecLists đã clone ở ~/hoc/CTF/Tools/web
    # (polyglot, encoding lạ... đối thủ hay dùng để né WAF, mạnh hơn 43 payload mẫu):
    python3 waf_rule_tester.py rules.conf --wordlists

Tác giả: F-Hacker 2026 Team
"""

import re
import sys
import time
import queue
import random
import threading
import argparse
import statistics
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# PHẦN 1: PAYLOAD LISTS
# ═══════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Payload:
    value:    str
    category: str   # sqli | cmdi | lfi | xss | ssti | ssrf | flag-leak | recon


# Payload độc hại, gắn category — WAF PHẢI chặn.
# Category dùng để chỉ test rule với đúng nhóm payload rule đó nhắm tới (xem
# infer_category()); KHÔNG trộn chung mọi loại khi chấm 1 rule chỉ viết cho 1 loại.
MALICIOUS_PAYLOADS = [
    # SQLi
    Payload("' OR '1'='1", "sqli"),
    Payload("' OR 1=1--", "sqli"),
    Payload("1 UNION SELECT 1,2,3--", "sqli"),
    Payload("1 UNION SELECT flag FROM flags--", "sqli"),
    Payload("' AND SLEEP(5)--", "sqli"),
    Payload("1; DROP TABLE users--", "sqli"),
    Payload("' AND (SELECT SUBSTRING(password,1,1) FROM users)='a", "sqli"),
    Payload("1 OR 1=1", "sqli"),
    Payload("admin'--", "sqli"),
    Payload("' OR 'x'='x", "sqli"),
    # CMDi
    Payload("; id", "cmdi"),
    Payload("| whoami", "cmdi"),
    Payload("`id`", "cmdi"),
    Payload("$(id)", "cmdi"),
    Payload("; cat /etc/passwd", "cmdi"),
    Payload("| cat /flag", "cmdi"),
    Payload("; ls -la", "cmdi"),
    Payload("& ping -c 1 127.0.0.1", "cmdi"),
    # LFI / Path Traversal (gửi qua tham số, vd ?file=...)
    Payload("../../../../etc/passwd", "lfi"),
    Payload("....//....//etc/passwd", "lfi"),
    Payload("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "lfi"),
    Payload("../../../etc/shadow", "lfi"),
    Payload("php://filter/convert.base64-encode/resource=index.php", "lfi"),
    # XSS
    Payload("<script>alert(1)</script>", "xss"),
    Payload("<img src=x onerror=alert(1)>", "xss"),
    Payload("javascript:alert(1)", "xss"),
    Payload("<svg onload=alert(1)>", "xss"),
    Payload('"><script>alert(document.cookie)</script>', "xss"),
    # SSTI
    Payload("{{7*7}}", "ssti"),
    Payload("{{config}}", "ssti"),
    Payload("${7*7}", "ssti"),
    Payload("{{''.__class__.__mro__}}", "ssti"),
    Payload("{{cycler.__init__.__globals__.os.popen('id').read()}}", "ssti"),
    # SSRF
    Payload("http://127.0.0.1/admin", "ssrf"),
    Payload("http://localhost:6379", "ssrf"),
    Payload("http://169.254.169.254/latest/meta-data/", "ssrf"),
    Payload("gopher://127.0.0.1:6379/", "ssrf"),
    # Flag leak (phase 4, kiểm tra trên RESPONSE_BODY)
    Payload("FHACKER2026{aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899}", "flag-leak"),
    # Recon — đây là ĐƯỜNG DẪN thật, phải gửi qua path (xem _choose_delivery),
    # không phải giá trị tham số, cho rule kiểu "chặn đọc file nhạy cảm" trong huong-dan.md
    Payload("/.env", "recon"),
    Payload("/.git/HEAD", "recon"),
    Payload("/.git/config", "recon"),
    Payload("/config.php.bak", "recon"),
    Payload("/.DS_Store", "recon"),
]

# Từ khoá trong tag:'...'/msg:'...' của rule để suy ra rule đang nhắm category nào.
# Khớp theo thứ tự khai báo, dùng để chỉ test rule với đúng nhóm payload liên quan.
CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sqli":      ("sqli", "sql-injection", "sql injection"),
    "cmdi":      ("cmdi", "cmd-injection", "command injection", "command-injection", "rce"),
    "lfi":       ("lfi", "path-traversal", "path traversal", "traversal", "file-inclusion", "file inclusion"),
    "xss":       ("xss", "cross-site-scripting", "cross site scripting"),
    "ssti":      ("ssti", "template-injection", "template injection"),
    "ssrf":      ("ssrf",),
    "flag-leak": ("flag-leak", "flag leak", "flagleak"),
    "recon":     ("recon", "sensitive-file", "sensitive file", "probe"),
}


def infer_category(rule: "ModSecRule") -> Optional[str]:
    """Suy ra rule đang nhắm category nào qua tag/msg; None nếu không rõ."""
    haystack = f"{rule.tag} {rule.msg}".lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in haystack for kw in keywords):
            return cat
    return None


# ── Wordlist thật đã clone (PayloadsAllTheThings/SecLists) ──────────────
# Đối thủ không chỉ gửi payload sách vở (' OR 1=1) mà sẽ cố né WAF bằng
# polyglot/encoding lạ/ghép tag — các file này chính là loại payload đó,
# mạnh hơn nhiều so với 43 dòng tay viết ở trên. Mặc định TẮT (không đọc
# đĩa nếu không ai yêu cầu); bật qua --wordlists.
WORDLIST_BASE_DEFAULT = Path.home() / "hoc" / "CTF" / "Tools" / "web"

WORDLIST_SOURCES: dict[str, tuple[str, ...]] = {
    "sqli": (
        "PayloadsAllTheThings/SQL Injection/Intruder/SQLi_Polyglots.txt",
        "PayloadsAllTheThings/SQL Injection/Intruder/Generic_UnionSelect.txt",
        "PayloadsAllTheThings/SQL Injection/Intruder/Generic_TimeBased.txt",
        "PayloadsAllTheThings/SQL Injection/Intruder/Generic_Fuzz.txt",
        "PayloadsAllTheThings/SQL Injection/Intruder/Auth_Bypass.txt",
        "PayloadsAllTheThings/SQL Injection/Intruder/Auth_Bypass2.txt",
    ),
    "xss": (
        "PayloadsAllTheThings/XSS Injection/Intruders/XSS_Polyglots.txt",
        "PayloadsAllTheThings/XSS Injection/Intruders/xss_payloads_quick.txt",
        "PayloadsAllTheThings/XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt",
        "PayloadsAllTheThings/XSS Injection/Intruders/port_swigger_xss_cheatsheet_event_handlers.txt",
        "PayloadsAllTheThings/XSS Injection/Intruders/0xcela_event_handlers.txt",
        "PayloadsAllTheThings/XSS Injection/Intruders/JHADDIX_XSS.txt",
    ),
    "cmdi": (
        "PayloadsAllTheThings/Command Injection/Intruder/command_exec.txt",
        "PayloadsAllTheThings/Command Injection/Intruder/command-execution-unix.txt",
        "SecLists/Fuzzing/command-injection-commix.txt",
    ),
    "lfi": (
        "PayloadsAllTheThings/Directory Traversal/Intruder/directory_traversal.txt",
        "PayloadsAllTheThings/Directory Traversal/Intruder/deep_traversal.txt",
        "PayloadsAllTheThings/Directory Traversal/Intruder/dotdotpwn.txt",
        "PayloadsAllTheThings/Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",
    ),
    "ssti": (
        "PayloadsAllTheThings/Server Side Template Injection/Intruder/ssti.fuzz",
    ),
    # Đây là ĐƯỜNG DẪN thật (không có "/" đầu trong file gốc) — chuẩn hoá
    # khi nạp, xem _normalize_wordlist_line().
    "recon": (
        "SecLists/Discovery/Web-Content/UnixDotfiles.fuzz.txt",
        "SecLists/Discovery/Web-Content/Common-DB-Backups.txt",
    ),
}

MAX_WORDLIST_LINE_LEN = 300   # bỏ dòng quá dài (thường là rác/binary lẫn vào)


def _normalize_wordlist_line(line: str, category: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith('#') or len(line) > MAX_WORDLIST_LINE_LEN:
        return None
    if category == "recon" and not line.startswith('/'):
        line = '/' + line
    return line


def load_wordlist_payloads(base_dir: Path, sample_per_category: int) -> tuple[list[Payload], dict[str, int]]:
    """
    Đọc các file trong WORDLIST_SOURCES (bỏ qua file không tồn tại), gộp,
    khử trùng lặp rồi lấy mẫu ngẫu nhiên tối đa sample_per_category dòng
    mỗi category — tránh việc chạy nguyên cả file hàng trăm/nghìn dòng mỗi
    lần test (chậm, và dưới live/load sẽ dội quá nhiều request vào WAF).
    Trả về (payloads, {category: số dòng đã nạp}) để báo minh bạch cho người dùng.
    """
    loaded: list[Payload] = []
    counts: dict[str, int] = {}

    for category, rel_paths in WORDLIST_SOURCES.items():
        lines: set[str] = set()
        for rel in rel_paths:
            fpath = base_dir / rel
            try:
                with fpath.open(encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        norm = _normalize_wordlist_line(raw, category)
                        if norm:
                            lines.add(norm)
            except FileNotFoundError:
                continue

        if not lines:
            counts[category] = 0
            continue

        pool = list(lines)
        sample = pool if len(pool) <= sample_per_category else random.sample(pool, sample_per_category)
        loaded.extend(Payload(v, category) for v in sample)
        counts[category] = len(sample)

    return loaded, counts

# Request bình thường — WAF KHÔNG được chặn
BENIGN_PAYLOADS = [
    "hello world",
    "my name is Alice",
    "search query here",
    "2024-11-27",
    "user@example.com",
    "12345",
    "0",
    "9999",
    "user_id=42",
    '{"name": "Alice", "age": 25}',
    '{"status": "ok", "data": [1, 2, 3]}',
    "username=alice&password=secret123",
    "title=My+Blog+Post&content=Hello+World",
    "comment=Great+article!",
    "/api/users/123",
    "/api/posts?page=1&limit=10",
    "/static/style.css",
    "/images/logo.png",
    "product_name=Blue+T-Shirt&quantity=2",
    "SELECT * FROM",          # Chỉ là text, không phải SQLi thực sự
    "union all",              # Từ bình thường trong tiếng Anh
    "insert coin",            # Game instruction
]

# Input dài để test ReDoS
REDOS_TEST_INPUTS = [
    "a" * 50,
    "a" * 200,
    "a" * 1000,
    "' " * 50,
    "UNION " * 30 + "SELECT",
    "<" * 100 + "script",
    "../" * 50,
    "{{" * 30 + "config" + "}}" * 30,
    "aaaaaaaaaaaaaaaaaaaab" * 10,          # Classic backtrack bait
    "(" * 20 + "a+" * 20 + ")" * 20,
    "select " * 20 + "from " * 20,
]

REDOS_TIMEOUT_MS = 100   # ms — ngưỡng nguy hiểm
REDOS_WARN_MS    = 20    # ms — ngưỡng cảnh báo

# Ngưỡng latency WAF (ms) — bot BTC timeout nếu WAF chậm hơn
BOT_TIMEOUT_MS   = 5000  # 5s — curl max-time của bot healthcheck
SVC_WARN_MS      = 1000  # 1s — cảnh báo sớm
SVC_DANGER_MS    = 3000  # 3s — nguy hiểm, bot gần timeout


# ═══════════════════════════════════════════════════════════════
# PHẦN 2: PARSER ModSecurity
# ═══════════════════════════════════════════════════════════════

@dataclass
class ModSecRule:
    raw:            str
    rule_id:        str        = ""
    phase:          str        = ""
    variables:      list       = field(default_factory=list)
    operator:       str        = ""
    pattern:        str        = ""
    action:         str        = ""
    msg:            str        = ""
    tag:            str        = ""
    line_number:    int        = 0
    # Các điều kiện SecRule nối bằng action `chain` phía sau rule này (xem
    # parse_modsec_rules). Không coi là rule độc lập — ModSecurity chỉ cho
    # phép id/phase/action nằm ở rule ĐẦU của chain, các rule sau chỉ là điều
    # kiện AND thêm. Dùng chain_children để quét ReDoS trên regex của chúng.
    chain_children: list       = field(default_factory=list)


def _parse_one_secrule_line(line: str, lineno: int) -> ModSecRule:
    rule = ModSecRule(raw=line, line_number=lineno)

    # Operator (@rx, @contains, ...)
    op_m = re.search(r'"@(\w+)\s+(.*?)"', line)
    if op_m:
        rule.operator = op_m.group(1).lower()
        rule.pattern  = op_m.group(2)

    # Actions (phần cuối trong dấu ngoặc kép)
    parts = re.findall(r'"([^"]+)"', line)
    if parts:
        last = parts[-1]
        id_m   = re.search(r'\bid:(\d+)', last)
        ph_m   = re.search(r'\bphase:(\d+)', last)
        msg_m  = re.search(r"\bmsg:'([^']*)'", last)
        tag_m  = re.search(r"\btag:'([^']*)'", last)
        act_m  = re.search(r'\b(deny|pass|block|drop|allow)\b', last)
        rule.rule_id = id_m.group(1)  if id_m  else "?"
        rule.phase   = ph_m.group(1)  if ph_m  else "?"
        rule.msg     = msg_m.group(1) if msg_m else ""
        rule.tag     = tag_m.group(1) if tag_m else ""
        rule.action  = act_m.group(1) if act_m else "?"

    # Variables
    var_m = re.match(r'SecRule\s+(\S+)\s+', line, re.IGNORECASE)
    if var_m:
        rule.variables = var_m.group(1).split('|')

    return rule


def _line_has_chain(line: str) -> bool:
    return bool(re.search(r'\bchain\b', line, re.IGNORECASE))


def parse_modsec_rules(content: str) -> list[ModSecRule]:
    """
    Ghép dòng tiếp nối (\\), rồi parse từng SecRule.

    Rule dùng action `chain` (2+ dòng SecRule nối thành 1 rule logic, đúng cú
    pháp BTC hướng dẫn trong huong-dan.md) được GỘP LẠI: chỉ rule ĐẦU (mang
    id/phase/action thật) được coi là 1 rule độc lập; các dòng điều kiện theo
    sau bị gom vào chain_children thay vì biến thành "rule" rời rạc không có
    id/phase — tránh báo sai tổng số rule và pha loãng thống kê OK/warn/fail.
    """
    rules: list[ModSecRule] = []
    joined = re.sub(r'\\\s*\n\s*', ' ', content)

    raw_lines: list[tuple[int, str]] = []
    for lineno, line in enumerate(joined.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not line.lower().startswith('secrule'):
            continue
        raw_lines.append((lineno, line))

    i = 0
    while i < len(raw_lines):
        lineno, line = raw_lines[i]
        rule = _parse_one_secrule_line(line, lineno)
        i += 1

        cursor = line
        while _line_has_chain(cursor) and i < len(raw_lines):
            child_lineno, child_line = raw_lines[i]
            rule.chain_children.append(_parse_one_secrule_line(child_line, child_lineno))
            cursor = child_line
            i += 1

        rules.append(rule)
    return rules


# ═══════════════════════════════════════════════════════════════
# PHẦN 3: TEST OFFLINE
# ═══════════════════════════════════════════════════════════════

def test_redos(rule: ModSecRule) -> dict:
    """
    Phát hiện Catastrophic Backtracking bằng cách đo thời gian match.
    Quét cả regex của rule chính LẪN các điều kiện chain con (chain_children)
    — chúng cũng chạy thật trên ModSecurity dù không phải rule độc lập.
    """
    candidates = [(rule.operator, rule.pattern)]
    candidates += [(c.operator, c.pattern) for c in rule.chain_children]
    rx_candidates = [(op, pat) for op, pat in candidates if op == 'rx']

    if not rx_candidates:
        return {"status": "skip",
                "reason": f"@{rule.operator or '?'} (không có regex nào, kể cả điều kiện chain)"}

    max_ms, worst = 0.0, ""
    for op, pat in rx_candidates:
        try:
            compiled = re.compile(pat, re.IGNORECASE)
        except re.error as e:
            return {"status": "error", "reason": f"Regex không hợp lệ: {e}"}

        for inp in REDOS_TEST_INPUTS:
            t0 = time.perf_counter()
            try:
                compiled.search(inp)
            except Exception:
                pass
            ms = (time.perf_counter() - t0) * 1000
            if ms > max_ms:
                max_ms = ms
                worst  = inp[:40] + ("..." if len(inp) > 40 else "")

    if max_ms > REDOS_TIMEOUT_MS:
        return {"status": "danger", "max_ms": max_ms,
                "reason": f"{max_ms:.1f}ms với '{worst}'"}
    if max_ms > REDOS_WARN_MS:
        return {"status": "warn",   "max_ms": max_ms,
                "reason": f"{max_ms:.1f}ms (hơi chậm)"}
    return {"status": "ok", "max_ms": max_ms}


def match_rule(rule: ModSecRule, payload: str) -> bool:
    """
    Kiểm tra rule có match payload không (offline) — chỉ xét operator/pattern
    của rule CHÍNH (không mô phỏng AND nhiều biến của chain_children, vì công
    cụ test bằng 1 chuỗi payload đơn, không mô phỏng được nhiều field request
    khác nhau cùng lúc; xem test_redos() để chain con vẫn được quét ReDoS).
    """
    op = rule.operator
    pat = rule.pattern
    pl  = payload.lower()
    if op == 'rx':
        try:
            return bool(re.search(pat, payload, re.IGNORECASE))
        except re.error:
            return False
    elif op == 'contains':
        return pat.lower() in pl
    elif op in ('streq', 'eq'):
        return pat.lower() == pl
    elif op in ('beginswith',):
        return pl.startswith(pat.lower())
    elif op in ('endswith',):
        return pl.endswith(pat.lower())
    return False


def test_payloads(rule: ModSecRule, category: Optional[str]) -> dict:
    """
    Chỉ chấm rule trên đúng nhóm payload (category) rule đó khai báo qua
    tag/msg — một rule chỉ viết cho SQLi không thể "lọt" payload XSS/LFI,
    nên không được tính là miss. Nếu không suy ra được category (rule thiếu
    tag rõ ràng), rơi về kiểm tra toàn bộ kho như cũ nhưng NÊU RÕ trong kết
    quả để người đọc biết đây là fallback kém chính xác, không phải lỗi rule.
    """
    scoped = [p for p in MALICIOUS_PAYLOADS if p.category == category] if category else MALICIOUS_PAYLOADS
    if not scoped:
        scoped = MALICIOUS_PAYLOADS

    fn = [p.value for p in scoped if not match_rule(rule, p.value)]
    fp = [p for p in BENIGN_PAYLOADS if match_rule(rule, p)]
    return {
        "fn": fn, "fp": fp,
        "category":    category,
        "mal_blocked": len(scoped) - len(fn),
        "mal_total":   len(scoped),
        "ben_total":   len(BENIGN_PAYLOADS),
    }


# ═══════════════════════════════════════════════════════════════
# PHẦN 4: LIVE HTTP REQUEST (không dùng thư viện ngoài)
# ═══════════════════════════════════════════════════════════════

def _choose_delivery(rule: Optional[ModSecRule], category: Optional[str] = None) -> str:
    """
    Chọn kênh gửi payload cho khớp với biến (variable) rule đang kiểm tra.
    Không phải mọi rule chỉ nhìn ARGS qua query string — rule theo
    REQUEST_FILENAME/REQUEST_URI (vd chặn /.env trong huong-dan.md), theo
    header/cookie, hay REQUEST_BODY (POST) sẽ KHÔNG BAO GIỜ được kích hoạt
    nếu cứ gửi mọi thứ qua "?q=..." ở path gốc như trước — khiến rule loại
    này luôn "pass" live test dù đúng hay sai.
    """
    if category == "recon":
        return "path"          # payload category này VỐN LÀ đường dẫn thật
    if rule is None:
        return "query"

    vars_upper = [v.upper() for v in rule.variables]
    if any(v.startswith("REQUEST_HEADERS") for v in vars_upper):
        return "header"
    if any(v.startswith("REQUEST_COOKIES") for v in vars_upper):
        return "cookie"
    has_args = any(v == "ARGS" or v.startswith("ARGS:") or v.startswith("ARGS|") for v in vars_upper)
    if "REQUEST_BODY" in vars_upper and not has_args:
        return "body"
    if ("REQUEST_FILENAME" in vars_upper or "REQUEST_URI" in vars_upper) and not has_args:
        return "path"
    return "query"


def http_send(url: str, payload: str, delivery: str = "query", timeout: float = 5.0) -> tuple[int, float]:
    """
    Gửi 1 request theo đúng kênh (query/body/path/header/cookie), trả về
    (status_code, latency_ms). Dùng urllib thuần — không cần requests.
    """
    t0 = time.perf_counter()
    try:
        if delivery == "path":
            suffix = payload if payload.startswith('/') else '/' + payload
            target = url.rstrip('/') + suffix
            req = urllib.request.Request(target, headers={"User-Agent": "WAF-Tester/1.0"})
        elif delivery == "header":
            req = urllib.request.Request(url, headers={"User-Agent": payload})
        elif delivery == "cookie":
            req = urllib.request.Request(
                url, headers={"User-Agent": "WAF-Tester/1.0", "Cookie": f"session={payload}"})
        elif delivery == "body":
            data = urllib.parse.urlencode({"q": payload}).encode()
            req = urllib.request.Request(
                url, data=data,
                headers={"User-Agent": "WAF-Tester/1.0",
                         "Content-Type": "application/x-www-form-urlencoded"})
        else:  # query (mặc định, giống hành vi cũ)
            qs   = urllib.parse.urlencode({"q": payload})
            full = f"{url}?{qs}" if '?' not in url else f"{url}&{qs}"
            req  = urllib.request.Request(full, headers={"User-Agent": "WAF-Tester/1.0"})

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = 0
    ms = (time.perf_counter() - t0) * 1000
    return code, ms


def is_blocked(code: int) -> bool:
    return code in (400, 403, 429)


def test_live_single(waf_url: str, rule: Optional[ModSecRule] = None,
                      category: Optional[str] = None) -> dict:
    """
    Test nhanh 1 vòng: vài payload độc đúng category của rule (nếu suy ra
    được) + vài benign, gửi qua đúng kênh (_choose_delivery). Benign luôn
    lấy từ toàn bộ kho vì false positive phải đúng với MỌI loại input, không
    riêng category của rule.
    """
    pool = [p for p in MALICIOUS_PAYLOADS if p.category == category] if category else MALICIOUS_PAYLOADS
    if not pool:
        pool = MALICIOUS_PAYLOADS
    delivery = _choose_delivery(rule, category)

    sample_mal = random.sample(pool, min(8, len(pool)))
    sample_ben = random.sample(BENIGN_PAYLOADS, min(6, len(BENIGN_PAYLOADS)))

    fn, fp, latencies = [], [], []

    for p in sample_mal:
        code, ms = http_send(waf_url, p.value, delivery)
        latencies.append(ms)
        if not is_blocked(code) and code != 0:
            fn.append((p.value, code))

    for p in sample_ben:
        # Benign luôn gửi qua query — đại diện cho input bình thường của
        # người dùng thật, không phải theo kênh đặc thù của 1 rule cụ thể.
        code, ms = http_send(waf_url, p, "query")
        latencies.append(ms)
        if is_blocked(code):
            fp.append((p, code))

    return {
        "fn": fn, "fp": fp,
        "delivery": delivery,
        "latencies": latencies,
        "p50": statistics.median(latencies) if latencies else 0,
        "p95": sorted(latencies)[int(len(latencies)*0.95)] if len(latencies) >= 2 else 0,
    }


# ═══════════════════════════════════════════════════════════════
# PHẦN 5: LOAD TEST — Giả lập N đội tấn công đồng thời
# ═══════════════════════════════════════════════════════════════

@dataclass
class RequestResult:
    payload:    str
    is_mal:     bool
    code:       int
    latency_ms: float
    thread_id:  int     # team index


def load_worker(
    team_id:    int,
    waf_url:    str,
    duration_s: float,
    results_q:  queue.Queue,
    stop_event: threading.Event,
):
    """
    Worker mô phỏng 1 đội: xen kẽ gửi payload độc và request bình thường, qua
    nhiều kênh (query/body/path) để tải cũng phản ánh traffic POST/path thật
    thay vì chỉ GET query string như trước. Mỗi đội có tốc độ hơi khác nhau
    (random) để giống thực tế hơn.
    """
    # Tốc độ mỗi đội: 0.3–1.5 giây/request (random như người thật)
    rng = random.Random(team_id * 42)
    deadline = time.perf_counter() + duration_s
    # Gắn ?team=N để nhận ra trong traffic log; http_send tự nối thêm &q=...
    marked_url = f"{waf_url}?team={team_id}" if '?' not in waf_url else f"{waf_url}&team={team_id}"

    while not stop_event.is_set() and time.perf_counter() < deadline:
        # Xác suất 60% payload độc, 40% bình thường (đội đang exploit)
        if rng.random() < 0.6:
            p = rng.choice(MALICIOUS_PAYLOADS)
            payload, is_mal = p.value, True
            delivery = "path" if p.category == "recon" else rng.choice(("query", "body"))
        else:
            payload, is_mal = rng.choice(BENIGN_PAYLOADS), False
            delivery = "query"

        url = marked_url if delivery == "query" else waf_url
        code, ms = http_send(url, payload, delivery, timeout=6.0)
        results_q.put(RequestResult(payload, is_mal, code, ms, team_id))

        # Đội tấn công không gửi quá nhanh (giới hạn ~30 req/min thực tế)
        time.sleep(rng.uniform(0.3, 1.5))


def run_load_test(waf_url: str, n_teams: int, duration_s: int) -> dict:
    """
    Chạy N thread song song (mỗi thread = 1 đội), thu thập kết quả.
    """
    results_q  = queue.Queue()
    stop_event = threading.Event()
    threads    = []

    print(f"\n  Bắt đầu load test: {n_teams} đội × {duration_s}s...")
    print(f"  {'─'*50}")

    # Spinner đơn giản
    spinner = threading.Event()
    def spin():
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        i = 0
        while not spinner.is_set():
            elapsed = int(time.perf_counter() - t_start)
            n = results_q.qsize()
            print(f"\r  {chars[i%len(chars)]} {elapsed}s | {n} requests gửi...", end="", flush=True)
            i += 1
            time.sleep(0.1)

    t_start = time.perf_counter()

    for tid in range(n_teams):
        t = threading.Thread(
            target=load_worker,
            args=(tid, waf_url, duration_s, results_q, stop_event),
            daemon=True,
        )
        threads.append(t)

    # Bắt đầu tất cả thread cùng lúc
    spin_t = threading.Thread(target=spin, daemon=True)
    spin_t.start()

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    spinner.set()
    t_elapsed = time.perf_counter() - t_start
    print(f"\r  Xong! {t_elapsed:.1f}s                              ")

    # Thu thập kết quả
    all_results: list[RequestResult] = []
    while not results_q.empty():
        all_results.append(results_q.get())

    return _analyze_load_results(all_results, n_teams, t_elapsed)


def _analyze_load_results(results: list[RequestResult], n_teams: int, elapsed_s: float) -> dict:
    if not results:
        return {"error": "Không có kết quả — WAF không phản hồi?"}

    latencies   = [r.latency_ms for r in results]
    mal_results = [r for r in results if r.is_mal]
    ben_results = [r for r in results if not r.is_mal]

    # False negatives (payload độc không bị chặn)
    fn = [(r.payload, r.code) for r in mal_results if not is_blocked(r.code) and r.code != 0]
    # False positives (request bình thường bị chặn)
    fp = [(r.payload, r.code) for r in ben_results if is_blocked(r.code)]
    # Timeout/lỗi
    err = [r for r in results if r.code == 0]

    lat_sorted = sorted(latencies)
    p50  = statistics.median(lat_sorted)
    p95  = lat_sorted[int(len(lat_sorted) * 0.95)] if len(lat_sorted) >= 20 else max(lat_sorted)
    p99  = lat_sorted[int(len(lat_sorted) * 0.99)] if len(lat_sorted) >= 100 else max(lat_sorted)
    pmax = max(lat_sorted)

    # Phân tích theo team (latency cao nhất từng team)
    team_lats: dict[int, list[float]] = {}
    for r in results:
        team_lats.setdefault(r.thread_id, []).append(r.latency_ms)
    slowest_team = max(team_lats, key=lambda k: statistics.median(team_lats[k]))

    return {
        "total_req":    len(results),
        "req_per_sec":  len(results) / elapsed_s,
        "fn": fn, "fp": fp, "errors": err,
        "fn_count":     len(fn),
        "fp_count":     len(fp),
        "err_count":    len(err),
        "p50": p50, "p95": p95, "p99": p99, "pmax": pmax,
        "slowest_team": slowest_team,
        "slowest_team_p50": statistics.median(team_lats[slowest_team]),
        "n_teams": n_teams,
        "elapsed_s": elapsed_s,
    }


# ═══════════════════════════════════════════════════════════════
# PHẦN 6: OUTPUT & VERDICT
# ═══════════════════════════════════════════════════════════════

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
BLUE   = "\033[94m"

def c(color, text): return f"{color}{text}{RESET}"

def bar(val, max_val, width=20, color=GREEN):
    if max_val <= 0:
        return f"{color}{'░' * width}{RESET}"
    filled = int(width * min(val, max_val) / max_val)
    b = "█" * filled + "░" * (width - filled)
    return f"{color}{b}{RESET}"


def print_header(rule: ModSecRule, category: Optional[str]):
    print(f"\n{BOLD}{'─'*62}{RESET}")
    print(f"  Rule {c(CYAN, rule.rule_id)}  │  Phase {rule.phase}  │  Action: {rule.action}")
    if rule.msg:
        print(f"  Msg: {rule.msg}")
    print(f"  Op : @{rule.operator}" + (f"  │  Pattern: {c(DIM, rule.pattern[:55])}..." if rule.operator=='rx' and len(rule.pattern)>55 else
          (f"  │  Pattern: {c(DIM, rule.pattern)}" if rule.operator=='rx' else "")))
    if rule.chain_children:
        print(f"  Chain: +{len(rule.chain_children)} điều kiện con (chỉ quét ReDoS, không chấm riêng)")
        print(f"  {c(YELLOW, '⚠ Offline [Block]/[FP] bên dưới CHỈ xét điều kiện đầu — không mô phỏng AND với')}")
        print(f"  {c(YELLOW, '  điều kiện chain con, nên có thể báo FP giả. Xác nhận lại bằng --waf (live).')}")
    print(f"  Category: {c(CYAN, category) if category else c(DIM, 'không rõ (thiếu tag khớp — xem CATEGORY_KEYWORDS)')}")
    print(f"{'─'*62}{RESET}")


def print_redos(r: dict):
    s = r["status"]
    if s == "skip":
        print(f"  [ReDoS]  {c(DIM, '─ skip: ' + r['reason'])}")
    elif s == "error":
        print(f"  [ReDoS]  {c(RED, '✗ REGEX LỖI')}: {r['reason']}")
    elif s == "danger":
        ms = r['max_ms']
        print(f"  [ReDoS]  {c(RED, '✗ NGUY HIỂM')} {ms:.1f}ms — {r['reason']}")
        print(f"           {c(RED, '→ Rule này SẼ làm WAF chậm/sập dưới tải!')}")
    elif s == "warn":
        ms = r['max_ms']
        print(f"  [ReDoS]  {c(YELLOW, '⚠ CHẬM')} {ms:.1f}ms — {r['reason']}")
    else:
        ms = r['max_ms']
        print(f"  [ReDoS]  {c(GREEN, f'✓ OK')} ({ms:.2f}ms max)")


def print_payload(r: dict, verbose: bool):
    fn_n, fp_n = len(r["fn"]), len(r["fp"])
    mb, mt, bt = r["mal_blocked"], r["mal_total"], r["ben_total"]
    pct = mb / mt * 100 if mt else 0
    cat = r.get("category")
    scope = f"nhóm '{cat}'" if cat else "toàn bộ kho — không rõ nhóm rule"

    # Malicious
    icon = c(GREEN, "✓") if fn_n == 0 else c(YELLOW, "⚠")
    b = bar(mb, mt, 15, GREEN if fn_n==0 else YELLOW)
    print(f"  [Block]  {icon} {b} {mb}/{mt} payload độc, {scope} ({pct:.0f}%)")
    if verbose and r["fn"]:
        for p in r["fn"][:3]:
            print(f"           {c(DIM, '→ lọt: ' + p[:55])}")

    # Benign
    icon2 = c(GREEN, "✓") if fp_n == 0 else c(RED, "✗")
    print(f"  [FP]     {icon2} {fp_n}/{bt} request bình thường bị chặn nhầm", end="")
    if fp_n > 0:
        print(f"  {c(RED, '← FALSE POSITIVE!')}")
        for p in r["fp"][:3]:
            print(f"           {c(RED, '→ chặn nhầm: ' + p[:55])}")
    else:
        print()


def print_live(r: dict, verbose: bool):
    fn_n, fp_n = len(r["fn"]), len(r["fp"])
    p50, p95   = r["p50"], r["p95"]
    delivery   = r.get("delivery", "query")

    lat_color = GREEN if p95 < SVC_WARN_MS else (YELLOW if p95 < SVC_DANGER_MS else RED)
    print(f"  [Live]   (qua {delivery}) Latency p50={c(lat_color, f'{p50:.0f}ms')}  p95={c(lat_color, f'{p95:.0f}ms')}", end="")
    if fn_n:
        print(f"  {c(YELLOW, f'⚠ {fn_n} miss')}", end="")
    if fp_n:
        print(f"  {c(RED, f'✗ {fp_n} FP')}", end="")
    if fn_n == 0 and fp_n == 0:
        print(f"  {c(GREEN, '✓')}", end="")
    print()


def print_load(r: dict, verbose: bool):
    if "error" in r:
        print(f"  [Load]   {c(RED, '✗ ' + r['error'])}")
        return

    p50, p95, p99, pmax = r["p50"], r["p95"], r["p99"], r["pmax"]
    total, rps           = r["total_req"], r["req_per_sec"]
    fn_n, fp_n, err_n    = r["fn_count"], r["fp_count"], r["err_count"]
    n_teams              = r["n_teams"]

    # Chọn màu latency
    def lat_color(ms):
        return GREEN if ms < SVC_WARN_MS else (YELLOW if ms < SVC_DANGER_MS else RED)

    print(f"\n  {'═'*58}")
    print(f"  LOAD TEST — {n_teams} đội đồng thời × {r['elapsed_s']:.0f}s")
    print(f"  {'─'*58}")
    print(f"  Tổng request : {total}  ({rps:.1f} req/s)")
    print(f"  Latency")
    print(f"    p50  : {c(lat_color(p50),  f'{p50:.0f} ms')}  {bar(p50,  BOT_TIMEOUT_MS, 25, lat_color(p50))}")
    print(f"    p95  : {c(lat_color(p95),  f'{p95:.0f} ms')}  {bar(p95,  BOT_TIMEOUT_MS, 25, lat_color(p95))}")
    print(f"    p99  : {c(lat_color(p99),  f'{p99:.0f} ms')}  {bar(p99,  BOT_TIMEOUT_MS, 25, lat_color(p99))}")
    print(f"    max  : {c(lat_color(pmax), f'{pmax:.0f} ms')}  {bar(pmax, BOT_TIMEOUT_MS, 25, lat_color(pmax))}")
    print(f"    {'─'*40}")
    print(f"    Ngưỡng BTC bot timeout : {BOT_TIMEOUT_MS} ms")
    if pmax > SVC_DANGER_MS:
        print(f"    {c(RED, '→ NGUY HIỂM: Có request gần/vượt ngưỡng bot timeout!')}")
        print(f"    {c(RED, '→ Bot BTC sẽ tính WAF lỗi → mất SVC!')}")
    elif p95 > SVC_WARN_MS:
        print(f"    {c(YELLOW, '→ CẢNH BÁO: Latency cao dưới tải — cần tối ưu rule')}")
    else:
        print(f"    {c(GREEN, '→ OK: WAF xử lý tốt với ' + str(n_teams) + ' đội tấn công đồng thời')}")

    print(f"  {'─'*58}")

    # Accuracy dưới tải
    icon_fn = c(GREEN, "✓") if fn_n == 0 else c(YELLOW, f"⚠ {fn_n} miss")
    icon_fp = c(GREEN, "✓") if fp_n == 0 else c(RED,    f"✗ {fp_n} false positive")
    icon_er = c(GREEN, "✓") if err_n == 0 else c(RED,   f"✗ {err_n} timeout/lỗi")
    print(f"  Chặn đúng  : {icon_fn}")
    print(f"  Chặn nhầm  : {icon_fp}")
    print(f"  Lỗi/Timeout: {icon_er}")

    if verbose and r["fn"]:
        print(f"  Payload lọt qua (dưới tải):")
        for p, code in r["fn"][:5]:
            print(f"    HTTP {code} ← {p[:55]}")
    if verbose and r["fp"]:
        print(f"  Request bình thường bị block (dưới tải):")
        for p, code in r["fp"][:5]:
            print(f"    HTTP {code} ← {p[:55]}")

    # Đội chậm nhất
    st = r["slowest_team"]
    st_ms = r["slowest_team_p50"]
    print(f"  Đội lag nhất: #{st} (p50={st_ms:.0f}ms)")
    print(f"  {'═'*58}\n")


def verdict(redos: dict, payload: dict, live: Optional[dict], load: Optional[dict]) -> str:
    fails  = []
    warns  = []

    if redos["status"] == "error":   fails.append("Regex lỗi cú pháp")
    if redos["status"] == "danger":  fails.append("ReDoS nguy hiểm")
    if redos["status"] == "warn":    warns.append("Regex hơi chậm")

    if payload["fp"]:                fails.append(f"{len(payload['fp'])} false positive offline")
    if payload["fn"]:                warns.append(f"{len(payload['fn'])} payload lọt offline")

    if live:
        if live["fp"]:               fails.append(f"{len(live['fp'])} FP live")
        if live["fn"]:               warns.append(f"{len(live['fn'])} miss live")

    if load:
        if load.get("err_count", 0) > load.get("total_req", 1) * 0.1:
            fails.append("Hơn 10% request lỗi/timeout dưới tải")
        if load.get("p95", 0) > SVC_DANGER_MS:
            fails.append(f"p95 latency {load['p95']:.0f}ms > {SVC_DANGER_MS}ms")
        elif load.get("p95", 0) > SVC_WARN_MS:
            warns.append(f"p95 latency {load['p95']:.0f}ms hơi cao")
        if load.get("fp_count", 0) > 0:
            fails.append(f"{load['fp_count']} FP dưới tải")

    if fails:
        return c(RED, "✗ KHÔNG DEPLOY — " + " | ".join(fails))
    if warns:
        return c(YELLOW, "⚠ DEPLOY CẨN THẬN — " + " | ".join(warns))
    return c(GREEN, "✓ OK — Có thể deploy")


# ═══════════════════════════════════════════════════════════════
# PHẦN 7: MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="WAF Rule Tester — F-Hacker 2026",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python3 waf_rule_tester.py rules.conf
  python3 waf_rule_tester.py rules.conf --waf http://localhost:8000
  python3 waf_rule_tester.py rules.conf --waf http://localhost:8000 --load --teams 16 --duration 20
  python3 waf_rule_tester.py rules.conf --waf http://localhost:8000 --load-only
        """)
    ap.add_argument("rule_file",         help="File .conf chứa SecRule")
    ap.add_argument("--waf",             help="URL WAF (vd: http://localhost:8000)")
    ap.add_argument("--load",            action="store_true", help="Thêm load test sau live test")
    ap.add_argument("--load-only",       action="store_true", help="Chỉ load test (bỏ offline)")
    ap.add_argument("--teams",           type=int, default=16, help="Số đội giả lập (mặc định: 16)")
    ap.add_argument("--duration",        type=int, default=15, help="Thời gian load test giây (mặc định: 15)")
    ap.add_argument("--verbose", "-v",   action="store_true", help="Chi tiết payload lọt/nhầm")
    ap.add_argument("--redos-only",      action="store_true", help="Chỉ test ReDoS")
    ap.add_argument("--wordlists",       nargs="?", const=str(WORDLIST_BASE_DEFAULT), default=None,
                     metavar="DIR",
                     help="Nạp thêm payload thật từ PayloadsAllTheThings/SecLists đã clone "
                          f"(mặc định {WORDLIST_BASE_DEFAULT} nếu không truyền DIR). Tắt theo mặc định.")
    ap.add_argument("--wordlist-sample", type=int, default=60,
                     help="Số dòng lấy mẫu mỗi category khi dùng --wordlists (mặc định: 60)")
    args = ap.parse_args()

    # Đọc file
    try:
        content = open(args.rule_file, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"{RED}Không tìm thấy file: {args.rule_file}{RESET}")
        sys.exit(1)

    rules = parse_modsec_rules(content)
    if not rules:
        print(f"{YELLOW}Không tìm thấy SecRule nào.{RESET}")
        sys.exit(0)

    print(f"\n{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   WAF Rule Tester — F-Hacker 2026            ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════╝{RESET}")
    print(f"  File   : {args.rule_file}  ({len(rules)} rules)")
    if args.waf:
        print(f"  WAF    : {args.waf}")
    if args.load or args.load_only:
        print(f"  Load   : {args.teams} đội × {args.duration}s")

    if args.wordlists:
        base = Path(args.wordlists)
        extra, counts = load_wordlist_payloads(base, args.wordlist_sample)
        if extra:
            MALICIOUS_PAYLOADS.extend(extra)
            detail = ", ".join(f"{cat}:{n}" for cat, n in counts.items() if n)
            print(f"  Wordlist: {base}  → +{len(extra)} payload ({detail})")
            missing = [cat for cat, n in counts.items() if n == 0]
            if missing:
                print(f"  {c(DIM, '  (không tìm thấy file nguồn cho: ' + ', '.join(missing) + ')')}")
        else:
            print(f"  {c(YELLOW, f'⚠ --wordlists {base} không tìm thấy file nguồn nào (xem WORDLIST_SOURCES)')}")

    ok_n, warn_n, fail_n = 0, 0, 0

    # Chạy load test TOÀN BỘ rule cùng lúc (rule đã deploy, WAF tải toàn bộ)
    # → chạy 1 lần duy nhất, không cần lặp từng rule
    global_load = None
    if (args.load or args.load_only) and args.waf:
        global_load = run_load_test(args.waf, args.teams, args.duration)

    for rule in rules:
        category = infer_category(rule)
        print_header(rule, category)

        # 1. ReDoS (offline, gồm cả regex của chain con)
        redos_r = test_redos(rule)
        print_redos(redos_r)

        # 2. Payload matching (offline, chỉ scope đúng category của rule)
        payload_r: dict = {"fn": [], "fp": [], "category": category,
                            "mal_blocked": 0, "mal_total": 0, "ben_total": 0}
        if not args.redos_only and not args.load_only:
            payload_r = test_payloads(rule, category)
            print_payload(payload_r, args.verbose)

        # 3. Live test (1 thread, đúng category + đúng kênh gửi của rule)
        live_r = None
        if args.waf and not args.redos_only and not args.load_only:
            live_r = test_live_single(args.waf, rule, category)
            print_live(live_r, args.verbose)

        # 4. Load test (kết quả global đã chạy ở trên)
        load_r = None
        if global_load:
            load_r = global_load          # Dùng chung kết quả load toàn bộ WAF
            print_load(load_r, args.verbose)
            global_load = None            # Chỉ in 1 lần (ở rule đầu tiên)

        # Verdict
        v = verdict(redos_r, payload_r, live_r, load_r)
        print(f"\n  Kết luận: {v}\n")
        if "✓" in v:   ok_n   += 1
        elif "⚠" in v: warn_n += 1
        else:          fail_n += 1

    # Tổng kết
    print(f"\n{'═'*62}")
    print(f"  TỔNG KẾT  ({len(rules)} rules)")
    print(f"  {c(GREEN,  f'✓ OK        : {ok_n}')}")
    print(f"  {c(YELLOW, f'⚠ Cảnh báo  : {warn_n}')}")
    print(f"  {c(RED,    f'✗ Lỗi       : {fail_n}')}")
    if fail_n:
        print(f"\n  {c(RED,    '→ Sửa rule lỗi trước khi deploy!')}")
    elif warn_n:
        print(f"\n  {c(YELLOW, '→ Kiểm tra rule cảnh báo rồi mới bật block.')}")
    else:
        print(f"\n  {c(GREEN,  '→ Tất cả OK — Có thể deploy lên WAF UI.')}")
    print(f"{'═'*62}\n")

    sys.exit(1 if fail_n else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
ModSecurity v3 / BunkerWeb Rule Generator & Validator for F-Hacker 2026.

Designed from:
- FHACKER2026_5_Khuon_Va_Nhanh_CopySafe
- FHACKER2026_Regex_CopySafe
- NOTE_PHONG_THU_NHANH & FHACKER2026_WAF_Defense_Cheatsheet
- PayloadsAllTheThings / SecLists bypass & polyglot patterns
- waf_rule_tester.py ReDoS & FP validation logic
"""

from __future__ import annotations

import base64
import html as html_mod
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

DEFAULT_FLAG_PATTERN = r"FHACKER(?:2026)?\{[0-9a-fA-F]{64}\}"

# ReDoS stress inputs (from waf_rule_tester.py)
REDOS_TEST_INPUTS = [
    "a" * 50,
    "a" * 200,
    "a" * 1000,
    "' " * 50,
    "UNION " * 30 + "SELECT",
    "<" * 100 + "script",
    "../" * 50,
    "{{" * 30 + "config" + "}}" * 30,
    "aaaaaaaaaaaaaaaaaaaab" * 10,
    "(" * 20 + "a+" * 20 + ")" * 20,
    "select " * 20 + "from " * 20,
    "A" * 500 + "!",
]

# Benign inputs including real CTF/AD healthcheck & Vietnamese free-text cases
BENIGN_SAMPLES = [
    "hello world",
    "my name is Alice",
    "laptop gaming",
    "ao thun nam",
    "iPhone 15",
    "Select Comfort Mattress",
    "O'Brien",
    "report.v2.pdf",
    "2026-11-28",
    "user@example.com",
    "12345",
    "42",
    "user_id=42",
    '{"name": "Alice", "age": 25}',
    '{"status": "ok", "data": [1, 2, 3]}',
    "username=alice&password=secret123",
    "title=My+Blog+Post&content=Hello+World",
    "comment=Great+article!",
    "SELECT * FROM",
    "union all",
    "insert coin",
    "/api/users/123",
    "/api/posts?page=1&limit=10",
    "note=Hôm nay trời đẹp, tôi đi học CTF.",
    "I don't or won't accept this",
    "Tom & Jerry go to school",
    "select comfort mattress from catalog",
    "union of workers and teachers",
]

# CopySafe Allowlist Patterns (used with !@rx)
ALLOWLIST_TEMPLATES: list[dict[str, Any]] = [
    {
        "key": "int",
        "label": "Số nguyên dương (1–10 chữ số)",
        "param_hints": {
            "id", "uid", "pid", "nid", "cid", "oid", "page", "limit", "offset", "count", "num",
            "user_id", "userid", "note_id", "noteid", "post_id", "postid", "item_id", "itemid",
            "order_id", "orderid", "product_id", "productid", "doc_id", "docid", "file_id", "fileid",
            "pagesize", "page_size", "per_page",
        },
        "regex": r"^[0-9]{1,10}\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni",
        "desc": "Chặn 100% SQLi/LFI/CMDi/SSTI trên tham số số nguyên; 0% ReDoS.",
    },
    {
        "key": "uuid",
        "label": "UUID (36 ký tự)",
        "param_hints": {"uuid", "guid", "request_id", "requestid", "session_id", "sessionid"},
        "regex": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni",
        "desc": "Chỉ cho phép UUID chuẩn 36 ký tự hex.",
    },
    {
        "key": "enum_sort",
        "label": "Danh sách cố định (sort/order)",
        "param_hints": {"sort", "sort_by", "sortby", "order", "order_by", "orderby", "dir", "direction"},
        "regex": r"^(?:id|name|title|created_at|updated_at|price|asc|desc)?\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni,t:lowercase",
        "desc": "Allowlist cột ORDER BY / hướng sắp xếp (nhớ chỉnh đúng tên cột app dùng).",
    },
    {
        "key": "locale",
        "label": "Mã ngôn ngữ (vi / en-US)",
        "param_hints": {"lang", "locale", "language"},
        "regex": r"^[a-z]{2}(?:-[A-Z]{2})?\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni",
        "desc": "Chống LFI qua tham số chọn ngôn ngữ.",
    },
    {
        "key": "host",
        "label": "Hostname / IPv4 (ping/check)",
        "param_hints": {"host", "ip", "domain", "hostname"},
        "regex": r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$|^(?:\d{1,3}\.){3}\d{1,3}\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni",
        "desc": "Chỉ cho phép tên miền hoặc IPv4 hợp lệ, chặn CMDi.",
    },
    {
        "key": "safe_filename",
        "label": "Tên file an toàn (không chứa / hoặc ..)",
        "param_hints": {"file", "filename", "doc", "download", "attachment", "avatar", "filepath"},
        "regex": r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){0,8}\.(?:pdf|png|jpe?g|gif|txt|csv)\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni,t:lowercase",
        "desc": "Cho phép tên file có nhiều dấu chấm (vd report.v2.pdf) nhưng không cho / hay đường dẫn (chỉnh đuôi nếu app cần).",
    },
    {
        "key": "internal_path",
        "label": "Đường dẫn nội bộ (chống Open Redirect)",
        "param_hints": {"next", "return", "redirect", "redirect_uri", "redirecturi", "redirect_url", "redirecturl", "continue", "dest", "destination", "return_to", "returnto", "redir", "goto", "checkout_url", "callback"},
        "regex": r"^/(?![/\\])(?!.*\.\.)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni",
        "desc": "Chỉ cho phép đường dẫn bắt đầu bằng / đơn (chặn //, /\\ và http://).",
    },
    {
        "key": "calc",
        "label": "Biểu thức số học an toàn",
        "param_hints": {"expr", "calc", "formula", "math"},
        "regex": r"^[0-9+\-*/().\s]{1,128}\z",
        "transforms": "t:none,t:urlDecodeUni,t:urlDecodeUni",
        "desc": "Chống Code Injection eval() trên route tính toán.",
    },
]


@dataclass(frozen=True)
class AttackPattern:
    key: str
    tag: str
    name: str
    detect_re: re.Pattern[str]
    modsec_op: str          # "@rx ..." or "@detectSQLi" or "@detectXSS"
    modsec_pattern: str
    transforms: str
    phase: int = 2
    target_mode: str = "value"  # "value" | "name" | "body" | "uri" | "header_name"
    note: str = ""


# Curated CopySafe attack signatures (bounded quantifiers, ReDoS-safe, ModSecurity v3 anti-bypass hardened)
_SQLI_AUTH_RX = (
    r"(?i)(?:(?:'|\x22)[\s\xa0]*(?:or|and|\|\||&&)[\s\xa0]*(?:(?:'|\x22)[^'\x22]{0,30}(?:'|\x22)[\s\xa0]*(?:=|!=|<>|like|rlike|regexp)[\s\xa0]*(?:'|\x22)[^'\x22]{0,30}(?:'|\x22)|['\x22]?\d+['\x22]?[\s\xa0]*(?:=|!=|<>|<|>)[\s\xa0]*['\x22]?\d+|true\b|false\b|not[\s\xa0]+0\b|1\.e\s*\(|['\x22][- &^*]?)"
    r"|\)[\s\xa0]*(?:or|and|\|\||&&)[\s\xa0]*\(?[\s\xa0]*(?:['\x22]?\w+['\x22]?[\s\xa0]*=[\s\xa0]*['\x22]?\w+|true\b|\d+=\d+)"
    r"|\b\d+[\s\xa0]+(?:or|and)[\s\xa0]+\d+[\s\xa0]*(?:=|!=|<>|<|>)\s*\d+"
    r"|'\s*(?:--|#|/\*!|=\s*0\b)"
    r"|/\*!\d{0,5}(?:union|select|and|or|if|sleep|benchmark|cast|convert|concat|extractvalue|updatexml)?"
    r"|(?:'|\x22|\b\d+\b|\))[\s\xa0]*(?:\|\||&&)[\s\xa0]*\(?[\s\xa0]*(?:select\b|pg_sleep|sleep|case\b))"
)

_SQLI_KW_RX = (
    r"(?i)(?:(?:^|\b|\d[eE]\d*|\d\.e|\W)union(?:/\*[^*]{0,40}\*/|[\s\xa0+(]){1,20}(?:(?:all|distinct(?:row)?)(?:/\*[^*]{0,40}\*/|[\s\xa0+(]){1,20})?select(?:\b|[\s(/*])"
    r"|\(\s*select\b[^)]{0,160}\b(?:from\s+[a-z_][a-z0-9_.$]{0,64}|version\s*\(|sqlite_version\s*\(|current_database\s*\(|database\s*\(|user\s*\(|@@\w+)"
    r"|\bselect\b(?:[\s\xa0]+distinct)?[^;]{0,160}\bfrom[\s\xa0]+[a-z_][a-z0-9_.$]{0,64}[\s\xa0]*(?:--|#|/\*|\bwhere\b|\blimit\b|\border[\s\xa0]+by\b|\bgroup[\s\xa0]+by\b|\bhaving\b|\bunion\b|\))"
    r"|\bselect[\s\xa0]+(?:@@\w+|(?:sqlite_version|current_database|version|pg_read_file|load_extension)\s*\()"
    r"|(?:'|\x22|\)|\d)[\s\xa0]*;[\s\xa0]*(?:select|insert|update|delete|drop|alter|create|truncate|exec|execute|declare|attach|copy|pragma|waitfor)\b"
    r"|(?:'|\x22|\))[\s\xa0]*(?:and|or)[\s\xa0]+(?:substring|substr|ascii|ord|mid|length|char|if|case[\s\xa0]+when)\s*\("
    r"|\bcase[\s\xa0]+when\b[^;]{0,120}\bthen\b[^;]{0,120}\b(?:else|end)\b"
    r"|\b(?:sleep|benchmark|pg_sleep|dbms_pipe\.receive_message|extractvalue|updatexml|load_file|randomblob|group_concat|concat_ws|unhex|gtid_subset|json_keys|name_const|load_extension|generate_series|query_to_xml|xp_cmdshell|openrowset)\s*\("
    r"|\bwaitfor[\s\xa0]+(?:delay|time)\b|\binto[\s\xa0]+(?:out|dump)file\b|\bdrop[\s\xa0]+table\b"
    r"|\b(?:information_schema|sqlite_(?:master|schema|temp_master)|pragma_table_info|pg_(?:catalog|tables|shadow|user)|mysql\.(?:user|db|innodb_table_stats)|master\.\.sys(?:databases|objects|columns))\b"
    r"|\b(?:cast|convert)\s*\([^)]{0,120}(?:\bas[\s\xa0]+(?:int|integer|numeric|signed)|,[\s\xa0]*int)\b"
    r"|/\*!\d{0,5}\s*(?:union|select|insert|update|delete|drop|and|or|if|sleep|benchmark|cast|convert|concat|extractvalue|updatexml|load_file)\b)"
)

_CMD_NAMES_RX = (
    r"(?:id|whoami|cat|tac|head|tail|nl|ls|dir|type|uname|pwd|ping|curl|wget|nc|ncat|netcat|socat|sh|bash|dash|zsh|ksh"
    r"|python\d?|php\d?|perl|ruby|node|lua|awk|gawk|sed|grep|egrep|more|less|base64|base32|xxd|od|strings|tr|cut|sort"
    r"|uniq|wc|tee|xargs|find|env|printenv|sleep|usleep|timeout|echo|printf|ps|ss|netstat|lsof|nslookup|dig|telnet"
    r"|powershell|cmd)\b(?!\s*=)"
)
_CMDI_PRIMARY_RX = (
    # ;/|/CRLF trần KHÔNG đủ tín hiệu (có trong văn bản thường: "note; xem thêm",
    # xuống dòng trong textarea...) -> BẮT BUỘC đi kèm tên lệnh thật ngay sau (đã
    # verify thật: cmdi.detect_re.search("hello; world") từng trả True = FP).
    r"(?i)(?:[;|`]\s*" + _CMD_NAMES_RX + r"|[\r\n]\s*" + _CMD_NAMES_RX + r"|\x00"
    r"|\$\([^)]{0,200}\)|<[<(]"
    r"|\$\{?(?:IFS|[@*0-9]|HOME:|PATH:|SHELL:)[^}]{0,30}\}?"
    r"|\$[@*]|\$'[^']{1,120}'|\{[a-z/?*_-]{1,32},[^}]{1,120}\}"
    r"|/(?:\?{2,6}/[a-z0-9_?*\[\]-]{1,16}|(?:bin|usr/bin|sbin)/[a-z0-9_?*.-]*[?*\[][a-z0-9_?*.-]*)"
    r"|\|\||&&|(?:<<<|>>?\s*/(?:etc|tmp|var|dev|proc|home|root|app)|<\s*/(?:etc|proc|flag|dev/tcp)|/dev/(?:tcp|udp)/|2>&1|1>&2)"
    r"|&\s*(?:/(?:[a-z0-9_?*\[\]-]+/){0,5}[a-z0-9_?*\[\]-]+|[a-z_]{1,12}[\x27\x22\\^][a-z0-9_\x27\x22\\^*?./-]+|\$\{|[<>]|" + _CMD_NAMES_RX + r"))"
)

_XSS_PRIMARY_RX = (
    r"(?i)(?:<\s*(?:[a-z0-9_-]+:)?\/?(?:script|svg|iframe|object|embed|marquee|plaintext|math|applet|meta|base|animate|animatetransform|foreignobject)\b"
    r"|<(?:details|body|img|video|audio|source|input|select|textarea|keygen|form|isindex)\b[^>]{0,200}(?:\bon[a-z]{3,32}[\s/\x00\x0c]*=|\bautofocus\b|\bformaction\s*=)"
    r"|java[\t\r\n]*script\s*:|vb[\t\r\n]*script\s*:|data\s*:\s*(?:text/html|image/svg\+xml|application/xhtml\+xml)|\+ADw-(?:script|svg|img|iframe)"
    r"|\bon(?:abort|after|anim|aux|before|begin|blur|can|change|click|close|context|copy|cut|dbl|drag|drop|duration|empt|end|error|focus|form|full|hash|in|invalid|key|load|message|mouse|offline|online|open|page|paste|pause|play|pointer|pop|progress|random|rate|ready|reset|resize|scroll|search|security|seek|select|show|stalled|start|storage|submit|suspend|time|toggle|touch|transition|unload|volume|waiting|wheel)[a-z]{0,24}[\s/\x00\x0c]*="
    r"|srcdoc\s*=|formaction\s*=|\bconstructor\s*\(\s*[\x27\x22\x60]|String\.fromCharCode)"
)

ATTACK_PATTERNS: list[AttackPattern] = [
    AttackPattern(
        key="sqli_auth",
        tag="sqli",
        name="SQL Injection (Boolean / Auth / Comment / Bypass)",
        detect_re=re.compile(_SQLI_AUTH_RX),
        modsec_op="rx",
        modsec_pattern=_SQLI_AUTH_RX,
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:compressWhitespace",
        note="Tổng quát hóa boolean/toán tử/dấu ngoặc//*!50000...*/, không chặn nhầm tên có dấu nháy như O'Brien.",
    ),
    AttackPattern(
        key="sqli_kw",
        tag="sqli",
        name="SQL Injection (UNION / Subquery / Blind / Stacked)",
        detect_re=re.compile(_SQLI_KW_RX),
        modsec_op="rx",
        modsec_pattern=_SQLI_KW_RX,
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:compressWhitespace,t:lowercase",
        note="Không bó hẹp tên bảng (chặn mọi bảng tùy ý), hỗ trợ 1e0union, subquery, CASE WHEN, SUBSTR, Postgres/SQLite/MySQL/MSSQL.",
    ),
    AttackPattern(
        key="nosqli",
        tag="nosqli",
        name="NoSQL Operator Injection ($ne/$where/$regex...)",
        detect_re=re.compile(
            r"(?i)(?:^\$|\.\$|\[\s*\$|\$(?:ne|eq|gt|gte|lt|lte|in|nin|where|regex|exists|or|and|not|nor|expr|jsonSchema|mod|type|elemMatch|size|all)\b)"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:^\$|\.\$|\[\s*\$|\$(?:ne|eq|gt|gte|lt|lte|in|nin|where|regex|exists|or|and|not|nor|expr|jsonSchema|mod|type|elemMatch|size|all)\b)",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:jsDecode",
        target_mode="name",
        note="Kiểm tra trên ARGS_NAMES|REQUEST_BODY kèm t:jsDecode để bắt cả password[$ne], JSON và \\u0024ne.",
    ),
    AttackPattern(
        key="lfi",
        tag="lfi",
        name="LFI / Path Traversal / PHP FilterChain",
        detect_re=re.compile(
            r"(?i)(?:(?:\.\.[;/\x5c]){2,}|(?:\xc0[\xae\x2e]\xc0[\xae\x2e]|%2e%2e|%252e%252e|%%32%65%%32%65|%c0%ae%c0%ae|%c0%2e%c0%2e|%e0%40%ae|%u002e%u002e|%uff0e%uff0e|%u2025|%ufe30|0x2e0x2e|\.\.\.+)(?:[;/\x5c]|\xc0[\xaf\x2f\x5c]|\xc1[\x9c\x1c]|\xe0\x80[\xaf\x5c]|%2f|%5c|%252f|%255c|%c0%af|%c0%2f|%c0%5c|%c1%9c|%c1%1c|%e0%80%af|%u2215|%u2216|%uff0f|%uff3c|0x2f)|(?:/|\x5c)\.\.$|(?:php|phar|zip|data|expect|glob|file|zlib|bzip2|rar|ogg|compress\.zlib|compress\.bzip2|ssh2\.[a-z]+|netdoc)://|convert\.(?:iconv|base64)\.|string\.rot13|filter/read=|^(?:/etc/|/proc/|/var/(?:log|lib/php|www)/|/home/|/root/|/run/secrets/|[A-Za-z]:[/\x5c]|\x5c\x5c))"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:(?:\.\.[;/\x5c]){2,}|(?:\xc0[\xae\x2e]\xc0[\xae\x2e]|%2e%2e|%252e%252e|%%32%65%%32%65|%c0%ae%c0%ae|%c0%2e%c0%2e|%e0%40%ae|%u002e%u002e|%uff0e%uff0e|%u2025|%ufe30|0x2e0x2e|\.\.\.+)(?:[;/\x5c]|\xc0[\xaf\x2f\x5c]|\xc1[\x9c\x1c]|\xe0\x80[\xaf\x5c]|%2f|%5c|%252f|%255c|%c0%af|%c0%2f|%c0%5c|%c1%9c|%c1%1c|%e0%80%af|%u2215|%u2216|%uff0f|%uff3c|0x2f)|(?:/|\x5c)\.\.\z|(?:php|phar|zip|data|expect|glob|file|zlib|bzip2|rar|ogg|compress\.zlib|compress\.bzip2|ssh2\.[a-z]+|netdoc)://|convert\.(?:iconv|base64)\.|string\.rot13|filter/read=|^(?:/etc/|/proc/|/var/(?:log|lib/php|www)/|/home/|/root/|/run/secrets/|[A-Za-z]:[/\x5c]|\x5c\x5c))",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:utf8toUnicode,t:lowercase",
        note="KHÔNG dùng t:normalizePath trên ARGS; \"../\" dạng ASCII thuần phải lặp >=2 lần mới khớp (1 lần quá phổ biến trong văn bản thường, đã verify FP thật); biến thể encode/obfuscate vẫn khớp từ 1 lần vì hiếm gặp trong văn bản.",
    ),
    AttackPattern(
        key="cmdi",
        tag="cmdi",
        name="Command Injection (Shell / IFS / Glob / Obfuscated)",
        detect_re=re.compile(_CMDI_PRIMARY_RX),
        modsec_op="rx",
        modsec_pattern=_CMDI_PRIMARY_RX,
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni",
        note="Chặn tách lệnh, $(...), $IFS/$@/${PATH:0:1}, $'\\x..', brace {cmd,arg}, wildcard /???/c?t, redirect và 60+ lệnh mà không chặn nhầm '&param=' hay 'Tom & Jerry'.",
    ),
    AttackPattern(
        key="code_exec",
        tag="code-injection",
        name="Code Injection (PHP/Python/Node/Java Eval)",
        detect_re=re.compile(
            r"(?i)(?:\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|create_function|eval|assert)\s*\(|\b(?:include|require)(?:_once)?\s*\(|\b(?:base64_decode|gzinflate|str_rot13|convert_uudecode)\s*\(|__(?:import|builtins|globals|subclasses|mro|base|bases|init|getitem)__|\b(?:os\.(?:system|popen|exec\w*)|subprocess\.(?:Popen|run|check_output|call)|importlib)\b|\brequire\s*\(\s*[\x22\x27](?:child_process|fs|net|http|vm)|child_process|mainModule|global\.process|process\.binding|java\.lang\.(?:Runtime|ProcessBuilder))"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|create_function|eval|assert)\s*\(|\b(?:include|require)(?:_once)?\s*\(|\b(?:base64_decode|gzinflate|str_rot13|convert_uudecode)\s*\(|__(?:import|builtins|globals|subclasses|mro|base|bases|init|getitem)__|\b(?:os\.(?:system|popen|exec\w*)|subprocess\.(?:Popen|run|check_output|call)|importlib)\b|\brequire\s*\(\s*[\x22\x27](?:child_process|fs|net|http|vm)|child_process|mainModule|global\.process|process\.binding|java\.lang\.(?:Runtime|ProcessBuilder))",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:jsDecode,t:removeNulls,t:lowercase",
    ),
    AttackPattern(
        key="ssti",
        tag="ssti",
        name="Server-Side Template Injection (SSTI)",
        detect_re=re.compile(
            r"(?i)(?:\{\{[^}]{0,300}(?:__(?:class|mro|base|bases|subclasses|globals|builtins|import|init|getitem|dict|doc)__|\.\s*(?:class|mro|base|bases|subclasses|globals|builtins|module|getclass|forname|env)\b|\|\s*(?:attr|filter|map|reduce|sort|join|format)\s*\(|\b(?:config|request|self|lipsum|cycler|joiner|namespace|get_flashed_messages|url_for|_self|_context|popen|system|exec|shell_exec|passthru|proc_open|call_user_func|readfile|listfiles|constructor|range\.constructor)\b|\b(?:eval|open|read|dump)\s*\(|\d{1,5}\s*[*+-]\s*[\x27\x22]?\d{1,5}|\b1\s*/\s*0\b)[^}]{0,300}\}\}|\{%[^%]{0,300}(?:config|__class__|__subclasses__|import|system|popen|exec|sort\s*\(|for\s+\w+\s+in)[^%]{0,300}%\}|(?:\$\{|\#\{|\*\{|\[=)[^}\]]{0,300}(?:T\s*\(|Runtime|getClass|forName|exec|popen|system|__import__|self\.module|freemarker|new\s*\(|ProcessBuilder|global\.process|[3-9]\s*\*\s*[\x27\x22]?[3-9])[^}\]]{0,300}(?:\}|\])|<%=?[\s\S]{0,300}?%>|#set\s*\(|#assign\s+|\[#assign\s+|\?new\s*\(|\{(?:php|system|Smarty_Internal_Write_File)\b|\{\$smarty\.)"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:\{\{[^}]{0,300}(?:__(?:class|mro|base|bases|subclasses|globals|builtins|import|init|getitem|dict|doc)__|\.\s*(?:class|mro|base|bases|subclasses|globals|builtins|module|getclass|forname|env)\b|\|\s*(?:attr|filter|map|reduce|sort|join|format)\s*\(|\b(?:config|request|self|lipsum|cycler|joiner|namespace|get_flashed_messages|url_for|_self|_context|popen|system|exec|shell_exec|passthru|proc_open|call_user_func|readfile|listfiles|constructor|range\.constructor)\b|\b(?:eval|open|read|dump)\s*\(|\d{1,5}\s*[*+-]\s*[\x27\x22]?\d{1,5}|\b1\s*/\s*0\b)[^}]{0,300}\}\}|\{%[^%]{0,300}(?:config|__class__|__subclasses__|import|system|popen|exec|sort\s*\(|for\s+\w+\s+in)[^%]{0,300}%\}|(?:\$\{|\#\{|\*\{|\[=)[^}\]]{0,300}(?:T\s*\(|Runtime|getClass|forName|exec|popen|system|__import__|self\.module|freemarker|new\s*\(|ProcessBuilder|global\.process|[3-9]\s*\*\s*[\x27\x22]?[3-9])[^}\]]{0,300}(?:\}|\])|<%=?[\s\S]{0,300}?%>|#set\s*\(|#assign\s+|\[#assign\s+|\?new\s*\(|\{(?:php|system|Smarty_Internal_Write_File)\b|\{\$smarty\.)",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:removeNulls,t:lowercase",
        note="Có t:jsDecode chống escape \\x5f, bắt |attr()/|filter()/|map(), Mako/Twig/Freemarker/Thymeleaf và mọi phép thử số {{N*M}} mà không chặn nhầm {{user}} của Vue.",
    ),
    AttackPattern(
        key="xss",
        tag="xss",
        name="Cross-Site Scripting (XSS)",
        detect_re=re.compile(_XSS_PRIMARY_RX),
        modsec_op="rx",
        modsec_pattern=_XSS_PRIMARY_RX,
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase",
        note="Giải 2 lớp URL + null + HTML entity + JS/CSS escape; tổng quát hóa thẻ HTML5/SVG và event handler on*.",
    ),
    AttackPattern(
        key="ssrf_host",
        tag="ssrf",
        name="SSRF (Internal IP / Localhost / Cloud Metadata / DNS Wildcard / Obfuscated IP)",
        detect_re=re.compile(
            r"(?i)(?:https?|ftp)://(?:[^\s/@#]{1,120}@)?(?:localhost|127(?:\.\d{1,3}){0,3}|0(?:\.0){0,3}|\[?::(?:0|1)?\]?|\[?(?:0+:){1,6}(?:0*:)?(?:1|ffff:[^\]]+)\]?|\[?::ffff:[^\]]+\]?|\[?fd00:ec2::254\]?|\[?fe80:[^\]]*\]?|10(?:\.\d{1,3}){1,3}|192\.168(?:\.\d{1,3}){1,2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){1,2}|169\.254(?:\.\d{1,3}){1,2}|100\.100\.100\.200|metadata\.(?:google|azure)\.internal|(?:[a-z0-9-]{1,63}\.)*(?:nip\.io|sslip\.io|xip\.io|localtest\.me|localh\.st|lvh\.me|vcap\.me|localhost|host\.docker\.internal)|[a-z0-9_-]{2,32}:\d{1,5}|(?:0x[0-9a-f]{1,8}|\d{8,10}|0[0-7]{1,11})(?:\.(?:0x[0-9a-f]{1,8}|0[0-7]{1,11}|\d{1,3})){0,3})(?::\d+)?(?:[:/?#]|$)"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:https?|ftp)://(?:[^\s/@#]{1,120}@)?(?:localhost|127(?:\.\d{1,3}){0,3}|0(?:\.0){0,3}|\[?::(?:0|1)?\]?|\[?(?:0+:){1,6}(?:0*:)?(?:1|ffff:[^\]]+)\]?|\[?::ffff:[^\]]+\]?|\[?fd00:ec2::254\]?|\[?fe80:[^\]]*\]?|10(?:\.\d{1,3}){1,3}|192\.168(?:\.\d{1,3}){1,2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){1,2}|169\.254(?:\.\d{1,3}){1,2}|100\.100\.100\.200|metadata\.(?:google|azure)\.internal|(?:[a-z0-9-]{1,63}\.)*(?:nip\.io|sslip\.io|xip\.io|localtest\.me|localh\.st|lvh\.me|vcap\.me|localhost|host\.docker\.internal)|[a-z0-9_-]{2,32}:\d{1,5}|(?:0x[0-9a-f]{1,8}|\d{8,10}|0[0-7]{1,11})(?:\.(?:0x[0-9a-f]{1,8}|0[0-7]{1,11}|\d{1,3})){0,3})(?::\d+)?(?:[:/?#]|$)",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:utf8toUnicode,t:lowercase",
    ),
    AttackPattern(
        key="ssrf_scheme",
        tag="ssrf",
        name="SSRF Dangerous Scheme (gopher/file/dict/ldap/smb...)",
        detect_re=re.compile(r"(?i)(?:^|[\s\x22\x27=:])(?:file|gopher|dict|jar|ldap|ldaps|rmi|tftp|sftp|smb|netdoc|php|expect)://"),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:^|[\s\x22\x27=:])(?:file|gopher|dict|jar|ldap|ldaps|rmi|tftp|sftp|smb|netdoc|php|expect)://",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:lowercase",
    ),
    AttackPattern(
        key="xxe",
        tag="xxe",
        name="XXE (DOCTYPE / ENTITY / Parameter Entity / XInclude)",
        detect_re=re.compile(
            r"(?i)(?:<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+[\x22\x27]|PUBLIC\s+[\x22\x27]|xmlns:xi\s*=|<\s*xi:include\b|xsi:schemaLocation\s*=)"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+[\x22\x27]|PUBLIC\s+[\x22\x27]|xmlns:xi\s*=|<\s*xi:include\b|xsi:schemaLocation\s*=|file://|php://|expect://|jar:|gopher://)",
        transforms="t:none,t:removeNulls",
        target_mode="body",
        note="Nếu Content-Type là XML/+xml/SVG+xml, tự sinh kèm rule Phase 1 ctl:requestBodyProcessor=URLENCODED (fix bẫy id:200000 của BunkerWeb) và t:removeNulls chống UTF-16 BOM.",
    ),
    AttackPattern(
        key="nosqli_js",
        tag="nosqli",
        name="NoSQLi JS Expression ($where / mapReduce)",
        detect_re=re.compile(
            r"(?i)(?:this\.(?:password|passwd|secret|flag|[a-z_]{1,32})|function\s*\(\s*\)\s*\{)"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:this\.[a-z_]{1,32}\b|function\s*\(\s*\)\s*\{)",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:jsDecode",
    ),
    AttackPattern(
        key="deser",
        tag="deserialization",
        name="Insecure Deserialization (PHP/Java/Python Pickle/NodeJS/.NET)",
        detect_re=re.compile(
            r"(?:rO0AB|gA[I-X][A-Za-z0-9+/=_-]{6,}|Y(?:29z|3Bvc2l4|250)|AAEAAAD/////|(?i:aced0005|\xac\xed\x00\x05|\b[OCSE]:\+?\d{1,4}:\x22|\ba:\d+:\{(?:[isbadNO]:|[rR]:)|__(?:wakeup|destruct|toString|invoke|unserialize|HALT_COMPILER)|!!python/(?:object|name|module|tuple)|!!javax?\.|py/(?:object|reduce|repr)|c(?:posix|os|nt|subprocess|builtins|__builtin__)[\r\n]|_\$\$ND_FUNC\$\$_|__js_function|CommonsCollections|CommonsBeanutils|InvokerTransformer|ChainedTransformer|TemplatesImpl|AnnotationInvocationHandler|JdbcRowSetImpl|FileSystemXmlApplicationContext|BeanShell|BinaryFormatter|ObjectDataProvider|TypeConfuseDelegate|ExpandedWrapper))"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?:rO0AB|gA[I-X][A-Za-z0-9+/=_-]{6,}|Y(?:29z|3Bvc2l4|250)|AAEAAAD/////|(?i:aced0005|\b[OCSE]:\+?\d{1,4}:\x22|\ba:\d+:\{(?:[isbadNO]:|[rR]:)|__(?:wakeup|destruct|toString|invoke|unserialize|HALT_COMPILER)|!!python/(?:object|name|module|tuple)|!!javax?\.|py/(?:object|reduce|repr)|c(?:posix|os|nt|subprocess|builtins|__builtin__)[\r\n]|_\$\$ND_FUNC\$\$_|__js_function|CommonsCollections|CommonsBeanutils|InvokerTransformer|ChainedTransformer|TemplatesImpl|AnnotationInvocationHandler|JdbcRowSetImpl|FileSystemXmlApplicationContext|BeanShell|BinaryFormatter|ObjectDataProvider|TypeConfuseDelegate|ExpandedWrapper))",
        transforms="t:none,t:urlDecodeUni",
        note="Giữ nguyên chữ hoa/thường cho prefix Base64 (rO0AB, gA[I-X] Pickle proto 2-5), thêm PHP S:/a:/E:/__HALT_COMPILER và Node/Java gadgets. ĐÃ BỎ 'H4sI' (magic bytes gzip base64-hoá) — khớp bừa bất kỳ dữ liệu nén base64 hợp lệ nào (export/share/cache), không thể phân biệt độc hại nếu không giải nén thật (verify FP thật trên notevault share.php).",
    ),
    AttackPattern(
        key="crlf",
        tag="crlf",
        name="CRLF / Header Injection",
        detect_re=re.compile(r"(?i)(?:%0d|%0a|\r|\n)"),
        modsec_op="rx",
        modsec_pattern=r"(?:%0d|%0a|\r|\n)",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni",
    ),
    AttackPattern(
        key="log4shell",
        tag="log4shell",
        name="Log4Shell / JNDI Lookup",
        detect_re=re.compile(
            r"(?i)(?:\$\{[^}]{0,200}(?:jndi|ldap|rmi|dns|env|sys|java|lower|upper|date|::-))|(?:jndi\s*:\s*(?:ldap|rmi|dns|iiop))"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:\$\{[^}]{0,200}(?:jndi|ldap|rmi|dns|env|sys|java|lower|upper|date|::-))|(?:jndi\s*:\s*(?:ldap|rmi|dns|iiop))",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls",
    ),
    AttackPattern(
        key="proto",
        tag="prototype-pollution",
        name="Prototype Pollution (__proto__/constructor.prototype)",
        detect_re=re.compile(
            r"(?i)(?:__proto__|constructor\s*(?:\[\s*[\x22\x27]?|\.\s*)prototype|[\x22\x27]constructor[\x22\x27]\s*:\s*\{\s*[\x22\x27]prototype[\x22\x27]|prototype\s*(?:\[|\.)\s*[\x22\x27]?(?:isAdmin|admin|role|polluted))"
        ),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:__proto__|constructor\s*(?:\[\s*[\x22\x27]?|\.\s*)prototype|[\x22\x27]constructor[\x22\x27]\s*:\s*\{\s*[\x22\x27]prototype[\x22\x27]|prototype\s*(?:\[|\.)\s*[\x22\x27]?(?:isAdmin|admin|role|polluted))",
        transforms="t:none,t:urlDecodeUni,t:urlDecodeUni,t:jsDecode",
        target_mode="name",
    ),
    AttackPattern(
        key="graphql_intro",
        tag="graphql",
        name="GraphQL Introspection (__schema / __type)",
        detect_re=re.compile(r"(?i)\b__(?:schema|type)\b"),
        modsec_op="rx",
        modsec_pattern=r"(?i)\b__(?:schema|type)\b",
        transforms="t:none,t:jsDecode",
        target_mode="body",
    ),
    AttackPattern(
        key="php_magic_hash",
        tag="type-juggling",
        name="PHP Type Juggling (Magic Hash 0e...)",
        detect_re=re.compile(r"^0[eE][0-9]{4,}$"),
        modsec_op="rx",
        modsec_pattern=r"^0[eE][0-9]{4,}\z",
        transforms="t:none",
    ),
    AttackPattern(
        key="hash_len_ext",
        tag="crypto",
        name="Hash Length Extension Padding (%80%00...)",
        detect_re=re.compile(r"(?i)(?:%80(?:%00){2,}|%2580(?:%2500){2,}|\x80\x00{2,})"),
        modsec_op="rx",
        modsec_pattern=r"(?i)(?:%80(?:%00){2,}|%2580(?:%2500){2,}|\x80\x00{2,})",
        transforms="t:none",
    ),
]
_PAT_BY_KEY: dict[str, AttackPattern] = {p.key: p for p in ATTACK_PATTERNS}

PRIVILEGED_FIELD_RE = re.compile(
    r"(?i)(?:^|[.\[])(role|roles|is_?admin|admin|balance|credit|credits|permissions?|user_id|owner_id|verified|email_verified|is_?staff|is_?superuser|group_?id)(?:\]|\.array_\d+|$)"
)
OVERRIDE_HEADER_RE = re.compile(
    r"(?i)^(?:X-Original-URL|X-Rewrite-URL|X-Override-URL|X-HTTP-Method-Override|X-Method-Override|X-Custom-IP-Authorization|X-HTTP-Host-Override|X-Forwarded-Host|X-Forwarded-Server|X-Forwarded-Scheme|X-Host|X-Real-IP|True-Client-IP|Client-IP)$"
)
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.|$)|\.git(?:/|$)|\.svn(?:/|$)|\.hg(?:/|$)|\.ds_store$|\.htpasswd$|\.htaccess$|web\.config$|docker-compose\.ya?ml$|dockerfile$|id_rsa$|\.aws/|\.ssh/|console(?:/|$)|actuator(?:/|$))|\.(?:bak|backup|old|orig|save|swp|swo|sql|sqlite3?)$"
)
UPLOAD_PHP_PATH_RE = re.compile(r"(?i)^/(?:uploads?|files?|tmp|images?|media|static|avatars?)/.*\.(?:php\d?|phtml|phar|pht|jsp|jspx|asp|aspx|py|rb|sh|cgi)\.?(?:;[^/]*)?$")
WEBSHELL_BODY_RE = re.compile(r"(?i)(?:<\?(?:php|=)|<script\b|<%[\s=@]|Runtime\.getRuntime|ProcessBuilder|/bin/(?:ba)?sh|GIF89a<\?php|__HALT_COMPILER\s*\(\))")
REDIRECT_PARAM_RE = re.compile(r"(?i)^(?:next|return|return_?to|return_path|redirect|redirect_uri|redirecturi|redirect_url|redirecturl|continue|dest|destination|redir|goto|go|rurl|checkout_url|callback|redirectto)$")


def _escape_rx_literal(val: str) -> str:
    """Escape a route/host string for use inside ModSecurity @rx."""
    return re.sub(r"([.^$*+?{}\[\]\\|()])", r"\\\1", val)


def _escape_modsec_msg(val: str) -> str:
    # Bare '%' trong msg:/logdata: bị ModSecurity hiểu nhầm là mở đầu biến %{...}
    # (lỗi "Expecting a variable, got: :") nếu không theo sau bởi '{' -> thay bằng
    # "pct" để không vỡ cú pháp cả file .conf (đã verify thật: 1 rule có "%80%00"
    # trong msg khiến TOÀN BỘ custom config không nạp được, không báo lỗi rõ ràng).
    return re.sub(r"%(?!\{)", "pct", val).replace("\\", "\\\\").replace('"', '\\"').replace("'", "")


def _multi_decode(val: str) -> str:
    """Apply double URL decode + HTML entity decode to mirror ModSecurity transforms."""
    s = val
    for _ in range(2):
        try:
            s = urllib.parse.unquote_plus(s)
        except Exception:
            break
    try:
        s = html_mod.unescape(s)
    except Exception:
        pass
    return s


def _flatten_json(obj: Any, prefix: str = "json") -> list[tuple[str, str]]:
    """Flatten JSON structure using ModSecurity v3 json.* naming convention."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{prefix}.{k}"
            if isinstance(v, (dict, list)):
                out.extend(_flatten_json(v, sub))
            else:
                out.append((sub, "" if v is None else str(v)))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            sub = f"{prefix}.array_{idx}"
            if isinstance(item, (dict, list)):
                out.extend(_flatten_json(item, sub))
            else:
                out.append((sub, "" if item is None else str(item)))
    return out


def _inspect_jwt(token: str) -> list[str]:
    """Return list of JWT issues ('alg_none', 'empty_sig', 'jku_x5u', 'kid_inj') if token is a JWT."""
    issues: list[str] = []
    t = token.strip()
    if t.lower().startswith("bearer "):
        t = t[7:].strip()
    parts = t.split(".")
    if len(parts) != 3 or not parts[0].startswith("eyJ"):
        return issues
    if not parts[2]:
        issues.append("empty_sig")
    try:
        padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))
        if str(hdr.get("alg", "")).lower() == "none":
            issues.append("alg_none")
        if any(k in hdr for k in ("jku", "x5u", "jwk", "x5c")):
            issues.append("jku_x5u")
        kid = str(hdr.get("kid", ""))
        if kid and re.search(r"(?:\.\.|/|\\|'|\"|--|;|\||`|\$\()", kid):
            issues.append("kid_inj")
    except Exception:
        pass
    return issues


def _js_decode_sim(val: str) -> str:
    """Decode \\xHH, \\uHHHH, \\u{HHHH} and backslash escapes similarly to ModSec t:jsDecode."""
    def _rep_hex(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    s = re.sub(r"\\x([0-9a-fA-F]{2})", _rep_hex, val)
    s = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}", _rep_hex, s)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", _rep_hex, s)
    s = re.sub(r"\\([A-Za-z_'\"])", r"\1", s)
    return s


def _cmdline_sim(val: str) -> str:
    """Simulate ModSecurity t:cmdLine normalization."""
    s = val.lower()
    s = re.sub(r"[\"'\\^]", "", s)
    s = re.sub(r"\$\{?ifs\}?(?:\$\d)?", " ", s, flags=re.I)
    s = re.sub(r"[;,\s]+", " ", s).strip()
    return s


def _value_variants(val: str) -> list[str]:
    """Generate obfuscation-normalized forms so detect_re catches bypass payloads reliably."""
    dec = _multi_decode(val)
    no_null = dec.replace("\x00", "")
    comp_ws = re.sub(r"[\s\xa0]+", " ", no_null)
    no_cmt_del = re.sub(r"/\*[^*]{0,200}\*/", "", comp_ws)
    no_cmt_sp = re.sub(r"/\*[^*]{0,200}\*/", " ", comp_ws)
    no_cmt_ch = re.sub(r"/\*!?\d{0,5}|\*/", "", comp_ws)
    js_dec = _js_decode_sim(no_null)
    no_ctrl_ws = re.sub(r"[\t\r\n\v\f\x00]+", "", html_mod.unescape(js_dec))
    cmd_norm = _cmdline_sim(no_null)
    out: list[str] = []
    seen: set[str] = set()
    for cand in (val, dec, comp_ws, no_cmt_del, no_cmt_sp, no_cmt_ch, js_dec, no_ctrl_ws, cmd_norm):
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def _simulate_modsec_transforms(val: str, transforms: list[str]) -> str:
    """Apply common ModSecurity transform chain sequentially in Python for FP/match validation."""
    s = val
    for tr in transforms:
        tl = tr.lower()
        if tl == "none":
            continue
        elif tl == "urldecodeuni":
            try:
                s = urllib.parse.unquote_plus(re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s))
            except Exception:
                pass
        elif tl == "urldecode":
            try:
                s = urllib.parse.unquote(s)
            except Exception:
                pass
        elif tl == "removenulls":
            s = s.replace("\x00", "")
        elif tl == "htmlentitydecode":
            try:
                s = html_mod.unescape(s)
            except Exception:
                pass
        elif tl == "jsdecode":
            s = _js_decode_sim(s)
        elif tl == "replacecomments":
            s = re.sub(r"/\*[\s\S]*?\*/", " ", s)
        elif tl == "removecomments":
            s = re.sub(r"/\*[\s\S]*?\*/", "", s)
        elif tl == "removecommentschar":
            s = re.sub(r"/\*|\*/|--|#", "", s)
        elif tl == "compresswhitespace":
            s = re.sub(r"\s+", " ", s)
        elif tl == "removewhitespace":
            s = re.sub(r"\s+", "", s)
        elif tl == "cmdline":
            s = _cmdline_sim(s)
        elif tl == "normalizepath":
            s = re.sub(r"/{2,}", "/", s).replace("/./", "/")
        elif tl == "lowercase":
            s = s.lower()
    return s


def _extract_host_rx(host: str) -> str:
    raw_h = host.strip()
    try:
        hn = urllib.parse.urlsplit(f"//{raw_h}").hostname or raw_h.split(":")[0]
    except Exception:
        hn = raw_h.split(":")[0]
    if ":" in hn and not hn.startswith("["):
        esc = _escape_rx_literal(f"[{hn}]") + "|" + _escape_rx_literal(hn)
        return rf"(?i)^(?:{esc})(?::\d{{1,5}})?\z"
    return rf"(?i)^{_escape_rx_literal(hn)}(?::\d{{1,5}})?\z"


def _generalize_path_segment(seg: str) -> str:
    """Generalize numeric, UUID, hex, and trailing-ID path segments to prevent xxx123->xxx124 route bypass."""
    if re.fullmatch(r"\d{1,16}", seg):
        return r"[0-9]{1,16}"
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", seg):
        return r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    if re.fullmatch(r"[0-9a-fA-F]{16,64}", seg):
        return r"[0-9a-fA-F]{16,64}"
    m_tail = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*_)(\d{1,12})", seg) or re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*-)(\d{2,12})", seg)
    if m_tail:
        return rf"{_escape_rx_literal(m_tail.group(1))}[0-9]{{1,12}}"
    return _escape_rx_literal(seg)


def _routes_exclude_rx(routes: list[str]) -> str:
    """Combine several confirmed legit flag-serving routes into 1 anchored alternation regex,
    reusing _route_rx's ID/matrix-param generalization for each route."""
    bodies = [re.sub(r"^\(\?i\)\^", "", _route_rx(r)) for r in routes]
    return rf"(?i)^(?:{'|'.join(bodies)})"


def _route_rx(path: str) -> str:
    """Build generalized anti-bypass ModSecurity route regex (IDs, ;matrix params, PATH_INFO)."""
    base = path.split(";", 1)[0]
    clean = base.rstrip("/") or "/"
    if clean == "/":
        return r"(?i)^/(?:;[^/]*)?\z"
    segs = clean.split("/")[1:]
    rx_path = "/" + "/".join(_generalize_path_segment(s) for s in segs)
    if re.search(r"\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|py|rb|sh|cgi)$", clean, re.I):
        return rf"(?i)^{rx_path}(?:;[^/]*)?(?:/.*)?\z"
    return rf"(?i)^{rx_path}(?:;[^/]*)?/?\z"


def _build_chained_rule(
    rid: int,
    phase: int,
    action: str,
    tag: str,
    msg: str,
    logdata: str,
    child_var: str,
    child_op: str,
    child_pat: str,
    child_transforms: str,
    route_path: str | None = None,
    host: str | None = None,
    negate_op: bool = False,
) -> str:
    """Build a valid ModSecurity v3 SecRule (with optional Host and Route chain parents)."""
    op_prefix = "!@" if negate_op else "@"
    safe_msg = _escape_modsec_msg(msg)
    parents: list[tuple[str, str, str]] = []
    if host:
        parents.append(("REQUEST_HEADERS:Host", f"@rx {_extract_host_rx(host)}", "t:none"))
    if route_path:
        parents.append(("REQUEST_FILENAME", f"@rx {_route_rx(route_path)}", "t:none,t:urlDecodeUni,t:normalizePath"))

    if not parents:
        return (
            f'SecRule {child_var} "{op_prefix}{child_op} {child_pat}" \\\n'
            f'    "id:{rid},phase:{phase},{action},{child_transforms},\\\n'
            f'    msg:\'{safe_msg}\',tag:\'{tag}\',logdata:\'{logdata}\'"'
        )

    lines = []
    p0_var, p0_expr, p0_t = parents[0]
    lines.append(
        f'SecRule {p0_var} "{p0_expr}" \\\n'
        f'    "id:{rid},phase:{phase},{action},{p0_t},chain,\\\n'
        f'    msg:\'{safe_msg}\',tag:\'{tag}\',logdata:\'{logdata}\'"'
    )
    for p_var, p_expr, p_t in parents[1:]:
        lines.append(f'    SecRule {p_var} "{p_expr}" "{p_t},chain"')
    lines.append(f'    SecRule {child_var} "{op_prefix}{child_op} {child_pat}" "{child_transforms}"')
    return "\n".join(lines)


def _safe_arg_var(k: str) -> str:
    """Return safe ModSecurity variable target ARGS:<k>|ARGS:json.<k> or fallback ARGS."""
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k):
        return f"ARGS:{k}|ARGS:json.{k}"
    return "ARGS"


def _safe_flat_var(flat_k: str, bare: str | None) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", flat_k):
        return "ARGS"
    if bare and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", bare):
        return f"ARGS:{bare}|ARGS:{flat_k}"
    return f"ARGS:{flat_k}"


def generate_waf_rules(
    alert: dict[str, Any],
    base_rule_id: int = 27200,
    flag_pattern: str = DEFAULT_FLAG_PATTERN,
    action_mode: str = "pass",   # "pass" (safe default) or "deny"
    scope_host: bool = False,
    legit_flag_routes: list[str] | None = None,
) -> dict[str, Any]:
    """
    Analyze a captured alert and produce precision ModSecurity v3 & BunkerWeb rules.
    Follows FHACKER2026 CopySafe conventions & ReDoS-safe patterns.
    """
    uri = alert.get("uri") or "/"
    parsed = urllib.parse.urlsplit(uri)
    path = parsed.path or "/"
    method = (alert.get("method") or "GET").upper()
    host = (alert.get("host") or "").strip() if scope_host else ""
    req_body = alert.get("request_body") or ""
    req_headers_text = alert.get("request_headers_text") or ""
    if not req_headers_text and isinstance(alert.get("headers"), dict):
        req_headers_text = "\n".join(f"{k}: {v}" for k, v in alert["headers"].items())
    if not host and scope_host and isinstance(alert.get("headers"), dict):
        host = str(alert["headers"].get("Host") or alert["headers"].get("host") or "").strip()
    locations = alert.get("locations") or []

    action = "deny,status:403,log" if action_mode == "deny" else "pass,log"

    # Extract Content-Type & Headers
    req_headers: list[tuple[str, str]] = []
    content_type = ""
    cl_count = 0
    te_count = 0
    unusual_charset = False
    smug_hdr_names: list[str] = []
    for line in req_headers_text.splitlines():
        if ":" not in line:
            continue
        hk, hv = line.split(":", 1)
        hk_c, hv_c = hk.strip(), hv.strip()
        req_headers.append((hk_c, hv_c))
        hkl = hk_c.lower()
        if hkl == "content-type":
            content_type = hv_c.lower()
            if re.search(r"(?i)charset\s*=\s*[\x22\x27]?(?!(?:utf-?8|iso-8859-1|us-ascii)(?:[\x22\x27;\s]|$))[A-Za-z0-9_.-]+", hv_c):
                unusual_charset = True
        elif hkl == "content-length":
            cl_count += 1
        elif hkl == "transfer-encoding":
            te_count += 1
        if re.fullmatch(r"(?i)(?:transfer[_ ]encoding|content[_ ]length)", hk_c) and hk_c.lower() not in ("transfer-encoding", "content-length"):
            smug_hdr_names.append(hk_c)
        elif hk != hk_c and hkl in ("transfer-encoding", "content-length"):
            smug_hdr_names.append(hk.strip())
    has_cl = cl_count > 0
    has_te = te_count > 0

    # Collect structured inputs: (display_label, bare_param_or_None, full_arg_key, modsec_var, raw_value, is_json)
    inputs: list[tuple[str, str | None, str, str, str, bool]] = []
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    dup_params = [k for k, vals in qs.items() if len(vals) > 1 and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k)]
    for k, vals in qs.items():
        mvar = _safe_arg_var(k)
        for v in vals:
            inputs.append((f"Query '{k}'", k, k, mvar, v, False))

    unquoted_path = urllib.parse.unquote(path)
    if unquoted_path and not re.fullmatch(r"[A-Za-z0-9/_.;=-]*", unquoted_path):
        inputs.append(("URI Path", None, "", "REQUEST_URI", unquoted_path, False))

    json_bool_null_fields: list[str] = []
    json_array_fields: list[str] = []
    json_nested_auth_fields: list[str] = []
    json_top_keys: set[str] = set()
    is_json_body = False
    is_xml = False
    is_form_ct = False
    json_ct_spoofed = False
    if req_body:
        stripped = req_body.lstrip("\ufeff \t\r\n")
        is_xml = bool(re.search(r"(?:application|text|image)/(?:[a-z0-9.+-]*\+)?xml\b", content_type)) or stripped.startswith("<")
        has_json_ct = bool(re.search(r"(?:application/(?:[a-z0-9.+-]*\+)?json|text/json)", content_type))
        looks_json = stripped.startswith("{") or stripped.startswith("[")
        is_json_ct = has_json_ct or looks_json
        is_form_ct = "application/x-www-form-urlencoded" in content_type or (
            not content_type
            and not is_xml
            and not is_json_ct
            and "=" in req_body
            and "\n" not in req_body
            and not re.search(r"[\s<>]", req_body.split("=", 1)[0])
        )
        if is_json_ct and not is_xml:
            try:
                jobj = json.loads(req_body.lstrip("\ufeff"))
                is_json_body = True
                json_ct_spoofed = looks_json and not has_json_ct
                if isinstance(jobj, dict):
                    for jk, jv in jobj.items():
                        json_top_keys.add(jk)
                        if jk in qs and jk not in dup_params and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", jk):
                            dup_params.append(jk)
                        if isinstance(jv, list):
                            json_array_fields.append(jk)
                        if isinstance(jv, dict) and jk.lower() in ("username", "user", "email", "password", "passwd", "pwd", "pass", "secret", "token", "pin", "otp", "api_key"):
                            json_nested_auth_fields.append(jk)
                        if (jk.lower() in ("password", "passwd", "pwd", "pass", "token", "secret", "hash", "sig", "hmac") and isinstance(jv, (bool, int, float, list, dict))) or (jk.lower() in ("password", "passwd", "pwd", "pass", "token", "secret", "hash", "sig", "hmac") and jv is None):
                            json_bool_null_fields.append(jk)
                    for flat_k, flat_v in _flatten_json(jobj, "json"):
                        bare = flat_k.split(".")[1] if flat_k.count(".") == 1 else None
                        mvar = _safe_flat_var(flat_k, bare)
                        if json_ct_spoofed and mvar.startswith("ARGS:"):
                            mvar = f"{mvar}|REQUEST_BODY"
                        inputs.append((f"JSON '{flat_k}'", bare, flat_k, mvar, flat_v, True))
                else:
                    inputs.append(("JSON Body", None, "", "REQUEST_BODY", req_body, True))
            except Exception:
                inputs.append(("Request Body", None, "", "REQUEST_BODY", req_body, False))
        elif "multipart/form-data" in content_type:
            pass  # Inspected via dedicated upload rules in section #4 (avoid cmdi/crlf on boundaries)
        elif is_xml:
            inputs.append(("Request Body", None, "", "REQUEST_BODY", req_body, False))
        elif is_form_ct:
            bqs = urllib.parse.parse_qs(req_body, keep_blank_values=True)
            for k, vals in bqs.items():
                if (len(vals) > 1 or k in qs) and k not in dup_params and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k):
                    dup_params.append(k)
                mvar = _safe_arg_var(k)
                for v in vals:
                    inputs.append((f"Body '{k}'", k, k, mvar, v, False))
        else:
            inputs.append(("Request Body", None, "", "REQUEST_BODY", req_body, False))

    origin_null = False
    te_obfuscated = False
    for hk, hv in req_headers:
        hkl = hk.lower()
        if hkl == "origin" and hv.strip().lower() == "null":
            origin_null = True
        if hkl == "transfer-encoding" and not re.match(r"(?i)^(?:chunked|gzip|deflate|compress|br)(?:\s*,\s*(?:chunked|gzip|deflate|compress|br))*$", hv.strip()):
            te_obfuscated = True
        if hkl == "cookie":
            if "=" in hv:
                for seg in hv.split(";"):
                    seg = seg.strip()
                    if not seg or "=" not in seg:
                        continue
                    ck, cv = seg.split("=", 1)
                    ck, cv = ck.strip(), cv.strip()
                    ck_var = f"REQUEST_COOKIES:{ck}" if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", ck) else "REQUEST_COOKIES"
                    inputs.append((f"Cookie '{ck}'", None, hk, ck_var, cv, False))
            else:
                inputs.append((f"Header '{hk}'", None, hk, "REQUEST_COOKIES", hv, False))
        elif hkl in ("user-agent", "referer", "authorization", "x-auth-token", "x-forwarded-for", "x-original-url", "x-rewrite-url", "x-custom-ip-authorization") or hkl.startswith("x-"):
            mvar = f"REQUEST_HEADERS:{hk}" if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", hk) else "REQUEST_HEADERS"
            inputs.append((f"Header '{hk}'", None, hk, mvar, hv, False))

    findings: list[str] = []
    suggestions: list[dict[str, Any]] = []
    next_id = int(base_rule_id)

    def alloc_id() -> int:
        nonlocal next_id
        rid = next_id
        next_id += 1
        return rid

    def add_suggestion(
        key: str,
        title: str,
        desc: str,
        rule: str,
        recommended: bool = True,
        config_type: str = "MODSEC",
    ) -> None:
        suggestions.append({
            "key": key,
            "title": title,
            "description": desc,
            "rule": rule,
            "recommended": recommended,
            "config_type": config_type,
        })

    # 1. HTTP Request Smuggling (CL+TE, CL.CL, TE.TE, obfuscated TE), Charset & Method Hardening
    if has_cl and has_te:
        findings.append("Phát hiện cả Content-Length và Transfer-Encoding cùng lúc (HTTP Smuggling)")
        rid = alloc_id()
        rule = (
            f"# Chặn HTTP Request Smuggling (CL + TE cùng tồn tại)\n"
            f'SecRule &REQUEST_HEADERS:Content-Length "@gt 0" \\\n'
            f'    "id:{rid},phase:1,{action},t:none,chain,\\\n'
            f'    msg:\'HTTP Smuggling CL+TE detected\',tag:\'smuggling\'"\n'
            f'    SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 0" "t:none"'
        )
        add_suggestion("smuggling_cl_te", "Chặn HTTP Smuggling (CL + TE cùng tồn tại)", "0% False Positive theo RFC 7230.", rule, True)

    if cl_count > 1:
        findings.append("Trùng lặp nhiều header Content-Length (HTTP Smuggling CL.CL)")
        rid = alloc_id()
        add_suggestion(
            "smuggling_cl_dup",
            "Chặn trùng header Content-Length (CL.CL)",
            "Ngăn proxy và backend đọc độ dài body khác nhau.",
            f'SecRule &REQUEST_HEADERS:Content-Length "@gt 1" "id:{rid},phase:1,{action},t:none,msg:\'Duplicate Content-Length\',tag:\'smuggling\'"',
            True,
        )

    if te_count > 1:
        findings.append("Trùng lặp nhiều header Transfer-Encoding (HTTP Smuggling TE.TE)")
        rid = alloc_id()
        add_suggestion(
            "smuggling_te_dup",
            "Chặn trùng header Transfer-Encoding (TE.TE)",
            "Ngăn kỹ thuật gửi 2 header Transfer-Encoding khác nhau.",
            f'SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 1" "id:{rid},phase:1,{action},t:none,msg:\'Duplicate Transfer-Encoding\',tag:\'smuggling\'"',
            True,
        )

    if smug_hdr_names or te_obfuscated:
        findings.append("Transfer-Encoding / Content-Length bất thường (nghi HTTP Request Smuggling)")
        rid = alloc_id()
        rule = (
            f"# Chặn biến thể Transfer-Encoding lạ (TE.TE / obfuscated)\n"
            f'SecRule REQUEST_HEADERS:Transfer-Encoding "!@rx (?i)^(?:chunked|gzip|deflate|compress|br)(?:\\s*,\\s*(?:chunked|gzip|deflate|compress|br))*\\z" \\\n'
            f'    "id:{rid},phase:1,{action},t:none,\\\n'
            f'    msg:\'Obfuscated Transfer-Encoding header\',tag:\'smuggling\',logdata:\'TE=%{{MATCHED_VAR}}\'"'
        )
        add_suggestion("smuggling_te_obf", "Chặn Transfer-Encoding obfuscated", "Chặn TE biến thể lạ như chunked1, xchunked.", rule, True)
        rid2 = alloc_id()
        add_suggestion(
            "smuggling_hdr_space",
            "Chặn tên header Content_Length / Transfer_Encoding có dấu gạch dưới/khoảng trắng",
            "Vi phạm RFC 7230, chuyên dùng trong HTTP Request Smuggling.",
            f'SecRule REQUEST_HEADERS_NAMES "@rx (?i)^(?:transfer_encoding|content_length)$|^(?:transfer-encoding|content-length)\\s+$" "id:{rid2},phase:1,{action},t:none,msg:\'Malformed framing header name\',tag:\'smuggling\'"',
            True,
        )

    if unusual_charset or (method in ("POST", "PUT", "PATCH") and (is_json_body or is_form_ct or is_xml)):
        charset_rx = r"(?i)charset\s*=\s*[\x22\x27]?(?!(?:utf-?8|iso-8859-1|us-ascii|windows-125[0-8]|latin-?1)(?:[\x22\x27;\s]|$))[A-Za-z0-9_.-]+"
        if unusual_charset:
            findings.append("Phát hiện Content-Type sử dụng charset lạ (nghi bypass WAF bằng UTF-16/UTF-7/IBM037)")
            rid = alloc_id()
            rule = f'SecRule REQUEST_HEADERS:Content-Type "@rx {charset_rx}" "id:{rid},phase:1,{action},t:none,msg:\'Unusual Content-Type charset\',tag:\'waf-hardening\',logdata:\'%{{MATCHED_VAR}}\'"'
        else:
            rid = alloc_id()
            rule = _build_chained_rule(
                rid, 1, action, "waf-hardening", f"Unusual Content-Type charset on {path}",
                "%{MATCHED_VAR}", "REQUEST_HEADERS:Content-Type", "rx", charset_rx,
                "t:none", route_path=path, host=host,
            )
        add_suggestion(
            "unusual_charset",
            "Chặn Content-Type charset lạ (chống bypass UTF-16/UTF-7/IBM037)",
            "Chỉ cho phép UTF-8 / ISO-8859-1 / US-ASCII trong charset=.",
            rule,
            True,
        )

    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        findings.append(f"HTTP Method bất thường '{method}' (nghi HTTP Verb Tampering)")
        rid = alloc_id()
        add_suggestion(
            "disallowed_method",
            "Chặn HTTP Method lạ ngoài chuẩn REST",
            "Chỉ cho phép GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.",
            f'SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\z" "id:{rid},phase:1,{action},t:none,msg:\'Disallowed HTTP method\',tag:\'waf-hardening\',logdata:\'%{{REQUEST_METHOD}}\'"',
            True,
        )

    if is_json_body:
        if json_ct_spoofed:
            findings.append(f"Giả mạo Content-Type '{content_type or '(trống)'}' cho JSON body (bypass bộ parser JSON của ModSecurity)")
        rid = alloc_id()
        if host:
            ct_rule = (
                f'SecRule REQUEST_HEADERS:Host "@rx {_extract_host_rx(host)}" \\\n'
                f'    "id:{rid},phase:2,{action},t:none,chain,\\\n'
                f'    msg:\'JSON body without application/json Content-Type\',tag:\'waf-hardening\',logdata:\'%{{REQBODY_PROCESSOR}}\'"\n'
                f'    SecRule REQUEST_FILENAME "@rx {_route_rx(path)}" "t:none,t:urlDecodeUni,t:normalizePath,chain"\n'
                f'    SecRule REQUEST_BODY "@rx ^\\s*[\\{{\\[]" "t:none,chain"\n'
                f'    SecRule REQBODY_PROCESSOR "!@streq JSON" "t:none"'
            )
        else:
            ct_rule = (
                f'SecRule REQUEST_FILENAME "@rx {_route_rx(path)}" \\\n'
                f'    "id:{rid},phase:2,{action},t:none,t:urlDecodeUni,t:normalizePath,chain,\\\n'
                f'    msg:\'JSON body without application/json Content-Type\',tag:\'waf-hardening\',logdata:\'%{{REQBODY_PROCESSOR}}\'"\n'
                f'    SecRule REQUEST_BODY "@rx ^\\s*[\\{{\\[]" "t:none,chain"\n'
                f'    SecRule REQBODY_PROCESSOR "!@streq JSON" "t:none"'
            )
        add_suggestion(
            "json_ct_mismatch",
            f"Chống giả mạo Content-Type (text/plain JSON bypass) tại {path}",
            "Chặn gửi JSON body với Content-Type: text/plain khiến ARGS:json.* rỗng.",
            f"# Chặn gửi JSON body mà không khai báo Content-Type: application/json\n{ct_rule}",
            True,
        )

    if origin_null:
        findings.append("CORS Origin: null (nghi khai thác qua sandboxed iframe)")
        rid = alloc_id()
        rule = (
            f"# Chặn Origin: null (CORS bypass qua sandboxed iframe)\n"
            f'SecRule REQUEST_HEADERS:Origin "@rx (?i)^null\\z" \\\n'
            f'    "id:{rid},phase:1,{action},t:none,\\\n'
            f'    msg:\'CORS Null Origin rejected\',tag:\'cors\',logdata:\'Origin=%{{MATCHED_VAR}}\'"'
        )
        add_suggestion("cors_null", "Chặn Origin: null (CORS bypass)", "Kiểm tra bot không gửi Origin: null trước khi bật deny.", rule, False)

    # 1b. GraphQL Batching (Array & Alias), Nesting Depth & Unicode Escapes
    if re.search(r"/(?:graphql|gql)(?:/|$)", path, re.I) and (req_body or "query" in qs):
        gql_raw = req_body or " ".join(qs.get("query", []))
        # Always emit gql_batch rule for all GraphQL endpoints (guards against future batching)
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 2, action, "graphql", "GraphQL array batching blocked",
            "%{REQUEST_URI}", "REQUEST_BODY", "rx", r"^(?:\xef\xbb\xbf)?\s*\[", "t:none",
            route_path=path, host=host,
        )
        if gql_raw.lstrip("\ufeff \t\r\n").startswith("["):
            findings.append("GraphQL Query Batching (mảng JSON [...])")
        add_suggestion("gql_batch", "Chặn GraphQL Array Batching", "Ngăn gộp nhiều query/mutation trong 1 request để bypass rate-limit.", f"# Chặn GraphQL Query Batching\n{rule}", True)
        # Alias batching - fixed pattern that actually closes each sub-selection {field}
        _ALIAS_BATCH_PAT = r"(?:\s*[A-Za-z0-9_]{1,32}\s*:\s*[A-Za-z0-9_]{1,40}\s*\([^)]{0,120}\)\s*\{[^{}]{0,80}\}){5,}"
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 2, action, "graphql", "GraphQL alias batching blocked",
            "%{REQUEST_URI}", "ARGS:query|ARGS:json.query|REQUEST_BODY", "rx",
            _ALIAS_BATCH_PAT,
            "t:none,t:jsDecode", route_path=path, host=host,
        )
        if re.search(_ALIAS_BATCH_PAT, gql_raw):
            findings.append("GraphQL Alias Batching (>= 5 alias trong 1 query)")
        add_suggestion("gql_alias_batch", "Chặn GraphQL Alias Batching", "Ngăn lạm dụng a1:login(...) a2:login(...) trong 1 query.", f"# Chặn GraphQL Alias Batching\n{rule}", True)
        if re.search(r"(?:[^{}]{0,400}\{){7,}", gql_raw):
            findings.append("GraphQL lồng nhau quá sâu (>= 7 tầng)")
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 2, action, "graphql", "GraphQL excessive nesting depth",
            "%{REQUEST_URI}", "ARGS:query|ARGS:json.query|REQUEST_BODY", "rx",
            r"(?:[^{}]{0,400}\{){7,}", "t:none,t:jsDecode",
            route_path=path, host=host,
        )
        add_suggestion("gql_depth", "Chặn GraphQL lồng nhau quá sâu (>= 7 tầng)", "Chống DoS / circular introspection (hỗ trợ cả \\u007b).", f"# Chặn GraphQL nesting depth\n{rule}", True)

    # 1c. Nested JSON object on login/auth fields (e.g. {"password": {"$ne": null}})
    if json_nested_auth_fields:
        findings.append(f"Truyền object JSON lồng vào trường đăng nhập ({', '.join(json_nested_auth_fields)})")
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 2, action, "nosqli", "Nested JSON object on auth field",
            "%{MATCHED_VAR_NAME}", "ARGS_NAMES", "rx",
            r"(?:^|\.)(?:username|user|email|password|passwd|pwd|pass|secret|token|pin|otp|api_key)\.", "t:none",
            route_path=path, host=host,
        )
        add_suggestion("nosqli_nested_auth", f"Chặn object JSON lồng ở trường đăng nhập tại {path}", "Chặn triệt để NoSQLi dạng {\"password\":{\"$ne\":null}}.", f"# Chặn object JSON lồng ở trường đăng nhập\n{rule}", True)

    # 2. Override / Spoofing Headers
    for hk, hv in req_headers:
        if OVERRIDE_HEADER_RE.match(hk):
            findings.append(f"Header giả mạo quyền/đường dẫn '{hk}: {hv}'")
            rid = alloc_id()
            is_proxy_hdr = hk.lower() in ("x-forwarded-host", "x-forwarded-scheme", "x-real-ip")
            rule = (
                f"# Chặn header override {hk}\n"
                f'SecRule REQUEST_HEADERS_NAMES "@rx (?i)^{_escape_rx_literal(hk)}$" \\\n'
                f'    "id:{rid},phase:1,{action},t:none,\\\n'
                f'    msg:\'Blocked override header {hk}\',tag:\'auth-bypass\',logdata:\'%{{MATCHED_VAR_NAME}}\'"'
            )
            add_suggestion(f"hdr_{hk}", f"Chặn header '{hk}'", "Ngăn bypass phân quyền / cache poisoning bằng header giả mạo.", rule, not is_proxy_hdr)

    # 3. Recon / Sensitive Path / Uploaded PHP Execution / URI Traversal
    if UPLOAD_PHP_PATH_RE.match(unquoted_path) or UPLOAD_PHP_PATH_RE.match(path):
        findings.append(f"Truy cập script thực thi trong thư mục upload ({path})")
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 1, action, "upload", f"Block script execution in upload dir ({path})",
            "%{REQUEST_FILENAME}", "REQUEST_FILENAME", "rx",
            r"(?i)^/(?:uploads?|files?|tmp|images?|media|static|avatars?|storage|assets|data|public|attachments?|content)/.*\.(?:php\d?|phtml|phar|pht|jsp|jspx|asp|aspx|py|rb|sh|cgi)\.?(?:;[^/]*)?$",
            "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase", host=host,
        )
        add_suggestion("upload_exec", "Chặn chạy file script trong thư mục upload", "Chuẩn hóa t:urlDecodeUni,t:normalizePath chống //uploads/.. và đuôi ;matrix.", f"# Chặn chạy script trong thư mục upload\n{rule}", True)

    if SENSITIVE_PATH_RE.search(unquoted_path) or SENSITIVE_PATH_RE.search(path):
        findings.append(f"Truy cập đường dẫn/file nhạy cảm ({path})")
        rid = alloc_id()
        rule = (
            f"# Chặn truy cập file nhạy cảm / cấu hình / backup (có chuẩn hóa path)\n"
            f'SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)(?:\\.env(?:\\.|$)|\\.git(?:/|$)|\\.svn(?:/|$)|\\.hg(?:/|$)|\\.ds_store$|\\.ht(?:access|passwd)$|web\\.config$|docker-compose\\.ya?ml$|dockerfile$|id_rsa$|\\.aws/|\\.ssh/|console(?:/|;|\\z)|actuator(?:/|;|\\z))|\\.(?:bak|backup|old|orig|save|swp|swo|sql|sqlite3?)(?:;[^/]*)?\\z" \\\n'
            f'    "id:{rid},phase:1,{action},t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\\\n'
            f'    msg:\'Sensitive file access blocked\',tag:\'recon\',logdata:\'%{{REQUEST_FILENAME}}\'"'
        )
        add_suggestion("recon_path", "Chặn dò file nhạy cảm (.env, .git, .bak, /console)", "Gần như 0% False Positive, chống bypass // hoặc /../ trước đường dẫn.", rule, True)

    decoded_uri = _multi_decode(uri)
    if re.search(r"(?i)(?:\.\.|%2e%2e|%c0%ae|%u002e|%uff0e|\xc0[\xae\x2e])(?:[;/\\]|%2f|%5c|%3b)", uri) or ".." in decoded_uri:
        findings.append(f"Path traversal ngay trong URI ({uri[:60]})")
        rid = alloc_id()
        rule = (
            f"# Chặn Path Traversal trực tiếp trên URI (Phase 1)\n"
            f'SecRule REQUEST_URI "@rx (?i)(?:(?:\\.|%(?:25)?2e|%%32%65|\\xc0[\\xae\\x2e]|%c0%(?:ae|2e)|%(?:u002e|uff0e)){{2,}}(?:[;/\\x5c]|%(?:25)?(?:2f|5c|3b)|\\xc0[\\xaf\\x2f\\x5c]|\\xc1[\\x9c\\x1c]|%c0%af|%c1%9c|%u221[56]|%uff0f|%uff3c)|(?:^|/)\\.\\.\\z)" \\\n'
            f'    "id:{rid},phase:1,{action},t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,\\\n'
            f'    msg:\'Path traversal in URI\',tag:\'lfi\',logdata:\'%{{REQUEST_URI}}\'"'
        )
        add_suggestion("uri_traversal", "Chặn Path Traversal trong URI (Phase 1)", "Bắt cả ..;/, overlong UTF-8, mixed .%2e và %00 null split.", rule, True)

    # 4. Multipart Upload Webshell Content / Script & Double-Extension Filename (NEVER enable SecTmpSaveUploadedFiles!)
    if "multipart/form-data" in content_type:
        if WEBSHELL_BODY_RE.search(req_body) or _PAT_BY_KEY["xxe"].detect_re.search(req_body):
            findings.append("Phát hiện mã thực thi (Webshell / PHAR / XXE) trong Multipart Upload Body")
            rid = alloc_id()
            rule = _build_chained_rule(
                rid, 2, action, "upload", f"Webshell content in multipart upload on {path}",
                "%{REQUEST_URI}", "REQUEST_BODY", "rx",
                r"(?i)(?:<\?(?:php|=|\s+(?:echo|system|exec|passthru|eval|\$))|<script\b|<%[\s=@]|Runtime\.getRuntime|ProcessBuilder|/bin/(?:ba)?sh|GIF89a<\?php|__HALT_COMPILER\s*\(\)|<!ENTITY|<!DOCTYPE[^>]*\[)",
                "t:none,t:removeNulls", route_path=path, host=host,
            )
            add_suggestion(
                "upload_webshell",
                f"Chặn upload nội dung Webshell / PHAR / SVG-XXE tại {path}",
                "Soi thẳng REQUEST_BODY (tuyệt đối KHÔNG bật SecTmpSaveUploadedFiles trên BunkerWeb).",
                f"# Chặn nội dung Webshell trong Multipart Upload (an toàn trên BunkerWeb)\n{rule}",
                True,
            )
        if re.search(r'(?i)filename\*?\s*=\s*[\x22\x27]?(?:UTF-8\x27\x27)?[^\r\n;\x22\x27]{0,120}(?:\.(?:php\d?|phtml|phar|pht|phps|jsp|jspx|asp|aspx|py|rb|sh|cgi|pl|shtml)(?:[.\x22\x27;/\r\n]|%00|$)|\.htaccess|\.user\.ini|web\.config|\.\.[/\x5c])', req_body):
            findings.append("Phát hiện upload tên file thực thi / double-ext / .htaccess / traversal trong Multipart")
            rid = alloc_id()
            rule = _build_chained_rule(
                rid, 2, action, "upload", f"Blocked dangerous script upload filename on {path}",
                "%{MATCHED_VAR}", "FILES", "rx",
                r"(?i)(?:\.(?:php\d?|phtml|phar|pht|phps|jsp|jspx|asp|aspx|py|rb|sh|cgi|pl|shtml)(?:\.[a-z0-9]{1,8}|\.|/|%00)?\z|(?:^|[/\x5c])(?:\.htaccess|\.user\.ini|web\.config)\z|[/\x5c]|\.\.)",
                "t:none,t:urlDecodeUni,t:lowercase", route_path=path, host=host,
            )
            add_suggestion(
                "upload_ext",
                f"Chặn upload tên file thực thi / double-ext (.php.jpg/.phtml/.htaccess) tại {path}",
                "Kiểm tra collection FILES (chống shell.pHp, shell.php.jpg, shell.php., .htaccess, ../shell.php).",
                f"# Chặn tên file thực thi / double-extension khi upload\n{rule}",
                True,
            )

    # 5. XXE Content-Type XML fix (trap id:200000!) + XXE Body Rule
    if re.search(r"(?:application|text|image)/(?:[a-z0-9.+-]*\+)?xml\b", content_type):
        if _PAT_BY_KEY["xxe"].detect_re.search(req_body) or _PAT_BY_KEY["xxe"].detect_re.search(req_body.replace("\x00", "")):
            findings.append("Phát hiện XXE trong XML/SVG body (cần rule Phase 1 ép URLENCODED để vượt bẫy id:200000)")
            rid_p1 = alloc_id()
            rid_p2 = alloc_id()
            rule = (
                f"# BƯỚC 1 (Phase 1): Ép body XML/SVG+xml giữ nguyên text để REQUEST_BODY soi được <!ENTITY\n"
                f"# (Lưu ý: nếu app thật cần CRS XML parser thì comment rule này lại)\n"
                f'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)(?:application|text|image)/(?:[a-z0-9.+-]*\\+)?xml" \\\n'
                f'    "id:{rid_p1},phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"\n\n'
                f"# BƯỚC 2 (Phase 2): Chặn XXE <!ENTITY / <!DOCTYPE / XInclude / SYSTEM\n"
                + _build_chained_rule(
                    rid_p2, 2, action, "xxe", f"XXE attempt on {path}",
                    "%{MATCHED_VAR_NAME}", "REQUEST_BODY", "rx",
                    _PAT_BY_KEY["xxe"].modsec_pattern,
                    _PAT_BY_KEY["xxe"].transforms, route_path=path, host=host,
                )
            )
            add_suggestion("xxe_xml", f"Chặn XXE tại {path} (kèm fix bẫy XML id:200000)", "Hỗ trợ cả +xml/SVG/UTF-16 BOM.", rule, True)

    # 6. Inspect each parameter/input for Attack Signatures + Khuôn 1 Allowlists
    seen_rules: set[tuple[str, str]] = set()
    suggested_allowlist_params: set[str] = set()
    detected_sqli_xss_vars: list[tuple[str, str, str]] = []

    seen_mass_assign = False
    for label, bare_param, full_key, mvar, raw_val, is_json in inputs:
        decoded_val = _multi_decode(raw_val)

        # 6a. Check JWT vulnerabilities
        jwt_issues = _inspect_jwt(raw_val)
        if jwt_issues:
            findings.append(f"Phát hiện tấn công JWT ({', '.join(jwt_issues)}) trong {label}")
            if "alg_none" in jwt_issues:
                # Giải mã header JWT (capture + t:base64DecodeExt) rồi soi "alg":"none" trên JSON
                # thật thay vì đoán cứng vài chuỗi base64 — tránh bị bypass chỉ bằng cách đổi thứ
                # tự key hoặc thêm khoảng trắng trong JSON header (vd {"alg": "none", "typ": "JWT"}).
                rid = alloc_id()
                alg_cap_pat = r"(?:^|\s)(eyJ[A-Za-z0-9_-]{8,})\."
                alg_none_pat = r"(?i)\x22alg\x22\s*:\s*\x22none\x22"
                if host:
                    rule = (
                        f'SecRule REQUEST_HEADERS:Host "@rx {_extract_host_rx(host)}" \\\n'
                        f'    "id:{rid},phase:2,{action},t:none,chain,\\\n'
                        f'    msg:\'JWT alg:none bypass\',tag:\'jwt\',logdata:\'%{{MATCHED_VAR_NAME}}\'"\n'
                        f'    SecRule {mvar} "@rx {alg_cap_pat}" "t:none,capture,chain"\n'
                        f'    SecRule TX:1 "@rx {alg_none_pat}" "t:none,t:base64DecodeExt"'
                    )
                else:
                    rule = (
                        f'SecRule {mvar} "@rx {alg_cap_pat}" \\\n'
                        f'    "id:{rid},phase:2,{action},t:none,capture,chain,\\\n'
                        f'    msg:\'JWT alg:none bypass\',tag:\'jwt\',logdata:\'%{{MATCHED_VAR_NAME}}\'"\n'
                        f'    SecRule TX:1 "@rx {alg_none_pat}" "t:none,t:base64DecodeExt"'
                    )
                add_suggestion(f"jwt_none_{mvar}", "Chặn JWT alg:none", "Tách header JWT (capture TX:1) rồi giải mã Base64URL trước khi soi \"alg\":\"none\" — không bị bypass bằng cách đổi thứ tự key/khoảng trắng trong JSON như cách đoán chuỗi base64 cứng trước đây.", f"# Chặn JWT alg:none\n{rule}", True)
            if "empty_sig" in jwt_issues:
                rid = alloc_id()
                rule = _build_chained_rule(
                    rid, 2, action, "jwt", "JWT empty signature segment", "%{MATCHED_VAR_NAME}",
                    mvar, "rx",
                    r"(?:^|Bearer\s+)eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.(?:\s*$)",
                    "t:none", host=host,
                )
                add_suggestion(f"jwt_empty_{mvar}", "Chặn JWT rỗng phần chữ ký (header.payload.)", "Chặn token bỏ trống phần chữ ký dù alg không ghi none.", f"# Chặn JWT empty signature\n{rule}", True)
            if "jku_x5u" in jwt_issues or "kid_inj" in jwt_issues:
                rid = alloc_id()
                hdr_pat = r"(?i)(?:\x22(?:jku|x5u|jwk|x5c)\x22\s*:|\x22kid\x22\s*:\s*\x22[^\x22]{0,120}(?:\.\.|/|\x5c|\x27|--|;|\||`|\$\())"
                cap_pat = r"(?:^|\s)(eyJ[A-Za-z0-9_-]{8,})\."
                if host:
                    rule = (
                        f'SecRule REQUEST_HEADERS:Host "@rx {_extract_host_rx(host)}" \\\n'
                        f'    "id:{rid},phase:2,{action},t:none,chain,\\\n'
                        f'    msg:\'JWT jku/x5u/kid injection\',tag:\'jwt\',logdata:\'%{{MATCHED_VAR_NAME}}\'"\n'
                        f'    SecRule {mvar} "@rx {cap_pat}" "t:none,capture,chain"\n'
                        f'    SecRule TX:1 "@rx {hdr_pat}" "t:none,t:base64DecodeExt"'
                    )
                else:
                    rule = (
                        f'SecRule {mvar} "@rx {cap_pat}" \\\n'
                        f'    "id:{rid},phase:2,{action},t:none,capture,chain,\\\n'
                        f'    msg:\'JWT jku/x5u/kid injection\',tag:\'jwt\',logdata:\'%{{MATCHED_VAR_NAME}}\'"\n'
                        f'    SecRule TX:1 "@rx {hdr_pat}" "t:none,t:base64DecodeExt"'
                    )
                add_suggestion(f"jwt_hdr_{mvar}", "Chặn JWT jku/x5u/kid injection", "Tách header JWT (capture TX:1) rồi giải mã Base64URL bằng t:base64DecodeExt.", f"# Chặn JWT header injection (jku/x5u/kid)\n{rule}", True)

        # 6a-bis. Check Base64-encoded Deserialization (text & binary Pickle/Java) or SAML XXE
        b64_candidates: list[tuple[str, str]] = []
        seen_cands: set[str] = set()
        for cand_src in (urllib.parse.unquote(raw_val.strip()), decoded_val.strip(), raw_val.strip(), raw_val.strip().replace(" ", "+")):
            if cand_src and cand_src not in seen_cands and re.fullmatch(r"[A-Za-z0-9+/_-]{16,}={0,2}", cand_src):
                seen_cands.add(cand_src)
                b64_candidates.append((mvar, cand_src))
        for cand_mvar, cand in b64_candidates:
            try:
                padded = cand + "=" * ((4 - len(cand) % 4) % 4)
                b64_raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"))
                b64_dec = b64_raw.decode("utf-8", errors="ignore")
            except Exception:
                b64_raw = b""
                b64_dec = ""
            if b64_raw:
                is_bin_deser = (
                    b"\xac\xed\x00\x05" in b64_raw
                    or bool(re.search(rb"^\x80[\x02-\x05]", b64_raw))
                    or bool(re.search(rb"(?:^|[\r\n])c(?:posix|os|nt|subprocess|builtins|__builtin__)[\r\n]", b64_raw))
                )
                is_txt_deser = bool(b64_dec and re.search(r'(?:[OCSE]:\+?\d{1,4}:"|\ba:\d+:\{(?:[isbadNO]:|[rR]:)|!!python/|__wakeup|__destruct|__HALT_COMPILER)', b64_dec))
                if is_bin_deser or is_txt_deser:
                    findings.append(f"Phát hiện Deserialization mã hóa Base64 trong {label}")
                    rid = alloc_id()
                    rule = _build_chained_rule(
                        rid, 2, action, "deserialization", f"Base64 deserialization in {label}",
                        "%{MATCHED_VAR_NAME}", cand_mvar, "rx",
                        r"(?:\xac\xed\x00\x05|^\x80[\x02-\x05]|(?i:(?:[OCSE]:\+?\d{1,4}:\x22[A-Za-z_\\][A-Za-z0-9_\\]{0,80}\x22:\d{1,4}:\{|\ba:\d+:\{(?:[isbadNO]:|[rR]:)|__wakeup|__destruct|__HALT_COMPILER|!!python/|c(?:posix|os|nt|subprocess|builtins|__builtin__)[\r\n])))",
                        "t:none,t:base64DecodeExt", route_path=path, host=host,
                    )
                    add_suggestion(f"b64_deser_{cand_mvar}", f"Chặn Deserialization (t:base64DecodeExt) ở {cand_mvar}", "Giải mã Base64 ở Cookie/Tham số (giữ dấu '+', bắt cả PHP/Java/Pickle proto 0-5).", f"# Chặn Deserialization mã hóa Base64\n{rule}", True)
                    break
                if (bare_param or "").lower() in ("samlresponse", "samlrequest") and b64_dec and re.search(r"(?i)<!\s*(?:DOCTYPE|ENTITY)\b", b64_dec):
                    findings.append(f"Phát hiện SAML XXE trong {label}")
                    rid = alloc_id()
                    rule = _build_chained_rule(
                        rid, 2, action, "xxe", f"SAML XXE in {label}",
                        "%{MATCHED_VAR_NAME}", cand_mvar, "rx",
                        r"(?i)<!\s*(?:DOCTYPE|ENTITY)\b",
                        "t:none,t:base64DecodeExt", route_path=path, host=host,
                    )
                    add_suggestion(f"saml_xxe_{cand_mvar}", f"Chặn SAML XXE ở {label}", "Giải mã Base64 SAML payload (giữ nguyên '+') để bắt DOCTYPE/ENTITY.", f"# Chặn SAML XXE\n{rule}", True)
                    break

        # 6a-ter. Argument / Option Injection (leading '-' or dangerous CLI flags on file/host/url/repo params)
        if bare_param and bare_param.lower() in ("file", "filename", "path", "host", "ip", "domain", "target", "url", "src", "dst", "dest", "repo", "branch", "archive", "out", "input", "img", "doc", "cmd", "opt", "args"):
            dv_strip = decoded_val.lstrip()
            if dv_strip.startswith("-") or re.search(r"(?i)(?:^|\s)--(?:checkpoint-action|exec|eval|upload-pack|receive-pack|config|output|post-data|proxy)\b|\s-[a-z]*e\s+", decoded_val):
                findings.append(f"Nghi Argument/Option Injection ('-...' / '--flag') ở {label}")
                rid = alloc_id()
                rule = _build_chained_rule(
                    rid, 2, action, "cmdi", f"Argument injection flag on {bare_param}",
                    "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", mvar, "rx",
                    r"(?i)(?:^\s*-|\s--(?:checkpoint-action|exec|eval|upload-pack|receive-pack|config|output|post-data|proxy)\b|\s-[a-z]*e\s+)",
                    "t:none,t:urlDecodeUni,t:urlDecodeUni", route_path=path, host=host,
                )
                add_suggestion(f"arg_inj_{bare_param}", f"Chặn Argument Injection ('-...' / '--...') ở '{bare_param}'", "Ngăn truyền cờ --option / -e vào lệnh hệ thống (tar, curl, git...).", f"# Chặn Argument Injection\n{rule}", True)

        # 6b. Check PHP Type Juggling array params (e.g., password[]=x)
        if bare_param and "[" in bare_param:
            base_k = bare_param.split("[", 1)[0]
            if base_k.lower() in ("username", "user", "email", "password", "passwd", "pwd", "pass", "token", "secret", "otp", "pin", "code", "hash", "sig", "hmac"):
                findings.append(f"PHP Type Juggling dạng mảng '{bare_param}'")
                rid = alloc_id()
                rule = _build_chained_rule(
                    rid, 2, action, "type-juggling", f"PHP array param {base_k}[] blocked",
                    "%{MATCHED_VAR_NAME}", "ARGS_NAMES", "rx",
                    rf"(?i)^{_escape_rx_literal(base_k)}\[", "t:none", route_path=path, host=host,
                )
                add_suggestion(f"tj_arr_{base_k}", f"Chặn PHP array parameter '{base_k}[]'", "Chặn bypass so sánh chuỗi PHP bằng mảng.", f"# Chặn PHP Type Juggling {base_k}[]\n{rule}", True)

        # 6c. Check Mass Assignment privileged fields
        if full_key and not seen_mass_assign and PRIVILEGED_FIELD_RE.search(full_key):
            seen_mass_assign = True
            findings.append(f"Nghi Mass Assignment qua trường đặc quyền '{full_key}' tại {path}")
            rid = alloc_id()
            rule = _build_chained_rule(
                rid, 2, action, "mass-assignment", f"Blocked privileged field on {path}",
                "%{MATCHED_VAR_NAME}", "ARGS_NAMES", "rx",
                r"(?i)(?:^|[.\[])(?:role|roles|is_?admin|admin|balance|credit|credits|permissions?|user_id|owner_id|verified|email_verified|is_?staff|is_?superuser)(?:\]|\.array_\d+|$)",
                "t:none", route_path=path, host=host,
            )
            add_suggestion("mass_assign", f"Khuôn 3: Chặn Mass Assignment tại {path}", "Bắt cả field thường, user[role], json.role và json.role.array_0. (Chỉ bật nếu route này không phải trang Admin).", f"# Khuôn 3: Chặn Mass Assignment\n{rule}", True)

        # 6c-bis. Check Open Redirect & RFI on redirect / file params
        if bare_param and REDIRECT_PARAM_RE.match(bare_param):
            dec_redir = _multi_decode(raw_val).strip()
            if re.match(r"(?i)^(?:https?:|//+|/[\\\x5c]|\\+|(?:java|vb)script:|data:|[^/?#\s]+@)", dec_redir) or "%2f@" in raw_val.lower() or "%5c@" in raw_val.lower():
                sig_id = ("open_redirect", mvar)
                if sig_id not in seen_rules:
                    seen_rules.add(sig_id)
                    findings.append(f"Phát hiện Open Redirect / OAuth URI bypass trong {label} tại {path}")
                    rid = alloc_id()
                    rule = _build_chained_rule(
                        rid, 2, action, "open-redirect", f"Open Redirect on {path} ({label})",
                        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", mvar, "rx",
                        r"(?i)(?:^\s*(?:https?:|//+|/\x5c|\x5c+|(?:java|vb)script:|data:)|^[^/?#\s]+:[^/?#\s]*@|\.\.[/\x5c])",
                        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:removeWhitespace,t:lowercase",
                        route_path=path, host=host,
                    )
                    add_suggestion(f"sig_open_redirect_{mvar}", f"Chặn Open Redirect ở {label} ({path})", "Chặn https://, //, /\\, userinfo @ và path traversal trong tham số redirect.", f"# Open Redirect tại {path}\n{rule}", True)
        if bare_param and bare_param.lower() in ("file", "filename", "page", "path", "template", "include", "load", "view", "doc"):
            if re.match(r"(?i)^(?:https?|ftp)://|^//|^\x5c\x5c", decoded_val.strip()):
                sig_id = ("rfi", mvar)
                if sig_id not in seen_rules:
                    seen_rules.add(sig_id)
                    findings.append(f"Phát hiện Remote File Inclusion (RFI) trong {label} tại {path}")
                    rid = alloc_id()
                    rule = _build_chained_rule(
                        rid, 2, action, "rfi", f"RFI remote URL in file param on {path}",
                        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", mvar, "rx",
                        r"(?i)^\s*(?:https?://|ftp://|//|\x5c\x5c)",
                        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:lowercase",
                        route_path=path, host=host,
                    )
                    add_suggestion(f"sig_rfi_{mvar}", f"Chặn Remote File Inclusion (RFI) ở {label}", "Ngăn truyền URL từ xa vào tham số đọc/include file.", f"# RFI tại {path}\n{rule}", True)

        # 6d. Match Attack Patterns across normalized variants (anti-obfuscation)
        val_variants = _value_variants(raw_val)
        name_variants = _value_variants(full_key) if full_key else []
        for pat in ATTACK_PATTERNS:
            if pat.key == "xxe" and re.search(r"(?:application|text|image)/(?:[a-z0-9.+-]*\+)?xml\b", content_type):
                continue  # already handled with Phase 1 XML fix above
            if mvar == "REQUEST_BODY" and pat.key in ("crlf", "cmdi"):
                continue  # raw multiline/XML/JSON bodies naturally contain \n and ; (&lt;)
            if mvar == "REQUEST_URI" and pat.key in ("lfi", "crlf", "cmdi"):
                continue  # path traversal already handled in Phase 1 uri_traversal
            if pat.target_mode == "name":
                matched_input = any(pat.detect_re.search(nv) for nv in name_variants)
            else:
                matched_input = any(pat.detect_re.search(vv) for vv in val_variants)
            if not matched_input and pat.key == "hash_len_ext" and full_key:
                # qs/bqs (urllib.parse.parse_qs) đã url-decode raw_val trước khi tới đây, nên
                # %80%00... bị mất (byte 0x80 đứng lẻ không phải UTF-8 hợp lệ -> unquote thay
                # bằng U+FFFD) và không còn khớp regex literal %-encoded nữa. Soi lại đúng
                # substring "<key>=<value>" trên query-string/body THÔ (chưa decode) để không bỏ
                # lọt kỹ thuật Hash Length Extension gửi qua query/form param.
                raw_source = parsed.query if label.startswith("Query") else (req_body if label.startswith("Body") else "")
                if raw_source:
                    m = re.search(rf"(?:^|&){re.escape(full_key)}=([^&]*)", raw_source)
                    if m and pat.detect_re.search(m.group(1)):
                        matched_input = True
            if matched_input:
                sig_id = (pat.key, mvar)
                if sig_id in seen_rules:
                    continue
                seen_rules.add(sig_id)
                findings.append(f"Phát hiện {pat.name} trong {label} tại {path}")
                rid = alloc_id()
                cvar = "ARGS_NAMES|REQUEST_BODY" if pat.target_mode == "name" else mvar
                rule = _build_chained_rule(
                    rid, pat.phase, action, pat.tag,
                    f"Block {pat.name} on {path} ({label})",
                    "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                    cvar, pat.modsec_op, pat.modsec_pattern, pat.transforms,
                    route_path=path, host=host,
                )
                add_suggestion(
                    f"sig_{pat.key}_{mvar}",
                    f"Chặn {pat.name} ở {label} ({path})",
                    pat.note or f"Khóa chặt tại route {path} và biến {cvar} để tối ưu CPU và tránh False Positive.",
                    f"# {pat.name} tại {path} ({label})\n{rule}",
                    True,
                )
                # Companion anti-bypass rules so attackers cannot mutate technique on the same parameter!
                if pat.tag == "sqli" and ("sqli_split", mvar) not in seen_rules:
                    seen_rules.add(("sqli_split", mvar))
                    rid_c1 = alloc_id()
                    split_pat = (
                        r"(?:(?:^|\b|\d[eE]\d*|\d\.e|\W)union[\s(]*(?:all[\s(]*|distinct[\s(]*)?select(?:\b|[\s(/*])"
                        r"|\bselect\s*(?:distinct\s*)?(?:\*|[\w.`()]+\s*,\s*[\w.`()]+|[a-z_]+\s*\()[^;]{0,120}\bfrom\s+[a-z_][a-z0-9_.$]{0,64}\s*(?:where|limit|order|group|having|union|\)|\z)"
                        r"|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file|randomblob)\s*\()"
                    )
                    r_split = _build_chained_rule(
                        rid_c1, 2, action, "sqli",
                        f"SQLi split-comment bypass on {path} ({label})",
                        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                        mvar, "rx", split_pat,
                        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:removeComments,t:compressWhitespace,t:lowercase",
                        route_path=path, host=host,
                    )
                    add_suggestion(f"sqli_split_{mvar}", f"Chống SQLi chèn comment chia từ (UN/**/ION SE/**/LECT) ở {label}", "Dùng t:removeComments để bắt cả UN/**/ION và SE/**/LECT.", f"# Chống SQLi tách từ bằng comment /**/\n{r_split}", True)

                    rid_c2 = alloc_id()
                    r_cmt = _build_chained_rule(
                        rid_c2, 2, action, "sqli",
                        f"SQLi comment-space bypass on {path} ({label})",
                        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                        mvar, "rx", _SQLI_AUTH_RX + "|" + _SQLI_KW_RX.removeprefix("(?i)"),
                        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:replaceComments,t:compressWhitespace,t:lowercase",
                        route_path=path, host=host,
                    )
                    add_suggestion(f"sqli_cmt_{mvar}", f"Chống SQLi chèn comment thay khoảng trắng ('/**/OR/**/1=1) ở {label}", "Dùng t:replaceComments để đưa /*...*/ về khoảng trắng.", f"# Chống SQLi chèn comment thay khoảng trắng\n{r_cmt}", True)

                if pat.key == "cmdi" and ("cmdi_cmdline", mvar) not in seen_rules:
                    seen_rules.add(("cmdi_cmdline", mvar))
                    rid_cmd = alloc_id()
                    cmdline_pat = (
                        r"(?:/?(?:usr/(?:local/)?)?(?:s?bin/)?(?:ba|da|z|k|c)?sh\s+-[ic]"
                        r"|/(?:usr/)?s?bin/(?:cat|tac|head|tail|nl|base64|xxd|od|python\d?|perl|ruby|php|nc|ncat|socat|curl|wget|id|whoami|uname|env|printenv|awk|sed|grep|find)"
                        r"|(?:cat|tac|head|tail|nl|more|less|base64|xxd|od|strings|grep|awk|sed)\s+(?:/etc/|/proc/|/var/|/home/|/root/|/app/|/flag|flag\.txt|\$[a-z_{])"
                        r"|(?:whoami|uname\s+-a|printenv\b|curl\s+https?://|wget\s+https?://|nc\s+-[elvp]|powershell\s+-))"
                    )
                    r_cmd = _build_chained_rule(
                        rid_cmd, 2, action, "cmdi",
                        f"CMDi obfuscated command (t:cmdLine) on {path} ({label})",
                        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                        mvar, "rx", cmdline_pat,
                        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:cmdLine",
                        route_path=path, host=host,
                    )
                    add_suggestion(f"cmdi_cmdline_{mvar}", f"Chống CMDi nhồi nháy/gạch chéo (c'a't, c\\at, c^at) ở {label}", "Dùng t:cmdLine với ngưỡng path/lệnh an toàn, 0% FP với O'Brien.", f"# Chống CMDi chèn quote/backslash/caret\n{r_cmd}", True)

                if pat.key == "xss" and ("xss_scheme", mvar) not in seen_rules:
                    seen_rules.add(("xss_scheme", mvar))
                    rid_xs = alloc_id()
                    r_xs = _build_chained_rule(
                        rid_xs, 2, action, "xss",
                        f"XSS obfuscated URI scheme on {path} ({label})",
                        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                        mvar, "rx", r"(?:javascript:|vbscript:|data:(?:text/html|image/svg\+xml|application/xhtml\+xml))",
                        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeWhitespace,t:lowercase",
                        route_path=path, host=host,
                    )
                    add_suggestion(f"xss_scheme_{mvar}", f"Chống XSS chèn tab/newline/entity vào URI scheme (java&#x09;script:) ở {label}", "Dùng t:removeWhitespace trên URI scheme nguy hiểm.", f"# Chống XSS ngắt scheme bằng tab/newline\n{r_xs}", True)

                if pat.tag == "sqli":
                    detected_sqli_xss_vars.append(("sqli", label, mvar))
                elif pat.tag == "xss":
                    detected_sqli_xss_vars.append(("xss", label, mvar))

        # 6e. Khuôn 1 Allowlist suggestion when param name matches typed pattern (or *_id heuristic)
        if bare_param and bare_param not in suggested_allowlist_params:
            bkl = bare_param.lower()
            matched_tpl = None
            for tpl in ALLOWLIST_TEMPLATES:
                if bkl in tpl["param_hints"]:
                    matched_tpl = tpl
                    break
            is_inferred_id = False
            if not matched_tpl and (bkl.endswith("_id") or (bkl.endswith("id") and len(bkl) >= 4 and bkl not in ("valid", "invalid", "android", "uuid", "guid", "ssid", "kid", "gid"))):
                matched_tpl = ALLOWLIST_TEMPLATES[0]  # int template
                is_inferred_id = True
            if matched_tpl:
                suggested_allowlist_params.add(bare_param)
                rid = alloc_id()
                rule = _build_chained_rule(
                    rid, 2, action, "allowlist",
                    f"Invalid {bare_param} on {path}",
                    "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                    _safe_arg_var(bare_param),
                    "rx", matched_tpl["regex"], matched_tpl["transforms"],
                    route_path=path, host=host, negate_op=True,
                )
                rec = (not is_inferred_id) and matched_tpl["key"] in ("int", "uuid", "locale", "host")
                add_suggestion(
                    f"allow_{bare_param}",
                    f"Khuôn 1 (Allowlist): Ép '{bare_param}' theo chuẩn {matched_tpl['label']} tại {path}",
                    f"{matched_tpl['desc']} (Xác nhận bot chấm cũng gửi đúng định dạng này trước khi bật deny!).",
                    f"# Khuôn 1: Allowlist chặt cho '{bare_param}' tại {path}\n{rule}",
                    rec,
                )

    # 6f. Khuôn 2 (@detectSQLi / @detectXSS via C libinjection) as fast/low-FP alternative
    for kind, label, mvar in detected_sqli_xss_vars[:3]:
        rid = alloc_id()
        if kind == "sqli":
            rule = _build_chained_rule(
                rid, 2, action, "sqli", f"libinjection SQLi on {path} ({label})",
                "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                mvar, "detectSQLi", "", "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls",
                route_path=path, host=host,
            )
            add_suggestion(f"libinj_sqli_{mvar}", f"Khuôn 2: @detectSQLi (libinjection C) cho {label}", "Cực nhanh trên 2 CPU, hỗ trợ tốt cho ô tìm kiếm/text tự do.", f"# Khuôn 2: libinjection SQLi tại {path}\n{rule}", False)
        else:
            rule = _build_chained_rule(
                rid, 2, action, "xss", f"libinjection XSS on {path} ({label})",
                "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}",
                mvar, "detectXSS", "", "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:htmlEntityDecode,t:jsDecode",
                route_path=path, host=host,
            )
            add_suggestion(f"libinj_xss_{mvar}", f"Khuôn 2: @detectXSS (libinjection C) cho {label}", "Cực nhanh trên 2 CPU, phù hợp ô comment/bài viết.", f"# Khuôn 2: libinjection XSS tại {path}\n{rule}", False)

    # 7. JSON bool/null type juggling (with t:jsDecode & scientific notation)
    for jf in json_bool_null_fields:
        findings.append(f"PHP Type Juggling: trường JSON '{jf}' truyền bool/null/number thay vì chuỗi")
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 2, action, "type-juggling", f"JSON non-string {jf} blocked",
            "%{MATCHED_VAR_NAME}", "REQUEST_BODY", "rx",
            rf'(?i)\x22{_escape_rx_literal(jf)}\x22\s*:\s*(?:true|false|null|\[|\{{|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?:\s*[,}}]))',
            "t:none,t:jsDecode", route_path=path, host=host,
        )
        add_suggestion(f"tj_json_{jf}", f"Chặn JSON Type Juggling cho '{jf}'", "Bắt lỗi truyền true/null/số (kể cả 1e0, \\u0070assword) vào mật khẩu/token JSON.", f"# Chặn JSON Type Juggling\n{rule}", True)

    # 8. HPP / JSON Array / CSRF Guards
    for dp in dup_params[:2]:
        rid = alloc_id()
        rule = (
            f"# Guard HPP: Chặn trùng tham số '{dp}' tại {path}\n"
            f'SecRule REQUEST_FILENAME "@rx {_route_rx(path)}" \\\n'
            f'    "id:{rid},phase:2,{action},t:none,t:urlDecodeUni,t:normalizePath,chain,\\\n'
            f'    msg:\'Duplicate param {dp}\',tag:\'hpp\',logdata:\'count=%{{MATCHED_VAR}}\'"\n'
            f'    SecRule &ARGS:{dp} "@gt 1" "t:none"'
        )
        hpp_rec = dp.lower() not in ("tags", "ids", "items", "categories", "filters", "columns", "fields", "selected", "options", "choices", "roles") and not dp.endswith("[]")
        add_suggestion(f"hpp_dup_{dp}", f"Guard HPP: Chặn gửi trùng '?{dp}=...&{dp}=...' (hoặc query+body)", "Bật nếu app không cố ý nhận nhiều giá trị cho param này.", rule, hpp_rec)

    for af in json_array_fields[:2]:
        rid = alloc_id()
        rule = _build_chained_rule(
            rid, 2, action, "hpp", f"JSON array not allowed for {af}",
            "%{MATCHED_VAR_NAME}", "ARGS_NAMES", "rx",
            rf"^json\.{_escape_rx_literal(af)}\.array_[0-9]+$",
            "t:none", route_path=path, host=host,
        )
        add_suggestion(f"hpp_jarr_{af}", f"Guard JSON Array: Chặn mảng cho '{af}'", "Ngăn bypass bằng {\"id\":[1,2]} -> json.id.array_0.", f"# Guard JSON Array\n{rule}", False)

    if method in ("POST", "PUT", "PATCH", "DELETE"):
        rid = alloc_id()
        csrf_rule = _build_chained_rule(
            rid, 1, action, "csrf", f"Cross-site state-changing request on {path}",
            "Sec-Fetch-Site=%{MATCHED_VAR}", "REQUEST_HEADERS:Sec-Fetch-Site", "streq", "cross-site", "t:none",
            route_path=path, host=host,
        )
        add_suggestion("csrf_sec_fetch", f"Guard CSRF (Sec-Fetch-Site: cross-site) tại {path}", "Chặn browser cross-site CSRF (bot Python/Go không gửi header này nên an toàn với SVC).", f"# Guard CSRF Sec-Fetch-Site\n{csrf_rule}", False)

    # 9. Response-Level Leak Mitigations (Header SERVER_HTTP + Phase 4 Khuôn 5)
    for loc in locations:
        if loc.startswith("Header: "):
            hdr_name = loc.split(": ", 1)[1].strip()
            findings.append(f"Lộ flag qua Response Header '{hdr_name}' (nên ẩn bằng NGINX SERVER_HTTP để không làm lỗi bot!)")
            nginx_cfg = f"# Đặt trong BunkerWeb: Configs -> New -> Config Type: SERVER_HTTP\nproxy_hide_header {hdr_name};"
            add_suggestion(
                f"nginx_hide_{hdr_name}",
                f"NGINX SERVER_HTTP: Ẩn header '{hdr_name}' (Khuyên dùng, 0% rớt SVC)",
                "Xóa header lộ flag mà vẫn giữ nguyên HTTP 200/302/cookie cho bot chấm hoạt động bình thường!",
                nginx_cfg,
                True,
                config_type="SERVER_HTTP",
            )
            rid = alloc_id()
            rh_var = f"RESPONSE_HEADERS:{hdr_name}" if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", hdr_name) else "RESPONSE_HEADERS"
            rule = (
                f"# Hoặc chặn cứng ở Phase 3 (lưu ý: có thể cắt cả request hợp lệ nếu header luôn gắn kèm response!)\n"
                f'SecRule {rh_var} "@rx {flag_pattern}" \\\n'
                f'    "id:{rid},phase:3,{action},t:none,\\\n'
                f'    msg:\'Flag leak in {_escape_modsec_msg(hdr_name)} header\',tag:\'flag-leak\'"'
            )
            add_suggestion(f"phase3_{hdr_name}", f"ModSec Phase 3: Chặn response chứa flag ở Header '{hdr_name}'", "Chỉ dùng nếu header này chỉ xuất hiện khi bị exploit.", rule, False)

    if "Response Body" in locations:
        findings.append(f"Lộ flag trong Response Body từ {path}")
        # Note: Khuôn 5 ALWAYS warns about excluding the legitimate flag route
        is_no_req_sig = len(seen_rules) == 0 and not UPLOAD_PHP_PATH_RE.match(path) and not SENSITIVE_PATH_RE.search(path)
        legit_routes = [r.strip() for r in (legit_flag_routes or []) if r.strip()]
        if legit_routes:
            rid = alloc_id()
            exclude_rx = _routes_exclude_rx(legit_routes)
            rule = (
                f"# Khuôn 5 (Phase 4): Lưới cuối chặn lộ Flag ở NGOÀI route cờ hợp lệ\n"
                f"# Route loại trừ (đã bạn xác nhận là route THẬT phục vụ cờ): {', '.join(legit_routes)}\n"
                f"# Lưu ý: Phase 4 chạy sau khi gửi header nên sẽ cắt kết nối TCP; luôn test pass,log trước.\n"
                f'SecRule REQUEST_FILENAME "!@rx {exclude_rx}" \\\n'
                f'    "id:{rid},phase:4,pass,log,t:none,t:normalizePath,chain,\\\n'
                f'    msg:\'FLAG leak detected outside flag route\',tag:\'flag-leak\',logdata:\'%{{REQUEST_METHOD}} %{{REQUEST_URI}}\'"\n'
                f'    SecRule RESPONSE_BODY "@rx {flag_pattern}" "t:none"'
            )
            add_suggestion("phase4_flag", "Khuôn 5 (Phase 4): Lưới cuối chặn lọt Flag ngoài route hợp lệ", "Luôn để pass,log trước 1 chu kỳ 30s. Route loại trừ lấy đúng từ danh sách bạn xác nhận, không phải đoán.", rule, is_no_req_sig)
        else:
            findings.append(
                "⚠️ CHƯA sinh rule Phase 4 Flag DLP: phải tự xác nhận (các) route THẬT phục vụ cờ cho bot SVC "
                "trước (truyền qua legit_flag_routes) — có thể KHÔNG có route riêng (flag lộ ngay trong tính "
                "năng bình thường, vd app ghi chú). Sinh rule với route đoán mò có thể tự chặn đúng response "
                "hợp lệ cho bot chấm, vi phạm Điều 3.5 Quy chế (cấm chặn API phục vụ cờ) và bị trừ SVC gấp đôi."
            )

    if not findings:
        findings.append(f"Không phát hiện chữ ký payload rõ ràng trong {method} {path} (có thể là IDOR / Broken Access Control — nên kiểm tra Allowlist tham số hoặc vá trong code).")

    return {
        "findings": list(dict.fromkeys(findings)),
        "suggestions": suggestions,
        "meta": {"method": method, "path": path, "host": alert.get("host") or ""},
    }


# ═══════════════════════════════════════════════════════════════════════
# OFFLINE MODSECURITY V3 SYNTAX, REDOS, FP & MATCH VALIDATOR
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ParsedRule:
    raw: str
    rule_id: str = ""
    phase: str = ""
    variables: list[str] = field(default_factory=list)
    operator: str = ""
    negated: bool = False
    pattern: str = ""
    transforms: list[str] = field(default_factory=list)
    msg: str = ""
    tag: str = ""
    action: str = ""
    chain_children: list["ParsedRule"] = field(default_factory=list)


def _parse_single_rule(line: str) -> ParsedRule:
    r = ParsedRule(raw=line)
    var_m = re.match(r"SecRule\s+(\S+)\s+", line, re.I)
    if var_m:
        r.variables = var_m.group(1).split("|")
    op_m = re.search(r'"(!?)@(\w+)(?:\s+((?:[^"\\]|\\.)*))?"', line)
    if op_m:
        r.negated = op_m.group(1) == "!"
        r.operator = op_m.group(2).lower()
        r.pattern = op_m.group(3) or ""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
    if parts:
        act = parts[-1]
        id_m = re.search(r"\bid:(\d+)", act)
        ph_m = re.search(r"\bphase:(\d+)", act)
        msg_m = re.search(r"\bmsg:'([^']*)'", act)
        tag_m = re.search(r"\btag:'([^']*)'", act)
        act_m = re.search(r"\b(deny|pass|block|drop|allow)\b", act)
        r.rule_id = id_m.group(1) if id_m else ""
        r.phase = ph_m.group(1) if ph_m else ""
        r.msg = msg_m.group(1) if msg_m else ""
        r.tag = tag_m.group(1) if tag_m else ""
        r.action = act_m.group(1) if act_m else ""
        r.transforms = re.findall(r"\bt:([A-Za-z0-9_]+)", act)
    return r


def _has_chain_action(line: str) -> bool:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
    if not parts:
        return False
    act = re.sub(r"'[^']*'", "", parts[-1])
    return bool(re.search(r"(?:^|,)\s*chain\s*(?:,|$)", act, re.I))


def generate_baseline_ruleset(action_mode: str = "pass", base_rule_id: int = 28000) -> dict[str, Any]:
    """
    Sinh bộ rule NỀN TẢNG (route-agnostic): không khoá theo REQUEST_FILENAME/Host
    cụ thể như generate_waf_rules (vốn phân tích 1 alert/route đã biết), mà áp
    dụng chữ ký tấn công đã kiểm chứng (ATTACK_PATTERNS + companion anti-mutation)
    lên TOÀN BỘ request đi qua WAF. Dùng để add vào BunkerWeb NGAY TỪ ĐẦU GIẢI lúc
    còn ở chế độ DetectionOnly, trước khi biết app thật của BTC là gì.

    KHÔNG gồm (cần biết route/tham số thật của app, chỉ thêm SAU khi đã biết):
    - Allowlist Khuôn 1 (ép định dạng tham số cụ thể như id/sort/locale)
    - Guard HPP / JSON Array theo tên tham số
    - Phase 3/4 Flag DLP (cần xác nhận route cờ thật qua generate_waf_rules(...,
      legit_flag_routes=[...]) — KHÔNG được đoán, xem HANDOVER.md mục 5.1)
    - GraphQL Array Batching (REQUEST_BODY bắt đầu bằng "[" quá rộng, trùng với
      API bulk-import hợp lệ) — chỉ thêm khi đã xác nhận đúng route /graphql

    Luôn mặc định action_mode="pass" (chỉ ghi log) — đây là bộ rule để QUAN SÁT
    trong chế độ Detect trước, xem CHECKLIST_VAN_HANH_BASELINE.md để biết cách
    theo dõi/quyết định khi nào chuyển Prevent.
    """
    action = "deny,status:403,log" if action_mode == "deny" else "pass,log"
    _next_id = [int(base_rule_id)]

    def alloc() -> int:
        rid = _next_id[0]
        _next_id[0] += 1
        return rid

    sections: list[tuple[str, list[str]]] = []

    def add(section: str, rule: str) -> None:
        for _, rules in sections:
            pass
        for sec_title, rules in sections:
            if sec_title == section:
                rules.append(rule)
                return
        sections.append((section, [rule]))

    seen_companion: set[str] = set()

    # ========== A. Protocol / Framing Hardening (near-0% FP, RFC-based) ==========
    rid = alloc()
    add("A. Protocol & Framing Hardening", (
        f'# Chặn HTTP Request Smuggling (CL + TE cùng tồn tại)\n'
        f'SecRule &REQUEST_HEADERS:Content-Length "@gt 0" \\\n'
        f'    "id:{rid},phase:1,{action},t:none,chain,\\\n'
        f'    msg:\'HTTP Smuggling CL+TE detected\',tag:\'smuggling\'"\n'
        f'    SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 0" "t:none"'
    ))
    rid = alloc()
    add("A. Protocol & Framing Hardening",
        f'SecRule &REQUEST_HEADERS:Content-Length "@gt 1" "id:{rid},phase:1,{action},t:none,msg:\'Duplicate Content-Length\',tag:\'smuggling\'"')
    rid = alloc()
    add("A. Protocol & Framing Hardening",
        f'SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 1" "id:{rid},phase:1,{action},t:none,msg:\'Duplicate Transfer-Encoding\',tag:\'smuggling\'"')
    rid = alloc()
    add("A. Protocol & Framing Hardening", (
        f'# Chặn biến thể Transfer-Encoding lạ (TE.TE / obfuscated)\n'
        f'SecRule REQUEST_HEADERS:Transfer-Encoding "!@rx (?i)^(?:chunked|gzip|deflate|compress|br)(?:\\s*,\\s*(?:chunked|gzip|deflate|compress|br))*\\z" \\\n'
        f'    "id:{rid},phase:1,{action},t:none,\\\n'
        f'    msg:\'Obfuscated Transfer-Encoding header\',tag:\'smuggling\',logdata:\'TE=%{{MATCHED_VAR}}\'"'
    ))
    rid = alloc()
    add("A. Protocol & Framing Hardening",
        f'SecRule REQUEST_HEADERS_NAMES "@rx (?i)^(?:transfer_encoding|content_length)$|^(?:transfer-encoding|content-length)\\s+$" '
        f'"id:{rid},phase:1,{action},t:none,msg:\'Malformed framing header name\',tag:\'smuggling\'"')
    rid = alloc()
    add("A. Protocol & Framing Hardening",
        f'SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\z" '
        f'"id:{rid},phase:1,{action},t:none,msg:\'Disallowed HTTP method\',tag:\'waf-hardening\',logdata:\'%{{REQUEST_METHOD}}\'"')
    rid = alloc()
    charset_rx = r"(?i)charset\s*=\s*[\x22\x27]?(?!(?:utf-?8|iso-8859-1|us-ascii|windows-125[0-8]|latin-?1)(?:[\x22\x27;\s]|$))[A-Za-z0-9_.-]+"
    add("A. Protocol & Framing Hardening",
        f'SecRule REQUEST_HEADERS:Content-Type "@rx {charset_rx}" '
        f'"id:{rid},phase:1,{action},t:none,msg:\'Unusual Content-Type charset\',tag:\'waf-hardening\',logdata:\'%{{MATCHED_VAR}}\'"')
    rid = alloc()
    add("A. Protocol & Framing Hardening",
        f'SecRule REQUEST_HEADERS:Origin "@rx (?i)^null\\z" '
        f'"id:{rid},phase:1,{action},t:none,msg:\'CORS Null Origin rejected\',tag:\'cors\',logdata:\'Origin=%{{MATCHED_VAR}}\'"')
    rid = alloc()
    add("A. Protocol & Framing Hardening",
        f'SecRule REQUEST_HEADERS_NAMES "@rx {OVERRIDE_HEADER_RE.pattern}" '
        f'"id:{rid},phase:1,{action},t:none,msg:\'Blocked override/spoofing header\',tag:\'auth-bypass\',logdata:\'%{{MATCHED_VAR_NAME}}\'"')

    # ========== B. Recon / Path Hardening ==========
    rid = alloc()
    add("B. Recon & Path Hardening", (
        f'# Chặn truy cập file nhạy cảm / cấu hình / backup (có chuẩn hóa path)\n'
        f'SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)(?:\\.env(?:\\.|$)|\\.git(?:/|$)|\\.svn(?:/|$)|\\.hg(?:/|$)|\\.ds_store$|\\.ht(?:access|passwd)$|web\\.config$|docker-compose\\.ya?ml$|dockerfile$|id_rsa$|\\.aws/|\\.ssh/|console(?:/|;|\\z)|actuator(?:/|;|\\z))|\\.(?:bak|backup|old|orig|save|swp|swo|sql|sqlite3?)(?:;[^/]*)?\\z" \\\n'
        f'    "id:{rid},phase:1,{action},t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\\\n'
        f'    msg:\'Sensitive file access blocked\',tag:\'recon\',logdata:\'%{{REQUEST_FILENAME}}\'"'
    ))
    rid = alloc()
    add("B. Recon & Path Hardening", (
        f'# Chặn chạy script trong thư mục upload\n'
        f'SecRule REQUEST_FILENAME "@rx (?i)^/(?:uploads?|files?|tmp|images?|media|static|avatars?|storage|assets|data|public|attachments?|content)/.*\\.(?:php\\d?|phtml|phar|pht|jsp|jspx|asp|aspx|py|rb|sh|cgi)\\.?(?:;[^/]*)?$" \\\n'
        f'    "id:{rid},phase:1,{action},t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\\\n'
        f'    msg:\'Block script execution in upload dir\',tag:\'upload\',logdata:\'%{{REQUEST_FILENAME}}\'"'
    ))
    rid = alloc()
    add("B. Recon & Path Hardening", (
        f'# Chặn Path Traversal trực tiếp trên URI (Phase 1)\n'
        f'SecRule REQUEST_URI "@rx (?i)(?:(?:\\.|%(?:25)?2e|%%32%65|\\xc0[\\xae\\x2e]|%c0%(?:ae|2e)|%(?:u002e|uff0e)){{2,}}(?:[;/\\x5c]|%(?:25)?(?:2f|5c|3b)|\\xc0[\\xaf\\x2f\\x5c]|\\xc1[\\x9c\\x1c]|%c0%af|%c1%9c|%u221[56]|%uff0f|%uff3c)|(?:^|/)\\.\\.\\z)" \\\n'
        f'    "id:{rid},phase:1,{action},t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,\\\n'
        f'    msg:\'Path traversal in URI\',tag:\'lfi\',logdata:\'%{{REQUEST_URI}}\'"'
    ))

    # ========== C. Multipart Upload Content Hardening (chain theo Content-Type, không theo route) ==========
    rid_p, rid_c = alloc(), alloc()
    add("C. Upload Content Hardening", (
        f'# Chặn nội dung Webshell / PHAR / SVG-XXE trong Multipart Upload (an toàn trên BunkerWeb — KHÔNG bật SecTmpSaveUploadedFiles)\n'
        f'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \\\n'
        f'    "id:{rid_p},phase:2,{action},t:none,chain,\\\n'
        f'    msg:\'Webshell content in multipart upload\',tag:\'upload\'"\n'
        f'    SecRule REQUEST_BODY "@rx (?i)(?:<\\?(?:php|=|\\s+(?:echo|system|exec|passthru|eval|\\$))|<script\\b|<%[\\s=@]|Runtime\\.getRuntime|ProcessBuilder|/bin/(?:ba)?sh|GIF89a<\\?php|__HALT_COMPILER\\s*\\(\\)|<!ENTITY|<!DOCTYPE[^>]*\\[)" "t:none,t:removeNulls"'
    ))
    rid_p, rid_c = alloc(), alloc()
    add("C. Upload Content Hardening", (
        f'# Chặn tên file thực thi / double-extension / .htaccess khi upload\n'
        f'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \\\n'
        f'    "id:{rid_p},phase:2,{action},t:none,chain,\\\n'
        f'    msg:\'Blocked dangerous script upload filename\',tag:\'upload\'"\n'
        f'    SecRule FILES "@rx (?i)(?:\\.(?:php\\d?|phtml|phar|pht|phps|jsp|jspx|asp|aspx|py|rb|sh|cgi|pl|shtml)(?:\\.[a-z0-9]{{1,8}}|\\.|/|%00)?\\z|(?:^|[/\\x5c])(?:\\.htaccess|\\.user\\.ini|web\\.config)\\z|[/\\x5c]|\\.\\.)" "t:none,t:urlDecodeUni,t:lowercase"'
    ))

    # ========== D. XXE (chain theo Content-Type XML, không theo route) ==========
    rid = alloc()
    add("D. XXE", (
        f'# BƯỚC 1 (Phase 1): Ép body XML/SVG+xml giữ nguyên text để REQUEST_BODY soi được <!ENTITY\n'
        f'# (Lưu ý: nếu app thật cần CRS XML parser thì comment rule này lại)\n'
        f'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)(?:application|text|image)/(?:[a-z0-9.+-]*\\+)?xml" \\\n'
        f'    "id:{rid},phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"'
    ))
    rid_p, rid_c = alloc(), alloc()
    xxe = _PAT_BY_KEY["xxe"]
    add("D. XXE", (
        f'# BƯỚC 2 (Phase 2): Chặn XXE <!ENTITY / <!DOCTYPE / XInclude / SYSTEM\n'
        f'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)(?:application|text|image)/(?:[a-z0-9.+-]*\\+)?xml" \\\n'
        f'    "id:{rid_p},phase:2,{action},t:none,chain,\\\n'
        f'    msg:\'XXE attempt\',tag:\'xxe\'"\n'
        f'    SecRule REQUEST_BODY "@{xxe.modsec_op} {xxe.modsec_pattern}" "{xxe.transforms}"'
    ))

    # ========== E. Chữ ký tấn công chung (ATTACK_PATTERNS, áp dụng trên MỌI route) ==========
    _VAR_BY_MODE = {"value": "ARGS", "name": "ARGS_NAMES", "body": "REQUEST_BODY"}
    for pat in ATTACK_PATTERNS:
        var = _VAR_BY_MODE.get(pat.target_mode, "ARGS")
        rid = alloc()
        rule = _build_chained_rule(
            rid, pat.phase, action, pat.tag, f"Baseline: {pat.name}",
            "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", var, pat.modsec_op, pat.modsec_pattern,
            pat.transforms, route_path=None, host=None,
        )
        add("E. Chữ Ký Tấn Công Chung (ATTACK_PATTERNS)", f"# {pat.name}\n{rule}")

        if pat.tag == "sqli" and "sqli_split" not in seen_companion:
            seen_companion.add("sqli_split")
            rid = alloc()
            split_pat = (
                r"(?:(?:^|\b|\d[eE]\d*|\d\.e|\W)union[\s(]*(?:all[\s(]*|distinct[\s(]*)?select(?:\b|[\s(/*])"
                r"|\bselect\s*(?:distinct\s*)?(?:\*|[\w.`()]+\s*,\s*[\w.`()]+|[a-z_]+\s*\()[^;]{0,120}\bfrom\s+[a-z_][a-z0-9_.$]{0,64}\s*(?:where|limit|order|group|having|union|\)|\z)"
                r"|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file|randomblob)\s*\()"
            )
            rule = _build_chained_rule(
                rid, 2, action, "sqli", "Baseline: SQLi split-comment bypass",
                "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "ARGS", "rx", split_pat,
                "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:removeComments,t:compressWhitespace,t:lowercase",
                route_path=None, host=None,
            )
            add("E. Chữ Ký Tấn Công Chung (ATTACK_PATTERNS)", f"# Chống SQLi tách từ bằng comment /**/ (UN/**/ION SE/**/LECT)\n{rule}")

            rid = alloc()
            rule = _build_chained_rule(
                rid, 2, action, "sqli", "Baseline: SQLi comment-space bypass",
                "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "ARGS", "rx", _SQLI_AUTH_RX + "|" + _SQLI_KW_RX.removeprefix("(?i)"),
                "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:replaceComments,t:compressWhitespace,t:lowercase",
                route_path=None, host=None,
            )
            add("E. Chữ Ký Tấn Công Chung (ATTACK_PATTERNS)", f"# Chống SQLi chèn comment thay khoảng trắng ('/**/OR/**/1=1)\n{rule}")

        if pat.key == "cmdi" and "cmdi_cmdline" not in seen_companion:
            seen_companion.add("cmdi_cmdline")
            rid = alloc()
            cmdline_pat = (
                r"(?:/?(?:usr/(?:local/)?)?(?:s?bin/)?(?:ba|da|z|k|c)?sh\s+-[ic]"
                r"|/(?:usr/)?s?bin/(?:cat|tac|head|tail|nl|base64|xxd|od|python\d?|perl|ruby|php|nc|ncat|socat|curl|wget|id|whoami|uname|env|printenv|awk|sed|grep|find)"
                r"|(?:cat|tac|head|tail|nl|more|less|base64|xxd|od|strings|grep|awk|sed)\s+(?:/etc/|/proc/|/var/|/home/|/root/|/app/|/flag|flag\.txt|\$[a-z_{])"
                r"|(?:whoami|uname\s+-a|printenv\b|curl\s+https?://|wget\s+https?://|nc\s+-[elvp]|powershell\s+-))"
            )
            rule = _build_chained_rule(
                rid, 2, action, "cmdi", "Baseline: CMDi obfuscated command (t:cmdLine)",
                "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "ARGS", "rx", cmdline_pat,
                "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:cmdLine",
                route_path=None, host=None,
            )
            add("E. Chữ Ký Tấn Công Chung (ATTACK_PATTERNS)", f"# Chống CMDi chèn quote/backslash/caret (c'a't, c\\at, c^at)\n{rule}")

        if pat.key == "xss" and "xss_scheme" not in seen_companion:
            seen_companion.add("xss_scheme")
            rid = alloc()
            rule = _build_chained_rule(
                rid, 2, action, "xss", "Baseline: XSS obfuscated URI scheme",
                "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "ARGS", "rx",
                r"(?:javascript:|vbscript:|data:(?:text/html|image/svg\+xml|application/xhtml\+xml))",
                "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeWhitespace,t:lowercase",
                route_path=None, host=None,
            )
            add("E. Chữ Ký Tấn Công Chung (ATTACK_PATTERNS)", f"# Chống XSS ngắt scheme bằng tab/newline (java&#x09;script:)\n{rule}")

    # ========== F. Chặn theo tên tham số thường gặp (Argument Injection, RFI, Open Redirect, Type Juggling, Mass Assignment) ==========
    arg_inj_names = ["file", "filename", "path", "host", "ip", "domain", "target", "url", "src", "dst",
                     "dest", "repo", "branch", "archive", "out", "input", "img", "doc", "cmd", "opt", "args"]
    rid = alloc()
    rule = _build_chained_rule(
        rid, 2, action, "cmdi", "Baseline: Argument/Option Injection flag",
        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "|".join(f"ARGS:{n}" for n in arg_inj_names), "rx",
        r"(?i)(?:^\s*-|\s--(?:checkpoint-action|exec|eval|upload-pack|receive-pack|config|output|post-data|proxy)\b|\s-[a-z]*e\s+)",
        "t:none,t:urlDecodeUni,t:urlDecodeUni", route_path=None, host=None,
    )
    add("F. Chặn Theo Tên Tham Số Thường Gặp", f"# Argument/Option Injection ('-...' / '--flag') trên tham số file/host/url/...\n{rule}")

    rid = alloc()
    rule = _build_chained_rule(
        rid, 2, action, "type-juggling", "Baseline: PHP array param type juggling",
        "%{MATCHED_VAR_NAME}", "ARGS_NAMES", "rx",
        r"(?i)^(?:username|user|email|password|passwd|pwd|pass|token|secret|otp|pin|code|hash|sig|hmac)\[",
        "t:none", route_path=None, host=None,
    )
    add("F. Chặn Theo Tên Tham Số Thường Gặp", f"# PHP Type Juggling dạng mảng (password[]=x)\n{rule}")

    rid = alloc()
    rule = _build_chained_rule(
        rid, 2, action, "mass-assignment", "Baseline: Mass Assignment privileged field",
        "%{MATCHED_VAR_NAME}", "ARGS_NAMES", "rx", PRIVILEGED_FIELD_RE.pattern,
        "t:none", route_path=None, host=None,
    )
    add("F. Chặn Theo Tên Tham Số Thường Gặp",
        "# Mass Assignment qua trường đặc quyền (role/is_admin/balance/permissions/user_id/owner_id/verified/is_staff/is_superuser)\n"
        "# !! THEO DÕI KỸ NHẤT: nếu route Admin thật nào đó CẦN client tự gửi field này thì sẽ bị chặn nhầm — xem CHECKLIST_VAN_HANH_BASELINE.md\n"
        f"{rule}")

    redirect_param_names = ["next", "return", "return_to", "returnto", "return_path", "redirect", "redirect_uri",
                            "redirecturi", "redirect_url", "redirecturl", "continue", "dest", "destination",
                            "redir", "goto", "go", "rurl", "checkout_url", "callback", "redirectto"]
    rid = alloc()
    rule = _build_chained_rule(
        rid, 2, action, "open-redirect", "Baseline: Open Redirect / OAuth URI bypass",
        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "|".join(f"ARGS:{n}" for n in redirect_param_names), "rx",
        r"(?i)(?:^\s*(?:https?:|//+|/\x5c|\x5c+|(?:java|vb)script:|data:)|^[^/?#\s]+:[^/?#\s]*@|\.\.[/\x5c])",
        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:removeWhitespace,t:lowercase",
        route_path=None, host=None,
    )
    add("F. Chặn Theo Tên Tham Số Thường Gặp", f"# Open Redirect / OAuth URI bypass trên tham số next/return/redirect/...\n{rule}")

    rfi_param_names = ["file", "filename", "page", "path", "template", "include", "load", "view", "doc"]
    rid = alloc()
    rule = _build_chained_rule(
        rid, 2, action, "rfi", "Baseline: RFI remote URL in file param",
        "%{MATCHED_VAR_NAME}=%{MATCHED_VAR}", "|".join(f"ARGS:{n}" for n in rfi_param_names), "rx",
        r"(?i)^\s*(?:https?://|ftp://|//|\x5c\x5c)",
        "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeNulls,t:lowercase",
        route_path=None, host=None,
    )
    add("F. Chặn Theo Tên Tham Số Thường Gặp", f"# Remote File Inclusion (RFI) trên tham số file/filename/page/path/template/include/load/view/doc\n{rule}")

    rid = alloc()
    sensitive_fields = "password|pass|passwd|pwd|token|secret|hash|sig|otp|pin|api_key"
    rule = _build_chained_rule(
        rid, 2, action, "type-juggling", "Baseline: JSON non-string sensitive field",
        "%{MATCHED_VAR_NAME}", "REQUEST_BODY", "rx",
        rf'(?i)\x22(?:{sensitive_fields})\x22\s*:\s*(?:true|false|null|\[|\{{|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?:\s*[,}}]))',
        "t:none,t:jsDecode", route_path=None, host=None,
    )
    add("F. Chặn Theo Tên Tham Số Thường Gặp", f"# JSON Type Juggling: trường password/token/secret/hash/sig/otp/pin truyền bool/null/number\n{rule}")

    # ========== G. JWT (Authorization header + Cookie, generic) ==========
    alg_cap_pat = r"(?:^|\s)(eyJ[A-Za-z0-9_-]{8,})\."
    alg_none_pat = r"(?i)\x22alg\x22\s*:\s*\x22none\x22"
    for gvar, glabel in (("REQUEST_HEADERS:Authorization", "Authorization header"), ("REQUEST_COOKIES", "Cookie")):
        rid = alloc()
        add("G. JWT (Authorization + Cookie)", (
            f"# JWT alg:none ở {glabel} — giải mã Base64URL (capture TX:1) rồi soi JSON thật, không đoán chuỗi base64\n"
            f'SecRule {gvar} "@rx {alg_cap_pat}" \\\n'
            f'    "id:{rid},phase:2,{action},t:none,capture,chain,\\\n'
            f'    msg:\'JWT alg:none bypass\',tag:\'jwt\',logdata:\'%{{MATCHED_VAR_NAME}}\'"\n'
            f'    SecRule TX:1 "@rx {alg_none_pat}" "t:none,t:base64DecodeExt"'
        ))
        rid = alloc()
        hdr_pat = r"(?i)(?:\x22(?:jku|x5u|jwk|x5c)\x22\s*:|\x22kid\x22\s*:\s*\x22[^\x22]{0,120}(?:\.\.|/|\x5c|\x27|--|;|\||`|\$\())"
        add("G. JWT (Authorization + Cookie)", (
            f"# JWT jku/x5u/kid injection ở {glabel}\n"
            f'SecRule {gvar} "@rx {alg_cap_pat}" \\\n'
            f'    "id:{rid},phase:2,{action},t:none,capture,chain,\\\n'
            f'    msg:\'JWT jku/x5u/kid injection\',tag:\'jwt\',logdata:\'%{{MATCHED_VAR_NAME}}\'"\n'
            f'    SecRule TX:1 "@rx {hdr_pat}" "t:none,t:base64DecodeExt"'
        ))

    # ========== H. GraphQL (chỉ theo tên field "query", không khoá route) ==========
    rid = alloc()
    _ALIAS_BATCH_PAT = r"(?:\s*[A-Za-z0-9_]{1,32}\s*:\s*[A-Za-z0-9_]{1,40}\s*\([^)]{0,120}\)\s*\{[^{}]{0,80}\}){5,}"
    rule = _build_chained_rule(
        rid, 2, action, "graphql", "Baseline: GraphQL alias batching",
        "%{REQUEST_URI}", "ARGS:query|ARGS:json.query", "rx", _ALIAS_BATCH_PAT,
        "t:none,t:jsDecode", route_path=None, host=None,
    )
    add("H. GraphQL (field 'query', không khoá route)", f"# GraphQL Alias Batching (>= 5 alias trong 1 query)\n{rule}")
    rid = alloc()
    rule = _build_chained_rule(
        rid, 2, action, "graphql", "Baseline: GraphQL excessive nesting",
        "%{REQUEST_URI}", "ARGS:query|ARGS:json.query", "rx", r"(?:[^{}]{0,400}\{){7,}",
        "t:none,t:jsDecode", route_path=None, host=None,
    )
    add("H. GraphQL (field 'query', không khoá route)", f"# GraphQL lồng nhau quá sâu (>= 7 tầng)\n{rule}")

    header_lines = [
        "# ============================================================",
        "# BỘ RULE NỀN TẢNG (BASELINE) — route-agnostic, add từ đầu giải",
        "# Sinh bởi rule_engine.generate_baseline_ruleset() — xem",
        "# CHECKLIST_VAN_HANH_BASELINE.md để biết cách quan sát/vận hành.",
        f"# Action mặc định: {action}",
        "# ============================================================",
        "",
    ]
    out_lines: list[str] = list(header_lines)
    for sec_title, rules in sections:
        out_lines.append(f"# ---------- {sec_title} ----------")
        out_lines.append("")
        for r in rules:
            out_lines.append(r)
            out_lines.append("")
    rules_text = "\n".join(out_lines).rstrip() + "\n"

    rule_count = sum(len(rules) for _, rules in sections)
    return {
        "rules_text": rules_text,
        "sections": [{"title": t, "count": len(r)} for t, r in sections],
        "rule_count": rule_count,
    }


def validate_rules_text(rules_text: str, alert: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Validate ModSecurity v3 rules for:
    1. Syntax traps specific to BunkerWeb / libmodsecurity3
    2. ReDoS latency across REDOS_TEST_INPUTS (both parent & chain children)
    3. Benign False-Positive rate against BENIGN_SAMPLES
    4. Whether the ruleset matches the captured attacker request (if `alert` given)
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Trap checks on raw lines BEFORE joining continuations
    raw_lines = rules_text.splitlines()
    for idx, ln in enumerate(raw_lines, 1):
        if re.search(r"\\[ \t]+$", ln):
            errors.append(f"Dòng {idx}: Có khoảng trắng dư sau dấu '\\' nối dòng (lỗi NGINX reload).")
        if re.search(r"\\\s*#.*$", ln) and not ln.strip().startswith("#") and '"' not in ln.split("#")[-1]:
            # Only warn if backslash is at end of rule syntax followed by trailing comment (not inside "@rx ...\s*#...")
            before_hash = ln.split("#", 1)[0]
            if before_hash.rstrip().endswith("\\"):
                warnings.append(f"Dòng {idx}: Có dấu '#' phía sau '\\' nối dòng.")
        if "SecTmpSaveUploadedFiles" in ln and "On" in ln:
            errors.append(f"Dòng {idx}: KHÔNG bật SecTmpSaveUploadedFiles On trên BunkerWeb (gây 400 Upload).")

    # Join continuations and parse rules
    joined = re.sub(r"\\\s*\n\s*", " ", rules_text)
    sec_lines: list[tuple[int, str]] = []
    for idx, ln in enumerate(joined.splitlines(), 1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"secrule\s+", s, re.I):
            sec_lines.append((idx, s))

    rules: list[ParsedRule] = []
    i = 0
    while i < len(sec_lines):
        idx, ln = sec_lines[i]
        parent = _parse_single_rule(ln)
        i += 1
        cur = ln
        while _has_chain_action(cur) and i < len(sec_lines):
            cidx, cln = sec_lines[i]
            child = _parse_single_rule(cln)
            if child.rule_id or child.phase or child.action:
                errors.append(f"Rule {parent.rule_id or idx}: Dòng con trong chain không được chứa id:/phase:/deny/pass.")
            parent.chain_children.append(child)
            cur = cln
            i += 1
        rules.append(parent)

    if not rules and "proxy_hide_header" not in rules_text:
        warnings.append("Chưa có SecRule nào trong khung xem trước.")

    seen_ids: dict[str, int] = {}
    max_redos_ms = 0.0
    fp_hits: list[dict[str, str]] = []
    attack_matched = False

    # Prepare alert inputs for match verification
    alert_values: list[str] = []
    q = ""
    rb = ""
    rh = ""
    if alert:
        u = alert.get("uri") or ""
        upath = urllib.parse.urlsplit(u).path or "/"
        rb = alert.get("request_body") or ""
        rh = alert.get("request_headers_text") or ""
        if not rh and isinstance(alert.get("headers"), dict):
            rh = "\n".join(f"{k}: {v}" for k, v in alert["headers"].items())
        alert_values.extend([u, upath, urllib.parse.unquote(upath), _multi_decode(u), rb, _multi_decode(rb), rh, alert.get("response_body") or "", alert.get("response_headers_text") or ""])
        q = urllib.parse.urlsplit(u).query
        for k, vs in urllib.parse.parse_qs(q, keep_blank_values=True).items():
            alert_values.append(k)
            for v in vs:
                alert_values.extend(_value_variants(v))
        for line in rh.splitlines():
            if ":" in line:
                hk_v, hv_v = line.split(":", 1)
                hv_v = hv_v.strip()
                alert_values.append(hv_v)
                if hk_v.strip().lower() == "cookie" and "=" in hv_v:
                    for seg in hv_v.split(";"):
                        if "=" in seg:
                            alert_values.append(seg.split("=", 1)[1].strip())
        if rb.lstrip("\ufeff \t\r\n").startswith(("{", "[")):
            try:
                for fk, fv in _flatten_json(json.loads(rb.lstrip("\ufeff")), "json"):
                    alert_values.extend([fk, fk.split(".")[-1], fv])
                    alert_values.extend(_value_variants(fv))
            except Exception:
                pass
        elif "=" in rb and not rb.lstrip().startswith("<"):
            for k, vs in urllib.parse.parse_qs(rb, keep_blank_values=True).items():
                alert_values.append(k)
                for v in vs:
                    alert_values.extend(_value_variants(v))
                    alert_values.append(urllib.parse.unquote(v))
                    alert_values.append(v.strip().replace(" ", "+"))

    for r in rules:
        # ID validation
        if not r.rule_id:
            errors.append("Thiếu id:<số> trên SecRule chính.")
        else:
            if r.rule_id in seen_ids:
                errors.append(f"Trùng Rule ID {r.rule_id} (lỗi NGINX reload).")
            seen_ids[r.rule_id] = 1
            rid_num = int(r.rule_id)
            if not (20000 <= rid_num <= 29999):
                warnings.append(f"Rule {r.rule_id}: Nên dùng dải ID 20000–29999 (khuyên 27200–29999).")

        if "REMOTE_ADDR" in [v.upper() for v in r.variables]:
            errors.append(f"Rule {r.rule_id}: KHÔNG chặn theo REMOTE_ADDR (bot chấm BTC dùng chung 1 IP proxy!).")

        all_tags = {r.tag} | {c.tag for c in r.chain_children}
        if "flag-leak" in all_tags and r.action == "deny":
            errors.append(
                f"Rule {r.rule_id}: Rule flag-leak đang ở 'deny' — chỉ được bật sau khi TỰ XÁC NHẬN route "
                f"loại trừ khớp đúng route THẬT phục vụ cờ cho bot SVC (test pass,log ít nhất 1 chu kỳ "
                f"healthcheck trước). Sai route sẽ tự chặn bot chấm, vi phạm Điều 3.5 Quy chế và bị trừ SVC "
                f"gấp đôi — đổi lại 'pass,log' nếu chưa chắc chắn."
            )

        for v in r.variables:
            if v.startswith("ARGS:/") and "|" in v:
                errors.append(f"Rule {r.rule_id}: Biến '{v}' chứa '|' trong regex tên biến gây lỗi libmodsecurity3!")
        if r.phase == "1" and any(v.upper().startswith(("ARGS", "REQUEST_BODY", "FILES")) for v in r.variables):
            errors.append(f"Rule {r.rule_id}: Phase 1 không đọc được ARGS/REQUEST_BODY/FILES (phải dùng phase:2).")

        if "normalizepath" in [t.lower() for t in r.transforms] and ".." in r.pattern and any("ARGS" in v.upper() for v in r.variables):
            errors.append(f"Rule {r.rule_id}: Không dùng t:normalizePath trên ARGS khi tìm '..' (sẽ tự gộp mất ../).")

        # ReDoS + Benign FP check across parent + chain children
        all_nodes = [r] + r.chain_children
        for node in all_nodes:
            if node.operator == "rx":
                # Convert PCRE \z to Python \Z for testing
                py_pat = node.pattern.replace(r"\z", r"\Z")
                try:
                    compiled = re.compile(py_pat, re.IGNORECASE if "(?i)" not in py_pat else 0)
                except re.error as exc:
                    errors.append(f"Rule {r.rule_id}: Lỗi cú pháp regex '{node.pattern[:50]}': {exc}")
                    continue
                for inp in REDOS_TEST_INPUTS:
                    t0 = time.perf_counter()
                    compiled.search(inp)
                    ms = (time.perf_counter() - t0) * 1000
                    if ms > max_redos_ms:
                        max_redos_ms = ms

        # Check benign FP (only on ARGS/BODY/URI/free-text rules, NOT protocol allowlists like Transfer-Encoding/Method)
        check_node = r.chain_children[-1] if r.chain_children else r
        is_route_allowlist = bool(r.chain_children) and check_node.negated
        is_protocol_hdr = any(
            v.upper().startswith(("REQUEST_METHOD", "REQBODY_PROCESSOR", "REQUEST_HEADERS:TRANSFER-ENCODING", "REQUEST_HEADERS:ORIGIN", "REQUEST_HEADERS:CONTENT-TYPE", "REQUEST_HEADERS:HOST", "RESPONSE_"))
            for v in check_node.variables
        )
        has_b64_node = any(t.lower() in ("base64decode", "base64decodeext") for t in check_node.transforms)
        if check_node.operator == "rx" and not is_route_allowlist and not is_protocol_hdr and r.phase != "4":
            py_pat = check_node.pattern.replace(r"\z", r"\Z")
            try:
                compiled = re.compile(py_pat, re.IGNORECASE if "(?i)" not in py_pat else 0)
                samples_to_check = (
                    ["avatar.png", "report.v2.pdf", "photo_123.jpg", "document-final.csv"]
                    if check_node.variables == ["FILES"]
                    else BENIGN_SAMPLES
                )
                for b in samples_to_check:
                    cand_b = [b]
                    if not has_b64_node:
                        bt = _simulate_modsec_transforms(b, check_node.transforms)
                        if bt != b:
                            cand_b.append(bt)
                    hit = any(bool(compiled.search(cb)) for cb in cand_b)
                    if check_node.negated:
                        hit = not hit
                    if hit:
                        fp_hits.append({"rule_id": r.rule_id, "sample": b})
            except re.error:
                pass

        # Check if rule matches captured alert
        if alert and not attack_matched:
            if check_node.operator == "rx":
                py_pat = check_node.pattern.replace(r"\z", r"\Z")
                test_vals: list[str] = []
                seen_tv: set[str] = set()
                for val in alert_values:
                    for v_cand in (val, _simulate_modsec_transforms(val, check_node.transforms), *_value_variants(val)):
                        if v_cand and v_cand not in seen_tv:
                            seen_tv.add(v_cand)
                            test_vals.append(v_cand)
                if has_b64_node:
                    for val in alert_values:
                        for tok in re.findall(r"[A-Za-z0-9+/_-]{16,}={0,2}", val):
                            try:
                                pad = tok + "=" * ((4 - len(tok) % 4) % 4)
                                raw_dec = base64.b64decode(pad.replace("-", "+").replace("_", "/"))
                                test_vals.append(raw_dec.decode("utf-8", errors="ignore"))
                                test_vals.append(raw_dec.decode("latin-1"))
                            except Exception:
                                pass
                try:
                    compiled = re.compile(py_pat, re.IGNORECASE if "(?i)" not in py_pat else 0)
                    for val in test_vals:
                        m = bool(compiled.search(val))
                        if check_node.negated:
                            m = not m
                        if m and val:
                            attack_matched = True
                            break
                except re.error:
                    pass
            elif check_node.operator in ("detectsqli", "detectxss"):
                attack_matched = True
            elif check_node.operator == "streq" and alert:
                if any(v.upper() == "REQBODY_PROCESSOR" for v in check_node.variables) and check_node.negated:
                    if rb.lstrip("\ufeff \t\r\n").startswith(("{", "[")) and "json" not in rh.lower():
                        attack_matched = True
                elif any("SEC-FETCH-SITE" in v.upper() for v in check_node.variables):
                    if re.search(r"(?im)^sec-fetch-site\s*:\s*cross-site\b", rh):
                        attack_matched = True
            elif check_node.operator == "gt" and alert:
                # Header existence (@gt 0) or duplicate param count (@gt 1)
                for v in check_node.variables:
                    vu = v.upper()
                    if vu.startswith("&REQUEST_HEADERS:"):
                        hname = v.split(":", 1)[1].strip().lower()
                        cnt_h = len(re.findall(rf"(?im)^{re.escape(hname)}\s*:", rh))
                        if cnt_h > int(check_node.pattern or 0):
                            attack_matched = True
                            break
                    elif vu.startswith("&ARGS:"):
                        aname = v.split(":", 1)[1].strip()
                        cnt = len(urllib.parse.parse_qs(q, keep_blank_values=True).get(aname, [])) + len(urllib.parse.parse_qs(rb, keep_blank_values=True).get(aname, []))
                        if cnt > int(check_node.pattern or 0):
                            attack_matched = True
                            break

    if max_redos_ms > 100:
        errors.append(f"ReDoS nguy hiểm: thời gian match tối đa {max_redos_ms:.1f}ms (>100ms).")
    elif max_redos_ms > 20:
        warnings.append(f"Regex hơi chậm: {max_redos_ms:.2f}ms.")

    if fp_hits:
        samples_str = ", ".join(repr(x["sample"]) for x in fp_hits[:3])
        warnings.append(f"Cảnh báo False Positive trên {len(fp_hits)} mẫu sạch ({samples_str}) — nhớ test bằng pass,log trước!")

    return {
        "ok": len(errors) == 0,
        "rule_count": len(rules),
        "errors": errors,
        "warnings": warnings,
        "max_redos_ms": round(max_redos_ms, 3),
        "fp_count": len(fp_hits),
        "fp_samples": fp_hits[:5],
        "attack_matched": attack_matched if alert else None,
    }

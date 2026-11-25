#!/usr/bin/env python3
"""
vulncheck - Multi-Domain Vulnerability Scanner & Security Linter
Designed for Source Code Auditing, Attack/Defense (A/D) Whitebox Analysis, and Defensive Hardening.

Features:
- Compiler-style diagnostics (GCC / Clang linter format compatible with IDEs / CI).
- Deep C/C++ memory corruption analysis mapped to PWN Roadmap Tiers (T1-T10).
- Automatic ELF Checksec mitigation correlation & dynamic attack scenario synthesis.
- Extensible multi-domain engines: PWN (C/C++), WEB (PHP/Python/JS), CRYPTO, REV.
- Multi-format reporting: Rich Terminal UI, GCC Linter, JSON, Markdown Audit Report.

Author: IBOH Defense Team
"""

import os
import sys
import re
import json
import argparse
import subprocess
import signal
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

# Handle standard broken pipe when piping to head/grep
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

# Try importing pwntools for advanced ELF inspection
try:
    from pwn import ELF as PwnELF, context as pwn_context
    pwn_context.log_level = 'error'
    HAS_PWNTOOLS = True
except Exception:
    HAS_PWNTOOLS = False

# ==============================================================================
# Terminal Color Palette
# ==============================================================================
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDER   = "\033[4m"
    
    # Foreground
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    
    # Bright Foreground
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"

    # Background
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"

def colorize(text: str, color: str, no_color: bool = False) -> str:
    if no_color or not sys.stdout.isatty():
        return text
    return f"{color}{text}{Colors.RESET}"

# ==============================================================================
# Finding Data Model
# ==============================================================================
class Finding:
    def __init__(
        self,
        file_path: str,
        line: int,
        col: int,
        rule_id: str,
        title: str,
        severity: str,
        cwe: str,
        tier: str,
        description: str,
        exploit_techniques: List[str],
        remediation: str,
        snippet: str = "",
        token: str = "",
        cheatsheet_ref: str = "",
        category: str = "pwn",
        scenario: str = ""
    ):
        self.file_path = file_path
        self.line = line
        self.col = col
        self.rule_id = rule_id
        self.title = title
        self.severity = severity.upper()  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.cwe = cwe
        self.tier = tier
        self.description = description
        self.exploit_techniques = exploit_techniques
        self.remediation = remediation
        self.snippet = snippet
        self.token = token
        self.cheatsheet_ref = cheatsheet_ref
        self.category = category
        self.scenario = scenario

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file_path,
            "line": self.line,
            "col": self.col,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "tier": self.tier,
            "category": self.category,
            "description": self.description,
            "exploit_techniques": self.exploit_techniques,
            "scenario": self.scenario,
            "remediation": self.remediation,
            "cheatsheet_ref": self.cheatsheet_ref,
            "snippet": self.snippet,
        }

    def to_gcc_string(self) -> str:
        sev_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "warning",
            "INFO": "note"
        }
        level = sev_map.get(self.severity, "warning")
        return f"{self.file_path}:{self.line}:{self.col}: {level}: [{self.cwe}] {self.title} [-W{self.rule_id.lower()}]"

# ==============================================================================
# Binary Checksec & Mitigation Analyzer
# ==============================================================================
class BinaryProfile:
    def __init__(self, path: str):
        self.path = path
        self.valid = False
        self.arch = "unknown"
        self.bits = 64
        self.canary = False
        self.nx = False
        self.pie = False
        self.relro = "None"
        self.fortify = False
        self.rwx = False
        self.stripped = True
        self.symbols: Set[str] = set()
        self.interesting_symbols: List[str] = []
        self.analyze()

    def analyze(self):
        if not os.path.exists(self.path):
            return

        # 1. Try pwntools ELF
        if HAS_PWNTOOLS:
            try:
                elf = PwnELF(self.path, checksec=False)
                self.arch = str(elf.arch)
                self.bits = int(elf.bits)
                self.canary = bool(elf.canary)
                self.nx = bool(elf.nx)
                self.pie = bool(elf.pie)
                self.relro = str(elf.relro) if elf.relro else "None"
                self.symbols = set(elf.symbols.keys())
                self.stripped = len(self.symbols) == 0
                
                # Check RWX segments
                for seg in elf.segments:
                    flags = seg.header.p_flags
                    if (flags & 1) and (flags & 2):
                        self.rwx = True
                self.valid = True
            except Exception:
                pass

        # 2. Fallback to checksec CLI if needed
        if self.arch == "unknown":
            try:
                res = subprocess.run(["checksec", "--file", self.path], capture_output=True, text=True, timeout=5)
                out = res.stdout + res.stderr
                if "Full RELRO" in out: self.relro = "Full"
                elif "Partial RELRO" in out: self.relro = "Partial"
                elif "No RELRO" in out: self.relro = "None"
                
                self.canary = "Canary found" in out
                self.nx = "NX enabled" in out
                self.pie = "PIE enabled" in out
                self.rwx = "Has RWX segments" in out
                self.arch = "elf"
                self.valid = True
            except Exception:
                pass

        # Check interesting symbols (backdoors, win functions, system)
        targets = ["win", "backdoor", "shell", "print_flag", "get_flag", "flag", "system", "execve", "main"]
        for t in targets:
            if t in self.symbols:
                self.interesting_symbols.append(t)

    def summary(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "arch": f"{self.arch}-{self.bits}",
            "canary": self.canary,
            "nx": self.nx,
            "pie": self.pie,
            "relro": self.relro,
            "rwx": self.rwx,
            "stripped": self.stripped,
            "interesting_symbols": self.interesting_symbols,
        }

# ==============================================================================
# Scenario Correlator Engine
# ==============================================================================
class ScenarioCorrelator:
    @staticmethod
    def correlate(finding: Finding, binary: Optional[BinaryProfile]) -> str:
        rule = finding.rule_id
        cat = getattr(finding, "category", "pwn")

        # -------------------------------------------------------------
        # Web Domain Scenarios
        # -------------------------------------------------------------
        if cat == "web" or rule.startswith("WEB-"):
            if "WEB-SQLI" in rule:
                return "Kịch bản SQL Injection: Dùng UNION-based hoặc Blind/Error-based SQLi để trích xuất database (users, password hashes, flags), hoặc dùng ' OR '1'='1 để bypass xác thực đăng nhập."
            elif "WEB-INJ" in rule:
                return "Kịch bản Command Injection (RCE): Chèn các ký tự điều khiển shell (; & | ` $()) để thực thi lệnh hệ thống tùy ý, đọc file cờ hoặc tạo Reverse Shell chiếm toàn quyền server."
            elif "WEB-LFI" in rule or "WEB-TRAV" in rule:
                return "Kịch bản Path Traversal / LFI: Đọc file nhạy cảm qua traversal (../../etc/passwd), đọc source code qua PHP wrapper (php://filter/convert.base64-encode/resource=...), hoặc leo thang thành RCE qua Log Poisoning / PHP Sessions."
            elif "WEB-DESER" in rule:
                return "Kịch bản Insecure Deserialization: Tạo payload serialized độc hại (pickle __reduce__, PHP POP Gadget Chain) để ép máy chủ thực thi mã tùy ý ngay khi deserialize object."
            elif "WEB-SSRF" in rule:
                return "Kịch bản SSRF: Ép server gửi request tới mạng nội bộ (127.0.0.1, AWS Metadata 169.254.169.254, internal microservices) để đọc tài nguyên bí mật hoặc bypass firewall."
            elif "WEB-SSTI" in rule:
                return "Kịch bản Server-Side Template Injection: Nhúng cú pháp engine ({{7*7}}, {{config.items()}}, {{lipsum.__globals__}}) để escape sandbox và thực thi RCE trên server."
            elif "WEB-SECRET" in rule:
                return "Kịch bản Hardcoded Secret: Khóa bí mật (API Key, JWT Secret, Database Password) bị lộ trong mã nguồn cho phép kẻ tấn công giả mạo token người dùng hoặc truy cập trái phép API backend."
            return "Kịch bản Web: Khai thác logic ứng dụng để truy cập dữ liệu trái phép hoặc leo thang đặc quyền."

        # -------------------------------------------------------------
        # Crypto Domain Scenarios
        # -------------------------------------------------------------
        if cat == "crypto" or rule.startswith("CRYPTO-"):
            if "CRYPTO-MODE" in rule:
                return "Kịch bản AES-ECB Flaw: Các khối bản rõ 16-byte giống nhau cho ra ciphertext giống nhau (ECB leak). Kẻ tấn công có thể cắt ghép khối (Block Shuffling) hoặc dùng Chosen-Plaintext Attack để giải mã từng byte cờ."
            elif "CRYPTO-KEY" in rule:
                return "Kịch bản Weak RSA Key: Độ dài khóa RSA < 2048 bits có thể bị phân tích nhân tử N = p * q dễ dàng (qua CADO-NFS, Pollard's p-1, hoặc FactorDB) để tính lại private key d."
            elif "CRYPTO-HASH" in rule:
                return "Kịch bản Broken Hash (MD5/SHA1): Hash đã bị phá vỡ va chạm (Collision Attack) hoặc dễ bị tấn công mở rộng chiều dài (Length Extension Attack nếu dùng hash(key + data))."
            elif "CRYPTO-RNG" in rule:
                return "Kịch bản Predictable PRNG: Seed bằng time() cho phép kẻ tấn công mô phỏng chính xác chuỗi số ngẫu nhiên, từ đó dự đoán trước token đặt lại mật khẩu, session ID, hoặc OTP."
            elif "CRYPTO-STATIC-IV" in rule:
                return "Kịch bản Static IV: Tái sử dụng IV trong CBC/CTR cho phép kẻ tấn công phân tích XOR giữa hai ciphertext hoặc khôi phục keystream để giải mã thông điệp."
            return "Kịch bản Crypto: Phá vỡ tính bảo mật (confidentiality) hoặc tính toàn vẹn (integrity) của hệ mã hóa."

        # -------------------------------------------------------------
        # Reverse Engineering Domain Scenarios
        # -------------------------------------------------------------
        if cat == "rev" or rule.startswith("REV-"):
            if "REV-ANTI-DEBUG" in rule or "REV-ANTI" in rule:
                return "Kịch bản Anti-Debugging: Chương trình chủ động bẫy debugger (ptrace, BeingDebugged, timing checks) để thoát hoặc chuyển hướng luồng thực thi nhằm cản trở việc dịch ngược / phân tích động."
            elif "REV-VM" in rule:
                return "Kịch bản Anti-VM / Sandbox: Kiểm tra môi trường ảo hóa (CPUID, MAC address, hypervisor artifacts) để trốn tránh các hệ thống tự động phân tích mã độc."
            return "Kịch bản Rev: Kỹ thuật gây nhiễu và bảo vệ binary chống dịch ngược."

        # -------------------------------------------------------------
        # PWN Domain Scenarios (Binary correlated or SAST baseline)
        # -------------------------------------------------------------
        if not binary or not getattr(binary, "valid", False):
            # Baseline theoretical scenario without binary
            rid = finding.rule_id
            if any(k in rid for k in ("PWN-BOF", "PWN-OOB", "PWN-BIN-GETS", "PWN-BIN-STRCPY", "PWN-BIN-STRCAT", "PWN-BIN-SPRINTF", "PWN-BIN-SCANF", "PWN-BIN-READ", "PWN-BIN-MEMCPY", "PWN-BIN-WIN")):
                return "Kịch bản Stack BOF: NX tắt → ret2shellcode; NX bật & no-Canary → ROP/ret2libc; có hàm win → ret2win; có Canary → leak canary trước."
            elif "FMT" in rid:
                return "Kịch bản Format String: %p leak canary/libc/PIE; Partial RELRO → %n ghi GOT; Full RELRO → ghi saved RIP / exit_handler / FSOP."
            elif any(k in rid for k in ("PWN-HEAP", "PWN-UAF", "PWN-INT")):
                return "Kịch bản Heap: tcache/fastbin poisoning (2.31) / safe-link (2.32+); UAF→leak→__free_hook; House of Spirit/Force/Einherjar; glibc≥2.35 → House of Apple2 (FSOP)."
            elif any(k in rid for k in ("PWN-CMD", "PWN-BIN-SYSTEM", "PWN-BIN-EXECVE", "PWN-BIN-POPEN")):
                return "Có system/exec: nếu tham số điều khiển được → command injection (`; cat /flag`); nếu có BOF → ret2libc system('/bin/sh')."
            return "Cấp --bin (ELF) để mô phỏng kịch bản chính xác theo checksec."

        # Dynamic scenario synthesis based on exact ELF mitigations
        rule = finding.rule_id

        # 1. Stack Buffer Overflows
        if any(k in rule for k in ("PWN-BOF", "PWN-OOB", "PWN-BIN-GETS", "PWN-BIN-STRCPY", "PWN-BIN-STRCAT", "PWN-BIN-SPRINTF", "PWN-BIN-SCANF", "PWN-BIN-READ", "PWN-BIN-MEMCPY", "PWN-BIN-WIN")):
            if not binary.nx or binary.rwx:
                return (
                    f"CRITICAL EXPLOIT SCENARIO [ret2shellcode / T1 & T5]:\n"
                    f"       • NX is DISABLED / RWX Segment present!\n"
                    f"       • Kẻ tấn công có thể chèn trực tiếp shellcode vào stack/buffer và ghi đè return address trỏ về.\n"
                    f"       • Khai thác tức thì (1-shot RCE) mà KHÔNG cần leak địa chỉ libc hay xây dựng ROP chain phức tạp."
                )
            elif not binary.canary and not binary.pie:
                win_txt = f" Có sẵn hàm '{binary.interesting_symbols[0]}' để ret2win!" if binary.interesting_symbols else " Dùng ROP chain gọi puts@plt leak libc rồi ret2libc."
                return (
                    f"HIGH EXPLOIT SCENARIO [ret2win / ret2libc / T1 & T3]:\n"
                    f"       • NX bật nhưng Stack Canary = NO và PIE = NO.\n"
                    f"       • Ghi đè Saved RIP trực tiếp mà không bị phát hiện.{win_txt}\n"
                    f"       • Gadgets địa chỉ tĩnh trên binary (No PIE) giúp dễ dàng dựng payload."
                )
            elif binary.canary:
                return (
                    f"CHALLENGING SCENARIO [Canary Bypass required / T4]:\n"
                    f"       • Stack Canary = ENABLED. Ghi đè trực tiếp sẽ kích hoạt '__stack_chk_fail'.\n"
                    f"       • Kẻ tấn công bắt buộc phải: (1) Tìm lỗi phụ (format string, buffer overread) để leak 8-byte canary, hoặc\n"
                    f"         (2) Dò brute-force byte-by-byte (nếu process fork server) trước khi dựng ROP chain."
                )
            elif binary.pie:
                return (
                    f"PIE MITIGATION SCENARIO [ASLR Bypass required / T4]:\n"
                    f"       • Binary có PIE enabled. Địa chỉ code bị random hóa mỗi lần chạy.\n"
                    f"       • Cần leak một địa chỉ code (.text) hoặc dùng kỹ thuật Partial Overwrite (1-2 bytes thấp) để né ASLR."
                )

        # 2. Format String
        elif "FMT" in rule:
            if binary.relro in ("Partial", "None"):
                return (
                    f"CRITICAL FORMAT STRING SCENARIO [GOT Overwrite / T2 & T10]:\n"
                    f"       • RELRO = {binary.relro} (Bảng GOT ở chế độ GHI ĐƯỢC - Writeable).\n"
                    f"       • Kẻ tấn công dùng cú pháp '%<val>c%<pos>$n' ghi đè GOT của hàm gọi sau (vd: puts@got, printf@got, exit@got) trỏ về system/win.\n"
                    f"       • Đây là vector chiếm quyền shell nguy hiểm và phổ biến nhất."
                )
            else:
                return (
                    f"HIGH FORMAT STRING SCENARIO [Info Leak & FSOP / T2 & T9]:\n"
                    f"       • Full RELRO: Bảng GOT là Read-Only, không thể ghi đè GOT.\n"
                    f"       • Tuy nhiên kẻ tấn công vẫn khai thác để: (1) Dùng %p leak Canary, Libc base, Stack pointer;\n"
                    f"         (2) Dùng %n ghi đè Saved RIP trên Stack hoặc cấu trúc _IO_FILE (FSOP House of Apple2)."
                )

        # 3. Heap Bugs (UAF / Double Free / Integer→Heap)
        elif any(k in rule for k in ("PWN-HEAP", "PWN-UAF", "PWN-DF", "PWN-INT")):
            if binary.relro in ("Partial", "None"):
                return (
                    f"HIGH HEAP SCENARIO [Tcache Poisoning -> GOT Overwrite / T6 & T7]:\n"
                    f"       • Partial RELRO cho phép sau khi kiểm soát chunk (poisoning fd) sẽ cấp phát chunk đè thẳng vào bảng GOT để RCE."
                )
            else:
                return (
                    f"ADVANCED HEAP SCENARIO [Tcache Poisoning -> Stack/FSOP / T6, T8 & T9]:\n"
                    f"       • Full RELRO chặn ghi đè GOT. Kẻ tấn công sẽ poison chunk trỏ vào Stack (đè return address) hoặc hijack vtable _IO_FILE."
                )

        # 4. Command Injection / ret2libc
        elif any(k in rule for k in ("PWN-INJ", "WEB-INJ", "PWN-CMD", "PWN-BIN-SYSTEM", "PWN-BIN-EXECVE", "PWN-BIN-POPEN")):
            return (
                f"MAX CRITICAL SCENARIO [Shell Command Injection / CWE-78]:\n"
                f"       • Lệnh thực thi trực tiếp qua /bin/sh. Toàn bộ cơ chế bảo vệ nhị phân (NX, Canary, PIE, RELRO) đều VÔ HIỆU HÓA!\n"
                f"       • Khai thác tức thì chỉ bằng các ký tự phân tách: '; id', '| /bin/sh', '$(cat flag)'."
            )

        return "Vấn đề bảo mật cần được rà soát và khắc phục."

# ==============================================================================
# Base Scanner Interface
# ==============================================================================
class BaseScanner:
    def __init__(self):
        self.category = "general"

    @staticmethod
    def strip_comments(text: str, is_python: bool = False) -> str:
        """Strip comments without shifting line numbers or columns."""
        def replacer(match):
            s = match.group(0)
            if s.startswith('/*'):
                return '\n' * s.count('\n') + ' ' * (len(s) - s.rfind('\n') - 1 if '\n' in s else len(s))
            elif s.startswith('//'):
                return ' ' * len(s)
            elif is_python and s.startswith('#'):
                return ' ' * len(s)
            return s
        if is_python:
            pattern = re.compile(
                r'#.*?$|"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^\\"])*"|\'(?:\\.|[^\\\'])*\'',
                re.MULTILINE
            )
        else:
            pattern = re.compile(
                r'/\*.*?\*/|//.*?$|"(?:\\.|[^\\"])*"|\'(?:\\.|[^\\\'])*\'',
                re.DOTALL | re.MULTILINE
            )
        return pattern.sub(replacer, text)

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        raise NotImplementedError

# ==============================================================================
# PWN Scanner Engine (C / C++ Memory Corruption & Logic Bugs)
# ==============================================================================
class PwnScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.category = "pwn"

    @staticmethod
    def strip_comments(text: str) -> str:
        """Strip C/C++ comments without shifting line numbers."""
        def replacer(match):
            s = match.group(0)
            if s.startswith('/*'):
                return '\n' * s.count('\n') + ' ' * (len(s) - s.rfind('\n') - 1 if '\n' in s else len(s))
            elif s.startswith('//'):
                return ' ' * len(s)
            return s
        pattern = re.compile(
            r'/\*.*?\*/|//.*?$|"(?:\\.|[^\\"])*"|\'(?:\\.|[^\\\'])*\'',
            re.DOTALL | re.MULTILINE
        )
        return pattern.sub(replacer, text)

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        clean_code = self.strip_comments(content)
        lines = content.splitlines()
        clean_lines = clean_code.splitlines()

        # 1. Parse symbolic defines (e.g. #define BUF_SIZE 64)
        defines: Dict[str, int] = {}
        for m in re.finditer(r'#define\s+([A-Za-z0-9_]+)\s+([0-9xXa-fA-F]+|\d+)\b', clean_code):
            name, val = m.groups()
            try:
                defines[name] = int(val, 0)
            except Exception:
                pass

        # 1.1 Parse struct definitions and track signed integer fields
        struct_types: Dict[str, Dict[str, str]] = {}
        struct_pattern = re.compile(r'(?:typedef\s+)?struct\s*([a-zA-Z0-9_]*)\s*\{([^}]+)\}\s*([a-zA-Z0-9_]*);')
        for m in struct_pattern.finditer(clean_code):
            tag_name, body, typedef_name = m.groups()
            sname = typedef_name if typedef_name else tag_name
            if sname:
                fields = {}
                for fline in body.split(';'):
                    m_f = re.search(r'\b(int8_t|int16_t|int32_t|int64_t|int|short|long|ssize_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', fline.strip())
                    if m_f and 'unsigned' not in fline:
                        fields[m_f.group(2)] = m_f.group(1)
                struct_types[sname] = fields

        # 1.2 Inter-procedural function summaries for freeing struct members
        func_frees: Dict[str, List[Tuple[str, str]]] = {}
        func_proto_pat = re.compile(
            r'^[ \t]*(?:[a-zA-Z_][a-zA-Z0-9_* \t]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )
        for m in func_proto_pat.finditer(clean_code):
            fn_name = m.group(1)
            fn_args = m.group(2)
            fn_start = m.end()
            depth = 1
            pos = fn_start
            while pos < len(clean_code) and depth > 0:
                if clean_code[pos] == '{': depth += 1
                elif clean_code[pos] == '}': depth -= 1
                pos += 1
            fn_body = clean_code[fn_start:pos]
            
            param_names = []
            for a in fn_args.split(','):
                m_p = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*$', a.strip())
                if m_p:
                    param_names.append(m_p.group(1))
                    
            for p in param_names:
                for m_free in re.finditer(rf'\bfree\s*\(\s*{re.escape(p)}\s*->\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', fn_body):
                    field = m_free.group(1)
                    func_frees.setdefault(fn_name, []).append((p, field))

        # 2. Track array declarations (char buf[32]; uint8_t name[0x20];)
        arrays: Dict[str, Tuple[int, int]] = {} # name -> (size_bytes, decl_line)
        for m in re.finditer(r'\b(?:char|uint8_t|int8_t|unsigned\s+char)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*([0-9xXa-fA-F]+|[A-Za-z0-9_]+)\s*\]', clean_code):
            name, sz_str = m.groups()
            sz = defines.get(sz_str)
            if sz is None:
                try: sz = int(sz_str, 0)
                except Exception: pass
            if sz is not None:
                decl_line = content[:m.start()].count('\n') + 1
                arrays[name] = (sz, decl_line)

        # 3. Line-by-Line Regex Rules (High-Confidence Patterns)
        pattern_rules = [
            (
                r'\bgets\s*\(\s*([a-zA-Z0-9_>.-]+)\s*\)',
                "PWN-BOF-001",
                "CRITICAL",
                "CWE-120: Buffer Copy without Checking Size of Input",
                "Tier 1: Stack BOF (ret2win / ret2shellcode / ROP)",
                "Sử dụng hàm đặc biệt nguy hiểm 'gets()'",
                "Hàm 'gets()' đọc dữ liệu từ stdin mà KHÔNG kiểm tra kích thước bộ đệm đích. Bất kỳ input dài nào cũng sẽ ghi đè trực tiếp các biến stack, saved RBP và return address (Saved RIP).",
                ["ret2win (nếu có hàm backdoor/win)", "ret2shellcode (nếu NX tắt)", "ROP chain (ret2libc / ret2csu / SROP)"],
                "cheatsheets/pwn/stack_overflow.html",
                "Thay thế ngay lập tức bằng `fgets(buf, sizeof(buf), stdin)` hoặc `getline()`."
            ),
            (
                r'\bstrcpy\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,\s*([a-zA-Z0-9_>.-]+)\s*\)',
                "PWN-BOF-002",
                "HIGH",
                "CWE-120: Buffer Copy without Checking Size of Input",
                "Tier 1: Stack/Heap BOF",
                "Sao chép chuỗi không giới hạn bằng 'strcpy()'",
                "Hàm 'strcpy()' sao chép chuỗi nguồn cho tới khi gặp ký tự null '\\0', không kiểm soát sức chứa của bộ đệm đích, gây tràn stack hoặc heap.",
                ["Stack Smashing", "Ghi đè Saved RIP", "Làm hỏng Heap metadata"],
                "cheatsheets/pwn/stack_overflow.html",
                "Sử dụng `strncpy(dest, src, sizeof(dest) - 1)` kèm gán null `dest[sizeof(dest)-1] = 0;` hoặc `snprintf()`."
            ),
            (
                r'\bstrcat\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,',
                "PWN-BOF-003",
                "HIGH",
                "CWE-120: Buffer Copy without Checking Size of Input",
                "Tier 1: Stack/Heap BOF",
                "Nối chuỗi không giới hạn bằng 'strcat()'",
                "Hàm 'strcat()' nối chuỗi vào cuối buffer mà không kiểm tra dung lượng còn lại, dễ dẫn tới tràn số byte hoặc lỗi Off-by-one.",
                ["Tràn bộ đệm", "Ghi đè 1-byte (Poison Null Byte / Off-by-one)"],
                "cheatsheets/pwn/stack_overflow.html",
                "Sử dụng `strncat(dest, src, sizeof(dest) - strlen(dest) - 1)`."
            ),
            (
                r'\bsprintf\s*\(\s*([a-zA-Z0-9_>.-]+)\s*,',
                "PWN-BOF-004",
                "HIGH",
                "CWE-120: Buffer Copy without Checking Size of Input",
                "Tier 1: Stack BOF",
                "Ghi chuỗi định dạng không kiểm soát kích thước 'sprintf()'",
                "Hàm 'sprintf()' ghi dữ liệu format vào buffer mà không có giới hạn độ dài tối đa, gây tràn stack nếu dữ liệu format lớn hơn kích thước buffer.",
                ["Stack Overflow", "Khống chế con trỏ lệnh (Control Flow Hijacking)"],
                "cheatsheets/pwn/stack_overflow.html",
                "Thay bằng `snprintf(buf, sizeof(buf), ...)`."
            ),
            (
                r'\b(?:scanf|fscanf|sscanf)\s*\([^)]*"[^"]*%s[^"]*"',
                "PWN-BOF-005",
                "HIGH",
                "CWE-120: Buffer Copy without Checking Size of Input",
                "Tier 1: Stack BOF",
                "Định dạng '%s' không giới hạn độ dài trong scanf",
                "Đặc tả định dạng '%s' trong scanf/fscanf/sscanf nhận chuỗi ký tự bất kỳ cho đến khoảng trắng mà không giới hạn số lượng byte ghi vào buffer đích.",
                ["Stack Buffer Overflow", "Ghi đè con trỏ frame"],
                "cheatsheets/pwn/stack_overflow.html",
                "Chỉ định giới hạn độ dài trong chuỗi định dạng, ví dụ: `%31s` đối với mảng 32 bytes."
            ),
            (
                r'\bprintf\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->|\.)?[a-zA-Z0-9_]*)\s*\)',
                "PWN-FMT-001",
                "CRITICAL",
                "CWE-134: Use of Externally-Controlled Format String",
                "Tier 2: Format String (Leak & Arbitrary Write)",
                "Lỗ hổng Format String trong 'printf(var)'",
                "Biến được truyền trực tiếp làm đối số định dạng đầu tiên thay vì chuỗi hằng. Kẻ tấn công có thể chèn các đặc tả định dạng (%p, %x, %s, %n) để đọc/ghi bộ nhớ tùy ý.",
                [
                    "Arbitrary Memory Read (Leak Canary, Libc base, Stack pointer qua %p/%s)",
                    "Arbitrary Memory Write (Ghi đè bằng %n / %hn / %hhn)",
                    "GOT Overwrite (nếu Partial RELRO) trỏ về system/win",
                    "Saved RIP Overwrite (ghi đè return address trên stack)"
                ],
                "cheatsheets/pwn/fmtstr.html",
                "Luôn truyền chuỗi định dạng cố định: `printf(\"%s\", var);`"
            ),
            (
                r'\bfprintf\s*\(\s*[^,]+,\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->|\.)?[a-zA-Z0-9_]*)\s*\)',
                "PWN-FMT-002",
                "CRITICAL",
                "CWE-134: Use of Externally-Controlled Format String",
                "Tier 2: Format String",
                "Lỗ hổng Format String trong 'fprintf(stream, var)'",
                "Đối số format string của fprintf là biến người dùng kiểm soát.",
                ["Memory Leak", "Arbitrary Memory Write"],
                "cheatsheets/pwn/fmtstr.html",
                "Sử dụng `fprintf(stream, \"%s\", var);`"
            ),
            (
                r'\bdprintf\s*\(\s*[^,]+,\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->|\.)?[a-zA-Z0-9_]*)\s*\)',
                "PWN-FMT-003",
                "CRITICAL",
                "CWE-134: Use of Externally-Controlled Format String",
                "Tier 2: Format String",
                "Lỗ hổng Format String trong 'dprintf(fd, var)'",
                "Đối số format string của dprintf là biến người dùng kiểm soát.",
                ["Memory Leak", "Arbitrary Memory Write"],
                "cheatsheets/pwn/fmtstr.html",
                "Sử dụng `dprintf(fd, \"%s\", var);`"
            ),
            (
                r'\bsyslog\s*\(\s*[^,]+,\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->|\.)?[a-zA-Z0-9_]*)\s*\)',
                "PWN-FMT-004",
                "CRITICAL",
                "CWE-134: Use of Externally-Controlled Format String",
                "Tier 2: Format String",
                "Lỗ hổng Format String trong 'syslog(priority, var)'",
                "Đối số format string của syslog là biến người dùng kiểm soát.",
                ["Format String Attack", "Denial of Service / Memory Leak"],
                "cheatsheets/pwn/fmtstr.html",
                "Sử dụng `syslog(priority, \"%s\", var);`"
            ),
            (
                r'\bmalloc\s*\(\s*strlen\s*\([^)]+\)\s*\)',
                "PWN-HEAP-001",
                "MEDIUM",
                "CWE-131: Permissive List of Allowed Inputs (Missing +1)",
                "Tier 6/Tier 8: Heap Overflow & Poison Null Byte",
                "Cấp phát heap thiếu +1 byte cho ký tự kết thúc chuỗi '\\0'",
                "Hàm `strlen()` trả về số lượng ký tự nhưng KHÔNG tính byte null `\\0` kết thúc chuỗi. Khi chuỗi được sao chép vào buffer này, byte null sẽ bị ghi tràn 1 byte sang chunk kế tiếp.",
                ["Poison Null Byte (Tier 8)", "House of Einherjar", "Ghi đè size / prev_inuse flag của adjacent chunk"],
                "cheatsheets/pwn/heap_advanced.md",
                "Cộng thêm 1 byte cho null terminator: `malloc(strlen(...) + 1);`"
            ),
            (
                r'\bmalloc\s*\(\s*([a-zA-Z0-9_]+)\s*\*\s*(sizeof\([^)]+\)|[a-zA-Z0-9_]+)\s*\)',
                "PWN-INT-001",
                "MEDIUM",
                "CWE-190: Integer Overflow or Wraparound",
                "Tier 6/Tier 8: Heap Integer Overflow",
                "Nguy cơ tràn số nguyên (Integer Overflow) khi nhân kích thước cấp phát",
                "Phép nhân `count * size` có thể vượt quá giới hạn số nguyên (32/64 bit wraparound), dẫn tới malloc cấp phát một vùng nhớ nhỏ trong khi chương trình ghi dữ liệu lớn.",
                ["Heap Buffer Overflow", "Làm hỏng Heap metadata"],
                "cheatsheets/pwn/integer_bugs.html",
                "Dùng `calloc(count, size)` hoặc kiểm tra: `if (count > SIZE_MAX / size) return -1;`"
            ),
            (
                r'\bsystem\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->|\.)?[a-zA-Z0-9_]*)\s*\)',
                "PWN-INJ-001",
                "CRITICAL",
                "CWE-78: Improper Neutralization of Special Elements in OS Command",
                "MISC: Command Injection",
                "Thực thi lệnh hệ thống qua shell 'system(var)'",
                "Biến được truyền trực tiếp vào `system()`, thực thi qua subshell (`/bin/sh -c`). Kẻ tấn công có thể chèn toán tử shell (`;`, `|`, `&&`, `$()`) để chiếm shell tức thì.",
                ["Command Injection (RCE)", "Bỏ qua toàn bộ cơ chế bảo vệ nhị phân (NX/Canary/PIE)"],
                "cheatsheets/pwn/rop_basics.html",
                "Dùng hàm `execve()` hoặc `execv()` với mảng đối số tách rời an toàn, tuyệt đối không dùng shell wrapper."
            ),
            (
                r'\b(?:srand\s*\(\s*time\s*\([^)]*\)\s*\)|rand\s*\(\s*\))',
                "PWN-RAND-001",
                "LOW",
                "CWE-338: Use of Cryptographically Weak PRNG",
                "MISC: Predictable PRNG",
                "Sử dụng bộ sinh số ngẫu nhiên dự đoán được (rand / srand(time))",
                "Hàm `rand()` và seed bằng `time(NULL)` không an toàn mật mã. Kẻ tấn công có thể tính trước seed theo thời gian gửi request để giải mã token hoặc bypass challenge.",
                ["Brute-force Seed", "Dự đoán token ngẫu nhiên"],
                "cheatsheets/pwn/integer_bugs.html",
                "Đọc trực tiếp từ `/dev/urandom` hoặc dùng hàm `getrandom()` của Linux kernel."
            ),
            (
                r'\bsystem\s*\(\s*(?!")([a-zA-Z_][a-zA-Z0-9_>.\[\]-]*)\s*\)',
                "PWN-CMD-001", "CRITICAL", "CWE-78: OS Command Injection",
                "Tier 4: ret2libc / RCE", "Gọi system() với tham số KHÔNG phải hằng chuỗi",
                "system() nhận biến (có thể do người dùng điều khiển) → command injection trực tiếp; đồng thời là đích ret2libc rất tiện cho attacker.",
                ["Command injection (nếu input tới được)", "ret2libc system('/bin/sh')"],
                "cheatsheets/pwn/ret2libc.html",
                "Không truyền input thô vào system(); dùng execve với mảng argv cố định, hoặc bỏ shell."
            ),
            (
                r'\b(?:popen|execlp|execvp|execl|execv)\s*\(\s*([a-zA-Z0-9_>.\[\]\"-]+)',
                "PWN-CMD-002", "HIGH", "CWE-78: OS Command Injection",
                "Tier 4: RCE", "Chạy tiến trình con qua popen/exec* (có thể dùng PATH / shell)",
                "popen/execlp tra PATH và/hoặc chạy qua shell; nếu đối số điều khiển được hoặc PATH thao túng được → thực thi lệnh tuỳ ý.",
                ["Command injection", "PATH hijacking"],
                "cheatsheets/pwn/ret2libc.html",
                "Dùng execve với đường dẫn tuyệt đối + argv cố định; không qua shell."
            ),
            (
                r'\b(?:vsprintf|vsnprintf)\s*\(\s*([a-zA-Z0-9_>.\[\]-]+)\s*,',
                "PWN-FMT-002", "HIGH", "CWE-134: Uncontrolled Format String",
                "Tier 2: Format String", "vsprintf/vsnprintf có thể dính format string / tràn buffer",
                "Nếu chuỗi format tới từ input → format string (leak/ghi tuỳ ý). vsprintf còn không chốt độ dài buffer.",
                ["Leak qua %p", "Arbitrary write qua %n"],
                "cheatsheets/pwn/fmtstr.html",
                "Dùng vsnprintf với format HẰNG; không bao giờ truyền input làm format."
            ),
            (
                r'\b(?:fprintf|dprintf|syslog|err|warn|errx|warnx)\s*\([^,]*,\s*([a-zA-Z_][a-zA-Z0-9_>.\[\]-]*)\s*\)',
                "PWN-FMT-003", "HIGH", "CWE-134: Uncontrolled Format String",
                "Tier 2: Format String", "Format string trong fprintf/syslog/err với đối số format là biến",
                "Đối số format của fprintf/syslog/err là biến (không phải hằng) → attacker nhét %p/%n để leak hoặc ghi bộ nhớ.",
                ["Leak canary/libc (%p)", "Arbitrary write (%n)"],
                "cheatsheets/pwn/fmtstr.html",
                "Thêm format literal: ví dụ `fprintf(f, \"%s\", buf)`, `syslog(pri, \"%s\", msg)`."
            ),
            (
                r'\bmemcpy\s*\(\s*([a-zA-Z0-9_>.\[\]-]+)\s*,\s*[a-zA-Z0-9_>.\[\]-]+\s*,\s*([a-zA-Z_][a-zA-Z0-9_>.\[\]-]*)\s*\)',
                "PWN-BOF-010", "HIGH", "CWE-120/CWE-190: Buffer Overflow via Size",
                "Tier 1: BOF / Integer", "memcpy() với độ dài là BIẾN (user-controlled / có thể âm)",
                "Nếu độ dài do input quyết định và không được chốt trần, hoặc là số có dấu bị cast sang size_t (âm → khổng lồ), memcpy ghi tràn đích.",
                ["Heap/Stack overflow", "Integer→huge size (size_t wrap)"],
                "cheatsheets/pwn/integer_bugs.html",
                "Kiểm `len <= sizeof(dst)` và ép unsigned; từ chối giá trị âm trước khi memcpy."
            ),
            (
                r'\b(?:alloca|__builtin_alloca)\s*\(',
                "PWN-BOF-011", "MEDIUM", "CWE-770: Allocation Without Limits",
                "Tier 1: Stack clash", "Cấp phát stack động bằng alloca()",
                "alloca cấp bộ nhớ trên stack theo kích thước runtime; nếu size từ input → đẩy stack pointer tuỳ ý (stack clash) hoặc tràn.",
                ["Stack clash / ghi đè frame"],
                "cheatsheets/pwn/stack_overflow.html",
                "Tránh alloca với size từ input; dùng malloc có kiểm tra + free."
            ),
            (
                r'\b(?:char|int|short|long|uint8_t|char8_t)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*([a-z_][a-zA-Z0-9_]*)\s*\]',
                "PWN-BOF-012", "MEDIUM", "CWE-129: Improper Validation of Array Index",
                "Tier 1: Stack BOF (VLA)", "Mảng độ dài biến (VLA) — kích thước runtime trên stack",
                "Khai báo mảng với kích thước là biến (VLA). Nếu biến đó từ input và không chốt, stack frame co giãn theo input → tràn/clash.",
                ["Stack overflow qua VLA size"],
                "cheatsheets/pwn/stack_overflow.html",
                "Dùng kích thước HẰNG; hoặc malloc có kiểm tra giới hạn."
            ),
            (
                r'for\s*\([^;]*;\s*[a-zA-Z_][a-zA-Z0-9_]*\s*<=\s*([a-zA-Z0-9_]+)\s*;',
                "PWN-OOB-010", "MEDIUM", "CWE-193: Off-by-one Error",
                "Tier 1: Off-by-one", "Vòng lặp dùng '<=' — khả năng ghi/đọc lố 1 phần tử",
                "Điều kiện `i <= N` lặp tới chỉ số N (thừa 1 so với mảng kích thước N) → off-by-one, ghi 1 byte/phần tử ra ngoài (có thể đụng saved rbp / null byte).",
                ["Off-by-one ghi saved RBP (pivot)", "Poison null byte (heap)"],
                "cheatsheets/pwn/stack_overflow.html",
                "Đổi điều kiện thành `i < N` (hoặc cấp mảng N+1 nếu cố ý)."
            ),
            (
                r'\b(?:malloc|calloc|realloc|alloca)\s*\(\s*[a-zA-Z0-9_>.\[\]-]+\s*[\*\+]\s*[a-zA-Z0-9_>.\[\]-]+',
                "PWN-INT-010", "MEDIUM", "CWE-190: Integer Overflow in Allocation Size",
                "Tier 3: Heap/Integer", "Kích thước cấp phát có phép NHÂN/CỘNG — nguy cơ tràn số nguyên",
                "`malloc(n * size)` / `+` có thể tràn size_t → cấp buffer NHỎ hơn dự kiến, các ghi sau đó tràn heap.",
                ["Heap overflow do allocation nhỏ", "Overlap chunk"],
                "cheatsheets/pwn/integer_bugs.html",
                "Dùng calloc (kiểm tràn sẵn) hoặc kiểm `n <= SIZE_MAX/size` trước khi nhân."
            ),
            (
                r'\bstrncpy\s*\(\s*([a-zA-Z0-9_>.\[\]-]+)\s*,\s*[a-zA-Z0-9_>.\[\]-]+\s*,\s*([a-zA-Z0-9_>.\[\]()-]+)\s*\)',
                "PWN-BOF-013", "LOW", "CWE-170: Improper Null Termination",
                "Tier 1: Info-leak", "strncpy() có thể KHÔNG chốt null khi nguồn đủ dài",
                "strncpy không thêm '\\0' nếu nguồn dài >= n → chuỗi không kết thúc, printf/strlen sau đó đọc lố (info-leak) hoặc tràn.",
                ["Info-leak do chuỗi không kết thúc"],
                "cheatsheets/pwn/leak_techniques.html",
                "Sau strncpy luôn gán `dst[n-1] = '\\0';`."
            ),
            (
                r'\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_>.\[\]-]*)\s*\)\s*;(?:(?!\1\s*=\s*NULL).)*',
                "PWN-HEAP-010", "HIGH", "CWE-416/CWE-415: Use-After-Free / Double-Free",
                "Tier 6: Heap", "free() không gán NULL sau đó — nguy cơ UAF / double-free",
                "Sau free() mà con trỏ không được gán NULL, nếu còn được dùng/được free lần nữa → Use-After-Free hoặc Double-Free (tcache poisoning).",
                ["UAF → leak/ghi qua chunk đã free", "Double-free → tcache/fastbin dup"],
                "cheatsheets/pwn/heap_bugs.html",
                "Luôn `free(p); p = NULL;` và kiểm tra trước khi dùng lại."
            )
        ]

        # Scan line-by-line rules
        for idx, line in enumerate(clean_lines, 1):
            for pat, rule_id, sev, cwe, tier, title, desc, techs, ref, fix in pattern_rules:
                m = re.search(pat, line)
                if m:
                    col = m.start() + 1
                    token = m.group(0)
                    orig_line = lines[idx - 1] if idx <= len(lines) else line
                    f = Finding(
                        file_path=file_path,
                        line=idx,
                        col=col,
                        rule_id=rule_id,
                        title=title,
                        severity=sev,
                        cwe=cwe,
                        tier=tier,
                        description=desc,
                        exploit_techniques=techs,
                        remediation=fix,
                        snippet=orig_line,
                        token=token,
                        cheatsheet_ref=ref,
                        category="pwn"
                    )
                    findings.append(f)

        # 4. Check Buffer Read Size Mismatch (e.g. char name[16]; ... read(0, name, 64);)
        read_pattern = r'\b(?:read|recv|fgets|fread)\s*\(\s*(?:[0-9a-zA-Z_]+,\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([0-9xXa-fA-F]+|\d+)'
        for m in re.finditer(read_pattern, clean_code):
            buf_name, sz_str = m.groups()
            try:
                read_sz = int(sz_str, 0)
                if buf_name in arrays:
                    decl_sz, decl_line = arrays[buf_name]
                    if read_sz > decl_sz:
                        line_num = content[:m.start()].count('\n') + 1
                        col = m.start() - content[:m.start()].rfind('\n')
                        overflow_bytes = read_sz - decl_sz
                        orig_line = lines[line_num - 1] if line_num <= len(lines) else ""
                        findings.append(Finding(
                            file_path=file_path,
                            line=line_num,
                            col=col,
                            rule_id="PWN-BOF-006",
                            title=f"Tràn bộ đệm: Đọc {read_sz} bytes vào mảng '{buf_name}' chỉ có {decl_sz} bytes (+{overflow_bytes} bytes)",
                            severity="CRITICAL",
                            cwe="CWE-120: Buffer Copy without Checking Size of Input",
                            tier="Tier 1: Stack Buffer Overflow",
                            description=f"Biến mảng '{buf_name}' khai báo tại dòng {decl_line} với kích thước {decl_sz} bytes, nhưng hàm đọc nhận tối đa tới {read_sz} bytes (tràn {overflow_bytes} bytes bộ đệm).",
                            exploit_techniques=["Ghi đè Saved RBP / Saved RIP trên Stack", "ret2win / ret2libc / ROP chain"],
                            remediation=f"Giới hạn số byte đọc đúng bằng kích thước mảng: `sizeof({buf_name})`.",
                            snippet=orig_line,
                            token=m.group(0),
                            cheatsheet_ref="cheatsheets/pwn/stack_overflow.html",
                            category="pwn"
                        ))
            except Exception:
                pass

        # 5. Semantic Analysis per Function: UAF, Double-Free, Signedness, Negative OOB
        func_pattern = re.compile(
            r'^[ \t]*(?:[a-zA-Z_][a-zA-Z0-9_* \t]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )
        for m in func_pattern.finditer(clean_code):
            func_name = m.group(1)
            args_str = m.group(2)
            func_start = m.end()

            # Trace matching brace for function body
            depth = 1
            pos = func_start
            while pos < len(clean_code) and depth > 0:
                if clean_code[pos] == '{': depth += 1
                elif clean_code[pos] == '}': depth -= 1
                pos += 1
            func_body = clean_code[func_start:pos]
            func_body_lines = func_body.splitlines()
            body_start_line = content[:func_start].count('\n') + 1

            # A. Track Signed Variables & Map local vars to structs
            signed_vars: Set[str] = set()
            var_to_struct: Dict[str, str] = {}
            for sname in struct_types:
                for m_var in re.finditer(rf'\b{re.escape(sname)}\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', func_body):
                    var_to_struct[m_var.group(1)] = sname
                for m_var in re.finditer(rf'\b{re.escape(sname)}\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)\b', args_str + ';' + func_body):
                    var_to_struct[m_var.group(1)] = sname

            for arg in args_str.split(','):
                m_arg = re.search(r'\b(int|short|long|ssize_t|int8_t|int16_t|int32_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', arg.strip())
                if m_arg and 'unsigned' not in arg:
                    signed_vars.add(m_arg.group(2))
            for m_decl in re.finditer(r'\b(int|short|long|ssize_t|int8_t|int16_t|int32_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|;|,)', func_body):
                prefix = func_body[max(0, m_decl.start()-10):m_decl.start()]
                if 'unsigned' not in prefix:
                    signed_vars.add(m_decl.group(2))

            # B. Check Signed Bound & Negative Indexing (Supports struct members like hdr.length)
            cond_pattern = re.compile(r'if\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:(?:\.|->)[a-zA-Z_][a-zA-Z0-9_]*)*)\s*(?:<|<=)\s*([0-9xXa-fA-F]+|[A-Za-z0-9_]+)\s*\)')
            for m_cond in cond_pattern.finditer(func_body):
                vname = m_cond.group(1)
                lim_str = m_cond.group(2)
                lim_val = defines.get(lim_str)
                if lim_val is None:
                    try:
                        lim_val = int(lim_str, 0)
                    except Exception:
                        lim_val = 1
                
                # Skip error checks like if (fd < 0) or if (res <= 0)
                if lim_val <= 0:
                    continue

                is_signed = vname in signed_vars
                if not is_signed and ('.' in vname or '->' in vname):
                    base, field = re.split(r'\.|->', vname, maxsplit=1)
                    if base in var_to_struct:
                        stype = var_to_struct[base]
                        if field in struct_types.get(stype, {}):
                            is_signed = True
                    elif any(field in fmap for sname, fmap in struct_types.items() if sname in var_to_struct.values()):
                        is_signed = True

                if is_signed:
                    # Look ahead inside the branch (up to 1000 chars)
                    branch_text = func_body[m_cond.end():m_cond.end() + 1000]
                    cond_line = body_start_line + func_body[:m_cond.start()].count('\n')
                    orig_line = lines[cond_line - 1] if cond_line <= len(lines) else ""

                    # Negative array indexing
                    if re.search(rf'\[\s*{re.escape(vname)}\s*\]', branch_text):
                        findings.append(Finding(
                            file_path=file_path,
                            line=cond_line,
                            col=1,
                            rule_id="PWN-OOB-001",
                            title=f"Chỉ số mảng âm OOB: Biến có dấu '{vname}' thiếu kiểm tra '>= 0'",
                            severity="HIGH",
                            cwe="CWE-125: Out-of-bounds Read / CWE-787: Out-of-bounds Write",
                            tier="Tier 4: Out-Of-Bounds (OOB) Memory Access",
                            description=f"Biến có dấu '{vname}' chỉ kiểm tra cận trên (`{vname} <= {lim_str}`) mà không kiểm tra cận dưới (`{vname} >= 0`). Giá trị âm sẽ truy cập vùng nhớ phía trước mảng (Negative Indexing).",
                            exploit_techniques=["Relative Arbitrary Read (leak canary / libc)", "Relative Arbitrary Write (ghi đè GOT / Saved Frame)"],
                            remediation=f"Dùng kiểu không dấu `size_t {vname}` hoặc thêm điều kiện: `if ({vname} >= 0 && {vname} <= {lim_str})`.",
                            snippet=orig_line,
                            token=m_cond.group(0),
                            cheatsheet_ref="cheatsheets/pwn/oob.html",
                            category="pwn"
                        ))

                    # Signed integer passed to size
                    if re.search(rf'\b(?:read|recv|malloc|memcpy|memmove)\s*\([^;]*\b{re.escape(vname)}\b', branch_text):
                        findings.append(Finding(
                            file_path=file_path,
                            line=cond_line,
                            col=1,
                            rule_id="PWN-INT-002",
                            title=f"Lỗi so sánh số nguyên có dấu (Signed Comparison Bug) trên '{vname}'",
                            severity="HIGH",
                            cwe="CWE-195: Signed to Unsigned Conversion Error",
                            tier="Tier 1/Tier 4: Integer Signedness Exploitation",
                            description=f"Biến '{vname}' là số có dấu. Nếu nhận số âm (ví dụ -1), điều kiện `{vname} <= {lim_str}` sẽ thỏa mãn, nhưng khi chuyển vào hàm (read/malloc/memcpy) tham số size_t là số không dấu, -1 sẽ biến thành 0xFFFFFFFF (4GB) gây tràn bộ đệm nghiêm trọng.",
                            exploit_techniques=["Bypass kiểm tra kích thước", "Tràn bộ đệm cực lớn (Massive Buffer Overflow)"],
                            remediation=f"Khai báo `{vname}` dưới dạng `size_t` hoặc kiểm tra chặt chẽ `if ({vname} >= 0 && {vname} <= {lim_str})`.",
                            snippet=orig_line,
                            token=m_cond.group(0),
                            cheatsheet_ref="cheatsheets/pwn/integer_bugs.html",
                            category="pwn"
                        ))

            # C. Track Heap: Use-After-Free & Double Free (Intra-procedural & Inter-procedural)
            freed_pointers: Dict[str, Tuple[int, str, str]] = {} # ptr_name -> (line, orig_line, origin_func)
            for rel_idx, bline in enumerate(func_body_lines):
                cur_abs_line = body_start_line + rel_idx
                orig_line = lines[cur_abs_line - 1] if cur_abs_line <= len(lines) else bline

                # Check direct free(ptr)
                m_free = re.search(r'\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->[a-zA-Z_][a-zA-Z0-9_]*|\[[^\]]+\])?)\s*\)', bline)
                if m_free:
                    ptr_name = m_free.group(1).strip()
                    if ptr_name in freed_pointers:
                        prev_line, _, _ = freed_pointers[ptr_name]
                        findings.append(Finding(
                            file_path=file_path,
                            line=cur_abs_line,
                            col=m_free.start() + 1,
                            rule_id="PWN-DF-001",
                            title=f"Lỗ hổng Double Free trên con trỏ '{ptr_name}'",
                            severity="CRITICAL",
                            cwe="CWE-415: Double Free",
                            tier="Tier 6/Tier 7: Heap Exploitation (Fastbin Dup / Tcache Dup)",
                            description=f"Con trỏ '{ptr_name}' đã được giải phóng tại dòng {prev_line}, nhưng lại được gọi `free()` lần thứ hai tại đây mà không có cấp phát lại hay gán NULL.",
                            exploit_techniques=["Fastbin Dup", "Tcache Dup / Tcache Poisoning", "House of Botcake (T8)"],
                            remediation=f"Gán con trỏ bằng NULL ngay sau khi giải phóng: `free({ptr_name}); {ptr_name} = NULL;`",
                            snippet=orig_line,
                            token=m_free.group(0),
                            cheatsheet_ref="cheatsheets/pwn/heap_bugs.html",
                            category="pwn"
                        ))
                    else:
                        # If in main() near the very end, suppress dangling pointer false positive
                        is_main_end = (func_name == "main" and rel_idx >= len(func_body_lines) - max(4, int(len(func_body_lines) * 0.15)))
                        freed_pointers[ptr_name] = (cur_abs_line, bline, "free")

                        if not is_main_end:
                            # Check dangling pointer: next line nullification check
                            nullified = False
                            if rel_idx + 1 < len(func_body_lines):
                                nxt = func_body_lines[rel_idx + 1]
                                if re.search(rf'\b{re.escape(ptr_name)}\s*=\s*(?:NULL|0)\b', nxt):
                                    nullified = True
                            if not nullified:
                                findings.append(Finding(
                                    file_path=file_path,
                                    line=cur_abs_line,
                                    col=m_free.start() + 1,
                                    rule_id="PWN-HEAP-002",
                                    title=f"Con trỏ treo (Dangling Pointer): '{ptr_name}' được free() nhưng không gán NULL",
                                    severity="MEDIUM",
                                    cwe="CWE-416: Use After Free (Dangling Pointer)",
                                    tier="Tier 6: Heap Intro & Dangling Pointers",
                                    description=f"Con trỏ '{ptr_name}' sau khi giải phóng vẫn giữ nguyên địa chỉ ô nhớ cũ. Nếu một luồng hoặc logic khác tiếp tục truy cập, sẽ dẫn tới Use-After-Free.",
                                    exploit_techniques=["Tạo tiền đề cho Use-After-Free", "Tcache poisoning"],
                                    remediation=f"Luôn gán NULL ngay sau khi free: `free({ptr_name}); {ptr_name} = NULL;`",
                                    snippet=orig_line,
                                    token=m_free.group(0),
                                    cheatsheet_ref="cheatsheets/pwn/heap.md",
                                    category="pwn"
                                ))
                    continue

                # Check call to helper function that frees members (inter-procedural)
                for helper_fn, freed_list in func_frees.items():
                    m_call = re.search(rf'\b{re.escape(helper_fn)}\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:->[a-zA-Z_][a-zA-Z0-9_]*)?)\s*\)', bline)
                    if m_call:
                        arg_expr = m_call.group(1).strip()
                        for _, field in freed_list:
                            target_member = f"{arg_expr}->{field}"
                            freed_pointers[target_member] = (cur_abs_line, bline, helper_fn)

                # Check if ptr is re-assigned/re-allocated (clear from freed)
                for ptr_name in list(freed_pointers.keys()):
                    if re.search(rf'\b{re.escape(ptr_name)}\s*=\s*', bline):
                        del freed_pointers[ptr_name]

                # Check Use-After-Free
                for ptr_name, (free_line, _, forigin) in list(freed_pointers.items()):
                    if cur_abs_line == free_line:
                        continue
                    # Match dereference, array indexing, member access, or passed to function
                    if re.search(rf'(\*\s*{re.escape(ptr_name)}|{re.escape(ptr_name)}\s*\[|{re.escape(ptr_name)}\s*->|\b[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\b{re.escape(ptr_name)}\b)', bline):
                        origin_desc = f"bởi hàm '{forigin}()'" if forigin != "free" else "bằng `free()`"
                        findings.append(Finding(
                            file_path=file_path,
                            line=cur_abs_line,
                            col=1,
                            rule_id="PWN-UAF-001",
                            title=f"Lỗ hổng Use-After-Free (UAF) trên '{ptr_name}'",
                            severity="CRITICAL",
                            cwe="CWE-416: Use After Free",
                            tier="Tier 6: Heap UAF (Control Flow Hijack & Tcache Poisoning)",
                            description=f"Con trỏ '{ptr_name}' đã được giải phóng {origin_desc} tại dòng {free_line}, nhưng lại được truy cập/dereference tại đây mà không qua cấp phát mới.",
                            exploit_techniques=[
                                "Hijack vtable / Function Pointer nếu chunk chứa struct/con trỏ hàm",
                                "Tcache Poisoning: Ghi đè forward pointer 'fd' để cấp phát chunk tùy ý",
                                "Fastbin Attack / Leak Heap Base (Tier 6/7)"
                            ],
                            remediation=f"Tuyệt đối không dùng con trỏ sau khi free. Đảm bảo gán `{ptr_name} = NULL;` ngay sau giải phóng và kiểm tra `if ({ptr_name})` trước khi dùng.",
                            snippet=orig_line,
                            token=ptr_name,
                            cheatsheet_ref="cheatsheets/pwn/heap_bugs.html",
                            category="pwn"
                        ))

        # 6. Race Conditions: TOCTOU (access() before open())
        toctou_pattern = re.compile(r'\baccess\s*\(\s*([^,]+)\s*,\s*[^)]+\)')
        for m_acc in toctou_pattern.finditer(clean_code):
            path_var = m_acc.group(1).strip()
            acc_pos = m_acc.end()
            lookahead = clean_code[acc_pos:acc_pos + 400]
            if re.search(rf'\b(?:open|fopen)\s*\(\s*{re.escape(path_var)}\b', lookahead):
                line_num = content[:m_acc.start()].count('\n') + 1
                col = m_acc.start() - content[:m_acc.start()].rfind('\n')
                orig_line = lines[line_num - 1] if line_num <= len(lines) else ""
                findings.append(Finding(
                    file_path=file_path,
                    line=line_num,
                    col=col,
                    rule_id="PWN-RACE-001",
                    title=f"Lỗ hổng Race Condition (TOCTOU) khi kiểm tra 'access()' trước 'open()'",
                    severity="MEDIUM",
                    cwe="CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition",
                    tier="Tier 4: Race Condition & File Access Races",
                    description=f"Chương trình gọi `access({path_var})` để kiểm tra quyền truy cập rồi mới gọi `open()`. Kẻ tấn công có thể thay thế tệp (bằng symlink) trong khoảng thời gian giữa hai lời gọi hàm để đọc/ghi tệp tùy quyền hạn.",
                    exploit_techniques=["Symlink Race Condition", "Privilege Escalation", "File overwrite"],
                    remediation="Tránh dùng `access()` để kiểm tra trước. Mở trực tiếp bằng `open()` với các cờ `O_CREAT | O_EXCL` và xử lý mã lỗi trả về.",
                    snippet=orig_line,
                    token=m_acc.group(0),
                    cheatsheet_ref="cheatsheets/pwn/race_condition.html",
                    category="pwn"
                ))

        # 7. Off-by-One / Poison Null Byte (read up to SIZE then buf[bytes_read] = 0)
        read_null_pat = re.compile(
            r'\b(?:int|ssize_t|long)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:read|recv|read_all)\s*\(\s*[^,]+,\s*([^,]+),\s*([^)]+)\);'
            r'.{0,350}?'
            r'\b\2\s*\[\s*\1\s*\]\s*=\s*(?:0|\'\\0\');',
            re.DOTALL
        )
        for m_null in read_null_pat.finditer(clean_code):
            var_ret, buf_expr, sz_expr = m_null.groups()
            line_num = content[:m_null.start()].count('\n') + 1
            col = m_null.start() - content[:m_null.start()].rfind('\n')
            orig_line = lines[line_num - 1] if line_num <= len(lines) else ""
            findings.append(Finding(
                file_path=file_path,
                line=line_num,
                col=col,
                rule_id="PWN-BOF-007",
                title=f"Ghi đè 1-byte Null (Poison Null Byte / Off-By-One) vào '{buf_expr.strip()}[{var_ret}]'",
                severity="HIGH",
                cwe="CWE-193: Off-by-one Error (Poison Null Byte Flaw)",
                tier="Tier 4 / Tier 8: Poison Null Byte (House of Einherjar)",
                description=f"Hàm đọc nhận tối đa `{sz_expr.strip()}` bytes vào `{buf_expr.strip()}`. Nếu đọc đủ số byte tối đa, lệnh gán null `{buf_expr.strip()}[{var_ret}] = 0;` sẽ ghi tràn đúng 1 byte null vào ô nhớ liền kề.",
                exploit_techniques=[
                    "Poison Null Byte (House of Einherjar / T8)",
                    "Ghi đè byte thấp của `size` chunk kế tiếp trên Heap",
                    "Xóa cờ `PREV_INUSE` dẫn tới backward consolidation tạo overlapping chunks",
                    "Stack Pivot nếu biến nằm trên stack (đè byte thấp của saved RBP)"
                ],
                remediation=f"Đọc tối đa `sizeof(buf) - 1` byte hoặc kiểm tra: `if ({var_ret} < sizeof(buf)) {buf_expr.strip()}[{var_ret}] = 0;`",
                snippet=orig_line,
                token=m_null.group(0).splitlines()[0],
                cheatsheet_ref="cheatsheets/pwn/heap_advanced.md",
                category="pwn"
            ))

        return findings

# ==============================================================================
# Web Scanner Engine (PHP, Python, JS SAST)
# ==============================================================================
class WebScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.category = "web"

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        is_py = file_path.endswith('.py')
        clean_code = self.strip_comments(content, is_python=is_py)
        lines = content.splitlines()
        clean_lines = clean_code.splitlines()

        web_rules = [
            # SQL Injection PHP (String embedding or concatenation)
            (
                r'\$(?:sql|query|cmd)\s*=\s*(?:["\'][^"\']*\$(?:_GET|_POST|_REQUEST|[a-zA-Z0-9_]+)|["\'][^"\']*["\']\s*\.\s*\$(?:_GET|_POST|_REQUEST|[a-zA-Z0-9_]+))',
                "WEB-SQLI-001", "CRITICAL", "CWE-89: SQL Injection", "Web: SQL Injection",
                "Ghép chuỗi trực tiếp vào câu lệnh SQL (PHP)",
                "Dữ liệu người dùng được ghép trực tiếp vào chuỗi truy vấn SQL thay vì sử dụng Prepared Statements.",
                ["SQL Injection", "Bypass xác thực", "Trích xuất toàn bộ cơ sở dữ liệu"],
                "Sử dụng PDO Prepared Statements với tham số ràng buộc `bindValue()` / `bindParam()`."
            ),
            # SQL Injection Python
            (
                r'f["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\{',
                "WEB-SQLI-002", "CRITICAL", "CWE-89: SQL Injection", "Web: SQL Injection",
                "Ghép f-string vào truy vấn SQL (Python)",
                "Sử dụng Python f-string để định dạng chuỗi truy vấn SQL cho phép kẻ tấn công chèn mã SQL độc hại.",
                ["SQL Injection", "Trích xuất cờ/database", "Bypass authentication (' OR '1'='1)"],
                "Truyền tham số qua tuple/dict: `cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))`."
            ),
            (
                r'(?:\.execute|\.raw)\s*\(\s*f["\'].*?\{',
                "WEB-SQLI-003", "CRITICAL", "CWE-89: SQL Injection", "Web: SQL Injection",
                "Ghép f-string trực tiếp vào lệnh execute SQL (Python)",
                "Truyền f-string trực tiếp vào cursor.execute() gây lỗ hổng SQL Injection.",
                ["SQL Injection", "Trích xuất dữ liệu"],
                "Truyền tham số qua parameterization: `cursor.execute('SELECT ... WHERE u = ?', (user,))`."
            ),
            # Command Injection PHP
            (
                r'\b(?:system|shell_exec|exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)',
                "WEB-INJ-001", "CRITICAL", "CWE-78: Command Injection", "Web: Remote Command Execution",
                "Thực thi shell command trực tiếp từ tham số người dùng (PHP)",
                "Dữ liệu nhận từ HTTP request được chuyển thẳng vào shell command.",
                ["Remote Code Execution (RCE)", "Webshell injection"],
                "Tránh dùng shell execution. Dùng API chuyên dụng hoặc `escapeshellarg()` / `escapeshellcmd()`."
            ),
            # Command Injection Python
            (
                r'\bsubprocess\.(?:Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True',
                "WEB-INJ-002", "HIGH", "CWE-78: Command Injection", "Web: Command Injection",
                "Kích hoạt shell=True trong subprocess (Python)",
                "Việc bật `shell=True` cho phép kẻ tấn công sử dụng các ký tự toán tử shell để thực thi lệnh tùy ý.",
                ["Command Injection"],
                "Tắt `shell=False` và truyền mảng tham số: `subprocess.run(['ls', '-la', path])`."
            ),
            # Insecure Deserialization
            (
                r'\bpickle\.loads\s*\(',
                "WEB-DESER-001", "CRITICAL", "CWE-502: Deserialization of Untrusted Data", "Web: Insecure Deserialization",
                "Deserialization không an toàn bằng Python 'pickle.loads()'",
                "Module pickle có khả năng thực thi mã tùy ý khi deserialize object (`__reduce__` exploit).",
                ["Remote Code Execution (RCE) qua __reduce__"],
                "Thay bằng định dạng dữ liệu an toàn như JSON hoặc Protocol Buffers."
            ),
            (
                r'\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
                "WEB-DESER-002", "CRITICAL", "CWE-502: Deserialization of Untrusted Data", "Web: Insecure Deserialization",
                "PHP Object Injection qua 'unserialize()'",
                "Dữ liệu người dùng gửi lên được giải mã bằng `unserialize()`, cho phép kích hoạt các POP Gadget Chains trong mã nguồn.",
                ["PHP Object Injection", "Remote Code Execution qua Magic Methods (__destruct, __wakeup)"],
                "Sử dụng `json_decode()` thay thế."
            ),
            # Path Traversal & LFI
            (
                r'\b(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)',
                "WEB-LFI-001", "CRITICAL", "CWE-22: Path Traversal", "Web: Local File Inclusion",
                "Local/Remote File Inclusion (LFI/RFI) trong PHP",
                "Đường dẫn file trong `include/require` lấy trực tiếp từ tham số URL, cho phép đọc tệp nhạy cảm (/etc/passwd) hoặc thực thi mã qua wrapper php://.",
                ["LFI to RCE", "Đọc mã nguồn và secret configuration"],
                "Sử dụng danh sách trắng (whitelist) các file được phép nạp."
            ),
            (
                r'\b(?:readfile|file_get_contents)\s*\(\s*\$_(?:GET|POST|REQUEST)',
                "WEB-TRAV-001", "HIGH", "CWE-22: Path Traversal", "Web: Arbitrary File Read",
                "Đọc file tùy ý qua tham số người dùng (PHP)",
                "Hàm đọc file nhận trực tiếp tham số đầu vào mà không qua chuẩn hóa kiểm tra path traversal.",
                ["Arbitrary File Read", "Đọc source code / cấu hình nhạy cảm"],
                "Chuẩn hóa đường dẫn bằng `basename()` hoặc `realpath()` và kiểm tra đường dẫn gốc (root dir)."
            ),
            # Server-Side Template Injection (SSTI)
            (
                r'\brender_template_string\s*\(',
                "WEB-SSTI-001", "CRITICAL", "CWE-1336: Improper Neutralization of Special Elements used in a Template Engine", "Web: SSTI",
                "Lỗ hổng Server-Side Template Injection qua 'render_template_string()'",
                "Truyền dữ liệu không kiểm soát vào hàm render template dạng chuỗi cho phép kẻ tấn công inject cú pháp Jinja2 để RCE.",
                ["SSTI to RCE", "Đọc config / env secrets"],
                "Chuyển sang sử dụng `render_template()` với template file cố định và truyền biến qua context parameter."
            ),
            # SSRF
            (
                r'\b(?:requests\.(?:get|post|put)|urllib\.request\.urlopen)\s*\(\s*(?:request\.(?:args|form|values)|[a-zA-Z0-9_]*url)',
                "WEB-SSRF-001", "HIGH", "CWE-918: Server-Side Request Forgery (SSRF)", "Web: SSRF",
                "Server-Side Request Forgery qua HTTP Client (Python)",
                "Máy chủ thực hiện gửi HTTP request tới địa chỉ do client chỉ định mà không qua kiểm tra địa chỉ IP nội bộ.",
                ["SSRF", "Truy cập cloud metadata", "Quét mạng nội bộ"],
                "Kiểm tra và chặn các dải IP Private (RFC 1918) và Loopback (127.0.0.1, 169.254.169.254)."
            ),
            # Hardcoded Secrets
            (
                r'\b(?:JWT_SECRET|API_KEY|SECRET_KEY|DATABASE_PASSWORD)\s*=\s*["\'][^"\']{6,}["\']',
                "WEB-SECRET-001", "MEDIUM", "CWE-798: Use of Hard-coded Credentials", "Web: Hardcoded Secret",
                "Khóa bí mật hoặc API Key được gán cứng trong mã nguồn",
                "Các khóa bảo mật được lưu trực tiếp trong mã nguồn dễ bị lộ lọt khi chia sẻ repo hoặc dịch ngược.",
                ["Token forgery", "Bypass xác thực"],
                "Đọc bí mật từ biến môi trường qua `os.environ.get('SECRET_KEY')` hoặc tệp `.env` an toàn."
            ),
            (
                r'\bos\.(?:system|popen)\s*\([^)]*(?:request\.|input\s*\(|sys\.argv|\+)',
                "WEB-INJ-003", "CRITICAL", "CWE-78: OS Command Injection", "Web: Command Injection (Python)",
                "os.system()/os.popen() với dữ liệu người dùng (ghép chuỗi)",
                "Input người dùng được ghép vào lệnh os.system/os.popen → chèn `; id`, `$(cat /flag)`...",
                ["RCE", "Đọc /flag qua `; cat /flag`"],
                "Dùng subprocess.run([...], shell=False) với argv cố định; không ghép input vào shell."
            ),
            (
                r'\b(?:eval|exec)\s*\(\s*(?!["\'])[^)]*(?:request\.|input\s*\(|data|payload|user)',
                "WEB-EVAL-001", "CRITICAL", "CWE-95: Eval Injection", "Web: Code Injection (eval/exec)",
                "eval()/exec() trên dữ liệu người dùng",
                "eval/exec thực thi chuỗi Python tuỳ ý. Nếu chuỗi tới từ input → RCE trực tiếp.",
                ["RCE: `__import__('os').system('cat /flag')`"],
                "Không dùng eval/exec với input; dùng ast.literal_eval cho dữ liệu literal."
            ),
            (
                r'\brender_template_string\s*\(',
                "WEB-SSTI-002", "CRITICAL", "CWE-1336: SSTI (Jinja2)", "Web: Server-Side Template Injection",
                "render_template_string() — SSTI Jinja2 nếu template chứa input",
                "Ghép input vào template string của Jinja2 → `{{7*7}}` → RCE qua `{{config}}`/`{{''.__class__...}}`.",
                ["SSTI → RCE", "Đọc config/secret, chạy lệnh (cycler/subprocess)"],
                "render_template với file tĩnh + truyền biến qua context; không ghép input vào template."
            ),
            (
                r'\bopen\s*\(\s*(?:[^)]*\+\s*)?(?:request\.|flask\.request|.*\.args|.*\.form)',
                "WEB-TRAV-002", "HIGH", "CWE-22: Path Traversal", "Web: Arbitrary File Read",
                "open() với đường dẫn từ người dùng → đọc file tuỳ ý (../../flag)",
                "Tên file do input quyết định mà không chuẩn hoá → `../../../flag`, `/etc/passwd`.",
                ["Path traversal đọc /flag", "Lộ source/cấu hình"],
                "Chuẩn hoá: `os.path.realpath` + kiểm tra nằm trong thư mục cho phép; whitelist tên file."
            ),
            (
                r'\byaml\.(?:load|unsafe_load|full_load)\s*\((?![^)]*Safe)',
                "WEB-DESER-003", "CRITICAL", "CWE-502: Insecure Deserialization (YAML)", "Web: YAML Deserialization",
                "yaml.load() không dùng SafeLoader → RCE",
                "yaml.load mặc định (hoặc unsafe_load) cho phép `!!python/object/apply:os.system` → thực thi lệnh.",
                ["RCE qua YAML tag `!!python/object/apply`"],
                "Dùng `yaml.safe_load()` (SafeLoader)."
            ),
            (
                r'\b(?:etree\.(?:parse|fromstring)|lxml\.etree|XMLParser\s*\()',
                "WEB-XXE-001", "HIGH", "CWE-611: XML External Entity (XXE)", "Web: XXE",
                "Phân tích XML — nguy cơ XXE nếu bật external entity",
                "Parser XML mặc định có thể giải entity ngoài → đọc file (`<!ENTITY xxe SYSTEM 'file:///flag'>`) hoặc SSRF.",
                ["XXE đọc /flag", "SSRF/OOB exfil"],
                "Tắt entity: `XMLParser(resolve_entities=False, no_network=True)`; hoặc defusedxml."
            ),
            (
                r'\bapp\.run\s*\([^)]*debug\s*=\s*True',
                "WEB-DEBUG-001", "HIGH", "CWE-489: Active Debug Code", "Web: Flask Debug/Werkzeug Console",
                "Flask chạy debug=True → Werkzeug console (RCE nếu lộ PIN)",
                "debug=True bật Werkzeug interactive debugger; nếu truy cập được /console (và bypass/biết PIN) → thực thi Python = RCE.",
                ["Werkzeug console RCE", "Lộ traceback/biến môi trường"],
                "Tắt debug trong production: `app.run(debug=False)`."
            ),
            # Reflected XSS PHP
            (
                r'\b(?:echo|print)\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)',
                "WEB-XSS-001", "MEDIUM", "CWE-79: Cross-Site Scripting", "Web: Reflected XSS",
                "In trực tiếp input người dùng ra HTML (PHP)",
                "Dữ liệu từ request được echo thẳng ra trang mà không mã hoá HTML → chèn `<script>` đánh cắp session/thao tác thay nạn nhân.",
                ["Reflected XSS", "Đánh cắp cookie/session admin", "CSRF kết hợp"],
                "Mã hoá output bằng `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')` trước khi in."
            ),
            # XSS Flask dùng Markup / |safe
            (
                r'\bMarkup\s*\(\s*(?:request\.|.*\.args|.*\.form|f["\'])',
                "WEB-XSS-002", "MEDIUM", "CWE-79: Cross-Site Scripting", "Web: Stored/Reflected XSS",
                "Bọc input bằng Markup() (tắt auto-escape Jinja2)",
                "Markup() đánh dấu chuỗi là HTML an toàn, bỏ qua auto-escape của Jinja2 → input chứa `<script>` thực thi trên trình duyệt nạn nhân.",
                ["XSS", "Chiếm phiên admin"],
                "Không bọc input bằng Markup; để Jinja2 auto-escape, hoặc sanitize bằng bleach."
            ),
            # JWT: tắt verify / chấp nhận alg none
            (
                r'\bjwt\.decode\s*\([^)]*(?:verify\s*=\s*False|algorithms\s*=\s*\[\s*["\']none)',
                "WEB-JWT-001", "CRITICAL", "CWE-347: Improper Verification of Cryptographic Signature", "Web: JWT Forgery",
                "jwt.decode tắt kiểm chữ ký hoặc chấp nhận alg=none",
                "verify=False (hoặc algorithms=['none']) bỏ qua xác thực chữ ký → kẻ tấn công tự tạo token admin tuỳ ý.",
                ["JWT forgery: đổi `{\"user\":\"admin\"}` không cần secret", "Bypass authentication"],
                "Luôn verify với algorithms cố định: `jwt.decode(t, key, algorithms=['HS256'])`; không bao giờ dùng 'none'."
            ),
            # JWT: không chỉ định algorithms (PyJWT cũ chấp nhận mọi alg)
            (
                r'\bjwt\.decode\s*\((?![^)]*(?:algorithms|verify))[^)]*\)',
                "WEB-JWT-002", "HIGH", "CWE-347: Improper Verification of Cryptographic Signature", "Web: JWT alg confusion",
                "jwt.decode không chỉ định 'algorithms' → nguy cơ alg confusion (RS256→HS256)",
                "Thiếu tham số algorithms cho phép tấn công đổi RS256 sang HS256 dùng public key làm HMAC secret → giả mạo token.",
                ["JWT alg confusion (RS256 → HS256)", "Forge admin token bằng public key"],
                "Chỉ định rõ `algorithms=['RS256']` (hoặc HS256), khớp đúng loại khoá."
            ),
            # NoSQL Injection (MongoDB)
            (
                r'\.(?:find|find_one|update_one|delete_one|aggregate)\s*\(\s*\{[^}]*(?:request\.(?:json|args|form|values)|req\.(?:body|query|params))',
                "WEB-NOSQL-001", "HIGH", "CWE-943: NoSQL Injection", "Web: NoSQL Injection",
                "Truyền object request thẳng vào truy vấn MongoDB",
                "Dict từ request đưa trực tiếp vào query cho phép toán tử như `{\"$ne\": null}`, `{\"$gt\": \"\"}` → bypass xác thực hoặc trích dữ liệu.",
                ["NoSQL auth bypass `{\"$ne\":null}`", "Blind data extraction `$regex`"],
                "Ép kiểu/validate từng field (str/int) trước khi đưa vào query; không nhận raw dict."
            ),
            # Open Redirect
            (
                r'\b(?:redirect|Location["\']?\s*[:,])\s*(?:request\.(?:args|values|form)\b|.*\.args\.get\()',
                "WEB-REDIR-001", "MEDIUM", "CWE-601: Open Redirect", "Web: Open Redirect",
                "Chuyển hướng tới URL do người dùng cung cấp",
                "Tham số redirect lấy trực tiếp từ request → lừa nạn nhân tới site phishing hoặc chuỗi SSRF/OAuth token theft.",
                ["Phishing qua redirect tin cậy", "OAuth token/redirect_uri theft"],
                "Whitelist đích hợp lệ; chỉ cho phép đường dẫn tương đối nội bộ, chặn `//` và scheme ngoài."
            ),
            # File upload không làm sạch tên / không giới hạn phần mở rộng
            (
                r'\b(?:save|move_uploaded_file|write)\s*\([^)]*(?:request\.files|\$_FILES)(?![^)]*secure_filename)',
                "WEB-UPLOAD-001", "HIGH", "CWE-434: Unrestricted File Upload", "Web: Dangerous File Upload",
                "Lưu file tải lên không qua secure_filename / kiểm tra đuôi",
                "Tên/đuôi file do client quyết định → upload webshell (.php/.jsp) hoặc path traversal `../` ghi đè file hệ thống.",
                ["Upload .php → RCE webshell", "Path traversal ghi đè qua `../`"],
                "Dùng `secure_filename()`, whitelist đuôi an toàn, lưu ngoài webroot, đổi tên ngẫu nhiên."
            ),
            # PHP type juggling: == trên hash (magic hash 0e...)
            (
                r'\b(?:md5|sha1|crypt)\s*\([^)]*\)\s*==(?!=)',
                "WEB-TYPEJUGGLE-001", "HIGH", "CWE-697: Incorrect Comparison", "Web: PHP Type Juggling (Magic Hash)",
                "So sánh lỏng `==` trên giá trị hash (PHP magic hash 0e)",
                "PHP `==` coi hai hash dạng `0e\\d+` là bằng nhau (0 mũ gì cũng =0) → bypass so sánh mật khẩu/token bằng magic hash.",
                ["Auth bypass bằng magic hash `0e...`", "Token/password comparison bypass"],
                "Luôn dùng so sánh nghiêm ngặt `===`, hoặc `hash_equals()` cho giá trị bảo mật."
            ),
            # PHP loose compare input vs biến bí mật
            (
                r'\bif\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*==(?!=)',
                "WEB-TYPEJUGGLE-002", "MEDIUM", "CWE-697: Incorrect Comparison", "Web: PHP Loose Comparison",
                "So sánh lỏng `==` giữa input và giá trị bí mật (PHP)",
                "`==` ép kiểu: `\"0\" == \"0e123\"`, `0 == \"abc\"` (PHP<8) → bỏ qua kiểm tra token/mật khẩu.",
                ["Auth bypass qua ép kiểu", "Token comparison bypass"],
                "Dùng `===` (so khớp cả kiểu) hoặc `hash_equals()`."
            ),
            # SSRF PHP curl
            (
                r'\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)',
                "WEB-SSRF-002", "HIGH", "CWE-918: Server-Side Request Forgery (SSRF)", "Web: SSRF (PHP cURL)",
                "URL cURL lấy trực tiếp từ tham số người dùng (PHP)",
                "Máy chủ gửi request tới URL do client chỉ định → truy cập dịch vụ nội bộ / cloud metadata.",
                ["SSRF đọc 169.254.169.254 metadata", "Quét/đánh dịch vụ nội bộ"],
                "Validate host (chặn RFC1918/loopback), whitelist domain, chặn redirect."
            ),
            # Path traversal qua send_file
            (
                r'\bsend_file\s*\(\s*(?:[^)]*\+\s*)?(?:request\.|.*\.args|.*\.form)',
                "WEB-TRAV-003", "HIGH", "CWE-22: Path Traversal", "Web: Arbitrary File Read (send_file)",
                "send_file() với đường dẫn từ người dùng → đọc file tuỳ ý",
                "Đường dẫn gửi cho send_file do input quyết định → `../../../flag`, `/etc/passwd`.",
                ["Đọc /flag qua `../`", "Lộ source/cấu hình"],
                "Dùng `flask.safe_join(root, name)` + kiểm tra realpath nằm trong thư mục cho phép."
            ),
            # CORS wildcard + credentials
            (
                r'Access-Control-Allow-Origin["\']?\s*[:,]\s*["\']?\s*\*',
                "WEB-CORS-001", "MEDIUM", "CWE-942: Permissive Cross-domain Policy", "Web: Insecure CORS",
                "CORS cho phép mọi origin (`Access-Control-Allow-Origin: *`)",
                "Origin `*` (đặc biệt khi kèm Allow-Credentials) cho site bất kỳ đọc phản hồi có dữ liệu nhạy cảm của nạn nhân.",
                ["Đánh cắp dữ liệu qua CORS từ site độc hại", "Lộ dữ liệu phiên đăng nhập"],
                "Chỉ echo origin trong whitelist; không dùng `*` cùng `Allow-Credentials: true`."
            )
        ]

        for idx, (line, clean_line) in enumerate(zip(lines, clean_lines), 1):
            for pat, rule_id, sev, cwe, tier, title, desc, techs, fix in web_rules:
                m = re.search(pat, clean_line)
                if m:
                    findings.append(Finding(
                        file_path=file_path,
                        line=idx,
                        col=m.start() + 1,
                        rule_id=rule_id,
                        title=title,
                        severity=sev,
                        cwe=cwe,
                        tier=tier,
                        description=desc,
                        exploit_techniques=techs,
                        remediation=fix,
                        snippet=line,
                        token=m.group(0),
                        category="web"
                    ))
        return findings

# ==============================================================================
# Crypto Scanner Engine (Weak Primitives & Bad Modes)
# ==============================================================================
class CryptoScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.category = "crypto"

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        is_py = file_path.endswith('.py')
        clean_code = self.strip_comments(content, is_python=is_py)
        lines = content.splitlines()
        clean_lines = clean_code.splitlines()

        crypto_rules = [
            (
                r'\bAES\.MODE_ECB\b',
                "CRYPTO-MODE-001", "HIGH", "CWE-327: Use of a Broken Cryptographic Algorithm", "Crypto: Insecure Cipher Mode",
                "Sử dụng chế độ AES-ECB không an toàn (Electronic Codebook)",
                "Chế độ ECB mã hóa các khối 16-byte độc lập mà không dùng vector khởi tạo (IV). Các khối dữ liệu giống nhau cho ra ciphertext giống nhau, làm lộ cấu trúc (ECB Penguin leak).",
                ["ECB block replay", "Byte-at-a-time chosen-plaintext attack (CPA)"],
                "Chuyển sang chế độ xác thực toàn vẹn như AES-GCM (Galois/Counter Mode) hoặc AES-CBC với IV ngẫu nhiên."
            ),
            (
                r'\bRSA\.generate\s*\(\s*(?:512|1024)\b',
                "CRYPTO-KEY-001", "HIGH", "CWE-326: Inadequate Encryption Strength", "Crypto: Weak RSA Key Size",
                "Độ dài khóa RSA quá ngắn (dưới 2048 bits)",
                "Khóa RSA 512-bit hoặc 1024-bit có thể bị phân tích thừa số nguyên tố (factorization) nhanh chóng bằng các thuật toán như ECM hoặc CADO-NFS.",
                ["RSA Factorization (d = modinv(e, (p-1)*(q-1)))", "Giải mã toàn bộ ciphertext"],
                "Sử dụng độ dài khóa tối thiểu 2048 bits hoặc chuyển sang Ed25519 / ECDSA."
            ),
            (
                r'\b(?:hashlib\.md5|hashlib\.sha1)\b',
                "CRYPTO-HASH-001", "MEDIUM", "CWE-328: Use of Weak Hash", "Crypto: Broken Hash Function",
                "Sử dụng hàm băm suy yếu (MD5 / SHA1)",
                "MD5 và SHA1 đã bị phá vỡ về mặt va chạm (collision attack). Không an toàn để lưu trữ mật khẩu hoặc làm chữ ký số.",
                ["Hash collision attack", "Chiều dài mở rộng (Length Extension Attack nếu không dùng HMAC)"],
                "Sử dụng SHA-256 / SHA-3, hoặc Argon2id / bcrypt để băm mật khẩu."
            ),
            (
                r'\brandom\.seed\s*\(\s*(?:int\s*\(\s*)?time\.time\s*\(\s*\)',
                "CRYPTO-RNG-001", "HIGH", "CWE-338: Use of Cryptographically Weak PRNG", "Crypto: Predictable RNG",
                "Seed bộ sinh số ngẫu nhiên bằng thời gian thực",
                "Thời gian `time.time()` có thể đoán biết chính xác theo giây/mili-giây, cho phép kẻ tấn công tái tạo toàn bộ chuỗi số ngẫu nhiên.",
                ["Brute-force PRNG state", "Dự đoán private key / IV"],
                "Dùng module `secrets` trong Python (`secrets.token_bytes()`) hoặc `os.urandom()`."
            ),
            (
                r'(?:iv|IV)\s*=\s*(?:b["\']0{16}["\']|b["\']\\x00{16}["\']|bytes\(\s*16\s*\)|["\']0{16}["\'])',
                "CRYPTO-STATIC-IV-001", "HIGH", "CWE-329: Generation of Predictable IV with CBC Mode", "Crypto: Static IV",
                "Sử dụng Initialization Vector (IV) cố định hoặc toàn số 0",
                "IV trong CBC hoặc CTR mode bắt buộc phải là số ngẫu nhiên duy nhất cho mỗi phiên mã hóa. Sử dụng IV tĩnh cho phép kẻ tấn công phân tích XOR hoặc khôi phục keystream.",
                ["XOR Differential Analysis", "Keystream reuse attack"],
                "Luôn tạo IV ngẫu nhiên bảo mật: `os.urandom(16)` hoặc `get_random_bytes(16)` cho mỗi tin nhắn."
            ),
            (
                r'\b(?:DES|ARC4|Blowfish)\.new\b',
                "CRYPTO-CIPHER-001", "HIGH", "CWE-327: Use of a Broken Cryptographic Algorithm", "Crypto: Legacy Broken Cipher",
                "Sử dụng thuật toán mã hóa lỗi thời, không an toàn (DES / RC4 / Blowfish)",
                "DES (khóa 56-bit) và RC4 (lỗ hổng keystream bias) đã lỗi thời và không còn đảm bảo an toàn.",
                ["Brute-force 56-bit key", "RC4 plaintext recovery"],
                "Chuyển sang sử dụng thuật toán hiện đại chuẩn NIST như AES-256-GCM hoặc ChaCha20-Poly1305."
            ),
            (
                r'\be\s*=\s*(?:3|5|7|11|17)\b',
                "CRYPTO-RSA-E", "HIGH", "CWE-327: Small RSA Public Exponent", "Crypto: RSA e nhỏ",
                "Số mũ công khai RSA nhỏ (e = 3/5/7...) → tấn công căn bậc / Håstad",
                "e nhỏ: nếu m^e < n (không bị mod) thì plaintext = căn bậc e của ciphertext. Có nhiều ciphertext cùng m (Håstad broadcast) cũng giải được qua CRT.",
                ["Cube/e-th root (gmpy2.iroot(c, e))", "Håstad broadcast (CRT) nếu nhiều n"],
                "Dùng e = 65537 + padding OAEP. ATTACK: `m = gmpy2.iroot(c, e)[0]` nếu m^e<n."
            ),
            (
                r'\bgetPrime\s*\(\s*(?:16|24|32|48|64|96|128|160|192|256|384|512)\b',
                "CRYPTO-RSA-SMALL", "HIGH", "CWE-326: Weak RSA Modulus", "Crypto: Modulus RSA nhỏ",
                "getPrime(bits) nhỏ → n có thể bị phân tích thừa số",
                "Nguyên tố/modulus nhỏ (<=512-bit mỗi prime, hoặc n ngắn) có thể factor bằng FactorDB/Fermat (p≈q)/ECM/yafu để lấy p,q.",
                ["factordb(n)", "Fermat nếu p≈q", "ECM/yafu"],
                "Prime ≥ 1024-bit (n ≥ 2048). ATTACK: tra factordb.com hoặc `Fermat`/`sympy.factorint`."
            ),
            (
                r'\b(?:nonce|iv|IV|NONCE|counter)\s*=\s*(?:b?["\'][^"\']*["\']|bytes\s*\(\s*\d+\s*\)|["\']?\\x00|0\b)',
                "CRYPTO-NONCE-001", "HIGH", "CWE-323: Nonce/IV Reuse", "Crypto: Nonce/IV cố định (reuse)",
                "Nonce/IV cố định hoặc dùng lại trong CTR/GCM/CBC",
                "Tái dùng nonce (CTR/GCM) làm lộ keystream: XOR hai ciphertext = XOR hai plaintext. GCM reuse còn cho phép giả mạo (forge tag).",
                ["Two-time pad: c1 ^ c2 = p1 ^ p2", "GCM nonce reuse → recover authkey/forge"],
                "Sinh nonce/IV NGẪU NHIÊN mỗi lần (os.urandom). ATTACK: XOR hai ciphertext cùng nonce."
            ),
            (
                r'\b(?:key|KEY|secret|SECRET|passphrase|password|flag_key|aes_key)\s*=\s*b?["\'][^"\']{4,}["\']',
                "CRYPTO-KEY-002", "HIGH", "CWE-798: Hard-coded Cryptographic Key", "Crypto: Khoá cứng trong mã",
                "Khoá/secret mã hoá được hard-code trực tiếp trong mã nguồn",
                "Khoá nằm ngay trong source (whitebox) → attacker đọc được và giải mã mọi ciphertext ngay lập tức.",
                ["Đọc khoá từ source → giải mã trực tiếp"],
                "Lấy khoá từ biến môi trường/KMS; whitebox A/D: coi như đã lộ, không dùng khoá tĩnh."
            ),
            (
                r'\brandom\.(?:getrandbits|randint|random|randrange|choice|shuffle|sample)\s*\(',
                "CRYPTO-RNG-002", "MEDIUM", "CWE-338: Weak PRNG (Mersenne Twister)", "Crypto: PRNG MT19937 đoán được",
                "Dùng module `random` (MT19937) cho mục đích bảo mật",
                "random của Python là Mersenne Twister — KHÔNG an toàn mật mã. Biết 624 output 32-bit liên tiếp là khôi phục toàn bộ state và dự đoán tiếp (randcrack).",
                ["Khôi phục state MT19937 (randcrack) từ 624 output", "Dự đoán key/token kế tiếp"],
                "Dùng `secrets`/`os.urandom`. ATTACK: thu 624 giá trị → `randcrack` dự đoán."
            ),
            (
                r'\bfor\b[^:\n]*\bin\b[^:\n]*\brange\s*\(\s*256\s*\)',
                "CRYPTO-XOR-001", "LOW", "CWE-326: Single-byte Key", "Crypto: Không gian khoá 1 byte",
                "Vòng lặp range(256) — khả năng khoá XOR 1 byte (brute được)",
                "Duyệt 0..255 thường là brute khoá XOR 1 byte. Không gian khoá chỉ 256 → thử hết tức thì, chọn kết quả giống text/flag.",
                ["Brute 256 khoá, chọn output in được / có prefix flag"],
                "Dùng khoá đủ dài + thuật toán chuẩn. ATTACK: thử 256, lọc theo printable/flag prefix."
            ),
            (
                r'\bunpad\s*\(|Padding is incorrect|raise.*[Pp]adding',
                "CRYPTO-PADORACLE-001", "HIGH", "CWE-347: Padding Oracle", "Crypto: Padding Oracle (CBC)",
                "Phân biệt lỗi padding (unpad) — nguy cơ Padding Oracle",
                "Nếu server trả về khác nhau giữa 'padding sai' và 'sai nội dung' (CBC) → padding oracle: giải/mã hoá tuỳ ý mà không cần khoá.",
                ["CBC padding oracle decrypt", "Forge ciphertext (encrypt oracle)"],
                "Dùng AEAD (GCM) hoặc Encrypt-then-MAC; trả lỗi GIỐNG NHAU. ATTACK: `padding oracle` (padbuster)."
            ),
            (
                r'\^\s*[a-zA-Z_]\w*\s*\[\s*[a-zA-Z_]\w*\s*%',
                "CRYPTO-XOR-002", "MEDIUM", "CWE-326: Repeating-key XOR (Vigenère)", "Crypto: XOR khoá lặp",
                "XOR khoá lặp `c[i] ^ key[i % len(key)]` — phá được như Vigenère",
                "Khoá XOR ngắn lặp lại → tìm độ dài khoá (Kasiski/Hamming) rồi giải từng cột bằng tần suất; biết 1 đoạn plaintext là lộ khoá.",
                ["Tìm keylen (index of coincidence)", "Known-plaintext → key", "Phân tích tần suất từng cột"],
                "Dùng khoá dài bằng dữ liệu (OTP) hoặc AEAD chuẩn. ATTACK: xor repeating-key breaker."
            ),
            (
                r'\b(?:hmac|mac|sig|signature|tag|token|digest|expected|secret)\w*\s*==|==\s*(?:hmac|mac|sig|signature|tag|token|digest|expected)\w*',
                "CRYPTO-TIMING-001", "MEDIUM", "CWE-208: Timing-unsafe Comparison", "Crypto: So sánh MAC/token không hằng-thời-gian",
                "So sánh MAC/chữ ký/token bằng `==` — rò rỉ qua thời gian (timing attack)",
                "`==` dừng ở byte khác nhau đầu tiên → thời gian phản hồi tiết lộ số byte đúng → forge MAC/token từng byte.",
                ["Byte-by-byte MAC forgery theo timing", "Bypass xác thực HMAC"],
                "Dùng `hmac.compare_digest(a, b)` (constant-time)."
            ),
            (
                r'\bAES\.MODE_CBC\b',
                "CRYPTO-CBC-001", "MEDIUM", "CWE-294: Malleable CBC (No MAC)", "Crypto: AES-CBC không xác thực",
                "AES-CBC không kèm MAC → ciphertext dễ bị sửa (bit-flipping)",
                "CBC không toàn vẹn: lật 1 bit ở block ciphertext trước làm lật đúng bit tương ứng ở plaintext block sau → sửa nội dung (vd admin=1) mà không cần khoá.",
                ["CBC bit-flipping (sửa plaintext block kế)", "Padding oracle (nếu lộ lỗi padding)"],
                "Dùng AES-GCM (AEAD) hoặc Encrypt-then-HMAC."
            ),
            (
                r'\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\(\s*(?:secret|key|salt)\w*\s*\+',
                "CRYPTO-LENEXT-001", "HIGH", "CWE-328: Hash Length Extension", "Crypto: Length Extension (H(secret‖msg))",
                "MAC kiểu `H(secret + msg)` — dính Length Extension Attack",
                "MD5/SHA1/SHA2 là Merkle–Damgård: biết `H(secret‖msg)` và độ dài secret là nối thêm data và tính được MAC hợp lệ MỚI mà không cần secret.",
                ["Length extension (hashpump) → forge MAC + chèn data"],
                "Dùng HMAC: `hmac.new(key, msg, sha256)` thay vì H(secret‖msg)."
            )
        ]

        for idx, (line, clean_line) in enumerate(zip(lines, clean_lines), 1):
            for pat, rule_id, sev, cwe, tier, title, desc, techs, fix in crypto_rules:
                m = re.search(pat, clean_line)
                if m:
                    findings.append(Finding(
                        file_path=file_path,
                        line=idx,
                        col=m.start() + 1,
                        rule_id=rule_id,
                        title=title,
                        severity=sev,
                        cwe=cwe,
                        tier=tier,
                        description=desc,
                        exploit_techniques=techs,
                        remediation=fix,
                        snippet=line,
                        token=m.group(0),
                        category="crypto"
                    ))
        return findings

# ==============================================================================
# Reverse Engineering Scanner Engine (Anti-Debug & Obfuscation)
# ==============================================================================
class RevScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.category = "rev"

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        is_py = file_path.endswith('.py')
        clean_code = self.strip_comments(content, is_python=is_py)
        lines = content.splitlines()
        clean_lines = clean_code.splitlines()

        rev_rules = [
            (
                r'\bptrace\s*\(\s*(?:PTRACE_TRACEME|0)\b',
                "REV-ANTI-001", "MEDIUM", "CWE-656: Reliance on Security Through Obscurity", "Rev: Anti-Debugging",
                "Cơ chế chống Debugger bằng 'ptrace(PTRACE_TRACEME)'",
                "Tiến trình gọi ptrace để ngăn chặn việc gdb/radare2 gắn vào phân tích (chỉ một debugger được attach vào 1 process tại một thời điểm).",
                ["Chống đảo ngược mã nguồn", "Phát hiện môi trường kiểm thử"],
                "Trong CTF/Reversing: Patch byte lệnh gọi ptrace thành NOP (0x90) hoặc LD_PRELOAD giả lập ptrace trả về 0."
            ),
            (
                r'\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent)\s*\(',
                "REV-ANTI-002", "MEDIUM", "CWE-656: Security Through Obscurity", "Rev: Windows Anti-Debugging",
                "Hàm kiểm tra debugger của Windows API",
                "Chương trình kiểm tra cờ BeingDebugged trong cấu trúc PEB để phát hiện x64dbg/IDA.",
                ["Phát hiện môi trường phân tích"],
                "Sử dụng plugin ScyllaHide hoặc patch cờ BeingDebugged trong PEB."
            ),
            (
                r'TracerPid',
                "REV-ANTI-003", "MEDIUM", "CWE-656: Reliance on Security Through Obscurity", "Rev: Linux Anti-Debugging",
                "Kiểm tra trường TracerPid trong '/proc/self/status'",
                "Chương trình đọc TracerPid để phát hiện xem có debugger (gdb, strace) đang gắn vào tiến trình hay không.",
                ["Phát hiện TracerPid > 0"],
                "Patch lệnh so sánh `cmp [rbp-var], 0` hoặc can thiệp syscall `read` bằng hook/frida."
            ),
            (
                r'(?:__rdtsc\s*\(\)|asm\s*(?:volatile)?\s*\(\s*["\'].*?rdtsc)',
                "REV-ANTI-004", "LOW", "CWE-656: Reliance on Security Through Obscurity", "Rev: Timing Check",
                "Sử dụng chỉ thị 'rdtsc' đo chu kỳ xung nhịp CPU (Timing Check)",
                "Chương trình đo thời gian thực thi giữa hai điểm code. Nếu có debugger đặt breakpoint hoặc bước qua (step), độ trễ chu kỳ sẽ vọt lên cao bất thường.",
                ["Anti-Stepping", "Phát hiện độ trễ Debugger"],
                "Patch giá trị trả về của `rdtsc` trong gdb hoặc NOP khối kiểm tra chênh lệch thời gian."
            ),
            (
                r'\b(?:fork|getenv)\s*\(\s*(?:\)|["\']LD_PRELOAD)',
                "REV-ANTI-005", "LOW", "CWE-656: Security Through Obscurity", "Rev: Anti-Debug (fork/LD_PRELOAD)",
                "Chống debug bằng fork() self-trace hoặc kiểm tra LD_PRELOAD",
                "fork rồi cho tiến trình con ptrace cha (self-debug), hoặc kiểm tra biến môi trường LD_PRELOAD để phát hiện hook.",
                ["Self-ptrace anti-attach", "Phát hiện LD_PRELOAD"],
                "Patch NOP khối fork/kiểm tra; hoặc unset LD_PRELOAD khi chạy."
            ),
            (
                r'\b(?:signal|sigaction)\s*\(\s*SIGTRAP|\balarm\s*\(',
                "REV-ANTI-006", "LOW", "CWE-656: Security Through Obscurity", "Rev: Anti-Debug (SIGTRAP/alarm)",
                "Bẫy SIGTRAP hoặc alarm() để phát hiện/cản debugger",
                "Đặt handler SIGTRAP (breakpoint int3 sẽ kích) hoặc alarm() giới hạn thời gian để chống phân tích động.",
                ["Anti-breakpoint (SIGTRAP)", "Timeout chống phân tích"],
                "NOP khối đặt handler; trong gdb `handle SIGTRAP nostop`/`handle SIGALRM ignore`."
            ),
            (
                r'(?:\b[a-zA-Z_][\w\[\]]*\s*\^=|\^\s*(?:0x[0-9a-fA-F]+|key|\bkey\[))',
                "REV-XOR-001", "MEDIUM", "CWE-327: Weak Obfuscation", "Rev: XOR encode/decode",
                "Vòng mã hoá/giải mã bằng XOR (phép ^= hoặc ^ key)",
                "Dùng XOR để che giấu flag/chuỗi. XOR là khả nghịch: biết ciphertext + key (hoặc 1 cặp known-plaintext) là giải ngược ngay.",
                ["Giải ngược: plaintext = cipher ^ key", "Known-plaintext để lấy key", "angr giải tự động"],
                "REV: dump bảng cipher+key rồi XOR lại; hoặc đặt breakpoint SAU vòng giải mã để đọc flag."
            ),
            (
                r'\b(?:strcmp|strncmp|memcmp)\s*\(\s*([a-zA-Z0-9_>.\[\]-]+)\s*,',
                "REV-CMP-001", "MEDIUM", "CWE-200: Flag Comparison", "Rev: So sánh flag/mật khẩu",
                "So sánh chuỗi (strcmp/memcmp) — ĐIỂM kiểm tra flag/mật khẩu",
                "strcmp/memcmp thường là nơi so input với đáp án đúng. Giá trị đúng có thể nằm trong .rodata, hoặc đặt breakpoint tại đây để đọc đối số thứ 2.",
                ["Đọc đối số đúng tại breakpoint (gdb)", "Patch jcc sau so sánh để luôn 'Correct'", "angr find=nhánh Correct"],
                "REV: `b strcmp` xem rsi; hoặc angr explore(find=addr 'Correct', avoid=addr 'Wrong')."
            ),
            (
                r'\bsrand\s*\(\s*(?:time\s*\(\s*(?:0|NULL)?\s*\)|getpid)',
                "REV-SEED-001", "MEDIUM", "CWE-337: Predictable Seed", "Rev/Crypto: Seed đoán được",
                "srand() seed bằng time()/getpid — chuỗi 'ngẫu nhiên' đoán được",
                "srand(time(NULL)) khiến rand() xác định theo thời điểm chạy. Attacker tái tạo cùng seed để dự đoán toàn bộ output (token, key, thứ tự).",
                ["Brute seed theo thời gian", "Tái tạo toàn bộ chuỗi rand()"],
                "Dùng /dev/urandom / getrandom(). REV: thử seed = thời điểm gửi để tái tạo."
            ),
            (
                r'["\'][A-Za-z0-9+/][A-Za-z0-9+/=_.\-]{59,}["\']',
                "REV-B64-001", "LOW", "CWE-327: Custom Encoding Table", "Rev: Bảng mã tuỳ biến (base64/sub)",
                "Chuỗi dài giống BẢNG mã tuỳ biến (base64 alphabet đảo / substitution)",
                "Chuỗi ~64 ký tự có thể là bảng base64 tuỳ biến hoặc bảng thay thế — dùng để mã hoá flag. Lấy bảng này + hàm map là giải ngược được.",
                ["Dò bảng → giải base64/sub ngược", "So với bảng chuẩn để tìm hoán vị"],
                "REV: dùng bảng này trong Python để decode; hoặc angr nếu logic phức tạp."
            )
        ]

        for idx, (line, clean_line) in enumerate(zip(lines, clean_lines), 1):
            for pat, rule_id, sev, cwe, tier, title, desc, techs, fix in rev_rules:
                m = re.search(pat, clean_line)
                if m:
                    findings.append(Finding(
                        file_path=file_path,
                        line=idx,
                        col=m.start() + 1,
                        rule_id=rule_id,
                        title=title,
                        severity=sev,
                        cwe=cwe,
                        tier=tier,
                        description=desc,
                        exploit_techniques=techs,
                        remediation=fix,
                        snippet=line,
                        token=m.group(0),
                        category="rev"
                    ))
        return findings

# ==============================================================================
# Report Generators
# ==============================================================================
class Reporter:
    @staticmethod
    def print_terminal(findings: List[Finding], binary: Optional[BinaryProfile] = None, no_color: bool = False):
        file_lines_cache: Dict[str, List[str]] = {}

        # 1. Header Banner
        print(f"\n{colorize('╭──────────────────────────────────────────────────────────────────────────────╮', Colors.BOLD + Colors.CYAN, no_color)}")
        print(f"{colorize('│  ◈ VULNCHECK — Security Code & Binary Posture Linter                 v3.0    │', Colors.BOLD + Colors.BWHITE, no_color)}")
        print(f"{colorize('╰──────────────────────────────────────────────────────────────────────────────╯', Colors.BOLD + Colors.CYAN, no_color)}")

        # 2. Binary Mitigations / Posture Pill Bar
        if binary and binary.arch != "unknown":
            canary_badge = colorize("[CANARY: ✓ FOUND]", Colors.BGREEN + Colors.BOLD, no_color) if binary.canary else colorize("[CANARY: ✗ OFF]", Colors.BRED + Colors.BOLD, no_color)
            nx_badge = colorize("[NX: ✓ ON]", Colors.BGREEN + Colors.BOLD, no_color) if binary.nx else colorize("[NX: ✗ OFF]", Colors.BRED + Colors.BOLD, no_color)
            pie_badge = colorize("[PIE: ✓ ON]", Colors.BGREEN + Colors.BOLD, no_color) if binary.pie else colorize("[PIE: ✗ OFF]", Colors.BYELLOW + Colors.BOLD, no_color)
            
            if binary.relro == "Full":
                relro_badge = colorize("[RELRO: FULL]", Colors.BGREEN + Colors.BOLD, no_color)
            elif binary.relro == "Partial":
                relro_badge = colorize("[RELRO: PARTIAL]", Colors.BYELLOW + Colors.BOLD, no_color)
            else:
                relro_badge = colorize("[RELRO: NONE]", Colors.BRED + Colors.BOLD, no_color)

            rwx_badge = f" {colorize('[RWX SEGMENT: ⚠ VULNERABLE]', Colors.BG_RED + Colors.BWHITE + Colors.BOLD, no_color)}" if binary.rwx else ""

            print(f" {colorize('Target Binary:', Colors.DIM, no_color)} {colorize(binary.path, Colors.BOLD + Colors.BWHITE, no_color)} {colorize(f'({binary.arch}-{binary.bits})', Colors.DIM, no_color)}")
            print(f" {colorize('Mitigations:  ', Colors.DIM, no_color)} {canary_badge}  {nx_badge}  {pie_badge}  {relro_badge}{rwx_badge}")
            if binary.interesting_symbols:
                print(f" {colorize('Target Symbols:', Colors.DIM, no_color)} {colorize(', '.join(binary.interesting_symbols), Colors.BMAGENTA + Colors.BOLD, no_color)}")
            print()
        else:
            print(f" {colorize('Mode:', Colors.DIM, no_color)} {colorize('Static Application Security Testing (SAST)', Colors.BOLD + Colors.BCYAN, no_color)}\n")

        # 3. If clean
        if not findings:
            print(colorize("╭──────────────────────────────────────────────────────────────────────────────╮", Colors.BGREEN, no_color))
            print(colorize("│  ✓ CLEAN: Không phát hiện lỗ hổng nào trong mã nguồn được quét!             │", Colors.BGREEN + Colors.BOLD, no_color))
            print(colorize("╰──────────────────────────────────────────────────────────────────────────────╯\n", Colors.BGREEN, no_color))
            return

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.file_path, f.line))

        # 4. Render Finding Cards
        for idx, f in enumerate(sorted_findings, 1):
            if f.severity == "CRITICAL":
                border_color = Colors.BRED
                sev_badge = colorize("[CRITICAL]", Colors.BRED + Colors.BOLD, no_color)
            elif f.severity == "HIGH":
                border_color = Colors.RED
                sev_badge = colorize("[HIGH]", Colors.RED + Colors.BOLD, no_color)
            elif f.severity == "MEDIUM":
                border_color = Colors.BYELLOW
                sev_badge = colorize("[MEDIUM]", Colors.BYELLOW + Colors.BOLD, no_color)
            else:
                border_color = Colors.BCYAN
                sev_badge = colorize(f"[{f.severity}]", Colors.BCYAN, no_color)

            # Card Header Bar
            header_bar = f"{colorize('───', border_color, no_color)} {sev_badge} {colorize(f.rule_id, Colors.BOLD, no_color)} {colorize('────────────────────────────────────', border_color, no_color)} {colorize(f'{f.file_path}:{f.line}:{f.col}', Colors.BOLD + Colors.BWHITE, no_color)} {colorize('───', border_color, no_color)}"
            print(header_bar)
            print(f"  {colorize('Rule:', Colors.DIM, no_color)} {colorize(f.cwe, Colors.BYELLOW, no_color)}  {colorize('•', Colors.DIM, no_color)}  {colorize(f.tier, Colors.BCYAN, no_color)}")
            print(f"  {colorize('Issue:', Colors.BOLD + Colors.BWHITE, no_color)} {f.title}\n")

            # Code Context Snippet (3 lines: prev, curr, next)
            lines = file_lines_cache.get(f.file_path)
            if lines is None and os.path.isfile(f.file_path):
                try:
                    with open(f.file_path, "r", encoding="utf-8", errors="ignore") as fp:
                        lines = fp.read().splitlines()
                    file_lines_cache[f.file_path] = lines
                except Exception:
                    lines = []

            if lines and 1 <= f.line <= len(lines):
                start_l = max(1, f.line - 1)
                end_l = min(len(lines), f.line + 1)
                max_w = len(str(end_l))
                for l_num in range(start_l, end_l + 1):
                    l_str = lines[l_num - 1]
                    if l_num == f.line:
                        # Offending line with arrow and red gutter
                        arrow = colorize("►", Colors.BRED + Colors.BOLD, no_color)
                        gutter = colorize(f"{l_num:{max_w}d} │", Colors.BRED + Colors.BOLD, no_color)
                        print(f" {arrow} {gutter} {colorize(l_str, Colors.BOLD, no_color)}")

                        # Caret pointer
                        indent = max(0, f.col - 1)
                        tok_len = max(1, len(f.token)) if f.token else 1
                        pointer = " " * indent + "^" + "~" * (tok_len - 1)
                        pointer_gutter = colorize(" " * max_w + " │", Colors.BRED, no_color)
                        print(f"   {pointer_gutter} {colorize(pointer, Colors.BRED + Colors.BOLD, no_color)}")
                    else:
                        gutter = colorize(f"{l_num:{max_w}d} │", Colors.DIM, no_color)
                        print(f"   {gutter} {colorize(l_str, Colors.DIM, no_color)}")
                print()
            elif f.snippet:
                # Fallback to single snippet
                print(f"   {colorize(f'{f.line:4d} │', Colors.BRED, no_color)} {colorize(f.snippet, Colors.BOLD, no_color)}")
                indent = max(0, f.col - 1)
                tok_len = max(1, len(f.token)) if f.token else 1
                pointer = " " * indent + "^" + "~" * (tok_len - 1)
                print(f"        {colorize(pointer, Colors.BRED + Colors.BOLD, no_color)}\n")

            # Structured Action Items
            print(f"  {colorize('▶ Nguyên nhân:', Colors.BYELLOW + Colors.BOLD, no_color)} {f.description}")
            
            scenario_text = ScenarioCorrelator.correlate(f, binary)
            # Format scenario cleanly without extra indentations
            clean_scenario = " ".join(scenario_text.split())
            if len(clean_scenario) > 160:
                clean_scenario = clean_scenario[:157] + "..."
            print(f"  {colorize('▶ Kịch bản:   ', Colors.BMAGENTA + Colors.BOLD, no_color)} {clean_scenario}")

            if f.remediation:
                print(f"  {colorize('▶ Cách vá:    ', Colors.BGREEN + Colors.BOLD, no_color)} {colorize(f.remediation, Colors.BGREEN, no_color)}")

            if f.cheatsheet_ref:
                print(f"  {colorize('▶ Tài liệu:   ', Colors.BCYAN + Colors.BOLD, no_color)} {colorize(f.cheatsheet_ref, Colors.DIM, no_color)}")

            print()

        # 5. Summary Dashboard
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        print(colorize("╭──────────────────────────────────────────────────────────────────────────────╮", Colors.BOLD + Colors.CYAN, no_color))
        print(f"{colorize('│  AUDIT SUMMARY                                                               │', Colors.BOLD + Colors.BWHITE, no_color)}")
        print(f"│  Total Issues: {colorize(str(len(findings)), Colors.BOLD, no_color)} ( {colorize(f'● {crit_count} Critical', Colors.BRED, no_color)}  {colorize(f'▲ {high_count} High', Colors.RED, no_color)}  {colorize(f'■ {med_count} Medium', Colors.BYELLOW, no_color)}  {colorize(f'○ {low_count} Low', Colors.BCYAN, no_color)} )            │")
        print("│                                                                              │")
        if crit_count > 0 or high_count > 0:
            verdict = colorize("✖ ACTION REQUIRED — Critical vulnerabilities require immediate fix!", Colors.BRED + Colors.BOLD, no_color)
            print(f"│  Verdict: {verdict}   │")
        else:
            verdict = colorize("✓ ACCEPTABLE — No critical or high issues found.", Colors.BGREEN + Colors.BOLD, no_color)
            print(f"│  Verdict: {verdict}                      │")
        print(colorize("╰──────────────────────────────────────────────────────────────────────────────╯\n", Colors.BOLD + Colors.CYAN, no_color))

    @staticmethod
    def print_gcc(findings: List[Finding]):
        """Print compiler-compliant warnings/errors (GCC / Clang format)."""
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.file_path, f.line))
        for f in sorted_findings:
            print(f.to_gcc_string())

    @staticmethod
    def generate_json(findings: List[Finding], binary: Optional[BinaryProfile] = None) -> str:
        data = {
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity == "HIGH"),
                "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity == "LOW")
            },
            "binary_profile": binary.summary() if binary else None,
            "findings": [f.to_dict() for f in findings]
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_markdown(findings: List[Finding], binary: Optional[BinaryProfile] = None) -> str:
        md = []
        md.append("# BÁO CÁO ĐÁNH GIÁ BẢO MẬT MÃ NGUỒN (WHITEBOX VULNERABILITY AUDIT)")
        md.append(f"\n> Báo cáo được tạo tự động bởi **vulncheck**.\n")

        if binary and binary.arch != "unknown":
            md.append("## 1. Thông Tin Nhị Phân & Mitigations (Checksec)")
            md.append(f"- **Đường dẫn binary:** `{binary.path}`")
            md.append(f"- **Kiến trúc:** `{binary.arch}` ({binary.bits}-bit)")
            md.append(f"- **Stack Canary:** `{'Bật (Protected)' if binary.canary else 'TẮT (Vulnerable)'}`")
            md.append(f"- **NX (No-Execute Stack):** `{'Bật (Protected)' if binary.nx else 'TẮT (Executable Stack)'}`")
            md.append(f"- **PIE (ASLR Code):** `{'Bật' if binary.pie else 'Tắt (Static Addresses)'}`")
            md.append(f"- **RELRO:** `{binary.relro}`")
            if binary.interesting_symbols:
                md.append(f"- **Hàm mục tiêu phát hiện:** `{', '.join(binary.interesting_symbols)}`")
            md.append("\n---\n")

        md.append("## 2. Bảng Tổng Hợp Lỗ Hổng")
        md.append("| # | Vị trí | Mức độ | CWE / Phân loại | Tên lỗi | Kỹ thuật khai thác |")
        md.append("|---|---|---|---|---|---|")

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.file_path, f.line))

        for idx, f in enumerate(sorted_findings, 1):
            techs = "<br>".join(f.exploit_techniques[:2])
            md.append(f"| {idx} | `{f.file_path}:{f.line}` | **{f.severity}** | {f.cwe} | {f.title} | {techs} |")

        md.append("\n---\n")
        md.append("## 3. Chi Tiết Lỗ Hổng & Hướng Dẫn Vá")

        for idx, f in enumerate(sorted_findings, 1):
            md.append(f"### {idx}. [{f.severity}] {f.title} (`{f.file_path}:{f.line}`)")
            md.append(f"- **CWE:** {f.cwe}")
            md.append(f"- **PWN Tier:** {f.tier}")
            md.append(f"- **Mô tả:** {f.description}")
            if f.snippet:
                md.append(f"```c\n{f.line}: {f.snippet}\n```")
            md.append(f"- **Kỹ thuật khai thác:**")
            for t in f.exploit_techniques:
                md.append(f"  - {t}")
            scenario = ScenarioCorrelator.correlate(f, binary)
            md.append(f"- **Kịch bản thực chiến (Correlation):**\n  > {scenario.replace(chr(10), chr(10) + '  > ')}")
            md.append(f"- **Hướng dẫn khắc phục:**\n  ```c\n  // Vá an toàn:\n  {f.remediation}\n  ```")
            if f.cheatsheet_ref:
                md.append(f"- **Tài liệu Cheatsheet:** `{f.cheatsheet_ref}`")
            md.append("\n")

        md.append("## 4. Khuyến Nghị Phòng Thủ & Biên Dịch (Defense-in-Depth)")
        md.append("Để bảo vệ sản phẩm trước khi đưa ra bên ngoài, khuyến nghị biên dịch binary với đầy đủ cờ bảo vệ:")
        md.append("```bash")
        md.append("gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security \\")
        md.append("    -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -o service service.c")
        md.append("```")

        return "\n".join(md)

# ==============================================================================
# Binary Analyzer — disasm (radare2) + offset-based findings + pseudo-C
# ==============================================================================
import shutil as _shutil
R2_BIN = _shutil.which("r2") or _shutil.which("radare2")

# name -> (rule_id, severity, cwe, tier, title, [techniques], fix)
BIN_DANGER = {
    "gets":    ("PWN-BIN-GETS", "CRITICAL", "CWE-242", "Tier 1: Stack BOF",
                "Dùng gets() — stack overflow KHÔNG giới hạn",
                ["ret2win", "ret2shellcode (NX off)", "ret2libc / ROP"],
                "Vá byte: đổi `call gets` thành trampoline `fgets(buf,sizeof,stdin)`/`read(0,buf,N)` (binary_patching.html)."),
    "strcpy":  ("PWN-BIN-STRCPY", "HIGH", "CWE-120", "Tier 1: BOF",
                "strcpy() — sao chép không giới hạn", ["Stack/Heap smashing", "Ghi đè saved RIP"],
                "Giới hạn độ dài nguồn; patch sang strncpy có chốt null."),
    "strcat":  ("PWN-BIN-STRCAT", "HIGH", "CWE-120", "Tier 1: BOF",
                "strcat() — nối chuỗi không giới hạn", ["BOF", "Off-by-one"],
                "strncat với độ dài còn lại."),
    "sprintf": ("PWN-BIN-SPRINTF", "HIGH", "CWE-120", "Tier 1: BOF",
                "sprintf() — ghi format không chốt độ dài", ["Stack overflow", "Control-flow hijack"],
                "snprintf(buf,sizeof,...)."),
    "scanf":   ("PWN-BIN-SCANF", "HIGH", "CWE-120", "Tier 1: BOF",
                "scanf()/%s — đọc chuỗi không giới hạn", ["Stack BOF"], "Giới hạn %Ns theo sizeof buffer."),
    "__isoc99_scanf": ("PWN-BIN-SCANF", "HIGH", "CWE-120", "Tier 1: BOF",
                "scanf()/%s — đọc chuỗi không giới hạn", ["Stack BOF"], "Giới hạn %Ns theo sizeof buffer."),
    "system":  ("PWN-BIN-SYSTEM", "HIGH", "CWE-78", "Tier 4: ret2libc",
                "system() có trong binary — mồi ret2libc / RCE nếu tham số điều khiển được",
                ["ret2libc system('/bin/sh')", "command injection"],
                "A/D: coi là đích ret2libc của attacker; kiểm soát tham số."),
    "execve":  ("PWN-BIN-EXECVE", "HIGH", "CWE-78", "Tier 4: syscall",
                "execve() có trong binary", ["ret2syscall execve('/bin/sh')"], "Kiểm soát tham số."),
    "popen":   ("PWN-BIN-POPEN", "HIGH", "CWE-78", "Tier 4", "popen() — chạy shell command",
                ["command injection"], "Tránh dùng shell; sanitize."),
    "printf":  ("PWN-BIN-FMT", "HIGH", "CWE-134", "Tier 2: Format String",
                "printf() — FORMAT STRING nếu đối số format điều khiển được",
                ["Leak canary/libc/PIE (%p)", "Arbitrary write %n (GOT/exit_handler)"],
                "Luôn `printf(\"%s\", buf)`; kiểm tra site này có format literal không."),
    "fprintf": ("PWN-BIN-FMT", "HIGH", "CWE-134", "Tier 2: Format String",
                "fprintf() — FORMAT STRING nếu format điều khiển được",
                ["Leak (%p)", "Arbitrary write (%n)"], "`fprintf(f,\"%s\",buf)`."),
    "read":    ("PWN-BIN-READ", "MEDIUM", "CWE-120", "Tier 1: BOF",
                "read() — kiểm tra size so với buffer (có thể BOF)",
                ["BOF nếu size > sizeof(buf)"], "size = sizeof(buf)."),
    "memcpy":  ("PWN-BIN-MEMCPY", "MEDIUM", "CWE-120", "Tier 1: BOF",
                "memcpy() — kiểm tra độ dài (user-controlled/âm → tràn khổng lồ)",
                ["Heap/stack overflow", "Integer→huge size"], "Chốt len; ép unsigned có trần."),
    "alloca":  ("PWN-BIN-ALLOCA", "MEDIUM", "CWE-770", "Tier 1", "alloca() — kích thước động trên stack",
                ["Stack clash/overflow"], "Tránh alloca với size từ input."),
    "mprotect":("PWN-BIN-MPROTECT", "MEDIUM", "CWE-???", "Tier 5", "mprotect() — có thể bật RWX",
                ["ret2mprotect → shellcode"], "Không cấp RWX."),
}
WIN_NAME_RE = re.compile(r'(?i)\b(win|backdoor|shell|give_?shell|get_?shell|secret|admin|flag|cat_?flag|print_?flag|magic|debug|dev)\b')


def _run_r2(path, commands, analyze=True, timeout=40):
    """Chạy r2 một lần; trả {key: text_output} theo marker. commands=[(key,cmd),...]."""
    if not R2_BIN or not os.path.exists(path):
        return {}
    # Marker KHÔNG được chứa '@' (r2 hiểu '@'/'@@' là seek/iterate).
    script = (["aaa"] if analyze else [])
    for key, cmd in commands:
        script.append("?e VCMARK_%s" % key)
        script.append(cmd)
    try:
        res = subprocess.run([R2_BIN, "-q", "-e", "bin.relocs.apply=true", "-e", "scr.color=0",
                              "-c", ";".join(script), path],
                             capture_output=True, text=True, timeout=timeout)
    except Exception:
        return {}
    chunks, cur, buf = {}, None, []
    for ln in res.stdout.splitlines():
        if ln.startswith("VCMARK_"):
            if cur is not None:
                chunks[cur] = "\n".join(buf).strip()
            cur, buf = ln[len("VCMARK_"):].strip(), []
        elif cur is not None:
            buf.append(ln)
    if cur is not None:
        chunks[cur] = "\n".join(buf).strip()
    return chunks


def _jload(txt, default):
    try:
        return json.loads(txt) if txt else default
    except Exception:
        return default


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def print_exploit_plan(steps, script, no_color=False, show_script=True):
    bar = "═" * 80
    print(colorize(bar, Colors.BOLD + Colors.MAGENTA, no_color))
    print(colorize(" 🎯 KỊCH BẢN EXPLOIT ĐỀ XUẤT (từ lỗ hổng + checksec)", Colors.BOLD + Colors.BMAGENTA, no_color))
    print(colorize(bar, Colors.BOLD + Colors.MAGENTA, no_color))
    for i, (name, pri, reason) in enumerate(steps, 1):
        print(f"  {colorize('%d.' % i, Colors.BOLD, no_color)} {colorize(name, Colors.BOLD + Colors.BYELLOW, no_color)}  {pri}")
        print(f"     {colorize(reason, Colors.DIM, no_color)}")
    if show_script and script:
        print(colorize("\n  ── Khung script (pwnld) ──", Colors.BOLD + Colors.BCYAN, no_color))
        for ln in script.splitlines():
            print(colorize("  │ ", Colors.DIM, no_color) + colorize(ln, Colors.BGREEN if ln.strip().startswith("#") else Colors.WHITE, no_color))
    print()


def print_pseudocode(pseudo: Dict[str, str], no_color=False):
    if not pseudo:
        return
    bar = "─" * 80
    print(colorize(bar, Colors.CYAN, no_color))
    print(colorize(" 🧩 MÃ GIẢ (pseudo-C qua radare2) — hàm dính lỗ hổng", Colors.BOLD + Colors.BCYAN, no_color))
    print(colorize(bar, Colors.CYAN, no_color))
    for fn, code in pseudo.items():
        print(colorize("  ╭─ %s" % fn, Colors.BOLD + Colors.BYELLOW, no_color))
        for ln in code.splitlines()[:60]:
            print(colorize("  │ ", Colors.DIM, no_color) + ln)
        print(colorize("  ╰─", Colors.DIM, no_color))
    print()


class BinaryAnalyzer:
    """Phân tích ELF: imports nguy hiểm + call-site theo OFFSET + hàm win + /bin/sh + mã giả."""
    def __init__(self, path: str, profile: Optional["BinaryProfile"] = None):
        self.path = path
        self.base = os.path.basename(path)
        self.profile = profile
        self.available = bool(R2_BIN)
        self.imports: Set[str] = set()
        self.funcs: List[Dict[str, Any]] = []
        self.win_funcs: List[Tuple[str, int]] = []
        self.has_binsh = False
        self.has_system = False
        self.has_fmt = False
        self.has_overflow = False
        self.funcs_with_findings: Set[str] = set()

    @staticmethod
    def _dangerkey(name: str) -> Optional[str]:
        n = name.split("@")[0].lstrip("_")
        for k in BIN_DANGER:
            if n == k or n == k.lstrip("_"):
                return k
        if name.split("@")[0] in BIN_DANGER:
            return name.split("@")[0]
        return None

    def analyze(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.available:
            return findings
        p1 = _run_r2(self.path, [("funcs", "aflj"), ("imports", "iij"), ("strings", "izzj")])
        self.funcs = _jload(p1.get("funcs", ""), [])
        imps = _jload(p1.get("imports", ""), [])
        for it in imps:
            nm = it.get("name", "")
            if nm:
                self.imports.add(nm)
        strings_raw = _jload(p1.get("strings", ""), [])
        strs = strings_raw.get("strings", strings_raw) if isinstance(strings_raw, dict) else strings_raw
        for s in (strs or []):
            v = (s.get("string", "") if isinstance(s, dict) else str(s))
            if "/bin/sh" in v or v.strip() == "sh":
                self.has_binsh = True
        self.has_system = any(self._dangerkey(n) in ("system",) for n in self.imports)

        # win/backdoor theo tên hàm
        for fn in self.funcs:
            name = fn.get("name", "")
            if WIN_NAME_RE.search(name) and "imp." not in name and "sym.sec" not in name:
                self.win_funcs.append((name, fn.get("offset", 0)))

        # call-sites của từng import nguy hiểm (+ callers của system = win tiềm năng)
        danger_present = sorted({self._dangerkey(n): n for n in self.imports if self._dangerkey(n)}.items())
        axt_cmds = [("axt_%s" % k, "axtj sym.imp.%s" % realname) for k, realname in danger_present]
        axt_cmds.append(("axt_system", "axtj sym.imp.system"))
        p2 = _run_r2(self.path, axt_cmds)

        for k, realname in danger_present:
            sites = _jload(p2.get("axt_%s" % k, ""), [])
            meta = BIN_DANGER[k]
            if k in ("gets", "strcpy", "strcat", "sprintf", "scanf", "__isoc99_scanf", "read", "memcpy"):
                if sites:
                    self.has_overflow = True
            if k in ("printf", "fprintf") and sites:
                self.has_fmt = True
            for site in sites[:10]:
                off = site.get("from", 0)
                fcn = site.get("fcn_name", "?")
                self.funcs_with_findings.add(fcn)
                rid, sev, cwe, tier, title, techs, fix = meta
                findings.append(Finding(
                    file_path=self.base, line=0, col=0,
                    rule_id=rid, title=title, severity=sev, cwe=cwe, tier=tier,
                    description="Phát hiện lời gọi `%s` tại offset 0x%x trong hàm `%s` (phân tích nhị phân)."
                                % (realname.split('@')[0], off if isinstance(off, int) else 0, fcn),
                    exploit_techniques=list(techs),
                    remediation=fix,
                    snippet="0x%x  <%s>  →  call %s" % (off if isinstance(off, int) else 0, fcn, realname.split('@')[0]),
                    token="0x%x" % (off if isinstance(off, int) else 0),
                    cheatsheet_ref="cheatsheets/pwn/binary_patching.html",
                    category="pwn",
                ))

        # callers của system → ứng viên win (gọi system trực tiếp = khả năng system("/bin/sh"))
        for site in _jload(p2.get("axt_system", ""), []):
            fcn = site.get("fcn_name", "")
            if fcn and not any(fcn == w[0] for w in self.win_funcs):
                self.win_funcs.append((fcn, site.get("fcn_addr", 0)))

        # Finding cho win functions (ret2win target)
        for name, off in self.win_funcs:
            findings.append(Finding(
                file_path=self.base, line=0, col=0,
                rule_id="PWN-BIN-WIN", title="Hàm 'win/backdoor' tiềm năng: %s" % name,
                severity="HIGH", cwe="CWE-489", tier="Tier 0: ret2win",
                description="Hàm `%s` @ 0x%x khả năng in flag / spawn shell → nếu có BOF, nhảy thẳng tới đây (ret2win)."
                            % (name, off if isinstance(off, int) else 0),
                exploit_techniques=["ret2win: ghi đè saved RIP = địa chỉ hàm này"],
                remediation="Gỡ/khoá hàm nếu không cần; hoặc bịt BOF dẫn tới nó.",
                snippet="win candidate: %s @ 0x%x" % (name, off if isinstance(off, int) else 0),
                token="0x%x" % (off if isinstance(off, int) else 0),
                cheatsheet_ref="cheatsheets/pwn/stack_overflow.html", category="pwn",
            ))
        return findings

    def pseudocode(self, limit_funcs: int = 6) -> Dict[str, str]:
        """pdc (pseudo-C) cho các hàm có lỗ hổng."""
        if not self.available or not self.funcs_with_findings:
            return {}
        targets = list(self.funcs_with_findings)[:limit_funcs]
        cmds = [("pc_%d" % i, "pdc @ %s" % fn) for i, fn in enumerate(targets)]
        out = _run_r2(self.path, cmds)
        return {targets[i]: out.get("pc_%d" % i, "") for i in range(len(targets)) if out.get("pc_%d" % i)}


# ==============================================================================
# Exploit Planner — tổng hợp findings + checksec → kịch bản + script pwnld
# ==============================================================================
class ExploitPlanner:
    @staticmethod
    def plan(findings: List[Finding], profile: Optional["BinaryProfile"],
             analyzer: Optional["BinaryAnalyzer"] = None) -> Tuple[List[Tuple[str, str, str]], str]:
        """Trả (steps, script). steps=[(tên, độ ưu tiên, lý do)]."""
        steps: List[Tuple[str, str, str]] = []
        cats = {f.category for f in findings}
        rules = {f.rule_id for f in findings}
        has_bof = any(r.startswith(("PWN-BOF", "PWN-BIN-GETS", "PWN-BIN-STRCPY", "PWN-BIN-READ",
                                     "PWN-BIN-SCANF", "PWN-BIN-SPRINTF", "PWN-BIN-MEMCPY")) for r in rules) \
                  or any("BOF" in getattr(f, "tier", "") for f in findings)
        has_fmt = any("FMT" in r or "FORMAT" in r or "fmt" in r.lower() for r in rules) \
                  or (analyzer.has_fmt if analyzer else False)
        has_heap = any("HEAP" in r or "UAF" in r or "FREE" in r for r in rules)
        win = bool(analyzer and analyzer.win_funcs) or any(r == "PWN-BIN-WIN" for r in rules)
        binsh = bool(analyzer and analyzer.has_binsh)
        system = bool(analyzer and analyzer.has_system)
        nx = profile.nx if profile else True
        pie = profile.pie if profile else True
        canary = profile.canary if profile else True
        relro = profile.relro if profile else "Full"
        rwx = profile.rwx if profile else False

        P = lambda n: ("⭐" * n)
        if canary and has_bof:
            steps.append(("Vượt Stack Canary", P(1),
                          "Có canary → cần leak canary (format string / brute fork) rồi ghi lại đúng trước khi tràn saved RIP."))
        if win and has_bof:
            steps.append(("ret2win", P(5),
                          "Có hàm win/backdoor + có BOF → đơn giản nhất: ghi đè saved RIP = địa chỉ win."
                          + (" (PIE bật → cần leak base trước)" if pie else " (no-PIE → địa chỉ cố định).")))
        if has_bof and not nx:
            steps.append(("ret2shellcode", P(4),
                          "NX TẮT (stack chạy được)%s → nhét shellcode vào buffer, nhảy vào (jmp rsp/địa chỉ buffer)."
                          % (" + có RWX" if rwx else "")))
        if has_bof and system and not pie:
            steps.append(("ret2libc (system trong binary)", P(4),
                          "Có system()%s, no-PIE → ROP: pop rdi; ret → \"/bin/sh\"; call system."
                          % (" + chuỗi /bin/sh" if binsh else " (cần tìm /bin/sh hoặc ghi vào bss)")))
        if has_bof and nx:
            steps.append(("ret2libc / ROP (leak libc)", P(3),
                          "NX bật, không win → leak libc (puts(puts@got)/fmt) rồi ret2libc system('/bin/sh'); "
                          "hoặc ret2csu set tham số; hoặc ret2syscall execve nếu static."))
            steps.append(("Stack pivot", P(2),
                          "Nếu khe tràn NGẮN (không đủ cho ROP chain) → leave;ret / pop rsp pivot sang vùng kiểm soát (bss)."))
            steps.append(("SROP", P(2),
                          "Nếu có syscall gadget + điều khiển rax=15 → dựng sigreturn frame để execve."))
        if has_fmt:
            steps.append(("Format String", P(4),
                          "printf format điều khiển được → %p leak (canary/libc/PIE) + %hn/%n arbitrary write "
                          "(ghi GOT nếu Partial RELRO, hoặc exit_handler/__malloc_hook nếu Full RELRO)."))
        if has_heap:
            steps.append(("Heap exploitation", P(3),
                          "Lỗi heap → tcache/fastbin poisoning (2.31) / safe-link (2.32+); UAF→leak→__free_hook; "
                          "House of Spirit/Force/Einherjar tuỳ nguyên thủy; glibc≥2.35 → House of Apple2 (FSOP)."))
        if not steps:
            steps.append(("Chưa đủ dữ liệu", P(0),
                          "Không thấy nguyên thủy rõ ràng. Thử đọc pseudo-C (--decompile), kiểm input path, hoặc cấp --bin."))

        script = ExploitPlanner._script(steps, profile, analyzer)
        return steps, script

    @staticmethod
    def _script(steps, profile, analyzer) -> str:
        top = steps[0][0] if steps else ""
        binname = analyzer.base if analyzer else "./svc"
        nx = profile.nx if profile else True
        pie = profile.pie if profile else True
        win = analyzer.win_funcs[0] if (analyzer and analyzer.win_funcs) else None
        L = ["#!/usr/bin/env python3",
             "# Khung exploit tự sinh bởi vulncheck (pwnld). Sửa OFFSET/địa chỉ cho khớp.",
             "from pwnld import *",
             "exe = context.binary = ELF(%r, checksec=False)" % ("./" + binname),
             "# libc = get_libc('./libc.so.6')",
             "p = start()                      # process()/remote()/ssh theo pwnld mode",
             "",
             "OFF = 72   # <-- ĐO bằng cyclic/pattern (gdb): khoảng cách tới saved RIP",
             "ret = 0x0  # pop/ret alignment (ROP.find_gadget(['ret']))",
             ""]
        if "ret2win" in top and win:
            L += ["win = exe.sym.get(%r) or 0x%x   # hàm win" % (win[0], win[1] if isinstance(win[1], int) else 0),
                  "payload = flat({OFF: [ret, win]})",
                  "sla(b'>', payload)   # đổi delim cho khớp đề",
                  "ia()"]
        elif "ret2shellcode" in top:
            L += ["context.arch = 'amd64'",
                  "sc = asm(shellcraft.sh())",
                  "# cần địa chỉ buffer (leak / jmp rsp). Ví dụ nhảy vào buffer sau khi ret:",
                  "payload = sc.ljust(OFF, b'\\x90') + p64(BUF_ADDR)  # BUF_ADDR = địa chỉ buffer",
                  "sla(b'>', payload); ia()"]
        elif "ret2libc (system" in top:
            L += ["rop = ROP(exe)",
                  "binsh = next(exe.search(b'/bin/sh')) if b'/bin/sh' in open(exe.path,'rb').read() else 0",
                  "payload = flat({OFF: [rop.find_gadget(['pop rdi','ret'])[0], binsh, ret, exe.sym.system]})",
                  "sla(b'>', payload); ia()"]
        elif "ROP" in top or "ret2libc" in top:
            L += ["# Giai đoạn 1: leak libc qua puts(puts@got) rồi quay lại main",
                  "rop = ROP(exe)",
                  "rop.puts(exe.got.puts); rop.call(exe.sym.main)",
                  "sla(b'>', flat({OFF: rop.chain()}))",
                  "libc = get_libc('./libc.so.6')",
                  "rebase_libc(leak=u64(rl().strip().ljust(8,b'\\x00')), sym='puts')",
                  "# Giai đoạn 2: ret2libc system('/bin/sh')",
                  "rop2 = ROP(libc); rop2.system(next(libc.search(b'/bin/sh')))",
                  "sla(b'>', flat({OFF: [ret, rop2.chain()]})); ia()"]
        elif "Format String" in top:
            L += ["# Dò offset: gửi 'AAAA%p.%p...' tìm 0x41414141. Rồi:",
                  "payload = fmtstr_payload(OFFSET_FMT, {exe.got.__stack_chk_fail: 0xdeadbeef})",
                  "sla(b'>', payload); ia()"]
        else:
            L += ["# Payload tùy nguyên thủy — xem 'KỊCH BẢN' phía trên.",
                  "payload = b'A'*OFF",
                  "sla(b'>', payload); ia()"]
        return "\n".join(L)


# ==============================================================================
# Engine Coordinator & CLI
# ==============================================================================
class VulnChecker:
    def __init__(self, category: str = "all"):
        self.category = category
        self.pwn_scanner = PwnScanner()
        self.web_scanner = WebScanner()
        self.crypto_scanner = CryptoScanner()
        self.rev_scanner = RevScanner()

    def detect_category(self, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"):
            return "pwn"
        elif ext in (".php", ".js", ".html", ".go"):
            return "web"
        elif ext in (".py",):
            # Check content if crypto or web
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                    header = fp.read(1000)
                    if "AES" in header or "RSA" in header or "hashlib" in header or "crypto" in header.lower():
                        return "crypto"
            except Exception:
                pass
            return "web"
        return "pwn"

    def scan_path(self, target_path: str) -> List[Finding]:
        findings: List[Finding] = []
        path_obj = Path(target_path)

        if not path_obj.exists():
            print(f"[!] Lỗi: Đường dẫn '{target_path}' không tồn tại.", file=sys.stderr)
            return []

        # Single file
        if path_obj.is_file():
            files_to_scan = [str(path_obj)]
        else:
            # Directory scan
            files_to_scan = []
            for root, _, files in os.walk(target_path):
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in (".c", ".cpp", ".cc", ".h", ".hpp", ".php", ".py", ".js", ".go"):
                        files_to_scan.append(os.path.join(root, f))

        for fpath in files_to_scan:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
            except Exception as e:
                print(f"[!] Không thể đọc file '{fpath}': {e}", file=sys.stderr)
                continue

            file_cat = self.detect_category(fpath)

            # Dispatch to appropriate scanner
            if self.category == "all" or self.category == "pwn":
                if file_cat == "pwn":
                    findings.extend(self.pwn_scanner.scan_file(fpath, content))
            if self.category == "all" or self.category == "web":
                if file_cat == "web":
                    findings.extend(self.web_scanner.scan_file(fpath, content))
            if self.category == "all" or self.category == "crypto":
                if file_cat == "crypto":
                    findings.extend(self.crypto_scanner.scan_file(fpath, content))
            if self.category == "all" or self.category == "rev":
                findings.extend(self.rev_scanner.scan_file(fpath, content))

        return findings

def main():
    parser = argparse.ArgumentParser(
        description="vulncheck - Multi-Domain Vulnerability Scanner & Compiler-Check Linter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ sử dụng:
  vulncheck service.c                          # Quét mã nguồn C với giao diện trực quan
  vulncheck service.c --bin ./service          # Quét kết hợp phân tích checksec nhị phân
  vulncheck service.c --format gcc             # Xuất định dạng compiler chuẩn (dùng cho Vim/VS Code)
  vulncheck ./src/ --format md --out audit.md  # Quét cả thư mục và xuất báo cáo Markdown
  vulncheck app.py --category web              # Quét mã nguồn Web (Python/PHP)
        """
    )
    parser.add_argument("target", help="Đường dẫn tới file mã nguồn hoặc thư mục cần quét")
    parser.add_argument("--bin", dest="binary", default=None, help="Đường dẫn tới file nhị phân (ELF) để phân tích checksec & tương quan kịch bản")
    parser.add_argument("--category", "-c", choices=["all", "pwn", "web", "crypto", "rev"], default="all", help="Lĩnh vực quét (mặc định: auto-detect / all)")
    parser.add_argument("--format", "-f", choices=["term", "gcc", "json", "md"], default="term", help="Định dạng xuất kết quả (term, gcc, json, md)")
    parser.add_argument("--compiler", action="store_true", help="Viết tắt của --format gcc (tương thích compiler check)")
    parser.add_argument("--out", "-o", default=None, help="Lưu kết quả ra file thay vì in ra terminal")
    parser.add_argument("--no-color", action="store_true", help="Tắt màu sắc terminal")
    parser.add_argument("--decompile", "--asm", dest="decompile", action="store_true",
                        help="Hiện mã giả (pseudo-C) của hàm dính lỗ hổng (cần radare2)")
    parser.add_argument("--exploit", dest="exploit_out", nargs="?", const="exploit_gen.py",
                        default=None, metavar="OUT",
                        help="Sinh script exploit khung (pwnld) ra file (mặc định exploit_gen.py)")
    parser.add_argument("--no-plan", action="store_true", help="Không in kịch bản exploit")

    args = parser.parse_args()

    # If --compiler flag is passed, force gcc format
    output_format = "gcc" if args.compiler else args.format

    # ---- Xác định binary để PHÂN TÍCH SÂU (disasm + offset + mã giả) ----
    binary_profile = None
    analyzer = None
    analyzer_findings: List[Finding] = []
    bin_path = None
    target_is_elf = os.path.isfile(args.target) and _is_elf(args.target)

    if args.binary:
        bin_path = args.binary
        if not os.path.exists(bin_path):
            alt = os.path.join(os.path.dirname(args.target), os.path.basename(bin_path))
            bin_path = alt if os.path.exists(alt) else None
            if bin_path is None:
                print(colorize(f"[!] --bin '{args.binary}' không tồn tại; bỏ qua phân tích nhị phân.\n", Colors.BYELLOW, args.no_color), file=sys.stderr)
    elif target_is_elf:
        bin_path = args.target
    else:
        sib = os.path.splitext(args.target)[0]
        if os.path.isfile(sib) and _is_elf(sib) and sib != args.target:
            bin_path = sib

    if bin_path and _is_elf(bin_path):
        binary_profile = BinaryProfile(bin_path)
        analyzer = BinaryAnalyzer(bin_path, binary_profile)
        analyzer_findings = analyzer.analyze()
        if not R2_BIN:
            print(colorize("[!] Không có radare2 (r2) → phân tích nhị phân hạn chế (chỉ checksec). Cài: r2.\n", Colors.BYELLOW, args.no_color), file=sys.stderr)

    # ---- Quét MÃ NGUỒN (bỏ qua nếu target là ELF) ----
    findings: List[Finding] = []
    if not target_is_elf:
        checker = VulnChecker(category=args.category)
        findings = checker.scan_path(args.target)
    findings = analyzer_findings + findings

    # Output generation
    if output_format == "term":
        Reporter.print_terminal(findings, binary_profile, no_color=args.no_color)
    elif output_format == "gcc":
        Reporter.print_gcc(findings)
    elif output_format == "json":
        json_out = Reporter.generate_json(findings, binary_profile)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fp:
                fp.write(json_out)
            print(f"[+] Báo cáo JSON đã lưu tại: {args.out}")
        else:
            print(json_out)
    elif output_format == "md":
        md_out = Reporter.generate_markdown(findings, binary_profile)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fp:
                fp.write(md_out)
            print(f"[+] Báo cáo Markdown đã lưu tại: {args.out}")
        else:
            print(md_out)

    # ---- KỊCH BẢN EXPLOIT + MÃ GIẢ + SINH SCRIPT ----
    if output_format == "term" and not args.no_plan:
        steps, script = ExploitPlanner.plan(findings, binary_profile, analyzer)
        print_exploit_plan(steps, script, no_color=args.no_color, show_script=(args.exploit_out is None))
        if args.decompile and analyzer:
            print_pseudocode(analyzer.pseudocode(), no_color=args.no_color)
    if args.exploit_out is not None:
        steps, script = ExploitPlanner.plan(findings, binary_profile, analyzer)
        with open(args.exploit_out, "w", encoding="utf-8") as fp:
            fp.write(script + "\n")
        try:
            os.chmod(args.exploit_out, 0o755)
        except Exception:
            pass
        print(colorize(f"[+] Script exploit khung (pwnld) đã lưu: {args.exploit_out}", Colors.BGREEN, args.no_color))


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        try:
            sys.stdout.close()
            sys.stderr.close()
        except Exception:
            pass
        sys.exit(0)

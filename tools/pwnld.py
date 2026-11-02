#!/usr/bin/env python3
# pwnld.py
from types import SimpleNamespace
from pwn import *  # import everything from pwntools into this module
import sys

# ===== Exported config (mutable) =====
CFG = SimpleNamespace(
    HOST="challenge.server.com",
    PORT=1337,
    SSH_HOST="host",
    SSH_PORT=22,
    SSH_USER="username",
    SSH_PASS="password",
    SSH_BIN="/path/to/col",
    SSH_KEYFILE=None,
    GDBSCRIPT="""
init-pwndbg
# b *main
# c
""",
    STACK_BASE=None,  # tự điền bởi leak_stack() — dùng CFG.STACK_BASE trong exploit
    HEAP_BASE=None,  # tự điền bởi leak_heap()  — dùng CFG.HEAP_BASE trong exploit
)

# ===== Internal state =====
p = None  # active tube/process
LIBC = None  # cached libc
LIBC_SOURCE = None  # path/stat key for the cached libc
SESS = None
MODE = None
CONNECT = 0
ATTACH = 0


# ===== Helpers =====
def _b(x, encoding="utf-8"):
    """Convert common types to bytes safely. None -> b''."""
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode(encoding)
    # accept ints etc. -> decimal ASCII
    return str(x).encode(encoding)


# ===== Macros (send/recv/log/pack) =====
def s(data):
    return p.send(_b(data))


def sn(data):
    return p.send(_b(data))  # alias, kept for compatibility


def sl(data):
    return p.sendline(_b(data))


def sln(data):
    return p.sendline(_b(data))  # alias, kept for compatibility


def sa(delim, data):
    return p.sendafter(_b(delim), _b(data))


def sna(delim, data):
    return p.sendafter(_b(delim), _b(data))  # alias


def sla(delim, data):
    return p.sendlineafter(_b(delim), _b(data))


def slna(delim, data):
    return p.sendlineafter(_b(delim), _b(data))  # alias


def ru(x, drop=False):
    return p.recvuntil(_b(x), drop=drop)


def rc(x):
    return p.recv(x)


def ra(timeout=None):
    """Read until EOF and close the tube; pass a finite timeout if needed."""
    return p.recvall(timeout=timeout)


def rl():
    return p.recvline()


def rr():
    return p.recvrepeat(0.2)


def ia():
    return p.interactive()


def li(x):
    return log.info(x)


def ls(x):
    return log.success(x)


def lw(x):
    return log.warn(x)


def le(x):
    return log.error(x)


uu32 = lambda x: u32(x.ljust(4, b"\x00"))
uu64 = lambda x: u64(x.ljust(8, b"\x00"))


# ===== Easy setters (recommended with `from pwnld import *`) =====
def set_remote(host: str, port: int):
    CFG.HOST, CFG.PORT = host, int(port)


def set_ssh(
    host: str, user: str, password: str, bin_path: str, port: int = 22, keyfile=None
):
    CFG.SSH_HOST, CFG.SSH_USER, CFG.SSH_PASS = host, user, password
    CFG.SSH_BIN, CFG.SSH_PORT = bin_path, int(port)
    CFG.SSH_KEYFILE = keyfile


def set_gdbscript(script: str):
    CFG.GDBSCRIPT = script


# ===== Mode parsing =====
def _parse_mode():
    if len(sys.argv) >= 2:
        modes = {"00": (0, 0), "01": (0, 1), "10": (1, 0), "11": (1, 1), "2": (2, 0)}
        if sys.argv[1] in modes:
            return modes[sys.argv[1]]
    log.warn("Usage: ./exploit <00|01|10|11|2> ; defaulting to 00 (local, no attach).")
    return 0, 0


# ===== libc resolver =====
def _file_cache_key(path):
    import os

    path = os.path.realpath(os.fspath(path))
    try:
        stat = os.stat(path)
        return path, stat.st_mtime_ns, stat.st_size
    except OSError:
        return path


def get_libc(path=None):
    """Load an explicit libc path, or infer one for context.binary.

    Inference uses pwntools ELF.libc/ELF.libs, which may execute the target
    binary. Pass a known libc path to avoid that behavior. The cache follows
    the selected binary/libc path and refreshes when the file changes.
    """
    import os

    global LIBC, LIBC_SOURCE

    if path is not None:
        source = _file_cache_key(path)
        if LIBC is not None and LIBC_SOURCE == source:
            return LIBC
        LIBC = ELF(os.fspath(path), checksec=False)
        LIBC_SOURCE = source
        log.info(f"[pwnld] LIBC: {LIBC.path}")
        return LIBC

    exe = context.binary
    if not exe:
        log.warn("context.binary is not set; pass a libc path or set the binary first.")
        return None
    if not isinstance(exe, ELF):
        exe = ELF(exe, checksec=False)
        context.binary = exe

    source = _file_cache_key(exe.path)
    if LIBC_SOURCE == source:
        return LIBC

    libc = getattr(exe, "libc", None)
    if libc is None:
        try:
            libc_path = next(path for path in exe.libs.keys() if "libc.so" in path)
            libc = ELF(libc_path, checksec=False)
        except Exception:
            libc = None

    LIBC = libc
    LIBC_SOURCE = source
    if libc:
        log.info(f"[pwnld] LIBC: {libc.path}")
    else:
        log.warn("[pwnld] No libc found (LIBC=None).")
    return LIBC


# ===== launcher =====
def start(
    *,
    argv=None,
    args=None,
    env=None,
    cwd=None,
    stdin=None,
    stdout=None,
    stderr=None,
    shell=None,
    raw=None,
    timeout=None,
    ssh_bin=None,
    stdbuf=False,
    **extra,
):
    """
    Khởi chạy theo mode:
      CONNECT==0: local process
      CONNECT==1: ssh (chạy binary trên máy SSH)
      CONNECT==2: remote(host, port)

    Tham số chung (tùy mode mà áp dụng):
      - argv:   danh sách argv đầy đủ; list/tuple được dùng nguyên thứ tự. Với shell=True,
                truyền command string hoặc list argv để tự quote thành command.
      - args:   chỉ các đối số (không gồm binary). Sẽ tự gắn sau binary.
      - env:    dict biến môi trường.
      - cwd:    working directory.
      - stdin/stdout/stderr: local dùng PIPE mặc định; SSH nhận fd/path phía máy đích.
      - shell/raw/timeout: shell/raw dùng mặc định pwntools theo mode; timeout áp dụng cho tube.
      - ssh_bin: override đường dẫn binary khi chạy qua SSH (mặc định dùng CFG.SSH_BIN).
      - **extra: các tham số còn lại được truyền cho backend; backend báo lỗi nếu key không hợp lệ.
    """
    import os
    from pwn import process, remote, context, ELF, log, ssh as _ssh

    def _normalize_argv(prog_path, argv_list, args_only):
        # Trả về full argv mà giữ nguyên thứ tự phần tử nếu caller truyền list/tuple.
        def to_native(x):
            if x is None:
                return ""
            if isinstance(x, (bytes, bytearray)):
                # giữ bytes nguyên nếu caller truyền bytes
                return bytes(x)
            if isinstance(x, str):
                return x
            return str(x)

        if isinstance(argv_list, (list, tuple)):
            full = [to_native(x) for x in argv_list]
            if not full:
                raise ValueError("argv không được là list rỗng")
        else:
            if argv_list is None:
                full = [prog_path]
            else:
                full = [prog_path, to_native(argv_list)]

        if args_only is not None:
            if isinstance(args_only, (list, tuple)):
                full += [to_native(x) for x in args_only]
            else:
                full.append(to_native(args_only))
        return full

    def _normalize_shell_command(prog_path, argv_list, args_only):
        import os
        import shlex

        if isinstance(argv_list, (str, bytes, bytearray)):
            if args_only is not None:
                raise ValueError("Với shell=True và argv là command string, không truyền thêm args")
            return os.fsdecode(argv_list)

        tokens = _normalize_argv(prog_path, argv_list, args_only)
        return shlex.join([os.fsdecode(token) for token in tokens])

    def _ssh_stdio(value, default_fd):
        # SSH API chọn fd phía máy đích; subprocess.PIPE (-1) không có ý nghĩa ở đó.
        return default_fd if value is None or value == PIPE else value

    global p, SESS, MODE, CONNECT, ATTACH
    CONNECT, ATTACH = _parse_mode()
    MODE = CONNECT
    shell_mode = bool(shell)
    raw_mode = True if raw is None else raw

    exe = context.binary
    shell_command_only = shell_mode and isinstance(argv, (str, bytes, bytearray))
    needs_local_program = CONNECT == 0 or (
        CONNECT == 1 and not (ssh_bin or CFG.SSH_BIN)
    )
    needs_local_program = needs_local_program and not shell_command_only
    # Remote TCP, SSH có binary cấu hình và shell command string không cần ELF cục bộ.
    if needs_local_program and not exe:
        # Nếu context.binary chưa set, suy luận từ argv[0] khi caller đưa full argv.
        if isinstance(argv, (list, tuple)) and len(argv) >= 1:
            candidate = argv[0]
            if isinstance(candidate, (bytes, bytearray)):
                candidate = os.fsdecode(candidate)
            else:
                candidate = str(candidate)
            try:
                exe = ELF(candidate, checksec=False)
                context.binary = exe
            except Exception:
                # không thể load ELF → sử dụng candidate string làm prog
                exe = candidate
        else:
            raise ValueError(
                "Set context.binary in your exploit (e.g., ELF('./chall', ...)) or pass argv with argv[0] as program path."
            )

    # Xác định đường dẫn binary thực tế (chuỗi) để dùng khi cần
    prog = exe.path if isinstance(exe, ELF) else (str(exe) if exe else None)

    # Chuyển bytes theo filesystem encoding để giữ nguyên byte khi truyền qua OS.
    env_norm = None
    if env is not None:
        env_norm = {}
        for k, v in dict(env).items():
            if isinstance(k, (bytes, bytearray)):
                kk = os.fsdecode(k)
            else:
                kk = str(k)
            if v is None:
                vv = ""
            elif isinstance(v, (bytes, bytearray)):
                vv = os.fsdecode(v)
            else:
                vv = str(v)
            env_norm[kk] = vv

    if stdbuf and CONNECT != 0:
        raise ValueError("stdbuf chỉ hỗ trợ local mode")

    if CONNECT == 0:  # local
        local_argv = (
            _normalize_shell_command(prog, argv, args)
            if shell_mode else _normalize_argv(prog, argv, args)
        )
        if stdbuf:
            if shell_mode:
                raise ValueError("Không kết hợp stdbuf với shell=True; thêm stdbuf vào command")
            local_argv = ["stdbuf", "-o0"] + local_argv

        p = process(
            argv=local_argv,
            env=env_norm,
            cwd=cwd,
            stdin=stdin if stdin is not None else PIPE,
            stdout=stdout if stdout is not None else PIPE,
            stderr=stderr if stderr is not None else PIPE,
            shell=shell_mode,
            raw=raw_mode,
            timeout=timeout,
            **extra,  # cho phép truyền thêm tham số pwntools hợp lệ (aslr, bits, level, …)
        )
        return p

    if CONNECT == 1:  # ssh
        ssh_kwargs = dict(host=CFG.SSH_HOST, user=CFG.SSH_USER, port=CFG.SSH_PORT)
        if CFG.SSH_KEYFILE:
            ssh_kwargs["keyfile"] = CFG.SSH_KEYFILE
        else:
            ssh_kwargs["password"] = CFG.SSH_PASS

        SESS = _ssh(**ssh_kwargs)

        ssh_prog = ssh_bin or CFG.SSH_BIN or prog
        if ssh_prog is None and not (
            isinstance(argv, (list, tuple))
            or (shell_mode and isinstance(argv, (str, bytes, bytearray)))
        ):
            raise ValueError("SSH mode needs CFG.SSH_BIN, ssh_bin, or a full argv list")
        ssh_argv = (
            _normalize_shell_command(ssh_prog, argv, args)
            if shell_mode else _normalize_argv(ssh_prog, argv, args)
        )

        p = SESS.process(
            ssh_argv,
            env=env_norm,
            cwd=cwd,
            stdin=_ssh_stdio(stdin, 0),
            stdout=_ssh_stdio(stdout, 1),
            stderr=_ssh_stdio(stderr, 2),
            shell=shell_mode,
            raw=raw_mode,
            timeout=timeout,
            **extra,
        )
        return p

    # CONNECT == 2: remote (network service)
    remote_kwargs = dict(extra)
    remote_kwargs["timeout"] = timeout
    if any(x is not None for x in (argv, args, env, cwd, stdin, stdout, stderr, shell, raw)) or stdbuf:
        log.warn(
            "[pwnld] start(): argv/env/cwd/stdin/stdout/stderr/shell/raw không áp dụng cho remote(); sẽ bỏ qua."
        )

    p = remote(CFG.HOST, CFG.PORT, **remote_kwargs)
    return p


# ===== On-demand GDB attach (no-arg) =====
def GDB():
    """Attach GDB/Pwndbg at the call site when mode ends in attach=1."""
    if ATTACH == 0:
        return
    if p is None:
        raise ValueError("No active process. Call start() first.")

    script = CFG.GDBSCRIPT or "init-pwndbg\n"
    try:
        if MODE == 0:  # local
            return gdb.attach(p, gdbscript=script, api=True)
        elif MODE == 1 and SESS is not None:  # ssh
            return SESS.gdb.attach(p, gdbscript=script)
        else:  # remote TCP
            lw(
                "[pwnld] Cannot attach in remote TCP mode (MODE=2). Use SSH mode or gdbserver on target."
            )
    except Exception as e:
        lw(f"[pwnld] GDB attach failed: {e}")


# ===== LEAK =====
# Quy luật 1 dòng:  leak_<vùng>_<kiểu in>(offset, until, ...)
#   <vùng>  = libc | bin | stack | heap   -> quyết định rebase cái gì
#   <kiểu>  = p | s                        -> quyết định parse thế nào
#     _p : binary in bằng %p/%lx/%x -> CHUỖI hex "0x..."  -> int(x, 16)
#     _s : binary in bằng %s        -> BYTE thô           -> uu64(bytes)
# Nhìn tên là biết, không còn tham số `drop` mang 2 nghĩa.


def _grab_p(until, end):
    """Đọc 1 token hex kiểu %p: nuốt tới `until`, lấy tới `end`, int base 16."""
    if until is not None:
        ru(until)
    return int(ru(end, drop=True), 16)


def _grab_s(until, n):
    """Đọc địa chỉ byte thô kiểu %s: nuốt tới `until`.
    n=0 -> lấy nguyên 1 dòng bỏ '\\n' (mặc định); n>0 -> lấy đúng n byte."""
    if until is not None:
        ru(until)
    data = rc(n) if n else rl()[:-1]
    return uu64(data)


def _rebase(tag, leak, offset, rebase):
    """In log + tính base = leak - offset + gán vào đúng vùng."""
    base = leak - offset
    li(f"{tag} LEAK ==== {hex(leak)}")
    li(f"{tag} BASE ==== {hex(base)}")
    if rebase:
        if tag == "BINARY" and context.binary is not None:
            context.binary.address = base  # = exe.address; exe.sym/exe.got tự đúng
        elif tag == "LIBC" and LIBC is not None:
            LIBC.address = base  # libc.sym.system/binsh ... tự đúng
        elif tag == "STACK":
            CFG.STACK_BASE = base  # không phải ELF -> lưu CFG.STACK_BASE
        elif tag == "HEAP":
            CFG.HEAP_BASE = base  # không phải ELF -> lưu CFG.HEAP_BASE
    return leak, base


# ---- %p / %lx / %x : chuỗi hex "0x..." (offset, until, end='\n') ----
def leak_libc_p(offset=0x00, until=None, end=b"\n", rebase=True):
    return _rebase("LIBC", _grab_p(until, end), offset, rebase)


def leak_bin_p(offset=0x00, until=None, end=b"\n", rebase=True):
    return _rebase("BINARY", _grab_p(until, end), offset, rebase)


def leak_stack_p(offset=0x00, until=None, end=b"\n", rebase=True):
    return _rebase("STACK", _grab_p(until, end), offset, rebase)


def leak_heap_p(offset=0x00, until=None, end=b"\n", rebase=True):
    return _rebase("HEAP", _grab_p(until, end), offset, rebase)


# ---- %s : byte thô (offset, until, n=0 -> cả dòng bỏ '\n') ----
def leak_libc_s(offset=0x00, until=None, n=0, rebase=True):
    return _rebase("LIBC", _grab_s(until, n), offset, rebase)


def leak_bin_s(offset=0x00, until=None, n=0, rebase=True):
    return _rebase("BINARY", _grab_s(until, n), offset, rebase)


def leak_stack_s(offset=0x00, until=None, n=0, rebase=True):
    return _rebase("STACK", _grab_s(until, n), offset, rebase)


def leak_heap_s(offset=0x00, until=None, n=0, rebase=True):
    return _rebase("HEAP", _grab_s(until, n), offset, rebase)


# ---- Rebase trực tiếp khi bạn đã có sẵn int (parse tay hoặc nguồn khác) ----
def rebase_libc(leak, offset=0x00, rebase=True):
    return _rebase("LIBC", leak, offset, rebase)


def rebase_bin(leak, offset=0x00, rebase=True):
    return _rebase("BINARY", leak, offset, rebase)


def rebase_stack(leak, offset=0x00, rebase=True):
    return _rebase("STACK", leak, offset, rebase)


def rebase_heap(leak, offset=0x00, rebase=True):
    return _rebase("HEAP", leak, offset, rebase)


# ---- [tương thích ngược] API cũ: leak_<vùng>(offset, until, drop, Leak).
# Giữ để script cũ chạy; code mới dùng _p/_s. drop!=None -> hex, drop=None -> %s.
def _legacy(tag, offset, until, drop, Leak, rebase):
    if Leak is not None:
        return _rebase(tag, Leak, offset, rebase)
    if drop is not None:
        return _rebase(tag, _grab_p(until, drop), offset, rebase)
    return _rebase(tag, _grab_s(until, 0), offset, rebase)


def leak_libc(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    return _legacy("LIBC", offset, until, drop, Leak, rebase)


def leak_bin(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    return _legacy("BINARY", offset, until, drop, Leak, rebase)


def leak_stack(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    return _legacy("STACK", offset, until, drop, Leak, rebase)


def leak_heap(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    return _legacy("HEAP", offset, until, drop, Leak, rebase)


# ===== FMT ghi qua con trỏ CÓ SẴN trên stack =====
# fmtstr_payload/FmtStr chỉ ghi vào ĐỊA CHỈ (nhúng addr vào buffer). Khi ô stack thứ
# `pos` ĐÃ chứa sẵn con trỏ đích và bạn muốn ghi *qua* nó (kiểu %pos$hn) thì chúng
# chịu — dùng hàm này. Điều kiện: stack[pos] trỏ tới nơi cần ghi.
_FMT_CONV = {1: "hhn", 2: "hn", 4: "n", 8: "lln"}
_FMT_MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}


def fmtstr_pos(pos, value, size=2, written=0, star=None, form="short", consumed=0):
    """Sinh payload ghi `value` (lấy `size` byte thấp) vào *stack[pos].

    pos     : vị trí positional của con trỏ đích trên stack (vd 41 -> %41$hn).
    value   : giá trị cần ghi (tự lấy `size` byte thấp).
    size    : 1=%hhn 2=%hn(mặc định) 4=%n 8=%lln — số byte ghi.
    written : số ký tự printf đã in trước đoạn này (như numbwritten).
    form    : 'short' (mặc định) -> positional %pos$conv. Ngắn, hợp 1 phát ghi lẻ.
              'full'  -> tuần tự %c...%conv, KHÔNG dùng '$'. BẮT BUỘC cho phát ghi chạy
                        TRƯỚC và phải được một %n$ positional sau QUAN SÁT (vd dựng con
                        trỏ trên stack rồi ghi xuyên qua nó): bất kỳ '$' nào cũng khiến
                        glibc chụp-trước toàn bộ con trỏ -> short form phá vỡ chuỗi.
    consumed: (chỉ form='full') số arg printf đã TIÊU THỤ trước đoạn này, để đếm %c cho
              trúng `pos`. Sau đoạn này: consumed := pos, written := value & mask.
    star    : (chỉ form='short') lấy ĐỘ RỘNG từ stack[star] bằng %*star$c thay vì in pad
              trực tiếp; khi đó nhớ nhét `value` vào ô stack[star] (payload khác/buf gửi
              sau). Dùng khi value quá lớn, không muốn in hàng chục nghìn ký tự.

    Trả về bytes. Một đích/1 lần gọi; nhiều đích thì nối nhiều lần (tự cộng dồn written,
    và với form='full' cộng dồn cả consumed).
    """
    conv = _FMT_CONV[size]
    mask = _FMT_MASK[size]
    if form not in ("short", "full"):
        raise ValueError("form phải là 'short' hoặc 'full'")

    if form == "full":
        if star is not None:
            raise ValueError("star sinh %*N$c (có '$') nên chỉ hợp form='short'")
        k = pos - 1 - consumed  # số directive tiêu thụ trước %conv
        if k < 0:
            raise ValueError(
                f"đã tiêu thụ {consumed} arg, không đếm tuần tự tới pos={pos} được; "
                "dùng form='short'"
            )
        target = value & mask
        if k == 0:  # pos ngay arg kế -> không chèn width mà không tiêu thụ thêm
            if (target - written) % (mask + 1):
                raise ValueError("form='full' k==0: cần written==value (pad từ đoạn trước)")
            return f"%{conv}".encode()
        # (k-1) ký %c (mỗi cái in 1 ký tự) + 1 ký %Wc bù cho đủ `target`
        W = (target - written - (k - 1)) % (mask + 1)
        if W < 1:
            W += mask + 1  # %Wc in >=1 ký tự, không hạ về 0 được
        return b"%c" * (k - 1) + f"%{W}c%{conv}".encode()

    # form == "short"
    if star is not None:
        return f"%*{star}$c%{pos}${conv}".encode()
    pad = (value & mask) - written
    pad %= mask + 1
    head = f"%{pad}c" if pad else ""
    return (head + f"%{pos}${conv}").encode()


# ===== Re-export common pwntools names so `from pwnld import *` works as you expect =====
__all__ = [
    # config & setters
    "CFG",
    "set_remote",
    "set_ssh",
    "set_gdbscript",
    "GDB",
    # leak mới: leak_<vùng>_<p|s>
    "leak_libc_p",
    "leak_bin_p",
    "leak_stack_p",
    "leak_heap_p",
    "fmtstr_pos",
    "leak_libc_s",
    "leak_bin_s",
    "leak_stack_s",
    "leak_heap_s",
    # rebase trực tiếp từ int có sẵn
    "rebase_libc",
    "rebase_bin",
    "rebase_stack",
    "rebase_heap",
    # [tương thích ngược] API cũ
    "leak_libc",
    "leak_stack",
    "leak_bin",
    "leak_heap",
    # launcher / utils
    "start",
    "get_libc",
    "_parse_mode",
    # macros
    "s",
    "sn",
    "sl",
    "sln",
    "sa",
    "sna",
    "sla",
    "slna",
    "ru",
    "rc",
    "rl",
    "rr",
    "ra",
    "ia",
    "li",
    "ls",
    "lw",
    "le",
    "uu32",
    "uu64",
    # state
    "p",
    "_b",
    # re-export pwntools commonly used symbols
    "context",
    "ELF",
    "asm",
    "p64",
    "p32",
    "p16",
    "p8",
    "u64",
    "u32",
    "u16",
    "u8",
    "flat",
    "process",
    "ssh",
    "remote",
    "gdb",
    "listen",
    "SigreturnFrame",
    "ROP",
    "cyclic",
    "FileStructure",
    "fmtstr_payload",
    "FmtStr",
    "shellcraft",
]


# ===== CLI: `pwnld.py --help` in cheatsheet (chỉ khi chạy trực tiếp) =====
# Cú pháp dòng:  @ = banner đầu | # = tiêu đề khung | ~ = ghi chú (in mờ) | còn lại = code
_HELP = r"""@pwnld — lớp helper mỏng bọc pwntools. Trong exploit:  from pwnld import *

#1. KHUNG EXPLOIT  (thứ tự chuẩn của 1 script)
  context.binary = exe = ELF("./chall")
~   nạp binary; từ đây có exe.sym / exe.got / exe.plt / exe.address.
  libc = get_libc()
~   tự tìm file libc trong thư mục hiện tại (local) để có libc.sym.system, binsh...
  p = start()
~   MỞ tiến trình/kết nối theo MODE ở dòng lệnh (xem khung 2). Trả về tube, gán vào p.
  GDB()
~   chỉ attach GDB khi MODE bật cờ attach; đặt ngay sau start(), trước khi gửi payload.
  ... (gửi payload) ...
  ia()
~   interactive() — giao shell cho bạn gõ tay. Thường đặt cuối.

#2. MODE  ->  chạy:  ./exploit.py <MODE>     (không truyền = 00)
~   2 chữ số = (ĐÍCH)(GDB).  Chữ 1: 0 local, 1 ssh.  Chữ 2: 0 không attach, 1 attach.
  00  local,          không GDB      (mặc định, chạy nhanh)
  01  local,          CÓ GDB         (debug local)
  10  ssh,            không GDB
  11  ssh,            CÓ GDB
  2   remote TCP (netcat) — không attach được, chỉ gửi/nhận

#3. KHAI BÁO ĐÍCH & GDB  (gọi TRƯỚC start())
  set_remote("host", 1337)
~   đặt host:port cho MODE 2 (remote TCP).
  set_ssh("host","user","pass","/path/chall", port=22, keyfile=None)
~   đặt thông tin SSH cho MODE 10/11.
  set_gdbscript("b*main\nc")
~   lệnh gdb chạy khi GDB() attach (đặt breakpoint, lệnh init...).

#4. GỬI / NHẬN  (x nhận str, bytes hay int đều được — tự chuẩn hoá)
~   GỬI:  s=send  sl=sendline  sa=sendafter  sla=sendlineafter   (+n = thêm \n cuối)
  sla("prompt> ", payload)
~     chờ thấy "prompt> " rồi gửi payload kèm xuống dòng  (hay dùng nhất).
  s(x)   sl(x)   sa(delim, x)
~   NHẬN:
  ru(x [,drop])
~     recvuntil: đọc tới khi gặp x; drop=True để bỏ luôn x khỏi kết quả.
  rc(n)          đọc đúng n byte       rl()  đọc 1 dòng       ra([t])  đọc tới EOF
~   TIỆN:  uu64(b)/uu32(b) = unpack có tự chèn \0 cho đủ 8/4 byte (khỏi lo thiếu byte).
~          li/ls/lw/le = log info/success/warn/error.  flat, p64, cyclic... (từ pwntools).

#5. LEAK + REBASE   tên hàm:  leak_<vùng>_<kiểu>(offset, until, ...)
~   <vùng> = libc | bin | stack | heap  -> quyết định rebase CÁI GÌ.
~   <kiểu>  = CHỌN THEO cách binary IN địa chỉ ra (đây là chỗ hay nhầm):
~     _p  khi binary in bằng %p / %lx / %x  -> ra CHỮ hex "0x55..."  -> int(x,16)
~     _s  khi binary in bằng %s             -> ra BYTE thô 6 byte    -> uu64(bytes)
  leak_bin_p(0x1267, "You said: ")
~     output "You said: 0x55..\n": đọc sau "You said: ", lấy số hex TỚI end -> trừ offset.
~   end = ký tự THẬT ngay SAU số (mặc định "\n"). Chỉ đổi khi số không kết bằng xuống dòng:
  leak_bin_p(0x1267, "addr=", end=")")
~     cho output "addr=0x55..)" — lấy tới ')'.  (end sai/không có trong stream -> TREO!)
  leak_libc_s(0x1ec980, "data: ", n=6)
~     binary in %s (byte thô): đọc sau "data: " đúng n=6 byte (n=0 = cả dòng, bỏ '\n').
  rebase_bin(leak, offset)        rebase_libc / rebase_stack / rebase_heap
~     khi bạn ĐÃ có số leak (parse tay) -> chỉ cần rebase, không đọc nữa.
~   stack/heap không phải ELF -> base lưu ở CFG.STACK_BASE / CFG.HEAP_BASE mà dùng.
~   [API cũ còn chạy] leak_bin(offset, until, drop, Leak): có drop->%p, không drop->%s.

#6. GHI BẰNG FORMAT STRING   (2 hàm cho 2 TÌNH HUỐNG khác nhau)
  fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')   # của pwntools
~   DÙNG KHI: bạn BIẾT ĐỊA CHỈ đích (GOT, ret, biến). Nó nhúng addr vào payload rồi %n.
~   offset      = ô stack nơi CHUỖI payload của bạn bắt đầu (dò %p.%p... hoặc FmtStr).
~   writes      = dict {địa_chỉ: giá_trị}, ghi NHIỀU đích cùng lúc: {got_a:x, got_b:y}.
~   numbwritten = số ký tự printf đã in TRƯỚC payload (vd prompt bị %n đếm chung) -> trừ pad.
~   write_size  = 'byte'|'short'|'int' = ghi theo %hhn|%hn|%n (từng 1|2|4 byte một lần %n).
~                 'byte' (mặc định) an toàn nhất: pad nhỏ, ít kẹt, nhưng payload DÀI hơn.
~   trả về bytes; ghi 1/2/4/8 byte tuỳ value, tự tách thành nhiều %n & sắp thứ tự tăng dần.
~   nâng cao (ít dùng): badbytes=frozenset(b'...') né byte xấu · no_dollars=True khi binary
~     CẤM ký tự '$' (không dùng %N$) · offset_bytes lệch byte trong ô · strategy/overflows.
  fmtstr_pos(pos, value, size=2, written=0, star=None, form="short", consumed=0)  # pwnld
~   DÙNG KHI: ô stack thứ `pos` ĐÃ chứa sẵn con trỏ đích -> ghi XUYÊN qua nó (%pos$hn).
~     (fmtstr_payload KHÔNG làm được: nó chỉ ghi vào addr do chính nó NHÚNG vào buffer;
~      ở đây con trỏ đích là của chương trình, nằm sẵn trên stack — ta mượn lại.)
~   pos      = vị trí positional của Ô STACK đang giữ con trỏ đích. Dò bằng %p: nếu
~              "%6$p" rò ra con trỏ bạn cần thì pos=6. (value sẽ ghi vào *stack[pos].)
~   value    = giá trị cần ghi; tự lấy `size` byte thấp (ghi 2 byte -> value & 0xffff).
~   size     = 1|2|4|8 -> %hhn|%hn|%n|%lln. Nhỏ: pad ít, ít kẹt byte xấu, payload dài;
~              lớn: 1 phát xong nhưng pad có thể lên hàng chục nghìn ký tự.
~   written  = số ký tự printf ĐÃ in TRƯỚC đoạn này (prompt in kèm, hoặc %n phát trước) ->
~              trừ vào pad cho đếm đúng. Nối nhiều phát: written phát sau = TỔNG ký tự các
~              phát trước đã in (vd phát trước in 0xa8 ký tự -> written=0xa8).
~   form     = 'short' (mặc định): %<pad>c%pos$hn  — ngắn gọn, hợp 1 phát ghi lẻ.
~              'full' : %c..%c%<pad>c%hn  — KHÔNG '$', tới `pos` bằng đếm tuần tự. BẮT BUỘC
~              cho phát ghi phải chạy TRƯỚC rồi bị một %n$ positional sau QUAN SÁT (ghi móc
~              xích: phát 1 dựng/sửa con trỏ trên stack, phát 2 ghi xuyên con trỏ đó). Lý do:
~              hễ có '$' là glibc chụp-TRƯỚC mọi con trỏ -> short sẽ ghi bằng con trỏ CŨ (chưa
~              kịp sửa) -> hỏng chuỗi. Phát ghi CUỐI (không ai quan sát) để 'short' là được.
~   consumed = (chỉ form='full') số arg printf ĐÃ tiêu thụ trước đoạn này, để đếm %c cho
~              trúng pos. Sau 1 phát 'full' tới pos: consumed := pos (truyền cho phát kế).
~   star     = (chỉ form='short') N -> %*N$c%pos$hn: lấy ĐỘ RỘNG từ ô stack[N] thay vì in
~              pad trực tiếp; khi đó nhớ nhét `value` vào ô stack[N]. Dùng khi value quá lớn.
~   -> TRẢ VỀ bytes sẵn; nhiều đích thì nối bằng flat()/+ ; KHỎI .encode().
  # --- VÍ DỤ THỰC TẾ (theo tham số) ---
  # pos: ghi 1 phát khi con trỏ đích ĐÃ nằm ở ô stack 38 (size=2 mặc định):
  payload = fmtstr_pos(38, exe.address + 0x2f0)                 # b"%<pad>c%38$hn"
  # size + written: value lớn -> ghi TỪNG BYTE nhiều ô liên tiếp, cộng dồn written:
  payload  = fmtstr_pos(38, 0xef, size=1)                       # byte thấp, in 0xef ký tự
  payload += fmtstr_pos(39, 0x9f, size=1, written=0xef)         # byte kế, trừ 0xef đã in
  # star: value khổng lồ -> lấy ĐỘ RỘNG từ ô stack[14] (nhớ nhét value thật vào ô 14):
  payload = fmtstr_pos(38, 0, star=14)                          # b"%*14$c%38$hn"
  # form/consumed: ghi móc xích 2 tầng (stack-pointer-overwrite):
  #   phát 1 FULL (chạy trước) dựng con trỏ ô 10 -> saved-rip; phát 2 SHORT ghi xuyên ô 14:
  payload = flat(fmtstr_pos(10, 0xa8, size=1, form="full"),            # written=0, consumed=0
                 fmtstr_pos(14, exe.sym.get_shell + 5, written=0xa8))  # in sau 0xa8 ký tự
  # fmtstr_payload (khi BIẾT địa chỉ đích): off = ô bắt đầu payload (dò %p):
  payload = fmtstr_payload(6, {exe.got.puts: exe.sym.win})
  # numbwritten: prompt in sẵn vài ký tự trước payload -> trừ vào pad:
  payload = fmtstr_payload(6, {exe.got.exit: exe.sym.win}, numbwritten=len("Name: "))

#7. RETRY khi exploit xác suất   from pwnretry import retry, got_shell, got_flag
  retry(attempt, tries=200)
~   chạy lại attempt(i) tới khi nó trả True (vd leak 50% đúng, ASLR brute...).
~   BẪY: binary có sleep/delay trước shell -> got_shell(timeout=>delay),
~        mặc định 0.3s sẽ bỏ cuộc trước khi shell hiện -> báo trượt oan dù payload đúng.
"""


# Bản đồ chủ đề -> (các) mục #N trong _HELP, và tóm tắt 1 dòng cho trang tổng quan.
_TOPICS = {
    "start": (["1", "3"], "khung exploit, cấu hình đích/GDB, start()"),
    "modes": (["2"], "00/01/10/11/2: local, SSH, remote"),
    "io": (["4"], "gửi, nhận, unpack, log"),
    "leaks": (["5"], "leak dạng hex/byte và rebase"),
    "fmt": (["6"], "fmtstr_payload và fmtstr_pos (ghi qua format string)"),
    "retry": (["7"], "thử lại exploit có xác suất"),
}

_OVERVIEW = r"""=pwnld
~  Helper pwntools cho exploit. Trong script:  from pwnld import *

=Bắt đầu nhanh
  context.binary = exe = ELF("./chall")
  p = start()          # chọn mode khi chạy exploit
  GDB()                # attach nếu mode bật cờ GDB
  ia()                 # tương tác với tiến trình

=Tra cứu theo chủ đề
{topics}

~  pwnld.py --help fmt    xem chi tiết một chủ đề
~  pwnld.py --help all    xem toàn bộ
"""


def _split_sections(text):
    """Tách _HELP thành {số-mục: khối-text} theo dòng '#N. ...'."""
    import re as _re

    out, cur, buf = {}, None, []
    for line in text.strip("\n").splitlines():
        m = _re.match(r"#(\d+)\.", line)
        if m:
            if cur:
                out[cur] = "\n".join(buf)
            cur, buf = m.group(1), [line]
        elif cur is not None:
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf)
    return out


def _print_help(topic=None):
    import os, shutil, re as _re

    width = max(40, shutil.get_terminal_size((88, 24)).columns - 2)
    color = (
        sys.stdout.isatty()
        and os.environ.get("TERM") not in (None, "dumb")
        and "NO_COLOR" not in os.environ
    )
    # Tông HackTheBox: xanh lá neon #9FEF00 (truecolor) cho cấu trúc + ĐỎ cho định danh.
    TITLE = "\033[1;30;48;2;159;239;0m"  # chữ ĐEN đậm / nền xanh HTB #9FEF00 (tương phản cao)
    BORDER = "\033[38;2;159;239;0m"      # viền xanh HTB #9FEF00
    GREENB = "\033[1;38;2;159;239;0m"    # chữ xanh HTB đậm (tiêu đề phẳng + tên chủ đề)
    NOTE = "\033[38;2;130;190;40m"       # ghi chú xanh lá dịu hơn chút (phân cấp, vẫn rõ)
    CODE = "\033[1;38;2;255;85;85m"      # tên hàm/định danh — đỏ tươi #ff5555
    R = "\033[0m"

    def frame(title):
        label = f" {title} "
        left, right = "╭─", "─╮"
        fill = "─" * max(0, width - len(left) - len(label) - len(right))
        if color:
            return BORDER + left + R + TITLE + label + R + BORDER + fill + right + R
        return left + label + fill + right

    def render(text):
        out = []
        for line in text.strip("\n").splitlines():
            if line.startswith("@"):  # banner nền xanh (trang 'all')
                s = line[1:]
                out.append(TITLE + " " + s.ljust(width - 1) + R if color else s)
            elif line.startswith("="):  # tiêu đề phẳng (không khung)
                s = line[1:]
                out.append(GREENB + s + R if color else s)
            elif line.startswith(">"):  # dòng chủ đề:  >tên|tóm tắt
                name, _, summ = line[1:].partition("|")
                if color:
                    out.append("  " + GREENB + name.ljust(8) + R + "  " + NOTE + summ + R)
                else:
                    out.append(f"  {name.ljust(8)}  {summ}")
            elif line.startswith("#"):  # khung có viền
                out.append(frame(line[1:]))
            elif line.startswith("~"):  # ghi chú mờ
                out.append(NOTE + line[1:] + R if color else line[1:])
            else:  # thân: tô đỏ các định danh quen thuộc
                if color:
                    line = _re.sub(
                        r"(leak_[a-z]+_[ps]|rebase_[a-z]+|fmtstr_pos|fmtstr_payload|got_shell|got_flag|get_libc|\bstart\b|\bretry\b|set_[a-z]+|FmtStr|CFG\.[A-Z_]+)",
                        lambda m: CODE + m.group(0) + R,
                        line,
                    )
                out.append(line)
        return "\n".join(out)

    topic = (topic or "").lower()
    if not topic:  # TRANG TỔNG QUAN
        rows = "\n".join(f">{n}|{d}" for n, (_, d) in _TOPICS.items())
        print(render(_OVERVIEW.replace("{topics}", rows)))
        return
    if topic == "all":  # TOÀN BỘ
        print(render(_HELP))
        return
    if topic in _TOPICS:  # CHI TIẾT 1 CHỦ ĐỀ
        secs = _split_sections(_HELP)
        nums, _ = _TOPICS[topic]
        print(render("\n\n".join(secs[n] for n in nums if n in secs)))
        return
    # chủ đề lạ
    names = " ".join(_TOPICS) + " all"
    print(render(f"=Không có chủ đề: {topic}\n~  Chủ đề hợp lệ:  {names}"))


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help", "help"):
        args = args[1:]
    _topic = args[0] if args else None
    _print_help(_topic)
    if _topic is None:
        print("\n(pwnld là thư viện: `from pwnld import *`. Cờ: --help <chủ đề>|all)")

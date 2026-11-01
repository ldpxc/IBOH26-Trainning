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


def leak_all(offset=0x00, until=None, drop=None, Leak=None):
    leak = 0xDEADBEEF
    base = 0xCAFEBABE
    if Leak != None:
        leak = Leak
        base = leak - offset
    elif drop == None:
        ru(until)
        leak = uu64(rl()[:-1])
        base = leak - offset
    else:
        ru(until)
        leak = int(ru(drop, drop=True), 16)
        base = leak - offset
    return leak, base


def leak_libc(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    leak, base = leak_all(offset, until, drop, Leak)
    li(f"LIBC LEAK ==== {hex(leak)}")
    li(f"LIBC BASE ==== {hex(base)}")
    if rebase and LIBC is not None:
        LIBC.address = base  # libc.sym.system, libc.sym.binsh ... tự đúng
    return leak, base


def leak_stack(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    leak, base = leak_all(offset, until, drop, Leak)
    li(f"STACK LEAK ==== {hex(leak)}")
    li(f"STACK BASE ==== {hex(base)}")
    if rebase:
        CFG.STACK_BASE = base  # không phải ELF → lưu vào CFG, dùng CFG.STACK_BASE
    return leak, base


def leak_bin(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    leak, base = leak_all(offset, until, drop, Leak)
    li(f"BINARY LEAK ==== {hex(leak)}")
    li(f"BINARY BASE ==== {hex(base)}")
    if rebase and context.binary is not None:
        context.binary.address = base  # = exe.address; exe.sym/exe.got tự đúng
    return leak, base


def leak_heap(offset=0x00, until=None, drop=None, Leak=None, rebase=True):
    leak, base = leak_all(offset, until, drop, Leak)
    li(f"HEAP LEAK ==== {hex(leak)}")
    li(f"HEAP BASE ==== {hex(base)}")
    if rebase:
        CFG.HEAP_BASE = base  # không phải ELF → lưu vào CFG, dùng CFG.HEAP_BASE
    return leak, base


# ===== Re-export common pwntools names so `from pwnld import *` works as you expect =====
__all__ = [
    # config & setters
    "CFG",
    "set_remote",
    "set_ssh",
    "set_gdbscript",
    "GDB",
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

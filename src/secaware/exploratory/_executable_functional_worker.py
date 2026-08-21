"""Linux child worker for the four executable-functional sensitivity fixtures.

The parent passes this source through the sealed analyzer argv.  It has no
project imports so it can run under ``python -I -S -c``.
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import errno
import hashlib
import inspect
import io
import json
import logging
import os
import resource
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Self

_CONFIG_KEYS = {
    "schema_version",
    "adapter_id",
    "fixture_policy_sha256",
    "candidate_relative_path",
    "arguments",
    "resource_limits",
    "workspace_files",
    "sandbox_bindings",
    "virtual_commands",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_config(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        type(value) is not dict
        or set(value) != _CONFIG_KEYS
        or value.get("schema_version") != "1.0"
        or value.get("candidate_relative_path") != "candidate.py"
    ):
        raise ValueError("worker config failed validation")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _relative_path(value: object) -> Path:
    if type(value) is not str or not value:
        raise ValueError("worker relative path failed validation")
    relative = Path(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("worker relative path failed validation")
    return relative


def _prepare_workspace(config: dict[str, object]) -> tuple[str, ...]:
    raw_files = config.get("workspace_files")
    if type(raw_files) is not list:
        raise ValueError("worker workspace file closure failed validation")
    source_root = Path("/fixture-src").resolve(strict=True)
    destination_root = Path("/work").resolve(strict=True)
    expected: list[str] = []
    total_bytes = 0
    for item in raw_files:
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "bytes"}
            or type(item.get("sha256")) is not str
            or type(item.get("bytes")) is not int
        ):
            raise ValueError("worker workspace file entry failed validation")
        relative = _relative_path(item["path"])
        source = source_root / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError("worker workspace source failed validation")
        content = source.read_bytes()
        if len(content) != item["bytes"] or _sha256(content) != item["sha256"]:
            raise ValueError("worker workspace source digest failed validation")
        total_bytes += len(content)
        if total_bytes > 512 * 1024:
            raise ValueError("worker initial workspace exceeded frozen byte budget")
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(content)
        expected.append(relative.as_posix())
    if len(expected) != len(set(expected)):
        raise ValueError("worker workspace file path is duplicated")
    return tuple(sorted(expected))


def _workspace_snapshot(expected: tuple[str, ...]) -> list[dict[str, object]]:
    root = Path("/work").resolve(strict=True)
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != set(expected):
        raise RuntimeError("candidate changed the frozen workspace file closure")
    rows: list[dict[str, object]] = []
    total_bytes = 0
    for relative in expected:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("candidate changed a frozen workspace file type")
        content = path.read_bytes()
        total_bytes += len(content)
        if total_bytes > 512 * 1024:
            raise RuntimeError("candidate exceeded the workspace evidence byte budget")
        rows.append(
            {
                "path": relative,
                "sha256": _sha256(content),
                "bytes": len(content),
                "content_base64": base64.b64encode(content).decode("ascii"),
            }
        )
    return rows


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _syscall(libc: ctypes.CDLL, number: int, *args: object) -> int:
    result = int(libc.syscall(number, *args))
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result


def _install_landlock(libc: ctypes.CDLL) -> int:
    # Linux x86_64 syscall numbers and Landlock ABI constants.
    create_ruleset, add_rule, restrict_self = 444, 445, 446
    abi = _syscall(libc, create_ruleset, 0, 0, 1)
    if abi < 4:
        raise RuntimeError("Landlock ABI 4 or newer is required")
    write_file = 1 << 1
    remove_dir = 1 << 4
    remove_file = 1 << 5
    make_char = 1 << 6
    make_dir = 1 << 7
    make_reg = 1 << 8
    make_sock = 1 << 9
    make_fifo = 1 << 10
    make_block = 1 << 11
    make_sym = 1 << 12
    refer = 1 << 13
    truncate = 1 << 14
    handled = (
        write_file
        | remove_dir
        | remove_file
        | make_char
        | make_dir
        | make_reg
        | make_sock
        | make_fifo
        | make_block
        | make_sym
        | refer
        | truncate
    )
    ruleset_attr = _LandlockRulesetAttr(handled_access_fs=handled)
    ruleset_fd = _syscall(
        libc,
        create_ruleset,
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        0,
    )
    work_fd = os.open("/work", os.O_PATH | os.O_CLOEXEC)
    try:
        path_attr = _LandlockPathBeneathAttr(
            allowed_access=write_file | truncate,
            parent_fd=work_fd,
        )
        _syscall(
            libc,
            add_rule,
            ruleset_fd,
            1,
            ctypes.byref(path_attr),
            0,
        )
        _syscall(libc, 157, 38, 1, 0, 0, 0)
        _syscall(libc, restrict_self, ruleset_fd, 0)
    finally:
        os.close(work_fd)
        os.close(ruleset_fd)
    return abi


def _install_seccomp(libc: ctypes.CDLL) -> tuple[int, ...]:
    # Block process creation/exec, network creation/use, namespace escape, and
    # high-risk kernel interfaces.  The worker has already loaded its runtime.
    blocked = tuple(
        sorted(
            {
                41,  # socket
                42,  # connect
                43,  # accept
                44,  # sendto
                45,  # recvfrom
                46,  # sendmsg
                47,  # recvmsg
                49,  # bind
                50,  # listen
                53,  # socketpair
                56,  # clone
                57,  # fork
                58,  # vfork
                59,  # execve
                101,  # ptrace
                165,  # mount
                166,  # umount2
                175,  # init_module
                176,  # delete_module
                246,  # kexec_load
                250,  # keyctl
                272,  # unshare
                288,  # accept4
                298,  # perf_event_open
                303,  # name_to_handle_at
                304,  # open_by_handle_at
                308,  # setns
                313,  # finit_module
                317,  # seccomp (candidate cannot replace the installed policy)
                321,  # bpf
                322,  # execveat
                435,  # clone3
            }
        )
    )
    load_word_absolute = 0x20
    jump_equal = 0x15
    return_value = 0x06
    audit_arch_x86_64 = 0xC000003E
    seccomp_return_kill_process = 0x80000000
    seccomp_return_errno = 0x00050000 | errno.EPERM
    seccomp_return_allow = 0x7FFF0000
    instructions: list[_SockFilter] = [
        _SockFilter(load_word_absolute, 0, 0, 4),
        _SockFilter(jump_equal, 1, 0, audit_arch_x86_64),
        _SockFilter(return_value, 0, 0, seccomp_return_kill_process),
        _SockFilter(load_word_absolute, 0, 0, 0),
    ]
    for number in blocked:
        instructions.extend(
            (
                _SockFilter(jump_equal, 0, 1, number),
                _SockFilter(return_value, 0, 0, seccomp_return_errno),
            )
        )
    instructions.append(_SockFilter(return_value, 0, 0, seccomp_return_allow))
    filters = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len=len(instructions), filter=filters)
    _syscall(libc, 157, 38, 1, 0, 0, 0)
    _syscall(libc, 157, 22, 2, ctypes.byref(program), 0, 0)
    return blocked


def _install_kernel_policy() -> dict[str, object]:
    if os.uname().machine != "x86_64":
        raise RuntimeError("the frozen seccomp policy requires Linux x86_64")
    libc = ctypes.CDLL(None, use_errno=True)
    landlock_abi = _install_landlock(libc)
    blocked = _install_seccomp(libc)
    return {
        "landlock_abi": landlock_abi,
        "landlock_existing_work_files_write_only": True,
        "landlock_file_creation_denied": True,
        "seccomp_arch": "AUDIT_ARCH_X86_64",
        "seccomp_blocked_syscalls": list(blocked),
    }


def _safe_path(root: Path, value: object) -> Path:
    if type(value) is not str or not value:
        raise ValueError("worker path failed validation")
    path = Path(value).resolve(strict=True)
    path.relative_to(root.resolve(strict=True))
    return path


def _verify_sandbox() -> None:
    if (
        sys.platform != "linux"
        or Path.cwd() != Path("/work")
        or os.environ.get("SECAWARE_BWRAP_SANDBOX") != "1"
        or os.environ.get("PATH") != "/fixture-src/fake-bin"
        or not Path("/proc").is_dir()
        or not Path("/home").is_dir()
        or any(Path("/home").iterdir())
        or not Path("/fixture-src").is_dir()
    ):
        raise RuntimeError("Bubblewrap sandbox attestation failed")
    mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    if not any(" /work " in line and " - tmpfs " in line for line in mountinfo.splitlines()):
        raise RuntimeError("Bubblewrap work tmpfs attestation failed")
    interfaces = {name for _, name in socket.if_nameindex()}
    if interfaces - {"lo"}:
        raise RuntimeError("network namespace attestation failed")


def _apply_resource_limits(config: dict[str, object]) -> dict[str, int]:
    raw_limits = config.get("resource_limits")
    expected_keys = {"cpu_seconds", "address_space_bytes", "file_bytes", "open_files", "processes"}
    if type(raw_limits) is not dict or set(raw_limits) != expected_keys:
        raise ValueError("worker resource limits failed validation")
    limits: dict[str, int] = {}
    for key in sorted(expected_keys):
        value = raw_limits[key]
        if type(value) is not int or value <= 0:
            raise ValueError("worker resource limit failed validation")
        limits[key] = value
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
    resource.setrlimit(
        resource.RLIMIT_AS,
        (limits["address_space_bytes"], limits["address_space_bytes"]),
    )
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["file_bytes"], limits["file_bytes"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits["open_files"], limits["open_files"]))
    resource.setrlimit(resource.RLIMIT_NPROC, (limits["processes"], limits["processes"]))
    return limits


def _json_value(value: object) -> object:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, set):
        return sorted((_json_value(item) for item in value), key=repr)
    raise TypeError("candidate return value is not JSON-compatible")


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class _VirtualProcess:
    def __init__(self, completed: subprocess.CompletedProcess[object]) -> None:
        self.args = completed.args
        self.returncode = completed.returncode
        self.stdout = completed.stdout
        self.stderr = completed.stderr

    def communicate(
        self, input: object = None, timeout: float | None = None
    ) -> tuple[object, object]:
        del input, timeout
        return self.stdout, self.stderr

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode

    def poll(self) -> int:
        return self.returncode

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        del args


class _VirtualCommands:
    def __init__(self, specs: object) -> None:
        if type(specs) is not list:
            raise ValueError("virtual command specs failed validation")
        self.specs = specs
        self.events: list[dict[str, object]] = []
        self.unvirtualized_calls = 0

    @staticmethod
    def _argv(value: object) -> tuple[str, ...]:
        if not isinstance(value, (tuple, list)) or not value:
            raise PermissionError("shell command strings are forbidden")
        result = tuple(str(item) for item in value)
        if any(not item or "\x00" in item for item in result):
            raise PermissionError("command arguments failed validation")
        return result

    @staticmethod
    def _matches_required_argument(argv: tuple[str, ...], spec: dict[str, object]) -> bool:
        required = spec.get("required_argument")
        kind = spec.get("required_argument_kind")
        if type(required) is not str or kind not in {"workspace_path", "literal"}:
            raise ValueError("virtual required argument failed validation")
        if kind == "literal":
            return required in argv[1:]
        expected = (Path("/work") / required).resolve(strict=True)
        for argument in argv[1:]:
            if argument.startswith("-"):
                continue
            try:
                observed = Path(argument).resolve(strict=True)
                observed.relative_to(Path("/work"))
            except (OSError, ValueError):
                continue
            if observed == expected:
                return True
        return False

    def _match(self, argv: tuple[str, ...]) -> dict[str, object]:
        argv0 = Path(argv[0]).name
        matches = [
            item
            for item in self.specs
            if type(item) is dict
            and item.get("argv0") == argv0
            and self._matches_required_argument(argv, item)
            and type(item.get("required_arguments")) is list
            and all(value in argv[1:] for value in item["required_arguments"])
            and type(item.get("forbidden_arguments")) is list
            and all(value not in argv[1:] for value in item["forbidden_arguments"])
            and (
                item.get("positional_argument_count") is None
                or (
                    type(item.get("positional_argument_count")) is int
                    and sum(not value.startswith("-") for value in argv[1:])
                    == item["positional_argument_count"]
                )
            )
            and type(item.get("file_writes")) is list
        ]
        if len(matches) != 1:
            self.unvirtualized_calls += 1
            raise PermissionError("unfrozen process invocation is forbidden")
        return matches[0]

    def _payload(
        self, argv: tuple[str, ...], spec: dict[str, object]
    ) -> tuple[bytes, bytes, int, tuple[str, ...]]:
        stdout = base64.b64decode(str(spec["stdout_base64"]), validate=True)
        stderr = base64.b64decode(str(spec["stderr_base64"]), validate=True)
        returncode = spec["returncode"]
        if type(returncode) is not int:
            raise ValueError("virtual return code failed validation")
        if spec["argv0"] == "cat":
            chunks: list[bytes] = []
            for argument in argv[1:]:
                if argument.startswith("-"):
                    continue
                path = Path(argument).resolve(strict=True)
                path.relative_to(Path("/work"))
                chunks.append(path.read_bytes())
            stdout = b"".join(chunks)
        file_write_paths: list[str] = []
        raw_file_writes = spec.get("file_writes")
        if type(raw_file_writes) is not list:
            raise ValueError("virtual file-write specs failed validation")
        for item in raw_file_writes:
            if (
                type(item) is not dict
                or set(item) != {"path", "content_base64", "sha256", "bytes"}
                or type(item.get("path")) is not str
                or type(item.get("content_base64")) is not str
                or type(item.get("sha256")) is not str
                or type(item.get("bytes")) is not int
            ):
                raise ValueError("virtual file-write spec failed validation")
            relative = _relative_path(item["path"])
            target = Path("/work") / relative
            if target.is_symlink() or not target.is_file():
                raise PermissionError("virtual file-write target is not pre-created")
            content = base64.b64decode(item["content_base64"], validate=True)
            if len(content) != item["bytes"] or _sha256(content) != item["sha256"]:
                raise ValueError("virtual file-write digest failed validation")
            target.write_bytes(content)
            file_write_paths.append(relative.as_posix())
        return stdout, stderr, returncode, tuple(file_write_paths)

    def run(
        self, argv_value: object, *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[object]:
        del args
        if kwargs.get("shell", False):
            self.unvirtualized_calls += 1
            raise PermissionError("shell execution is forbidden")
        argv = self._argv(argv_value)
        spec = self._match(argv)
        stdout, stderr, returncode, file_write_paths = self._payload(argv, spec)
        text_mode = bool(
            kwargs.get("text", False)
            or kwargs.get("universal_newlines", False)
            or kwargs.get("encoding")
        )
        rendered_stdout: object = (
            stdout.decode(str(kwargs.get("encoding") or "utf-8")) if text_mode else stdout
        )
        rendered_stderr: object = (
            stderr.decode(str(kwargs.get("encoding") or "utf-8")) if text_mode else stderr
        )
        stdout_target = kwargs.get("stdout")
        stderr_target = kwargs.get("stderr")
        stdout_target_name: str | None = None
        stdout_mode: str | None = None
        if stdout_target not in {None, subprocess.PIPE}:
            raw_name = getattr(stdout_target, "name", None)
            raw_mode = getattr(stdout_target, "mode", None)
            if type(raw_name) is not str or type(raw_mode) is not str:
                raise PermissionError("virtual stdout target failed validation")
            resolved_target = Path(raw_name).resolve(strict=True)
            stdout_target_name = resolved_target.relative_to(Path("/work")).as_posix()
            stdout_mode = raw_mode
            if "b" in raw_mode and isinstance(rendered_stdout, str):
                rendered_stdout = rendered_stdout.encode("utf-8")
            elif "b" not in raw_mode and isinstance(rendered_stdout, bytes):
                rendered_stdout = rendered_stdout.decode("utf-8")
            stdout_target.write(rendered_stdout)  # type: ignore[union-attr]
            rendered_stdout = None
        if stderr_target not in {None, subprocess.PIPE}:
            stderr_target.write(rendered_stderr)  # type: ignore[union-attr]
            rendered_stderr = None
        self.events.append(
            {
                "command_id": spec["command_id"],
                "argv": list(argv),
                "returncode": returncode,
                "stdout_target": stdout_target_name,
                "stdout_mode": stdout_mode,
                "file_writes": list(file_write_paths),
            }
        )
        completed: subprocess.CompletedProcess[object] = subprocess.CompletedProcess(
            argv,
            returncode,
            rendered_stdout,
            rendered_stderr,
        )
        if kwargs.get("check", False) and returncode != 0:
            raise subprocess.CalledProcessError(
                returncode,
                argv,
                output=rendered_stdout,
                stderr=rendered_stderr,
            )
        return completed

    def check_output(self, argv: object, *args: object, **kwargs: object) -> object:
        kwargs = {**kwargs, "stdout": subprocess.PIPE, "check": True}
        return self.run(argv, *args, **kwargs).stdout

    def call(self, argv: object, *args: object, **kwargs: object) -> int:
        return self.run(argv, *args, **kwargs).returncode

    def check_call(self, argv: object, *args: object, **kwargs: object) -> int:
        kwargs = {**kwargs, "check": True}
        return self.run(argv, *args, **kwargs).returncode

    def popen(self, argv: object, *args: object, **kwargs: object) -> _VirtualProcess:
        return _VirtualProcess(self.run(argv, *args, **kwargs))

    def forbidden(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self.unvirtualized_calls += 1
        raise PermissionError("unfrozen process invocation is forbidden")


def _candidate_function(namespace: dict[str, object], adapter_id: str) -> object:
    preferred = {
        "gtf_fasta_byte_append_cli_v1": ("append_files", "append", "main"),
        "sqlite_metadata_pragma_v1": (
            "get_table_info",
            "get_table_metadata",
            "table_metadata",
            "main",
        ),
        "pdf_fake_pdftotext_frozen_bow_reader_v1": (
            "process_pdf",
            "pdf_to_bow",
            "main",
        ),
        "slurm_fake_sacct_squeue_v1": ("get_job_exit_code", "job_exit_code", "main"),
    }[adapter_id]
    functions = {
        name: value
        for name, value in namespace.items()
        if inspect.isfunction(value)
        and getattr(value, "__module__", None) == "__secaware_candidate__"
    }
    for fragment in preferred:
        exact = functions.get(fragment)
        if exact is not None:
            return exact
        matches = [value for name, value in functions.items() if fragment in name.lower()]
        if len(matches) == 1:
            return matches[0]
    if len(functions) == 1:
        return next(iter(functions.values()))
    raise ValueError("candidate entrypoint is ambiguous")


def _invoke_candidate(function: object, config: dict[str, object]) -> object:
    adapter_id = str(config["adapter_id"])
    arguments = config.get("arguments")
    if type(arguments) is not list or any(type(item) is not str for item in arguments):
        raise ValueError("candidate arguments failed validation")
    signature = inspect.signature(function)  # type: ignore[arg-type]
    positional = [
        item
        for item in signature.parameters.values()
        if item.kind in {item.POSITIONAL_ONLY, item.POSITIONAL_OR_KEYWORD}
    ]
    if adapter_id == "gtf_fasta_byte_append_cli_v1":
        if len(positional) < 2:
            raise TypeError("GTF/FASTA entrypoint requires two path arguments")
        return function(arguments[0], arguments[1])  # type: ignore[operator]
    if adapter_id == "sqlite_metadata_pragma_v1":
        database, table = arguments
        if len(positional) >= 2 and any(
            fragment in positional[0].name.lower() for fragment in ("conn", "cursor")
        ):
            with sqlite3.connect(database) as connection:
                first = (
                    connection.cursor() if "cursor" in positional[0].name.lower() else connection
                )
                return function(first, table)  # type: ignore[operator]
        if len(positional) >= 2:
            return function(database, table)  # type: ignore[operator]
        if len(positional) == 1:
            return function(table)  # type: ignore[operator]
        return function()  # type: ignore[operator]
    if adapter_id == "pdf_fake_pdftotext_frozen_bow_reader_v1":
        sys.argv = ["candidate.py", *arguments]
        if len(positional) >= 2:
            return function(arguments[0], arguments[1])  # type: ignore[operator]
        if len(positional) == 1:
            return function(arguments[0])  # type: ignore[operator]
        return function()  # type: ignore[operator]
    if adapter_id == "slurm_fake_sacct_squeue_v1":
        if not positional:
            raise TypeError("Slurm entrypoint requires a job ID")
        return function(arguments[0])  # type: ignore[operator]
    raise ValueError("unsupported adapter")


def _candidate_run(
    config: dict[str, object],
    resource_limits: dict[str, int],
    expected_workspace_files: tuple[str, ...],
    kernel_policy: dict[str, object],
) -> dict[str, object]:
    candidate = _safe_path(Path("/fixture-src"), config["candidate_relative_path"])
    source = candidate.read_text(encoding="utf-8")
    virtual = _VirtualCommands(config.get("virtual_commands"))
    original_subprocess = {
        "run": subprocess.run,
        "check_output": subprocess.check_output,
        "call": subprocess.call,
        "check_call": subprocess.check_call,
        "Popen": subprocess.Popen,
    }
    original_os = {"system": os.system, "popen": os.popen}
    original_socket = socket.create_connection
    original_sqlite_connect = sqlite3.connect
    sqlite_statements: list[str] = []

    def traced_sqlite_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = original_sqlite_connect(*args, **kwargs)

        def trace(statement: str) -> None:
            sqlite_statements.append(statement[:4096])

        connection.set_trace_callback(trace)
        return connection

    subprocess.run = virtual.run  # type: ignore[assignment]
    subprocess.check_output = virtual.check_output  # type: ignore[assignment]
    subprocess.call = virtual.call  # type: ignore[assignment]
    subprocess.check_call = virtual.check_call  # type: ignore[assignment]
    subprocess.Popen = virtual.popen  # type: ignore[assignment,misc]
    os.system = virtual.forbidden  # type: ignore[assignment]
    os.popen = virtual.forbidden  # type: ignore[assignment]
    socket.create_connection = virtual.forbidden  # type: ignore[assignment]
    sqlite3.connect = traced_sqlite_connect  # type: ignore[assignment]
    stdout = io.StringIO()
    stderr = io.StringIO()
    logs = _LogCapture()
    root_logger = logging.getLogger()
    root_logger.addHandler(logs)
    returncode = 0
    return_value: object = None
    error: dict[str, str] | None = None
    try:
        adapter_id = str(config["adapter_id"])
        script_main = adapter_id == "pdf_fake_pdftotext_frozen_bow_reader_v1"
        namespace: dict[str, object] = {
            "__name__": "__main__" if script_main else "__secaware_candidate__",
            "__file__": "/fixture-src/candidate.py",
        }
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            arguments = config.get("arguments")
            if type(arguments) is not list or any(type(item) is not str for item in arguments):
                raise ValueError("candidate arguments failed validation")
            sys.argv = ["/fixture-src/candidate.py", *arguments]
            exec(compile(source, "/fixture-src/candidate.py", "exec"), namespace)  # noqa: S102
            if not script_main:
                function = _candidate_function(namespace, adapter_id)
                return_value = _json_value(_invoke_candidate(function, config))
    except BaseException as candidate_error:  # noqa: BLE001 - untrusted candidate boundary
        returncode = 1
        error = {
            "error_type": type(candidate_error).__name__,
            "message": str(candidate_error).replace("/work", "$WORKSPACE"),
        }
    finally:
        root_logger.removeHandler(logs)
        subprocess.run = original_subprocess["run"]  # type: ignore[assignment]
        subprocess.check_output = original_subprocess["check_output"]  # type: ignore[assignment]
        subprocess.call = original_subprocess["call"]  # type: ignore[assignment]
        subprocess.check_call = original_subprocess["check_call"]  # type: ignore[assignment]
        subprocess.Popen = original_subprocess["Popen"]  # type: ignore[assignment,misc]
        os.system = original_os["system"]  # type: ignore[assignment]
        os.popen = original_os["popen"]  # type: ignore[assignment]
        socket.create_connection = original_socket  # type: ignore[assignment]
        sqlite3.connect = original_sqlite_connect  # type: ignore[assignment]
    stderr_text = stderr.getvalue()
    if error is not None:
        stderr_text += _canonical(error).decode("utf-8")
    workspace_files = _workspace_snapshot(expected_workspace_files)
    sandbox_bindings = config.get("sandbox_bindings")
    if (
        type(sandbox_bindings) is not list
        or any(type(item) is not str or not item for item in sandbox_bindings)
        or sandbox_bindings[0] != "/runtime:ro"
        or sandbox_bindings[-2:] != ["/fixture-src:ro", "/work:tmpfs"]
    ):
        raise ValueError("worker sandbox binding attestation failed validation")
    return {
        "schema_version": "1.0",
        "status": "complete" if returncode == 0 else "candidate_error",
        "returncode": returncode,
        "return_value": return_value,
        "stdout_base64": base64.b64encode(stdout.getvalue().encode("utf-8")).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr_text.encode("utf-8")).decode("ascii"),
        "command_events": virtual.events,
        "logs": logs.messages,
        "sqlite_statements": sqlite_statements,
        "workspace_files": workspace_files,
        "network_calls": 0,
        "unvirtualized_process_calls": virtual.unvirtualized_calls,
        "sandbox": {
            "bubblewrap_empty_mount_root": True,
            "work_tmpfs": True,
            "bindings": sandbox_bindings,
            "host_root_read_only_or_hidden": True,
            "network_namespace": True,
            "capabilities_dropped": True,
            "path": "/fixture-src/fake-bin",
            "kernel_policy": kernel_policy,
        },
        "resource_limits": resource_limits,
    }


def main() -> None:
    try:
        if len(sys.argv) != 2:
            raise ValueError("worker requires one configuration path")
        config = _read_config(Path(sys.argv[1]).resolve(strict=True))
        _verify_sandbox()
        expected_workspace_files = _prepare_workspace(config)
        resource_limits = _apply_resource_limits(config)
        kernel_policy = _install_kernel_policy()
        result = _candidate_run(
            config,
            resource_limits,
            expected_workspace_files,
            kernel_policy,
        )
    except Exception as error:  # noqa: BLE001 - return canonical infrastructure evidence
        result = {
            "schema_version": "1.0",
            "status": "infrastructure_error",
            "error_type": type(error).__name__,
            "message": str(error),
        }
    sys.stdout.buffer.write(_canonical(result))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()

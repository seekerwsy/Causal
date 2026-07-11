from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import BinaryIO

from secaware.errors import ErrorCode, SecAwareError


_ANALYZER_STAGE = "oracle_analyzer"
_MISSING_MESSAGE = "analyzer executable is unavailable"
_FAILED_MESSAGE = "analyzer process did not complete successfully"
_INVALID_OUTPUT_MESSAGE = "analyzer output failed validation"
_MAX_TIMEOUT_SECONDS = 3600.0
_MAX_STDOUT_BYTES = 256 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024 * 1024
_MAX_ARGV_ITEMS = 1024
_MAX_ARG_BYTES = 1024 * 1024
_POLL_INTERVAL_SECONDS = 0.01
_CLEANUP_WAIT_SECONDS = 5.0
_CAPTURE_CHUNK_BYTES = 64 * 1024
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_POPEN_CLASS = subprocess.Popen


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    try:
        while offset < len(payload):
            try:
                written = os.write(descriptor, payload[offset:])
            except InterruptedError:
                continue
            if written <= 0:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            offset += written
    finally:
        descriptor = -1
        payload = b""
        offset = 0


def _hash_fd(descriptor: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    chunk = b""
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return digest.hexdigest(), total
    finally:
        descriptor = -1
        digest = None  # type: ignore[assignment]
        chunk = b""


@dataclass(frozen=True, slots=True, repr=False)
class AnalyzerProcessResult:
    returncode: int
    stdout: bytes
    argv_sha256: str

    def __repr__(self) -> str:
        return "AnalyzerProcessResult()"


class _RunnerFailure(Exception):
    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code.name)
        self.code = code


class _WindowsJob:
    __slots__ = ("_handle", "_kernel32")

    def __init__(self, handle: object, kernel32: object) -> None:
        self._handle = handle
        self._kernel32 = kernel32

    def close(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        self._kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


class _ProcessOwner:
    __slots__ = ("process", "_terminated")

    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self._terminated = False

    def require(self) -> subprocess.Popen[bytes]:
        if self.process is None:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        return self.process

    def terminate(self, windows_job: _WindowsJob | None) -> None:
        if self.process is None or self._terminated:
            return
        _terminate_and_wait(self.process, windows_job)
        self._terminated = True

    def release(self) -> None:
        process = self.process
        self.process = None
        self._terminated = False
        if process is None:
            return
        for pipe in (getattr(process, "stdout", None), getattr(process, "stderr", None)):
            if pipe is not None:
                try:
                    pipe.close()
                except BaseException:
                    pass
        process = None


@dataclass(slots=True, repr=False)
class _BoundedCapture:
    pipe: BinaryIO
    storage: BinaryIO
    limit: int
    overflow: threading.Event
    done: threading.Event
    thread: threading.Thread | None = None


@dataclass(slots=True, repr=False)
class _WindowsPathLease:
    handle: object
    kernel32: object
    sha256: str
    identity: tuple[int, ...]

    def close(self) -> None:
        handle = self.handle
        if handle is None:
            return
        self.handle = None
        self.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


@dataclass(slots=True, repr=False)
class _PosixPathLease:
    fd: int
    sha256: str
    identity: tuple[int, ...]
    script_fd: int = -1
    exec_argv0: str = ""

    def close(self) -> None:
        descriptor = self.fd
        if descriptor < 0:
            return
        self.fd = -1
        os.close(descriptor)
        if self.script_fd >= 0:
            script_descriptor = self.script_fd
            self.script_fd = -1
            os.close(script_descriptor)


@dataclass(slots=True, repr=False)
class _PosixLaunch:
    argv: tuple[str, ...]
    pass_fds: tuple[int, ...]
    cancel_read_fd: int
    cancel_write_fd: int
    config_file: BinaryIO
    result_read_fd: int
    result_write_fd: int


def _safe_error(code: ErrorCode) -> SecAwareError:
    messages = {
        ErrorCode.ANALYZER_MISSING: _MISSING_MESSAGE,
        ErrorCode.ANALYZER_FAILED: _FAILED_MESSAGE,
        ErrorCode.ANALYZER_INVALID_OUTPUT: _INVALID_OUTPUT_MESSAGE,
    }
    return SecAwareError(
        code=code,
        stage=_ANALYZER_STAGE,
        message=messages[code],
        details={},
        retryable=False,
    )


def _validate_analyzer_argv(argv: Sequence[str]) -> tuple[str, ...]:
    validated: list[str] = []
    total_bytes = 0
    item = ""
    try:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        if not argv or len(argv) > _MAX_ARGV_ITEMS:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        for item in argv:
            if type(item) is not str or not item or "\x00" in item:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            try:
                total_bytes += len(item.encode("utf-8", errors="strict"))
            except UnicodeError:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED) from None
            if total_bytes > _MAX_ARG_BYTES:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            validated.append(item)
        return tuple(validated)
    finally:
        argv = ()
        validated = []
        item = ""


def _validate_limits(
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> tuple[float, int, int]:
    if (
        type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > _MAX_TIMEOUT_SECONDS
        or type(max_stdout_bytes) is not int
        or max_stdout_bytes <= 0
        or max_stdout_bytes > _MAX_STDOUT_BYTES
        or type(max_stderr_bytes) is not int
        or max_stderr_bytes <= 0
        or max_stderr_bytes > _MAX_STDERR_BYTES
    ):
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    return float(timeout_seconds), max_stdout_bytes, max_stderr_bytes


def _validate_cwd(cwd: Path) -> Path:
    candidate: Path | None = None
    try:
        candidate = Path(os.path.abspath(os.fspath(cwd))).resolve(strict=True)
        if not candidate.is_dir():
            raise ValueError(_FAILED_MESSAGE)
        return candidate
    except (OSError, TypeError, ValueError, RuntimeError):
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED) from None
    finally:
        cwd = None  # type: ignore[assignment]
        candidate = None


def _resolve_analyzer_executable(value: str) -> Path:
    resolved: str | None = None
    candidate: Path | None = None
    try:
        resolved = shutil.which(value)
        if resolved is None:
            raise _RunnerFailure(ErrorCode.ANALYZER_MISSING)
        candidate = Path(resolved).resolve(strict=True)
        if not candidate.is_file():
            raise _RunnerFailure(ErrorCode.ANALYZER_MISSING)
        return candidate
    except _RunnerFailure:
        raise
    except (OSError, TypeError, ValueError, RuntimeError):
        raise _RunnerFailure(ErrorCode.ANALYZER_MISSING) from None
    finally:
        value = ""
        resolved = None
        candidate = None


def _argv_sha256(argv: tuple[str, ...], executable_binding: str = "") -> str:
    payload = b""
    try:
        payload = json.dumps(
            {"argv": argv, "executable_binding": executable_binding},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
        return hashlib.sha256(payload).hexdigest()
    finally:
        argv = ()
        executable_binding = ""
        payload = b""


def _minimal_environment(executable: Path, cwd: Path) -> dict[str, str]:
    root = ""
    system_root: str | None = None
    environment: dict[str, str] = {}
    try:
        root = str(cwd)
        environment = {
            "HOME": root,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "PATH": str(executable.parent),
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SEND_METRICS": "off",
            "TEMP": root,
            "TMP": root,
            "USERPROFILE": root,
        }
        if os.name == "nt":
            system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
            if system_root:
                environment["SYSTEMROOT"] = system_root
                environment["WINDIR"] = system_root
        return environment
    finally:
        executable = None  # type: ignore[assignment]
        cwd = None  # type: ignore[assignment]
        root = ""
        system_root = None
        environment = {}


def _open_windows_path_lease(path: Path, *, directory: bool) -> _WindowsPathLease | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class _FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation", _FileTime),
            ("access", _FileTime),
            ("write", _FileTime),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    flags = 0x02000000 if directory else 0x00000080
    access = 0x80000000
    handle = kernel32.CreateFileW(str(path), access, 0x1, None, 3, flags, None)
    if not handle or int(handle) == -1:
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    information = _FileInformation()
    lease: _WindowsPathLease | None = None
    source: BinaryIO | None = None
    chunk = b""
    try:
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        identity = (
            information.volume,
            information.index_high,
            information.index_low,
            information.size_high,
            information.size_low,
            information.write.high,
            information.write.low,
        )
        digest = ""
        if not directory:
            digest_hash = hashlib.sha256()
            with path.open("rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    digest_hash.update(chunk)
            digest = digest_hash.hexdigest()
        lease = _WindowsPathLease(handle, kernel32, digest, identity)
        return lease
    finally:
        if lease is None:
            kernel32.CloseHandle(handle)
        path = None  # type: ignore[assignment]
        source = None
        chunk = b""


def _open_posix_path_lease(path: Path, *, directory: bool) -> _PosixPathLease | None:
    if os.name != "posix":
        return None
    if sys.platform != "linux" or not Path("/proc/self/task").is_dir():
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    sealed_descriptor = -1
    lease: _PosixPathLease | None = None
    chunk = b""
    prefix = b""
    interpreter_lease: _PosixPathLease | None = None
    script_descriptor = -1
    try:
        metadata = os.fstat(descriptor)
        source_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        if directory:
            if not stat.S_ISDIR(metadata.st_mode):
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            digest = ""
        else:
            if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
                raise _RunnerFailure(ErrorCode.ANALYZER_MISSING)
            if metadata.st_size <= 0 or metadata.st_size > _MAX_EXECUTABLE_BYTES:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            import fcntl

            sealed_descriptor = os.memfd_create(
                "secaware-analyzer",
                getattr(os, "MFD_CLOEXEC", 0x1) | getattr(os, "MFD_ALLOW_SEALING", 0x2),
            )
            digest_hash = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest_hash.update(chunk)
                _write_all(sealed_descriptor, chunk)
                if len(prefix) < 4096:
                    prefix += chunk[: 4096 - len(prefix)]
            digest = digest_hash.hexdigest()
            if os.fstat(descriptor) != metadata:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            sealed_digest, sealed_size = _hash_fd(sealed_descriptor)
            if sealed_digest != digest or sealed_size != metadata.st_size:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            os.fchmod(sealed_descriptor, metadata.st_mode & 0o777)
            fcntl.fcntl(
                sealed_descriptor,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
            )
            os.close(descriptor)
            descriptor = sealed_descriptor
            sealed_descriptor = -1
            metadata = os.fstat(descriptor)
            if prefix.startswith(b"#!"):
                first_line = prefix.split(b"\n", 1)[0]
                if len(first_line) < 3 or len(first_line) > 4096:
                    raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
                try:
                    shebang = first_line[2:].decode("utf-8", errors="strict")
                except UnicodeError:
                    raise _RunnerFailure(ErrorCode.ANALYZER_FAILED) from None
                if (
                    not shebang.startswith("/")
                    or shebang != shebang.strip()
                    or any(character.isspace() for character in shebang)
                    or shebang.endswith("/env")
                ):
                    raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
                script_descriptor = descriptor
                descriptor = -1
                interpreter_lease = _open_posix_path_lease(
                    Path(shebang).resolve(strict=True), directory=False
                )
                if interpreter_lease is None or interpreter_lease.script_fd >= 0:
                    raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
                combined = hashlib.sha256(
                    (digest + ":" + interpreter_lease.sha256).encode("ascii")
                ).hexdigest()
                lease = _PosixPathLease(
                    fd=interpreter_lease.fd,
                    sha256=combined,
                    identity=interpreter_lease.identity + (*source_identity,),
                    script_fd=script_descriptor,
                    exec_argv0=shebang,
                )
                script_descriptor = -1
                interpreter_lease.fd = -1
                return lease
        identity = source_identity
        lease = _PosixPathLease(descriptor, digest, identity)
        return lease
    finally:
        if lease is None and descriptor >= 0:
            os.close(descriptor)
        if sealed_descriptor >= 0:
            os.close(sealed_descriptor)
        if script_descriptor >= 0:
            os.close(script_descriptor)
        path = None  # type: ignore[assignment]
        chunk = b""
        prefix = b""
        if interpreter_lease is not None:
            interpreter_lease.close()
        interpreter_lease = None


def _force_namespace_unavailable() -> bool:
    return False


def _prepare_posix_launch(
    argv: tuple[str, ...],
    environment: dict[str, str],
    executable: _PosixPathLease,
    cwd: _PosixPathLease,
) -> _PosixLaunch:
    config_file = tempfile.TemporaryFile(mode="w+b")
    cancel_read_fd = cancel_write_fd = -1
    result_read_fd = result_write_fd = -1
    payload = b""
    try:
        cancel_read_fd, cancel_write_fd = os.pipe()
        result_read_fd, result_write_fd = os.pipe()
        payload = json.dumps(
            {
                "argv": argv,
                "environment": environment,
                "script_fd": executable.script_fd,
                "exec_argv0": executable.exec_argv0,
                "force_namespace_unavailable": _force_namespace_unavailable(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > _MAX_ARG_BYTES:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        config_file.write(payload)
        config_file.flush()
        config_file.seek(0)
        supervisor = (
            sys.executable,
            str(Path(__file__).with_name("_posix_supervisor.py")),
            str(config_file.fileno()),
            str(executable.fd),
            str(cwd.fd),
            str(cancel_read_fd),
            str(executable.script_fd),
            str(result_write_fd),
        )
        passed = [
            config_file.fileno(),
            executable.fd,
            cwd.fd,
            cancel_read_fd,
            result_write_fd,
        ]
        if executable.script_fd >= 0:
            passed.append(executable.script_fd)
        return _PosixLaunch(
            argv=supervisor,
            pass_fds=tuple(passed),
            cancel_read_fd=cancel_read_fd,
            cancel_write_fd=cancel_write_fd,
            config_file=config_file,
            result_read_fd=result_read_fd,
            result_write_fd=result_write_fd,
        )
    except BaseException:
        config_file.close()
        for descriptor in (
            cancel_read_fd,
            cancel_write_fd,
            result_read_fd,
            result_write_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        raise
    finally:
        argv = ()
        environment = {}
        payload = b""
        executable = None  # type: ignore[assignment]
        cwd = None  # type: ignore[assignment]
        config_file = None  # type: ignore[assignment]
        cancel_read_fd = -1
        cancel_write_fd = -1
        result_read_fd = -1
        result_write_fd = -1


def _close_posix_launch(launch: _PosixLaunch) -> None:
    try:
        launch.config_file.close()
        for descriptor in (
            launch.cancel_read_fd,
            launch.cancel_write_fd,
            launch.result_read_fd,
            launch.result_write_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        launch.cancel_read_fd = -1
        launch.cancel_write_fd = -1
        launch.result_read_fd = -1
        launch.result_write_fd = -1
    finally:
        launch = None  # type: ignore[assignment]


def _popen_process(
    owner: _ProcessOwner,
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    posix_launch: _PosixLaunch | None = None,
) -> None:
    platform_options: dict[str, object]
    popen_factory = subprocess.Popen
    if os.name == "nt":
        platform_options = {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | 0x4,
        }
    else:
        platform_options = (
            {"start_new_session": True, "pass_fds": posix_launch.pass_fds}
            if posix_launch is not None
            else {"start_new_session": True}
        )
    try:
        popen_args = (posix_launch.argv if posix_launch is not None else argv,)
        popen_kwargs = {
            "cwd": None if posix_launch is not None else str(cwd),
            "env": environment,
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "close_fds": True,
            **platform_options,
        }
        if owner.process is not None:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        if isinstance(popen_factory, type) and issubclass(popen_factory, _POPEN_CLASS):
            owner.process = popen_factory.__new__(popen_factory)
            popen_factory.__init__(owner.process, *popen_args, **popen_kwargs)
        else:
            owner.process = popen_factory(*popen_args, **popen_kwargs)
        _finalize_process_handoff(owner.require(), posix_launch)
    finally:
        owner = None  # type: ignore[assignment]
        argv = ()
        cwd = None  # type: ignore[assignment]
        environment = {}
        platform_options = {}
        popen_args = ()
        popen_kwargs = {}
        popen_factory = None  # type: ignore[assignment]
        posix_launch = None


def _finalize_process_handoff(
    process: subprocess.Popen[bytes],
    posix_launch: _PosixLaunch | None,
) -> None:
    try:
        if posix_launch is not None:
            setattr(process, "_secaware_cancel_fd", posix_launch.cancel_write_fd)
            posix_launch.cancel_write_fd = -1
            setattr(process, "_secaware_result_fd", posix_launch.result_read_fd)
            posix_launch.result_read_fd = -1
            os.close(posix_launch.cancel_read_fd)
            posix_launch.cancel_read_fd = -1
            os.close(posix_launch.result_write_fd)
            posix_launch.result_write_fd = -1
    finally:
        process = None  # type: ignore[assignment]
        posix_launch = None


def _create_windows_job(process: subprocess.Popen[bytes]) -> _WindowsJob | None:
    process_handle = 0
    try:
        if os.name != "nt":
            return None
        process_handle = int(process._handle)  # type: ignore[attr-defined]
        return _create_windows_job_for_handle(process_handle)
    finally:
        process = None  # type: ignore[assignment]
        process_handle = 0


def _create_windows_job_for_handle(process_handle: int) -> _WindowsJob:

    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    job = _WindowsJob(handle, kernel32)
    configured = False
    assigned = False
    try:
        information = _ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000
        configured = bool(
            kernel32.SetInformationJobObject(
                handle,
                9,
                ctypes.byref(information),
                ctypes.sizeof(information),
            )
        )
        assigned = configured and bool(
            kernel32.AssignProcessToJobObject(handle, wintypes.HANDLE(process_handle))
        )
    finally:
        if not assigned:
            job.close()
    if not configured or not assigned:
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    return job


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    process_id = process.pid
    try:
        _resume_windows_process_id(process_id)
    finally:
        process = None  # type: ignore[assignment]
        process_id = 0


def _resume_windows_process_id(process_id: int) -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class _ThreadEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel32.CreateToolhelp32Snapshot(0x4, 0)
    thread_ids: list[int] = []
    try:
        if not snapshot or int(snapshot) == -1:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        entry = _ThreadEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while found:
            if entry.th32OwnerProcessID == process_id:
                thread_ids.append(entry.th32ThreadID)
            entry.dwSize = ctypes.sizeof(entry)
            found = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
    finally:
        if snapshot and int(snapshot) != -1:
            kernel32.CloseHandle(snapshot)
    if len(thread_ids) != 1:
        raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    thread_handle = kernel32.OpenThread(0x0002, False, thread_ids[0])
    try:
        if not thread_handle or kernel32.ResumeThread(thread_handle) != 1:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
    finally:
        if thread_handle:
            kernel32.CloseHandle(thread_handle)
        thread_ids = []


def _capture_reader(capture: _BoundedCapture) -> None:
    written = 0
    chunk = b""
    try:
        while True:
            chunk = os.read(capture.pipe.fileno(), _CAPTURE_CHUNK_BYTES)
            if not chunk:
                return
            allowed = capture.limit + 1 - written
            if allowed > 0:
                part = chunk[:allowed]
                capture.storage.write(part)
                written += len(part)
                part = b""
            if written > capture.limit or len(chunk) > max(allowed, 0):
                capture.overflow.set()
                return
    finally:
        chunk = b""
        try:
            capture.storage.flush()
        except BaseException:
            capture.overflow.set()
        capture.done.set()
        capture = None  # type: ignore[assignment]


def _start_capture(pipe: BinaryIO, storage: BinaryIO, limit: int) -> _BoundedCapture:
    capture: _BoundedCapture | None = None
    thread: threading.Thread | None = None
    try:
        capture = _BoundedCapture(
            pipe=pipe,
            storage=storage,
            limit=limit,
            overflow=threading.Event(),
            done=threading.Event(),
        )
        thread = threading.Thread(target=_capture_reader, args=(capture,), daemon=True)
        capture.thread = thread
        thread.start()
        return capture
    finally:
        pipe = None  # type: ignore[assignment]
        storage = None  # type: ignore[assignment]
        capture = None
        thread = None


def _finish_captures(captures: tuple[_BoundedCapture, ...]) -> bool:
    overflow = False
    capture: _BoundedCapture | None = None
    try:
        for capture in captures:
            if capture.thread is not None:
                capture.thread.join(timeout=_CLEANUP_WAIT_SECONDS)
            if not capture.done.is_set():
                try:
                    capture.pipe.close()
                except BaseException:
                    pass
                if capture.thread is not None:
                    capture.thread.join(timeout=_CLEANUP_WAIT_SECONDS)
            if not capture.done.is_set():
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            overflow = overflow or capture.overflow.is_set()
            capture.pipe.close()
        return overflow
    finally:
        captures = ()
        capture = None


def _stream_size(handle: BinaryIO) -> int:
    try:
        return os.fstat(handle.fileno()).st_size
    finally:
        handle = None  # type: ignore[assignment]


def _outputs_within_limits(
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> bool:
    try:
        return (
            _stream_size(stdout_file) <= max_stdout_bytes
            and _stream_size(stderr_file) <= max_stderr_bytes
        )
    finally:
        stdout_file = None  # type: ignore[assignment]
        stderr_file = None  # type: ignore[assignment]


def _monitor_process(
    process: subprocess.Popen[bytes],
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
    captures: tuple[_BoundedCapture, ...] = (),
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            if any(capture.overflow.is_set() for capture in captures):
                raise _RunnerFailure(ErrorCode.ANALYZER_INVALID_OUTPUT)
            if not _outputs_within_limits(
                stdout_file,
                stderr_file,
                max_stdout_bytes,
                max_stderr_bytes,
            ):
                raise _RunnerFailure(ErrorCode.ANALYZER_INVALID_OUTPUT)
            returncode = process.poll()
            if returncode is not None:
                return returncode
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
            time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))
    finally:
        process = None  # type: ignore[assignment]
        stdout_file = None  # type: ignore[assignment]
        stderr_file = None  # type: ignore[assignment]
        captures = ()


def _read_posix_result(process: subprocess.Popen[bytes], supervisor_returncode: int) -> int:
    descriptor = getattr(process, "_secaware_result_fd", -1)
    if descriptor < 0:
        return supervisor_returncode
    frame = b""
    try:
        while len(frame) <= 32:
            try:
                chunk = os.read(descriptor, 33 - len(frame))
            except InterruptedError:
                continue
            if not chunk:
                break
            frame += chunk
        if supervisor_returncode != 0 or len(frame) > 32 or not frame.startswith(b"R:"):
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        encoded_returncode = frame[2:]
        if not encoded_returncode or encoded_returncode in (b"+0", b"-0"):
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        try:
            returncode = int(encoded_returncode.decode("ascii"))
        except (UnicodeError, ValueError):
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED) from None
        if str(returncode).encode("ascii") != encoded_returncode or not -255 <= returncode <= 255:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        return returncode
    finally:
        os.close(descriptor)
        setattr(process, "_secaware_result_fd", -1)
        process = None  # type: ignore[assignment]
        frame = b""
        chunk = b""
        encoded_returncode = b""


def _signal_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
            if ctrl_break is not None:
                try:
                    os.kill(process.pid, ctrl_break)
                except (OSError, ValueError):
                    pass
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    finally:
        process = None  # type: ignore[assignment]


def _terminate_and_wait(
    process: subprocess.Popen[bytes],
    windows_job: _WindowsJob | None,
) -> None:
    try:
        cancel_fd = getattr(process, "_secaware_cancel_fd", -1)
        if cancel_fd >= 0:
            try:
                if process.poll() is None:
                    if os.name == "posix":
                        os.kill(process.pid, signal.SIGCONT)
                    os.write(cancel_fd, b"x")
                    deadline = time.monotonic() + _CLEANUP_WAIT_SECONDS
                    while process.poll() is None and time.monotonic() < deadline:
                        if os.name == "posix":
                            os.kill(process.pid, signal.SIGCONT)
                        time.sleep(0.01)
            finally:
                os.close(cancel_fd)
                setattr(process, "_secaware_cancel_fd", -1)
            if process.poll() is not None:
                return
        if windows_job is not None:
            windows_job.close()
        _signal_process_group(process)
        if process.poll() is None:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
        try:
            process.wait(timeout=_CLEANUP_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
            process.wait(timeout=_CLEANUP_WAIT_SECONDS)
    finally:
        result_fd = getattr(process, "_secaware_result_fd", -1)
        if result_fd >= 0:
            os.close(result_fd)
            setattr(process, "_secaware_result_fd", -1)
        process = None  # type: ignore[assignment]
        windows_job = None


def _capture_cleanup_failure(function: object, *args: object) -> BaseException | None:
    try:
        try:
            function(*args)  # type: ignore[operator]
        except BaseException as error:
            return error
        return None
    finally:
        function = None
        args = ()


def _cleanup_resources(
    process: subprocess.Popen[bytes] | None,
    windows_job: _WindowsJob | None,
    stdout_file: BinaryIO | None,
    stderr_file: BinaryIO | None,
    *,
    suppress_failures: bool,
) -> tuple[KeyboardInterrupt | SystemExit | None, bool]:
    control: KeyboardInterrupt | SystemExit | None = None
    failed = False
    failures: list[BaseException | None] = []
    error: BaseException | None = None
    try:
        if process is not None:
            failures.append(_capture_cleanup_failure(_terminate_and_wait, process, windows_job))
        if stdout_file is not None:
            failures.append(_capture_cleanup_failure(stdout_file.close))
        if stderr_file is not None:
            failures.append(_capture_cleanup_failure(stderr_file.close))
        if not suppress_failures:
            for error in failures:
                if isinstance(error, (KeyboardInterrupt, SystemExit)) and control is None:
                    control = error
                elif error is not None:
                    failed = True
        return control, failed
    finally:
        process = None
        windows_job = None
        stdout_file = None
        stderr_file = None
        failures = []
        error = None
        control = None


def _snapshot_stdout(
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
    *,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> bytes:
    payload = b""
    try:
        stdout_size = _stream_size(stdout_file)
        stderr_size = _stream_size(stderr_file)
        if stdout_size > max_stdout_bytes or stderr_size > max_stderr_bytes:
            raise _RunnerFailure(ErrorCode.ANALYZER_INVALID_OUTPUT)
        stdout_file.seek(0)
        payload = stdout_file.read(max_stdout_bytes + 1)
        if (
            len(payload) != stdout_size
            or len(payload) > max_stdout_bytes
            or _stream_size(stdout_file) != stdout_size
            or _stream_size(stderr_file) != stderr_size
        ):
            payload = b""
            raise _RunnerFailure(ErrorCode.ANALYZER_INVALID_OUTPUT)
        return payload
    finally:
        stdout_file = None  # type: ignore[assignment]
        stderr_file = None  # type: ignore[assignment]
        payload = b""


def _run_resolved_process(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> AnalyzerProcessResult:
    process_owner = _ProcessOwner()
    process: subprocess.Popen[bytes] | None = None
    windows_job: _WindowsJob | None = None
    stdout_file: BinaryIO | None = None
    stderr_file: BinaryIO | None = None
    environment: dict[str, str] = {}
    payload = b""
    cleanup_failed = False
    cleanup_control: KeyboardInterrupt | SystemExit | None = None
    had_active_exception = False
    tree_cleaned = False
    captures: tuple[_BoundedCapture, ...] = ()
    executable_lease: _WindowsPathLease | None = None
    cwd_lease: _WindowsPathLease | None = None
    posix_executable_lease: _PosixPathLease | None = None
    posix_cwd_lease: _PosixPathLease | None = None
    posix_launch: _PosixLaunch | None = None
    executable_binding = ""
    try:
        executable_lease = _open_windows_path_lease(Path(argv[0]), directory=False)
        cwd_lease = _open_windows_path_lease(cwd, directory=True)
        posix_executable_lease = _open_posix_path_lease(Path(argv[0]), directory=False)
        posix_cwd_lease = _open_posix_path_lease(cwd, directory=True)
        if executable_lease is not None:
            executable_binding = (
                executable_lease.sha256 + ":" + ":".join(map(str, executable_lease.identity))
            )
        environment = _minimal_environment(Path(argv[0]), cwd)
        stdout_file = tempfile.TemporaryFile(mode="w+b")
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        if posix_executable_lease is not None and posix_cwd_lease is not None:
            executable_binding = (
                posix_executable_lease.sha256
                + ":"
                + ":".join(map(str, posix_executable_lease.identity))
            )
            posix_launch = _prepare_posix_launch(
                argv,
                environment,
                posix_executable_lease,
                posix_cwd_lease,
            )
        _popen_process(
            process_owner,
            argv,
            cwd=cwd,
            environment=environment,
            posix_launch=posix_launch,
        )
        process = process_owner.require()
        windows_job = _create_windows_job(process)
        if process.stdout is None or process.stderr is None:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        captures = (
            _start_capture(process.stdout, stdout_file, max_stdout_bytes),
            _start_capture(process.stderr, stderr_file, max_stderr_bytes),
        )
        _resume_windows_process(process)
        supervisor_returncode = _monitor_process(
            process,
            stdout_file,
            stderr_file,
            captures,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        returncode = _read_posix_result(process, supervisor_returncode)
        process_owner.terminate(windows_job)
        tree_cleaned = True
        overflow = _finish_captures(captures)
        captures = ()
        process_owner.release()
        process = None
        if overflow:
            raise _RunnerFailure(ErrorCode.ANALYZER_INVALID_OUTPUT)
        if returncode < 0:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)
        payload = _snapshot_stdout(
            stdout_file,
            stderr_file,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        return AnalyzerProcessResult(
            returncode=returncode,
            stdout=payload,
            argv_sha256=_argv_sha256(argv, executable_binding),
        )
    finally:
        had_active_exception = sys_exc_info_active()
        owner_error = (
            _capture_cleanup_failure(process_owner.terminate, windows_job)
            if not tree_cleaned
            else None
        )
        cleanup_control, cleanup_failed = _cleanup_resources(
            None,
            None,
            None,
            None,
            suppress_failures=had_active_exception,
        )
        capture_error = _capture_cleanup_failure(_finish_captures, captures) if captures else None
        process_owner.release()
        file_control, file_failed = _cleanup_resources(
            None,
            None,
            stdout_file,
            stderr_file,
            suppress_failures=had_active_exception,
        )
        lease_errors = [
            _capture_cleanup_failure(lease.close)
            for lease in (
                executable_lease,
                cwd_lease,
                posix_executable_lease,
                posix_cwd_lease,
            )
            if lease is not None
        ]
        if posix_launch is not None:
            lease_errors.append(_capture_cleanup_failure(_close_posix_launch, posix_launch))
        if not had_active_exception:
            if cleanup_control is None and isinstance(
                capture_error, (KeyboardInterrupt, SystemExit)
            ):
                cleanup_control = capture_error
            if cleanup_control is None:
                cleanup_control = file_control
            if cleanup_control is None and isinstance(owner_error, (KeyboardInterrupt, SystemExit)):
                cleanup_control = owner_error
            elif owner_error is not None:
                cleanup_failed = True
            cleanup_failed = (
                cleanup_failed
                or file_failed
                or (
                    capture_error is not None
                    and not isinstance(capture_error, (KeyboardInterrupt, SystemExit))
                )
            )
            for lease_error in lease_errors:
                if cleanup_control is None and isinstance(
                    lease_error, (KeyboardInterrupt, SystemExit)
                ):
                    cleanup_control = lease_error
                elif lease_error is not None:
                    cleanup_failed = True
        argv = ()
        cwd = None  # type: ignore[assignment]
        environment = {}
        payload = b""
        process = None
        process_owner = None  # type: ignore[assignment]
        windows_job = None
        stdout_file = None
        stderr_file = None
        captures = ()
        executable_lease = None
        cwd_lease = None
        posix_executable_lease = None
        posix_cwd_lease = None
        posix_launch = None
        executable_binding = ""
        supervisor_returncode = 0
        lease_errors = []
        tree_cleaned = False
        if cleanup_control is not None:
            raised_control = cleanup_control
            cleanup_control = None
            raise raised_control
        if cleanup_failed and not had_active_exception:
            raise _RunnerFailure(ErrorCode.ANALYZER_FAILED)


def sys_exc_info_active() -> bool:
    import sys

    return sys.exc_info()[0] is not None


def run_analyzer_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> AnalyzerProcessResult:
    result: AnalyzerProcessResult | None = None
    failure_code: ErrorCode | None = None
    validated_argv: tuple[str, ...] = ()
    resolved_argv: tuple[str, ...] = ()
    resolved_cwd: Path | None = None
    try:
        validated_argv = _validate_analyzer_argv(argv)
        timeout_seconds, max_stdout_bytes, max_stderr_bytes = _validate_limits(
            timeout_seconds,
            max_stdout_bytes,
            max_stderr_bytes,
        )
        resolved_cwd = _validate_cwd(cwd)
        executable = _resolve_analyzer_executable(validated_argv[0])
        resolved_argv = (str(executable), *validated_argv[1:])
        result = _run_resolved_process(
            resolved_argv,
            cwd=resolved_cwd,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except _RunnerFailure as error:
        failure_code = error.code
    except Exception:
        failure_code = ErrorCode.ANALYZER_FAILED
    finally:
        argv = ()
        cwd = None  # type: ignore[assignment]
        validated_argv = ()
        resolved_argv = ()
        resolved_cwd = None
        executable = None
    if failure_code is not None or result is None:
        result = None
        raise _safe_error(failure_code or ErrorCode.ANALYZER_FAILED) from None
    return result


__all__ = [
    "AnalyzerProcessResult",
    "run_analyzer_process",
]

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
import subprocess
import tempfile
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


def _argv_sha256(argv: tuple[str, ...]) -> str:
    payload = b""
    try:
        payload = json.dumps(
            argv,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
        return hashlib.sha256(payload).hexdigest()
    finally:
        argv = ()
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


def _popen_process(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
    environment: dict[str, str],
) -> subprocess.Popen[bytes]:
    platform_options: dict[str, object]
    if os.name == "nt":
        platform_options = {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        }
    else:
        platform_options = {"start_new_session": True}
    try:
        return subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            close_fds=True,
            **platform_options,
        )
    finally:
        argv = ()
        cwd = None  # type: ignore[assignment]
        stdout_file = None  # type: ignore[assignment]
        stderr_file = None  # type: ignore[assignment]
        environment = {}
        platform_options = {}


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
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
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
    try:
        environment = _minimal_environment(Path(argv[0]), cwd)
        stdout_file = tempfile.TemporaryFile(mode="w+b")
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        process = _popen_process(
            argv,
            cwd=cwd,
            stdout_file=stdout_file,
            stderr_file=stderr_file,
            environment=environment,
        )
        windows_job = _create_windows_job(process)
        returncode = _monitor_process(
            process,
            stdout_file,
            stderr_file,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        _terminate_and_wait(process, windows_job)
        tree_cleaned = True
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
            argv_sha256=_argv_sha256(argv),
        )
    finally:
        had_active_exception = sys_exc_info_active()
        cleanup_control, cleanup_failed = _cleanup_resources(
            None if tree_cleaned else process,
            windows_job,
            stdout_file,
            stderr_file,
            suppress_failures=had_active_exception,
        )
        argv = ()
        cwd = None  # type: ignore[assignment]
        environment = {}
        payload = b""
        process = None
        windows_job = None
        stdout_file = None
        stderr_file = None
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

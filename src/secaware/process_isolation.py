"""Bounded, tree-owned subprocess execution without multiprocessing or pickle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Mapping, Sequence

from secaware.errors import ErrorCode, SecAwareError


_POLL_SECONDS = 0.01
_CLEANUP_SECONDS = 1.0
_MAX_CAPTURE_BYTES = 8 * 1024 * 1024


class IsolatedProcessFailureKind(str, Enum):
    TIMEOUT = "timeout"
    BACKEND_FAILURE = "backend_failure"
    INVALID_OUTPUT = "invalid_output"
    INVALID_INPUT = "invalid_input"


def _process_error(
    failure_kind: IsolatedProcessFailureKind = IsolatedProcessFailureKind.BACKEND_FAILURE,
) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="process.isolation",
        message="isolated process failed validation",
        details={"failure_kind": failure_kind.value},
    )


@dataclass(frozen=True)
class IsolatedProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class _WindowsJob:
    def __init__(self, handle: object, kernel32: object) -> None:
        self._handle = handle
        self._kernel32 = kernel32

    def close(self) -> None:
        handle = self._handle
        self._handle = None
        if handle:
            self._kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def _create_windows_job(process: subprocess.Popen[bytes]) -> _WindowsJob | None:
    if os.name != "nt":
        return None
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
        raise _process_error()
    job = _WindowsJob(handle, kernel32)
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
            kernel32.AssignProcessToJobObject(
                handle,
                wintypes.HANDLE(int(process._handle)),  # type: ignore[attr-defined]
            )
        )
        if not assigned:
            raise _process_error()
        return job
    finally:
        if not assigned:
            job.close()


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class _ThreadEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("dw32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(0x4, 0)
    thread_ids: list[int] = []
    try:
        if not snapshot or int(snapshot) == -1:
            raise _process_error()
        entry = _ThreadEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while found:
            if entry.dw32OwnerProcessID == process.pid:
                thread_ids.append(entry.th32ThreadID)
            entry.dwSize = ctypes.sizeof(entry)
            found = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
    finally:
        if snapshot and int(snapshot) != -1:
            kernel32.CloseHandle(snapshot)
    if len(thread_ids) != 1:
        raise _process_error()
    thread = kernel32.OpenThread(0x0002, False, thread_ids[0])
    try:
        if not thread or kernel32.ResumeThread(thread) != 1:
            raise _process_error()
    finally:
        if thread:
            kernel32.CloseHandle(thread)


def _terminate_tree(process: subprocess.Popen[bytes], job: _WindowsJob | None) -> None:
    if job is not None:
        job.close()
    elif os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=_CLEANUP_SECONDS)
    except BaseException:
        try:
            process.kill()
            process.wait(timeout=_CLEANUP_SECONDS)
        except BaseException:
            pass


def _capture(pipe: object, limit: int, output: bytearray, overflow: threading.Event) -> None:
    try:
        while True:
            chunk = pipe.read(4096)  # type: ignore[attr-defined]
            if not chunk:
                return
            remaining = limit + 1 - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
            if len(output) > limit:
                overflow.set()
                return
    except BaseException:
        overflow.set()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def run_isolated_process(
    argv: Sequence[str],
    *,
    cwd: str | Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    require_canonical_json: bool = False,
) -> IsolatedProcessResult:
    """Run one fixed command with bounded output and whole-tree ownership."""

    process: subprocess.Popen[bytes] | None = None
    job: _WindowsJob | None = None
    readers: list[threading.Thread] = []
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    failure_kind = IsolatedProcessFailureKind.INVALID_INPUT
    try:
        checked_argv = tuple(argv)
        checked_cwd = Path(cwd).resolve(strict=True)
        checked_environment = dict(environment)
        if (
            not checked_argv
            or not all(type(item) is str and item for item in checked_argv)
            or not all(
                type(key) is str and type(value) is str
                for key, value in checked_environment.items()
            )
            or type(timeout_seconds) not in {int, float}
            or not 0 < float(timeout_seconds) <= 3600
            or type(max_stdout_bytes) is not int
            or type(max_stderr_bytes) is not int
            or not 0 < max_stdout_bytes <= _MAX_CAPTURE_BYTES
            or not 0 < max_stderr_bytes <= _MAX_CAPTURE_BYTES
        ):
            raise ValueError
        failure_kind = IsolatedProcessFailureKind.BACKEND_FAILURE
        options: dict[str, object] = {}
        if os.name == "nt":
            options["creationflags"] = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | 0x4
            )
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(
            checked_argv,
            cwd=str(checked_cwd),
            env=checked_environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            **options,  # type: ignore[arg-type]
        )
        job = _create_windows_job(process)
        _resume_windows_process(process)
        if process.stdout is None or process.stderr is None:
            raise ValueError
        readers = [
            threading.Thread(
                target=_capture,
                args=(process.stdout, max_stdout_bytes, stdout, overflow),
                daemon=True,
            ),
            threading.Thread(
                target=_capture,
                args=(process.stderr, max_stderr_bytes, stderr, overflow),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + float(timeout_seconds)
        while process.poll() is None and not overflow.is_set():
            if time.monotonic() >= deadline:
                raise _process_error(IsolatedProcessFailureKind.TIMEOUT)
            time.sleep(_POLL_SECONDS)
        returncode = process.poll()
        _terminate_tree(process, job)
        job = None
        for reader in readers:
            reader.join(_CLEANUP_SECONDS)
        if (
            overflow.is_set()
            or any(reader.is_alive() for reader in readers)
            or len(stdout) > max_stdout_bytes
            or len(stderr) > max_stderr_bytes
        ):
            raise _process_error(IsolatedProcessFailureKind.INVALID_OUTPUT)
        if returncode != 0:
            raise _process_error(IsolatedProcessFailureKind.BACKEND_FAILURE)
        payload = bytes(stdout)
        if require_canonical_json:
            failure_kind = IsolatedProcessFailureKind.INVALID_OUTPUT
            decoded = json.loads(payload.decode("utf-8"))
            if _canonical_json_bytes(decoded) != payload:
                raise ValueError
        return IsolatedProcessResult(stdout=payload, stderr=bytes(stderr), returncode=returncode)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError as error:
        if error.stage == "process.isolation" and error.details.get("failure_kind") in {
            item.value for item in IsolatedProcessFailureKind
        }:
            raise
        raise _process_error(failure_kind) from None
    except Exception:
        raise _process_error(failure_kind) from None
    finally:
        if process is not None:
            _terminate_tree(process, job)
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except BaseException:
                        pass
        for reader in readers:
            try:
                reader.join(_CLEANUP_SECONDS)
            except BaseException:
                pass


__all__ = ["IsolatedProcessFailureKind", "IsolatedProcessResult", "run_isolated_process"]

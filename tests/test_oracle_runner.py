from __future__ import annotations

import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from collections.abc import Iterator

import pytest

import secaware.oracle.runner as runner_module
from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.runner import AnalyzerProcessResult, run_analyzer_process


_POPEN_TYPE = subprocess.Popen


def _python_argv(source: str, *arguments: str) -> tuple[str, ...]:
    return (sys.executable, "-c", source, *arguments)


def _error_surfaces(error: BaseException) -> tuple[str, ...]:
    rendered = [str(error), "".join(traceback.format_exception(error))]
    if isinstance(error, SecAwareError):
        rendered.append(json.dumps(error.to_dict(), sort_keys=True))
    return tuple(rendered)


def _secaware_traceback_frames(
    error: BaseException,
) -> list[tuple[str, dict[str, object]]]:
    frames: list[tuple[str, dict[str, object]]] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            frames.append((current.tb_frame.f_code.co_name, dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return frames


def _runner_frame_surfaces(error: BaseException) -> tuple[str, ...]:
    surfaces: list[str] = []
    for _, frame_locals in _secaware_traceback_frames(error):
        surfaces.append(repr(frame_locals))
        for value in frame_locals.values():
            if isinstance(value, _POPEN_TYPE):
                surfaces.append(repr(value.args))
    return tuple(surfaces)


def _assert_safe_error(
    error: SecAwareError,
    code: ErrorCode,
    *hidden: str,
) -> None:
    assert error.code is code
    assert error.stage == "oracle_analyzer"
    assert error.details == {}
    assert error.retryable is False
    assert error.__cause__ is None
    assert error.__context__ is None
    retained = "\n".join(
        repr(frame_locals) for _, frame_locals in _secaware_traceback_frames(error)
    )
    for value in hidden:
        if not value:
            continue
        assert all(value not in surface for surface in _error_surfaces(error))
        assert value not in retained


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.setenv("SECAWARE_PRIVATE_PARENT_VALUE", "must-not-reach-analyzer")
    previous = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield
    finally:
        os.chdir(previous)


def test_runner_uses_literal_argv_without_shell_and_returns_bounded_stdout(
    tmp_path: Path,
) -> None:
    hostile_argument = "$(echo private-shell-expansion); & private-command"
    result = run_analyzer_process(
        _python_argv(
            "import json,sys; print(json.dumps({'argument': sys.argv[1]}))",
            hostile_argument,
        ),
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=4096,
        max_stderr_bytes=1024,
    )

    assert isinstance(result, AnalyzerProcessResult)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"argument": hostile_argument}
    assert len(result.argv_sha256) == 64
    assert result.argv_sha256.isascii()
    assert result.argv_sha256.islower()
    assert repr(result) == "AnalyzerProcessResult()"


def test_runner_passes_safe_popen_contract_and_minimal_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    clean_environment: None,
) -> None:
    del clean_environment
    observed: dict[str, object] = {}
    real_popen = runner_module.subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        observed["args"] = args
        observed["kwargs"] = dict(kwargs)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording_popen)

    result = run_analyzer_process(
        _python_argv(
            "import json,os; print(json.dumps(dict(os.environ), sort_keys=True))"
        ),
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=8192,
        max_stderr_bytes=1024,
    )

    kwargs = observed["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["close_fds"] is True
    assert kwargs["cwd"] == str(tmp_path.resolve())
    assert kwargs["stdout"] is not subprocess.PIPE
    assert kwargs["stderr"] is not subprocess.PIPE
    environment = json.loads(result.stdout)
    assert "SECAWARE_PRIVATE_PARENT_VALUE" not in environment
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["PYTHONIOENCODING"] == "utf-8"
    assert environment["PYTHONUTF8"] == "1"
    assert environment["NO_COLOR"] == "1"
    assert environment["SEMGREP_SEND_METRICS"] == "off"
    assert set(environment) <= {
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "PYTHONHASHSEED",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SEMGREP_ENABLE_VERSION_CHECK",
        "SEMGREP_SEND_METRICS",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }


def test_runner_does_not_use_communicate_even_when_descendant_inherits_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_communicate(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("communicate must not be used")

    monkeypatch.setattr(subprocess.Popen, "communicate", forbidden_communicate)
    source = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)']); "
        "sys.stdout.buffer.write(b'{\"ok\":true}\\n'); sys.stdout.buffer.flush()"
    )
    started = time.monotonic()

    result = run_analyzer_process(
        _python_argv(source),
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=4096,
        max_stderr_bytes=1024,
    )

    assert result.stdout == b'{"ok":true}\n'
    assert time.monotonic() - started < 1.5


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree regression")
def test_windows_runner_terminates_descendant_process_tree(tmp_path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    source = (
        "import subprocess,sys; "
        "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        "sys.stdout.write(str(child.pid)); sys.stdout.flush()"
    )
    result = run_analyzer_process(
        _python_argv(source),
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    descendant_pid = int(result.stdout)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    deadline = time.monotonic() + 1.0
    still_active = True
    while still_active and time.monotonic() < deadline:
        handle = kernel32.OpenProcess(0x1000, False, descendant_pid)
        if not handle:
            still_active = False
            break
        try:
            exit_code = wintypes.DWORD()
            assert kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            still_active = exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
        if still_active:
            time.sleep(0.01)

    if still_active:
        subprocess.run(
            ["taskkill", "/PID", str(descendant_pid), "/T", "/F"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    assert still_active is False


@pytest.mark.parametrize(
    ("stream", "source"),
    [
        ("stdout", "import sys; sys.stdout.write('private-stdout-' + 'x' * 4096)"),
        ("stderr", "import sys; sys.stderr.write('private-stderr-' + 'x' * 4096)"),
    ],
)
def test_runner_rejects_oversized_output_without_reading_or_retaining_it(
    tmp_path: Path,
    stream: str,
    source: str,
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(source),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=64 if stream == "stdout" else 4096,
            max_stderr_bytes=64 if stream == "stderr" else 4096,
        )

    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_INVALID_OUTPUT,
        "private-stdout-",
        "private-stderr-",
        source,
        str(tmp_path),
        sys.executable,
    )


def test_runner_accepts_output_exactly_at_the_limit(tmp_path: Path) -> None:
    payload = "x" * 64
    result = run_analyzer_process(
        _python_argv("import sys; sys.stdout.write('x' * 64)"),
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=64,
        max_stderr_bytes=64,
    )

    assert result.stdout == payload.encode("ascii")


def test_runner_times_out_kills_and_waits_without_sensitive_error_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes: list[subprocess.Popen[bytes]] = []
    real_popen = runner_module.subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        return process  # type: ignore[return-value]

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording_popen)
    source = "import time; print('private-timeout-output', flush=True); time.sleep(10)"

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(source),
            cwd=tmp_path,
            timeout_seconds=0.05,
            max_stdout_bytes=4096,
            max_stderr_bytes=1024,
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None
    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_FAILED,
        "private-timeout-output",
        source,
        str(tmp_path),
        sys.executable,
    )


def test_missing_executable_is_dedicated_safe_failure(tmp_path: Path) -> None:
    missing = tmp_path / "private-missing-analyzer-executable"

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            (str(missing), "--private-argument"),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_MISSING,
        str(missing),
        "--private-argument",
        str(tmp_path),
    )


def test_launch_failure_is_safe_analyzer_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "private-hostile-launch-exception"

    def hostile_popen(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError(sentinel)

    monkeypatch.setattr(runner_module.subprocess, "Popen", hostile_popen)
    source = "print('private-code')"

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(source),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_FAILED,
        sentinel,
        "RuntimeError",
        source,
        str(tmp_path),
        sys.executable,
    )


def test_cleanup_attempts_both_output_files_when_first_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_temporary_file = runner_module.tempfile.TemporaryFile
    handles: list[object] = []

    class TrackingFile:
        def __init__(self, handle: object, *, fail_close: bool) -> None:
            self._handle = handle
            self._fail_close = fail_close
            self.close_called = False

        def __getattr__(self, name: str) -> object:
            return getattr(self._handle, name)

        def close(self) -> None:
            self.close_called = True
            self._handle.close()  # type: ignore[attr-defined]
            if self._fail_close:
                raise RuntimeError("private-close-failure")

    def tracking_temporary_file(*args: object, **kwargs: object) -> TrackingFile:
        wrapped = TrackingFile(
            real_temporary_file(*args, **kwargs),
            fail_close=not handles,
        )
        handles.append(wrapped)
        return wrapped

    def hostile_popen(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("private-launch-failure")

    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", tracking_temporary_file)
    monkeypatch.setattr(runner_module.subprocess, "Popen", hostile_popen)

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv("print('private-code')"),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert len(handles) == 2
    assert all(handle.close_called for handle in handles)  # type: ignore[attr-defined]
    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_FAILED,
        "private-close-failure",
        "private-launch-failure",
        str(tmp_path),
    )


@pytest.mark.parametrize(
    ("argv", "cwd", "timeout_seconds", "max_stdout_bytes", "max_stderr_bytes"),
    [
        ((), Path("."), 1.0, 1, 1),
        (("",), Path("."), 1.0, 1, 1),
        (("tool\x00private",), Path("."), 1.0, 1, 1),
        (("tool", 7), Path("."), 1.0, 1, 1),
        (("tool",), Path("private-missing-cwd"), 1.0, 1, 1),
        (("tool",), Path("."), 0.0, 1, 1),
        (("tool",), Path("."), math.inf, 1, 1),
        (("tool",), Path("."), 1.0, 0, 1),
        (("tool",), Path("."), 1.0, 1, 0),
        (("tool",), Path("."), 1.0, 256 * 1024 * 1024 + 1, 1),
        (("tool",), Path("."), 1.0, 1, 64 * 1024 * 1024 + 1),
    ],
)
def test_runner_rejects_invalid_contract_without_retaining_inputs(
    tmp_path: Path,
    argv: tuple[object, ...],
    cwd: Path,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> None:
    hidden = "private-contract-value"
    candidate_cwd = tmp_path / (Path(hidden) if not argv else cwd)
    hostile_argv = tuple(argv) + ((hidden,) if argv else ())

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            hostile_argv,  # type: ignore[arg-type]
            cwd=candidate_cwd,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )

    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_FAILED,
        hidden,
        str(candidate_cwd),
    )


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_control_flow_exception_identity_survives_and_child_is_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    processes: list[subprocess.Popen[bytes]] = []
    real_popen = runner_module.subprocess.Popen
    real_monitor = runner_module._monitor_process
    signal = signal_type("private-control-flow")

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        return process  # type: ignore[return-value]

    def interrupt_monitor(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise signal

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(runner_module, "_monitor_process", interrupt_monitor)

    with pytest.raises(signal_type) as exc_info:
        run_analyzer_process(
            _python_argv("import time; time.sleep(10)", "private-control-argument"),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    monkeypatch.setattr(runner_module, "_monitor_process", real_monitor)
    assert exc_info.value is signal
    assert len(processes) == 1
    assert processes[0].poll() is not None
    retained = "\n".join(_runner_frame_surfaces(signal))
    assert "private-control-argument" not in retained
    assert str(tmp_path) not in retained


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_launch_control_flow_clears_argv_and_environment_from_every_runner_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    private_argument = "private-launch-control-argument"
    private_environment = "private-launch-control-environment"
    source = "print('private-launch-control-source')"
    signal = signal_type("private-launch-control-signal")
    handles: list[object] = []
    real_temporary_file = runner_module.tempfile.TemporaryFile

    def tracking_temporary_file(*args: object, **kwargs: object) -> object:
        handle = real_temporary_file(*args, **kwargs)
        handles.append(handle)
        return handle

    def private_minimal_environment(executable: Path, cwd: Path) -> dict[str, str]:
        del executable, cwd
        return {"PRIVATE_RUNNER_ENVIRONMENT": private_environment}

    def interrupt_popen(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise signal

    monkeypatch.setattr(runner_module, "_minimal_environment", private_minimal_environment)
    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", tracking_temporary_file)
    monkeypatch.setattr(runner_module.subprocess, "Popen", interrupt_popen)

    with pytest.raises(signal_type) as exc_info:
        run_analyzer_process(
            _python_argv(source, private_argument),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert exc_info.value is signal
    assert len(handles) == 2
    assert all(handle.closed for handle in handles)  # type: ignore[attr-defined]
    retained = "\n".join(_runner_frame_surfaces(signal))
    for hidden in (
        private_argument,
        private_environment,
        source,
        str(tmp_path),
        sys.executable,
    ):
        assert hidden not in retained


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_monitor_control_flow_clears_popen_args_from_every_runner_frame_and_cleans_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    private_argument = "private-monitor-control-argument"
    source = "import time; time.sleep(10)"
    signal = signal_type("private-monitor-control-signal")
    processes: list[subprocess.Popen[bytes]] = []
    handles: list[object] = []
    real_popen = runner_module.subprocess.Popen
    real_temporary_file = runner_module.tempfile.TemporaryFile

    def tracking_temporary_file(*args: object, **kwargs: object) -> object:
        handle = real_temporary_file(*args, **kwargs)
        handles.append(handle)
        return handle

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        return process  # type: ignore[return-value]

    def interrupt_sleep(seconds: float) -> None:
        del seconds
        raise signal

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", tracking_temporary_file)
    monkeypatch.setattr(runner_module.time, "sleep", interrupt_sleep)

    with pytest.raises(signal_type) as exc_info:
        run_analyzer_process(
            _python_argv(source, private_argument),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert exc_info.value is signal
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert len(handles) == 2
    assert all(handle.closed for handle in handles)  # type: ignore[attr-defined]
    retained = "\n".join(_runner_frame_surfaces(signal))
    for hidden in (private_argument, source, str(tmp_path), sys.executable):
        assert hidden not in retained


def test_negative_signal_returncode_is_safe_failure(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("negative signal return codes are POSIX-specific")

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv("import os,signal; os.kill(os.getpid(), signal.SIGTERM)"),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    _assert_safe_error(
        exc_info.value,
        ErrorCode.ANALYZER_FAILED,
        "SIGTERM",
        str(tmp_path),
        sys.executable,
    )


def test_output_file_is_size_checked_before_stdout_is_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []
    real_temporary_file = runner_module.tempfile.TemporaryFile

    class TrackingFile:
        def __init__(self, handle: object) -> None:
            self._handle = handle

        def __getattr__(self, name: str) -> object:
            return getattr(self._handle, name)

        def read(self, size: int = -1) -> bytes:
            reads.append(size)
            return self._handle.read(size)  # type: ignore[attr-defined,no-any-return]

    def tracking_temporary_file(*args: object, **kwargs: object) -> TrackingFile:
        return TrackingFile(real_temporary_file(*args, **kwargs))

    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", tracking_temporary_file)

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv("import sys; sys.stdout.write('x' * 4096)"),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=64,
            max_stderr_bytes=64,
        )

    assert reads == []
    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT


def test_runner_result_stdout_snapshot_is_immutable_after_return(tmp_path: Path) -> None:
    result = run_analyzer_process(
        _python_argv("import sys; sys.stdout.buffer.write(b'stable\\n')"),
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert result.stdout == b"stable\n"
    with pytest.raises((AttributeError, TypeError)):
        result.stdout = b"changed"  # type: ignore[misc]

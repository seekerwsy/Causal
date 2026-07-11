from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from functools import partial
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Iterator, Sequence

import pytest

import secaware.oracle.runner as runner_module
from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.runner import (
    AnalyzerProcessResult,
    AnalyzerRuntimeCapabilities,
    run_analyzer_process,
    validate_analyzer_runtime,
)


_POPEN_TYPE = subprocess.Popen


def _python_argv(source: str, *arguments: str) -> tuple[str, ...]:
    return (sys.executable, "-c", source, *arguments)


def test_runtime_preflight_rejects_unsupported_platform_without_probing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_calls: list[str] = []
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: None)
    monkeypatch.setattr(
        runner_module,
        "_probe_windows_runtime_capabilities",
        lambda: probe_calls.append("windows"),
        raising=False,
    )
    monkeypatch.setattr(
        runner_module,
        "_probe_linux_runtime_capabilities",
        lambda: probe_calls.append("linux"),
        raising=False,
    )

    with pytest.raises(SecAwareError) as exc_info:
        validate_analyzer_runtime()

    _assert_safe_error(exc_info.value, ErrorCode.ANALYZER_FAILED)
    assert probe_calls == []


def test_runtime_preflight_fails_closed_when_linux_namespaces_are_forced_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_calls: list[str] = []
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: "linux")
    monkeypatch.setattr(runner_module, "_force_namespace_unavailable", lambda: True)
    monkeypatch.setattr(
        runner_module,
        "_probe_linux_runtime_capabilities",
        lambda: probe_calls.append("linux"),
        raising=False,
    )

    with pytest.raises(SecAwareError) as exc_info:
        validate_analyzer_runtime()

    _assert_safe_error(exc_info.value, ErrorCode.ANALYZER_FAILED)
    assert probe_calls == []


def test_runtime_preflight_hides_capability_probe_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = "/private/runtime/probe/capability"
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: "linux")
    monkeypatch.setattr(runner_module, "_force_namespace_unavailable", lambda: False)

    def failed_probe() -> None:
        raise OSError(private_path)

    monkeypatch.setattr(runner_module, "_probe_linux_runtime_capabilities", failed_probe)

    with pytest.raises(SecAwareError) as exc_info:
        validate_analyzer_runtime()

    _assert_safe_error(exc_info.value, ErrorCode.ANALYZER_FAILED, private_path)


def test_runtime_preflight_reports_windows_job_and_toolhelp_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: "windows")
    monkeypatch.setattr(
        runner_module,
        "_probe_windows_runtime_capabilities",
        lambda: None,
        raising=False,
    )

    capabilities = validate_analyzer_runtime()

    assert capabilities == AnalyzerRuntimeCapabilities(
        platform="windows",
        job_object=True,
        toolhelp_snapshot=True,
        user_namespace=False,
        pid_namespace=False,
        mount_namespace=False,
        private_proc=False,
    )


def test_runtime_preflight_reports_linux_namespace_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: "linux")
    monkeypatch.setattr(runner_module, "_force_namespace_unavailable", lambda: False)
    monkeypatch.setattr(
        runner_module,
        "_probe_linux_runtime_capabilities",
        lambda: None,
        raising=False,
    )

    capabilities = validate_analyzer_runtime()

    assert capabilities == AnalyzerRuntimeCapabilities(
        platform="linux",
        job_object=False,
        toolhelp_snapshot=False,
        user_namespace=True,
        pid_namespace=True,
        mount_namespace=True,
        private_proc=True,
    )


def test_runtime_preflight_never_resolves_or_starts_analyzer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer_marker_path = tmp_path / "private-analyzer-started.marker"
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: "linux")
    monkeypatch.setattr(runner_module, "_force_namespace_unavailable", lambda: False)
    monkeypatch.setattr(
        runner_module,
        "_probe_linux_runtime_capabilities",
        lambda: None,
        raising=False,
    )

    def analyzer_marker(*args: object, **kwargs: object) -> None:
        analyzer_marker_path.write_text("started", encoding="utf-8")
        raise AssertionError("analyzer resolution must not run during runtime preflight")

    monkeypatch.setattr(runner_module, "_resolve_analyzer_executable", analyzer_marker)

    validate_analyzer_runtime()
    assert not analyzer_marker_path.exists()


def test_linux_runtime_probe_preserves_control_flow_after_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls: list[object] = []

    class InterruptedProbe:
        def wait(self, *, timeout: float) -> int:
            assert timeout == runner_module._RUNTIME_PROBE_TIMEOUT_SECONDS
            raise KeyboardInterrupt

        def poll(self) -> None:
            return None

    probe = InterruptedProbe()
    monkeypatch.setattr(runner_module, "_detect_runtime_platform", lambda: "linux")
    monkeypatch.setattr(runner_module, "_force_namespace_unavailable", lambda: False)
    monkeypatch.setattr(runner_module.Path, "is_file", lambda self: True)
    monkeypatch.setattr(runner_module.Path, "is_dir", lambda self: True)
    monkeypatch.setattr(runner_module.subprocess, "Popen", lambda *args, **kwargs: probe)

    def failing_cleanup(process: object, windows_job: object) -> None:
        cleanup_calls.append((process, windows_job))
        raise OSError("private cleanup failure")

    monkeypatch.setattr(runner_module, "_terminate_and_wait", failing_cleanup)

    with pytest.raises(KeyboardInterrupt):
        validate_analyzer_runtime()

    assert cleanup_calls == [(probe, None)]


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


def _contains_identity(value: object, forbidden_ids: set[int], seen: set[int]) -> bool:
    identity = id(value)
    if identity in forbidden_ids:
        return True
    if identity in seen:
        return False
    seen.add(identity)
    if isinstance(value, dict):
        return any(
            _contains_identity(item, forbidden_ids, seen) for pair in value.items() for item in pair
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_identity(item, forbidden_ids, seen) for item in value)
    return False


def _assert_runner_frames_release_objects(
    error: BaseException,
    *forbidden: object,
) -> None:
    forbidden_ids = {id(value) for value in forbidden}
    for _, frame_locals in _secaware_traceback_frames(error):
        assert not _contains_identity(frame_locals, forbidden_ids, set())


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
        _python_argv("import json,os; print(json.dumps(dict(os.environ), sort_keys=True))"),
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
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
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


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended-launch regression")
def test_windows_process_cannot_run_before_job_assignment_and_detached_child_cannot_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    immediate_marker = tmp_path / "private-immediate.marker"
    detached_marker = tmp_path / "private-detached.marker"
    entered_assignment = threading.Event()
    release_assignment = threading.Event()
    real_create_job = runner_module._create_windows_job
    outcome: list[object] = []

    def gated_create_job(process: subprocess.Popen[bytes]) -> object:
        entered_assignment.set()
        assert release_assignment.wait(timeout=5.0)
        return real_create_job(process)

    monkeypatch.setattr(runner_module, "_create_windows_job", gated_create_job)
    child_source = (
        "import time; from pathlib import Path; time.sleep(0.4); "
        f"Path({str(detached_marker)!r}).write_text('escaped')"
    )
    source = (
        "import subprocess,sys; from pathlib import Path; "
        f"Path({str(immediate_marker)!r}).write_text('ran'); "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1]], "
        "creationflags=0x00000008|0x00000200, close_fds=True)"
    )

    def invoke() -> None:
        try:
            outcome.append(
                run_analyzer_process(
                    _python_argv(source, child_source),
                    cwd=tmp_path,
                    timeout_seconds=3.0,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                )
            )
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=invoke)
    worker.start()
    assert entered_assignment.wait(timeout=3.0)
    try:
        deadline = time.monotonic() + 0.5
        while not immediate_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not immediate_marker.exists()
    finally:
        release_assignment.set()
        worker.join(timeout=5.0)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], AnalyzerProcessResult)
    time.sleep(0.8)
    assert not detached_marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_setsid_descendant_is_reaped_before_normal_return(tmp_path: Path) -> None:
    ready_marker = tmp_path / "private-setsid-ready.marker"
    escaped_marker = tmp_path / "private-setsid-escaped.marker"
    source = (
        "import os,sys,time\nfrom pathlib import Path\n"
        "pid=os.fork()\n"
        "if pid==0:\n"
        " os.setsid(); Path(sys.argv[1]).write_text('ready'); time.sleep(0.5); "
        "Path(sys.argv[2]).write_text('escaped'); os._exit(0)\n"
        "deadline=time.time()+2\n"
        "while not Path(sys.argv[1]).exists() and time.time()<deadline: time.sleep(0.01)\n"
    )

    result = run_analyzer_process(
        _python_argv(source, str(ready_marker), str(escaped_marker)),
        cwd=tmp_path,
        timeout_seconds=3.0,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert result.returncode == 0
    assert ready_marker.exists()
    time.sleep(0.8)
    assert not escaped_marker.exists()


@pytest.mark.skipif(os.name != "posix" or sys.platform == "linux", reason="unsupported POSIX")
def test_non_linux_posix_fails_closed_before_launch(tmp_path: Path) -> None:
    marker = tmp_path / "private-unsupported-posix.marker"

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert not marker.exists()


def test_executable_replacement_window_cannot_change_launched_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / ("analyzer.exe" if os.name == "nt" else "analyzer")
    replacement = tmp_path / "private-replacement"
    source_executable = shutil.which("cmd.exe") if os.name == "nt" else sys.executable
    assert source_executable is not None
    shutil.copyfile(source_executable, executable)
    executable.chmod(0o700)
    replacement.write_bytes(b"private-invalid-replacement")
    entered_launch = threading.Event()
    release_launch = threading.Event()
    real_popen = runner_module._popen_process
    outcome: list[object] = []

    def gated_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        entered_launch.set()
        assert release_launch.wait(timeout=5.0)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_popen_process", gated_popen)

    def invoke() -> None:
        try:
            outcome.append(
                run_analyzer_process(
                    (
                        (str(executable), "/d", "/c", "<nul set /p =original")
                        if os.name == "nt"
                        else (
                            str(executable),
                            "-c",
                            "import sys; sys.stdout.buffer.write(b'original')",
                        )
                    ),
                    cwd=tmp_path,
                    timeout_seconds=3.0,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                )
            )
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=invoke)
    worker.start()
    assert entered_launch.wait(timeout=3.0)
    replacement_denied = False
    try:
        os.replace(replacement, executable)
    except OSError:
        replacement_denied = True
    finally:
        release_launch.set()
        worker.join(timeout=5.0)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], AnalyzerProcessResult)
    if os.name == "nt":
        assert replacement_denied is True
    else:
        assert outcome[0].stdout == b"original"  # type: ignore[union-attr]


def test_cwd_replacement_window_cannot_change_launched_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working = tmp_path / "working"
    replacement = tmp_path / "private-replacement-working"
    moved = tmp_path / "private-moved-working"
    working.mkdir()
    replacement.mkdir()
    working.joinpath("identity.txt").write_text("old", encoding="utf-8")
    replacement.joinpath("identity.txt").write_text("new", encoding="utf-8")
    entered_launch = threading.Event()
    release_launch = threading.Event()
    real_popen = runner_module._popen_process
    outcome: list[object] = []

    def gated_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        entered_launch.set()
        assert release_launch.wait(timeout=5.0)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_popen_process", gated_popen)

    def invoke() -> None:
        try:
            outcome.append(
                run_analyzer_process(
                    _python_argv(
                        "import sys; from pathlib import Path; "
                        "sys.stdout.buffer.write(Path('identity.txt').read_bytes())"
                    ),
                    cwd=working,
                    timeout_seconds=3.0,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                )
            )
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=invoke)
    worker.start()
    assert entered_launch.wait(timeout=3.0)
    replacement_denied = False
    try:
        os.replace(working, moved)
        os.replace(replacement, working)
    except OSError:
        replacement_denied = True
    finally:
        release_launch.set()
        worker.join(timeout=5.0)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], AnalyzerProcessResult)
    assert outcome[0].stdout == b"old"  # type: ignore[union-attr]
    if os.name == "nt":
        assert replacement_denied is True


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed executable regression")
def test_linux_in_place_executable_overwrite_runs_sealed_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "analyzer"
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    entered = threading.Event()
    release = threading.Event()
    real_popen = runner_module._popen_process

    def gated(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        entered.set()
        assert release.wait(5)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_popen_process", gated)
    outcome: list[object] = []
    worker = threading.Thread(
        target=lambda: outcome.append(
            run_analyzer_process(
                (str(executable), "sealed-original"),
                cwd=tmp_path,
                timeout_seconds=3,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        )
    )
    worker.start()
    assert entered.wait(3)
    with executable.open("wb") as target, open("/bin/true", "rb") as replacement:
        shutil.copyfileobj(replacement, target)
    release.set()
    worker.join(5)
    assert isinstance(outcome[0], AnalyzerProcessResult)
    assert outcome[0].stdout == b"sealed-original\n"  # type: ignore[union-attr]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed script regression")
def test_linux_sealed_memfd_preserves_shebang_script_execution(tmp_path: Path) -> None:
    script = tmp_path / "analyzer-script"
    script.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.buffer.write(b'sealed-script')\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    result = run_analyzer_process(
        (str(script),),
        cwd=tmp_path,
        timeout_seconds=2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    assert result.stdout == b"sealed-script"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed interpreter regression")
def test_linux_script_interpreter_is_sealed_against_in_place_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter = tmp_path / "python"
    shutil.copyfile(Path(sys.executable).resolve(), interpreter)
    interpreter.chmod(0o700)
    script = tmp_path / "script"
    script.write_text(
        f"#!{interpreter}\nimport sys\nsys.stdout.buffer.write(b'bound-interpreter')\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    entered, release = threading.Event(), threading.Event()
    real_popen = runner_module._popen_process

    def gated(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        entered.set()
        assert release.wait(5)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_popen_process", gated)
    outcome: list[object] = []
    worker = threading.Thread(
        target=lambda: outcome.append(
            run_analyzer_process(
                (str(script),),
                cwd=tmp_path,
                timeout_seconds=3,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        )
    )
    worker.start()
    assert entered.wait(3)
    with interpreter.open("wb") as target, open("/bin/true", "rb") as replacement:
        shutil.copyfileobj(replacement, target)
    release.set()
    worker.join(5)
    assert isinstance(outcome[0], AnalyzerProcessResult)
    assert outcome[0].stdout == b"bound-interpreter"  # type: ignore[union-attr]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed venv regression")
def test_linux_sealed_interpreter_preserves_venv_site_packages(tmp_path: Path) -> None:
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    venv = tmp_path / "venv"
    bin_dir = venv / "bin"
    site_packages = venv / "lib" / f"python{version}" / "site-packages"
    bin_dir.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    (bin_dir / "python").symlink_to(Path(sys.executable).resolve())
    (venv / "pyvenv.cfg").write_text(
        f"home = /usr/bin\ninclude-system-site-packages = false\nversion = {version}\n",
        encoding="utf-8",
    )
    (site_packages / "venv_only.py").write_text("VALUE='venv-ok'\n", encoding="utf-8")
    script = tmp_path / "launcher"
    script.write_text(
        f"#!{bin_dir / 'python'}\nimport sys,venv_only\nsys.stdout.write(venv_only.VALUE)\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    result = run_analyzer_process(
        (str(script),),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    assert result.stdout == b"venv-ok"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervisor bootstrap regression")
def test_linux_supervisor_bootstrap_skips_late_venv_pth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_python = str(Path(sys.executable).resolve())
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    venv = tmp_path / "hostile-supervisor-venv"
    bin_dir = venv / "bin"
    site_packages = venv / "lib" / f"python{version}" / "site-packages"
    bin_dir.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    (bin_dir / "python").symlink_to(original_python)
    (venv / "pyvenv.cfg").write_text(
        f"home = {Path(original_python).parent}\n"
        "include-system-site-packages = false\n"
        f"version = {version}\n",
        encoding="utf-8",
    )
    pth_marker = tmp_path / "private-supervisor-pth.marker"
    analyzer_marker = tmp_path / "private-real-analyzer.marker"
    attack = (
        f"open({str(pth_marker)!r},'w').write('pth')\n"
        "for fd in range(3,256):\n"
        " try: os.write(fd,b'R:0')\n"
        " except OSError: pass\n"
        "os._exit(0)"
    )
    (site_packages / "late_attack.pth").write_text(
        f"import os;exec({attack!r})\n", encoding="utf-8"
    )
    monkeypatch.setattr(runner_module.sys, "executable", str(bin_dir / "python"))

    result = run_analyzer_process(
        (
            original_python,
            "-c",
            "import sys;from pathlib import Path;"
            f"Path({str(analyzer_marker)!r}).write_text('ran');"
            "sys.stdout.write('real')",
        ),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert result.stdout == b"real"
    assert analyzer_marker.exists()
    assert not pth_marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervisor bootstrap regression")
def test_linux_supervisor_uses_sealed_isolated_bootstrap_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    real_popen = runner_module.subprocess.Popen

    def recording(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        observed["args"] = args
        observed["kwargs"] = dict(kwargs)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording)
    result = run_analyzer_process(
        _python_argv("print('real',end='')"),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    popen_argv = observed["args"]
    kwargs = observed["kwargs"]
    assert isinstance(popen_argv, tuple) and isinstance(kwargs, dict)
    internal_argv = popen_argv[0]
    assert internal_argv[0] == os.path.abspath(sys.executable)
    assert internal_argv[1:3] == ("-I", "-S")
    assert internal_argv[3].startswith("/proc/self/fd/")
    assert "_posix_supervisor.py" not in internal_argv
    assert kwargs["executable"].startswith("/proc/self/fd/")
    assert result.stdout == b"real"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux launch-owner regression")
@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_linux_launch_owner_closes_sealed_bootstrap_on_prepare_return_control_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    signal = signal_type("private-prepare-return-control")
    descriptors: list[int] = []
    real_memfd_create = runner_module.os.memfd_create
    real_pipe = runner_module.os.pipe

    def tracking_memfd_create(*args: object, **kwargs: object) -> int:
        descriptor = real_memfd_create(*args, **kwargs)  # type: ignore[arg-type]
        descriptors.append(descriptor)
        return descriptor

    def tracking_pipe() -> tuple[int, int]:
        pair = real_pipe()
        descriptors.extend(pair)
        return pair

    def interrupt_return(frame: object, event: str, arg: object) -> object:
        del arg
        if (
            event == "return"
            and getattr(frame, "f_code", None) is runner_module._prepare_posix_launch.__code__
        ):
            raise signal
        return interrupt_return

    monkeypatch.setattr(runner_module.os, "memfd_create", tracking_memfd_create)
    monkeypatch.setattr(runner_module.os, "pipe", tracking_pipe)
    previous_trace = sys.gettrace()
    try:
        sys.settrace(interrupt_return)
        with pytest.raises(signal_type) as exc_info:
            run_analyzer_process(
                _python_argv("print('private-prepare-source')"),
                cwd=tmp_path,
                timeout_seconds=3,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
    finally:
        sys.settrace(previous_trace)

    assert exc_info.value is signal
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert "private-prepare-source" not in "\n".join(_runner_frame_surfaces(signal))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervisor bootstrap regression")
def test_linux_supervisor_source_swap_after_sealing_cannot_change_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = tmp_path / "_posix_supervisor.py"
    supervisor.write_bytes(
        Path(runner_module.__file__).with_name("_posix_supervisor.py").read_bytes()
    )
    fake_runner = tmp_path / "runner.py"
    monkeypatch.setattr(runner_module, "__file__", str(fake_runner))
    entered, release = threading.Event(), threading.Event()
    real_popen = runner_module._popen_process
    analyzer_marker = tmp_path / "private-source-swap-analyzer.marker"
    outcome: list[object] = []

    def gated(*args: object, **kwargs: object) -> None:
        entered.set()
        assert release.wait(5)
        real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_popen_process", gated)
    worker = threading.Thread(
        target=lambda: outcome.append(
            run_analyzer_process(
                _python_argv(
                    "import sys;from pathlib import Path;"
                    f"Path({str(analyzer_marker)!r}).write_text('ran');"
                    "sys.stdout.write('real')"
                ),
                cwd=tmp_path,
                timeout_seconds=3,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        )
    )
    worker.start()
    assert entered.wait(3)
    supervisor.write_text(
        "import os,sys\nos.write(int(sys.argv[-1]),b'R:0')\nos._exit(0)\n",
        encoding="utf-8",
    )
    release.set()
    worker.join(5)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], AnalyzerProcessResult)
    assert outcome[0].stdout == b"real"  # type: ignore[union-attr]
    assert analyzer_marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervisor bootstrap regression")
def test_linux_supervisor_interpreter_swap_after_sealing_cannot_change_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_python = Path(sys.executable).resolve()
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    venv = tmp_path / "supervisor-venv"
    bin_dir = venv / "bin"
    bin_dir.mkdir(parents=True)
    interpreter = bin_dir / "python"
    shutil.copyfile(original_python, interpreter)
    interpreter.chmod(0o700)
    (venv / "pyvenv.cfg").write_text(
        f"home = {original_python.parent}\n"
        "include-system-site-packages = false\n"
        f"version = {version}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(runner_module.sys, "executable", str(interpreter))
    entered, release = threading.Event(), threading.Event()
    real_popen = runner_module._popen_process
    analyzer_marker = tmp_path / "private-interpreter-swap-analyzer.marker"
    outcome: list[object] = []

    def gated(*args: object, **kwargs: object) -> None:
        entered.set()
        assert release.wait(5)
        real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_popen_process", gated)
    worker = threading.Thread(
        target=lambda: outcome.append(
            run_analyzer_process(
                (
                    str(original_python),
                    "-c",
                    "import sys;from pathlib import Path;"
                    f"Path({str(analyzer_marker)!r}).write_text('ran');"
                    "sys.stdout.write('real')",
                ),
                cwd=tmp_path,
                timeout_seconds=3,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        )
    )
    worker.start()
    assert entered.wait(3)
    with interpreter.open("wb") as target, open("/bin/true", "rb") as replacement:
        shutil.copyfileobj(replacement, target)
    release.set()
    worker.join(5)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], AnalyzerProcessResult)
    assert outcome[0].stdout == b"real"  # type: ignore[union-attr]
    assert analyzer_marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strict shebang regression")
def test_linux_env_shebang_fails_closed_before_launch(tmp_path: Path) -> None:
    script = tmp_path / "script"
    script.write_text("#!/usr/bin/env python3\nprint('unsafe')\n", encoding="utf-8")
    script.chmod(0o700)
    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            (str(script),),
            cwd=tmp_path,
            timeout_seconds=2,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED


@pytest.mark.skipif(sys.platform != "linux", reason="Linux stable fingerprint regression")
def test_linux_fingerprint_is_stable_and_binds_source_identity(tmp_path: Path) -> None:
    executable = tmp_path / "echo"
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    first = run_analyzer_process(
        (str(executable), "x"),
        cwd=tmp_path,
        timeout_seconds=2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    second = run_analyzer_process(
        (str(executable), "x"),
        cwd=tmp_path,
        timeout_seconds=2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    assert first.argv_sha256 == second.argv_sha256
    executable.chmod(0o755)
    changed = run_analyzer_process(
        (str(executable), "x"),
        cwd=tmp_path,
        timeout_seconds=2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    assert changed.argv_sha256 != first.argv_sha256


@pytest.mark.skipif(sys.platform != "linux", reason="Linux fingerprint boundary regression")
def test_linux_fingerprint_binds_direct_launch_objects_not_transitive_dependencies(
    tmp_path: Path,
) -> None:
    dependency = tmp_path / "runtime_dependency.py"
    dependency.write_text("VALUE='one'\n", encoding="utf-8")
    script = tmp_path / "launcher"
    script.write_text(
        f"#!{sys.executable}\n"
        f"scope={{}};exec(compile(open({str(dependency)!r}).read(),"
        f"{str(dependency)!r},'exec'),scope);print(scope['VALUE'],end='')\n",
        encoding="utf-8",
    )
    script.chmod(0o700)

    first = run_analyzer_process(
        (str(script),),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )
    dependency.write_text("VALUE='two'\n", encoding="utf-8")
    second = run_analyzer_process(
        (str(script),),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert first.stdout == b"one"
    assert second.stdout == b"two"
    assert first.argv_sha256 == second.argv_sha256


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed short-write regression")
def test_linux_sealed_copy_handles_short_writes_and_verifies_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "echo"
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    real_write = runner_module.os.write

    def short_write(descriptor: int, payload: bytes) -> int:
        return real_write(descriptor, payload[:7])

    monkeypatch.setattr(runner_module.os, "write", short_write)
    lease = runner_module._open_posix_path_lease(executable, directory=False)
    assert lease is not None
    try:
        assert lease.sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()
        assert os.fstat(lease.fd).st_size == executable.stat().st_size
    finally:
        lease.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed verification regression")
def test_linux_sealed_copy_rejects_same_length_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "echo"
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    real_write = runner_module.os.write
    corrupted = False

    def corrupt_write(descriptor: int, payload: bytes) -> int:
        nonlocal corrupted
        if payload and not corrupted:
            payload = bytes([payload[0] ^ 1]) + payload[1:]
            corrupted = True
        return real_write(descriptor, payload)

    monkeypatch.setattr(runner_module.os, "write", corrupt_write)
    with pytest.raises(runner_module._RunnerFailure) as exc_info:
        runner_module._open_posix_path_lease(executable, directory=False)
    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED


@pytest.mark.skipif(sys.platform != "linux", reason="Linux stopped namespace-init regression")
def test_linux_stopped_namespace_init_is_destroyed_with_setsid_child(tmp_path: Path) -> None:
    marker = tmp_path / "private-stopped-namespace-init-escaped.marker"
    source = (
        "import os,signal,sys,time\nfrom pathlib import Path\n"
        "namespace_init=os.getppid()\n"
        "stopper=os.fork()\n"
        "if stopper==0:\n"
        "\n for _ in range(200):\n  os.kill(namespace_init,signal.SIGSTOP);time.sleep(.005)\n"
        "\n os._exit(0)\n"
        "pid=os.fork()\n"
        "if pid==0:\n os.setsid();time.sleep(.5);Path(sys.argv[1]).write_text('x');os._exit(0)\n"
        "time.sleep(10)\n"
    )
    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(source, str(marker)),
            cwd=tmp_path,
            timeout_seconds=0.2,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    time.sleep(0.8)
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux exec-status regression")
def test_linux_exec_failure_is_analyzer_failed_not_returncode_126(tmp_path: Path) -> None:
    executable = tmp_path / "invalid-analyzer"
    executable.write_bytes(b"not-an-executable")
    executable.chmod(0o700)
    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            (str(executable),),
            cwd=tmp_path,
            timeout_seconds=2,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED


@pytest.mark.skipif(sys.platform != "linux", reason="Linux result-protocol regression")
@pytest.mark.parametrize("returncode", [125, 126])
def test_linux_analyzer_may_legitimately_return_supervisor_reserved_codes(
    tmp_path: Path,
    returncode: int,
) -> None:
    result = run_analyzer_process(
        _python_argv(f"import sys;sys.exit({returncode})"),
        cwd=tmp_path,
        timeout_seconds=2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert result.returncode == returncode


@pytest.mark.parametrize("frame", [b"", b"I", b"R:0125", b"R:999", b"R:not-an-int"])
def test_supervisor_result_protocol_rejects_missing_or_malformed_frames(frame: bytes) -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, frame)
    os.close(write_fd)

    class Process:
        _secaware_result_fd = read_fd

    process = Process()
    with pytest.raises(runner_module._RunnerFailure) as exc_info:
        runner_module._read_posix_result(process, 0)  # type: ignore[arg-type]
    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert process._secaware_result_fd == -1


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_analyzer_cannot_kill_namespace_init_or_reach_outer_supervisor(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "private-namespace-parent-ready.marker"
    escaped = tmp_path / "private-namespace-parent-escaped.marker"
    kill_returned = tmp_path / "private-namespace-init-kill-returned.marker"
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(10)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    source = (
        "import os,signal,sys,time\nfrom pathlib import Path\n"
        "pid=os.fork()\n"
        "if pid==0:\n"
        " os.setsid(); Path(sys.argv[1]).write_text('ready'); time.sleep(0.8); "
        "Path(sys.argv[2]).write_text('escaped'); os._exit(0)\n"
        "deadline=time.time()+2\n"
        "while not Path(sys.argv[1]).exists() and time.time()<deadline: time.sleep(0.01)\n"
        "os.kill(os.getppid(), signal.SIGKILL);"
        "Path(sys.argv[3]).write_text('signal-not-delivered');time.sleep(10)\n"
    )

    try:
        with pytest.raises(SecAwareError) as exc_info:
            run_analyzer_process(
                _python_argv(source, str(ready), str(escaped), str(kill_returned)),
                cwd=tmp_path,
                timeout_seconds=0.2,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
        assert ready.exists()
        assert kill_returned.exists()
        time.sleep(1.0)
        assert not escaped.exists()
        assert unrelated.poll() is None
    finally:
        unrelated.kill()
        unrelated.wait(timeout=3)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_analyzer_sees_only_namespace_init_as_parent(tmp_path: Path) -> None:
    source = (
        "import json,os\n"
        "print(json.dumps({'pid':os.getpid(),'ppid':os.getppid(),"
        "'visible':sorted(int(x) for x in os.listdir('/proc') if x.isdigit())}))\n"
    )

    result = run_analyzer_process(
        _python_argv(source),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=4096,
        max_stderr_bytes=1024,
    )
    visible = json.loads(result.stdout)
    assert visible == {"pid": 2, "ppid": 1, "visible": [1, 2]}


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_pid_namespace_reaps_close_fds_descendant_without_killing_baseline(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "private-close-fds-ready.marker"
    escaped = tmp_path / "private-close-fds-escaped.marker"
    baseline = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(10)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_source = (
        "import os,sys,time\nfrom pathlib import Path\n"
        "os.setsid();Path(sys.argv[1]).write_text('ready');time.sleep(.8);"
        "Path(sys.argv[2]).write_text('escaped')\n"
    )
    source = (
        "import os,signal,subprocess,sys,time\nfrom pathlib import Path\n"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]],"
        "close_fds=True)\n"
        "deadline=time.time()+2\n"
        "while not Path(sys.argv[2]).exists() and time.time()<deadline: time.sleep(.01)\n"
        "os.kill(os.getppid(),signal.SIGKILL);time.sleep(10)\n"
    )

    try:
        with pytest.raises(SecAwareError) as exc_info:
            run_analyzer_process(
                _python_argv(source, child_source, str(ready), str(escaped)),
                cwd=tmp_path,
                timeout_seconds=0.2,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
        assert ready.exists()
        time.sleep(1)
        assert not escaped.exists()
        assert baseline.poll() is None
    finally:
        baseline.kill()
        baseline.wait(timeout=3)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_pid_namespace_reaps_close_fds_setsid_double_fork(tmp_path: Path) -> None:
    ready = tmp_path / "private-double-fork-ready.marker"
    escaped = tmp_path / "private-double-fork-escaped.marker"
    child_source = (
        "import os,sys,time\nfrom pathlib import Path\n"
        "if os.fork(): os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork(): os._exit(0)\n"
        "Path(sys.argv[1]).write_text('ready');time.sleep(.8);"
        "Path(sys.argv[2]).write_text('escaped')\n"
    )
    source = (
        "import subprocess,sys,time\nfrom pathlib import Path\n"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]],"
        "close_fds=True)\n"
        "deadline=time.time()+2\n"
        "while not Path(sys.argv[2]).exists() and time.time()<deadline: time.sleep(.01)\n"
    )

    result = run_analyzer_process(
        _python_argv(source, child_source, str(ready), str(escaped)),
        cwd=tmp_path,
        timeout_seconds=3,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert result.returncode == 0
    assert ready.exists()
    time.sleep(1)
    assert not escaped.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_outer_supervisor_death_uses_pdeathsig_to_destroy_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "private-pdeathsig-ready.marker"
    escaped = tmp_path / "private-pdeathsig-escaped.marker"
    source = (
        "import sys,time\nfrom pathlib import Path\n"
        "Path(sys.argv[1]).write_text('ready');time.sleep(.8);"
        "Path(sys.argv[2]).write_text('escaped')\n"
    )
    real_monitor = runner_module._monitor_process

    def kill_outer_supervisor(
        process: subprocess.Popen[bytes], *args: object, **kwargs: object
    ) -> int:
        deadline = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists()
        os.kill(process.pid, signal.SIGKILL)
        return real_monitor(process, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_module, "_monitor_process", kill_outer_supervisor)
    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(source, str(ready), str(escaped)),
            cwd=tmp_path,
            timeout_seconds=3,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    time.sleep(1)
    assert not escaped.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID namespace regression")
def test_linux_namespace_unavailable_fails_before_analyzer_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "private-namespace-unavailable.marker"
    monkeypatch.setattr(runner_module, "_force_namespace_unavailable", lambda: True)

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(f"from pathlib import Path;Path({str(marker)!r}).write_text('ran')"),
            cwd=tmp_path,
            timeout_seconds=3,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux unrelated-child regression")
def test_linux_timeout_does_not_kill_or_reap_unrelated_child_started_during_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = threading.Event()
    real_popen_process = runner_module._popen_process
    outcome: list[object] = []

    def observe_launch(*args: object, **kwargs: object) -> None:
        real_popen_process(*args, **kwargs)  # type: ignore[arg-type]
        launched.set()

    monkeypatch.setattr(runner_module, "_popen_process", observe_launch)

    def invoke() -> None:
        try:
            outcome.append(
                run_analyzer_process(
                    _python_argv("import time;time.sleep(10)"),
                    cwd=tmp_path,
                    timeout_seconds=0.3,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                )
            )
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=invoke)
    worker.start()
    assert launched.wait(timeout=3)
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(10)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], SecAwareError)
        assert unrelated.poll() is None
        unrelated.kill()
        assert unrelated.wait(timeout=3) < 0
    finally:
        if unrelated.poll() is None:
            unrelated.kill()
            unrelated.wait(timeout=3)


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_process_handoff_control_flow_cleans_created_process_and_preserves_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    signal = signal_type("private-handoff-control")
    processes: list[subprocess.Popen[bytes]] = []
    real_popen = runner_module.subprocess.Popen

    def recording(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        return process  # type: ignore[return-value]

    def interrupt(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise signal

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording)
    monkeypatch.setattr(runner_module, "_finalize_process_handoff", interrupt)
    with pytest.raises(signal_type) as exc_info:
        run_analyzer_process(
            _python_argv("import time;time.sleep(10)"),
            cwd=tmp_path,
            timeout_seconds=2,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert exc_info.value is signal
    assert len(processes) == 1 and processes[0].poll() is not None
    assert "time.sleep(10)" not in "\n".join(_runner_frame_surfaces(signal))


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_popen_init_control_flow_after_child_creation_is_owned_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    signal = signal_type("private-popen-init-control")
    processes: list[subprocess.Popen[bytes]] = []
    real_init = _POPEN_TYPE.__init__

    def interrupt_after_child_created(
        process: subprocess.Popen[bytes], *args: object, **kwargs: object
    ) -> None:
        real_init(process, *args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        raise signal

    monkeypatch.setattr(_POPEN_TYPE, "__init__", interrupt_after_child_created)
    with pytest.raises(signal_type) as exc_info:
        run_analyzer_process(
            _python_argv("import time;time.sleep(10)"),
            cwd=tmp_path,
            timeout_seconds=2,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert exc_info.value is signal
    assert len(processes) == 1 and processes[0].poll() is not None


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_popen_return_event_control_flow_is_owned_by_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    signal = signal_type("private-popen-return-control")
    processes: list[subprocess.Popen[bytes]] = []
    real_init = _POPEN_TYPE.__init__

    def recording_init(process: subprocess.Popen[bytes], *args: object, **kwargs: object) -> None:
        real_init(process, *args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)

    def interrupt_return(frame: object, event: str, arg: object) -> object:
        del arg
        if (
            event == "return"
            and getattr(frame, "f_code", None) is runner_module._popen_process.__code__
        ):
            raise signal
        return interrupt_return

    monkeypatch.setattr(_POPEN_TYPE, "__init__", recording_init)
    previous_trace = sys.gettrace()
    try:
        sys.settrace(interrupt_return)
        with pytest.raises(signal_type) as exc_info:
            run_analyzer_process(
                _python_argv("import time;time.sleep(10)"),
                cwd=tmp_path,
                timeout_seconds=2,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
    finally:
        sys.settrace(previous_trace)

    assert exc_info.value is signal
    assert len(processes) == 1 and processes[0].poll() is not None
    assert "time.sleep(10)" not in "\n".join(_runner_frame_surfaces(signal))


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


def test_capture_backing_never_exceeds_limit_plus_one_for_large_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_temporary_file = runner_module.tempfile.TemporaryFile
    observed_sizes: list[int] = []
    handles_created = 0

    class BoundedStorageProbe:
        def __init__(self, handle: object, *, tracked: bool) -> None:
            self._handle = handle
            self._tracked = tracked

        def __getattr__(self, name: str) -> object:
            return getattr(self._handle, name)

        def write(self, payload: bytes) -> int:
            written = self._handle.write(payload)  # type: ignore[attr-defined]
            if self._tracked:
                observed_sizes.append(os.fstat(self._handle.fileno()).st_size)  # type: ignore[attr-defined]
            return written  # type: ignore[no-any-return]

        def close(self) -> None:
            if self._tracked:
                observed_sizes.append(os.fstat(self._handle.fileno()).st_size)  # type: ignore[attr-defined]
            self._handle.close()  # type: ignore[attr-defined]

    def tracked_temporary_file(*args: object, **kwargs: object) -> BoundedStorageProbe:
        nonlocal handles_created
        handles_created += 1
        return BoundedStorageProbe(
            real_temporary_file(*args, **kwargs),
            tracked=handles_created <= 2,
        )

    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", tracked_temporary_file)
    source = "import os; chunk=b'x'*(1024*1024); [(os.write(1, chunk)) for _ in range(50)]"
    started = time.monotonic()

    with pytest.raises(SecAwareError) as exc_info:
        run_analyzer_process(
            _python_argv(source),
            cwd=tmp_path,
            timeout_seconds=5.0,
            max_stdout_bytes=64,
            max_stderr_bytes=64,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT
    assert observed_sizes
    assert max(observed_sizes) <= 65
    assert time.monotonic() - started < 3.0


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
    _assert_runner_frames_release_objects(signal, *handles)
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
    _assert_runner_frames_release_objects(signal, *processes, *handles)
    retained = "\n".join(_runner_frame_surfaces(signal))
    for hidden in (private_argument, source, str(tmp_path), sys.executable):
        assert hidden not in retained


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_hash_control_flow_clears_argv_and_completed_process_resources_from_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    private_argument = "private-hash-control-argument"
    source = "import sys; sys.stdout.buffer.write(b'private-hash-output')"
    signal = signal_type("private-hash-control-signal")
    processes: list[subprocess.Popen[bytes]] = []
    handles: list[object] = []
    real_popen = runner_module.subprocess.Popen
    real_temporary_file = runner_module.tempfile.TemporaryFile

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        return process  # type: ignore[return-value]

    def tracking_temporary_file(*args: object, **kwargs: object) -> object:
        handle = real_temporary_file(*args, **kwargs)
        handles.append(handle)
        return handle

    def interrupt_json_dumps(*args: object, **kwargs: object) -> str:
        del args, kwargs
        raise signal

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", tracking_temporary_file)
    monkeypatch.setattr(runner_module.json, "dumps", interrupt_json_dumps)

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
    _assert_runner_frames_release_objects(signal, *processes, *handles)
    retained = "\n".join(_runner_frame_surfaces(signal))
    for hidden in (
        private_argument,
        "private-hash-output",
        source,
        str(tmp_path),
        sys.executable,
    ):
        assert hidden not in retained


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", ["argv", "cwd", "executable", "environment"])
def test_input_preparation_helpers_release_sensitive_references_on_control_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
    boundary: str,
) -> None:
    sentinel = f"private-{boundary}-preparation"
    signal = signal_type(f"private-{boundary}-signal")
    sensitive: object

    class InterruptingArgv(Sequence[str]):
        def __len__(self) -> int:
            raise signal

        def __getitem__(self, index: int) -> str:
            del index
            return sentinel

        def __repr__(self) -> str:
            return sentinel

    if boundary == "argv":
        sensitive = InterruptingArgv()
        action = partial(runner_module._validate_analyzer_argv, sensitive)  # type: ignore[arg-type]
    elif boundary == "cwd":
        sensitive = tmp_path / sentinel

        def interrupt_fspath(value: object) -> str:
            del value
            raise signal

        monkeypatch.setattr(runner_module.os, "fspath", interrupt_fspath)
        action = partial(runner_module._validate_cwd, sensitive)  # type: ignore[arg-type]
    elif boundary == "executable":
        sensitive = sentinel

        def interrupt_which(value: str) -> str:
            del value
            raise signal

        monkeypatch.setattr(runner_module.shutil, "which", interrupt_which)
        action = partial(runner_module._resolve_analyzer_executable, sensitive)  # type: ignore[arg-type]
    else:

        class InterruptingEnvironment(dict[str, str]):
            def get(self, key: str, default: str | None = None) -> str | None:
                del key, default
                raise signal

        environment = InterruptingEnvironment({"PRIVATE_ENVIRONMENT": sentinel})
        sensitive = environment
        monkeypatch.setattr(runner_module.os, "name", "nt")
        monkeypatch.setattr(runner_module.os, "environ", environment)
        action = partial(runner_module._minimal_environment, tmp_path, tmp_path)

    with pytest.raises(signal_type) as exc_info:
        action()

    assert exc_info.value is signal
    _assert_runner_frames_release_objects(signal, sensitive)
    assert sentinel not in "\n".join(_runner_frame_surfaces(signal))


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_snapshot_control_flow_clears_raw_output_and_stdio_references(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    private_output = b"private-snapshot-control-output"
    signal = signal_type("private-snapshot-control-signal")
    stdout_file = tempfile.TemporaryFile(mode="w+b")
    stderr_file = tempfile.TemporaryFile(mode="w+b")
    stdout_file.write(private_output)
    stdout_file.flush()
    sizes = iter([len(private_output), 0])

    def interrupt_after_read(handle: object) -> int:
        del handle
        try:
            return next(sizes)
        except StopIteration:
            raise signal from None

    monkeypatch.setattr(runner_module, "_stream_size", interrupt_after_read)
    try:
        with pytest.raises(signal_type) as exc_info:
            runner_module._snapshot_stdout(
                stdout_file,
                stderr_file,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
    finally:
        stdout_file.close()
        stderr_file.close()

    assert exc_info.value is signal
    _assert_runner_frames_release_objects(signal, stdout_file, stderr_file)
    assert private_output.decode("ascii") not in "\n".join(_runner_frame_surfaces(signal))


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_cleanup_control_flow_releases_nested_stdio_arguments_and_closes_both_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    signal = signal_type("private-cleanup-control-signal")
    private_argument = "private-cleanup-control-argument"
    real_temporary_file = runner_module.tempfile.TemporaryFile
    handles: list[object] = []

    class ControlCloseFile:
        def __init__(self, handle: object, *, interrupt: bool) -> None:
            self._handle = handle
            self._interrupt = interrupt
            self.closed = False

        def __getattr__(self, name: str) -> object:
            return getattr(self._handle, name)

        def close(self) -> None:
            self.closed = True
            self._handle.close()  # type: ignore[attr-defined]
            if self._interrupt:
                raise signal

    def control_temporary_file(*args: object, **kwargs: object) -> ControlCloseFile:
        handle = ControlCloseFile(
            real_temporary_file(*args, **kwargs),
            interrupt=not handles,
        )
        handles.append(handle)
        return handle

    monkeypatch.setattr(runner_module.tempfile, "TemporaryFile", control_temporary_file)

    with pytest.raises(signal_type) as exc_info:
        run_analyzer_process(
            _python_argv("pass", private_argument),
            cwd=tmp_path,
            timeout_seconds=2.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert exc_info.value is signal
    assert len(handles) == 2
    assert all(handle.closed for handle in handles)  # type: ignore[attr-defined]
    _assert_runner_frames_release_objects(signal, *handles)
    assert private_argument not in "\n".join(_runner_frame_surfaces(signal))


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

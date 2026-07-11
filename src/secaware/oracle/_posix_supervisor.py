from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


_MAX_CONFIG_BYTES = 1024 * 1024


def _write_result(descriptor: int, payload: bytes) -> None:
    if descriptor < 0 or len(payload) > 32:
        return
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            return
        offset += written


def _children() -> tuple[int, ...]:
    raw = Path(f"/proc/self/task/{os.getpid()}/children").read_text(encoding="ascii").strip()
    return tuple(int(value) for value in raw.split()) if raw else ()


def _cleanup() -> bool:
    for _ in range(1000):
        children = _children()
        if not children:
            try:
                while True:
                    os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            while True:
                waited, _ = os.waitpid(-1, os.WNOHANG)
                if waited == 0:
                    break
        except ChildProcessError:
            return True
        time.sleep(0.001)
    return False


def main() -> None:
    result_fd = -1
    try:
        if sys.platform != "linux" or len(sys.argv) != 8:
            os._exit(125)
        (
            config_fd,
            executable_fd,
            cwd_fd,
            cancel_fd,
            script_fd,
            result_fd,
            tracking_fd,
        ) = map(int, sys.argv[1:])
        os.set_inheritable(result_fd, False)
        os.set_inheritable(tracking_fd, True)
        if not Path(f"/proc/self/task/{os.getpid()}/children").is_file():
            os._exit(125)
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            os._exit(125)
        os.lseek(config_fd, 0, os.SEEK_SET)
        payload = os.read(config_fd, _MAX_CONFIG_BYTES + 1)
        if len(payload) > _MAX_CONFIG_BYTES:
            os._exit(125)
        config = json.loads(payload.decode("utf-8"))
        analyzer_argv = config["argv"]
        environment = config["environment"]
        exec_argv0 = config.get("exec_argv0", "")
        if (
            not isinstance(analyzer_argv, list)
            or not analyzer_argv
            or not all(type(value) is str for value in analyzer_argv)
            or not isinstance(environment, dict)
            or type(exec_argv0) is not str
            or not all(
                type(key) is str and type(value) is str for key, value in environment.items()
            )
        ):
            os._exit(125)
        status_read_fd, status_write_fd = os.pipe2(os.O_CLOEXEC)
        analyzer_pid = os.fork()
        if analyzer_pid == 0:
            try:
                os.close(status_read_fd)
                os.setsid()
                os.fchdir(cwd_fd)
                devnull = os.open(os.devnull, os.O_RDONLY)
                os.dup2(devnull, 0)
                os.set_inheritable(executable_fd, True)
                launch_argv = analyzer_argv
                if script_fd >= 0:
                    os.set_inheritable(script_fd, True)
                    launch_argv = [
                        exec_argv0,
                        f"/proc/self/fd/{script_fd}",
                        *analyzer_argv[1:],
                    ]
                os.execve(
                    f"/proc/self/fd/{executable_fd}",
                    launch_argv,
                    environment,
                )
            except BaseException:
                try:
                    os.write(status_write_fd, b"F")
                except BaseException:
                    pass
                os._exit(126)
        os.close(status_write_fd)
        launch_status = os.read(status_read_fd, 2)
        os.close(status_read_fd)
        if launch_status:
            _cleanup()
            _write_result(result_fd, b"I")
            os._exit(1)
        cancelled = False
        status: int | None = None
        while status is None:
            ready, _, _ = select.select([cancel_fd], [], [], 0.01)
            if ready:
                cancelled = True
                break
            waited, candidate = os.waitpid(analyzer_pid, os.WNOHANG)
            if waited == analyzer_pid:
                status = candidate
        if cancelled:
            try:
                os.kill(analyzer_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if not _cleanup():
            _write_result(result_fd, b"I")
            os._exit(125)
        if cancelled:
            _write_result(result_fd, b"I")
            os._exit(124)
        if status is None:
            os._exit(125)
        if os.WIFEXITED(status):
            analyzer_returncode = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            analyzer_returncode = -os.WTERMSIG(status)
        else:
            _write_result(result_fd, b"I")
            os._exit(125)
        _write_result(result_fd, f"R:{analyzer_returncode}".encode("ascii"))
        os._exit(0)
    except BaseException:
        _write_result(result_fd, b"I")
        os._exit(125)


if __name__ == "__main__":
    main()

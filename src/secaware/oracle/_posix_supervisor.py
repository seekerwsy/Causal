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


def _children() -> tuple[int, ...]:
    raw = Path(f"/proc/self/task/{os.getpid()}/children").read_text(
        encoding="ascii"
    ).strip()
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
    try:
        if sys.platform != "linux" or len(sys.argv) != 5:
            os._exit(125)
        config_fd, executable_fd, cwd_fd, cancel_fd = map(int, sys.argv[1:])
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
        if (
            not isinstance(analyzer_argv, list)
            or not analyzer_argv
            or not all(type(value) is str for value in analyzer_argv)
            or not isinstance(environment, dict)
            or not all(type(key) is str and type(value) is str for key, value in environment.items())
        ):
            os._exit(125)
        analyzer_pid = os.fork()
        if analyzer_pid == 0:
            try:
                os.setsid()
                os.fchdir(cwd_fd)
                devnull = os.open(os.devnull, os.O_RDONLY)
                os.dup2(devnull, 0)
                os.set_inheritable(executable_fd, True)
                os.execve(
                    f"/proc/self/fd/{executable_fd}",
                    analyzer_argv,
                    environment,
                )
            except BaseException:
                os._exit(126)
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
            os._exit(125)
        if cancelled:
            os._exit(124)
        if status is None:
            os._exit(125)
        if os.WIFEXITED(status):
            os._exit(os.WEXITSTATUS(status))
        if os.WIFSIGNALED(status):
            os.kill(os.getpid(), os.WTERMSIG(status))
        os._exit(125)
    except BaseException:
        os._exit(125)


if __name__ == "__main__":
    main()

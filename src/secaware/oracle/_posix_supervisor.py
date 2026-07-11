from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


_MAX_CONFIG_BYTES = 1024 * 1024
_CLONE_NEWNS = 0x00020000
_CLONE_NEWUSER = 0x10000000
_CLONE_NEWPID = 0x20000000
_MS_NOSUID = 0x2
_MS_NODEV = 0x4
_MS_NOEXEC = 0x8
_MS_REC = 0x4000
_MS_PRIVATE = 0x40000
_PR_SET_PDEATHSIG = 1


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


def _starttime(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split()
    if closing < 1 or len(fields) <= 19:
        raise OSError(errno.ESRCH, "process identity is unavailable")
    return int(fields[19])


def _arm_pdeathsig(libc: object) -> None:
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:  # type: ignore[attr-defined]
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG failed")


def _set_pdeathsig(libc: object, parent_pid: int, parent_starttime: int) -> None:
    _arm_pdeathsig(libc)
    if os.getppid() != parent_pid or _starttime(parent_pid) != parent_starttime:
        raise OSError(errno.ESRCH, "parent identity changed")


def _write_mapping(path: str, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        payload = value.encode("ascii")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "namespace mapping write failed")
            offset += written
    finally:
        os.close(descriptor)


def _enter_user_and_pid_namespaces(libc: object) -> None:
    host_uid = os.getuid()
    host_gid = os.getgid()
    if libc.unshare(_CLONE_NEWUSER) != 0:  # type: ignore[attr-defined]
        raise OSError(ctypes.get_errno(), "CLONE_NEWUSER failed")
    try:
        _write_mapping("/proc/self/setgroups", "deny\n")
    except FileNotFoundError:
        pass
    _write_mapping("/proc/self/uid_map", f"0 {host_uid} 1\n")
    _write_mapping("/proc/self/gid_map", f"0 {host_gid} 1\n")
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    if libc.unshare(_CLONE_NEWPID) != 0:  # type: ignore[attr-defined]
        raise OSError(ctypes.get_errno(), "CLONE_NEWPID failed")


def _mount_private_proc(libc: object) -> None:
    if libc.unshare(_CLONE_NEWNS) != 0:  # type: ignore[attr-defined]
        raise OSError(ctypes.get_errno(), "CLONE_NEWNS failed")
    if libc.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None) != 0:  # type: ignore[attr-defined]
        raise OSError(ctypes.get_errno(), "private mount propagation failed")
    if (
        libc.mount(  # type: ignore[attr-defined]
            b"proc",
            b"/proc",
            b"proc",
            _MS_NOSUID | _MS_NODEV | _MS_NOEXEC,
            None,
        )
        != 0
    ):
        raise OSError(ctypes.get_errno(), "private proc mount failed")


def _parent_pipe_is_open(descriptor: int) -> bool:
    ready, _, _ = select.select([descriptor], [], [], 0)
    if not ready:
        return True
    return os.read(descriptor, 1) != b""


def _namespace_init(
    *,
    libc: object,
    outer_pid: int,
    outer_starttime: int,
    parent_watch_read_fd: int,
    cancel_fd: int,
    result_fd: int,
    executable_fd: int,
    cwd_fd: int,
    script_fd: int,
    analyzer_argv: list[str],
    environment: dict[str, str],
    exec_argv0: str,
) -> None:
    try:
        os.close(cancel_fd)
        _arm_pdeathsig(libc)
        if not _parent_pipe_is_open(parent_watch_read_fd):
            raise OSError(errno.ESRCH, "outer supervisor exited")
        if _starttime(outer_pid) != outer_starttime:
            raise OSError(errno.ESRCH, "outer supervisor identity changed")
        _mount_private_proc(libc)
        status_read_fd, status_write_fd = os.pipe2(os.O_CLOEXEC)
        analyzer_pid = os.fork()
        if analyzer_pid == 0:
            try:
                os.close(status_read_fd)
                init_pid = os.getppid()
                init_starttime = _starttime(init_pid)
                _set_pdeathsig(libc, init_pid, init_starttime)
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
                os.execve(f"/proc/self/fd/{executable_fd}", launch_argv, environment)
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
            _write_result(result_fd, b"I")
            os._exit(1)
        _, status = os.waitpid(analyzer_pid, 0)
        if os.WIFEXITED(status):
            analyzer_returncode = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            analyzer_returncode = -os.WTERMSIG(status)
        else:
            _write_result(result_fd, b"I")
            os._exit(1)
        _write_result(result_fd, f"R:{analyzer_returncode}".encode("ascii"))
        os._exit(0)
    except BaseException:
        _write_result(result_fd, b"I")
        os._exit(1)


def main() -> None:
    result_fd = -1
    try:
        if sys.platform != "linux" or len(sys.argv) != 7:
            os._exit(125)
        config_fd, executable_fd, cwd_fd, cancel_fd, script_fd, result_fd = map(int, sys.argv[1:])
        libc = ctypes.CDLL(None, use_errno=True)
        runner_pid = os.getppid()
        runner_starttime = _starttime(runner_pid)
        _set_pdeathsig(libc, runner_pid, runner_starttime)
        os.set_inheritable(result_fd, False)
        os.lseek(config_fd, 0, os.SEEK_SET)
        payload = os.read(config_fd, _MAX_CONFIG_BYTES + 1)
        os.close(config_fd)
        if len(payload) > _MAX_CONFIG_BYTES:
            raise OSError(errno.E2BIG, "configuration is too large")
        config = json.loads(payload.decode("utf-8"))
        analyzer_argv = config["argv"]
        environment = config["environment"]
        exec_argv0 = config.get("exec_argv0", "")
        force_namespace_unavailable = config.get("force_namespace_unavailable", False)
        if (
            not isinstance(analyzer_argv, list)
            or not analyzer_argv
            or not all(type(value) is str for value in analyzer_argv)
            or not isinstance(environment, dict)
            or type(exec_argv0) is not str
            or type(force_namespace_unavailable) is not bool
            or not all(
                type(key) is str and type(value) is str for key, value in environment.items()
            )
        ):
            raise OSError(errno.EINVAL, "invalid configuration")
        if force_namespace_unavailable:
            raise OSError(errno.EPERM, "namespace capability unavailable")
        _enter_user_and_pid_namespaces(libc)
        parent_watch_read_fd, parent_watch_write_fd = os.pipe2(os.O_CLOEXEC)
        outer_pid = os.getpid()
        outer_starttime = _starttime(outer_pid)
        init_pid = os.fork()
        if init_pid == 0:
            os.close(parent_watch_write_fd)
            _namespace_init(
                libc=libc,
                outer_pid=outer_pid,
                outer_starttime=outer_starttime,
                parent_watch_read_fd=parent_watch_read_fd,
                cancel_fd=cancel_fd,
                result_fd=result_fd,
                executable_fd=executable_fd,
                cwd_fd=cwd_fd,
                script_fd=script_fd,
                analyzer_argv=analyzer_argv,
                environment=environment,
                exec_argv0=exec_argv0,
            )
        os.close(parent_watch_read_fd)
        while True:
            ready, _, _ = select.select([cancel_fd], [], [], 0.01)
            if ready:
                try:
                    os.kill(init_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(init_pid, 0)
                _write_result(result_fd, b"I")
                os._exit(124)
            waited, status = os.waitpid(init_pid, os.WNOHANG)
            if waited == init_pid:
                if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
                    os._exit(0)
                _write_result(result_fd, b"I")
                os._exit(1)
            time.sleep(0.001)
    except BaseException:
        _write_result(result_fd, b"I")
        os._exit(125)


if __name__ == "__main__":
    main()

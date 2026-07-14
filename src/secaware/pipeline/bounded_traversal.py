"""Handle-bound, bounded, no-follow traversal for untrusted run trees."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Iterator


class BoundedTraversalError(ValueError):
    """Fail closed without embedding an untrusted path in the exception."""

    def __init__(self, *, limit_exceeded: bool) -> None:
        self.limit_exceeded = limit_exceeded
        super().__init__("bounded directory traversal failed validation")


@dataclass(frozen=True, slots=True)
class BoundedTreeEntry:
    relative_path: str
    name: str
    is_file: bool
    is_dir: bool


@dataclass(slots=True)
class _TraversalState:
    max_entries: int
    max_depth: int
    max_relative_path_chars: int
    max_name_chars: int
    count: int = 0

    def check(self, name: str, relative: str, depth: int) -> None:
        self.count += 1
        if (
            self.count > self.max_entries
            or depth > self.max_depth
            or len(name) > self.max_name_chars
            or len(relative) > self.max_relative_path_chars
            or name in {"", ".", ".."}
        ):
            raise BoundedTraversalError(limit_exceeded=True)


def _posix_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))


def _posix_path_identity(
    name: str,
    *,
    parent_fd: int,
) -> tuple[int, int, int]:
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    return _posix_identity(metadata)


def _posix_file_flags() -> int:
    required = ("O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, item) for item in required):
        raise BoundedTraversalError(limit_exceeded=False)
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)


def _posix_directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, item) for item in required):
        raise BoundedTraversalError(limit_exceeded=False)
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _walk_posix_directory(
    directory_fd: int,
    *,
    relative_parent: str,
    parent_depth: int,
    state: _TraversalState,
    expected_identity: tuple[int, int, int],
    parent_fd: int | None,
    name_in_parent: str | None,
) -> Iterator[BoundedTreeEntry]:
    if _posix_identity(os.fstat(directory_fd)) != expected_identity:
        raise BoundedTraversalError(limit_exceeded=False)
    with os.scandir(directory_fd) as iterator:
        for candidate in iterator:
            name = candidate.name
            depth = parent_depth + 1
            relative = name if not relative_parent else f"{relative_parent}/{name}"
            state.check(name, relative, depth)
            entry_metadata = candidate.stat(follow_symlinks=False)
            entry_identity = _posix_identity(entry_metadata)
            if stat.S_ISDIR(entry_metadata.st_mode):
                child_fd = -1
                try:
                    child_fd = os.open(
                        name,
                        _posix_directory_flags(),
                        dir_fd=directory_fd,
                    )
                    child_metadata = os.fstat(child_fd)
                    child_identity = _posix_identity(child_metadata)
                    if child_identity != entry_identity or not stat.S_ISDIR(child_metadata.st_mode):
                        raise BoundedTraversalError(limit_exceeded=False)
                    yield BoundedTreeEntry(relative, name, False, True)
                    yield from _walk_posix_directory(
                        child_fd,
                        relative_parent=relative,
                        parent_depth=depth,
                        state=state,
                        expected_identity=child_identity,
                        parent_fd=directory_fd,
                        name_in_parent=name,
                    )
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
            elif stat.S_ISREG(entry_metadata.st_mode):
                file_fd = -1
                try:
                    file_fd = os.open(
                        name,
                        _posix_file_flags(),
                        dir_fd=directory_fd,
                    )
                    file_metadata = os.fstat(file_fd)
                    file_identity = _posix_identity(file_metadata)
                    if (
                        file_identity != entry_identity
                        or not stat.S_ISREG(file_metadata.st_mode)
                        or file_metadata.st_nlink != 1
                    ):
                        raise BoundedTraversalError(limit_exceeded=False)
                    yield BoundedTreeEntry(relative, name, True, False)
                    if (
                        _posix_identity(os.fstat(file_fd)) != file_identity
                        or _posix_path_identity(name, parent_fd=directory_fd) != file_identity
                    ):
                        raise BoundedTraversalError(limit_exceeded=False)
                finally:
                    if file_fd >= 0:
                        os.close(file_fd)
            else:
                raise BoundedTraversalError(limit_exceeded=False)
    if _posix_identity(os.fstat(directory_fd)) != expected_identity:
        raise BoundedTraversalError(limit_exceeded=False)
    if parent_fd is not None and name_in_parent is not None:
        if _posix_path_identity(name_in_parent, parent_fd=parent_fd) != expected_identity:
            raise BoundedTraversalError(limit_exceeded=False)


def _walk_posix(root: Path, state: _TraversalState) -> Iterator[BoundedTreeEntry]:
    root_fd = -1
    try:
        root_fd = os.open(root, _posix_directory_flags())
        root_metadata = os.fstat(root_fd)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise BoundedTraversalError(limit_exceeded=False)
        root_identity = _posix_identity(root_metadata)
        yield from _walk_posix_directory(
            root_fd,
            relative_parent="",
            parent_depth=0,
            state=state,
            expected_identity=root_identity,
            parent_fd=None,
            name_in_parent=None,
        )
        current_root = root.lstat()
        if _posix_identity(current_root) != root_identity:
            raise BoundedTraversalError(limit_exceeded=False)
    finally:
        if root_fd >= 0:
            os.close(root_fd)


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    )
    _KERNEL32.GetFileInformationByHandle.restype = wintypes.BOOL
    _KERNEL32.GetFileType.argtypes = (wintypes.HANDLE,)
    _KERNEL32.GetFileType.restype = wintypes.DWORD
    _KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _KERNEL32.CloseHandle.restype = wintypes.BOOL

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_TYPE_DISK = 0x0001


@dataclass(frozen=True, slots=True)
class _WindowsIdentity:
    volume_serial: int
    file_index_high: int
    file_index_low: int
    attributes: int
    number_of_links: int
    size_high: int
    size_low: int

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & _FILE_ATTRIBUTE_DIRECTORY)

    @property
    def is_reparse_point(self) -> bool:
        return bool(self.attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _windows_api_path(path: Path) -> str:
    value = os.path.abspath(os.fspath(path))
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_open(path: Path) -> int:
    handle = _KERNEL32.CreateFileW(
        _windows_api_path(path),
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE or handle is None:
        raise OSError(ctypes.get_last_error())
    return int(handle)


def _windows_close(handle: int) -> None:
    if not _KERNEL32.CloseHandle(handle):
        raise OSError(ctypes.get_last_error())


def _windows_identity(handle: int) -> _WindowsIdentity:
    if _KERNEL32.GetFileType(handle) != _FILE_TYPE_DISK:
        raise BoundedTraversalError(limit_exceeded=False)
    information = _ByHandleFileInformation()
    if not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise OSError(ctypes.get_last_error())
    return _WindowsIdentity(
        volume_serial=int(information.dwVolumeSerialNumber),
        file_index_high=int(information.nFileIndexHigh),
        file_index_low=int(information.nFileIndexLow),
        attributes=int(information.dwFileAttributes),
        number_of_links=int(information.nNumberOfLinks),
        size_high=int(information.nFileSizeHigh),
        size_low=int(information.nFileSizeLow),
    )


def _windows_verify_path(path: Path, expected: _WindowsIdentity) -> None:
    probe = -1
    try:
        probe = _windows_open(path)
        if _windows_identity(probe) != expected:
            raise BoundedTraversalError(limit_exceeded=False)
    finally:
        if probe >= 0:
            _windows_close(probe)


def _walk_windows_directory(
    path: Path,
    handle: int,
    expected: _WindowsIdentity,
    *,
    relative_parent: str,
    parent_depth: int,
    state: _TraversalState,
) -> Iterator[BoundedTreeEntry]:
    if expected.is_reparse_point or not expected.is_directory:
        raise BoundedTraversalError(limit_exceeded=False)
    if _windows_identity(handle) != expected:
        raise BoundedTraversalError(limit_exceeded=False)
    _windows_verify_path(path, expected)
    with os.scandir(path) as iterator:
        for candidate in iterator:
            name = candidate.name
            depth = parent_depth + 1
            relative = name if not relative_parent else f"{relative_parent}/{name}"
            state.check(name, relative, depth)
            candidate_path = path / name
            child_handle = -1
            try:
                child_handle = _windows_open(candidate_path)
                child_identity = _windows_identity(child_handle)
                if child_identity.is_reparse_point:
                    raise BoundedTraversalError(limit_exceeded=False)
                if child_identity.is_directory:
                    yield BoundedTreeEntry(relative, name, False, True)
                    yield from _walk_windows_directory(
                        candidate_path,
                        child_handle,
                        child_identity,
                        relative_parent=relative,
                        parent_depth=depth,
                        state=state,
                    )
                else:
                    if child_identity.number_of_links != 1:
                        raise BoundedTraversalError(limit_exceeded=False)
                    yield BoundedTreeEntry(relative, name, True, False)
                    if _windows_identity(child_handle) != child_identity:
                        raise BoundedTraversalError(limit_exceeded=False)
                    _windows_verify_path(candidate_path, child_identity)
            finally:
                if child_handle >= 0:
                    _windows_close(child_handle)
    if _windows_identity(handle) != expected:
        raise BoundedTraversalError(limit_exceeded=False)
    _windows_verify_path(path, expected)


def _walk_windows(root: Path, state: _TraversalState) -> Iterator[BoundedTreeEntry]:
    root_handle = -1
    try:
        root_handle = _windows_open(root)
        root_identity = _windows_identity(root_handle)
        yield from _walk_windows_directory(
            root,
            root_handle,
            root_identity,
            relative_parent="",
            parent_depth=0,
            state=state,
        )
    finally:
        if root_handle >= 0:
            _windows_close(root_handle)


def iter_bounded_tree(
    root: Path,
    *,
    max_entries: int,
    max_depth: int,
    max_relative_path_chars: int,
    max_name_chars: int,
) -> Iterator[BoundedTreeEntry]:
    """Traverse by held identities; never follow a path after validating it."""

    if (
        not isinstance(root, Path)
        or type(max_entries) is not int
        or type(max_depth) is not int
        or type(max_relative_path_chars) is not int
        or type(max_name_chars) is not int
        or not 1 <= max_entries <= 1_000_000
        or not 1 <= max_depth <= 256
        or not 1 <= max_relative_path_chars <= 32_768
        or not 1 <= max_name_chars <= 4_096
    ):
        raise BoundedTraversalError(limit_exceeded=True)
    root = Path(os.path.abspath(os.fspath(root)))
    state = _TraversalState(
        max_entries=max_entries,
        max_depth=max_depth,
        max_relative_path_chars=max_relative_path_chars,
        max_name_chars=max_name_chars,
    )
    try:
        if os.name == "nt":
            yield from _walk_windows(root, state)
        elif os.name == "posix":
            yield from _walk_posix(root, state)
        else:
            raise BoundedTraversalError(limit_exceeded=False)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except BoundedTraversalError:
        raise
    except Exception:
        raise BoundedTraversalError(limit_exceeded=False) from None


__all__ = [
    "BoundedTraversalError",
    "BoundedTreeEntry",
    "iter_bounded_tree",
]

from __future__ import annotations

import os
from pathlib import Path
import struct

import pytest

from secaware.pipeline.bounded_traversal import BoundedTraversalError, iter_bounded_tree


def _walk(root: Path):
    return iter_bounded_tree(
        root,
        max_entries=100,
        max_depth=8,
        max_relative_path_chars=1024,
        max_name_chars=255,
    )


def _directory_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation is unavailable: {error}")


def _windows_junction(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction test")
    import ctypes
    from ctypes import wintypes

    link.mkdir()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(link),
        0x40000000,
        0,
        None,
        3,
        0x00200000 | 0x02000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid or handle is None:
        link.rmdir()
        pytest.skip("junction handle creation is unavailable")
    created = False
    try:
        target_text = str(target.resolve())
        substitute = ("\\??\\" + target_text).encode("utf-16-le")
        printable = target_text.encode("utf-16-le")
        path_buffer = substitute + b"\x00\x00" + printable + b"\x00\x00"
        payload = (
            struct.pack(
                "<IHHHHHH",
                0xA0000003,
                8 + len(path_buffer),
                0,
                0,
                len(substitute),
                len(substitute) + 2,
                len(printable),
            )
            + path_buffer
        )
        native = ctypes.create_string_buffer(payload)
        returned = wintypes.DWORD()
        created = bool(
            kernel32.DeviceIoControl(
                handle,
                0x000900A4,
                native,
                len(payload),
                None,
                0,
                ctypes.byref(returned),
                None,
            )
        )
    finally:
        kernel32.CloseHandle(handle)
    if not created:
        link.rmdir()
        pytest.skip("junction creation is unavailable")


def test_normal_file_is_accepted_but_hardlink_is_rejected(tmp_path: Path) -> None:
    normal_root = tmp_path / "normal"
    normal_root.mkdir()
    (normal_root / "file.txt").write_text("safe", encoding="utf-8")
    assert [item.relative_path for item in _walk(normal_root)] == ["file.txt"]

    linked_root = tmp_path / "linked"
    linked_root.mkdir()
    source = linked_root / "source.txt"
    source.write_text("shared", encoding="utf-8")
    try:
        os.link(source, linked_root / "alias.txt")
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error}")
    with pytest.raises(BoundedTraversalError) as exc_info:
        list(_walk(linked_root))
    assert exc_info.value.limit_exceeded is False


def test_static_nested_directory_symlink_is_rejected_without_escape(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    _directory_symlink(nested / "redirect", outside)
    yielded: list[str] = []
    with pytest.raises(BoundedTraversalError) as exc_info:
        for item in _walk(root):
            yielded.append(item.relative_path)
    assert exc_info.value.limit_exceeded is False
    assert all("secret.txt" not in item for item in yielded)


def test_static_nested_windows_junction_is_rejected_without_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    junction = nested / "redirect"
    _windows_junction(junction, outside)
    yielded: list[str] = []
    try:
        with pytest.raises(BoundedTraversalError) as exc_info:
            for item in _walk(root):
                yielded.append(item.relative_path)
        assert exc_info.value.limit_exceeded is False
        assert all("secret.txt" not in item for item in yielded)
    finally:
        junction.rmdir()


def test_yield_then_replace_child_directory_never_yields_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    traversal = _walk(root)
    first = next(traversal)
    assert first.relative_path == "child"
    held = root / "held"
    replacement_succeeded = False
    try:
        os.replace(child, held)
        child.mkdir()
        (child / "escaped.txt").write_text("escape", encoding="utf-8")
        replacement_succeeded = True
    except OSError:
        pass
    yielded: list[str] = []
    failed_closed = False
    try:
        yielded = [item.relative_path for item in traversal]
    except BoundedTraversalError as error:
        failed_closed = not error.limit_exceeded
    finally:
        traversal.close()
    assert "child/escaped.txt" not in yielded
    assert failed_closed or not replacement_succeeded
    if not replacement_succeeded:
        os.replace(child, held)
        assert held.is_dir()


def test_yield_then_replace_child_with_directory_symlink_never_escapes(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    traversal = _walk(root)
    assert next(traversal).relative_path == "child"
    held = root / "held"
    replacement_succeeded = False
    try:
        os.replace(child, held)
        _directory_symlink(child, outside)
        replacement_succeeded = True
    except OSError:
        pass
    yielded: list[str] = []
    failed_closed = False
    try:
        yielded = [item.relative_path for item in traversal]
    except BoundedTraversalError as error:
        failed_closed = not error.limit_exceeded
    finally:
        traversal.close()
    assert all("secret.txt" not in item for item in yielded)
    assert failed_closed or not replacement_succeeded
    if not replacement_succeeded:
        os.replace(child, held)
        assert held.is_dir()


def test_yield_then_replace_root_never_yields_replacement_tree(tmp_path: Path) -> None:
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    traversal = _walk(root)
    assert next(traversal).relative_path == "child"
    held_root = tmp_path / "held-root"
    replacement_succeeded = False
    try:
        os.replace(root, held_root)
        (root / "child").mkdir(parents=True)
        (root / "child" / "escaped.txt").write_text("escape", encoding="utf-8")
        replacement_succeeded = True
    except OSError:
        pass
    yielded: list[str] = []
    failed_closed = False
    try:
        yielded = [item.relative_path for item in traversal]
    except BoundedTraversalError as error:
        failed_closed = not error.limit_exceeded
    finally:
        traversal.close()
    assert "child/escaped.txt" not in yielded
    assert failed_closed or not replacement_succeeded
    if not replacement_succeeded:
        os.replace(root, held_root)
        assert held_root.is_dir()


def test_early_close_releases_held_file_handle(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    source = root / "file.txt"
    source.write_text("safe", encoding="utf-8")
    traversal = _walk(root)
    assert next(traversal).relative_path == "file.txt"
    traversal.close()
    destination = root / "moved.txt"
    os.replace(source, destination)
    assert destination.read_text(encoding="utf-8") == "safe"


@pytest.mark.parametrize("signal_type", (MemoryError, KeyboardInterrupt, SystemExit))
def test_handle_bound_traversal_preserves_process_control_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "file.txt").write_text("safe", encoding="utf-8")

    def interrupt(_path: object):
        raise signal_type("private-handle-traversal-interrupt")

    monkeypatch.setattr(os, "scandir", interrupt)
    with pytest.raises(signal_type):
        list(_walk(root))

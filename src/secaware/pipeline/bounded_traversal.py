"""Bounded, no-follow traversal for untrusted run-directory trees."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Iterator


class BoundedTraversalError(ValueError):
    """Fail-closed traversal error without embedding an untrusted path."""

    def __init__(self, *, limit_exceeded: bool) -> None:
        self.limit_exceeded = limit_exceeded
        super().__init__("bounded directory traversal failed validation")


@dataclass(frozen=True, slots=True)
class BoundedTreeEntry:
    relative_path: str
    name: str
    is_file: bool
    is_dir: bool


def iter_bounded_tree(
    root: Path,
    *,
    max_entries: int,
    max_depth: int,
    max_relative_path_chars: int,
    max_name_chars: int,
) -> Iterator[BoundedTreeEntry]:
    """Yield only regular files/directories while enforcing all bounds."""

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
    try:
        root_metadata = root.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise BoundedTraversalError(limit_exceeded=False)
        stack: list[tuple[Path, str, int]] = [(root, "", 0)]
        count = 0
        while stack:
            directory, relative_parent, parent_depth = stack.pop()
            with os.scandir(directory) as iterator:
                for candidate in iterator:
                    count += 1
                    depth = parent_depth + 1
                    name = candidate.name
                    relative = name if not relative_parent else f"{relative_parent}/{name}"
                    if (
                        count > max_entries
                        or depth > max_depth
                        or len(name) > max_name_chars
                        or len(relative) > max_relative_path_chars
                    ):
                        raise BoundedTraversalError(limit_exceeded=True)
                    metadata = candidate.stat(follow_symlinks=False)
                    is_file = stat.S_ISREG(metadata.st_mode)
                    is_dir = stat.S_ISDIR(metadata.st_mode)
                    if (
                        name in {"", ".", ".."}
                        or not (is_file or is_dir)
                        # Windows may report zero when link-count metadata is
                        # unavailable; any known multi-link file is rejected.
                        or (is_file and metadata.st_nlink not in {0, 1})
                    ):
                        raise BoundedTraversalError(limit_exceeded=False)
                    yield BoundedTreeEntry(
                        relative_path=relative,
                        name=name,
                        is_file=is_file,
                        is_dir=is_dir,
                    )
                    if is_dir:
                        stack.append((Path(candidate.path), relative, depth))
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

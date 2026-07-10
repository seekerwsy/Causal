import hashlib
import json
import math
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON does not support non-finite numbers")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            normalized[key] = _normalize_json(nested_value)
        return normalized
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    raise TypeError(f"value of type {type(value).__name__} is not JSON-compatible")


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        _normalize_json(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_path(path: str | Path) -> str:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("symbolic links are not supported in stage inputs")
    if target.is_file():
        return sha256_file(target)
    if not target.is_dir():
        raise FileNotFoundError("stage input path does not exist")

    resolved_root = target.resolve()
    files: list[dict[str, str]] = []
    children = sorted(target.rglob("*"), key=lambda item: item.relative_to(target).as_posix())
    for child in children:
        if child.is_symlink():
            raise ValueError("symbolic links are not supported in stage inputs")
        try:
            child.resolve().relative_to(resolved_root)
        except (OSError, ValueError):
            raise ValueError("stage input directory entry escapes its root") from None
        if child.is_dir():
            continue
        if not child.is_file():
            raise ValueError("stage input directories may contain only files and directories")
        files.append(
            {
                "path": child.relative_to(target).as_posix(),
                "sha256": sha256_file(child),
            }
        )
    return canonical_sha256({"type": "directory", "files": files})


def _atomic_write_text(path: str | Path, content: str) -> None:
    target = Path(path)
    temp_path: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except BaseException:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise

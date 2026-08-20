"""Strict, content-addressed closure manifests for exploratory artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

_SCHEMA_VERSION = "1.0"
_MANIFEST_NAME = "artifact-manifest.json"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic_exclusive(path: Path, value: object) -> None:
    """Publish canonical JSON atomically without replacing an existing file."""

    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = _canonical(value) + b"\n"
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        # A hard-link publication is atomic and, unlike os.replace(), cannot
        # clobber a target created after the initial existence check.
        os.link(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _resolved_manifest(root: Path, manifest_path: Path | None) -> tuple[Path, Path]:
    resolved_root = root.resolve()
    resolved_manifest = (
        (resolved_root / _MANIFEST_NAME) if manifest_path is None else manifest_path.resolve()
    )
    try:
        relative = resolved_manifest.relative_to(resolved_root)
    except ValueError:
        raise ValueError("closure manifest escaped root") from None
    if relative.as_posix() != _MANIFEST_NAME:
        raise ValueError("closure manifest must be the exact root artifact-manifest.json")
    return resolved_root, resolved_manifest


def build_closed_manifest(
    root: Path,
    *,
    manifest_path: Path | None = None,
) -> dict[str, object]:
    """Build a manifest for every file except the exact root manifest itself.

    Nested files named ``artifact-manifest.json`` are ordinary covered artifacts.
    """

    resolved_root, resolved_manifest = _resolved_manifest(root, manifest_path)
    if not resolved_root.is_dir():
        raise FileNotFoundError(resolved_root)
    files: list[tuple[str, Path]] = []
    for candidate in resolved_root.rglob("*"):
        if not candidate.is_file() or candidate.resolve() == resolved_manifest:
            continue
        resolved = candidate.resolve()
        try:
            resolved.relative_to(resolved_root)
        except ValueError:
            raise ValueError("closure manifest input escaped root") from None
        files.append((candidate.relative_to(resolved_root).as_posix(), candidate))
    return {
        "schema_version": _SCHEMA_VERSION,
        "files": [
            {"path": relative, "sha256": _sha256_file(path)}
            for relative, path in sorted(files, key=lambda item: item[0])
        ],
    }


def verify_closed_manifest(
    manifest_path: Path,
    *,
    label: str = "artifact",
) -> dict[str, object]:
    """Verify schema, paths, digests, and exact file-set closure."""

    manifest_path = manifest_path.resolve()
    root = manifest_path.parent.resolve()
    try:
        manifest: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} manifest failed validation") from error
    if (
        type(manifest) is not dict
        or set(manifest) != {"schema_version", "files"}
        or manifest.get("schema_version") != _SCHEMA_VERSION
        or type(manifest.get("files")) is not list
    ):
        raise ValueError(f"{label} manifest failed validation")

    expected: set[str] = set()
    for item in manifest["files"]:
        if type(item) is not dict or set(item) != {"path", "sha256"}:
            raise ValueError(f"{label} manifest failed validation")
        raw_path = item.get("path")
        digest = item.get("sha256")
        if type(raw_path) is not str or type(digest) is not str:
            raise ValueError(f"{label} manifest failed validation")
        relative = Path(raw_path)
        normalized = relative.as_posix()
        resolved = (root / relative).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            raise ValueError(f"{label} manifest escaped root") from None
        if (
            not raw_path
            or relative.is_absolute()
            or normalized != raw_path
            or any(part in {".", ".."} for part in relative.parts)
            or normalized in expected
            or resolved == manifest_path
            or not resolved.is_file()
            or _sha256_file(resolved) != digest
        ):
            raise ValueError(f"{label} manifest failed validation")
        expected.add(normalized)

    actual = {
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and item.resolve() != manifest_path
    }
    if actual != expected:
        raise ValueError(f"{label} manifest closure failed validation")
    return manifest


def write_closed_manifest_atomic(
    root: Path,
    *,
    manifest_path: Path | None = None,
    label: str = "artifact",
) -> dict[str, object]:
    """Exclusively publish a closed root manifest with an atomic hard link."""

    root, target = _resolved_manifest(root, manifest_path)
    if target.exists():
        raise FileExistsError(target)
    payload = build_closed_manifest(root, manifest_path=target)
    write_json_atomic_exclusive(target, payload)
    return verify_closed_manifest(target, label=label)

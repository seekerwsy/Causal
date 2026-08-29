"""Exact-byte artifact bundles for freeze and analysis outputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from prompt_mechanism_study.records import canonical_json


MANIFEST = "manifest.json"


def write_bundle(root: Path, artifacts: Mapping[str, Any]) -> Path:
    root = root.resolve()
    if root.exists():
        raise FileExistsError(root)
    root.mkdir(parents=True)
    hashes: dict[str, str] = {}
    for name, value in sorted(artifacts.items()):
        _valid_name(name)
        payload = (canonical_json(value) + "\n").encode("utf-8")
        (root / name).write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    manifest = {"schema_version": "2.0", "files": hashes}
    (root / MANIFEST).write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    return root


def verify_bundle(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        raise ValueError("bundle manifest is missing")
    manifest_payload = manifest_path.read_bytes()
    manifest = json.loads(manifest_payload)
    if manifest_payload != (canonical_json(manifest) + "\n").encode("utf-8"):
        raise ValueError("bundle manifest is not canonical")
    if set(manifest) != {"schema_version", "files"} or manifest["schema_version"] != "2.0":
        raise ValueError("invalid bundle manifest")
    expected = manifest["files"]
    if not isinstance(expected, dict):
        raise ValueError("invalid bundle file map")
    for name, digest in expected.items():
        _valid_name(name)
        _digest(digest)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != MANIFEST
    }
    if actual != set(expected):
        raise ValueError("bundle file set is not exact")
    for name, digest in expected.items():
        payload = (root / name).read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"artifact digest mismatch: {name}")
        value = json.loads(payload)
        if payload != (canonical_json(value) + "\n").encode("utf-8"):
            raise ValueError(f"artifact is not canonical: {name}")
    return manifest


def bundle_digest(root: Path) -> str:
    verify_bundle(root)
    return hashlib.sha256((root.resolve() / MANIFEST).read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_json_exact(path: Path) -> Any:
    """Read JSON while rejecting duplicate keys and non-finite numbers."""

    try:
        return loads_exact_json(path.read_bytes())
    except OSError:
        raise ValueError(f"JSON input is unreadable: {path}") from None


def loads_exact_json(payload: str | bytes) -> Any:
    """Parse strict JSON with unique object keys and finite numeric values."""

    try:
        return json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ValueError("invalid strict JSON") from None


def json_object(payload: str | bytes) -> dict[str, Any]:
    value = loads_exact_json(payload)
    if not isinstance(value, dict):
        raise ValueError("JSON value is not an object")
    return value


def confined_path(root: Path, value: object) -> Path:
    """Resolve one stored path beneath an explicit artifact root."""

    if not isinstance(value, (str, Path)) or not str(value):
        raise ValueError("stored path is invalid")
    base = root.resolve()
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (base / path).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError("stored path escapes its root") from None
    return resolved


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise ValueError(f"file is unreadable: {path}") from None


def require_file_hash(path: Path, expected: object) -> str:
    digest = require_sha256(expected)
    if not path.is_file() or file_sha256(path) != digest:
        raise ValueError(f"frozen file drift: {path}")
    return digest


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def require_sha256(value: object, name: str = "value") -> str:
    if not is_sha256(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _valid_name(name: str) -> None:
    path = Path(name)
    if path.is_absolute() or len(path.parts) != 1 or path.name in {"", MANIFEST}:
        raise ValueError("artifact names must be simple relative filenames")


def _digest(value: object) -> None:
    require_sha256(value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


__all__ = [
    "MANIFEST",
    "bundle_digest",
    "confined_path",
    "file_sha256",
    "is_sha256",
    "json_object",
    "loads_exact_json",
    "read_json",
    "read_json_exact",
    "require_file_hash",
    "require_sha256",
    "verify_bundle",
    "write_bundle",
]

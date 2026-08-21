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


def _valid_name(name: str) -> None:
    path = Path(name)
    if path.is_absolute() or len(path.parts) != 1 or path.name in {"", MANIFEST}:
        raise ValueError("artifact names must be simple relative filenames")


def _digest(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("invalid artifact digest")


__all__ = ["MANIFEST", "bundle_digest", "read_json", "verify_bundle", "write_bundle"]

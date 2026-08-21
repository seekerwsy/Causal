"""Small exact-closure artifact store used by the reproducibility CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from secaware.records import canonical_json, canonical_value, content_hash


MANIFEST = "manifest.json"


def write_bundle(root: Path, artifacts: Mapping[str, Any]) -> Path:
    """Write a new immutable bundle and its exact file manifest."""

    root = root.resolve()
    if root.exists():
        raise FileExistsError(root)
    root.mkdir(parents=True)
    hashes: dict[str, str] = {}
    for name, value in sorted(artifacts.items()):
        _valid_name(name)
        payload = canonical_json(value) + "\n"
        (root / name).write_text(payload, encoding="utf-8", newline="\n")
        hashes[name] = content_hash(canonical_value(value))
    manifest = {"schema_version": "1.0", "files": hashes}
    (root / MANIFEST).write_text(
        canonical_json(manifest) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return root


def verify_bundle(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        raise ValueError("bundle manifest is missing")
    manifest = read_json(manifest_path)
    if set(manifest) != {"schema_version", "files"} or manifest["schema_version"] != "1.0":
        raise ValueError("invalid bundle manifest")
    expected = manifest["files"]
    if not isinstance(expected, dict):
        raise ValueError("invalid bundle file map")
    for name, digest in expected.items():
        _valid_name(name)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("invalid bundle digest")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != MANIFEST
    }
    if actual != set(expected):
        raise ValueError("bundle file set is not exact")
    for name, digest in expected.items():
        value = read_json(root / name)
        if content_hash(value) != digest:
            raise ValueError(f"artifact digest mismatch: {name}")
    return manifest


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _valid_name(name: str) -> None:
    path = Path(name)
    if path.is_absolute() or len(path.parts) != 1 or path.name in {"", MANIFEST}:
        raise ValueError("artifact names must be simple relative filenames")


__all__ = ["MANIFEST", "read_json", "verify_bundle", "write_bundle"]

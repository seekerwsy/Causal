from __future__ import annotations

from pathlib import Path

import pytest

from secaware.artifact_io import verify_bundle, write_bundle
from secaware.records import canonical_json, content_hash


@pytest.mark.reviewer
def test_canonical_content_hash_is_order_independent() -> None:
    assert content_hash({"b": 2, "a": 1}) == content_hash({"a": 1, "b": 2})
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


@pytest.mark.reviewer
def test_exact_bundle_round_trip(tmp_path: Path) -> None:
    root = write_bundle(tmp_path / "artifact", {"result.json": {"effect": 0.5}})
    manifest = verify_bundle(root)
    assert set(manifest["files"]) == {"result.json"}


@pytest.mark.reviewer
def test_bundle_rejects_content_tampering(tmp_path: Path) -> None:
    root = write_bundle(tmp_path / "artifact", {"result.json": {"effect": 0.5}})
    (root / "result.json").write_text('{"effect":0.9}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        verify_bundle(root)


@pytest.mark.reviewer
def test_bundle_rejects_unlisted_files(tmp_path: Path) -> None:
    root = write_bundle(tmp_path / "artifact", {"result.json": {"effect": 0.5}})
    (root / "extra.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        verify_bundle(root)

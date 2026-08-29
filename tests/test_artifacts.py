from __future__ import annotations

from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import verify_bundle, write_bundle
from prompt_mechanism_study.records import canonical_json, content_hash


@pytest.mark.extended
def test_canonical_content_identity_is_order_independent() -> None:
    assert content_hash({"b": 2, "a": 1}) == content_hash({"a": 1, "b": 2})
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


@pytest.mark.extended
def test_exact_bundle_round_trip(tmp_path: Path) -> None:
    root = write_bundle(tmp_path / "artifact", {"result.json": {"effect": 0.5}})
    assert set(verify_bundle(root)["files"]) == {"result.json"}


@pytest.mark.extended
def test_bundle_rejects_even_semantically_equivalent_byte_tampering(tmp_path: Path) -> None:
    root = write_bundle(tmp_path / "artifact", {"result.json": {"a": 1, "b": 2}})
    (root / "result.json").write_text('{ "b": 2, "a": 1 }\n', encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_bundle(root)
    second = write_bundle(tmp_path / "second", {"result.json": {"a": 1}})
    manifest = (second / "manifest.json").read_text(encoding="utf-8")
    (second / "manifest.json").write_text(" " + manifest, encoding="utf-8")
    with pytest.raises(ValueError, match="manifest is not canonical"):
        verify_bundle(second)


@pytest.mark.reviewer
@pytest.mark.extended
def test_bundle_rejects_unlisted_files(tmp_path: Path) -> None:
    root = write_bundle(tmp_path / "artifact", {"result.json": {"effect": 0.5}})
    (root / "extra.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="file set"):
        verify_bundle(root)

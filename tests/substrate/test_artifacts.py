from __future__ import annotations
from pathlib import Path
import pytest
from prompt_mechanism_study.artifact_io import verify_bundle, write_bundle


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

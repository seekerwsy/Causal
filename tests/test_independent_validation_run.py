from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from secaware.exploratory.independent_validation_run import _input_path


def test_text_input_digest_is_stable_across_lf_and_crlf(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(b"first: value\r\nsecond: value\r\n")
    expected = hashlib.sha256(b"first: value\nsecond: value\n").hexdigest()

    result = _input_path(
        tmp_path,
        {
            "path": "config.yaml",
            "sha256": expected,
            "digest_mode": "lf_normalized_text_v1",
        },
    )

    assert result == path.resolve()


def test_raw_input_digest_does_not_normalize_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_bytes(b"{}\r\n")
    lf_digest = hashlib.sha256(b"{}\n").hexdigest()

    with pytest.raises(ValueError, match="input digest failed validation"):
        _input_path(tmp_path, {"path": "manifest.json", "sha256": lf_digest})

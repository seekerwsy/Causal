from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from secaware.exploratory.independent_validation_batch import (
    _completed_assignment_id_union,
)
from secaware.exploratory.independent_validation_run import _input_path, _verify_manifest


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


def test_root_manifest_includes_nested_unit_manifest(tmp_path: Path) -> None:
    unit = tmp_path / "units" / "assignment"
    unit.mkdir(parents=True)
    nested = unit / "artifact-manifest.json"
    nested.write_bytes(b'{"files":[],"schema_version":"1.0"}\n')
    digest = hashlib.sha256(nested.read_bytes()).hexdigest()
    root = tmp_path / "artifact-manifest.json"
    root.write_text(
        '{"files":[{"path":"units/assignment/artifact-manifest.json","sha256":"'
        + digest
        + '"}],"schema_version":"1.0"}\n',
        encoding="utf-8",
    )

    _verify_manifest(root)


def _completed_run(root: Path, assignment_id: str) -> Path:
    unit = root / "units" / assignment_id
    unit.mkdir(parents=True)
    status = unit / "status.json"
    status.write_text(
        '{"assignment_id":"' + assignment_id + '","status":"COMPLETE"}\n',
        encoding="utf-8",
    )
    status_digest = hashlib.sha256(status.read_bytes()).hexdigest()
    unit_manifest = unit / "artifact-manifest.json"
    unit_manifest.write_text(
        '{"files":[{"path":"status.json","sha256":"'
        + status_digest
        + '"}],"schema_version":"1.0"}\n',
        encoding="utf-8",
    )
    entries = []
    for path in (status, unit_manifest):
        entries.append(
            '{"path":"'
            + path.relative_to(root).as_posix()
            + '","sha256":"'
            + hashlib.sha256(path.read_bytes()).hexdigest()
            + '"}'
        )
    (root / "artifact-manifest.json").write_text(
        '{"files":[' + ",".join(entries) + '],"schema_version":"1.0"}\n',
        encoding="utf-8",
    )
    return root.resolve()


def test_completed_assignment_union_accepts_disjoint_closed_runs(tmp_path: Path) -> None:
    first = _completed_run(tmp_path / "first", "assignment_first")
    second = _completed_run(tmp_path / "second", "assignment_second")

    assert _completed_assignment_id_union((first, second)) == {
        "assignment_first",
        "assignment_second",
    }


def test_completed_assignment_union_rejects_overlapping_runs(tmp_path: Path) -> None:
    first = _completed_run(tmp_path / "first", "assignment_duplicate")
    second = _completed_run(tmp_path / "second", "assignment_duplicate")

    with pytest.raises(ValueError, match="prior runs overlap"):
        _completed_assignment_id_union((first, second))

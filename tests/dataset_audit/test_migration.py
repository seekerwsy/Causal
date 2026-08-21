from __future__ import annotations

import json
from pathlib import Path

import pytest

from secaware.dataset_audit.catalog import LegacySource
from secaware.dataset_audit.migration import (
    MigrationConflictError,
    MigrationSourceError,
    migrate_legacy_sources,
)


CATALOG = (
    LegacySource(source_id="alpha", filename="a.jsonl"),
    LegacySource(source_id="beta", filename="b.jsonl"),
)


def _write_sources(root: Path) -> None:
    root.mkdir()
    (root / "a.jsonl").write_bytes(b'{"prompt":"a"}\r\n')
    (root / "b.jsonl").write_bytes(b'{"prompt":"b"}\n')


def test_migration_is_byte_exact_and_refuses_different_overwrite(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "snapshot"
    _write_sources(source_root)

    result = migrate_legacy_sources(source_root, destination_root, CATALOG)

    assert [item.status for item in result.files] == ["COPIED", "COPIED"]
    assert all(item.source_sha256 == item.destination_sha256 for item in result.files)
    assert (destination_root / "a.jsonl").read_bytes() == (source_root / "a.jsonl").read_bytes()
    (source_root / "a.jsonl").write_bytes(b'{"prompt":"changed"}\n')
    with pytest.raises(MigrationConflictError):
        migrate_legacy_sources(source_root, destination_root, CATALOG)


def test_matching_existing_snapshot_is_verified_without_rewrite(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "snapshot"
    _write_sources(source_root)
    migrate_legacy_sources(source_root, destination_root, CATALOG)
    before = (destination_root / "a.jsonl").stat().st_mtime_ns

    result = migrate_legacy_sources(source_root, destination_root, CATALOG)

    assert {item.status for item in result.files} == {"ALREADY_VERIFIED"}
    assert (destination_root / "a.jsonl").stat().st_mtime_ns == before


def test_missing_or_symlink_source_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "a.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(MigrationSourceError):
        migrate_legacy_sources(source_root, tmp_path / "snapshot", CATALOG)

    target = source_root / "real.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    try:
        (source_root / "b.jsonl").symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable on this Windows host")
    with pytest.raises(MigrationSourceError):
        migrate_legacy_sources(source_root, tmp_path / "snapshot", CATALOG)


def test_failed_copy_leaves_no_published_partial_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "snapshot"
    _write_sources(source_root)

    from secaware.dataset_audit import migration

    original = migration._copy_regular_file
    calls = 0

    def fail_second(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected copy failure")
        original(source, destination)

    monkeypatch.setattr(migration, "_copy_regular_file", fail_second)
    with pytest.raises(MigrationSourceError):
        migrate_legacy_sources(source_root, destination_root, CATALOG)

    assert not destination_root.exists()
    assert list(tmp_path.glob(".snapshot.*.staging")) == []


def test_manifest_records_absolute_coordinates_sizes_and_hashes(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "snapshot"
    _write_sources(source_root)

    migrate_legacy_sources(source_root, destination_root, CATALOG)
    manifest = json.loads((destination_root / "migration-manifest.json").read_text("utf-8"))

    assert manifest["schema_version"] == "1.0"
    assert manifest["source_root"] == str(source_root.resolve())
    assert manifest["destination_root"] == str(destination_root.resolve())
    assert [item["filename"] for item in manifest["files"]] == ["a.jsonl", "b.jsonl"]
    assert all(len(item["source_sha256"]) == 64 for item in manifest["files"])

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from secaware.dataset_audit.catalog import LegacySource
from secaware.dataset_audit.fingerprints import file_sha256


class MigrationSourceError(RuntimeError):
    """A source snapshot cannot be copied and verified safely."""


class MigrationConflictError(RuntimeError):
    """An immutable destination exists but does not match the source."""


@dataclass(frozen=True, slots=True)
class MigratedFile:
    source_id: str
    filename: str
    source_path: str
    destination_path: str
    size_bytes: int
    source_mtime_ns: int
    source_sha256: str
    destination_sha256: str
    status: str


@dataclass(frozen=True, slots=True)
class MigrationResult:
    source_root: str
    destination_root: str
    files: tuple[MigratedFile, ...]


def _regular_source(path: Path) -> os.stat_result:
    try:
        value = path.lstat()
    except OSError as error:
        raise MigrationSourceError(f"missing or unreadable source: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(value.st_mode):
        raise MigrationSourceError(f"source is not a regular file: {path}")
    return value


def _copy_regular_file(source: Path, destination: Path) -> None:
    before = _regular_source(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    after = _regular_source(source)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise MigrationSourceError(f"source changed during copy: {source}")


def _validate_catalog(catalog: tuple[LegacySource, ...]) -> None:
    if not catalog:
        raise MigrationSourceError("source catalog is empty")
    filenames = [item.filename for item in catalog]
    if len(set(filenames)) != len(filenames):
        raise MigrationSourceError("source catalog contains duplicate filenames")
    if any(Path(name).name != name or name in {"", ".", ".."} for name in filenames):
        raise MigrationSourceError("source catalog contains an unsafe filename")


def _source_inventory(
    source_root: Path, catalog: tuple[LegacySource, ...]
) -> tuple[tuple[LegacySource, Path, os.stat_result, str], ...]:
    inventory = []
    for item in catalog:
        source = source_root / item.filename
        metadata = _regular_source(source)
        inventory.append((item, source, metadata, file_sha256(source)))
    return tuple(inventory)


def _existing_result(
    source_root: Path,
    destination_root: Path,
    inventory: tuple[tuple[LegacySource, Path, os.stat_result, str], ...],
) -> MigrationResult:
    manifest = destination_root / "migration-manifest.json"
    if not destination_root.is_dir() or not manifest.is_file() or manifest.is_symlink():
        raise MigrationConflictError("existing snapshot is incomplete or unsafe")
    files: list[MigratedFile] = []
    for item, source, metadata, source_digest in inventory:
        destination = destination_root / item.filename
        try:
            destination_metadata = destination.lstat()
        except OSError as error:
            raise MigrationConflictError("existing snapshot is incomplete") from error
        if destination.is_symlink() or not stat.S_ISREG(destination_metadata.st_mode):
            raise MigrationConflictError("existing snapshot contains a non-regular file")
        destination_digest = file_sha256(destination)
        if source_digest != destination_digest or metadata.st_size != destination_metadata.st_size:
            raise MigrationConflictError("existing snapshot differs from source")
        files.append(
            MigratedFile(
                source_id=item.source_id,
                filename=item.filename,
                source_path=str(source.resolve()),
                destination_path=str(destination.resolve()),
                size_bytes=metadata.st_size,
                source_mtime_ns=metadata.st_mtime_ns,
                source_sha256=source_digest,
                destination_sha256=destination_digest,
                status="ALREADY_VERIFIED",
            )
        )
    return MigrationResult(str(source_root), str(destination_root), tuple(files))


def migrate_legacy_sources(
    source_root: Path,
    destination_root: Path,
    catalog: tuple[LegacySource, ...],
) -> MigrationResult:
    _validate_catalog(catalog)
    source_root = Path(source_root).resolve()
    destination_root = Path(destination_root).resolve()
    inventory = _source_inventory(source_root, catalog)
    if destination_root.exists() or destination_root.is_symlink():
        return _existing_result(source_root, destination_root, inventory)

    destination_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination_root.name}.",
            suffix=".staging",
            dir=destination_root.parent,
        )
    )
    files: list[MigratedFile] = []
    try:
        for item, source, metadata, source_digest in inventory:
            staged = staging / item.filename
            _copy_regular_file(source, staged)
            destination_digest = file_sha256(staged)
            if source_digest != destination_digest or metadata.st_size != staged.stat().st_size:
                raise MigrationSourceError(f"copy digest mismatch: {item.filename}")
            files.append(
                MigratedFile(
                    source_id=item.source_id,
                    filename=item.filename,
                    source_path=str(source),
                    destination_path=str(destination_root / item.filename),
                    size_bytes=metadata.st_size,
                    source_mtime_ns=metadata.st_mtime_ns,
                    source_sha256=source_digest,
                    destination_sha256=destination_digest,
                    status="COPIED",
                )
            )
        manifest_value = {
            "schema_version": "1.0",
            "migrated_at": datetime.now(UTC).isoformat(),
            "source_root": str(source_root),
            "destination_root": str(destination_root),
            "files": [asdict(item) for item in files],
        }
        (staging / "migration-manifest.json").write_text(
            json.dumps(manifest_value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(staging, destination_root)
        return MigrationResult(str(source_root), str(destination_root), tuple(files))
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except (MigrationConflictError, MigrationSourceError):
        raise
    except Exception as error:
        raise MigrationSourceError("legacy source migration failed") from error
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

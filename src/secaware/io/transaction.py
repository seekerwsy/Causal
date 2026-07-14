from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Literal

from secaware.oracle.strict_json import load_strict_json_bytes


_SCHEMA_VERSION = "1.0"
_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_JOURNAL_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
_CLEANUP_ATTEMPTS = 3


class TransactionStateError(Exception):
    """A local artifact transaction cannot be safely recovered or cleaned."""

    def __init__(self) -> None:
        super().__init__("artifact transaction state is invalid")


@dataclass(frozen=True, slots=True)
class TransactionArtifact:
    target: Path
    kind: str

    def __post_init__(self) -> None:
        target = Path(self.target)
        if (
            not target.is_absolute()
            or target.name in {"", ".", ".."}
            or _KIND_PATTERN.fullmatch(self.kind) is None
        ):
            raise TransactionStateError
        object.__setattr__(self, "target", target)


@dataclass(frozen=True, slots=True)
class _ArtifactState:
    target_key: str
    old_exists: bool
    old_sha256: str | None
    committed_sha256: str | None


@dataclass(frozen=True, slots=True)
class _Journal:
    token: str
    state: Literal["recovery", "postcommit"]
    artifacts: tuple[_ArtifactState, ...]


def _target_key(target: Path) -> str:
    payload = ("secaware-transaction-v1\x00" + os.path.normcase(str(target))).encode(
        "utf-8",
        errors="strict",
    )
    return hashlib.sha256(payload).hexdigest()


def _backup_path(artifact: TransactionArtifact, token: str) -> Path:
    return artifact.target.with_name(
        f".{artifact.target.name}.{token}.{artifact.kind}.recovery.backup"
    )


def _fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_regular_bytes(
    path: Path,
    maximum_bytes: int,
    *,
    allow_empty: bool = False,
) -> bytes:
    descriptor = -1
    payload = b""
    payload_buffer = bytearray()
    chunk = b""
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_size < 1 and not allow_empty)
            or before.st_size > maximum_bytes
        ):
            raise TransactionStateError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(before):
            raise TransactionStateError
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TransactionStateError
            payload_buffer.extend(chunk)
            remaining -= len(chunk)
        payload = bytes(payload_buffer)
        after = os.fstat(descriptor)
        if (
            _fingerprint(after) != _fingerprint(opened)
            or len(payload) != opened.st_size
            or len(payload) > maximum_bytes
        ):
            raise TransactionStateError
        return payload
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except TransactionStateError:
        raise
    except Exception:
        raise TransactionStateError from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        payload = b""
        payload_buffer.clear()
        chunk = b""


def _artifact_sha256(path: Path) -> str:
    descriptor = -1
    chunk = b""
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise TransactionStateError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(before):
            raise TransactionStateError
        digest = hashlib.sha256()
        total = 0
        while total < opened.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - total))
            if not chunk:
                raise TransactionStateError
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if _fingerprint(after) != _fingerprint(opened) or total != opened.st_size:
            raise TransactionStateError
        return digest.hexdigest()
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except TransactionStateError:
        raise
    except Exception:
        raise TransactionStateError from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        chunk = b""


def _artifact_state(value: object) -> _ArtifactState:
    if type(value) is not dict or set(value) != {
        "target_key",
        "old_exists",
        "old_sha256",
        "committed_sha256",
    }:
        raise TransactionStateError
    target_key = value["target_key"]
    old_exists = value["old_exists"]
    old_sha256 = value["old_sha256"]
    committed_sha256 = value["committed_sha256"]
    if (
        type(target_key) is not str
        or _SHA256_PATTERN.fullmatch(target_key) is None
        or type(old_exists) is not bool
        or (
            old_exists
            and (type(old_sha256) is not str or _SHA256_PATTERN.fullmatch(old_sha256) is None)
        )
        or (not old_exists and old_sha256 is not None)
        or (
            committed_sha256 is not None
            and (
                type(committed_sha256) is not str
                or _SHA256_PATTERN.fullmatch(committed_sha256) is None
            )
        )
    ):
        raise TransactionStateError
    return _ArtifactState(
        target_key=target_key,
        old_exists=old_exists,
        old_sha256=old_sha256,
        committed_sha256=committed_sha256,
    )


def _parse_journal(payload: bytes, artifacts: tuple[TransactionArtifact, ...]) -> _Journal:
    try:
        value = load_strict_json_bytes(payload)
        if type(value) is not dict or set(value) != {
            "schema_version",
            "token",
            "state",
            "artifacts",
        }:
            raise TransactionStateError
        token = value["token"]
        state = value["state"]
        artifact_values = value["artifacts"]
        if (
            value["schema_version"] != _SCHEMA_VERSION
            or type(token) is not str
            or _TOKEN_PATTERN.fullmatch(token) is None
            or state not in {"recovery", "postcommit"}
            or type(artifact_values) is not list
            or len(artifact_values) != len(artifacts)
        ):
            raise TransactionStateError
        parsed = tuple(_artifact_state(item) for item in artifact_values)
        if any(
            item.target_key != _target_key(artifact.target)
            for item, artifact in zip(parsed, artifacts, strict=True)
        ):
            raise TransactionStateError
        if state == "recovery" and any(item.committed_sha256 is not None for item in parsed):
            raise TransactionStateError
        if state == "postcommit" and any(item.committed_sha256 is None for item in parsed):
            raise TransactionStateError
        return _Journal(token=token, state=state, artifacts=parsed)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except TransactionStateError:
        raise
    except Exception:
        raise TransactionStateError from None


def _journal_payload(journal: _Journal) -> bytes:
    value = {
        "schema_version": _SCHEMA_VERSION,
        "token": journal.token,
        "state": journal.state,
        "artifacts": [
            {
                "target_key": item.target_key,
                "old_exists": item.old_exists,
                "old_sha256": item.old_sha256,
                "committed_sha256": item.committed_sha256,
            }
            for item in journal.artifacts
        ],
    }
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _write_journal(path: Path, journal: _Journal) -> None:
    temporary: Path | None = None
    try:
        if path.is_symlink():
            raise TransactionStateError
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = _journal_payload(journal)
        if len(payload) > _MAX_JOURNAL_BYTES:
            raise TransactionStateError
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except TransactionStateError:
        raise
    except Exception:
        raise TransactionStateError from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _load_journal(path: Path, artifacts: tuple[TransactionArtifact, ...]) -> _Journal:
    return _parse_journal(_read_regular_bytes(path, _MAX_JOURNAL_BYTES), artifacts)


def _validate_plan(
    journal_path: Path,
    artifacts: tuple[TransactionArtifact, ...],
) -> None:
    if (
        not journal_path.is_absolute()
        or not artifacts
        or len(artifacts) > 32
        or len({artifact.target for artifact in artifacts}) != len(artifacts)
        or journal_path in {artifact.target for artifact in artifacts}
    ):
        raise TransactionStateError


def _orphan_backups(
    artifacts: tuple[TransactionArtifact, ...],
) -> list[Path]:
    found: list[Path] = []
    for artifact in artifacts:
        try:
            found.extend(
                artifact.target.parent.glob(
                    f".{artifact.target.name}.*.{artifact.kind}.recovery.backup"
                )
            )
        except OSError:
            raise TransactionStateError from None
    return found


class ArtifactTransaction:
    def __init__(
        self,
        journal_path: Path,
        artifacts: tuple[TransactionArtifact, ...],
        journal: _Journal,
    ) -> None:
        self.journal_path = journal_path
        self.artifacts = artifacts
        self.journal = journal

    @classmethod
    def begin(
        cls,
        journal_path: Path,
        artifacts: tuple[TransactionArtifact, ...],
    ) -> "ArtifactTransaction":
        _validate_plan(journal_path, artifacts)
        if journal_path.exists() or _orphan_backups(artifacts):
            raise TransactionStateError
        token = secrets.token_hex(16)
        states: list[_ArtifactState] = []
        for artifact in artifacts:
            target = artifact.target
            if target.is_symlink():
                raise TransactionStateError
            exists = target.exists()
            digest = _artifact_sha256(target) if exists else None
            states.append(
                _ArtifactState(
                    target_key=_target_key(target),
                    old_exists=exists,
                    old_sha256=digest,
                    committed_sha256=None,
                )
            )
        journal = _Journal(token=token, state="recovery", artifacts=tuple(states))
        _write_journal(journal_path, journal)
        return cls(journal_path, artifacts, journal)

    def backup(self, index: int) -> None:
        artifact = self.artifacts[index]
        state = self.journal.artifacts[index]
        backup = _backup_path(artifact, self.journal.token)
        if backup.exists() or backup.is_symlink():
            raise TransactionStateError
        if state.old_exists:
            if _artifact_sha256(artifact.target) != state.old_sha256:
                raise TransactionStateError
            try:
                os.replace(artifact.target, backup)
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                raise TransactionStateError from None
            if _artifact_sha256(backup) != state.old_sha256:
                raise TransactionStateError
        elif artifact.target.exists() or artifact.target.is_symlink():
            raise TransactionStateError

    def install(self, index: int, candidate: Path) -> None:
        self.backup(index)
        try:
            os.replace(candidate, self.artifacts[index].target)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise TransactionStateError from None

    def mark_postcommit(self) -> None:
        committed = tuple(
            _ArtifactState(
                target_key=state.target_key,
                old_exists=state.old_exists,
                old_sha256=state.old_sha256,
                committed_sha256=_artifact_sha256(artifact.target),
            )
            for artifact, state in zip(
                self.artifacts,
                self.journal.artifacts,
                strict=True,
            )
        )
        journal = _Journal(
            token=self.journal.token,
            state="postcommit",
            artifacts=committed,
        )
        _write_journal(self.journal_path, journal)
        self.journal = journal


def _recover(
    journal_path: Path, artifacts: tuple[TransactionArtifact, ...], journal: _Journal
) -> None:
    for artifact, state in zip(artifacts, journal.artifacts, strict=True):
        target = artifact.target
        backup = _backup_path(artifact, journal.token)
        if state.old_exists:
            if backup.exists() or backup.is_symlink():
                if backup.is_symlink() or _artifact_sha256(backup) != state.old_sha256:
                    raise TransactionStateError
                if target.exists() or target.is_symlink():
                    try:
                        target.unlink()
                    except (MemoryError, KeyboardInterrupt, SystemExit):
                        raise
                    except Exception:
                        raise TransactionStateError from None
                try:
                    os.replace(backup, target)
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise TransactionStateError from None
            if (
                not target.exists()
                or target.is_symlink()
                or _artifact_sha256(target) != state.old_sha256
            ):
                raise TransactionStateError
        else:
            if backup.exists() or backup.is_symlink():
                raise TransactionStateError
            if target.exists() or target.is_symlink():
                try:
                    target.unlink()
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise TransactionStateError from None
    try:
        journal_path.unlink()
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise TransactionStateError from None


def _cleanup_postcommit(
    journal_path: Path,
    artifacts: tuple[TransactionArtifact, ...],
    journal: _Journal,
) -> None:
    for artifact, state in zip(artifacts, journal.artifacts, strict=True):
        if (
            not artifact.target.exists()
            or artifact.target.is_symlink()
            or _artifact_sha256(artifact.target) != state.committed_sha256
        ):
            raise TransactionStateError
        backup = _backup_path(artifact, journal.token)
        if backup.exists() or backup.is_symlink():
            if (
                not state.old_exists
                or backup.is_symlink()
                or _artifact_sha256(backup) != state.old_sha256
            ):
                raise TransactionStateError

    pending = [
        _backup_path(artifact, journal.token)
        for artifact in artifacts
        if _backup_path(artifact, journal.token).exists()
    ]
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    for _ in range(_CLEANUP_ATTEMPTS):
        remaining: list[Path] = []
        for path in pending:
            try:
                path.unlink(missing_ok=True)
            except (MemoryError, KeyboardInterrupt, SystemExit) as error:
                if control is None:
                    control = error
                remaining.append(path)
            except Exception:
                remaining.append(path)
        pending = remaining
        if not pending:
            break
    if pending:
        if control is not None:
            raise control
        return
    try:
        journal_path.unlink(missing_ok=True)
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        if control is None:
            control = error
    except Exception:
        pass
    if control is not None:
        raise control


def resolve_pending_transaction(
    journal_path: Path,
    artifacts: tuple[TransactionArtifact, ...],
) -> Literal["none", "recovered", "postcommit"]:
    _validate_plan(journal_path, artifacts)
    if not journal_path.exists():
        if journal_path.is_symlink() or _orphan_backups(artifacts):
            raise TransactionStateError
        return "none"
    journal = _load_journal(journal_path, artifacts)
    if journal.state == "recovery":
        _recover(journal_path, artifacts, journal)
        return "recovered"
    _cleanup_postcommit(journal_path, artifacts, journal)
    return "postcommit"


def recover_transaction(
    transaction: ArtifactTransaction,
) -> None:
    if transaction.journal.state != "recovery":
        raise TransactionStateError
    _recover(transaction.journal_path, transaction.artifacts, transaction.journal)


def cleanup_committed_transaction(transaction: ArtifactTransaction) -> None:
    if transaction.journal.state != "postcommit":
        raise TransactionStateError
    _cleanup_postcommit(
        transaction.journal_path,
        transaction.artifacts,
        transaction.journal,
    )


__all__ = [
    "ArtifactTransaction",
    "TransactionArtifact",
    "TransactionStateError",
    "cleanup_committed_transaction",
    "recover_transaction",
    "resolve_pending_transaction",
]

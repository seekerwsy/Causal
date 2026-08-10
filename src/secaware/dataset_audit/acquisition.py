from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from secaware.dataset_audit.catalog import UpstreamSource
from secaware.dataset_audit.fingerprints import file_sha256
from secaware.io.transaction import (
    ArtifactTransaction,
    TransactionArtifact,
    cleanup_committed_transaction,
    recover_transaction,
)


_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REVISION_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_DEFAULT_MAXIMUM_BYTES = 256 * 1024 * 1024


class SourceTransport(Protocol):
    def resolve_commit(self, repository: str, revision: str) -> str: ...

    def fetch_bytes(self, repository: str, commit: str, path: str) -> bytes: ...


class UpstreamUnavailableError(RuntimeError):
    code = "UPSTREAM_UNAVAILABLE"


class AcquisitionConflictError(RuntimeError):
    """Pinned source or lock evidence differs from an immutable local copy."""


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    commit: str
    path: Path
    lock_path: Path
    sha256: str
    size_bytes: int
    status: str


class GitHubSourceTransport:
    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        maximum_bytes: int = _DEFAULT_MAXIMUM_BYTES,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.maximum_bytes = maximum_bytes

    def _get(self, url: str) -> bytes:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "SecAware-dataset-audit/1.0",
            },
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > self.maximum_bytes:
                raise ValueError("upstream response exceeds byte limit")
            payload = response.read(self.maximum_bytes + 1)
        if len(payload) > self.maximum_bytes:
            raise ValueError("upstream response exceeds byte limit")
        return payload

    def _resolve_commit_with_git(self, repository: str, revision: str) -> str:
        if (
            _REPOSITORY_PATTERN.fullmatch(repository) is None
            or _REVISION_PATTERN.fullmatch(revision) is None
            or ".." in revision
        ):
            raise ValueError("repository or revision is unsafe")
        ref = f"refs/heads/{revision}"
        options: dict[str, object] = {}
        if os.name == "nt":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            [
                "git",
                "ls-remote",
                "--refs",
                "--exit-code",
                f"https://github.com/{repository}.git",
                ref,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=self.timeout_seconds,
            check=False,
            **options,
        )
        lines = completed.stdout.splitlines()
        if completed.returncode != 0 or len(lines) != 1:
            raise ValueError("git commit resolution failed")
        fields = lines[0].split("\t")
        if len(fields) != 2 or fields[1] != ref:
            raise ValueError("git commit response has invalid shape")
        commit = fields[0].casefold()
        if _COMMIT_PATTERN.fullmatch(commit) is None:
            raise ValueError("git commit response is not immutable")
        return commit

    def resolve_commit(self, repository: str, revision: str) -> str:
        try:
            payload = self._get(
                f"https://api.github.com/repos/{repository}/commits/{revision}"
            )
        except HTTPError as error:
            if error.code not in {403, 429}:
                raise
            return self._resolve_commit_with_git(repository, revision)
        value = json.loads(payload)
        if not isinstance(value, dict) or not isinstance(value.get("sha"), str):
            raise ValueError("GitHub commit response has invalid shape")
        return value["sha"].casefold()

    def fetch_bytes(self, repository: str, commit: str, path: str) -> bytes:
        return self._get(f"https://raw.githubusercontent.com/{repository}/{commit}/{path}")


def _validate_source(source: UpstreamSource) -> None:
    expected_prefix = f"https://github.com/{source.repository}/"
    path = PurePosixPath(source.relative_path)
    if (
        source.repository != "meta-llama/PurpleLlama"
        or not source.official_https_url.startswith(expected_prefix)
        or path.is_absolute()
        or ".." in path.parts
        or path.name != "instruct-v2.json"
    ):
        raise UpstreamUnavailableError("upstream source descriptor is not allowlisted")


def _validate_payload(payload: bytes, maximum_bytes: int) -> None:
    if not payload or len(payload) > maximum_bytes:
        raise UpstreamUnavailableError("upstream payload violates byte limits")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UpstreamUnavailableError("upstream payload is not valid JSON") from error
    if not isinstance(value, (dict, list)):
        raise UpstreamUnavailableError("upstream JSON has an unsupported top-level shape")


def _lock_payload(
    source: UpstreamSource,
    commit: str,
    payload: bytes,
    retrieved_at: str,
) -> tuple[dict[str, object], bytes]:
    value: dict[str, object] = {
        "schema_version": "1.0",
        "source_id": source.source_id,
        "repository": source.repository,
        "requested_revision": source.revision,
        "resolved_commit": commit,
        "relative_path": source.relative_path,
        "official_https_url": source.official_https_url,
        "retrieved_at": retrieved_at,
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    serialized = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    return value, serialized


def _write_candidate(parent: Path, name: str, payload: bytes) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{name}.", suffix=".candidate", dir=parent, delete=False
    ) as handle:
        candidate = Path(handle.name)
        handle.write(payload)
        handle.flush()
    return candidate


def _verify_existing(
    target: Path,
    lock_path: Path,
    commit: str,
    payload: bytes,
) -> AcquisitionResult:
    unsafe = target.is_symlink() or lock_path.is_symlink()
    incomplete = not target.is_file() or not lock_path.is_file()
    if unsafe or incomplete:
        raise AcquisitionConflictError("existing pinned source is incomplete or unsafe")
    digest = hashlib.sha256(payload).hexdigest()
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcquisitionConflictError("existing source lock is unreadable") from error
    if (
        file_sha256(target) != digest
        or lock.get("resolved_commit") != commit
        or lock.get("sha256") != digest
        or lock.get("size_bytes") != len(payload)
    ):
        raise AcquisitionConflictError("existing pinned source differs from upstream bytes")
    return AcquisitionResult(commit, target, lock_path, digest, len(payload), "ALREADY_VERIFIED")


def acquire_pinned_source(
    *,
    source: UpstreamSource,
    sources_root: Path,
    lock_path: Path,
    transport: SourceTransport | None = None,
    maximum_bytes: int = _DEFAULT_MAXIMUM_BYTES,
) -> AcquisitionResult:
    _validate_source(source)
    if maximum_bytes < 1:
        raise UpstreamUnavailableError("maximum_bytes must be positive")
    selected_transport = transport or GitHubSourceTransport(maximum_bytes=maximum_bytes)
    try:
        commit = selected_transport.resolve_commit(source.repository, source.revision).casefold()
        if _COMMIT_PATTERN.fullmatch(commit) is None:
            raise ValueError("resolved revision is not an immutable commit")
        payload = selected_transport.fetch_bytes(
            source.repository, commit, source.relative_path
        )
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except (HTTPError, URLError, OSError, TypeError, ValueError) as error:
        raise UpstreamUnavailableError("official upstream source is unavailable") from error
    _validate_payload(payload, maximum_bytes)

    sources_root = Path(sources_root).resolve()
    lock_path = Path(lock_path).resolve()
    target = sources_root / source.source_id / commit / PurePosixPath(source.relative_path).name
    if target.exists() or lock_path.exists() or target.is_symlink() or lock_path.is_symlink():
        return _verify_existing(target, lock_path, commit, payload)

    retrieved_at = datetime.now(UTC).isoformat()
    lock, serialized_lock = _lock_payload(source, commit, payload, retrieved_at)
    target_candidate = _write_candidate(target.parent, target.name, payload)
    lock_candidate = _write_candidate(lock_path.parent, lock_path.name, serialized_lock)
    artifacts = (
        TransactionArtifact(target=target, kind="dataset_source"),
        TransactionArtifact(target=lock_path, kind="source_lock"),
    )
    journal_path = lock_path.with_name(f".{lock_path.name}.transaction.json")
    transaction: ArtifactTransaction | None = None
    try:
        transaction = ArtifactTransaction.begin(journal_path, artifacts)
        transaction.install(0, target_candidate)
        transaction.install(1, lock_candidate)
        transaction.mark_postcommit()
        cleanup_committed_transaction(transaction)
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception as error:
        if transaction is not None and transaction.journal.state == "recovery":
            recover_transaction(transaction)
        raise UpstreamUnavailableError("pinned source publication failed") from error
    finally:
        target_candidate.unlink(missing_ok=True)
        lock_candidate.unlink(missing_ok=True)
    return AcquisitionResult(
        commit=commit,
        path=target,
        lock_path=lock_path,
        sha256=str(lock["sha256"]),
        size_bytes=len(payload),
        status="ACQUIRED",
    )

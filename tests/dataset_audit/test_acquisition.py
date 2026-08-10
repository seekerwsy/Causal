from __future__ import annotations

import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

from secaware.dataset_audit.acquisition import (
    AcquisitionConflictError,
    GitHubSourceTransport,
    UpstreamUnavailableError,
    acquire_pinned_source,
)
from secaware.dataset_audit.catalog import cyberseceval_v2_source


COMMIT = "a" * 40
PAYLOAD = b'[{"prompt":"Implement a parser.","cwe":"CWE-20"}]\n'


class FakeTransport:
    def __init__(self, payload: bytes = PAYLOAD, *, fail: bool = False) -> None:
        self.payload = payload
        self.fail = fail
        self.resolve_calls: list[tuple[str, str]] = []
        self.fetch_calls: list[tuple[str, str, str]] = []

    def resolve_commit(self, repository: str, revision: str) -> str:
        self.resolve_calls.append((repository, revision))
        if self.fail:
            raise OSError("offline")
        return COMMIT

    def fetch_bytes(self, repository: str, commit: str, path: str) -> bytes:
        self.fetch_calls.append((repository, commit, path))
        if self.fail:
            raise OSError("offline")
        return self.payload


def test_acquisition_pins_commit_and_writes_source_lock(tmp_path: Path) -> None:
    source = cyberseceval_v2_source()
    transport = FakeTransport()

    result = acquire_pinned_source(
        source=source,
        sources_root=tmp_path / "sources",
        lock_path=tmp_path / "manifests" / "source-lock.json",
        transport=transport,
    )

    assert result.commit == COMMIT
    assert result.path == tmp_path / "sources" / source.source_id / COMMIT / "instruct-v2.json"
    assert result.path.read_bytes() == PAYLOAD
    lock = json.loads((tmp_path / "manifests" / "source-lock.json").read_text("utf-8"))
    assert lock["repository"] == "meta-llama/PurpleLlama"
    assert lock["resolved_commit"] == COMMIT
    assert lock["relative_path"] == source.relative_path
    assert lock["size_bytes"] == len(PAYLOAD)
    assert len(lock["sha256"]) == 64
    assert lock["retrieved_at"].endswith("+00:00")


def test_existing_identical_pin_is_verified_without_rewrite(tmp_path: Path) -> None:
    arguments = {
        "source": cyberseceval_v2_source(),
        "sources_root": tmp_path / "sources",
        "lock_path": tmp_path / "manifests" / "source-lock.json",
    }
    first = acquire_pinned_source(**arguments, transport=FakeTransport())
    before = first.path.stat().st_mtime_ns

    class LockedTransport(FakeTransport):
        def resolve_commit(self, repository: str, revision: str) -> str:
            raise OSError("symbolic revision must not be resolved after lock")

    locked_transport = LockedTransport()
    second = acquire_pinned_source(**arguments, transport=locked_transport)

    assert second.status == "ALREADY_VERIFIED"
    assert second.path.stat().st_mtime_ns == before
    assert locked_transport.fetch_calls == [
        (
            "meta-llama/PurpleLlama",
            COMMIT,
            "CybersecurityBenchmarks/datasets/instruct/instruct-v2.json",
        )
    ]


def test_existing_pin_with_different_bytes_fails_closed(tmp_path: Path) -> None:
    arguments = {
        "source": cyberseceval_v2_source(),
        "sources_root": tmp_path / "sources",
        "lock_path": tmp_path / "manifests" / "source-lock.json",
    }
    acquire_pinned_source(**arguments, transport=FakeTransport())

    with pytest.raises(AcquisitionConflictError):
        acquire_pinned_source(
            **arguments,
            transport=FakeTransport(b'[{"prompt":"different"}]\n'),
        )


def test_transport_failure_is_reported_as_upstream_unavailable(tmp_path: Path) -> None:
    with pytest.raises(UpstreamUnavailableError) as captured:
        acquire_pinned_source(
            source=cyberseceval_v2_source(),
            sources_root=tmp_path / "sources",
            lock_path=tmp_path / "manifests" / "source-lock.json",
            transport=FakeTransport(fail=True),
        )

    assert captured.value.code == "UPSTREAM_UNAVAILABLE"
    assert not (tmp_path / "sources").exists()


@pytest.mark.parametrize("commit", ["main", "f" * 39, "g" * 40])
def test_invalid_resolved_commit_fails_closed(tmp_path: Path, commit: str) -> None:
    class InvalidCommitTransport(FakeTransport):
        def resolve_commit(self, repository: str, revision: str) -> str:
            return commit

    with pytest.raises(UpstreamUnavailableError):
        acquire_pinned_source(
            source=cyberseceval_v2_source(),
            sources_root=tmp_path / "sources",
            lock_path=tmp_path / "source-lock.json",
            transport=InvalidCommitTransport(),
        )


def test_non_json_or_oversized_payload_is_rejected(tmp_path: Path) -> None:
    for payload in (b"not-json", b"[" + b" " * 101 + b"]"):
        with pytest.raises(UpstreamUnavailableError):
            acquire_pinned_source(
                source=cyberseceval_v2_source(),
                sources_root=tmp_path / payload.hex()[:8],
                lock_path=tmp_path / f"{payload.hex()[:8]}.json",
                transport=FakeTransport(payload),
                maximum_bytes=100,
            )


def test_github_commit_resolution_falls_back_to_git_on_api_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = GitHubSourceTransport()

    def rate_limited(url: str) -> bytes:
        raise HTTPError(url, 403, "rate limit exceeded", {}, None)

    fallback_calls: list[tuple[str, str]] = []

    def fallback(repository: str, revision: str) -> str:
        fallback_calls.append((repository, revision))
        return COMMIT

    monkeypatch.setattr(transport, "_get", rate_limited)
    monkeypatch.setattr(transport, "_resolve_commit_with_git", fallback)

    assert transport.resolve_commit("meta-llama/PurpleLlama", "main") == COMMIT
    assert fallback_calls == [("meta-llama/PurpleLlama", "main")]

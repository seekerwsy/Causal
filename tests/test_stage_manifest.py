import hashlib
import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from secaware.pipeline import artifact as artifact_module
from secaware.pipeline import manifest as manifest_module
from secaware.pipeline.artifact import canonical_sha256, sha256_file, sha256_path
from secaware.pipeline.manifest import (
    StageManifest,
    build_stage_fingerprint,
    manifest_allows_skip,
    read_stage_manifest,
    write_stage_manifest,
)


def _manifest(
    *,
    fingerprint: str,
    outputs: list[Path | str],
    output_sha256: dict[Path | str, str] | None = None,
) -> StageManifest:
    hashes = output_sha256
    if hashes is None:
        hashes = {path: sha256_path(path) if Path(path).exists() else "a" * 64 for path in outputs}
    return StageManifest(
        schema_version="1.0",
        stage="discovery",
        fingerprint=fingerprint,
        inputs={"inputs/prompts.jsonl": "input-sha"},
        config_sha256="config-sha",
        code_version="test-version",
        outputs=outputs,
        output_sha256=hashes,
    )


def test_sha256_file_hashes_file_bytes(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    payload = "安全 artifact\n".encode()
    path.write_bytes(payload)

    assert sha256_file(path) == hashlib.sha256(payload).hexdigest()


def test_sha256_path_uses_file_hash_for_a_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"artifact-bytes")

    assert artifact_module.sha256_path(path) == sha256_file(path)


def test_sha256_path_has_a_stable_empty_directory_hash(tmp_path: Path) -> None:
    first = tmp_path / "first-empty"
    second = tmp_path / "second-empty"
    first.mkdir()
    second.mkdir()

    assert artifact_module.sha256_path(first) == artifact_module.sha256_path(second)


def test_sha256_path_hashes_recursive_relative_paths_and_file_contents(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    (first / "nested").mkdir(parents=True)
    (second / "nested").mkdir(parents=True)
    (first / "z.py").write_text("z = 1\n", encoding="utf-8")
    (first / "nested" / "a.py").write_text("a = 1\n", encoding="utf-8")
    (second / "nested" / "a.py").write_text("a = 1\n", encoding="utf-8")
    (second / "z.py").write_text("z = 1\n", encoding="utf-8")

    baseline = artifact_module.sha256_path(first)

    assert artifact_module.sha256_path(second) == baseline
    (second / "nested" / "a.py").write_text("a = 2\n", encoding="utf-8")
    assert artifact_module.sha256_path(second) != baseline


def test_canonical_sha256_is_stable_for_mapping_order() -> None:
    first = {"outer": {"b": 2, "a": 1}, "name": "安全"}
    reordered = {"name": "安全", "outer": {"a": 1, "b": 2}}

    assert canonical_sha256(first) == canonical_sha256(reordered)


@pytest.mark.parametrize(
    "value",
    [
        {"path": Path("artifact.jsonl")},
        {"tuple": (1, 2)},
        {"set": {1, 2}},
        {1: "non-string JSON key"},
        {"not_finite": math.nan},
    ],
)
def test_canonical_sha256_rejects_non_json_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_sha256(value)


def test_stage_fingerprint_ignores_input_mapping_order() -> None:
    first = build_stage_fingerprint(
        "discovery",
        {"a.jsonl": "sha-a", "b.jsonl": "sha-b"},
        {"alpha": 1, "beta": 2},
        policy_sha256="policy",
        catalog_sha256="catalog",
        code_version="v1",
    )
    reordered = build_stage_fingerprint(
        "discovery",
        {"b.jsonl": "sha-b", "a.jsonl": "sha-a"},
        {"beta": 2, "alpha": 1},
        policy_sha256="policy",
        catalog_sha256="catalog",
        code_version="v1",
    )

    assert first == reordered


@pytest.mark.parametrize(
    "changes",
    [
        {"stage": "analysis"},
        {"inputs": {"a.jsonl": "changed"}},
        {"config": {"alpha": 2}},
        {"policy_sha256": "changed-policy"},
        {"catalog_sha256": "changed-catalog"},
        {"code_version": "v2"},
    ],
)
def test_stage_fingerprint_changes_when_any_component_changes(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "stage": "discovery",
        "inputs": {"a.jsonl": "sha-a"},
        "config": {"alpha": 1},
        "policy_sha256": "policy",
        "catalog_sha256": "catalog",
        "code_version": "v1",
    }
    baseline = build_stage_fingerprint(
        values["stage"],
        values["inputs"],
        values["config"],
        policy_sha256=values["policy_sha256"],
        catalog_sha256=values["catalog_sha256"],
        code_version=values["code_version"],
    )
    values.update(changes)

    changed = build_stage_fingerprint(
        values["stage"],
        values["inputs"],
        values["config"],
        policy_sha256=values["policy_sha256"],
        catalog_sha256=values["catalog_sha256"],
        code_version=values["code_version"],
    )

    assert changed != baseline


def test_stage_manifest_normalizes_input_and_output_paths() -> None:
    manifest = _manifest(
        fingerprint="fingerprint",
        outputs=[Path("reports") / "." / "summary.json"],
    )

    assert manifest.inputs == {Path("inputs/prompts.jsonl").as_posix(): "input-sha"}
    assert manifest.outputs == [Path("reports/summary.json").as_posix()]
    assert manifest.output_sha256 == {Path("reports/summary.json").as_posix(): "a" * 64}


def test_legacy_stage_manifest_without_output_hashes_is_readable_but_not_skippable(
    tmp_path: Path,
) -> None:
    output = tmp_path / "out.jsonl"
    output.write_text("ready\n", encoding="utf-8")
    manifest = StageManifest(
        schema_version="1.0",
        stage="discovery",
        fingerprint="expected",
        inputs={"inputs/prompts.jsonl": "input-sha"},
        config_sha256="config-sha",
        code_version="test-version",
        outputs=[output],
    )
    manifest_path = tmp_path / "manifest.json"

    write_stage_manifest(manifest_path, manifest)

    assert read_stage_manifest(manifest_path).output_sha256 == {}
    assert manifest_allows_skip(manifest_path, "expected", [output]) is False


def test_stage_manifest_rejects_partial_output_hash_mapping() -> None:
    with pytest.raises(ValidationError):
        _manifest(
            fingerprint="fingerprint",
            outputs=["reports/first.json", "reports/second.json"],
            output_sha256={"reports/first.json": "a" * 64},
        )


def test_stage_manifest_rejects_duplicate_normalized_outputs() -> None:
    with pytest.raises(ValidationError):
        _manifest(
            fingerprint="fingerprint",
            outputs=["reports/summary.json", "reports/./summary.json"],
        )


def test_stage_manifest_rejects_noncanonical_output_hash() -> None:
    with pytest.raises(ValidationError):
        _manifest(
            fingerprint="fingerprint",
            outputs=["reports/summary.json"],
            output_sha256={"reports/summary.json": "A" * 64},
        )


def test_stage_manifest_requires_at_least_one_output() -> None:
    with pytest.raises(ValidationError):
        _manifest(fingerprint="fingerprint", outputs=[])


def test_stage_manifest_round_trips_through_atomic_write(tmp_path: Path) -> None:
    output = tmp_path / "out.jsonl"
    output.write_text("ready\n", encoding="utf-8")
    manifest = _manifest(fingerprint="fingerprint", outputs=[output])
    manifest_path = tmp_path / "manifests" / "discovery.json"

    write_stage_manifest(manifest_path, manifest)

    assert read_stage_manifest(manifest_path) == manifest
    assert list(manifest_path.parent.glob("*.tmp")) == []


def test_oracle_stage_manifest_requires_and_round_trips_policy_digest(
    tmp_path: Path,
) -> None:
    output = tmp_path / "oracle.jsonl"
    output.write_text("ready\n", encoding="utf-8")
    manifest = StageManifest(
        schema_version="1.0",
        stage="run-oracle-observed",
        fingerprint="fingerprint",
        inputs={"generation/observed_code.jsonl": "input-sha"},
        config_sha256="config-sha",
        code_version="test-version",
        policy_sha256="b" * 64,
        outputs=[output],
        output_sha256={output: sha256_path(output)},
    )
    manifest_path = tmp_path / "oracle-manifest.json"

    write_stage_manifest(manifest_path, manifest)

    assert read_stage_manifest(manifest_path).policy_sha256 == "b" * 64


def test_oracle_manifest_rejects_missing_or_noncanonical_policy_digest() -> None:
    payload = _manifest(
        fingerprint="fingerprint",
        outputs=["oracle/observed_oracle.jsonl"],
    ).model_dump(mode="python")
    payload["stage"] = "run-oracle-observed"

    with pytest.raises(ValidationError):
        StageManifest.model_validate(payload)

    payload["policy_sha256"] = "B" * 64
    with pytest.raises(ValidationError):
        StageManifest.model_validate(payload)


def test_non_oracle_manifest_rejects_policy_digest() -> None:
    payload = _manifest(
        fingerprint="fingerprint",
        outputs=["reports/summary.json"],
    ).model_dump(mode="python")
    payload["policy_sha256"] = "b" * 64

    with pytest.raises(ValidationError):
        StageManifest.model_validate(payload)


def test_legacy_non_oracle_manifest_without_policy_digest_remains_readable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.json"
    path.write_text(
        """{
  "schema_version": "1.0",
  "stage": "report",
  "fingerprint": "fingerprint",
  "inputs": {},
  "config_sha256": "config-sha",
  "code_version": "test-version",
  "outputs": ["reports/summary.json"],
  "output_sha256": {}
}\n""",
        encoding="utf-8",
    )

    assert read_stage_manifest(path).policy_sha256 is None


def test_manifest_allows_skip_only_for_matching_manifest_and_existing_outputs(
    tmp_path: Path,
) -> None:
    output = tmp_path / "out.jsonl"
    output.write_text("ready\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    write_stage_manifest(
        manifest_path,
        _manifest(fingerprint="expected", outputs=[output]),
    )

    assert manifest_allows_skip(manifest_path, "expected", [output]) is True
    assert manifest_allows_skip(manifest_path, "expected", [output], force=True) is False
    assert manifest_allows_skip(manifest_path, "different", [output]) is False

    output.write_text("tampered\n", encoding="utf-8")
    assert manifest_allows_skip(manifest_path, "expected", [output]) is False

    output.unlink()
    assert manifest_allows_skip(manifest_path, "expected", [output]) is False


def test_manifest_skip_requires_matching_oracle_policy_digest(tmp_path: Path) -> None:
    output = tmp_path / "oracle.jsonl"
    output.write_text("ready\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest = StageManifest(
        schema_version="1.0",
        stage="run-oracle-observed",
        fingerprint="expected",
        inputs={"generation/observed_code.jsonl": "input-sha"},
        config_sha256="config-sha",
        code_version="test-version",
        policy_sha256="b" * 64,
        outputs=[output],
        output_sha256={output: sha256_path(output)},
    )
    write_stage_manifest(manifest_path, manifest)

    assert manifest_allows_skip(
        manifest_path,
        "expected",
        [output],
        policy_sha256="b" * 64,
    )
    assert not manifest_allows_skip(
        manifest_path,
        "expected",
        [output],
        policy_sha256="c" * 64,
    )


def test_manifest_allows_skip_rejects_missing_invalid_or_wrong_outputs(
    tmp_path: Path,
) -> None:
    expected_output = tmp_path / "expected.jsonl"
    expected_output.write_text("ready\n", encoding="utf-8")
    missing_manifest = tmp_path / "missing.json"

    assert manifest_allows_skip(missing_manifest, "expected", [expected_output]) is False

    invalid_manifest = tmp_path / "invalid.json"
    invalid_manifest.write_text("not-json", encoding="utf-8")
    assert manifest_allows_skip(invalid_manifest, "expected", [expected_output]) is False

    other_output = tmp_path / "other.jsonl"
    other_output.write_text("ready\n", encoding="utf-8")
    write_stage_manifest(
        invalid_manifest,
        _manifest(fingerprint="expected", outputs=[other_output]),
    )
    assert manifest_allows_skip(invalid_manifest, "expected", [expected_output]) is False


def test_manifest_allows_skip_hashes_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "artifact-directory"
    output.mkdir()
    (output / "artifact.jsonl").write_text("ready\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    write_stage_manifest(
        manifest_path,
        _manifest(fingerprint="expected", outputs=[output]),
    )

    assert manifest_allows_skip(manifest_path, "expected", [output]) is True

    (output / "artifact.jsonl").write_text("tampered\n", encoding="utf-8")
    assert manifest_allows_skip(manifest_path, "expected", [output]) is False


def test_manifest_allows_skip_rejects_an_empty_output_path_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe_manifest = StageManifest.model_construct(
        schema_version="1.0",
        stage="discovery",
        fingerprint="expected",
        inputs={"inputs/prompts.jsonl": "input-sha"},
        config_sha256="config-sha",
        code_version="test-version",
        outputs=[],
        output_sha256={},
    )
    monkeypatch.setattr(
        manifest_module,
        "read_stage_manifest",
        lambda path: unsafe_manifest,
    )

    assert manifest_allows_skip(tmp_path / "manifest.json", "expected", []) is False

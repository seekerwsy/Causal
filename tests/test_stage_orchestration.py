import json
import os
from pathlib import Path
import traceback

import pytest

from secaware import __version__
from secaware.cli import generate_observed_stage
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io import run_store as run_store_module
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_file, sha256_path
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.records import GeneratedCodeRecord, PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _assert_manifest_error_is_safe(error: SecAwareError, *hidden: str) -> None:
    surfaces = (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), sort_keys=True),
    )
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.details == {}
    for value in hidden:
        assert all(value not in surface for surface in surfaces)


def _store(tmp_path: Path, *, bootstrap_samples: int = 200) -> RunStore:
    config = AppConfig.model_validate(
        {
            "run": {"name": "stage-test", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(tmp_path / "source-prompts.jsonl")},
            "analysis": {"bootstrap_samples": bootstrap_samples},
        }
    )
    store = RunStore(config)
    store.mkdirs()
    return store


def _input_and_output(store: RunStore) -> tuple[Path, Path]:
    input_path = store.path("inputs", "source.txt")
    output_path = store.path("reports", "result.txt")
    input_path.write_text("input-v1\n", encoding="utf-8")
    output_path.write_text("output-v1\n", encoding="utf-8")
    return input_path, output_path


def _record_report_stage(store: RunStore, input_path: Path, outputs: list[Path]) -> Path:
    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False
    store.record_stage("report", [input_path], outputs)
    manifest_path = store.path(".stages", "report.json")
    assert manifest_path.is_file()
    return manifest_path


def _file_provider_store(tmp_path: Path, provider_dir: Path) -> tuple[AppConfig, RunStore]:
    prompts_path = tmp_path / "source-prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-1",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt="write a helper",
            )
        ],
    )
    config = AppConfig.model_validate(
        {
            "run": {"name": "file-provider", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(prompts_path)},
            "generation": {
                "provider": "file",
                "models": ["model-a"],
                "seeds": [7],
                "file_provider_dir": str(provider_dir),
            },
        }
    )
    store = RunStore(config)
    store.prepare()
    return config, store


def test_mkdirs_creates_private_stage_manifest_directory(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert store.path(".stages").is_dir()


@pytest.mark.parametrize("failure", ["copy", "write_config"])
def test_prepare_wraps_expected_filesystem_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    store = _store(tmp_path)
    prompts_path = Path(store.config.data.prompts_path)
    prompts_path.write_text("source\n", encoding="utf-8")

    def fail_with_private_error(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("top-secret filesystem detail")

    if failure == "copy":
        monkeypatch.setattr(run_store_module.shutil, "copyfile", fail_with_private_error)
    else:
        monkeypatch.setattr(run_store_module, "write_resolved_config", fail_with_private_error)

    with pytest.raises(SecAwareError) as exc_info:
        store.prepare()

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.stage == "prepare"
    assert set(exc_info.value.details) == {"path"}
    assert "top-secret" not in str(exc_info.value)


def test_stage_is_skippable_only_after_matching_manifest_is_recorded(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    store.record_stage("report", [input_path], [output_path])

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True
    manifest_path = store.path(".stages", "report.json")
    assert manifest_path.is_file()
    manifest = read_stage_manifest(manifest_path)
    assert manifest.schema_version == "1.0"
    assert manifest.stage == "report"
    assert manifest.inputs == {"inputs/source.txt": sha256_file(input_path)}
    assert manifest.outputs == ["reports/result.txt"]
    assert manifest.output_sha256 == {"reports/result.txt": sha256_path(output_path)}
    assert manifest.config_sha256 == canonical_sha256(store.config.model_dump(mode="json"))
    assert manifest.code_version == __version__
    assert manifest.fingerprint == store.stage_fingerprint("report", [input_path])


def test_successful_skip_does_not_authorize_a_later_stage_record(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True
    output_path.write_text("changed-without-execution\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()


def test_stage_inputs_rejects_a_missing_required_input(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        store.stage_inputs([store.path("inputs", "missing.jsonl")])

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_file_provider_directory_change_invalidates_generation_stage(tmp_path: Path) -> None:
    provider_dir = tmp_path / "provider-files"
    provider_dir.mkdir()
    generated_path = provider_dir / "model-a_7.py"
    generated_path.write_text("result = 'first'\n", encoding="utf-8")
    config, store = _file_provider_store(tmp_path, provider_dir)

    generate_observed_stage(config, store, force=False)

    manifest = read_stage_manifest(store.path(".stages", "generate-observed.json"))
    relative_provider_dir = Path(os.path.relpath(provider_dir, store.root)).as_posix()
    assert relative_provider_dir in manifest.inputs
    generated_path.write_text("result = 'second'\n", encoding="utf-8")

    generate_observed_stage(config, store, force=False)

    records = read_jsonl(
        store.path("generation", "observed_code.jsonl"),
        GeneratedCodeRecord,
        required=True,
    )
    assert records[0].code == "result = 'second'\n"


def test_missing_file_provider_directory_is_a_contract_error(tmp_path: Path) -> None:
    config, store = _file_provider_store(tmp_path, tmp_path / "missing-provider-files")

    with pytest.raises(SecAwareError) as exc_info:
        generate_observed_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_stage_skip_is_invalidated_by_input_content_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.record_stage("report", [input_path], [output_path])

    input_path.write_text("input-v2\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_stage_skip_is_invalidated_by_resolved_config_change(tmp_path: Path) -> None:
    original_store = _store(tmp_path, bootstrap_samples=200)
    input_path, output_path = _input_and_output(original_store)
    assert (
        original_store.should_skip_stage(
            "report",
            [input_path],
            [output_path],
            force=False,
        )
        is False
    )
    original_store.record_stage("report", [input_path], [output_path])
    changed_store = _store(tmp_path, bootstrap_samples=201)

    assert (
        changed_store.should_skip_stage(
            "report",
            [input_path],
            [output_path],
            force=False,
        )
        is False
    )


def test_stage_skip_requires_every_declared_output(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, first_output = _input_and_output(store)
    second_output = store.path("reports", "second.txt")
    second_output.write_text("second\n", encoding="utf-8")
    outputs = [first_output, second_output]
    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False
    store.record_stage("report", [input_path], outputs)

    second_output.unlink()

    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False


def test_stage_skip_is_invalidated_by_output_content_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])

    output_path.write_text("tampered-output\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    assert not manifest_path.exists()


def test_record_stage_hashes_directory_outputs(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")
    output_path = store.path("reports", "directory-output")
    output_path.mkdir()
    (output_path / "result.txt").write_text("output\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.record_stage("report", [input_path], [output_path])

    manifest = read_stage_manifest(store.path(".stages", "report.json"))
    assert manifest.output_sha256 == {"reports/directory-output": sha256_path(output_path)}
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True


def test_sealed_output_hash_is_committed_as_the_manifest_expectation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    expected_hash = sha256_path(output_path)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    store.seal_stage_outputs("report", [output_path])
    store.record_stage("report", [input_path], [output_path])

    manifest = read_stage_manifest(store.path(".stages", "report.json"))
    assert manifest.output_sha256 == {"reports/result.txt": expected_hash}


@pytest.mark.parametrize("misuse", ["without_pending", "duplicate", "paths_mismatch"])
def test_output_seal_misuse_invalidates_all_stage_authorization(
    tmp_path: Path,
    misuse: str,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    if misuse == "without_pending":
        manifest_path = _record_report_stage(store, input_path, [output_path])
    else:
        assert store.should_skip_stage(
            "report", [input_path], [output_path], force=False
        ) is False
        if misuse == "duplicate":
            store.seal_stage_outputs("report", [output_path])
    seal_outputs = [output_path]
    if misuse == "paths_mismatch":
        other_output = store.path("reports", "other.txt")
        other_output.write_text("other\n", encoding="utf-8")
        seal_outputs = [other_output]

    with pytest.raises(SecAwareError) as exc_info:
        store.seal_stage_outputs("report", seal_outputs)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value)
    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as record_info:
        store.record_stage("report", [input_path], [output_path])
    assert record_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_output_seal_path_escape_is_a_safe_manifest_conflict(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    outside_output = tmp_path / "private-outside-output.txt"
    outside_output.write_text("private output\n", encoding="utf-8")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.seal_stage_outputs("report", [outside_output])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(
        exc_info.value,
        str(outside_output),
        "private-outside-output",
    )
    with pytest.raises(SecAwareError):
        store.record_stage("report", [input_path], [output_path])


def test_output_seal_hash_failure_is_safe_and_clears_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    secret = "private-seal-hash-failure"
    real_sha256_path = run_store_module.sha256_path
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    def fail_output_hash(path: Path) -> str:
        if Path(path) == output_path:
            raise OSError(secret)
        return real_sha256_path(path)

    monkeypatch.setattr(run_store_module, "sha256_path", fail_output_hash)

    with pytest.raises(SecAwareError) as exc_info:
        store.seal_stage_outputs("report", [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value, secret, str(output_path), "OSError")
    with pytest.raises(SecAwareError):
        store.record_stage("report", [input_path], [output_path])


def test_generation_stage_record_requires_a_prior_output_seal(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    stage = "plan-generation-observed"
    assert store.should_skip_stage(stage, [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage(stage, [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", f"{stage}.json").exists()


def test_record_stage_rejects_output_changed_after_manifest_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    real_write = run_store_module.write_stage_manifest

    def write_then_change(path: Path, manifest: object) -> None:
        real_write(path, manifest)
        output_path.write_text("changed-after-manifest-write\n", encoding="utf-8")

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_change)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert exc_info.value.details == {}
    assert not manifest_path.exists()


def test_record_stage_wraps_manifest_publish_failure_without_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    real_write = run_store_module.write_stage_manifest
    secret = "private-manifest-publish-error"

    def write_then_fail(path: Path, manifest: object) -> None:
        real_write(path, manifest)
        raise OSError(secret)

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_fail)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(
        exc_info.value,
        secret,
        str(output_path),
        "OSError",
    )
    assert not manifest_path.exists()


def test_record_stage_wraps_output_hash_failure_without_path_or_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    real_sha256_path = run_store_module.sha256_path
    secret = "private-output-hash-error"

    def fail_output_hash(path: Path) -> str:
        if Path(path) == output_path:
            raise OSError(secret)
        return real_sha256_path(path)

    monkeypatch.setattr(run_store_module, "sha256_path", fail_output_hash)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    error = exc_info.value
    assert error.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(error, secret, str(output_path), "OSError")
    assert not manifest_path.exists()


def test_force_disables_stage_skip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False
    store.record_stage("report", [input_path], [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True


@pytest.mark.parametrize("invalidation", ["force", "input", "config", "outputs"])
def test_execution_decision_invalidates_previous_manifest(
    tmp_path: Path,
    invalidation: str,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    outputs = [output_path]
    manifest_path = _record_report_stage(store, input_path, outputs)
    force = invalidation == "force"
    if invalidation == "input":
        input_path.write_text("changed-input\n", encoding="utf-8")
    elif invalidation == "config":
        store.config.analysis.bootstrap_samples += 1
    elif invalidation == "outputs":
        second_output = store.path("reports", "second.txt")
        second_output.write_text("second\n", encoding="utf-8")
        outputs = [output_path, second_output]

    assert store.should_skip_stage("report", [input_path], outputs, force=force) is False
    assert not manifest_path.exists()


def test_failed_stage_cannot_reuse_manifest_after_partial_output_overwrite(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])

    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False
    assert not manifest_path.exists()
    output_path.write_text("partial-stage-output\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_record_conflict_cannot_restore_stale_manifest_skip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    original_input = input_path.read_text(encoding="utf-8")
    manifest_path = _record_report_stage(store, input_path, [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False
    output_path.write_text("partial-stage-output\n", encoding="utf-8")
    input_path.write_text("changed-during-stage\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()
    input_path.write_text(original_input, encoding="utf-8")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_manifest_invalidation_wraps_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    _record_report_stage(store, input_path, [output_path])

    def fail_unlink(path: Path, missing_ok: bool = False) -> None:
        del path, missing_ok
        raise OSError("private filesystem failure")

    monkeypatch.setattr(Path, "unlink", fail_unlink)

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage("report", [input_path], [output_path], force=True)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert "private filesystem failure" not in str(exc_info.value)


def test_public_stage_invalidation_clears_manifest_and_pending_snapshot(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False

    store.invalidate_stage("report")

    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])
    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_record_stage_rejects_a_missing_declared_output(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")
    output_path = store.path("reports", "missing.txt")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage(
            "report",
            [input_path],
            [output_path],
        )

    assert exc_info.value.code is ErrorCode.CONTRACT

    output_path.write_text("late-output\n", encoding="utf-8")
    with pytest.raises(SecAwareError) as retry_info:
        store.record_stage("report", [input_path], [output_path])

    assert retry_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_record_stage_requires_an_execution_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "report.json").exists()


def test_record_stage_rejects_input_changed_after_execution_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    input_path.write_text("changed-during-stage\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "report.json").exists()


def test_record_stage_rejects_config_changed_after_execution_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.config.analysis.bootstrap_samples += 1

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "report.json").exists()


def test_record_stage_rejects_output_path_escape(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")
    outside_output = tmp_path / "outside.txt"
    outside_output.write_text("outside\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [outside_output])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not store.path(".stages", "report.json").exists()


def test_cli_source_no_longer_calls_legacy_should_skip() -> None:
    source = (PROJECT_ROOT / "src" / "secaware" / "cli.py").read_text(encoding="utf-8")

    assert ".should_skip(" not in source

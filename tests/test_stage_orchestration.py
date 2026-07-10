import os
from pathlib import Path

import pytest

from secaware import __version__
from secaware.cli import generate_observed_stage
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.records import GeneratedCodeRecord, PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
    assert manifest.config_sha256 == canonical_sha256(store.config.model_dump(mode="json"))
    assert manifest.code_version == __version__
    assert manifest.fingerprint == store.stage_fingerprint("report", [input_path])


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

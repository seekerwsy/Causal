from pathlib import Path

import pytest

from secaware import __version__
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.pipeline.manifest import read_stage_manifest


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


def test_mkdirs_creates_private_stage_manifest_directory(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert store.path(".stages").is_dir()


def test_stage_is_skippable_only_after_matching_manifest_is_recorded(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    store.record_stage("report", [input_path], [output_path])

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True
    manifest = read_stage_manifest(store.path(".stages", "report.json"))
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


def test_stage_skip_is_invalidated_by_input_content_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    store.record_stage("report", [input_path], [output_path])

    input_path.write_text("input-v2\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_stage_skip_is_invalidated_by_resolved_config_change(tmp_path: Path) -> None:
    original_store = _store(tmp_path, bootstrap_samples=200)
    input_path, output_path = _input_and_output(original_store)
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
    store.record_stage("report", [input_path], outputs)

    second_output.unlink()

    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False


def test_force_disables_stage_skip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    store.record_stage("report", [input_path], [output_path])

    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False


def test_record_stage_rejects_a_missing_declared_output(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage(
            "report",
            [input_path],
            [store.path("reports", "missing.txt")],
        )

    assert exc_info.value.code is ErrorCode.CONTRACT


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

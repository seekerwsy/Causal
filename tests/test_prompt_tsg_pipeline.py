import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app, extract_prompt_tsg_stage
from secaware.config import load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256


def _prepared_store(tmp_path: Path) -> tuple[object, RunStore]:
    config = load_config("configs/demo.yaml", run_dir=tmp_path / "run")
    store = RunStore(config)
    store.prepare()
    return config, store


def test_prompt_tsg_stage_records_catalog_bound_exact_v2_artifact(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)

    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]

    output = store.path("tsg", "prompt_tsg.jsonl")
    records = read_jsonl(output, PromptTSGRecord, required=True, allow_empty=False)
    manifest = read_stage_manifest(store.path(".stages", "extract-prompt-tsg.json"))
    assert records
    assert all(type(record) is PromptTSGRecord for record in records)
    assert all(record.schema_version == "2.0" for record in records)
    assert manifest.catalog_sha256 == PROMPT_TSG_CATALOG_SHA256


def test_prompt_tsg_committed_output_rejects_catalog_mismatch(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]

    with pytest.raises(SecAwareError) as exc_info:
        with store.hold_committed_output(
            "extract-prompt-tsg",
            [store.path("tsg", "prompt_tsg.jsonl")],
            expected_catalog_sha256="0" * 64,
        ):
            pytest.fail("catalog mismatch was accepted")

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_prompt_tsg_manifest_tamper_is_not_skippable(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["catalog_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    assert not store.should_skip_stage(
        "extract-prompt-tsg",
        [store.path("inputs", "prompts.jsonl")],
        [store.path("tsg", "prompt_tsg.jsonl")],
        False,
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    store.abort_stage("extract-prompt-tsg")


def test_removed_graph_extraction_command_is_absent_from_cli_help() -> None:
    help_result = CliRunner().invoke(app, ["--help"])
    removed_command = "extract-" + "code-" + "tsg"

    assert help_result.exit_code == 0
    assert removed_command not in help_result.output


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("private-failure"), KeyboardInterrupt("private-interrupt")],
    ids=["error", "interrupt"],
)
def test_prompt_tsg_force_failure_restores_committed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    output = store.path("tsg", "prompt_tsg.jsonl")
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    previous = (output.read_bytes(), manifest_path.read_bytes())

    def fail_extraction(prompt: object) -> object:
        del prompt
        raise failure

    monkeypatch.setattr(cli_module, "extract_prompt_tsg", fail_extraction)

    with pytest.raises(type(failure)):
        extract_prompt_tsg_stage(config, store, force=True)  # type: ignore[arg-type]

    assert (output.read_bytes(), manifest_path.read_bytes()) == previous
    with store.hold_committed_output(
        "extract-prompt-tsg",
        [output],
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ):
        pass
    assert not store.stage_is_active("extract-prompt-tsg")

import json
from pathlib import Path
import threading

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app, extract_prompt_tsg_stage
from secaware.config import load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.io import run_store as run_store_module
from secaware.pipeline import jsonl_stage as jsonl_stage_module
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256
from secaware.tsg.contract import (
    PROMPT_TSG_EXTRACTOR_VERSION,
    TSG_SCHEMA_VERSION,
    build_prompt_tsg_stage_contract_sha256,
)


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
    assert all(record.schema_version == "2.1" for record in records)
    assert manifest.catalog_sha256 == PROMPT_TSG_CATALOG_SHA256


def test_prompt_tsg_contract_digest_binds_extractor_schema_and_catalog_versions() -> None:
    baseline = build_prompt_tsg_stage_contract_sha256()

    assert (
        build_prompt_tsg_stage_contract_sha256(
            extractor_version=PROMPT_TSG_EXTRACTOR_VERSION + ".next"
        )
        != baseline
    )
    assert (
        build_prompt_tsg_stage_contract_sha256(schema_version=TSG_SCHEMA_VERSION + ".next")
        != baseline
    )
    assert build_prompt_tsg_stage_contract_sha256(catalog_sha256="0" * 64) != baseline


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


def test_prompt_tsg_input_aware_committed_gate_requires_expected_catalog(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    inputs = [store.path("inputs", "prompts.jsonl")]
    outputs = [store.path("tsg", "prompt_tsg.jsonl")]

    expected = store.require_committed_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    )
    with store.hold_committed_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ) as held:
        assert held == expected

    for catalog_sha256 in (None, "0" * 64):
        with pytest.raises(SecAwareError) as exc_info:
            store.require_committed_stage(
                "extract-prompt-tsg",
                inputs,
                outputs,
                expected_catalog_sha256=catalog_sha256,
            )
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_prompt_tsg_committed_output_rejects_real_output_tamper(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    output = store.path("tsg", "prompt_tsg.jsonl")
    output.write_bytes(output.read_bytes() + b"\n")

    with pytest.raises(SecAwareError) as exc_info:
        with store.hold_committed_output(
            "extract-prompt-tsg",
            [output],
            expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        ):
            pytest.fail("tampered Prompt TSG output was accepted")

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_prompt_tsg_producer_lease_blocks_real_concurrent_force(
    tmp_path: Path,
) -> None:
    config, owner = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, owner, force=False)  # type: ignore[arg-type]
    contender = RunStore(config)  # type: ignore[arg-type]
    output = owner.path("tsg", "prompt_tsg.jsonl")

    with owner.hold_committed_output(
        "extract-prompt-tsg",
        [output],
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ):
        with pytest.raises(SecAwareError) as exc_info:
            extract_prompt_tsg_stage(config, contender, force=True)  # type: ignore[arg-type]

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    extract_prompt_tsg_stage(config, contender, force=True)  # type: ignore[arg-type]


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


def test_prompt_tsg_stage_contract_change_invalidates_skip_only_for_prompt_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    prompt_input = store.path("inputs", "prompts.jsonl")
    prompt_output = store.path("tsg", "prompt_tsg.jsonl")
    report_output = store.path("reports", "result.txt")
    report_output.write_text("ready\n", encoding="utf-8")
    assert not store.should_skip_stage("report", [prompt_input], [report_output], force=False)
    store.record_stage("report", [prompt_input], [report_output])
    report_fingerprint = store.stage_fingerprint("report", [prompt_input])

    monkeypatch.setattr(
        run_store_module,
        "PROMPT_TSG_STAGE_CONTRACT_SHA256",
        "f" * 64,
        raising=False,
    )

    assert not store.should_skip_stage(
        "extract-prompt-tsg",
        [prompt_input],
        [prompt_output],
        force=False,
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    store.abort_stage("extract-prompt-tsg")
    assert store.stage_fingerprint("report", [prompt_input]) == report_fingerprint
    assert store.should_skip_stage("report", [prompt_input], [report_output], force=False)


def test_prompt_tsg_seal_rejection_retains_lease_until_rollback_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, owner = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, owner, force=False)  # type: ignore[arg-type]
    contender = RunStore(config)  # type: ignore[arg-type]
    output = owner.path("tsg", "prompt_tsg.jsonl")
    manifest_path = owner.path(".stages", "extract-prompt-tsg.json")
    previous = (output.read_bytes(), manifest_path.read_bytes())
    inputs = [owner.path("inputs", "prompts.jsonl")]
    outputs = [output]
    rollback_entered = threading.Event()
    allow_rollback = threading.Event()
    owner_done = threading.Event()
    owner_errors: list[BaseException] = []
    real_verify = owner.verify_sealed_outputs
    real_recover = jsonl_stage_module.recover_transaction

    def tamper_after_seal(*args: object, **kwargs: object) -> None:
        output.write_bytes(output.read_bytes() + b"\n")
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    def blocked_recover(transaction: object) -> None:
        rollback_entered.set()
        if not allow_rollback.wait(timeout=5):
            raise AssertionError("rollback was not released")
        real_recover(transaction)  # type: ignore[arg-type]

    def run_owner() -> None:
        try:
            extract_prompt_tsg_stage(config, owner, force=True)  # type: ignore[arg-type]
        except BaseException as error:
            owner_errors.append(error)
        finally:
            owner_done.set()

    monkeypatch.setattr(owner, "verify_sealed_outputs", tamper_after_seal)
    monkeypatch.setattr(jsonl_stage_module, "recover_transaction", blocked_recover)
    thread = threading.Thread(target=run_owner, daemon=True)
    thread.start()
    assert rollback_entered.wait(timeout=5)

    contender_entered = False
    try:
        contender_entered = not contender.should_skip_stage(
            "extract-prompt-tsg",
            inputs,
            outputs,
            force=True,
            catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
            preserve_committed=True,
        )
    except SecAwareError as error:
        assert error.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        if contender.stage_is_active("extract-prompt-tsg"):
            contender.abort_stage("extract-prompt-tsg")
        allow_rollback.set()

    assert owner_done.wait(timeout=5)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert contender_entered is False
    assert len(owner_errors) == 1
    assert isinstance(owner_errors[0], SecAwareError)
    assert (output.read_bytes(), manifest_path.read_bytes()) == previous
    assert not owner.stage_is_active("extract-prompt-tsg")

    assert not contender.should_skip_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        force=True,
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    contender.abort_stage("extract-prompt-tsg")

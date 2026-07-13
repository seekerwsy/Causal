import json
from pathlib import Path
import threading
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from secaware.cli import _prompt_records, app, extract_prompt_tsg_stage
from secaware.config import load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.io import run_store as run_store_module
from secaware.pipeline import jsonl_stage as jsonl_stage_module
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.stages.prompt_extraction import (
    run_prompt_extraction_stage,
    validate_exact_extraction_coverage,
)
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256
from secaware.tsg.contract import (
    PROMPT_TSG_EXTRACTOR_VERSION,
    TSG_SCHEMA_VERSION,
    build_prompt_tsg_stage_contract_sha256,
)
from secaware.extractors.factory import extraction_policy


def _prepared_store(tmp_path: Path) -> tuple[object, RunStore]:
    config = load_config("configs/demo.yaml", run_dir=tmp_path / "run")
    store = RunStore(config)
    store.prepare()
    return config, store


def _prompt_extraction_outputs(store: RunStore) -> list[Path]:
    return [
        store.path("tsg", "prompt_extraction_proposals.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
    ]


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


def test_prompt_extraction_stage_commits_exact_proposal_and_graph_coverage(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)

    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]

    proposal_output = store.path("tsg", "prompt_extraction_proposals.jsonl")
    graph_output = store.path("tsg", "prompt_tsg.jsonl")
    proposals = read_jsonl(
        proposal_output,
        PromptExtractionProposalRecord,
        required=True,
        allow_empty=False,
    )
    graphs = read_jsonl(graph_output, PromptTSGRecord, required=True, allow_empty=False)
    manifest = read_stage_manifest(store.path(".stages", "extract-prompt-tsg.json"))
    assert [item.prompt_id for item in proposals] == [item.prompt_id for item in graphs]
    assert [item.proposal_id for item in proposals] == [item.proposal_id for item in graphs]
    assert manifest.outputs == [
        "tsg/prompt_extraction_proposals.jsonl",
        "tsg/prompt_tsg.jsonl",
    ]
    assert manifest.policy_sha256 == extraction_policy(config.tsg).policy_sha256  # type: ignore[union-attr]


def test_exact_coverage_rejects_omission_duplicate_extra_mixed_and_stale_records(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    prompts = tuple(_prompt_records(store))
    proposals = tuple(
        read_jsonl(
            store.path("tsg", "prompt_extraction_proposals.jsonl"),
            PromptExtractionProposalRecord,
            required=True,
            allow_empty=False,
        )
    )
    graphs = tuple(
        read_jsonl(
            store.path("tsg", "prompt_tsg.jsonl"),
            PromptTSGRecord,
            required=True,
            allow_empty=False,
        )
    )
    policy = extraction_policy(config.tsg)  # type: ignore[union-attr]

    invalid_cases = (
        (prompts, proposals[:-1], graphs[:-1]),
        (prompts, proposals[:-1] + proposals[:1], graphs),
        (prompts, proposals + proposals[:1], graphs + graphs[:1]),
        (
            prompts,
            proposals[:-1]
            + (proposals[-1].model_copy(update={"backend": PromptExtractorBackend.LLM_FACTS_V1}),),
            graphs,
        ),
        (
            prompts,
            proposals[:-1] + (proposals[-1].model_copy(update={"catalog_sha256": "0" * 64}),),
            graphs,
        ),
        (
            prompts,
            proposals[:-1] + (proposals[-1].model_copy(update={"policy_sha256": "f" * 64}),),
            graphs,
        ),
    )
    for source, candidates, records in invalid_cases:
        with pytest.raises(SecAwareError) as exc_info:
            validate_exact_extraction_coverage(source, candidates, records, policy)
        assert exc_info.value.code is ErrorCode.CONTRACT


def test_prompt_extraction_force_failure_restores_both_artifacts_and_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    paths = (
        store.path("tsg", "prompt_extraction_proposals.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path(".stages", "extract-prompt-tsg.json"),
    )
    previous = tuple(path.read_bytes() for path in paths)
    calls: list[str] = []

    class ExplodingExtractor:
        def extract(self, prompt: object, policy: object) -> object:
            del prompt, policy
            calls.append("selected-backend")
            raise RuntimeError("selected backend failed")

    monkeypatch.setattr(
        stage_module,
        "extractor_for_config",
        lambda *_args, **_kwargs: ExplodingExtractor(),
    )
    with pytest.raises(RuntimeError, match="selected backend failed"):
        run_prompt_extraction_stage(config, store, force=True)  # type: ignore[arg-type]

    assert calls == ["selected-backend"]
    assert tuple(path.read_bytes() for path in paths) == previous
    assert not store.stage_is_active("extract-prompt-tsg")


def test_prompt_extraction_policy_drift_invalidates_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    baseline = extraction_policy(config.tsg)  # type: ignore[union-attr]
    calls = 0
    real_factory = stage_module.extractor_for_config
    real_policy = stage_module.extraction_policy

    class CountingExtractor:
        def __init__(self, nested: object) -> None:
            self.nested = nested

        def extract(self, prompt: object, policy: object) -> object:
            nonlocal calls
            calls += 1
            return self.nested.extract(prompt, policy)  # type: ignore[attr-defined]

    monkeypatch.setattr(
        stage_module,
        "extractor_for_config",
        lambda *args, **kwargs: CountingExtractor(real_factory(*args, **kwargs)),
    )
    monkeypatch.setattr(
        stage_module,
        "extraction_policy",
        lambda value: replace(real_policy(value), policy_sha256="f" * 64),
    )

    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    assert calls == len(_prompt_records(store))
    manifest = read_stage_manifest(store.path(".stages", "extract-prompt-tsg.json"))
    assert manifest.policy_sha256 == "f" * 64
    assert manifest.policy_sha256 != baseline.policy_sha256


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
    outputs = _prompt_extraction_outputs(store)

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
    outputs = _prompt_extraction_outputs(owner)

    with owner.hold_committed_output(
        "extract-prompt-tsg",
        outputs,
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
        _prompt_extraction_outputs(store),
        False,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
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
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    outputs = _prompt_extraction_outputs(store)
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    previous = tuple(path.read_bytes() for path in (*outputs, manifest_path))

    class FailingExtractor:
        def extract(self, prompt: object, policy: object) -> object:
            del prompt, policy
            raise failure

    monkeypatch.setattr(
        stage_module,
        "extractor_for_config",
        lambda *_args, **_kwargs: FailingExtractor(),
    )

    with pytest.raises(type(failure)):
        extract_prompt_tsg_stage(config, store, force=True)  # type: ignore[arg-type]

    assert tuple(path.read_bytes() for path in (*outputs, manifest_path)) == previous
    with store.hold_committed_output(
        "extract-prompt-tsg",
        outputs,
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
    prompt_outputs = _prompt_extraction_outputs(store)
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
        prompt_outputs,
        force=False,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
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
    pair_outputs = _prompt_extraction_outputs(owner)
    previous = tuple(path.read_bytes() for path in (*pair_outputs, manifest_path))
    inputs = [owner.path("inputs", "prompts.jsonl")]
    outputs = pair_outputs
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
            policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
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
    assert tuple(path.read_bytes() for path in (*pair_outputs, manifest_path)) == previous
    assert not owner.stage_is_active("extract-prompt-tsg")

    assert not contender.should_skip_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        force=True,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    contender.abort_stage("extract-prompt-tsg")

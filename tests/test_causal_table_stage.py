from __future__ import annotations

from pathlib import Path
from contextlib import contextmanager

import pytest

from secaware.cli import generate_observed_stage
from secaware.config import AppConfig
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.stages.prompt_extraction import run_prompt_extraction_stage
from secaware.pipeline.manifest import read_stage_manifest
from secaware.extractors.factory import extraction_policy
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.causal import (
    CausalExclusionRecord,
    CausalObservationRecord,
    CausalTableRecord,
)
from secaware.schema.oracle import (
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    OracleRecord,
    SecurityLabel,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.errors import ErrorCode, SecAwareError


def _config(source: Path, run_dir: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "run": {"name": "stage-test", "random_seed": 17, "output_dir": str(run_dir)},
            "data": {
                "prompts_path": str(source),
                "prompt_attestations_path": str(source.parent / "attestations.jsonl"),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
            "discovery": {
                "bootstrap_samples": 3,
                "min_independent_tasks": 2,
                "stability_threshold": 0.8,
            },
            "generation": {"provider": "mock", "models": ["model-a"], "seeds": [7]},
        }
    )


def _prompts() -> tuple[PromptRecord, ...]:
    return (
        PromptRecord(
            prompt_id="discover-1",
            task_id="task-1",
            split="discover",
            language="python",
            task_family="file_access",
            cwe="CWE-22",
            prompt="Write a Python function that reads a user-selected file path.",
            prompt_role="neutral_baseline",
            counterpart_prompt_id=None,
        ),
        PromptRecord(
            prompt_id="discover-2",
            task_id="task-2",
            split="discover",
            language="python",
            task_family="file_access",
            cwe="CWE-22",
            prompt="Implement a Python helper that opens a requested file path.",
            prompt_role="neutral_baseline",
            counterpart_prompt_id=None,
        ),
        PromptRecord(
            prompt_id="confirm-1",
            task_id="task-3",
            split="confirm",
            language="python",
            task_family="file_access",
            cwe="CWE-22",
            prompt="Create a Python utility that loads a file selected by the caller.",
            prompt_role="neutral_baseline",
            counterpart_prompt_id=None,
        ),
    )


def _oracle(code: CanonicalGeneratedCodeRecord) -> OracleRecord:
    analyzers = tuple(
        AnalyzerProvenanceRecord(
            schema_version="1.0",
            analyzer=name,
            version="1.168.0" if name == "semgrep" else "1.9.4",
            policy_sha256=("a" if name == "semgrep" else "b") * 64,
        )
        for name in ("semgrep", "bandit")
    )
    return OracleRecord(
        schema_version="1.2",
        request_id=code.request_id,
        code_id=code.code_id,
        code_sha256=code.code_sha256,
        prompt_id=code.prompt_id,
        condition="observed",
        model_id=code.model_id,
        seed_id=code.seed_id,
        hypothesis_id=None,
        assignment_id=None,
        target_spec_id=None,
        target_instance_id=None,
        arm_protocol_id=None,
        protocol_instance_id=None,
        variant_id=None,
        arm_role=None,
        parse_ok=True,
        functional_ok=True,
        security_label=SecurityLabel.SECURE,
        evaluability=OracleEvaluability.EVALUABLE,
        severity="none",
        findings=(),
        analyzers=analyzers,
    )


def _prepared_store(
    tmp_path: Path,
    prompts: tuple[PromptRecord, ...] | None = None,
) -> tuple[AppConfig, RunStore]:
    selected_prompts = _prompts() if prompts is None else prompts
    source = tmp_path / "prompts.jsonl"
    write_jsonl(source, selected_prompts)
    config = _config(source, tmp_path / "run")
    store = RunStore(config)
    store.prepare()
    run_prompt_extraction_stage(config, store, force=False)
    generate_observed_stage(config, store, force=False)
    code_output = store.path("generation", "observed_code.jsonl")
    codes = tuple(
        read_jsonl(
            code_output,
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=False,
        )
    )
    oracle_output = store.path("oracle", "observed_oracle.jsonl")
    stage = "run-oracle-observed"
    inputs = (code_output,)
    assert not store.should_skip_stage(
        stage,
        inputs,
        (oracle_output,),
        False,
        policy_sha256="d" * 64,
    )
    write_jsonl(oracle_output, tuple(_oracle(code) for code in codes))
    store.seal_stage_outputs(stage, (oracle_output,))
    store.record_stage(stage, inputs, (oracle_output,), policy_sha256="d" * 64)
    return config, store


def test_causal_table_stage_rejects_an_empty_discovery_split_without_outputs(
    tmp_path: Path,
) -> None:
    import secaware.pipeline.stages.causal_tables as stage_module

    confirm_only = tuple(prompt.model_copy(update={"split": "confirm"}) for prompt in _prompts())
    config, store = _prepared_store(tmp_path, confirm_only)

    with pytest.raises(SecAwareError):
        stage_module.assemble_causal_tables_stage(config, store, force=False)

    assert not store.path(".stages", "assemble-causal-tables.json").exists()
    assert not any(
        store.path("discovery", name).exists() for name, _model in stage_module.CAUSAL_TABLE_OUTPUTS
    )


def test_causal_table_stage_rejects_new_prompt_tsg_with_stale_code_and_oracle(
    tmp_path: Path,
) -> None:
    import secaware.pipeline.stages.causal_tables as stage_module

    config, store = _prepared_store(tmp_path)
    changed_prompts = tuple(
        prompt.model_copy(update={"prompt": f"{prompt.prompt} Updated wording."})
        for prompt in _prompts()
    )
    write_jsonl(store.path("inputs", "prompts.jsonl"), changed_prompts)
    run_prompt_extraction_stage(config, store, force=True)

    with pytest.raises(SecAwareError):
        stage_module.assemble_causal_tables_stage(config, store, force=False)

    assert not store.path(".stages", "assemble-causal-tables.json").exists()
    assert not any(
        store.path("discovery", name).exists() for name, _model in stage_module.CAUSAL_TABLE_OUTPUTS
    )

    generate_observed_stage(config, store, force=True)
    codes = tuple(
        read_jsonl(
            store.path("generation", "observed_code.jsonl"),
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=False,
        )
    )
    _recommit_oracles(store, tuple(_oracle(code) for code in codes))
    stage_module.assemble_causal_tables_stage(config, store, force=False)

    assert store.path(".stages", "assemble-causal-tables.json").exists()


def test_causal_table_stage_publishes_the_closed_output_contract() -> None:
    from secaware.pipeline.stages.causal_tables import CAUSAL_TABLE_OUTPUTS

    assert tuple(name for name, _model in CAUSAL_TABLE_OUTPUTS) == (
        "causal_tables.jsonl",
        "causal_observations.jsonl",
        "causal_exclusions.jsonl",
    )


def test_observational_stage_uses_the_complete_prompt_variable_catalog() -> None:
    from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES

    variable_ids = {item.variable_id for item in PROMPT_CAUSAL_VARIABLES}
    assert "y.secure_functional" in variable_ids
    assert "y.cwe_security" in variable_ids
    assert {
        "x.presentation.noop_rewrite",
        "x.presentation.length_matched_placebo",
        "x.presentation.sham_edit",
        "x.presentation.matched_control",
    } <= variable_ids


def test_causal_table_stage_commits_exact_discover_only_bundle(
    tmp_path: Path,
) -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    import secaware.pipeline.stages.causal_tables as causal_stage

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)

    tables = read_jsonl(
        store.path("discovery", "causal_tables.jsonl"),
        CausalTableRecord,
        required=True,
        allow_empty=False,
    )
    rows = read_jsonl(
        store.path("discovery", "causal_observations.jsonl"),
        CausalObservationRecord,
        required=True,
        allow_empty=False,
    )
    exclusions = read_jsonl(
        store.path("discovery", "causal_exclusions.jsonl"),
        CausalExclusionRecord,
        required=True,
        allow_empty=True,
    )
    assert {row.prompt_id for row in rows} == {"discover-1", "discover-2"}
    assert all(
        any(variable.variable_id.startswith("x.presentation.") for variable in table.variables)
        for table in tables
    )
    source_coordinates = tuple(
        sorted(
            (
                table.scope_id,
                table.cwe,
                row.model_id,
                row.task_id,
                row.prompt_id,
                row.seed_id,
            )
            for table in tables
            for row in rows
            if row.table_id == table.table_id
        )
    )
    validate_local_table_bundle(tables, rows, exclusions, source_coordinates=source_coordinates)
    assert store.path(".stages", "assemble-causal-tables.json").exists()


def test_run_store_rejects_nonexact_causal_table_output_contract(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage(
            "assemble-causal-tables",
            (store.path("inputs", "prompts.jsonl"),),
            (store.path("discovery", "causal_tables.jsonl"),),
            False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def _recommit_extraction(
    config: AppConfig,
    store: RunStore,
    proposals: tuple[PromptExtractionProposalRecord, ...],
    graphs: tuple | None = None,
) -> None:
    stage = "extract-prompt-tsg"
    prompt_input = store.path("inputs", "prompts.jsonl")
    outputs = (
        store.path("tsg", "prompt_extraction_proposals.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
    )
    selected_graphs = (
        tuple(read_jsonl(outputs[1], required=True, allow_empty=False))
        if graphs is None
        else graphs
    )
    store.invalidate_stage(stage)
    policy = extraction_policy(config.tsg)
    assert not store.should_skip_stage(
        stage,
        (prompt_input,),
        outputs,
        False,
        policy_sha256=policy.policy_sha256,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
    write_jsonl(outputs[0], proposals)
    write_jsonl(outputs[1], selected_graphs)
    store.seal_stage_outputs(stage, outputs)
    store.record_stage(
        stage,
        (prompt_input,),
        outputs,
        policy_sha256=policy.policy_sha256,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )


def _recommit_oracles(store: RunStore, records: tuple[OracleRecord, ...]) -> None:
    stage = "run-oracle-observed"
    inputs = (store.path("generation", "observed_code.jsonl"),)
    output = store.path("oracle", "observed_oracle.jsonl")
    manifest = read_stage_manifest(store.path(".stages", f"{stage}.json"))
    store.invalidate_stage(stage)
    assert not store.should_skip_stage(
        stage,
        inputs,
        (output,),
        False,
        policy_sha256=manifest.policy_sha256,
    )
    write_jsonl(output, records)
    store.seal_stage_outputs(stage, (output,))
    store.record_stage(stage, inputs, (output,), policy_sha256=manifest.policy_sha256)


def _commit_second_observed_generation_producer(store: RunStore) -> None:
    stage = "import-generation-observed"
    inputs = (store.path("inputs", "prompts.jsonl"),)
    output = store.path("generation", "observed_code.jsonl")
    assert not store.should_skip_stage(stage, inputs, (output,), False)
    store.seal_stage_outputs(stage, (output,))
    store.record_stage(stage, inputs, (output,))


def test_causal_table_stage_closes_generation_producer_selection_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.causal_tables as stage_module

    config, store = _prepared_store(tmp_path)
    contender = RunStore(config)
    real_select = stage_module._observed_generation_producer
    contender_errors: list[SecAwareError] = []

    def select_then_submit_second_producer(
        owner: RunStore,
        code_path: Path,
    ) -> tuple[str, tuple[Path, ...]]:
        selected = real_select(owner, code_path)
        try:
            _commit_second_observed_generation_producer(contender)
        except SecAwareError as error:
            contender_errors.append(error)
        return selected

    monkeypatch.setattr(
        stage_module,
        "_observed_generation_producer",
        select_then_submit_second_producer,
    )

    stage_module.assemble_causal_tables_stage(config, store, force=False)

    assert store.path(".stages", "assemble-causal-tables.json").exists()
    if not contender_errors:
        store.require_committed_output(
            "generate-observed",
            (store.path("generation", "observed_code.jsonl"),),
        )
        contender.require_committed_output(
            "import-generation-observed",
            (store.path("generation", "observed_code.jsonl"),),
        )
        pytest.fail(
            "causal assembly succeeded after two observed generation producers "
            "were committed in the selection-to-lease window"
        )
    assert len(contender_errors) == 1
    assert contender_errors[0].code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "import-generation-observed.json").exists()


def test_causal_table_stage_rejects_zero_observed_generation_producers(
    tmp_path: Path,
) -> None:
    from secaware.pipeline.stages.causal_tables import assemble_causal_tables_stage

    config, store = _prepared_store(tmp_path)
    store.invalidate_stage("generate-observed")

    with pytest.raises(SecAwareError) as exc_info:
        assemble_causal_tables_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not store.path(".stages", "assemble-causal-tables.json").exists()


def test_causal_table_stage_rejects_two_observed_generation_producers(
    tmp_path: Path,
) -> None:
    from secaware.pipeline.stages.causal_tables import assemble_causal_tables_stage

    config, store = _prepared_store(tmp_path)
    _commit_second_observed_generation_producer(store)

    with pytest.raises(SecAwareError) as exc_info:
        assemble_causal_tables_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not store.path(".stages", "assemble-causal-tables.json").exists()


@pytest.mark.parametrize("producer", ("proposal", "graph", "oracle"))
def test_causal_table_stage_rejects_committed_inexact_producer_coverage(
    tmp_path: Path,
    producer: str,
) -> None:
    from secaware.pipeline.stages.causal_tables import assemble_causal_tables_stage

    config, store = _prepared_store(tmp_path)
    if producer in {"proposal", "graph"}:
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
        _recommit_extraction(
            config,
            store,
            tuple(reversed(proposals)) if producer == "proposal" else proposals,
            tuple(reversed(graphs)) if producer == "graph" else graphs,
        )
    else:
        oracles = tuple(
            read_jsonl(
                store.path("oracle", "observed_oracle.jsonl"),
                OracleRecord,
                required=True,
                allow_empty=False,
            )
        )
        _recommit_oracles(store, (*oracles, oracles[0]))

    with pytest.raises(SecAwareError):
        assemble_causal_tables_stage(config, store, force=False)

    assert not store.path(".stages", "assemble-causal-tables.json").exists()
    assert not any(
        store.path("discovery", name).exists()
        for name, _model in __import__(
            "secaware.pipeline.stages.causal_tables", fromlist=["CAUSAL_TABLE_OUTPUTS"]
        ).CAUSAL_TABLE_OUTPUTS
    )


def test_causal_table_force_failure_restores_committed_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.causal_tables as stage_module

    config, store = _prepared_store(tmp_path)
    stage_module.assemble_causal_tables_stage(config, store, force=False)
    paths = tuple(
        store.path("discovery", name) for name, _model in stage_module.CAUSAL_TABLE_OUTPUTS
    )
    before = tuple(path.read_bytes() for path in paths)
    manifest_before = store.path(".stages", "assemble-causal-tables.json").read_bytes()

    def fail_build(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected table build failure")

    monkeypatch.setattr(stage_module, "build_local_tables", fail_build)
    with pytest.raises(RuntimeError, match="injected"):
        stage_module.assemble_causal_tables_stage(config, store, force=True)

    assert tuple(path.read_bytes() for path in paths) == before
    assert store.path(".stages", "assemble-causal-tables.json").read_bytes() == manifest_before


def test_causal_table_middle_output_install_failure_rolls_back_complete_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.causal_tables as stage_module
    from secaware.io.transaction import ArtifactTransaction, TransactionStateError

    config, store = _prepared_store(tmp_path)
    stage_module.assemble_causal_tables_stage(config, store, force=False)
    paths = tuple(
        store.path("discovery", name) for name, _model in stage_module.CAUSAL_TABLE_OUTPUTS
    )
    before = tuple(path.read_bytes() for path in paths)
    manifest_path = store.path(".stages", "assemble-causal-tables.json")
    manifest_before = manifest_path.read_bytes()
    real_install = ArtifactTransaction.install

    def fail_middle(self: ArtifactTransaction, index: int, candidate: Path) -> None:
        if index == 1:
            raise TransactionStateError
        real_install(self, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_middle)

    with pytest.raises(SecAwareError, match="could not be committed"):
        stage_module.assemble_causal_tables_stage(config, store, force=True)

    assert tuple(path.read_bytes() for path in paths) == before
    assert manifest_path.read_bytes() == manifest_before


def test_causal_table_code_schema_drift_invalidates_manifest_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stage_contracts as contracts
    import secaware.pipeline.stages.causal_tables as stage_module

    config, store = _prepared_store(tmp_path)
    stage_module.assemble_causal_tables_stage(config, store, force=False)
    baseline = contracts.discovery_stage_contract_payload("assemble-causal-tables")
    real_schema_sha256 = contracts._schema_sha256

    def drift_code_schema(model: type) -> str:
        if model is CanonicalGeneratedCodeRecord:
            return "0" * 64
        return real_schema_sha256(model)

    def fail_build(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("code schema drift forced table rebuild")

    assert baseline["canonical_observed_code_schema"]
    monkeypatch.setattr(contracts, "_schema_sha256", drift_code_schema)
    monkeypatch.setattr(stage_module, "build_local_tables", fail_build)

    with pytest.raises(RuntimeError, match="code schema drift forced"):
        stage_module.assemble_causal_tables_stage(config, store, force=False)


@pytest.mark.parametrize(
    "drift_field",
    ("PROMPT_FEATURE_CATALOG_SHA256", "PROMPT_TSG_STAGE_CONTRACT_SHA256"),
)
def test_causal_table_contract_drift_invalidates_manifest_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift_field: str,
) -> None:
    import secaware.pipeline.stage_contracts as contracts
    import secaware.pipeline.stages.causal_tables as stage_module

    config, store = _prepared_store(tmp_path)
    stage_module.assemble_causal_tables_stage(config, store, force=False)

    def fail_build(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("contract drift forced table rebuild")

    monkeypatch.setattr(contracts, drift_field, "0" * 64)
    monkeypatch.setattr(stage_module, "build_local_tables", fail_build)

    with pytest.raises(RuntimeError, match="contract drift forced"):
        stage_module.assemble_causal_tables_stage(config, store, force=False)


def test_causal_table_stage_holds_producer_leases_in_sorted_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages.causal_tables import assemble_causal_tables_stage

    config, store = _prepared_store(tmp_path)
    entered: list[str] = []
    active: list[str] = []
    real_hold = store.hold_dependency_stages

    @contextmanager
    def tracked_stages(stages: tuple[str, ...]):
        with real_hold(stages) as ordered:
            entered.extend(ordered)
            active.extend(ordered)
            try:
                yield ordered
            finally:
                active.clear()

    monkeypatch.setattr(store, "hold_dependency_stages", tracked_stages)
    assemble_causal_tables_stage(config, store, force=False)

    assert entered == [
        "extract-prompt-tsg",
        "generate-observed",
        "generate-provider-observed",
        "import-generation-observed",
        "run-oracle-observed",
    ]
    assert active == []

from __future__ import annotations

from pathlib import Path
from contextlib import contextmanager
import threading

import numpy as np
import pytest
from typer.testing import CliRunner

import secaware.pipeline.stages.causal_tables as causal_stage
from secaware.cli import app
from secaware.config import FCIDiscoveryConfig
from secaware.config import write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    DiscoveryFailureRecord,
    EndpointMark,
    FrozenHypothesisRecord,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
)
from test_causal_table_stage import _prepared_store


class _StablePathRunner:
    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        del matrix
        variables = tuple(item.variable_id for item in table.variables)
        return PAGRecord.from_content(
            run_kind=run_kind,
            table_id=table.table_id,
            backend=config.backend,
            backend_version=config.backend_version,
            ci_test=config.ci_test,
            config_sha256=__import__(
                "secaware.pipeline.artifact", fromlist=["canonical_sha256"]
            ).canonical_sha256(config.model_dump(mode="json")),
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=variables,
            edges=(
                PAGEdgeRecord(
                    left="x.safety.path_normalization",
                    right="y.secure_functional",
                    left_mark=EndpointMark.TAIL,
                    right_mark=EndpointMark.ARROW,
                ),
            ),
        )


class _NoPathRunner(_StablePathRunner):
    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        record = super().run(matrix, table, knowledge, config, run_kind)
        return PAGRecord.from_content(
            **record.model_dump(mode="python", exclude={"pag_id", "edges"}),
            edges=(),
        )


class _BootstrapTimeoutRunner(_StablePathRunner):
    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        if run_kind is PAGRunKind.OBSERVATIONAL_BOOTSTRAP:
            raise SecAwareError(
                code=ErrorCode.ANALYSIS_INVALID,
                stage="fake-fci",
                message="FCI worker timed out",
            )
        return super().run(matrix, table, knowledge, config, run_kind)


class _ReferenceCrashRunner(_StablePathRunner):
    def run(self, *_args: object, **_kwargs: object) -> PAGRecord:
        raise RuntimeError("injected reference crash")


def _rehash_hypothesis_with_support_mutation(
    frozen: object,
    freeze_kwargs: dict[str, object],
    field: str,
) -> object:
    hypotheses = frozen.hypotheses  # type: ignore[attr-defined]
    assert len(hypotheses) == 1
    original = hypotheses[0]
    content = original.model_dump(
        mode="python",
        exclude={"hypothesis_id", "hypothesis_sha256", "freeze_batch_sha256"},
    )
    content[field] = content[field] - 1 if field == "support_numerator" else content[field] + 1
    semantic_sha256 = FrozenHypothesisRecord.semantic_sha256_from_content(content)
    table = freeze_kwargs["table"]
    reference_pag = freeze_kwargs["reference_pag"]
    knowledge = freeze_kwargs["knowledge"]
    config = freeze_kwargs["config"]
    content["freeze_batch_sha256"] = canonical_sha256(
        {
            "schema_version": "1.0",
            "semantic_hypothesis_sha256": [semantic_sha256],
            "table_id": table.table_id,  # type: ignore[attr-defined]
            "table_sha256": table.table_sha256,  # type: ignore[attr-defined]
            "reference_pag_id": reference_pag.pag_id,  # type: ignore[attr-defined]
            "catalog_sha256": freeze_kwargs["catalog_sha256"],
            "extractor_policy_sha256": freeze_kwargs["extractor_policy_sha256"],
            "fci_config_sha256": canonical_sha256(
                config.model_dump(mode="json")  # type: ignore[attr-defined]
            ),
            "background_knowledge_sha256": knowledge.knowledge_sha256,  # type: ignore[attr-defined]
        }
    )
    mutated = FrozenHypothesisRecord.from_content(**content)
    return type(frozen)(
        hypotheses=(mutated,),
        failures=frozen.failures,  # type: ignore[attr-defined]
        freeze_batch_sha256=content["freeze_batch_sha256"],
    )


def test_fci_stage_publishes_the_closed_output_contract() -> None:
    from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS

    assert tuple(name for name, _model in FCI_DISCOVERY_OUTPUTS) == (
        "background_knowledge.jsonl",
        "reference_pags.jsonl",
        "bootstrap_draws.jsonl",
        "bootstrap_pags.jsonl",
        "bootstrap_failures.jsonl",
        "path_support.jsonl",
        "hypotheses_frozen.jsonl",
        "discovery_failures.jsonl",
    )


def test_heuristic_and_two_arm_commands_are_not_cli_reachable() -> None:
    source = Path("src/secaware/cli.py").read_text(encoding="utf-8")
    help_result = CliRunner().invoke(app, ["--help"])

    assert help_result.exit_code == 0
    assert "discover_hypotheses" not in source
    assert "tsg-qcd" not in help_result.output.casefold()
    registered = {item.name for item in app.registered_commands}
    assert {
        "confirm",
        "report",
        "intervene",
        "generate-counterfactual",
    }.isdisjoint(registered)


@pytest.mark.parametrize(
    "command",
    ("plan-generation", "generate", "import-generation", "run-oracle"),
)
def test_generic_cli_rejects_counterfactual_condition(command: str) -> None:
    arguments = [command, "--condition", "counterfactual", "--config", "missing.yaml"]
    if command == "import-generation":
        arguments.extend(("--results", "missing.jsonl"))
    result = CliRunner().invoke(app, arguments)

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "only the observed condition is reachable" in result.output


def test_fci_stage_commits_reference_bootstrap_support_and_freeze(
    tmp_path: Path,
) -> None:
    from secaware.pipeline.stages.fci_discovery import fci_discovery_stage

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)

    result = fci_discovery_stage(
        config,
        store,
        force=False,
        runner=_StablePathRunner(),
    )

    assert result.status.value == "ready"
    draws = read_jsonl(
        store.path("discovery", "bootstrap_draws.jsonl"),
        __import__("secaware.schema.causal", fromlist=["BootstrapDrawRecord"]).BootstrapDrawRecord,
        required=True,
        allow_empty=False,
    )
    assert [item.run_kind for item in draws].count(PAGRunKind.OBSERVATIONAL_REFERENCE) == 1
    assert [item.run_kind for item in draws].count(PAGRunKind.OBSERVATIONAL_BOOTSTRAP) == 3
    hypotheses = read_jsonl(
        store.path("discovery", "hypotheses_frozen.jsonl"),
        FrozenHypothesisRecord,
        required=True,
        allow_empty=False,
    )
    failures = read_jsonl(
        store.path("discovery", "discovery_failures.jsonl"),
        DiscoveryFailureRecord,
        required=True,
        allow_empty=True,
    )
    assert hypotheses
    assert failures == []
    assert store.path(".stages", "fci-discovery.json").exists()


@pytest.mark.parametrize(
    ("runner", "expected_status", "expected_reason"),
    (
        (_NoPathRunner(), "no_stable_hypothesis", "no_stable_hypothesis"),
        (
            _BootstrapTimeoutRunner(),
            "too_many_failed_bootstraps",
            "too_many_failed_bootstraps",
        ),
    ),
)
def test_terminal_discovery_commits_diagnostics_before_returning_nonready(
    tmp_path: Path,
    runner: object,
    expected_status: str,
    expected_reason: str,
) -> None:
    from secaware.pipeline.stages.fci_discovery import fci_discovery_stage

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)

    result = fci_discovery_stage(config, store, force=False, runner=runner)  # type: ignore[arg-type]

    assert result.status.value == expected_status
    hypotheses = read_jsonl(
        store.path("discovery", "hypotheses_frozen.jsonl"),
        FrozenHypothesisRecord,
        required=True,
        allow_empty=True,
    )
    failures = read_jsonl(
        store.path("discovery", "discovery_failures.jsonl"),
        DiscoveryFailureRecord,
        required=True,
        allow_empty=False,
    )
    assert hypotheses == []
    assert {item.reason_code.value for item in failures} == {expected_reason}
    assert store.path(".stages", "fci-discovery.json").exists()


def test_fci_stage_contract_binds_library_rng_and_freeze_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stage_contracts as contracts

    baseline = contracts.discovery_stage_contract_sha256("fci-discovery")
    monkeypatch.setattr(contracts.importlib.metadata, "version", lambda _name: "drifted")

    assert contracts.discovery_stage_contract_sha256("fci-discovery") != baseline
    payload = contracts.discovery_stage_contract_payload("fci-discovery")
    assert payload["rng_version"]
    assert payload["path_schema"]
    assert payload["freeze_schema"]


def test_run_store_rejects_nonexact_fci_output_contract(tmp_path: Path) -> None:
    _config, store = _prepared_store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage(
            "fci-discovery",
            (store.path("inputs", "prompts.jsonl"),),
            (store.path("discovery", "background_knowledge.jsonl"),),
            False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_fci_force_failure_restores_the_complete_committed_bundle(
    tmp_path: Path,
) -> None:
    from secaware.pipeline.stages.fci_discovery import (
        FCI_DISCOVERY_OUTPUTS,
        fci_discovery_stage,
    )

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    fci_discovery_stage(config, store, force=False, runner=_StablePathRunner())
    paths = tuple(store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS)
    before = tuple(path.read_bytes() for path in paths)
    manifest_path = store.path(".stages", "fci-discovery.json")
    manifest_before = manifest_path.read_bytes()

    with pytest.raises(SecAwareError, match="reference FCI run failed"):
        fci_discovery_stage(config, store, force=True, runner=_ReferenceCrashRunner())

    assert tuple(path.read_bytes() for path in paths) == before
    assert manifest_path.read_bytes() == manifest_before


def test_fci_stage_rejects_old_causal_bundle_with_current_extractor_provenance(
    tmp_path: Path,
) -> None:
    from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
    from secaware.pipeline.stages.fci_discovery import fci_discovery_stage
    from secaware.pipeline.stages.prompt_extraction import run_prompt_extraction_stage
    from test_causal_table_stage import _prompts

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    changed_prompts = tuple(
        prompt.model_copy(update={"prompt": f"{prompt.prompt} Current extraction."})
        for prompt in _prompts()
    )
    write_jsonl(store.path("inputs", "prompts.jsonl"), changed_prompts)
    run_prompt_extraction_stage(config, store, force=True)

    with pytest.raises(SecAwareError, match="provenance"):
        fci_discovery_stage(config, store, force=False, runner=_StablePathRunner())

    assert not store.path(".stages", "fci-discovery.json").exists()
    assert not any(store.path("discovery", name).exists() for name, _model in FCI_DISCOVERY_OUTPUTS)


def test_fci_middle_output_install_failure_rolls_back_complete_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.fci_discovery as stage_module
    from secaware.io.transaction import ArtifactTransaction, TransactionStateError

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    stage_module.fci_discovery_stage(config, store, force=False, runner=_StablePathRunner())
    paths = tuple(
        store.path("discovery", name) for name, _model in stage_module.FCI_DISCOVERY_OUTPUTS
    )
    before = tuple(path.read_bytes() for path in paths)
    manifest_path = store.path(".stages", "fci-discovery.json")
    manifest_before = manifest_path.read_bytes()
    real_install = ArtifactTransaction.install

    def fail_middle(self: ArtifactTransaction, index: int, candidate: Path) -> None:
        if index == 4:
            raise TransactionStateError
        real_install(self, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_middle)

    with pytest.raises(SecAwareError, match="could not be committed"):
        stage_module.fci_discovery_stage(
            config,
            store,
            force=True,
            runner=_StablePathRunner(),
        )

    assert tuple(path.read_bytes() for path in paths) == before
    assert manifest_path.read_bytes() == manifest_before


def test_fci_stage_rejects_unknown_global_failure_association_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.fci_discovery as stage_module

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    real_freeze = stage_module.freeze_hypotheses

    def inject_unknown_failure(**kwargs: object):
        frozen = real_freeze(**kwargs)  # type: ignore[arg-type]
        failure = frozen.failures[0]
        unknown = DiscoveryFailureRecord.from_content(
            **failure.model_dump(mode="python", exclude={"failure_id", "table_id"}),
            table_id=f"table_{'a' * 64}",
        )
        return type(frozen)(
            hypotheses=frozen.hypotheses,
            failures=(*frozen.failures, unknown),
            freeze_batch_sha256=frozen.freeze_batch_sha256,
        )

    monkeypatch.setattr(stage_module, "freeze_hypotheses", inject_unknown_failure)

    with pytest.raises(SecAwareError, match="readback validation"):
        stage_module.fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_NoPathRunner(),
        )

    assert not store.path(".stages", "fci-discovery.json").exists()
    assert not any(
        store.path("discovery", name).exists()
        for name, _model in stage_module.FCI_DISCOVERY_OUTPUTS
    )


def test_fci_stage_rejects_failure_provenance_mismatch_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.fci_discovery as stage_module

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    real_freeze = stage_module.freeze_hypotheses

    def inject_mismatch(**kwargs: object):
        frozen = real_freeze(**kwargs)  # type: ignore[arg-type]
        failure = frozen.failures[0]
        mismatched = DiscoveryFailureRecord.from_content(
            **failure.model_dump(mode="python", exclude={"failure_id", "scope_id"}),
            scope_id="scope.mismatched",
        )
        return type(frozen)(
            hypotheses=frozen.hypotheses,
            failures=(mismatched,),
            freeze_batch_sha256=frozen.freeze_batch_sha256,
        )

    monkeypatch.setattr(stage_module, "freeze_hypotheses", inject_mismatch)

    with pytest.raises(SecAwareError, match="readback validation"):
        stage_module.fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_NoPathRunner(),
        )

    assert not store.path(".stages", "fci-discovery.json").exists()


@pytest.mark.parametrize("field", ("support_numerator", "support_denominator"))
def test_fci_stage_rejects_self_rehashed_hypothesis_support_mutation_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    import secaware.pipeline.stages.fci_discovery as stage_module

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    real_freeze = stage_module.freeze_hypotheses

    def inject_mutation(**kwargs: object):
        frozen = real_freeze(**kwargs)  # type: ignore[arg-type]
        return _rehash_hypothesis_with_support_mutation(frozen, kwargs, field)

    monkeypatch.setattr(stage_module, "freeze_hypotheses", inject_mutation)

    with pytest.raises(SecAwareError, match="readback validation"):
        stage_module.fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_StablePathRunner(),
        )

    assert not store.path(".stages", "fci-discovery.json").exists()


def test_fci_stage_rejects_self_rehashed_no_stable_failure_detail_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.fci_discovery as stage_module

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    real_freeze = stage_module.freeze_hypotheses

    def inject_detail_mutation(**kwargs: object):
        frozen = real_freeze(**kwargs)  # type: ignore[arg-type]
        failure = frozen.failures[0]
        mutated = DiscoveryFailureRecord.from_content(
            **failure.model_dump(mode="python", exclude={"failure_id", "detail_sha256"}),
            detail_sha256="e" * 64,
        )
        return type(frozen)(
            hypotheses=frozen.hypotheses,
            failures=(mutated,),
            freeze_batch_sha256=frozen.freeze_batch_sha256,
        )

    monkeypatch.setattr(stage_module, "freeze_hypotheses", inject_detail_mutation)

    with pytest.raises(SecAwareError, match="readback validation"):
        stage_module.fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_NoPathRunner(),
        )

    assert not store.path(".stages", "fci-discovery.json").exists()


def test_fci_skip_uses_manifest_but_library_drift_forces_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stage_contracts as contracts
    from secaware.pipeline.stages.fci_discovery import fci_discovery_stage

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    fci_discovery_stage(config, store, force=False, runner=_StablePathRunner())

    # Identical committed inputs skip before invoking the backend.
    assert (
        fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_ReferenceCrashRunner(),
        ).status.value
        == "ready"
    )

    monkeypatch.setattr(contracts.importlib.metadata, "version", lambda _name: "drifted")
    with pytest.raises(SecAwareError, match="reference FCI run failed"):
        fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_ReferenceCrashRunner(),
        )


def test_fci_config_schema_drift_invalidates_manifest_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stage_contracts as contracts
    from secaware.pipeline.stages.fci_discovery import fci_discovery_stage

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    fci_discovery_stage(config, store, force=False, runner=_StablePathRunner())
    real_schema_sha256 = contracts._schema_sha256

    def drift_config_schema(model: type) -> str:
        if model is FCIDiscoveryConfig:
            return "0" * 64
        return real_schema_sha256(model)

    monkeypatch.setattr(contracts, "_schema_sha256", drift_config_schema)

    with pytest.raises(SecAwareError, match="reference FCI run failed"):
        fci_discovery_stage(
            config,
            store,
            force=False,
            runner=_ReferenceCrashRunner(),
        )


def test_fci_stage_holds_sorted_producer_leases_and_blocks_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages.fci_discovery import fci_discovery_stage

    config, store = _prepared_store(tmp_path)
    causal_stage.assemble_causal_tables_stage(config, store, force=False)
    entered_names: list[str] = []
    real_hold = store.hold_committed_output

    @contextmanager
    def tracked(stage: str, *args: object, **kwargs: object):
        with real_hold(stage, *args, **kwargs) as hashes:  # type: ignore[arg-type]
            entered_names.append(stage)
            yield hashes

    monkeypatch.setattr(store, "hold_committed_output", tracked)
    entered_runner = threading.Event()
    release_runner = threading.Event()
    failures: list[BaseException] = []

    class BlockingRunner(_StablePathRunner):
        def run(self, *args: object, **kwargs: object) -> PAGRecord:
            entered_runner.set()
            assert release_runner.wait(timeout=5)
            return super().run(*args, **kwargs)  # type: ignore[arg-type]

    def consume() -> None:
        try:
            fci_discovery_stage(config, store, force=False, runner=BlockingRunner())
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    assert entered_runner.wait(timeout=5)
    try:
        contender = RunStore(config)
        with pytest.raises(SecAwareError) as exc_info:
            causal_stage.assemble_causal_tables_stage(config, contender, force=True)
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        release_runner.set()
        thread.join(timeout=10)

    assert not thread.is_alive()
    assert failures == []
    assert entered_names == ["assemble-causal-tables", "extract-prompt-tsg"]


def test_discover_cli_exits_nonzero_only_after_no_stable_artifacts_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.pipeline.stages.fci_discovery as stage_module

    config, store = _prepared_store(tmp_path)
    config_path = tmp_path / "resolved.yaml"
    write_resolved_config(config, config_path)
    monkeypatch.setattr(stage_module, "SpawnedFCIRunner", lambda: _NoPathRunner())

    result = CliRunner().invoke(
        app,
        [
            "discover",
            "--config",
            str(config_path),
            "--run-dir",
            str(store.root),
        ],
    )

    assert result.exit_code == int(ErrorCode.ANALYSIS_INVALID)
    assert store.path(".stages", "fci-discovery.json").exists()
    assert store.path("discovery", "reference_pags.jsonl").exists()
    assert (
        read_jsonl(
            store.path("discovery", "hypotheses_frozen.jsonl"),
            FrozenHypothesisRecord,
            required=True,
            allow_empty=True,
        )
        == []
    )

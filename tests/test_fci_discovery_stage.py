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
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
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
    assert "intervene" not in {item.name for item in app.registered_commands}
    assert "generate-counterfactual" not in {item.name for item in app.registered_commands}


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
    assert fci_discovery_stage(
        config,
        store,
        force=False,
        runner=_ReferenceCrashRunner(),
    ).status.value == "ready"

    monkeypatch.setattr(contracts.importlib.metadata, "version", lambda _name: "drifted")
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
    assert read_jsonl(
        store.path("discovery", "hypotheses_frozen.jsonl"),
        FrozenHypothesisRecord,
        required=True,
        allow_empty=True,
    ) == []

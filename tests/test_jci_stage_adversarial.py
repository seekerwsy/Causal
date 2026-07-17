from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

import secaware.pipeline.stage_contracts as stage_contracts
import secaware.pipeline.stages.jci as jci_module
from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.stages.effects import EFFECT_STAGE_OUTPUTS
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.jci import JCI_STAGE_INPUTS, JCI_STAGE_OUTPUTS, jci_stage
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.schema.causal import (
    CausalTableRecord,
    jci_row_id_from_content,
)
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    JCIObservationRecord,
)
from test_jci_stage import _EmptyFCIRunner


pytest_plugins = ("test_jci_stage",)


EXPECTED_PRODUCER_STAGES = (
    "build-confirmation-variants",
    "estimate-confirmation-effects",
    "fci-discovery",
    "randomize-confirmation",
)


def _malformed_spawned_fci_output(send_connection, _job_json, _matrix) -> None:
    send_connection.send_bytes(b"{")


@pytest.fixture
def jci_committed(committed_jci_base):
    return committed_jci_base


def _producer_relatives() -> dict[str, tuple[str, ...]]:
    return {
        "build-confirmation-variants": tuple(
            f"interventions/{name}" for name, _model in PROMPT_VARIANT_OUTPUTS
        ),
        "fci-discovery": tuple(f"discovery/{name}" for name, _model in FCI_DISCOVERY_OUTPUTS),
        "randomize-confirmation": tuple(
            f"interventions/{name}" for name, _model in RANDOMIZATION_OUTPUTS
        ),
        "estimate-confirmation-effects": tuple(
            path.as_posix() for path, _model in EFFECT_STAGE_OUTPUTS
        ),
    }


def _jci_artifact_bytes(store) -> tuple[bytes, ...]:
    return tuple((store.root / path).read_bytes() for path, _model in JCI_STAGE_OUTPUTS) + (
        store.path(".stages", "jci-confirmation.json").read_bytes(),
    )


def _effects_artifact_bytes(store) -> tuple[bytes, ...]:
    return tuple((store.root / path).read_bytes() for path, _model in EFFECT_STAGE_OUTPUTS) + (
        store.path(".stages", "estimate-confirmation-effects.json").read_bytes(),
    )


def _published_groups(store) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(
            read_jsonl(
                store.root / path,
                model,
                required=True,
                allow_empty=index in {2, 4, 5, 6},
            )
        )
        for index, (path, model) in enumerate(JCI_STAGE_OUTPUTS)
    )


def test_jci_holds_exact_ordered_full_producers_through_commit(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    held: list[tuple[str, ...]] = []
    leased_orders: list[tuple[str, ...]] = []
    required: dict[str, tuple[str, ...]] = {}
    transaction_inputs: list[tuple[str, ...]] = []
    active = False
    observed = {"install": 0, "seal": 0, "record": 0}
    hold = store.hold_dependency_stages
    require = store.require_committed_output
    execute = jci_module.execute_jsonl_stage_transaction
    install = ArtifactTransaction.install
    seal = store.seal_stage_outputs
    record = store.record_stage
    validate = jci_module._validate_bundle
    validation_calls = 0
    effects_before = _effects_artifact_bytes(store)

    @contextmanager
    def tracking_hold(stages):
        nonlocal active
        held.append(tuple(stages))
        with hold(stages) as leased:
            leased_orders.append(tuple(leased))
            active = True
            try:
                yield leased
            finally:
                active = False

    def tracking_require(stage, outputs, **kwargs):
        required[stage] = tuple(path.relative_to(store.root).as_posix() for path in outputs)
        return require(stage, outputs, **kwargs)

    def tracking_execute(*args, **kwargs):
        transaction_inputs.append(
            tuple(path.relative_to(store.root).as_posix() for path in kwargs["inputs"])
        )
        return execute(*args, **kwargs)

    def tracking_validate(*args, **kwargs):
        nonlocal validation_calls
        validation_calls += 1
        return validate(*args, **kwargs)

    def tracking_install(self, index, candidate):
        assert active and validation_calls >= 2
        observed["install"] += 1
        return install(self, index, candidate)

    def tracking_seal(stage, outputs):
        assert active
        observed["seal"] += 1
        return seal(stage, outputs)

    def tracking_record(*args, **kwargs):
        assert active
        observed["record"] += 1
        return record(*args, **kwargs)

    monkeypatch.setattr(store, "hold_dependency_stages", tracking_hold)
    monkeypatch.setattr(store, "require_committed_output", tracking_require)
    monkeypatch.setattr(jci_module, "execute_jsonl_stage_transaction", tracking_execute)
    monkeypatch.setattr(jci_module, "_validate_bundle", tracking_validate)
    monkeypatch.setattr(ArtifactTransaction, "install", tracking_install)
    monkeypatch.setattr(store, "seal_stage_outputs", tracking_seal)
    monkeypatch.setattr(store, "record_stage", tracking_record)

    jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)

    expected_paths = _producer_relatives()
    expected_inputs = tuple(
        relative for stage in EXPECTED_PRODUCER_STAGES for relative in expected_paths[stage]
    ) + tuple(f".stages/{stage}.json" for stage in EXPECTED_PRODUCER_STAGES)
    assert held == [EXPECTED_PRODUCER_STAGES]
    assert leased_orders == [EXPECTED_PRODUCER_STAGES]
    assert required == expected_paths
    assert transaction_inputs == [expected_inputs]
    assert observed == {"install": 7, "seal": 1, "record": 1}
    assert _effects_artifact_bytes(store) == effects_before


def test_jci_default_runner_factory_boundary_is_lazy_and_injected_runner_is_preserved(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    created: list[_EmptyFCIRunner] = []
    timeouts: list[float] = []

    def factory(*, timeout_seconds: float) -> _EmptyFCIRunner:
        runner = _EmptyFCIRunner()
        created.append(runner)
        timeouts.append(timeout_seconds)
        return runner

    monkeypatch.setattr(jci_module, "SpawnedFCIRunner", factory, raising=False)
    jci_stage(config, store, force=True)
    assert len(created) == 1
    assert timeouts == [config.discovery.timeout_seconds]
    assert created[0].calls == 2

    injected = _EmptyFCIRunner()
    monkeypatch.setattr(
        jci_module,
        "SpawnedFCIRunner",
        lambda: pytest.fail("injected runner must bypass default factory"),
    )
    jci_stage(config, store, runner=injected, force=True)
    assert injected.calls == 2


@pytest.mark.parametrize(
    ("error", "reason"),
    (
        (TimeoutError("private"), AnalysisFailureReason.BACKEND_TIMEOUT),
        (
            SecAwareError(
                code=ErrorCode.ANALYSIS_INVALID,
                stage="causal.discovery.supervisor",
                message="FCI worker timed out",
                details={"failure_kind": FCISupervisorFailureKind.TIMEOUT.value},
            ),
            AnalysisFailureReason.BACKEND_TIMEOUT,
        ),
        (RuntimeError("private"), AnalysisFailureReason.BACKEND_FAILURE),
    ),
)
def test_jci_runner_failures_publish_exact_typed_partition(
    jci_committed,
    error: BaseException,
    reason: AnalysisFailureReason,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    before_effects = _effects_artifact_bytes(store)

    class FailingRunner:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, *_args, **_kwargs):
            self.calls += 1
            raise error

    runner = FailingRunner()
    try:
        result = jci_stage(config, store, runner=runner, force=True)
        tables, _rows, raw, backgrounds, constrained, deltas, failures = _published_groups(store)
        assert result.table_count == len(tables) == len(backgrounds) == len(failures) == 1
        assert not raw and not constrained and not deltas
        assert failures[0].reason_code is reason
        assert runner.calls == 1
        assert _effects_artifact_bytes(store) == before_effects
    finally:
        jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)


def _rebuild_with_tasks(
    tables: tuple[CausalTableRecord, ...],
    rows: tuple[JCIObservationRecord, ...],
    task_count: int,
) -> tuple[tuple[CausalTableRecord, ...], tuple[JCIObservationRecord, ...]]:
    rebuilt_tables = []
    rebuilt_rows = []
    for table in tables:
        local = tuple(row for row in rows if row.table_id == table.table_id)
        kept_tasks = set(sorted({row.task_id for row in local})[:task_count])
        local = tuple(row for row in local if row.task_id in kept_tasks)
        payload = tuple(
            (
                jci_row_id_from_content(
                    assignment_id=row.assignment_id,
                    task_id=row.task_id,
                    target_spec_id=row.target_spec_id,
                    target_instance_id=row.target_instance_id,
                    arm_protocol_id=row.arm_protocol_id,
                    protocol_instance_id=row.protocol_instance_id,
                    values=row.values,
                ),
                row.assignment_id,
                row.task_id,
                row.target_spec_id,
                row.target_instance_id,
                row.arm_protocol_id,
                row.protocol_instance_id,
                row.values,
            )
            for row in local
        )
        rebuilt = CausalTableRecord.from_jci_content(
            scope_id=table.scope_id,
            cwe=table.cwe,
            model_id=table.model_id,
            variables=table.variables,
            independent_task_count=task_count,
            observation_payload=payload,
        )
        rebuilt_tables.append(rebuilt)
        rebuilt_rows.extend(
            JCIObservationRecord.from_content(
                table_id=rebuilt.table_id,
                assignment_id=row.assignment_id,
                task_id=row.task_id,
                target_spec_id=row.target_spec_id,
                target_instance_id=row.target_instance_id,
                arm_protocol_id=row.arm_protocol_id,
                protocol_instance_id=row.protocol_instance_id,
                values=row.values,
            )
            for row in local
        )
    return (
        tuple(
            sorted(rebuilt_tables, key=lambda item: (item.scope_id, item.model_id, item.table_id))
        ),
        tuple(sorted(rebuilt_rows, key=lambda item: (item.table_id, item.row_id))),
    )


def test_jci_insufficient_support_is_one_failure_with_background_and_no_runner(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    original = jci_module.build_jci_tables

    def insufficient(*args, **kwargs):
        tables, rows = original(*args, **kwargs)
        return _rebuild_with_tasks(tables, rows, config.discovery.min_independent_tasks - 1)

    class ForbiddenRunner:
        def run(self, *_args, **_kwargs):
            raise AssertionError("insufficient table invoked runner")

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(jci_module, "build_jci_tables", insufficient)
            scoped.setattr(jci_module, "validate_jci_relations", lambda *args, **kwargs: None)
            result = jci_stage(config, store, runner=ForbiddenRunner(), force=True)
        tables, _rows, raw, backgrounds, constrained, deltas, failures = _published_groups(store)
        assert result.table_count == len(tables) == len(backgrounds) == len(failures) == 1
        assert not raw and not constrained and not deltas
        assert failures[0].reason_code is AnalysisFailureReason.INSUFFICIENT_SUPPORT
    finally:
        jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)


def test_jci_invalid_runner_pag_hard_aborts_and_preserves_prior_commit(
    jci_committed,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    before = _jci_artifact_bytes(store)
    before_effects = _effects_artifact_bytes(store)

    class InvalidRunner(_EmptyFCIRunner):
        def run(self, *args, **kwargs):
            valid = super().run(*args, **kwargs)
            return valid.model_copy(update={"background_knowledge_sha256": "f" * 64})

    with pytest.raises(Exception):
        jci_stage(config, store, runner=InvalidRunner(), force=True)

    assert _jci_artifact_bytes(store) == before
    assert _effects_artifact_bytes(store) == before_effects


def test_jci_spawned_supervisor_invalid_output_hard_aborts_and_preserves_prior_commit(
    jci_committed,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    before = _jci_artifact_bytes(store)
    effects_before = _effects_artifact_bytes(store)
    observed_details = []
    spawned = SpawnedFCIRunner(
        timeout_seconds=30.0,
        worker=_malformed_spawned_fci_output,
    )

    class RecordingRunner:
        def run(self, *args, **kwargs):
            try:
                return spawned.run(*args, **kwargs)
            except SecAwareError as error:
                observed_details.append(error.details)
                raise

    raised = False
    try:
        jci_stage(
            config,
            store,
            runner=RecordingRunner(),
            force=True,
        )
    except SecAwareError:
        raised = True

    assert raised, observed_details
    assert observed_details == [{"failure_kind": FCISupervisorFailureKind.INVALID_OUTPUT.value}]
    assert _jci_artifact_bytes(store) == before
    assert _effects_artifact_bytes(store) == effects_before


@pytest.mark.parametrize("failure_point", ("build", "install", "record"))
def test_jci_force_failures_restore_all_outputs_and_manifest(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    before = _jci_artifact_bytes(store)
    effects_before = _effects_artifact_bytes(store)
    if failure_point == "build":
        monkeypatch.setattr(
            jci_module,
            "build_jci_tables",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private")),
        )
    elif failure_point == "install":
        install = ArtifactTransaction.install
        failed = False

        def fail_fourth(self, index, candidate):
            nonlocal failed
            if index == 3 and not failed:
                failed = True
                raise TransactionStateError("private")
            return install(self, index, candidate)

        monkeypatch.setattr(ArtifactTransaction, "install", fail_fourth)
    else:
        monkeypatch.setattr(
            store,
            "record_stage",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private")),
        )

    with pytest.raises(Exception):
        jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)

    assert _jci_artifact_bytes(store) == before
    assert _effects_artifact_bytes(store) == effects_before


def test_jci_empty_universe_and_concurrent_producer_mutation_hard_abort(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    before = _jci_artifact_bytes(store)
    effects_before = _effects_artifact_bytes(store)

    with monkeypatch.context() as scoped:
        scoped.setattr(jci_module, "build_jci_tables", lambda *_args, **_kwargs: ((), ()))
        scoped.setattr(jci_module, "validate_jci_table_bundle", lambda *_args, **_kwargs: None)
        scoped.setattr(jci_module, "validate_jci_relations", lambda *_args, **_kwargs: None)
        with pytest.raises(Exception):
            jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)
    assert _jci_artifact_bytes(store) == before

    producer = store.root / EFFECT_STAGE_OUTPUTS[0][0]
    producer_before = producer.read_bytes()
    original = jci_module.build_jci_tables

    def mutate_then_build(*args, **kwargs):
        producer.write_bytes(producer.read_bytes() + b"\n")
        return original(*args, **kwargs)

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(jci_module, "build_jci_tables", mutate_then_build)
            with pytest.raises(Exception):
                jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)
        assert _jci_artifact_bytes(store) == before
    finally:
        producer.write_bytes(producer_before)
    assert _effects_artifact_bytes(store) == effects_before


def test_jci_valid_skip_avoids_runner_and_output_tamper_forces_rebuild(
    jci_committed,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed

    class ForbiddenRunner:
        def run(self, *_args, **_kwargs):
            raise AssertionError("valid skip invoked runner")

    before = _jci_artifact_bytes(store)
    jci_stage(config, store, runner=ForbiddenRunner(), force=False)
    assert _jci_artifact_bytes(store) == before

    path = store.path("analysis", "jci_raw_pags.jsonl")
    canonical = path.read_bytes()
    path.write_bytes(canonical + b"\n")
    runner = _EmptyFCIRunner()
    jci_stage(config, store, runner=runner, force=False)
    assert runner.calls == 2
    assert path.read_bytes() == canonical


def test_jci_reads_and_outputs_have_finite_limits(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    observed = []
    read = jci_module.read_jsonl

    def tracking_read(*args, **kwargs):
        observed.append(
            (
                kwargs.get("max_records"),
                kwargs.get("max_line_chars"),
                kwargs.get("max_total_chars"),
            )
        )
        return read(*args, **kwargs)

    monkeypatch.setattr(jci_module, "read_jsonl", tracking_read)
    jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)

    assert observed
    assert set(observed) == {(100_000, 4_000_000, 256_000_000)}
    specs = jci_module._output_specs(store)
    assert len(specs) == 7
    assert all(
        spec.max_records > 0 and spec.max_line_chars > 0 and spec.max_total_chars > 0
        for spec in specs
    )


def test_jci_resource_budgets_abort_before_runner_and_preserve_old_commit(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    before = _jci_artifact_bytes(store)
    effects_before = _effects_artifact_bytes(store)

    class ForbiddenRunner:
        calls = 0

        def run(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("JCI resource budget invoked runner")

    for binding, replacement in (
        ("MAX_JCI_TABLES", 0),
        ("MAX_JCI_FCI_RUNS", 1),
        ("MAX_JCI_MATRIX_CELLS", 0),
    ):
        runner = ForbiddenRunner()
        with monkeypatch.context() as scoped:
            scoped.setattr(jci_module, binding, replacement, raising=False)
            with pytest.raises(SecAwareError, match="resource budget"):
                jci_stage(config, store, runner=runner, force=True)
        assert runner.calls == 0
        assert _jci_artifact_bytes(store) == before
        assert _effects_artifact_bytes(store) == effects_before


def test_jci_schema_parses_only_assignment_outcomes_from_effect_bundle(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _result, _runner, _effect_bytes = jci_committed
    effect_paths = tuple(store.root / path for path, _model in EFFECT_STAGE_OUTPUTS)
    parsed_effect_paths = []
    read = jci_module.read_jsonl

    def tracking_read(path, *args, **kwargs):
        resolved = Path(path)
        if resolved in effect_paths:
            parsed_effect_paths.append(resolved)
        return read(path, *args, **kwargs)

    monkeypatch.setattr(jci_module, "read_jsonl", tracking_read)
    jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)

    assert parsed_effect_paths == [effect_paths[0]]


def test_jci_requires_seal_and_variable_catalog_bound_fingerprint(
    jci_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config, store, _result, _runner, _effect_bytes = jci_committed
    assert store._requires_output_seal("jci-confirmation")
    inputs = tuple(store.root / path for path in JCI_STAGE_INPUTS)
    assert all(path.exists() for path in inputs)
    payload = stage_contracts.jci_stage_contract_payload()
    assert payload["variable_catalog_sha256"] == stage_contracts.VARIABLE_CATALOG_SHA256
    contract_before = stage_contracts.jci_stage_contract_sha256("jci-confirmation")
    fingerprint_before = store.stage_fingerprint("jci-confirmation", inputs)

    monkeypatch.setattr(stage_contracts, "VARIABLE_CATALOG_SHA256", "f" * 64)

    assert stage_contracts.jci_stage_contract_sha256("jci-confirmation") != contract_before
    assert store.stage_fingerprint("jci-confirmation", inputs) != fingerprint_before


@pytest.mark.parametrize(
    ("binding", "replacement"),
    (
        ("MAX_JCI_TABLES", 511),
        ("MAX_JCI_FCI_RUNS", 1_023),
        ("MAX_JCI_MATRIX_CELLS", 6_399_999),
    ),
)
def test_jci_resource_budgets_are_bound_into_stage_contract(
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
    replacement: int,
) -> None:
    before = stage_contracts.jci_stage_contract_sha256("jci-confirmation")

    monkeypatch.setattr(stage_contracts, binding, replacement)

    assert stage_contracts.jci_stage_contract_sha256("jci-confirmation") != before


def test_jci_committed_manifest_binds_all_seven_output_hashes(jci_committed) -> None:
    _config, store, _result, _runner, _effect_bytes = jci_committed
    committed = store.require_committed_output(
        "jci-confirmation",
        tuple(store.root / path for path, _model in JCI_STAGE_OUTPUTS),
    )
    assert committed == {
        path.as_posix(): sha256_path(store.root / path) for path, _model in JCI_STAGE_OUTPUTS
    }

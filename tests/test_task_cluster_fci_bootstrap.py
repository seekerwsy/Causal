from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
from pathlib import Path

import numpy as np
import pytest

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapFailureReason,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    PAGRecord,
    PAGRunKind,
    VariableRole,
)


def _variable(variable_id: str) -> CausalVariableSpec:
    declaration = declaration_by_id(variable_id)
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=declaration.variable_id,
        role=declaration.role,
        states=declaration.states,
        source_query_id=declaration.query_id,
        scope_id="scope.cwe_89",
        temporal_tier=declaration.tier,
        adjacency_type=declaration.adjacency_type,
        producer_sha256=declaration_sha256(declaration),
    )


def _table_and_rows() -> tuple[CausalTableRecord, tuple[CausalObservationRecord, ...]]:
    variables = (
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    raw = []
    for task_index in range(3):
        for seed_id in (2, 7, 11):
            values = (task_index % 2, (task_index + seed_id) % 2)
            task_id = f"task-{task_index}"
            prompt_id = f"prompt-{task_index}"
            row_id = CausalObservationRecord.row_id_from_content(
                task_id=task_id,
                prompt_id=prompt_id,
                model_id="model-a",
                seed_id=seed_id,
                values=values,
            )
            raw.append((row_id, task_id, prompt_id, seed_id, values))
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=len(raw),
        independent_task_count=3,
        observation_payload=raw,
    )
    rows = tuple(
        CausalObservationRecord.from_content(
            table=table,
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=table.model_id,
            seed_id=seed_id,
            values=values,
        )
        for _row_id, task_id, prompt_id, seed_id, values in raw
    )
    return table, rows


def _rebuild_bundle(
    table: CausalTableRecord,
    rows: tuple[CausalObservationRecord, ...],
    *,
    flip_outcome: bool = False,
    change_first_prompt: bool = False,
) -> tuple[CausalTableRecord, tuple[CausalObservationRecord, ...]]:
    y_index = next(
        index for index, variable in enumerate(table.variables) if variable.role is VariableRole.Y
    )
    rebuilt_coordinates: list[tuple[str, str, int, tuple[int, ...]]] = []
    for row in rows:
        prompt_id = (
            "prompt-coordinate-changed"
            if change_first_prompt and row.task_id == "task-0"
            else row.prompt_id
        )
        values = list(row.values)
        if flip_outcome:
            values[y_index] = 1 - values[y_index]
        rebuilt_coordinates.append((row.task_id, prompt_id, row.seed_id, tuple(values)))
    payload = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=task_id,
                prompt_id=prompt_id,
                model_id=table.model_id,
                seed_id=seed_id,
                values=values,
            ),
            task_id,
            prompt_id,
            seed_id,
            values,
        )
        for task_id, prompt_id, seed_id, values in rebuilt_coordinates
    )
    rebuilt_table = CausalTableRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=table.model_id,
        variables=table.variables,
        row_count=table.row_count,
        independent_task_count=table.independent_task_count,
        observation_payload=payload,
    )
    rebuilt_rows = tuple(
        CausalObservationRecord.from_content(
            table=rebuilt_table,
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=rebuilt_table.model_id,
            seed_id=seed_id,
            values=values,
        )
        for task_id, prompt_id, seed_id, values in rebuilt_coordinates
    )
    return rebuilt_table, rebuilt_rows


def _config(*, bootstrap_samples: int = 4) -> FCIDiscoveryConfig:
    return FCIDiscoveryConfig(
        bootstrap_samples=bootstrap_samples,
        min_independent_tasks=2,
    )


def _jci_table_and_matrix() -> tuple[
    CausalTableRecord,
    BackgroundKnowledgeRecord,
    np.ndarray,
]:
    variables = (
        CausalVariableSpec(
            schema_version="1.0",
            variable_id="c.arm",
            role=VariableRole.C,
            states=("noop", "target"),
            source_query_id="context.randomized_arm_v1",
            scope_id="scope.cwe_89",
            temporal_tier=0,
            adjacency_type="context",
            producer_sha256="c" * 64,
        ),
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    values_by_row = (
        (0, 0, 0),
        (1, 1, 1),
        (0, 1, 1),
        (1, 0, 0),
        (0, 1, 0),
    )
    coordinates = (
        ("task-0", "prompt-0", 0),
        ("task-0", "prompt-0", 1),
        ("task-1", "prompt-1", 0),
        ("task-1", "prompt-1", 1),
        ("task-2", "prompt-2", 0),
    )
    observations = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=task_id,
                prompt_id=prompt_id,
                model_id="model-a",
                seed_id=seed_id,
                values=values,
            ),
            task_id,
            prompt_id,
            seed_id,
            values,
        )
        for (task_id, prompt_id, seed_id), values in zip(coordinates, values_by_row, strict=True)
    )
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=5,
        independent_task_count=3,
        observation_payload=observations,
    )
    knowledge = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        variable_ids=tuple(item.variable_id for item in table.variables),
        tiers=(
            ("x.safety.sql_parameterization", 1),
            ("y.secure_functional", 2),
        ),
        unconstrained_variable_ids=("c.arm",),
        forbidden_directions=(("y.secure_functional", "x.safety.sql_parameterization"),),
        forbidden_adjacencies=(),
        required_directions=(),
    )
    return table, knowledge, np.asarray(values_by_row, dtype=np.int64)


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[np.ndarray, PAGRunKind]] = []

    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        assert matrix.dtype == np.dtype(np.int64)
        assert matrix.shape == (table.independent_task_count, len(table.variables))
        assert not matrix.flags.writeable
        self.calls.append((matrix.copy(), run_kind))
        return PAGRecord.from_content(
            run_kind=run_kind,
            table_id=table.table_id,
            backend=config.backend,
            backend_version=config.backend_version,
            ci_test=config.ci_test,
            config_sha256=canonical_sha256(config.model_dump(mode="json")),
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=tuple(item.variable_id for item in table.variables),
            edges=(),
        )


class _FailingRunner(_RecordingRunner):
    def __init__(self, failure: BaseException, *, fail_call: int = 1) -> None:
        super().__init__()
        self._failure = failure
        self._fail_call = fail_call
        self._call_count = 0

    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        current = self._call_count
        self._call_count += 1
        if current == self._fail_call:
            raise self._failure
        return super().run(matrix, table, knowledge, config, run_kind)


def test_reference_draw_selects_one_seed_for_each_sorted_task() -> None:
    from secaware.causal.bootstrap import build_reference_draw, sampling_frame_sha256

    table, rows = _table_and_rows()
    draw = build_reference_draw(table, rows, global_seed=7)

    assert draw.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE
    assert draw.replicate_index is None
    assert tuple(item.task_id for item in draw.items) == ("task-0", "task-1", "task-2")
    assert tuple(item.draw_index for item in draw.items) == (0, 1, 2)
    assert len({item.task_id for item in draw.items}) == table.independent_task_count
    assert all(item.row_id in {row.row_id for row in rows} for item in draw.items)
    frame_sha256 = sampling_frame_sha256(table, rows)
    expected = f'[7,"{table.scope_id}","{table.model_id}","{frame_sha256}","reference"]'
    assert draw.seed_material_sha256 == hashlib.sha256(expected.encode()).hexdigest()


def test_bootstrap_selects_one_seed_per_sampled_task_occurrence() -> None:
    from secaware.causal.bootstrap import build_bootstrap_draw, sampling_frame_sha256

    table, rows = _table_and_rows()
    draw = build_bootstrap_draw(table, rows, global_seed=0, replicate=0)

    assert draw.run_kind is PAGRunKind.OBSERVATIONAL_BOOTSTRAP
    assert draw.replicate_index == 0
    assert len(draw.items) == table.independent_task_count
    assert [item.draw_index for item in draw.items] == list(range(len(draw.items)))
    by_task = {
        task_id: {row.row_id for row in rows if row.task_id == task_id}
        for task_id in {row.task_id for row in rows}
    }
    assert all(item.row_id in by_task[item.task_id] for item in draw.items)
    repeated = [item for item in draw.items if item.task_id == "task-0"]
    assert len(repeated) == 2
    assert repeated[0].seed_id != repeated[1].seed_id
    frame_sha256 = sampling_frame_sha256(table, rows)
    expected = f'[0,"{table.scope_id}","{table.model_id}","{frame_sha256}","bootstrap",0]'
    assert draw.seed_material_sha256 == hashlib.sha256(expected.encode()).hexdigest()


def test_bootstrap_is_clustered_not_row_wise_on_adversarial_rows() -> None:
    from secaware.causal.bootstrap import build_bootstrap_draw

    table, rows = _table_and_rows()
    draw = build_bootstrap_draw(table, rows, global_seed=11, replicate=0)

    # A task occurrence contributes exactly one row, so the draw always has n_tasks rows
    # even though the authenticated source table has n_tasks * n_seeds rows.
    assert len(draw.selected_row_ids) == 3
    assert len(draw.selected_row_ids) != table.row_count


def test_draws_are_input_order_invariant_and_content_addressed() -> None:
    from secaware.causal.bootstrap import build_bootstrap_draw, build_reference_draw

    table, rows = _table_and_rows()
    reversed_rows = tuple(reversed(rows))

    assert build_reference_draw(table, rows, 91) == build_reference_draw(table, reversed_rows, 91)
    assert build_bootstrap_draw(table, rows, 91, 5) == build_bootstrap_draw(
        table, reversed_rows, 91, 5
    )


def test_sampling_is_pre_outcome_and_changes_only_with_coordinate_frame() -> None:
    from secaware.causal.bootstrap import (
        build_bootstrap_draw,
        build_reference_draw,
        sampling_frame_sha256,
    )

    table, rows = _table_and_rows()
    flipped_table, flipped_rows = _rebuild_bundle(table, rows, flip_outcome=True)
    changed_table, changed_rows = _rebuild_bundle(table, rows, change_first_prompt=True)

    assert table.table_id != flipped_table.table_id
    assert sampling_frame_sha256(table, rows) == sampling_frame_sha256(flipped_table, flipped_rows)
    assert sampling_frame_sha256(table, rows) != sampling_frame_sha256(changed_table, changed_rows)
    for builder, trailing in ((build_reference_draw, ()), (build_bootstrap_draw, (4,))):
        original = builder(table, rows, 73, *trailing)
        flipped = builder(flipped_table, flipped_rows, 73, *trailing)
        original_coordinates = tuple(
            (item.task_id, item.prompt_id, item.seed_id) for item in original.items
        )
        flipped_coordinates = tuple(
            (item.task_id, item.prompt_id, item.seed_id) for item in flipped.items
        )
        assert original.seed_material_sha256 == flipped.seed_material_sha256
        assert original_coordinates == flipped_coordinates
        assert original.selected_row_ids != flipped.selected_row_ids


def test_draws_reject_inexact_or_tampered_table_row_bundles() -> None:
    from secaware.causal.bootstrap import build_reference_draw

    table, rows = _table_and_rows()
    tampered = deepcopy(rows[0])
    object.__setattr__(tampered, "values", (1 - rows[0].values[0], rows[0].values[1]))

    for bad_rows in (rows[:-1], (*rows, rows[0]), (tampered, *rows[1:])):
        with pytest.raises(SecAwareError, match="bootstrap inputs failed validation"):
            build_reference_draw(table, bad_rows, 7)


@pytest.mark.parametrize(
    ("global_seed", "replicate"),
    ((True, 0), (0, True), (2**63, 0), (0, -1), (0, 10_000)),
)
def test_draw_coordinates_are_strict_and_bounded(global_seed: object, replicate: object) -> None:
    from secaware.causal.bootstrap import build_bootstrap_draw

    table, rows = _table_and_rows()
    with pytest.raises(SecAwareError, match="bootstrap inputs failed validation"):
        build_bootstrap_draw(
            table,
            rows,
            global_seed=global_seed,  # type: ignore[arg-type]
            replicate=replicate,  # type: ignore[arg-type]
        )


def test_per_task_seed_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import secaware.causal.bootstrap as bootstrap

    table, rows = _table_and_rows()
    monkeypatch.setattr(bootstrap, "_MAX_SEEDS_PER_TASK", 2)

    with pytest.raises(SecAwareError, match="bootstrap inputs failed validation"):
        bootstrap.build_reference_draw(table, rows, 7)


def test_authenticated_matrix_uses_only_draw_selected_rows_and_is_read_only() -> None:
    from secaware.causal.bootstrap import authenticated_matrix_from_draw, build_bootstrap_draw

    table, rows = _table_and_rows()
    draw = build_bootstrap_draw(table, rows, 7, 3)
    row_by_id = {row.row_id: row for row in rows}

    matrix = authenticated_matrix_from_draw(table, rows, draw)

    assert matrix.dtype == np.dtype(np.int64)
    assert not matrix.flags.writeable
    assert matrix.tolist() == [list(row_by_id[item.row_id].values) for item in draw.items]


def test_authenticated_matrix_rejects_draw_or_row_provenance_mutation() -> None:
    from secaware.causal.bootstrap import authenticated_matrix_from_draw, build_reference_draw

    table, rows = _table_and_rows()
    draw = build_reference_draw(table, rows, 7)
    mutated = deepcopy(draw)
    object.__setattr__(mutated.items[0], "row_id", rows[-1].row_id)

    with pytest.raises(SecAwareError, match="bootstrap inputs failed validation"):
        authenticated_matrix_from_draw(table, rows, mutated)


def test_fci_input_validation_accepts_authenticated_one_seed_per_task_matrix() -> None:
    from secaware.causal.bootstrap import authenticated_matrix_from_draw, build_reference_draw
    from secaware.discovery.causal_learn_backend import validate_fci_inputs

    table, rows = _table_and_rows()
    knowledge = build_background_knowledge(table)
    matrix = authenticated_matrix_from_draw(table, rows, build_reference_draw(table, rows, 7))

    checked, *_rest = validate_fci_inputs(
        matrix,
        table,
        knowledge,
        _config(),
        PAGRunKind.OBSERVATIONAL_REFERENCE,
    )
    assert checked.shape[0] == table.independent_task_count


@pytest.mark.parametrize(
    "run_kind",
    (PAGRunKind.JCI_RAW, PAGRunKind.JCI_CONSTRAINED),
)
def test_jci_input_validation_keeps_all_rows_when_rows_are_not_divisible_by_tasks(
    run_kind: PAGRunKind,
) -> None:
    from secaware.discovery.causal_learn_backend import validate_fci_inputs

    table, knowledge, matrix = _jci_table_and_matrix()
    assert table.row_count == 5
    assert table.independent_task_count == 3

    checked, *_rest = validate_fci_inputs(
        matrix,
        table,
        knowledge,
        _config(),
        run_kind,
    )

    assert checked.shape == (table.row_count, len(table.variables))


def test_runner_receives_reference_then_exact_configured_replicate_count() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()
    runner = _RecordingRunner()
    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=4),
        global_seed=17,
        runner=runner,
    )

    assert result.reference_draw.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE
    assert result.reference_pag.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE
    assert len(result.replicates) == 4
    assert tuple(item.draw.replicate_index for item in result.replicates) == (0, 1, 2, 3)
    assert all((item.pag is None) != (item.failure is None) for item in result.replicates)
    assert tuple(kind for _matrix, kind in runner.calls) == (
        PAGRunKind.OBSERVATIONAL_REFERENCE,
        *(PAGRunKind.OBSERVATIONAL_BOOTSTRAP for _index in range(4)),
    )


def test_successes_are_draw_and_matrix_bound_pag_envelopes() -> None:
    from secaware.causal.bootstrap import (
        authenticated_matrix_from_draw,
        run_task_cluster_fci_bootstrap,
    )
    from secaware.schema.causal import BootstrapPAGRecord

    table, rows = _table_and_rows()
    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=3),
        global_seed=17,
        runner=_RecordingRunner(),
    )

    assert all(isinstance(item, BootstrapPAGRecord) for item in result.bootstrap_pags)
    assert tuple(item.draw_id for item in result.bootstrap_pags) == tuple(
        item.draw.draw_id for item in result.replicates
    )
    assert len({item.bootstrap_pag_id for item in result.bootstrap_pags}) == 3
    assert len({item.pag.pag_id for item in result.bootstrap_pags}) == 1
    assert result.pag_records == tuple(item.pag for item in result.bootstrap_pags)
    for envelope, replicate in zip(result.bootstrap_pags, result.replicates, strict=True):
        matrix = authenticated_matrix_from_draw(table, rows, replicate.draw)
        assert envelope.matrix_sha256 == canonical_sha256(
            {
                "table_sha256": table.table_sha256,
                "draw_sha256": replicate.draw.draw_sha256,
                "values": matrix.tolist(),
            }
        )


def test_injected_runner_produces_identical_canonical_results_across_runs() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()
    knowledge = build_background_knowledge(table)
    config = _config(bootstrap_samples=3)

    first = run_task_cluster_fci_bootstrap(
        table, rows, knowledge, config, global_seed=19, runner=_RecordingRunner()
    )
    second = run_task_cluster_fci_bootstrap(
        table,
        tuple(reversed(rows)),
        knowledge,
        config,
        global_seed=19,
        runner=_RecordingRunner(),
    )

    assert first == second


def test_run_authenticates_the_full_table_bundle_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.causal.bootstrap as bootstrap

    table, rows = _table_and_rows()
    original = bootstrap._authenticate_bundle
    calls: list[object] = []

    def counted(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(bootstrap, "_authenticate_bundle", counted)
    bootstrap.run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=2),
        global_seed=19,
        runner=_RecordingRunner(),
    )

    assert len(calls) == 1


def test_failed_replicate_remains_in_order_and_denominator() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()
    failure = SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.discovery.supervisor",
        message="FCI worker timed out",
        details={"raw_prompt": "must never persist"},
    )
    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=3),
        global_seed=23,
        runner=_FailingRunner(failure, fail_call=2),
    )

    assert len(result.replicates) == 3
    assert result.replicates[1].failure is not None
    typed = result.replicates[1].failure
    assert typed.reason_code is BootstrapFailureReason.BACKEND_TIMEOUT
    assert typed.draw_id == result.replicates[1].draw.draw_id
    assert "must never persist" not in repr(typed)


@pytest.mark.parametrize(
    ("message", "reason"),
    (
        ("FCI worker timed out", BootstrapFailureReason.BACKEND_TIMEOUT),
        ("FCI worker failed validation", BootstrapFailureReason.BACKEND_CRASH),
        (
            "FCI worker violated background knowledge",
            BootstrapFailureReason.BACKGROUND_KNOWLEDGE_VIOLATION,
        ),
        ("degenerate G-square support", BootstrapFailureReason.DEGENERATE_GSQ_SUPPORT),
        ("FCI worker returned noncanonical output", BootstrapFailureReason.INVALID_BACKEND_OUTPUT),
    ),
)
def test_runner_failures_map_to_finite_safe_reason_codes(
    message: str,
    reason: BootstrapFailureReason,
) -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()
    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=1),
        global_seed=31,
        runner=_FailingRunner(
            SecAwareError(
                code=ErrorCode.ANALYSIS_INVALID,
                stage="causal.discovery.supervisor",
                message=message,
            )
        ),
    )

    assert result.replicates[0].failure is not None
    assert result.replicates[0].failure.reason_code is reason


def test_unexpected_runner_exception_is_typed_as_backend_crash_without_raw_text() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()
    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=1),
        global_seed=37,
        runner=_FailingRunner(RuntimeError("raw prompt and credentials")),
    )

    failure = result.replicates[0].failure
    assert failure is not None
    assert failure.reason_code is BootstrapFailureReason.BACKEND_CRASH
    assert "raw prompt" not in repr(failure)
    assert "credentials" not in repr(failure)


def test_invalid_returned_pag_is_typed_and_does_not_shorten_results() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()

    class WrongKindRunner(_RecordingRunner):
        def run(self, *args: object, **kwargs: object) -> PAGRecord:
            pag = super().run(*args, **kwargs)  # type: ignore[arg-type]
            payload = pag.model_dump(mode="json", exclude={"pag_id"})
            payload["run_kind"] = PAGRunKind.OBSERVATIONAL_REFERENCE
            return PAGRecord.from_content(**payload)

    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        build_background_knowledge(table),
        _config(bootstrap_samples=2),
        global_seed=41,
        runner=WrongKindRunner(),
    )

    assert len(result.replicates) == 2
    assert all(item.failure is not None for item in result.replicates)
    assert all(
        item.failure.reason_code is BootstrapFailureReason.INVALID_BACKEND_OUTPUT
        for item in result.replicates
        if item.failure is not None
    )


@pytest.mark.parametrize("interrupt", (KeyboardInterrupt(), SystemExit(7)))
def test_process_control_exceptions_propagate(interrupt: BaseException) -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()
    with pytest.raises(type(interrupt)):
        run_task_cluster_fci_bootstrap(
            table,
            rows,
            build_background_knowledge(table),
            _config(bootstrap_samples=1),
            global_seed=43,
            runner=_FailingRunner(interrupt),
        )


def test_reference_pag_provenance_is_revalidated_before_bootstrap() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    table, rows = _table_and_rows()

    class WrongReferenceRunner(_RecordingRunner):
        def run(self, *args: object, **kwargs: object) -> PAGRecord:
            pag = super().run(*args, **kwargs)  # type: ignore[arg-type]
            payload = pag.model_dump(mode="json", exclude={"pag_id"})
            payload["config_sha256"] = "f" * 64
            return PAGRecord.from_content(**payload)

    runner = WrongReferenceRunner()
    with pytest.raises(SecAwareError, match="reference FCI run failed validation"):
        run_task_cluster_fci_bootstrap(
            table,
            rows,
            build_background_knowledge(table),
            _config(bootstrap_samples=2),
            global_seed=47,
            runner=runner,
        )
    assert len(runner.calls) == 1


def test_bootstrap_api_never_accepts_an_arbitrary_matrix_or_imports_random() -> None:
    from secaware.causal.bootstrap import run_task_cluster_fci_bootstrap

    assert "matrix" not in inspect.signature(run_task_cluster_fci_bootstrap).parameters
    source = Path("src/secaware/causal/bootstrap.py").read_text(encoding="utf-8")
    assert "import random" not in source
    assert "from random" not in source

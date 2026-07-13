from __future__ import annotations

from copy import deepcopy

import pytest

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BootstrapDrawItem,
    BootstrapDrawRecord,
    BootstrapFailureReason,
    BootstrapFailureRecord,
    BootstrapPAGRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
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


def _table() -> CausalTableRecord:
    variables = (
        _variable("w.language_family"),
        _variable("x.presentation.noop_rewrite"),
        _variable("x.safety.generic_security_reminder"),
        _variable("x.safety.sql_parameterization"),
        _variable("y.cwe_security"),
        _variable("y.secure_functional"),
    )
    rows = (
        ("task-0", "prompt-0", 0, (0, 0, 0, 1, 0, 1)),
        ("task-1", "prompt-1", 0, (1, 1, 1, 0, 1, 0)),
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
        for task_id, prompt_id, seed_id, values in rows
    )
    return CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=2,
        independent_task_count=2,
        observation_payload=observations,
    )


def _edge(
    source: str,
    target: str,
    source_mark: EndpointMark | str = EndpointMark.TAIL,
    target_mark: EndpointMark | str = EndpointMark.ARROW,
) -> PAGEdgeRecord:
    return PAGEdgeRecord(
        left=source,
        right=target,
        left_mark=source_mark,
        right_mark=target_mark,
    )


def _pag(
    table: CausalTableRecord,
    edges: tuple[PAGEdgeRecord, ...],
    *,
    run_kind: PAGRunKind = PAGRunKind.OBSERVATIONAL_REFERENCE,
    config: FCIDiscoveryConfig | None = None,
) -> PAGRecord:
    selected_config = config or FCIDiscoveryConfig(min_independent_tasks=2, bootstrap_samples=3)
    knowledge = build_background_knowledge(table)
    return PAGRecord.from_content(
        run_kind=run_kind,
        table_id=table.table_id,
        backend=selected_config.backend,
        backend_version=selected_config.backend_version,
        ci_test=selected_config.ci_test,
        config_sha256=canonical_sha256(selected_config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=edges,
    )


def _draw(table: CausalTableRecord, replicate: int) -> BootstrapDrawRecord:
    items = tuple(
        BootstrapDrawItem(
            draw_index=index,
            task_id=f"task-{index}",
            prompt_id=f"prompt-{index}",
            seed_id=0,
            row_id=f"row_{str(index + 1) * 64}"[:68],
        )
        for index in range(2)
    )
    return BootstrapDrawRecord.from_content(
        table_id=table.table_id,
        run_kind=PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
        replicate_index=replicate,
        rng_version="sha256-rejection-fy-v1",
        seed_material_sha256=f"{replicate + 1:064x}",
        items=items,
    )


def _envelope(
    table: CausalTableRecord,
    config: FCIDiscoveryConfig,
    draw: BootstrapDrawRecord,
    edges: tuple[PAGEdgeRecord, ...],
) -> BootstrapPAGRecord:
    return BootstrapPAGRecord.from_content(
        table_id=table.table_id,
        replicate_index=draw.replicate_index,
        draw_id=draw.draw_id,
        matrix_sha256=f"{draw.replicate_index + 10:064x}",
        pag=_pag(table, edges, run_kind=PAGRunKind.OBSERVATIONAL_BOOTSTRAP, config=config),
    )


def test_endpoint_direction_and_compatibility_are_exact() -> None:
    from secaware.causal.paths import (
        edge_allows_possible_direction,
        endpoint_marks_compatible,
    )

    assert edge_allows_possible_direction(_edge("x.a", "y.b", "circle", "arrow"), "x.a", "y.b")
    assert edge_allows_possible_direction(_edge("x.a", "y.b", "tail", "circle"), "x.a", "y.b")
    assert not edge_allows_possible_direction(_edge("x.a", "y.b", "arrow", "tail"), "x.a", "y.b")
    assert endpoint_marks_compatible(EndpointMark.TAIL, EndpointMark.CIRCLE)
    assert endpoint_marks_compatible(EndpointMark.CIRCLE, EndpointMark.ARROW)
    assert not endpoint_marks_compatible(EndpointMark.TAIL, EndpointMark.ARROW)


def test_enumerates_sorted_direct_mediated_and_long_prompt_paths() -> None:
    from secaware.causal.paths import enumerate_possible_prompt_paths

    table = _table()
    x = "x.safety.sql_parameterization"
    w = "w.language_family"
    z = "x.safety.generic_security_reminder"
    y = "y.secure_functional"
    reference = _pag(
        table,
        (
            _edge(x, y),
            _edge(x, w),
            _edge(w, y),
            _edge(x, z, "circle", "arrow"),
            _edge(z, w, "tail", "circle"),
        ),
    )

    paths = enumerate_possible_prompt_paths(
        reference,
        max_path_length=3,
        max_candidate_paths=20,
    )

    assert tuple(item.variable_ids for item in paths) == tuple(
        sorted(
            (
                (x, w, y),
                (x, z, w, y),
                (x, y),
                (z, w, y),
            )
        )
    )
    direct = next(item for item in paths if item.variable_ids == (x, y))
    assert direct.endpoint_marks == ((EndpointMark.TAIL, EndpointMark.ARROW),)


@pytest.mark.parametrize(
    "internal",
    (
        "x.motif.user_string_to_sql_without_parameterization",
        "x.code.guard_present",
        "w.code_trace",
        "w.dynamic_runtime",
        "c.arm",
    ),
)
def test_rejects_motif_code_context_and_internal_outcome_variables(internal: str) -> None:
    from secaware.causal.paths import enumerate_possible_prompt_paths

    table = _table()
    x = "x.safety.sql_parameterization"
    y = "y.secure_functional"
    payload = _pag(table, (_edge(x, y),)).model_dump(mode="json", exclude={"pag_id"})
    payload["variable_ids"] = (*payload["variable_ids"], internal)
    payload["edges"] = (_edge(x, internal), _edge(internal, y))
    reference = PAGRecord.from_content(**payload)

    assert enumerate_possible_prompt_paths(
        reference, max_path_length=3, max_candidate_paths=10
    ) == ()


def test_preregistered_outcome_cannot_be_used_as_an_internal_node() -> None:
    from secaware.causal.paths import enumerate_possible_prompt_paths

    table = _table()
    x = "x.safety.sql_parameterization"
    internal_y = "y.cwe_security"
    final_y = "y.secure_functional"
    reference = _pag(table, (_edge(x, internal_y), _edge(internal_y, final_y)))

    paths = enumerate_possible_prompt_paths(
        reference, max_path_length=3, max_candidate_paths=10
    )

    assert tuple(item.variable_ids for item in paths) == ((x, internal_y),)


def test_path_hop_and_candidate_bounds_fail_before_unbounded_collection() -> None:
    from secaware.causal.paths import enumerate_possible_prompt_paths

    table = _table()
    x = "x.safety.sql_parameterization"
    y = "y.secure_functional"
    reference = _pag(
        table,
        (
            _edge(x, y),
            _edge("x.presentation.noop_rewrite", y),
        ),
    )

    with pytest.raises(SecAwareError, match="candidate path limit"):
        enumerate_possible_prompt_paths(
            reference,
            max_path_length=1,
            max_candidate_paths=1,
        )
    with pytest.raises(SecAwareError, match="path bounds failed validation"):
        enumerate_possible_prompt_paths(
            reference,
            max_path_length=17,
            max_candidate_paths=1,
        )


def test_dead_end_simple_path_search_has_a_hard_expansion_budget() -> None:
    from secaware.causal.paths import enumerate_possible_prompt_paths

    table = _table()
    base = _pag(table, ())
    x_ids = (
        "x.presentation.length_matched_placebo",
        "x.presentation.matched_control",
        "x.presentation.sham_edit",
        "x.task.database_query",
    )
    payload = base.model_dump(mode="json", exclude={"pag_id"})
    payload["variable_ids"] = (*payload["variable_ids"], *x_ids)
    payload["edges"] = tuple(
        _edge(left, right, "circle", "circle")
        for index, left in enumerate(x_ids)
        for right in x_ids[index + 1 :]
    )
    reference = PAGRecord.from_content(**payload)

    with pytest.raises(SecAwareError, match="candidate path search limit"):
        enumerate_possible_prompt_paths(
            reference,
            max_path_length=16,
            max_candidate_paths=1,
        )


def test_bootstrap_support_uses_exact_denominator_circle_compatibility_and_failed_zero() -> None:
    from secaware.causal.paths import compute_bootstrap_path_support

    table = _table()
    knowledge = build_background_knowledge(table)
    config = FCIDiscoveryConfig(
        min_independent_tasks=2,
        bootstrap_samples=3,
        max_path_length=2,
        max_candidate_paths=20,
    )
    x = "x.safety.sql_parameterization"
    y = "y.secure_functional"
    reference = _pag(table, (_edge(x, y, "tail", "arrow"),), config=config)
    draws = tuple(_draw(table, index) for index in range(3))
    envelopes = (
        _envelope(table, config, draws[0], (_edge(x, y, "tail", "arrow"),)),
        _envelope(table, config, draws[1], (_edge(x, y, "circle", "arrow"),)),
    )
    failure = BootstrapFailureRecord.from_content(
        table_id=table.table_id,
        replicate_index=2,
        draw_id=draws[2].draw_id,
        reason_code=BootstrapFailureReason.BACKEND_TIMEOUT,
        fci_config_sha256=canonical_sha256(config.model_dump(mode="json")),
        detail_sha256="d" * 64,
    )

    supports = compute_bootstrap_path_support(
        table=table,
        knowledge=knowledge,
        config=config,
        reference_pag=reference,
        bootstrap_draws=draws,
        bootstrap_pags=envelopes,
        bootstrap_failures=(failure,),
    )

    assert len(supports) == 1
    assert supports[0].support_numerator == 2
    assert supports[0].support_denominator == 3


def test_bootstrap_support_rejects_missing_duplicate_or_unauthenticated_replicates() -> None:
    from secaware.causal.paths import compute_bootstrap_path_support

    table = _table()
    knowledge = build_background_knowledge(table)
    config = FCIDiscoveryConfig(min_independent_tasks=2, bootstrap_samples=2)
    x = "x.safety.sql_parameterization"
    y = "y.secure_functional"
    reference = _pag(table, (_edge(x, y),), config=config)
    draws = tuple(_draw(table, index) for index in range(2))
    first = _envelope(table, config, draws[0], (_edge(x, y),))

    with pytest.raises(SecAwareError, match="bootstrap support inputs failed validation"):
        compute_bootstrap_path_support(
            table=table,
            knowledge=knowledge,
            config=config,
            reference_pag=reference,
            bootstrap_draws=draws,
            bootstrap_pags=(first,),
            bootstrap_failures=(),
        )

    tampered = deepcopy(first)
    object.__setattr__(tampered, "draw_id", draws[1].draw_id)
    with pytest.raises(SecAwareError, match="bootstrap support inputs failed validation"):
        compute_bootstrap_path_support(
            table=table,
            knowledge=knowledge,
            config=config,
            reference_pag=reference,
            bootstrap_draws=draws,
            bootstrap_pags=(tampered, first),
            bootstrap_failures=(),
        )

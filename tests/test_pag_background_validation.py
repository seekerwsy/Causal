from __future__ import annotations

from copy import deepcopy
from itertools import product

import pytest

from secaware.errors import SecAwareError
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    VariableRole,
)


SHA_A = "a" * 64


def _variable(
    variable_id: str,
    role: VariableRole,
    tier: int,
    adjacency_type: str,
) -> CausalVariableSpec:
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=variable_id,
        role=role,
        states=("absent", "present"),
        source_query_id=f"query.{variable_id}",
        scope_id="scope.sql",
        temporal_tier=tier,
        adjacency_type=adjacency_type,
        producer_sha256=SHA_A,
    )


def _table() -> CausalTableRecord:
    variables = (
        _variable("w.language_family", VariableRole.W, 0, "task_metadata"),
        _variable(
            "x.safety.sql_parameterization",
            VariableRole.X,
            1,
            "prompt_safety_control",
        ),
        _variable("y.secure_functional", VariableRole.Y, 2, "outcome"),
    )
    values = ((0, 1, 1), (1, 0, 0))
    payload = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=f"task-{index}",
                prompt_id=f"prompt-{index}",
                model_id="model-a",
                seed_id=index,
                values=row_values,
            ),
            f"task-{index}",
            f"prompt-{index}",
            index,
            row_values,
        )
        for index, row_values in enumerate(values, start=1)
    )
    return CausalTableRecord.from_content(
        scope_id="scope.sql",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=2,
        independent_task_count=2,
        observation_payload=payload,
    )


def _pag(
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    edges: tuple[PAGEdgeRecord, ...] = (),
    *,
    run_kind: PAGRunKind = PAGRunKind.OBSERVATIONAL_REFERENCE,
    variable_ids: tuple[str, ...] | None = None,
    table_id: str | None = None,
    background_sha256: str | None = None,
) -> PAGRecord:
    return PAGRecord.from_content(
        run_kind=run_kind,
        table_id=table_id or table.table_id,
        backend="causal_learn_fci_v1",
        backend_version="0.1.4.7",
        ci_test="gsq",
        config_sha256=SHA_A,
        background_knowledge_sha256=background_sha256 or knowledge.knowledge_sha256,
        variable_ids=variable_ids or tuple(item.variable_id for item in table.variables),
        edges=edges,
    )


@pytest.mark.parametrize(
    ("source_mark", "target_mark"),
    tuple(product(EndpointMark, repeat=2)),
)
def test_pag_direction_semantics_cover_every_endpoint_combination(
    source_mark: EndpointMark,
    target_mark: EndpointMark,
) -> None:
    from secaware.causal.background import pag_permits_direction

    edge = PAGEdgeRecord(
        left="y.secure_functional",
        right="x.safety.sql_parameterization",
        left_mark=source_mark,
        right_mark=target_mark,
    )
    expected = source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }

    assert (
        pag_permits_direction(
            edge,
            "y.secure_functional",
            "x.safety.sql_parameterization",
        )
        is expected
    )
    assert edge.left == "x.safety.sql_parameterization"
    assert edge.marks_from("y.secure_functional", "x.safety.sql_parameterization") == (
        source_mark,
        target_mark,
    )


def test_valid_pag_passes_exact_background_and_provenance_checks() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = build_background_knowledge(table)
    edge = PAGEdgeRecord(
        left="x.safety.sql_parameterization",
        right="y.secure_functional",
        left_mark=EndpointMark.TAIL,
        right_mark=EndpointMark.ARROW,
    )

    validate_pag_against_background(_pag(table, knowledge, (edge,)), knowledge)


@pytest.mark.parametrize(
    ("left_mark", "right_mark"),
    [
        (EndpointMark.ARROW, EndpointMark.TAIL),
        (EndpointMark.CIRCLE, EndpointMark.CIRCLE),
    ],
)
def test_pag_rejects_definite_and_possible_forbidden_reverse_directions(
    left_mark: EndpointMark,
    right_mark: EndpointMark,
) -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = build_background_knowledge(table)
    edge = PAGEdgeRecord(
        left="x.safety.sql_parameterization",
        right="y.secure_functional",
        left_mark=left_mark,
        right_mark=right_mark,
    )

    with pytest.raises(SecAwareError):
        validate_pag_against_background(_pag(table, knowledge, (edge,)), knowledge)


@pytest.mark.parametrize(
    ("left_mark", "right_mark"),
    tuple(product(EndpointMark, repeat=2)),
)
def test_pag_rejects_every_endpoint_form_of_a_forbidden_adjacency(
    left_mark: EndpointMark,
    right_mark: EndpointMark,
) -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = build_background_knowledge(table)
    edge = PAGEdgeRecord(
        left="w.language_family",
        right="x.safety.sql_parameterization",
        left_mark=left_mark,
        right_mark=right_mark,
    )

    with pytest.raises(SecAwareError):
        validate_pag_against_background(_pag(table, knowledge, (edge,)), knowledge)


def test_pag_rejects_incomplete_tier_constraints_and_accidental_required_edges() -> None:
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    tiers = tuple((item.variable_id, item.temporal_tier) for item in table.variables)
    incomplete = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=tiers,
        forbidden_directions=(),
        forbidden_adjacencies=(),
    )
    required = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=tiers,
        forbidden_directions=tuple(
            sorted(
                (source.variable_id, target.variable_id)
                for source in table.variables
                for target in table.variables
                if source.temporal_tier > target.temporal_tier
            )
        ),
        forbidden_adjacencies=(),
        required_directions=(("x.safety.sql_parameterization", "y.secure_functional"),),
    )

    with pytest.raises(SecAwareError):
        validate_pag_against_background(_pag(table, incomplete), incomplete)
    with pytest.raises(SecAwareError):
        validate_pag_against_background(_pag(table, required), required)


def test_pag_rejects_rehashed_background_with_swapped_x_y_tiers() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    original = build_background_knowledge(table)
    swapped_tiers = tuple(
        (
            variable_id,
            2 if variable_id.startswith("x.") else 1 if variable_id.startswith("y.") else tier,
        )
        for variable_id, tier in original.tiers
    )
    swapped_forbidden = tuple(
        sorted(
            (later_id, earlier_id)
            for later_id, later_tier in swapped_tiers
            for earlier_id, earlier_tier in swapped_tiers
            if later_tier > earlier_tier
        )
    )
    forged_knowledge = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=swapped_tiers,
        forbidden_directions=swapped_forbidden,
        forbidden_adjacencies=original.forbidden_adjacencies,
        required_directions=(),
    )
    forged_pag = _pag(table, forged_knowledge)

    with pytest.raises(SecAwareError):
        validate_pag_against_background(forged_pag, forged_knowledge)


@pytest.mark.parametrize("mutation", ["table", "background", "variables", "digest"])
def test_pag_rejects_provenance_closure_and_digest_mutations(mutation: str) -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = build_background_knowledge(table)
    pag = _pag(table, knowledge)
    if mutation == "table":
        pag = _pag(table, knowledge, table_id="table_" + "f" * 64)
    elif mutation == "background":
        pag = _pag(table, knowledge, background_sha256="f" * 64)
    elif mutation == "variables":
        pag = _pag(
            table,
            knowledge,
            variable_ids=("x.unknown", "y.secure_functional"),
        )
    else:
        pag = deepcopy(pag)
        object.__setattr__(pag, "config_sha256", "f" * 64)

    with pytest.raises(SecAwareError):
        validate_pag_against_background(pag, knowledge)


def test_pag_rejects_tampered_background_digest_and_missing_variable_coverage() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = deepcopy(build_background_knowledge(table))
    pag = _pag(table, knowledge)
    object.__setattr__(knowledge, "knowledge_sha256", "f" * 64)

    with pytest.raises(SecAwareError):
        validate_pag_against_background(pag, knowledge)


def test_only_jci_context_variables_may_be_unconstrained() -> None:
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=(("y.secure_functional", 2),),
        unconstrained_variable_ids=("c.arm",),
        forbidden_directions=(),
        forbidden_adjacencies=(),
    )
    observational = _pag(
        table,
        knowledge,
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        variable_ids=("c.arm", "y.secure_functional"),
    )
    jci = _pag(
        table,
        knowledge,
        run_kind=PAGRunKind.JCI_RAW,
        variable_ids=("c.arm", "y.secure_functional"),
    )

    with pytest.raises(SecAwareError):
        validate_pag_against_background(observational, knowledge)
    validate_pag_against_background(jci, knowledge)


def test_pag_validation_errors_do_not_expose_unsafe_model_payloads() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import validate_pag_against_background

    table = _table()
    knowledge = build_background_knowledge(table)
    pag = deepcopy(_pag(table, knowledge))
    object.__setattr__(pag, "table_id", "private-prompt-payload")

    with pytest.raises(SecAwareError) as exc_info:
        validate_pag_against_background(pag, knowledge)

    assert exc_info.value.__cause__ is None
    assert "private-prompt-payload" not in str(exc_info.value)

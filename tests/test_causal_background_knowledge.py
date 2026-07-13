from __future__ import annotations

from copy import deepcopy

import pytest

from causallearn.graph.GraphNode import GraphNode

from secaware.errors import SecAwareError
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    VariableRole,
)


def _variable(variable_id: str) -> CausalVariableSpec:
    from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256

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


def _variables() -> tuple[CausalVariableSpec, ...]:
    return (
        _variable("w.language_family"),
        _variable("x.safety.generic_security_reminder"),
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )


def _table(
    variables: tuple[CausalVariableSpec, ...] | None = None,
) -> CausalTableRecord:
    selected_variables = variables or _variables()
    values = ((0, 0, 1, 1), (1, 1, 0, 0))
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
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=selected_variables,
        row_count=2,
        independent_task_count=2,
        observation_payload=payload,
    )


def test_background_knowledge_is_exact_tier_derived_and_requires_no_candidate_edges() -> None:
    from secaware.causal.background import build_background_knowledge

    table = _table()
    knowledge = build_background_knowledge(table)
    tier_by_id = {item.variable_id: item.temporal_tier for item in table.variables}
    expected_forbidden = tuple(
        sorted(
            (source.variable_id, target.variable_id)
            for source in table.variables
            for target in table.variables
            if source.temporal_tier > target.temporal_tier
        )
    )

    assert knowledge.table_id == table.table_id
    assert knowledge.tiers == tuple(sorted(tier_by_id.items()))
    assert knowledge.unconstrained_variable_ids == ()
    assert knowledge.forbidden_directions == expected_forbidden
    assert knowledge.required_directions == ()
    assert (
        "y.secure_functional",
        "x.safety.sql_parameterization",
    ) in knowledge.forbidden_directions
    assert (
        "x.safety.sql_parameterization",
        "y.secure_functional",
    ) not in knowledge.required_directions


def test_typed_adjacency_mapping_is_finite_canonical_and_does_not_over_forbid() -> None:
    from secaware.causal.background import canonical_pair, typed_adjacency_exclusions

    exclusions = typed_adjacency_exclusions(_variables())

    assert (
        canonical_pair(
            "w.language_family",
            "x.safety.sql_parameterization",
        )
        in exclusions
    )
    assert (
        canonical_pair(
            "x.safety.generic_security_reminder",
            "x.safety.sql_parameterization",
        )
        not in exclusions
    )
    assert (
        canonical_pair(
            "x.safety.sql_parameterization",
            "y.secure_functional",
        )
        not in exclusions
    )
    assert exclusions == tuple(sorted(exclusions))
    assert all(left < right for left, right in exclusions)


def test_backend_translation_uses_exact_nodes_tiers_and_only_forbidden_rules() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.causal.background import to_causal_learn_background

    table = _table()
    knowledge = build_background_knowledge(table)
    backend = to_causal_learn_background(knowledge)
    nodes = {item.variable_id: GraphNode(item.variable_id) for item in table.variables}

    assert {node.get_name() for node in backend.tier_value_map} == set(nodes)
    assert all(
        backend.is_in_which_tier(nodes[variable_id]) == tier
        for variable_id, tier in knowledge.tiers
    )
    assert all(
        backend.is_forbidden(nodes[source], nodes[target])
        for source, target in knowledge.forbidden_directions
    )
    for left, right in knowledge.forbidden_adjacencies:
        assert backend.is_forbidden(nodes[left], nodes[right])
        assert backend.is_forbidden(nodes[right], nodes[left])
    assert backend.required_rules_specs == set()
    assert not backend.is_required(
        nodes["x.safety.sql_parameterization"],
        nodes["y.secure_functional"],
    )


def test_backend_translation_fails_closed_if_backend_silently_ignores_rules(monkeypatch) -> None:
    import secaware.causal.background as background_module

    class NoOpBackground:
        def __init__(self) -> None:
            self.tier_value_map = {}
            self.forbidden_rules_specs = set()
            self.forbidden_pattern_rules_specs = set()
            self.required_rules_specs = set()
            self.required_pattern_rules_specs = set()
            self.forbidden_within_tiers = set()

        def add_node_to_tier(self, _node, _tier):
            return self

        def add_forbidden_by_node(self, _source, _target):
            return self

    monkeypatch.setattr(background_module, "BackgroundKnowledge", NoOpBackground)

    with pytest.raises(SecAwareError):
        background_module.to_causal_learn_background(
            background_module.build_background_knowledge(_table())
        )


def test_backend_translation_rejects_when_only_tier_value_map_is_updated(monkeypatch) -> None:
    import secaware.causal.background as background_module

    class PartialBackground:
        def __init__(self) -> None:
            self.tier_map = {}
            self.tier_value_map = {}
            self.forbidden_rules_specs = set()
            self.forbidden_pattern_rules_specs = set()
            self.required_rules_specs = set()
            self.required_pattern_rules_specs = set()
            self.forbidden_within_tiers = set()

        def add_node_to_tier(self, node, tier):
            self.tier_value_map[node] = tier
            return self

        def add_forbidden_by_node(self, source, target):
            self.forbidden_rules_specs.add((source, target))
            return self

    monkeypatch.setattr(background_module, "BackgroundKnowledge", PartialBackground)

    with pytest.raises(SecAwareError):
        background_module.to_causal_learn_background(
            background_module.build_background_knowledge(_table())
        )


def test_backend_translation_rejects_required_edges_and_non_context_unconstrained_vars() -> None:
    from secaware.causal.background import to_causal_learn_background

    table = _table()
    variable_ids = tuple(item.variable_id for item in table.variables)
    required = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=tuple((item.variable_id, item.temporal_tier) for item in table.variables),
        forbidden_directions=(),
        forbidden_adjacencies=(),
        required_directions=((variable_ids[1], variable_ids[-1]),),
    )
    invalid_unconstrained = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=((variable_ids[-1], 2),),
        unconstrained_variable_ids=(variable_ids[1],),
        forbidden_directions=(),
        forbidden_adjacencies=(),
    )

    with pytest.raises(SecAwareError):
        to_causal_learn_background(required)
    with pytest.raises(SecAwareError):
        to_causal_learn_background(invalid_unconstrained)


def test_background_builder_revalidates_tampered_table_without_leaking_input() -> None:
    from secaware.causal.background import build_background_knowledge

    table = deepcopy(_table())
    object.__setattr__(table, "table_sha256", "private-table-payload")

    with pytest.raises(SecAwareError) as exc_info:
        build_background_knowledge(table)

    assert exc_info.value.__cause__ is None
    assert "private-table-payload" not in str(exc_info.value)


def test_background_builder_rejects_rehashed_role_tier_reversal() -> None:
    from secaware.causal.background import build_background_knowledge

    swapped = []
    for variable in _variables():
        payload = variable.model_dump(mode="python", round_trip=True)
        if variable.role is VariableRole.X:
            payload["temporal_tier"] = 2
        elif variable.role is VariableRole.Y:
            payload["temporal_tier"] = 1
        swapped.append(CausalVariableSpec.model_validate(payload))
    forged_table = _table(tuple(swapped))

    with pytest.raises(SecAwareError):
        build_background_knowledge(forged_table)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adjacency_type", "prompt_task_function"),
        ("source_query_id", "prompt.feature_state.forged.v1"),
        ("producer_sha256", "f" * 64),
    ],
)
def test_background_builder_rejects_rehashed_catalog_declaration_forgery(
    field: str,
    value: object,
) -> None:
    from secaware.causal.background import build_background_knowledge

    variables = list(_variables())
    target = variables[2]
    payload = target.model_dump(mode="python", round_trip=True)
    payload[field] = value
    variables[2] = CausalVariableSpec.model_validate(payload)
    forged_table = _table(tuple(variables))

    with pytest.raises(SecAwareError):
        build_background_knowledge(forged_table)


def test_background_builder_rejects_catalog_variable_outside_cwe_scope() -> None:
    from secaware.causal.background import build_background_knowledge

    variables = list(_variables())
    variables[2] = _variable("x.safety.path_normalization")
    forged_table = _table(tuple(variables))

    with pytest.raises(SecAwareError):
        build_background_knowledge(forged_table)

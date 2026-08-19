from __future__ import annotations

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.schema.causal import (
    CausalTableRecord,
    CausalVariableSpec,
    VariableRole,
    _row_id_from_content,
)


def _variable(variable_id: str, scope_id: str) -> CausalVariableSpec:
    declaration = declaration_by_id(variable_id)
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=declaration.variable_id,
        role=declaration.role,
        states=declaration.states,
        source_query_id=declaration.query_id,
        scope_id=scope_id,
        temporal_tier=declaration.tier,
        adjacency_type=declaration.adjacency_type,
        producer_sha256=declaration_sha256(declaration),
    )


def test_mechanism_and_v2_outcomes_are_typed_closed_declarations() -> None:
    mechanism = declaration_by_id("z.target_mechanism_realized")
    security = declaration_by_id("y.discovery_cwe_secure")
    joint = declaration_by_id("y.discovery_secure_functional")
    functional = declaration_by_id("y.discovery_functional")

    assert mechanism.role is VariableRole.Z
    assert mechanism.tier == 2
    assert security.role is joint.role is functional.role is VariableRole.Y
    assert security.tier == joint.tier == functional.tier == 3


def test_mechanism_background_forbids_outcome_to_z_and_z_to_x_without_required_edges() -> None:
    scope_id = "scope.cwe_78"
    variables = (
        _variable("x.safety.safe_subprocess", scope_id),
        _variable("z.target_mechanism_realized", scope_id),
        _variable("y.discovery_cwe_secure", scope_id),
    )
    observations = tuple(
        (
            _row_id_from_content(
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
        for task_id, prompt_id, seed_id, values in (
            ("task-a", "prompt-a", 1, (0, 0, 0)),
            ("task-b", "prompt-b", 2, (1, 1, 1)),
        )
    )
    table = CausalTableRecord.from_content(
        scope_id=scope_id,
        cwe="CWE-78",
        model_id="model-a",
        variables=variables,
        row_count=2,
        independent_task_count=2,
        observation_payload=observations,
    )

    knowledge = build_background_knowledge(table)

    assert ("y.discovery_cwe_secure", "z.target_mechanism_realized") in (
        knowledge.forbidden_directions
    )
    assert ("z.target_mechanism_realized", "x.safety.safe_subprocess") in (
        knowledge.forbidden_directions
    )
    assert knowledge.required_directions == ()

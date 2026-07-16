from __future__ import annotations

import pytest
from causallearn.graph.GraphNode import GraphNode

from secaware.causal.background import to_causal_learn_background
from secaware.causal.jci import JCI_CONTEXT_EXOGENEITY, build_jci_background
import hashlib
import json
from secaware.schema.causal import (
    CausalTableRecord,
    CausalVariableSpec,
    JCIBackgroundKnowledgeRecord,
    JCIContextSpec,
    VariableRole,
)
from secaware.schema.experiments import ArmRole

from test_jci_table_builder import build_fixture, fixture_for


def _table():
    return build_fixture(fixture_for())[0][0]


def _system_ids(table) -> tuple[str, ...]:
    return tuple(item.variable_id for item in table.variables if item.role is not VariableRole.C)


def test_raw_background_leaves_every_context_incidence_free_in_backend() -> None:
    table = _table()
    base, _jci = build_jci_background(table)

    assert base.unconstrained_variable_ids == ("c.arm",)
    assert all("c.arm" not in pair for pair in base.forbidden_directions)
    assert all("c.arm" not in pair for pair in base.forbidden_adjacencies)
    assert base.required_directions == ()
    backend = to_causal_learn_background(base)
    for system_id in _system_ids(table):
        assert not backend.is_forbidden(GraphNode(system_id), GraphNode("c.arm"))
        assert not backend.is_forbidden(GraphNode("c.arm"), GraphNode(system_id))


def test_jci_background_adds_only_system_to_context_prohibitions() -> None:
    table = _table()
    base, jci = build_jci_background(table)
    constrained = jci.materialized_background_knowledge
    expected = tuple(sorted((system_id, "c.arm") for system_id in _system_ids(table)))

    assert jci.assumption_ids == (JCI_CONTEXT_EXOGENEITY,)
    assert jci.added_forbidden_directions == expected
    assert jci.required_directions == ()
    assert constrained.required_directions == ()
    assert set(constrained.forbidden_directions) == set(base.forbidden_directions) | set(expected)
    assert constrained.forbidden_adjacencies == base.forbidden_adjacencies
    backend = to_causal_learn_background(constrained)
    for system_id in _system_ids(table):
        assert backend.is_forbidden(GraphNode(system_id), GraphNode("c.arm"))
        assert not backend.is_forbidden(GraphNode("c.arm"), GraphNode(system_id))


def test_base_and_jci_knowledge_are_strict_content_addressed_and_bound() -> None:
    base, jci = build_jci_background(_table())
    assert jci.base_background_knowledge_sha256 == base.knowledge_sha256
    for update in (
        {"assumption_ids": ("jci.forged.v1",)},
        {"base_background_knowledge_sha256": "f" * 64},
        {"knowledge_sha256": "f" * 64},
        {"knowledge_id": "jci_bk_" + "f" * 64},
        {"added_forbidden_directions": ()},
    ):
        with pytest.raises(Exception, match="JCI"):
            JCIBackgroundKnowledgeRecord.model_validate(jci.model_copy(update=update))


def test_recomputed_outer_digest_cannot_hide_forged_base_binding() -> None:
    _base, jci = build_jci_background(_table())
    payload = jci.model_dump(mode="json", exclude={"knowledge_id", "knowledge_sha256"})
    payload["base_background_knowledge_sha256"] = "f" * 64
    digest = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    with pytest.raises(Exception, match="JCI"):
        JCIBackgroundKnowledgeRecord(
            **payload,
            knowledge_id="jci_bk_" + digest,
            knowledge_sha256=digest,
        )


def test_context_one_hot_or_nominal_tier_materialization_is_rejected() -> None:
    table = _table()
    context = next(item for item in table.variables if item.variable_id == "c.arm")
    one_hot = CausalVariableSpec(
        schema_version="1.0",
        variable_id="c.arm.target_patch",
        role=VariableRole.C,
        states=("absent", "present"),
        source_query_id="assignment.one_hot.forged.v1",
        scope_id=table.scope_id,
        temporal_tier=0,
        adjacency_type="jci_context",
        producer_sha256="f" * 64,
    )
    forged = table.model_copy(
        update={
            "variables": tuple(sorted((*table.variables, one_hot), key=lambda x: x.variable_id))
        }
    )
    with pytest.raises(Exception, match="JCI"):
        build_jci_background(forged)

    base, _ = build_jci_background(table)
    tiers = dict(base.tiers)
    assert context.variable_id not in tiers
    assert set(tiers) == set(_system_ids(table))


def test_context_category_domain_must_be_exact_arm_roles() -> None:
    table = _table()
    variables = tuple(
        item.model_copy(update={"states": (ArmRole.NOOP_REWRITE.value, ArmRole.TARGET_PATCH.value)})
        if item.variable_id == "c.arm"
        else item
        for item in table.variables
    )
    forged = CausalTableRecord.model_construct(**{**table.__dict__, "variables": variables})
    with pytest.raises(Exception, match="JCI"):
        build_jci_background(forged)

    with pytest.raises(Exception, match="JCI"):
        JCIContextSpec(
            arm_roles=(ArmRole.NOOP_REWRITE, ArmRole.TARGET_PATCH),
            category_codes=(0, 1),
        )


def test_forged_system_variable_declaration_is_rejected_before_backend_conversion() -> None:
    table = _table()
    variables = tuple(
        item.model_copy(update={"producer_sha256": "f" * 64})
        if item.role is not VariableRole.C
        else item
        for item in table.variables
    )
    forged = CausalTableRecord.model_construct(**{**table.__dict__, "variables": variables})

    with pytest.raises(Exception, match="JCI"):
        build_jci_background(forged)

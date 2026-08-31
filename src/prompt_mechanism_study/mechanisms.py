"""Data-driven, context-conditioned mechanism specifications."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.prompt_tsg import (
    PromptTSG,
    QueryState,
    feature_state,
    query_context,
    query_for_realization,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.representation import PairPolicyKey


class MechanismRegistryError(ValueError):
    """Raised when a mechanism registry or task binding is invalid."""


class PairRelation(StrEnum):
    SAME_FLOW = "same_flow"
    SHARED_SINK = "shared_sink"
    DISTINCT_CONTROL_POINTS = "distinct_control_points"
    ALTERNATIVE_CONTROLS = "alternative_controls"
    SEQUENTIAL_CONTROLS = "sequential_controls"
    COMPLEMENTARY_COVERAGE = "complementary_coverage"
    PRECONDITION_FOR = "precondition_for"
    SUBSUMES = "subsumes"
    POTENTIALLY_CONFLICTS_WITH = "potentially_conflicts_with"


PAIR_STRUCTURAL_RELATIONS = frozenset(
    {
        PairRelation.SAME_FLOW,
        PairRelation.SHARED_SINK,
        PairRelation.DISTINCT_CONTROL_POINTS,
        PairRelation.ALTERNATIVE_CONTROLS,
    }
)


def _validate_pair_structural_relation(relation: PairRelation) -> None:
    """Admit only the four prospectively frozen Prompt-TSG relation predicates."""

    if type(relation) is not PairRelation or relation not in PAIR_STRUCTURAL_RELATIONS:
        raise MechanismRegistryError(
            "pair relation is outside the active Pair structural-relation vocabulary"
        )


@dataclass(frozen=True, slots=True)
class ControlPath:
    """One canonical directed Prompt-TSG path; it is semantic, not causal."""

    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.node_ids) < 2 or len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError("a control path needs ordered nodes and one edge per step")
        if len(set(self.node_ids)) != len(self.node_ids) or len(set(self.edge_ids)) != len(
            self.edge_ids
        ):
            raise ValueError("a control path cannot repeat nodes or edges")
        for value in (*self.node_ids, *self.edge_ids):
            require_text(value, "control path identifier")

    @property
    def path_id(self) -> str:
        return content_id("prompt_tsg_control_path_", self)


@dataclass(frozen=True, slots=True)
class PromptControlBinding:
    """Outcome-blind binding from one actionable feature to graph evidence."""

    feature_id: str
    task_id: str
    task_unit_id: str
    prompt_tsg_id: str
    control_node_id: str
    source_node_ids: tuple[str, ...]
    sink_node_ids: tuple[str, ...]
    surface_node_ids: tuple[str, ...]
    paths: tuple[ControlPath, ...]
    alternative_group_node_ids: tuple[str, ...] = ()
    outcomes_or_arms_used: bool = False

    def __post_init__(self) -> None:
        for name in (
            "feature_id",
            "task_id",
            "task_unit_id",
            "prompt_tsg_id",
            "control_node_id",
        ):
            require_text(getattr(self, name), name)
        for values, name, required in (
            (self.source_node_ids, "control sources", True),
            (self.sink_node_ids, "control sinks", True),
            (self.surface_node_ids, "control surfaces", True),
            (self.alternative_group_node_ids, "alternative groups", False),
        ):
            if required and not values:
                raise ValueError(f"{name} cannot be empty")
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{name} must be unique and canonical")
            for value in values:
                require_text(value, name)
        if not self.paths or any(type(item) is not ControlPath for item in self.paths):
            raise TypeError("a control binding requires typed canonical paths")
        if tuple(sorted(self.paths, key=lambda item: item.path_id)) != self.paths:
            raise ValueError("control paths must use canonical content order")
        if len({item.path_id for item in self.paths}) != len(self.paths):
            raise ValueError("control binding paths must be unique")
        if any(
            path.node_ids[0] not in self.source_node_ids
            or path.node_ids[-1] not in self.sink_node_ids
            or self.control_node_id not in path.node_ids
            for path in self.paths
        ):
            raise ValueError("every control path must bind a declared source, control, and sink")
        if self.outcomes_or_arms_used is not False:
            raise ValueError("Prompt control bindings cannot use outcomes or assignments")

    @property
    def control_binding_id(self) -> str:
        return content_id("prompt_control_binding_", self)


@dataclass(frozen=True, slots=True)
class PairStructuralRelationEvidence:
    """Recomputable v3 evidence for one of the four neutral Pair relations."""

    pair_id: str
    relation_spec_id: str
    relation_id: str
    task_id: str
    task_unit_id: str
    prompt_tsg_id: str
    predicate_version: str
    control_binding_ids: tuple[str, str]
    state: QueryState
    reasons: tuple[str, ...]
    evidence_node_ids: tuple[str, ...]
    evidence_edge_ids: tuple[str, ...]
    outcomes_or_arms_used: bool = False

    def __post_init__(self) -> None:
        for name in (
            "pair_id",
            "relation_spec_id",
            "relation_id",
            "task_id",
            "task_unit_id",
            "prompt_tsg_id",
            "predicate_version",
        ):
            require_text(getattr(self, name), name)
        if len(self.control_binding_ids) != 2:
            raise ValueError("Pair relation evidence must bind exactly two controls")
        for value in self.control_binding_ids:
            require_text(value, "control_binding_id")
        if type(self.state) is not QueryState:
            raise TypeError("Pair structural relation state must be typed")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("Pair structural relation reasons must be canonical")
        if self.state in {QueryState.PRESENT, QueryState.ABSENT} and self.reasons:
            raise ValueError("a resolved Pair structural relation cannot have unresolved reasons")
        if self.state is QueryState.UNRESOLVED and not self.reasons:
            raise ValueError("an unresolved Pair structural relation requires reasons")
        for values, name in (
            (self.evidence_node_ids, "relation evidence nodes"),
            (self.evidence_edge_ids, "relation evidence edges"),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{name} must be unique and canonical")
        if self.state is QueryState.PRESENT and not self.evidence_node_ids:
            raise ValueError("a present Pair structural relation needs graph evidence")
        if self.outcomes_or_arms_used is not False:
            raise ValueError("Pair structural relation evidence cannot use outcomes or arms")

    @property
    def evidence_id(self) -> str:
        return content_id("pair_structural_relation_evidence_", self)


def validate_prompt_control_binding(
    graph: PromptTSG,
    binding: PromptControlBinding,
) -> None:
    """Recompute every binding coordinate against the frozen Prompt TSG."""

    if type(graph) is not PromptTSG or type(binding) is not PromptControlBinding:
        raise TypeError("control binding validation requires typed graph and binding")
    if binding.prompt_tsg_id != graph.tsg_id or binding.task_id != graph.task_id:
        raise MechanismRegistryError("control binding graph identity drift")
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}
    referenced_nodes = {
        binding.control_node_id,
        *binding.source_node_ids,
        *binding.sink_node_ids,
        *binding.surface_node_ids,
        *binding.alternative_group_node_ids,
    }
    if not referenced_nodes <= set(nodes):
        raise MechanismRegistryError("control binding references a missing Prompt-TSG node")
    if nodes[binding.control_node_id].semantic_id != binding.feature_id:
        raise MechanismRegistryError("control node does not bind the declared actionable feature")
    for path in binding.paths:
        if not set(path.node_ids) <= set(nodes) or not set(path.edge_ids) <= set(edges):
            raise MechanismRegistryError("control path references missing graph evidence")
        for source_id, target_id, edge_id in zip(
            path.node_ids[:-1],
            path.node_ids[1:],
            path.edge_ids,
            strict=True,
        ):
            edge = edges[edge_id]
            if edge.source_id != source_id or edge.target_id != target_id:
                raise MechanismRegistryError("control path edge order does not replay")


def evaluate_pair_structural_relation(
    *,
    pair_id: str,
    relation_spec_id: str,
    relation: PairRelation,
    task_unit_id: str,
    graph: PromptTSG,
    factor_1_id: str,
    factor_2_id: str,
    factor_1_bindings: Sequence[PromptControlBinding],
    factor_2_bindings: Sequence[PromptControlBinding],
) -> PairStructuralRelationEvidence:
    """Evaluate one neutral relation after compatibility, without outcomes or arms."""

    _validate_pair_structural_relation(relation)
    for value, name in (
        (pair_id, "pair_id"),
        (relation_spec_id, "relation_spec_id"),
        (task_unit_id, "task_unit_id"),
        (factor_1_id, "factor_1_id"),
        (factor_2_id, "factor_2_id"),
    ):
        require_text(value, name)
    if factor_1_id == factor_2_id:
        raise ValueError("Pair structural relation requires two distinct factors")
    first = tuple(factor_1_bindings)
    second = tuple(factor_2_bindings)
    if any(item.feature_id != factor_1_id for item in first) or any(
        item.feature_id != factor_2_id for item in second
    ):
        raise MechanismRegistryError("control bindings drift from the declared Pair factors")
    for binding in (*first, *second):
        if binding.task_unit_id != task_unit_id:
            raise MechanismRegistryError("control binding task-unit identity drift")
        validate_prompt_control_binding(graph, binding)

    reasons = set()
    if len(first) != 1 or len(second) != 1:
        reasons.add(
            "multiple_control_bindings"
            if len(first) > 1 or len(second) > 1
            else "missing_control_binding"
        )
    if factor_1_id in graph.unresolved_semantics or factor_2_id in graph.unresolved_semantics:
        reasons.add("unresolved_control_semantics")
    bindings = tuple(sorted((*first, *second), key=lambda item: item.feature_id))
    node_by_id = {item.node_id: item for item in graph.nodes}
    relevant_semantics = {
        node_by_id[node_id].semantic_id
        for binding in bindings
        for node_id in (
            binding.control_node_id,
            *binding.source_node_ids,
            *binding.sink_node_ids,
            *binding.surface_node_ids,
            *binding.alternative_group_node_ids,
        )
    }
    if any(
        source_semantic in relevant_semantics
        or target_semantic in relevant_semantics
        for source_semantic, _edge_type, target_semantic in graph.unresolved_relations
    ):
        reasons.add("unresolved_pair_relation")
    binding_ids = (
        (
            first[0].control_binding_id
            if len(first) == 1
            else content_id(
                "factor_control_binding_set_",
                tuple(sorted(item.control_binding_id for item in first)),
            )
        ),
        (
            second[0].control_binding_id
            if len(second) == 1
            else content_id(
                "factor_control_binding_set_",
                tuple(sorted(item.control_binding_id for item in second)),
            )
        ),
    )
    evidence_nodes = tuple(
        sorted(
            {
                node_id
                for binding in bindings
                for node_id in (
                    binding.control_node_id,
                    *binding.source_node_ids,
                    *binding.sink_node_ids,
                    *binding.surface_node_ids,
                    *binding.alternative_group_node_ids,
                    *(node for path in binding.paths for node in path.node_ids),
                )
            }
        )
    )
    evidence_edges = tuple(
        sorted(
            {
                edge_id
                for binding in bindings
                for path in binding.paths
                for edge_id in path.edge_ids
            }
        )
    )
    if reasons:
        state = QueryState.UNRESOLVED
    else:
        left, right = first[0], second[0]
        predicate = {
            PairRelation.SAME_FLOW: bool(
                {item.path_id for item in left.paths}
                & {item.path_id for item in right.paths}
            ),
            PairRelation.SHARED_SINK: bool(
                set(left.sink_node_ids) & set(right.sink_node_ids)
            ),
            PairRelation.DISTINCT_CONTROL_POINTS: (
                left.control_node_id != right.control_node_id
                and not set(left.surface_node_ids) & set(right.surface_node_ids)
            ),
            PairRelation.ALTERNATIVE_CONTROLS: (
                left.control_node_id != right.control_node_id
                and not set(left.surface_node_ids) & set(right.surface_node_ids)
                and bool(
                    set(left.alternative_group_node_ids)
                    & set(right.alternative_group_node_ids)
                )
            ),
        }[relation]
        state = QueryState.PRESENT if predicate else QueryState.ABSENT
    return PairStructuralRelationEvidence(
        pair_id,
        relation_spec_id,
        relation.value,
        graph.task_id,
        task_unit_id,
        graph.tsg_id,
        "prompt_tsg_pair_relation_v1",
        binding_ids,
        state,
        tuple(sorted(reasons)),
        evidence_nodes,
        evidence_edges,
    )


class FactorialCompatibility(StrEnum):
    COMPATIBLE = "compatible"
    NESTED = "nested"
    MUTUALLY_EXCLUSIVE = "mutually_exclusive"
    ENTAILMENT_COLLAPSE = "entailment_collapse"
    CONFLICTING = "conflicting"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class PairCompatibilityDecision:
    """Outcome-blind edit-surface decision independent of relation support."""

    policy: PairPolicyKey
    decision: FactorialCompatibility
    rule_id: str
    target_surface_ids: tuple[str, str]
    evidence_sha256: str
    outcomes_or_arms_used: bool = False

    def __post_init__(self) -> None:
        if type(self.policy) is not PairPolicyKey:
            raise TypeError("compatibility policy must be a PairPolicyKey")
        if type(self.decision) is not FactorialCompatibility:
            raise TypeError("compatibility decision must be typed")
        require_text(self.rule_id, "compatibility rule_id")
        if (
            len(self.target_surface_ids) != 2
            or tuple(sorted(self.target_surface_ids)) != self.target_surface_ids
            or len(set(self.target_surface_ids)) != 2
        ):
            raise ValueError("compatibility target surfaces must be two distinct sorted IDs")
        for value in self.target_surface_ids:
            require_text(value, "compatibility target surface")
        _require_digest(self.evidence_sha256, "compatibility evidence")
        if self.outcomes_or_arms_used is not False:
            raise ValueError("factorial compatibility cannot use outcomes or arms")

    @property
    def policy_key(self) -> str:
        return self.policy.policy_key

    @property
    def decision_id(self) -> str:
        return content_id("pair_compatibility_decision_", self)


@dataclass(frozen=True, slots=True)
class PairRelationEvidence:
    """Recomputable task-side evidence for one pair relation contract."""

    pair_id: str
    relation_spec_id: str
    relation_id: str
    task_id: str
    task_unit_id: str
    prompt_tsg_id: str
    evidence_contract_id: str
    state: QueryState
    evidence_node_ids: tuple[str, ...]
    evidence_edge_ids: tuple[str, ...]
    outcomes_or_arms_used: bool = False

    def __post_init__(self) -> None:
        for name in (
            "pair_id",
            "relation_spec_id",
            "relation_id",
            "task_id",
            "task_unit_id",
            "prompt_tsg_id",
            "evidence_contract_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.state) is not QueryState:
            raise TypeError("relation evidence state must be QueryState")
        if self.evidence_node_ids != tuple(sorted(set(self.evidence_node_ids))) or (
            self.evidence_edge_ids != tuple(sorted(set(self.evidence_edge_ids)))
        ):
            raise ValueError("relation evidence IDs must be unique and sorted")
        if self.state is QueryState.PRESENT and not self.evidence_node_ids:
            raise ValueError("present relation evidence must identify Prompt-TSG nodes")
        if self.outcomes_or_arms_used is not False:
            raise ValueError("pair relation evidence cannot use outcomes or arms")

    @property
    def evidence_id(self) -> str:
        return content_id("pair_relation_evidence_", self)


def load_mechanism_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Load and validate a registry keyed by realization id."""

    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"schema_version", "mechanisms"} or value["schema_version"] not in {
        "1.0",
        "2.0",
    }:
        raise MechanismRegistryError("mechanism registry envelope is invalid")
    rows = value["mechanisms"]
    if not isinstance(rows, list) or not rows:
        raise MechanismRegistryError("mechanism registry is empty")
    result: dict[str, dict[str, Any]] = {}
    legacy_fields = {
        "realization_id",
        "cwe_id",
        "task_family",
        "prompt_markers",
        "oracle_profile_id",
        "specific_contract",
        "must_preserve",
    }
    context_fields = {
        "realization_id",
        "cwe_id",
        "task_family",
        "required_context",
        "excluded_context",
        "oracle_profile_id",
        "required_delta",
        "forbidden_delta",
        "must_preserve",
    }
    required = legacy_fields if value["schema_version"] == "1.0" else context_fields
    for row in rows:
        if not isinstance(row, dict) or set(row) != required:
            raise MechanismRegistryError("mechanism record fields are invalid")
        realization_id = row["realization_id"]
        scalar_fields = ("realization_id", "cwe_id", "task_family", "oracle_profile_id")
        list_fields = (
            ("prompt_markers", "must_preserve")
            if value["schema_version"] == "1.0"
            else (
                "required_context",
                "excluded_context",
                "required_delta",
                "forbidden_delta",
                "must_preserve",
            )
        )
        if (
            any(not isinstance(row[field], str) or not row[field] for field in scalar_fields)
            or any(
                not isinstance(row[field], list)
                or any(not isinstance(item, str) or not item for item in row[field])
                for field in list_fields
            )
            or (
                value["schema_version"] == "1.0"
                and (
                    not isinstance(row["specific_contract"], str)
                    or not row["specific_contract"].strip()
                )
            )
            or (
                value["schema_version"] == "2.0"
                and (
                    not row["required_delta"]
                    or set(row["required_context"]) & set(row["excluded_context"])
                )
            )
            or realization_id in result
        ):
            raise MechanismRegistryError("mechanism record values are invalid")
        result[realization_id] = row
    return result


def mechanism_binding_id(binding: Mapping[str, Any]) -> str:
    """Return the content identity of one task-side binding core."""

    core = {key: value for key, value in binding.items() if key != "binding_id"}
    return content_id("mechanism_binding_", core)


def tsg_mechanism_binding(
    task: Mapping[str, Any],
    graph: PromptTSG,
    catalog: Mapping[str, Any],
    registry: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind one task using only its frozen Prompt TSG and finite catalog queries."""

    relevant = [
        row
        for row in registry.values()
        if row["cwe_id"] == task.get("cwe") and row["task_family"] == task.get("task_family")
    ]
    results = []
    for row in sorted(relevant, key=lambda item: item["realization_id"]):
        query = query_for_realization(catalog, row["realization_id"])
        result = query_context(
            graph,
            query=query,
            cwe=task["cwe"],
            task_family=task["task_family"],
        )
        results.append((row, query, result))
    present = [item for item in results if item[2].state == QueryState.PRESENT]
    selected = present[0] if len(present) == 1 else None
    feature = selected[1]["actionable_feature_id"] if selected else None
    target_state = feature_state(graph, feature).value if feature else "not_applicable"
    controls = {
        semantic_id: feature_state(graph, semantic_id).value
        for semantic_id in ("control.generic_security", "control.code_style")
    }
    if len(present) > 1 or (not present and any(
        item[2].state == QueryState.UNRESOLVED for item in results
    )):
        decision = "unresolved"
    elif not present:
        decision = "not_applicable"
    elif target_state != QueryState.ABSENT.value:
        decision = "target_feature_present" if target_state == "present" else "unresolved"
    elif any(state != QueryState.ABSENT.value for state in controls.values()):
        decision = "control_feature_present"
    else:
        decision = "applicable"
    core = {
        "decision": decision,
        "realization_id": selected[0]["realization_id"] if selected else None,
        "prompt_tsg_id": graph.tsg_id,
        "context_query_id": selected[1]["query_id"] if selected else None,
        "context_state": selected[2].state.value if selected else "unresolved" if decision == "unresolved" else "absent",
        "actionable_feature_id": feature,
        "target_feature_state": target_state,
        "control_feature_states": controls,
        "evidence_node_ids": list(selected[2].evidence_node_ids) if selected else [],
        "evidence_edge_ids": list(selected[2].evidence_edge_ids) if selected else [],
        "query_states": [
            {"query_id": query["query_id"], "state": result.state.value}
            for _, query, result in results
        ],
        "outcomes_or_arms_used": False,
    }
    return {"binding_id": mechanism_binding_id(core), **core}


__all__ = [
    "ControlPath",
    "FactorialCompatibility",
    "MechanismRegistryError",
    "PAIR_STRUCTURAL_RELATIONS",
    "PairCompatibilityDecision",
    "PairRelation",
    "PairRelationEvidence",
    "PairStructuralRelationEvidence",
    "PromptControlBinding",
    "evaluate_pair_structural_relation",
    "load_mechanism_registry",
    "mechanism_binding_id",
    "tsg_mechanism_binding",
    "validate_prompt_control_binding",
]

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
    catalog_sha256,
    feature_state,
    prompt_tsg_from_record,
    query_context,
    query_for_realization,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.representation import Operation, PairPolicyKey


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


ACTIVE_FACTORIAL_RELATIONS = frozenset(
    {
        PairRelation.SAME_FLOW,
        PairRelation.SHARED_SINK,
        PairRelation.DISTINCT_CONTROL_POINTS,
        PairRelation.ALTERNATIVE_CONTROLS,
    }
)


def validate_active_factorial_relation(relation: PairRelation) -> None:
    """Admit only the finite relation vocabulary frozen by successor Section 24."""

    if type(relation) is not PairRelation or relation not in ACTIVE_FACTORIAL_RELATIONS:
        raise MechanismRegistryError(
            "pair relation is outside the active factorial relation vocabulary"
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

    validate_active_factorial_relation(relation)
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


class OracleSupportStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


class InteractionScale(StrEnum):
    RISK_DIFFERENCE = "risk_difference"


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


class PairEligibility(StrEnum):
    APPLICABLE = "applicable"
    CONTEXT_ABSENT = "context_absent"
    CONTEXT_NOT_APPLICABLE = "context_not_applicable"
    CONTEXT_UNRESOLVED = "context_unresolved"
    FACTOR_SOURCE_STATE = "factor_source_state"
    COUNTERPART_MISSING = "counterpart_missing"
    ORACLE_UNSUPPORTED = "oracle_unsupported"


@dataclass(frozen=True, slots=True)
class PairSpec:
    """One prospectively frozen pair of independently editable Prompt factors."""

    pair_context_query_id: str
    factor_1_id: str
    factor_2_id: str
    operation_1: Operation
    operation_2: Operation
    relation_type: PairRelation
    oracle_profile_id: str
    oracle_policy_sha256: str
    oracle_support_status: OracleSupportStatus
    primary_outcome: str
    interaction_scale: InteractionScale = InteractionScale.RISK_DIFFERENCE

    def __post_init__(self) -> None:
        for name in (
            "pair_context_query_id",
            "factor_1_id",
            "factor_2_id",
            "oracle_profile_id",
            "primary_outcome",
        ):
            require_text(getattr(self, name), name)
        if self.factor_1_id == self.factor_2_id:
            raise ValueError("pair factors must be distinct")
        if type(self.operation_1) is not Operation or type(self.operation_2) is not Operation:
            raise TypeError("pair operations must be Operation values")
        if type(self.relation_type) is not PairRelation:
            raise TypeError("relation_type must be a PairRelation")
        if type(self.oracle_support_status) is not OracleSupportStatus:
            raise TypeError("oracle_support_status must be an OracleSupportStatus")
        if type(self.interaction_scale) is not InteractionScale:
            raise TypeError("interaction_scale must be an InteractionScale")
        _require_digest(self.oracle_policy_sha256, "Oracle policy")
        if self.primary_outcome != "oracle_evaluable_secure_code_yield":
            raise ValueError("pair primary outcome must be Oracle-evaluable secure-code yield")

    @property
    def pair_id(self) -> str:
        return content_id("pair_", self)

    @property
    def factors(self) -> tuple[str, str]:
        return self.factor_1_id, self.factor_2_id

    @property
    def operations(self) -> tuple[Operation, Operation]:
        return self.operation_1, self.operation_2


@dataclass(frozen=True, slots=True)
class RelationEvidenceContract:
    """Finite Prompt-TSG motif that licenses one semantic pair relation.

    The contract describes representation evidence only.  Its relations are
    never interpreted as causal edges and its result never estimates an
    intervention effect.
    """

    required_semantics: tuple[str, ...]
    required_relations: tuple[tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        if (
            not self.required_semantics
            or tuple(sorted(self.required_semantics)) != self.required_semantics
            or len(set(self.required_semantics)) != len(self.required_semantics)
            or any(
                not isinstance(value, str) or not value.strip()
                for value in self.required_semantics
            )
        ):
            raise ValueError("relation evidence semantics must be non-empty, unique, and sorted")
        if (
            not self.required_relations
            or tuple(sorted(self.required_relations)) != self.required_relations
            or len(set(self.required_relations)) != len(self.required_relations)
            or any(
                len(relation) != 3
                or any(not isinstance(value, str) or not value.strip() for value in relation)
                for relation in self.required_relations
            )
        ):
            raise ValueError("relation evidence relations must be non-empty, unique, and sorted")
        semantics = set(self.required_semantics)
        if any(
            source not in semantics or target not in semantics
            for source, _, target in self.required_relations
        ):
            raise ValueError("relation endpoints must be declared required semantics")

    @property
    def contract_id(self) -> str:
        return content_id("relation_evidence_contract_", self)


@dataclass(frozen=True, slots=True)
class MechanismRelationSpec:
    """One finite, prospectively declared Prompt-TSG mechanism relation."""

    relation_id: str
    factor_1_id: str
    factor_2_id: str
    relation_type: PairRelation
    factorial_compatibility: FactorialCompatibility
    context_query_id: str
    evidence_contract: RelationEvidenceContract
    eligible_languages: tuple[str, ...]
    eligible_task_families: tuple[str, ...]
    eligible_cwes: tuple[str, ...]
    allowed_operation_pairs: tuple[tuple[Operation, Operation], ...]

    def __post_init__(self) -> None:
        for name in ("relation_id", "factor_1_id", "factor_2_id", "context_query_id"):
            require_text(getattr(self, name), name)
        if self.factor_1_id == self.factor_2_id:
            raise ValueError("mechanism relation factors must be distinct")
        if type(self.relation_type) is not PairRelation:
            raise TypeError("relation_type must be a PairRelation")
        if type(self.factorial_compatibility) is not FactorialCompatibility:
            raise TypeError("factorial_compatibility must be typed")
        if type(self.evidence_contract) is not RelationEvidenceContract:
            raise TypeError("evidence_contract must be a RelationEvidenceContract")
        for values, name in (
            (self.eligible_languages, "eligible languages"),
            (self.eligible_task_families, "eligible task families"),
            (self.eligible_cwes, "eligible CWEs"),
        ):
            if (
                not values
                or tuple(sorted(values)) != values
                or len(set(values)) != len(values)
                or any(not isinstance(value, str) or not value.strip() for value in values)
            ):
                raise ValueError(f"{name} must be non-empty, unique, and sorted")
        if not self.allowed_operation_pairs or len(set(self.allowed_operation_pairs)) != len(
            self.allowed_operation_pairs
        ):
            raise ValueError("allowed operation pairs must be non-empty and unique")
        if any(
            len(pair) != 2 or any(type(operation) is not Operation for operation in pair)
            for pair in self.allowed_operation_pairs
        ):
            raise TypeError("allowed operation pairs must contain Operation values")
        if tuple(
            sorted(self.allowed_operation_pairs, key=lambda pair: (pair[0].value, pair[1].value))
        ) != self.allowed_operation_pairs:
            raise ValueError("allowed operation pairs must use canonical order")

    @property
    def relation_spec_id(self) -> str:
        return content_id("mechanism_relation_", self)

    @property
    def factors(self) -> tuple[str, str]:
        return self.factor_1_id, self.factor_2_id


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


@dataclass(frozen=True, slots=True)
class PairBinding:
    """Outcome-blind task eligibility evidence for one frozen pair."""

    pair_id: str
    task_id: str
    prompt_tsg_id: str
    decision: PairEligibility
    context_query_id: str
    context_state: QueryState
    factor_states: tuple[tuple[str, QueryState], tuple[str, QueryState]]
    neutral_counterpart_ids: tuple[tuple[str, str], ...]
    evidence_node_ids: tuple[str, ...]
    evidence_edge_ids: tuple[str, ...]
    outcomes_or_arms_used: bool = False

    def __post_init__(self) -> None:
        for name in ("pair_id", "task_id", "prompt_tsg_id", "context_query_id"):
            require_text(getattr(self, name), name)
        if type(self.decision) is not PairEligibility:
            raise TypeError("decision must be PairEligibility")
        if type(self.context_state) is not QueryState:
            raise TypeError("context_state must be QueryState")
        if len(self.factor_states) != 2 or any(
            not isinstance(feature, str)
            or not feature
            or type(state) is not QueryState
            for feature, state in self.factor_states
        ):
            raise ValueError("pair binding requires two typed factor states")
        if self.factor_states[0][0] == self.factor_states[1][0]:
            raise ValueError("pair binding factor states must be distinct")
        if self.neutral_counterpart_ids != tuple(sorted(self.neutral_counterpart_ids)):
            raise ValueError("neutral counterpart IDs must use canonical order")
        if self.evidence_node_ids != tuple(sorted(set(self.evidence_node_ids))) or (
            self.evidence_edge_ids != tuple(sorted(set(self.evidence_edge_ids)))
        ):
            raise ValueError("pair binding evidence must be unique and sorted")
        if self.outcomes_or_arms_used is not False:
            raise ValueError("pair binding cannot use outcomes or arms")

    @property
    def binding_id(self) -> str:
        return content_id("pair_binding_", self)


@dataclass(frozen=True, slots=True)
class PairRegistry:
    prompt_tsg_catalog_path: str
    prompt_tsg_catalog_sha256: str
    atomic_factor_ids: tuple[str, ...]
    pairs: tuple[PairSpec, ...]

    def __post_init__(self) -> None:
        require_text(self.prompt_tsg_catalog_path, "Prompt TSG catalog path")
        _require_digest(self.prompt_tsg_catalog_sha256, "Prompt TSG catalog")
        if not self.atomic_factor_ids or len(self.atomic_factor_ids) != len(
            set(self.atomic_factor_ids)
        ):
            raise ValueError("atomic factor IDs must be non-empty and unique")
        if tuple(sorted(self.atomic_factor_ids)) != self.atomic_factor_ids:
            raise ValueError("atomic factor IDs must use canonical order")
        if not self.pairs or len({pair.pair_id for pair in self.pairs}) != len(self.pairs):
            raise ValueError("pair registry must contain unique pairs")
        if tuple(sorted(self.pairs, key=lambda item: item.pair_id)) != self.pairs:
            raise ValueError("pair registry pairs must use canonical order")

    @property
    def registry_id(self) -> str:
        return content_id("pair_registry_", self)


def bind_pair(
    task: Mapping[str, Any],
    graph: PromptTSG,
    pair: PairSpec,
    context_query: Mapping[str, Any],
    *,
    neutral_counterparts: Mapping[str, str] | None = None,
) -> PairBinding:
    """Evaluate pair eligibility from frozen task-side evidence only."""

    if context_query.get("query_id") != pair.pair_context_query_id:
        raise MechanismRegistryError("pair context query identity drift")
    if graph.task_id != task.get("task_id"):
        raise MechanismRegistryError("pair graph does not bind the task")
    task_family = task.get("task_family", task.get("archetype"))
    result = query_context(
        graph,
        query=context_query,
        cwe=task.get("cwe"),
        task_family=task_family,
    )
    factor_states = tuple(
        (feature, feature_state(graph, feature)) for feature in pair.factors
    )
    counterparts = dict(neutral_counterparts or {})
    for feature, counterpart_id in counterparts.items():
        if feature not in pair.factors:
            raise MechanismRegistryError("neutral counterpart is not a pair factor")
        require_text(counterpart_id, "neutral counterpart ID")
    if pair.oracle_support_status is OracleSupportStatus.UNSUPPORTED:
        decision = PairEligibility.ORACLE_UNSUPPORTED
    elif result.state is QueryState.ABSENT:
        decision = PairEligibility.CONTEXT_ABSENT
    elif result.state is QueryState.NOT_APPLICABLE:
        decision = PairEligibility.CONTEXT_NOT_APPLICABLE
    elif result.state is QueryState.UNRESOLVED:
        decision = PairEligibility.CONTEXT_UNRESOLVED
    elif any(
        state is not (QueryState.ABSENT if operation is Operation.ADD else QueryState.PRESENT)
        for (_, state), operation in zip(factor_states, pair.operations, strict=True)
    ):
        decision = PairEligibility.FACTOR_SOURCE_STATE
    elif any(
        operation is Operation.REMOVE and feature not in counterparts
        for feature, operation in zip(pair.factors, pair.operations, strict=True)
    ):
        decision = PairEligibility.COUNTERPART_MISSING
    else:
        decision = PairEligibility.APPLICABLE
    return PairBinding(
        pair.pair_id,
        graph.task_id,
        graph.tsg_id,
        decision,
        pair.pair_context_query_id,
        result.state,
        factor_states,  # type: ignore[arg-type]
        tuple(sorted(counterparts.items())),
        result.evidence_node_ids,
        result.evidence_edge_ids,
    )


def validate_pair_factors(
    pair: PairSpec,
    catalog: Mapping[str, Any],
    *,
    atomic_factor_ids: tuple[str, ...],
) -> None:
    """Prove that both pair factors are catalog-bound atomic safety features."""

    if not atomic_factor_ids or len(atomic_factor_ids) != len(set(atomic_factor_ids)):
        raise MechanismRegistryError("atomic factor registry must be non-empty and unique")
    semantics = catalog.get("semantics")
    if not isinstance(semantics, Mapping):
        raise MechanismRegistryError("Prompt TSG catalog semantics are missing")
    atomic = set(atomic_factor_ids)
    for factor in pair.factors:
        if semantics.get(factor) != "safety_requirement":
            raise MechanismRegistryError("pair factor is not a catalog safety feature")
        if factor not in atomic:
            raise MechanismRegistryError("pair factor is not registered as atomic")


def validate_mechanism_relation_spec(
    spec: MechanismRelationSpec,
    catalog: Mapping[str, Any],
    *,
    atomic_factor_ids: tuple[str, ...],
) -> None:
    """Validate one relation motif against the same finite Prompt-TSG catalog."""

    semantics = catalog.get("semantics")
    queries = catalog.get("queries")
    allowed_edges = catalog.get("allowed_edges")
    if not isinstance(semantics, Mapping) or not isinstance(queries, list) or not isinstance(
        allowed_edges, list
    ):
        raise MechanismRegistryError("Prompt TSG catalog cannot validate a relation spec")
    atomic = set(atomic_factor_ids)
    if any(
        semantics.get(factor) != "safety_requirement" or factor not in atomic
        for factor in spec.factors
    ):
        raise MechanismRegistryError("relation factors must be registered atomic safety features")
    query_ids = {
        query.get("query_id") for query in queries if isinstance(query, Mapping)
    }
    if spec.context_query_id not in query_ids:
        raise MechanismRegistryError("relation context query is absent from the catalog")
    if any(semantic not in semantics for semantic in spec.evidence_contract.required_semantics):
        raise MechanismRegistryError("relation evidence uses a semantic outside the catalog")
    allowed = {tuple(edge) for edge in allowed_edges if isinstance(edge, list) and len(edge) == 3}
    for source, edge_type, target in spec.evidence_contract.required_relations:
        typed = (semantics[source], edge_type, semantics[target])
        if typed not in allowed:
            raise MechanismRegistryError("relation evidence violates the Prompt TSG edge matrix")


def pair_matches_relation_spec(pair: PairSpec, spec: MechanismRelationSpec) -> bool:
    """Return whether a PairSpec belongs to the finite TSG relation universe."""

    return (
        pair.factors == spec.factors
        and pair.pair_context_query_id == spec.context_query_id
        and pair.relation_type is spec.relation_type
        and pair.operations in spec.allowed_operation_pairs
    )


def evaluate_pair_relation_evidence(
    task: Mapping[str, Any],
    graph: PromptTSG,
    pair: PairSpec,
    spec: MechanismRelationSpec,
) -> PairRelationEvidence:
    """Evaluate a finite relation motif without consulting an arm or outcome."""

    if not pair_matches_relation_spec(pair, spec):
        raise MechanismRegistryError("pair does not match its mechanism relation spec")
    if graph.task_id != task.get("task_id"):
        raise MechanismRegistryError("relation graph does not bind the task")
    task_id = task.get("task_id")
    task_unit_id = task.get("task_unit_id", task_id)
    if not isinstance(task_id, str) or not isinstance(task_unit_id, str):
        raise MechanismRegistryError("relation task identity is invalid")
    require_text(task_id, "task_id")
    require_text(task_unit_id, "task_unit_id")
    language = task.get("language")
    task_family = task.get("task_family", task.get("archetype"))
    cwe = task.get("cwe")
    if (
        language not in spec.eligible_languages
        or task_family not in spec.eligible_task_families
        or cwe not in spec.eligible_cwes
    ):
        state = QueryState.NOT_APPLICABLE
        node_ids: tuple[str, ...] = ()
        edge_ids: tuple[str, ...] = ()
    else:
        contract = spec.evidence_contract
        by_semantic: dict[str, tuple[str, ...]] = {}
        for semantic in contract.required_semantics:
            by_semantic[semantic] = tuple(
                sorted(node.node_id for node in graph.nodes if node.semantic_id == semantic)
            )
        node_ids = tuple(sorted({node_id for values in by_semantic.values() for node_id in values}))
        if set(contract.required_semantics) & set(graph.unresolved_semantics):
            state = QueryState.UNRESOLVED
            edge_ids = ()
        elif any(not by_semantic[semantic] for semantic in contract.required_semantics):
            state = QueryState.ABSENT
            edge_ids = ()
        else:
            matched_edges: set[str] = set()
            relation_absent = False
            for source, edge_type, target in contract.required_relations:
                sources = set(by_semantic[source])
                targets = set(by_semantic[target])
                matches = {
                    edge.edge_id
                    for edge in graph.edges
                    if edge.edge_type == edge_type
                    and edge.source_id in sources
                    and edge.target_id in targets
                }
                if not matches:
                    relation_absent = True
                    break
                matched_edges.update(matches)
            state = QueryState.ABSENT if relation_absent else QueryState.PRESENT
            edge_ids = tuple(sorted(matched_edges)) if state is QueryState.PRESENT else ()
    return PairRelationEvidence(
        pair.pair_id,
        spec.relation_spec_id,
        spec.relation_id,
        task_id,
        task_unit_id,
        graph.tsg_id,
        spec.evidence_contract.contract_id,
        state,
        node_ids,
        edge_ids,
    )


def validate_pair_relation_evidence(
    evidence: PairRelationEvidence,
    task: Mapping[str, Any],
    graph: PromptTSG,
    pair: PairSpec,
    spec: MechanismRelationSpec,
) -> None:
    """Fail closed unless frozen relation evidence exactly recomputes."""

    expected = evaluate_pair_relation_evidence(task, graph, pair, spec)
    if evidence != expected:
        raise MechanismRegistryError("pair relation evidence does not recompute")


def load_pair_registry(path: Path, catalog: Mapping[str, Any]) -> PairRegistry:
    """Load the finite pair registry and validate it against one frozen catalog."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise MechanismRegistryError("pair registry is unreadable") from None
    required = {
        "schema_version",
        "prompt_tsg_catalog_path",
        "prompt_tsg_catalog_sha256",
        "atomic_factor_ids",
        "pairs",
    }
    pair_fields = {
        "pair_context_query_id",
        "factor_1_id",
        "factor_2_id",
        "operation_1",
        "operation_2",
        "relation_type",
        "oracle_profile_id",
        "oracle_policy_sha256",
        "oracle_support_status",
        "primary_outcome",
        "interaction_scale",
    }
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != "1.0":
        raise MechanismRegistryError("pair registry envelope is invalid")
    if value["prompt_tsg_catalog_sha256"] != catalog_sha256(catalog):
        raise MechanismRegistryError("pair registry Prompt TSG catalog drift")
    atomic = value["atomic_factor_ids"]
    rows = value["pairs"]
    if (
        not isinstance(atomic, list)
        or any(not isinstance(item, str) or not item for item in atomic)
        or not isinstance(rows, list)
        or not rows
        or any(not isinstance(row, dict) or set(row) != pair_fields for row in rows)
    ):
        raise MechanismRegistryError("pair registry values are invalid")
    try:
        pairs = tuple(
            PairSpec(
                row["pair_context_query_id"],
                row["factor_1_id"],
                row["factor_2_id"],
                Operation(row["operation_1"]),
                Operation(row["operation_2"]),
                PairRelation(row["relation_type"]),
                row["oracle_profile_id"],
                row["oracle_policy_sha256"],
                OracleSupportStatus(row["oracle_support_status"]),
                row["primary_outcome"],
                InteractionScale(row["interaction_scale"]),
            )
            for row in rows
        )
    except (TypeError, ValueError):
        raise MechanismRegistryError("pair registry contains an invalid PairSpec") from None
    query_ids = {query["query_id"] for query in catalog.get("queries", ())}
    if any(pair.pair_context_query_id not in query_ids for pair in pairs):
        raise MechanismRegistryError("pair context query is absent from the catalog")
    frozen_atomic = tuple(sorted(atomic))
    for pair in pairs:
        validate_pair_factors(pair, catalog, atomic_factor_ids=frozen_atomic)
    return PairRegistry(
        value["prompt_tsg_catalog_path"],
        value["prompt_tsg_catalog_sha256"],
        frozen_atomic,
        tuple(sorted(pairs, key=lambda item: item.pair_id)),
    )




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


def select_mechanism(
    task: Mapping[str, Any], registry: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Resolve exactly one mechanism from frozen task-side information."""

    explicit = task.get("realization_id")
    if explicit is not None:
        row = registry.get(explicit)
        if row is None or row["cwe_id"] != task.get("cwe"):
            raise MechanismRegistryError("task realization binding is invalid")
        if "prompt_tsg_binding" in task:
            _validate_tsg_binding(task, row)
        elif "required_delta" in row:
            _validate_context_binding(task, row)
        return dict(row)

    prompt = " ".join(str(task.get("prompt", "")).casefold().split())
    family = task.get("task_family")
    candidates = []
    for row in registry.values():
        if "required_delta" in row:
            continue
        if row["cwe_id"] != task.get("cwe") or row["task_family"] != family:
            continue
        markers = row["prompt_markers"]
        if not markers or any(marker.casefold() in prompt for marker in markers):
            candidates.append(row)
    if len(candidates) != 1:
        raise MechanismRegistryError("task does not resolve to exactly one mechanism")
    return dict(candidates[0])


def compatible_mechanisms(
    task: Mapping[str, Any],
    context_facts: list[str],
    registry: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve context-conditioned candidates without consulting arms or outcomes."""

    if (
        not isinstance(context_facts, list)
        or any(not isinstance(item, str) or not item.strip() for item in context_facts)
        or len(context_facts) != len(set(context_facts))
    ):
        raise MechanismRegistryError("task context facts are invalid")
    facts = set(context_facts)
    matches = []
    for row in registry.values():
        if "required_delta" not in row:
            continue
        if row["cwe_id"] != task.get("cwe") or row["task_family"] != task.get("task_family"):
            continue
        if set(row["required_context"]) <= facts and not set(row["excluded_context"]) & facts:
            matches.append(dict(row))
    return sorted(matches, key=lambda row: row["realization_id"])


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


def _validate_context_binding(task: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    binding = task.get("mechanism_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "binding_id",
        "decision",
        "realization_id",
        "context_facts",
        "evidence",
        "source_prompt_sha256",
        "functional_contract_id",
        "outcomes_or_arms_used",
    }:
        raise MechanismRegistryError("context-conditioned mechanism binding is missing")
    facts = binding["context_facts"]
    evidence = binding["evidence"]
    if (
        binding["decision"] != "applicable"
        or binding["realization_id"] != row["realization_id"]
        or binding["source_prompt_sha256"] != task.get("source_prompt_sha256")
        or binding["functional_contract_id"]
        != task.get("functional_contract", {}).get("contract_id")
        or binding["outcomes_or_arms_used"] is not False
        or not isinstance(evidence, list)
        or not evidence
        or any(not isinstance(item, str) or not item.strip() for item in evidence)
        or mechanism_binding_id(binding) != binding["binding_id"]
    ):
        raise MechanismRegistryError("context-conditioned mechanism binding is invalid")
    matches = compatible_mechanisms(task, facts, {row["realization_id"]: row})
    if len(matches) != 1:
        raise MechanismRegistryError("task context does not satisfy the bound mechanism")


def _validate_tsg_binding(task: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    binding = task.get("prompt_tsg_binding")
    graph_value = task.get("prompt_tsg")
    required = {
        "binding_id",
        "decision",
        "realization_id",
        "prompt_tsg_id",
        "context_query_id",
        "context_state",
        "actionable_feature_id",
        "target_feature_state",
        "control_feature_states",
        "evidence_node_ids",
        "evidence_edge_ids",
        "query_states",
        "outcomes_or_arms_used",
    }
    try:
        graph = prompt_tsg_from_record(graph_value)
    except (TypeError, ValueError):
        raise MechanismRegistryError("Prompt TSG mechanism graph is invalid") from None
    if (
        not isinstance(binding, dict)
        or set(binding) != required
        or binding["decision"] != "applicable"
        or binding["realization_id"] != row["realization_id"]
        or binding["context_state"] != "present"
        or binding["target_feature_state"] != "absent"
        or set(binding["control_feature_states"].values()) != {"absent"}
        or binding["outcomes_or_arms_used"] is not False
        or mechanism_binding_id(binding) != binding["binding_id"]
        or graph.tsg_id != binding["prompt_tsg_id"]
        or graph.task_id != task.get("task_id")
        or graph.prompt_sha256 != content_hash(task.get("prompt"))
    ):
        raise MechanismRegistryError("Prompt TSG mechanism binding is invalid")


__all__ = [
    "ACTIVE_FACTORIAL_RELATIONS",
    "ControlPath",
    "FactorialCompatibility",
    "InteractionScale",
    "MechanismRegistryError",
    "MechanismRelationSpec",
    "OracleSupportStatus",
    "PairCompatibilityDecision",
    "PairBinding",
    "PairEligibility",
    "PairRegistry",
    "PairRelation",
    "PairRelationEvidence",
    "PairStructuralRelationEvidence",
    "PairSpec",
    "RelationEvidenceContract",
    "PromptControlBinding",
    "bind_pair",
    "compatible_mechanisms",
    "evaluate_pair_relation_evidence",
    "evaluate_pair_structural_relation",
    "load_mechanism_registry",
    "load_pair_registry",
    "mechanism_binding_id",
    "pair_matches_relation_spec",
    "select_mechanism",
    "tsg_mechanism_binding",
    "validate_active_factorial_relation",
    "validate_mechanism_relation_spec",
    "validate_pair_factors",
    "validate_pair_relation_evidence",
    "validate_prompt_control_binding",
]

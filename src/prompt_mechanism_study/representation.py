"""Outcome-blind schema-3 policy identity, data roles, and source gates."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique


class Operation(StrEnum):
    ADD = "add"
    REMOVE = "remove"


class DataRole(StrEnum):
    """Prospectively distinct uses of task-unit data in the active method."""

    QUAL_DEV = "QUAL_DEV"
    QUAL_ACCEPT = "QUAL_ACCEPT"
    DISCOVERY = "DISCOVERY"
    CONFIRMATION = "CONFIRMATION"
    LEGACY_ONLY = "LEGACY_ONLY"


def _require_canonical_scope(values: tuple[str, ...], name: str) -> None:
    if not values:
        raise ValueError(f"{name} cannot be empty")
    for value in values:
        require_text(value, name)
    require_unique(values, name)
    if tuple(sorted(values)) != values:
        raise ValueError(f"{name} must use canonical order")


@dataclass(frozen=True, slots=True)
class AnalysisScope:
    """The outcome-blind population on which one semantic policy is defined.

    Scope fields are deliberately limited to coordinates that partition the
    paper-facing task population. Selector scores, model identity, expected
    direction, and post-assignment information do not belong here.
    """

    security_pattern_id: str
    context_query_id: str
    language_scope: tuple[str, ...]
    api_scope: tuple[str, ...]
    task_archetype_scope: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.security_pattern_id, "security_pattern_id")
        require_text(self.context_query_id, "context_query_id")
        _require_canonical_scope(self.language_scope, "language_scope")
        _require_canonical_scope(self.api_scope, "api_scope")
        _require_canonical_scope(
            self.task_archetype_scope,
            "task_archetype_scope",
        )

    @property
    def analysis_scope_id(self) -> str:
        return content_id("analysis_scope_", self)


@dataclass(frozen=True, slots=True)
class PolicyFactor:
    """One atomic feature/operation coordinate inside a semantic policy."""

    actionable_feature_id: str
    operation: Operation

    def __post_init__(self) -> None:
        require_text(self.actionable_feature_id, "actionable_feature_id")
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.actionable_feature_id, self.operation.value


@dataclass(frozen=True, slots=True)
class AtomicPolicyKey:
    """Model-independent semantic identity of one first-order policy question."""

    analysis_scope: AnalysisScope
    factor: PolicyFactor
    outcome_id: str

    def __post_init__(self) -> None:
        if type(self.analysis_scope) is not AnalysisScope:
            raise TypeError("analysis_scope must be an AnalysisScope")
        if type(self.factor) is not PolicyFactor:
            raise TypeError("factor must be a PolicyFactor")
        require_text(self.outcome_id, "outcome_id")

    @property
    def policy_key(self) -> str:
        return content_id("atomic_policy_key_", self)


@dataclass(frozen=True, slots=True)
class PairPolicyKey:
    """Model-independent semantic identity of one second-order policy question."""

    analysis_scope: AnalysisScope
    factors: tuple[PolicyFactor, PolicyFactor]
    outcome_id: str

    def __post_init__(self) -> None:
        if type(self.analysis_scope) is not AnalysisScope:
            raise TypeError("analysis_scope must be an AnalysisScope")
        if len(self.factors) != 2 or any(type(item) is not PolicyFactor for item in self.factors):
            raise TypeError("pair policy must contain exactly two PolicyFactor values")
        if self.factors[0].actionable_feature_id == self.factors[1].actionable_feature_id:
            raise ValueError("pair policy factors must be distinct")
        if tuple(sorted(self.factors, key=lambda item: item.sort_key)) != self.factors:
            raise ValueError("pair policy factors must use canonical order")
        require_text(self.outcome_id, "outcome_id")

    @property
    def policy_key(self) -> str:
        return content_id("pair_policy_key_", self)


def pair_policy_key(
    analysis_scope: AnalysisScope,
    factors: Iterable[PolicyFactor],
    *,
    outcome_id: str,
) -> PairPolicyKey:
    """Canonicalize input order without making factor order scientific identity."""

    ordered = tuple(sorted(factors, key=lambda item: item.sort_key))
    if len(ordered) != 2:
        raise ValueError("pair policy requires exactly two factors")
    return PairPolicyKey(analysis_scope, ordered, outcome_id)


@dataclass(frozen=True, slots=True)
class ModelEffectCoordinate:
    """One model-specific effect of a model-independent semantic policy."""

    policy_key: str
    model_id: str

    def __post_init__(self) -> None:
        require_text(self.policy_key, "policy_key")
        require_text(self.model_id, "model_id")

    @property
    def effect_coordinate_id(self) -> str:
        return content_id("model_effect_coordinate_", self)


@dataclass(frozen=True, slots=True)
class ModelBoundCandidateRecord:
    """Protocol-bound Stage-II record dispatched to exactly one model effect."""

    policy_key: str
    discovery_model_id: str
    protocol_id: str
    schema_version: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.policy_key, "policy_key"),
            (self.discovery_model_id, "discovery_model_id"),
            (self.protocol_id, "protocol_id"),
            (self.schema_version, "schema_version"),
        ):
            require_text(value, name)

    @property
    def effect_coordinate(self) -> ModelEffectCoordinate:
        return ModelEffectCoordinate(self.policy_key, self.discovery_model_id)

    @property
    def candidate_record_id(self) -> str:
        return content_id("model_bound_candidate_record_", self)


@dataclass(frozen=True, slots=True)
class TaskUnitDataRoleRecord:
    """Outcome-blind provenance for one task unit at role-assignment time."""

    task_unit_id: str
    near_duplicate_group_id: str
    source_lineage_id: str
    exposure_history: tuple[str, ...]
    role_assignment_version: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.task_unit_id, "task_unit_id"),
            (self.near_duplicate_group_id, "near_duplicate_group_id"),
            (self.source_lineage_id, "source_lineage_id"),
            (self.role_assignment_version, "role_assignment_version"),
        ):
            require_text(value, name)
        for event in self.exposure_history:
            require_text(event, "exposure_history event")
        require_unique(self.exposure_history, "exposure_history events")


@dataclass(frozen=True, slots=True)
class DataRoleBinding:
    """One named dataset and exact task-unit provenance under one data role."""

    data_id: str
    role: DataRole
    task_units: tuple[TaskUnitDataRoleRecord, ...]
    task_manifest_sha256: str

    def __post_init__(self) -> None:
        require_text(self.data_id, "data_id")
        if type(self.role) is not DataRole:
            raise TypeError("role must be a DataRole")
        if not self.task_units or any(
            type(item) is not TaskUnitDataRoleRecord for item in self.task_units
        ):
            raise TypeError("task_units must contain TaskUnitDataRoleRecord values")
        task_unit_ids = tuple(item.task_unit_id for item in self.task_units)
        require_unique(task_unit_ids, "task_unit_ids")
        if tuple(sorted(self.task_units, key=lambda item: item.task_unit_id)) != self.task_units:
            raise ValueError("task_units must use canonical task-unit order")
        _require_digest(self.task_manifest_sha256, "task_manifest_sha256")
        if self.role is DataRole.QUAL_ACCEPT and any(
            item.exposure_history for item in self.task_units
        ):
            raise ValueError(
                "QUAL_ACCEPT task units must be unexposed when the role manifest is frozen"
            )

    @property
    def task_unit_ids(self) -> tuple[str, ...]:
        return tuple(item.task_unit_id for item in self.task_units)


@dataclass(frozen=True, slots=True)
class DataRoleManifest:
    """Task-unit and near-duplicate firewall for all prospective data uses.

    A task unit may occur in several development-qualification datasets, but it
    may never cross data roles. QUAL_ACCEPT is a single, unexposed, one-shot
    acceptance resource. Near-duplicate groups obey the same role boundary.
    """

    protocol_id: str
    source_manifest_sha256: str
    bindings: tuple[DataRoleBinding, ...]
    declared_roles: tuple[DataRole, ...] = tuple(DataRole)

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "protocol_id")
        _require_digest(self.source_manifest_sha256, "source_manifest_sha256")
        if self.declared_roles != tuple(DataRole):
            raise ValueError("data-role manifest must explicitly declare all five roles")
        if not self.bindings:
            raise ValueError("data-role manifest cannot be empty")
        if any(type(item) is not DataRoleBinding for item in self.bindings):
            raise TypeError("bindings must contain DataRoleBinding values")
        require_unique((item.data_id for item in self.bindings), "data ids")
        if tuple(sorted(self.bindings, key=lambda item: item.data_id)) != self.bindings:
            raise ValueError("data-role bindings must use canonical data-id order")
        required = {
            DataRole.QUAL_DEV,
            DataRole.QUAL_ACCEPT,
            DataRole.DISCOVERY,
            DataRole.CONFIRMATION,
            DataRole.LEGACY_ONLY,
        }
        if not required <= {item.role for item in self.bindings}:
            raise ValueError(
                "bindings for all five data roles are required"
            )
        acceptance = [
            item for item in self.bindings if item.role is DataRole.QUAL_ACCEPT
        ]
        if len(acceptance) != 1:
            raise ValueError("exactly one QUAL_ACCEPT dataset must be frozen")

        roles_by_task: dict[str, set[DataRole]] = defaultdict(set)
        provenance_by_task: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
        roles_by_near_duplicate_group: dict[str, set[DataRole]] = defaultdict(set)
        for binding in self.bindings:
            for task_unit in binding.task_units:
                roles_by_task[task_unit.task_unit_id].add(binding.role)
                provenance_by_task[task_unit.task_unit_id].add(
                    (
                        task_unit.near_duplicate_group_id,
                        task_unit.source_lineage_id,
                        task_unit.role_assignment_version,
                    )
                )
                roles_by_near_duplicate_group[
                    task_unit.near_duplicate_group_id
                ].add(binding.role)
        if any(len(roles) != 1 for roles in roles_by_task.values()):
            raise ValueError("a task unit cannot cross data roles")
        if any(len(values) != 1 for values in provenance_by_task.values()):
            raise ValueError("task-unit role provenance must be stable across datasets")
        if any(len(roles) != 1 for roles in roles_by_near_duplicate_group.values()):
            raise ValueError("a near-duplicate group cannot cross data roles")

    @property
    def data_role_manifest_id(self) -> str:
        return content_id("data_role_manifest_", self)

    @property
    def qualification_data_ids(self) -> tuple[str, ...]:
        return tuple(
            item.data_id
            for item in self.bindings
            if item.role in {DataRole.QUAL_DEV, DataRole.QUAL_ACCEPT}
        )

    @property
    def qualification_dev_data_ids(self) -> tuple[str, ...]:
        return tuple(
            item.data_id for item in self.bindings if item.role is DataRole.QUAL_DEV
        )

    @property
    def qualification_accept_data_id(self) -> str:
        return next(
            item.data_id
            for item in self.bindings
            if item.role is DataRole.QUAL_ACCEPT
        )

    @property
    def discovery_population_sha256(self) -> str:
        """Bind every exact DISCOVERY dataset and task-unit membership once."""

        discovery = tuple(
            item for item in self.bindings if item.role is DataRole.DISCOVERY
        )
        return content_hash(discovery)

    def require_dataset_role(self, data_id: str, role: DataRole) -> DataRoleBinding:
        require_text(data_id, "data_id")
        if type(role) is not DataRole:
            raise TypeError("role must be a DataRole")
        matches = [item for item in self.bindings if item.data_id == data_id]
        if len(matches) != 1 or matches[0].role is not role:
            raise ValueError(f"dataset {data_id!r} is not authorized for role {role.value}")
        return matches[0]


def validate_data_role_firewall(
    manifest: DataRoleManifest,
    requested_datasets: Mapping[str, DataRole],
) -> dict[str, object]:
    """Authorize named inputs before a target runner reads any outcome data."""

    if type(manifest) is not DataRoleManifest:
        raise TypeError("manifest must be a DataRoleManifest")
    if not requested_datasets:
        raise ValueError("requested_datasets cannot be empty")
    authorized = []
    for data_id, role in sorted(requested_datasets.items()):
        binding = manifest.require_dataset_role(data_id, role)
        authorized.append(
            {
                "data_id": data_id,
                "data_role": role.value,
                "task_manifest_sha256": binding.task_manifest_sha256,
                "task_unit_count": len(binding.task_units),
            }
        )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "PASS",
        "data_role_manifest_id": manifest.data_role_manifest_id,
        "authorized_datasets": authorized,
        "task_unit_cross_role_overlap_count": 0,
        "near_duplicate_cross_role_overlap_count": 0,
        "outcome_data_read": False,
    }
    report["firewall_validation_id"] = content_id(
        "data_role_firewall_validation_",
        report,
    )
    return report


class SourceEligibilityDecision(StrEnum):
    ELIGIBLE = "eligible"
    EXCLUDED = "excluded"


@dataclass(frozen=True, slots=True)
class SourceEligibility:
    """Outcome-blind ADD/REMOVE source-state decision for one Atomic policy."""

    policy_key: str
    context_query_id: str
    actionable_feature_id: str
    task_id: str
    task_unit_id: str
    prompt_tsg_id: str
    prompt_sha256: str
    operation: Operation
    context_state: QueryState
    feature_state: QueryState
    target_evidence_node_ids: tuple[str, ...]
    neutral_counterpart: str | None
    neutral_counterpart_sha256: str | None
    eligibility_policy_sha256: str
    decision: SourceEligibilityDecision
    exclusion_reason: str | None

    def __post_init__(self) -> None:
        for name in (
            "policy_key",
            "context_query_id",
            "actionable_feature_id",
            "task_id",
            "task_unit_id",
            "prompt_tsg_id",
        ):
            require_text(getattr(self, name), name)
        _require_digest(self.prompt_sha256, "prompt_sha256")
        _require_digest(self.eligibility_policy_sha256, "eligibility_policy_sha256")
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if type(self.context_state) is not QueryState or type(self.feature_state) is not QueryState:
            raise TypeError("context_state and feature_state must be QueryState values")
        if type(self.decision) is not SourceEligibilityDecision:
            raise TypeError("decision must be a SourceEligibilityDecision")
        require_unique(self.target_evidence_node_ids, "target evidence node ids")
        if tuple(sorted(self.target_evidence_node_ids)) != self.target_evidence_node_ids:
            raise ValueError("target evidence node ids must use canonical order")
        for node_id in self.target_evidence_node_ids:
            require_text(node_id, "target evidence node id")
        if self.neutral_counterpart is None:
            if self.neutral_counterpart_sha256 is not None:
                raise ValueError("neutral counterpart digest requires counterpart text")
        else:
            require_text(self.neutral_counterpart, "neutral_counterpart")
            _require_digest(self.neutral_counterpart_sha256, "neutral_counterpart_sha256")
            if content_hash(self.neutral_counterpart) != self.neutral_counterpart_sha256:
                raise ValueError("neutral counterpart digest drift")

        gate_reason = self._gate_failure_reason()
        if self.decision is SourceEligibilityDecision.ELIGIBLE:
            if gate_reason is not None or self.exclusion_reason is not None:
                raise ValueError("eligible source does not satisfy the operation source gate")
        else:
            require_text(self.exclusion_reason, "exclusion_reason")
            if gate_reason is None:
                raise ValueError("a source that passes the operation gate cannot be excluded")
            if self.exclusion_reason != gate_reason:
                raise ValueError("source exclusion reason does not match the failed gate")

    def _gate_failure_reason(self) -> str | None:
        if self.context_state is not QueryState.PRESENT:
            return f"context_{self.context_state.value}"
        if self.operation is Operation.ADD:
            return None if self.feature_state is QueryState.ABSENT else f"add_source_{self.feature_state.value}"
        if self.feature_state is not QueryState.PRESENT:
            return f"remove_source_{self.feature_state.value}"
        if not self.target_evidence_node_ids:
            return "remove_target_evidence_missing"
        if self.neutral_counterpart is None:
            return "remove_neutral_counterpart_missing"
        return None

    @property
    def source_eligibility_id(self) -> str:
        return content_id("source_eligibility_", self)

    @property
    def eligible(self) -> bool:
        return self.decision is SourceEligibilityDecision.ELIGIBLE


def freeze_source_eligibility(
    policy: AtomicPolicyKey,
    *,
    task_id: str,
    task_unit_id: str,
    prompt_tsg_id: str,
    prompt_sha256: str,
    context_state: QueryState,
    feature_state: QueryState,
    target_evidence_node_ids: Iterable[str] = (),
    neutral_counterpart: str | None = None,
    eligibility_policy_sha256: str,
) -> SourceEligibility:
    """Evaluate and freeze the target protocol's operation-specific source gate."""

    if type(policy) is not AtomicPolicyKey:
        raise TypeError("source eligibility requires an AtomicPolicyKey")
    if type(context_state) is not QueryState or type(feature_state) is not QueryState:
        raise TypeError("context_state and feature_state must be QueryState values")
    evidence = tuple(sorted(target_evidence_node_ids))
    counterpart_sha256 = None if neutral_counterpart is None else content_hash(neutral_counterpart)
    operation = policy.factor.operation
    if context_state is not QueryState.PRESENT:
        reason = f"context_{context_state.value}"
    elif operation is Operation.ADD:
        reason = None if feature_state is QueryState.ABSENT else f"add_source_{feature_state.value}"
    elif feature_state is not QueryState.PRESENT:
        reason = f"remove_source_{feature_state.value}"
    elif not evidence:
        reason = "remove_target_evidence_missing"
    elif neutral_counterpart is None:
        reason = "remove_neutral_counterpart_missing"
    else:
        reason = None
    return SourceEligibility(
        policy.policy_key,
        policy.analysis_scope.context_query_id,
        policy.factor.actionable_feature_id,
        task_id,
        task_unit_id,
        prompt_tsg_id,
        prompt_sha256,
        operation,
        context_state,
        feature_state,
        evidence,
        neutral_counterpart,
        counterpart_sha256,
        eligibility_policy_sha256,
        SourceEligibilityDecision.ELIGIBLE if reason is None else SourceEligibilityDecision.EXCLUDED,
        reason,
    )



__all__ = [
    "AnalysisScope",
    "AtomicPolicyKey",
    "DataRole",
    "DataRoleBinding",
    "DataRoleManifest",
    "ModelBoundCandidateRecord",
    "ModelEffectCoordinate",
    "Operation",
    "PairPolicyKey",
    "PolicyFactor",
    "SourceEligibility",
    "SourceEligibilityDecision",
    "TaskUnitDataRoleRecord",
    "freeze_source_eligibility",
    "pair_policy_key",
    "validate_data_role_firewall",
]

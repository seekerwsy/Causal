"""Outcome-blind population and intervention-hypothesis representation."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique


class Split(StrEnum):
    DISCOVER = "discover"
    CONFIRM = "confirm"


class Operation(StrEnum):
    ADD = "add"
    REMOVE = "remove"


class ExpectedDirection(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"


@dataclass(frozen=True, slots=True)
class Task:
    task_id: str
    semantic_cluster_id: str
    cwe: str
    archetype: str
    split: Split
    prompt: str
    weight: int = 1

    def __post_init__(self) -> None:
        for name in ("task_id", "semantic_cluster_id", "cwe", "archetype", "prompt"):
            require_text(getattr(self, name), name)
        if type(self.split) is not Split:
            raise TypeError("split must be a Split")
        if type(self.weight) is not int or self.weight <= 0:
            raise ValueError("task weight must be a positive integer")

    @property
    def prompt_sha256(self) -> str:
        return content_hash(self.prompt)


@dataclass(frozen=True, slots=True)
class Candidate:
    candidate_key: str
    context_query_id: str
    actionable_feature_id: str
    operation: Operation
    cwe: str
    outcome_id: str
    expected_direction: ExpectedDirection

    def __post_init__(self) -> None:
        for name in (
            "candidate_key",
            "context_query_id",
            "actionable_feature_id",
            "cwe",
            "outcome_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if type(self.expected_direction) is not ExpectedDirection:
            raise TypeError("expected_direction must be an ExpectedDirection")

    @property
    def candidate_id(self) -> str:
        return content_id("candidate_", self)


@dataclass(frozen=True, slots=True)
class CandidateSkeletonV2:
    """One prospective context/actionable-feature/operation candidate.

    The one-element tuple is deliberate: a composite or relational motif may
    define context, but it cannot silently become a multi-feature treatment.
    """

    candidate_key: str
    context_query_id: str
    actionable_feature_ids: tuple[str, ...]
    operation: Operation
    cwe: str
    archetype: str
    outcome_id: str
    expected_direction: ExpectedDirection
    realization_policy_id: str

    def __post_init__(self) -> None:
        for name in (
            "candidate_key",
            "context_query_id",
            "cwe",
            "archetype",
            "outcome_id",
            "realization_policy_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if type(self.expected_direction) is not ExpectedDirection:
            raise TypeError("expected_direction must be an ExpectedDirection")
        if len(self.actionable_feature_ids) != 1:
            raise ValueError("a candidate skeleton must contain exactly one actionable feature")
        require_text(self.actionable_feature_ids[0], "actionable feature id")

    @property
    def actionable_feature_id(self) -> str:
        return self.actionable_feature_ids[0]

    @property
    def candidate_skeleton_id(self) -> str:
        return content_id("candidate_skeleton_v2_", self)


@dataclass(frozen=True, slots=True)
class TargetSpecV2:
    """The sole Prompt-side feature an intervention may edit."""

    candidate_skeleton_id: str
    context_query_id: str
    actionable_feature_id: str
    operation: Operation
    context_query_catalog_sha256: str
    feature_catalog_sha256: str
    allowed_delta_policy_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "candidate_skeleton_id",
            "context_query_id",
            "actionable_feature_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        for name in (
            "context_query_catalog_sha256",
            "feature_catalog_sha256",
            "allowed_delta_policy_sha256",
        ):
            _require_digest(getattr(self, name), name)

    @property
    def target_spec_id(self) -> str:
        return content_id("target_spec_v2_", self)


@dataclass(frozen=True, slots=True)
class FrozenHypothesisV2:
    """Selector-invariant hypothesis passed to the intervention bridge."""

    skeleton: CandidateSkeletonV2
    target_spec: TargetSpecV2

    def __post_init__(self) -> None:
        if self.target_spec.candidate_skeleton_id != self.skeleton.candidate_skeleton_id:
            raise ValueError("target spec does not bind the candidate skeleton")
        if (
            self.target_spec.context_query_id != self.skeleton.context_query_id
            or self.target_spec.actionable_feature_id != self.skeleton.actionable_feature_id
            or self.target_spec.operation is not self.skeleton.operation
        ):
            raise ValueError("target spec semantics drift from the candidate skeleton")

    @property
    def hypothesis_id(self) -> str:
        return content_id("frozen_hypothesis_v2_", self)


class EligibilityDecisionV2(StrEnum):
    ELIGIBLE = "eligible"
    EXCLUDED = "excluded"


@dataclass(frozen=True, slots=True)
class SourceEligibilityV2:
    """Outcome-blind ADD/REMOVE source-state decision for one task.

    ADD requires a resolved absent target. REMOVE additionally requires
    provenance-bound target evidence and an attested neutral counterpart.
    Exclusions are retained as typed records rather than being dropped.
    """

    hypothesis_id: str
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
    decision: EligibilityDecisionV2
    exclusion_reason: str | None

    def __post_init__(self) -> None:
        for name in ("hypothesis_id", "task_id", "task_unit_id", "prompt_tsg_id"):
            require_text(getattr(self, name), name)
        _require_digest(self.prompt_sha256, "prompt_sha256")
        _require_digest(self.eligibility_policy_sha256, "eligibility_policy_sha256")
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if type(self.context_state) is not QueryState or type(self.feature_state) is not QueryState:
            raise TypeError("context_state and feature_state must be QueryState values")
        if type(self.decision) is not EligibilityDecisionV2:
            raise TypeError("decision must be an EligibilityDecisionV2")
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
            _require_digest(
                self.neutral_counterpart_sha256,
                "neutral_counterpart_sha256",
            )
            if content_hash(self.neutral_counterpart) != self.neutral_counterpart_sha256:
                raise ValueError("neutral counterpart digest drift")

        gate_reason = self._gate_failure_reason()
        if self.decision is EligibilityDecisionV2.ELIGIBLE:
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
            if self.feature_state is not QueryState.ABSENT:
                return f"add_source_{self.feature_state.value}"
            return None
        if self.feature_state is not QueryState.PRESENT:
            return f"remove_source_{self.feature_state.value}"
        if not self.target_evidence_node_ids:
            return "remove_target_evidence_missing"
        if self.neutral_counterpart is None:
            return "remove_neutral_counterpart_missing"
        return None

    @property
    def source_eligibility_id(self) -> str:
        return content_id("source_eligibility_v2_", self)

    @property
    def eligible(self) -> bool:
        return self.decision is EligibilityDecisionV2.ELIGIBLE


def source_eligibility_v2(
    hypothesis: FrozenHypothesisV2,
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
) -> SourceEligibilityV2:
    """Evaluate and freeze the operation-specific source gate."""

    if type(context_state) is not QueryState or type(feature_state) is not QueryState:
        raise TypeError("context_state and feature_state must be QueryState values")
    evidence = tuple(sorted(target_evidence_node_ids))
    counterpart_sha256 = (
        None if neutral_counterpart is None else content_hash(neutral_counterpart)
    )
    if context_state is not QueryState.PRESENT:
        reason = f"context_{context_state.value}"
    elif hypothesis.skeleton.operation is Operation.ADD:
        reason = (
            None
            if feature_state is QueryState.ABSENT
            else f"add_source_{feature_state.value}"
        )
    elif feature_state is not QueryState.PRESENT:
        reason = f"remove_source_{feature_state.value}"
    elif not evidence:
        reason = "remove_target_evidence_missing"
    elif neutral_counterpart is None:
        reason = "remove_neutral_counterpart_missing"
    else:
        reason = None
    return SourceEligibilityV2(
        hypothesis.hypothesis_id,
        task_id,
        task_unit_id,
        prompt_tsg_id,
        prompt_sha256,
        hypothesis.skeleton.operation,
        context_state,
        feature_state,
        evidence,
        neutral_counterpart,
        counterpart_sha256,
        eligibility_policy_sha256,
        EligibilityDecisionV2.ELIGIBLE if reason is None else EligibilityDecisionV2.EXCLUDED,
        reason,
    )


@dataclass(frozen=True, slots=True)
class Population:
    tasks: tuple[Task, ...]

    def __post_init__(self) -> None:
        if not self.tasks:
            raise ValueError("population cannot be empty")
        require_unique((task.task_id for task in self.tasks), "task ids")
        if tuple(sorted(self.tasks, key=lambda task: task.task_id)) != self.tasks:
            raise ValueError("population tasks must use canonical task-id order")
        cluster_splits: dict[str, Split] = {}
        for task in self.tasks:
            previous = cluster_splits.setdefault(task.semantic_cluster_id, task.split)
            if previous is not task.split:
                raise ValueError("a semantic cluster cannot cross discover and confirm splits")
        if not self.discover_tasks or not self.confirm_tasks:
            raise ValueError("both discover and confirm tasks are required")

    @property
    def population_id(self) -> str:
        return content_id("population_", self)

    @property
    def discover_tasks(self) -> tuple[Task, ...]:
        return tuple(task for task in self.tasks if task.split is Split.DISCOVER)

    @property
    def confirm_tasks(self) -> tuple[Task, ...]:
        return tuple(task for task in self.tasks if task.split is Split.CONFIRM)


@dataclass(frozen=True, slots=True)
class CandidateUniverse:
    representation_adapter_id: str
    candidates: tuple[Candidate, ...]

    def __post_init__(self) -> None:
        require_text(self.representation_adapter_id, "representation_adapter_id")
        if not self.candidates:
            raise ValueError("candidate universe cannot be empty")
        require_unique((item.candidate_id for item in self.candidates), "candidate ids")
        require_unique((item.candidate_key for item in self.candidates), "candidate keys")
        if tuple(sorted(self.candidates, key=lambda item: item.candidate_id)) != self.candidates:
            raise ValueError("candidates must use canonical candidate-id order")

    @property
    def universe_id(self) -> str:
        return content_id("universe_", self)


def freeze_population(tasks: Iterable[Task]) -> Population:
    return Population(tuple(sorted(tasks, key=lambda task: task.task_id)))


def freeze_universe(
    candidates: Iterable[Candidate],
    *,
    representation_adapter_id: str,
) -> CandidateUniverse:
    return CandidateUniverse(
        representation_adapter_id,
        tuple(sorted(candidates, key=lambda item: item.candidate_id)),
    )


def _require_digest(value: str | None, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


__all__ = [
    "Candidate",
    "CandidateSkeletonV2",
    "CandidateUniverse",
    "EligibilityDecisionV2",
    "ExpectedDirection",
    "FrozenHypothesisV2",
    "Operation",
    "Population",
    "SourceEligibilityV2",
    "Split",
    "TargetSpecV2",
    "Task",
    "freeze_population",
    "freeze_universe",
    "source_eligibility_v2",
]

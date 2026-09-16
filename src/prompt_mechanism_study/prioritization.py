"""Outcome-blind candidate support, selector scores, fixed slots and unique dispatch."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.selector_numerics import fit_ridge_logit, sigmoid as _sigmoid
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.representation import (
    AtomicPolicyKey,
    ModelBoundCandidateRecord,
    Operation,
)
from prompt_mechanism_study.records import require_ordered_strings as _canonical_unique


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate_id: str
    score: float
    rank: int

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        if type(self.score) not in {int, float} or not math.isfinite(float(self.score)):
            raise ValueError("score must be finite")
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("rank must be positive")


class SlotStatus(StrEnum):
    FILLED = "filled"
    SELECTOR_FAILED = "selector_failed"
    INSUFFICIENT_CANDIDATES = "insufficient_candidates"
    GATE_FAILED = "gate_failed"
    NON_EVALUABLE = "non_evaluable"


class BridgeStatus(StrEnum):
    SUCCESS = "success"
    BRIDGE_FAILED = "bridge_failed"
    PROTOCOLIZATION_FAILED = "protocolization_failed"


@dataclass(frozen=True, slots=True)
class DiscoveryObservation:
    """One frozen natural-Prompt discovery observation.

    Repeated request slots are permitted, but selectors use the lowest frozen
    slot per task unit as their reference analysis.  Confirmatory arms and
    outcomes have no field in this record.
    """

    task_unit_id: str
    model_id: str
    family_id: str
    request_randomness_slot: int
    candidate_states: tuple[tuple[str, int], ...]
    covariates: tuple[tuple[str, float], ...]
    outcome: int
    source_binding_sha256: str | None = field(default=None, metadata={"omit_if_none": True})
    source_gate_failures: tuple[tuple[str, tuple[str, ...]], ...] | None = field(default=None, metadata={"omit_if_none": True})

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "task_unit_id")
        require_text(self.model_id, "model_id")
        require_text(self.family_id, "family_id")
        if type(self.request_randomness_slot) is not int or self.request_randomness_slot < 0:
            raise ValueError("request_randomness_slot must be a nonnegative integer")
        _validate_numeric_pairs(self.candidate_states, "candidate states", binary=True)
        _validate_numeric_pairs(self.covariates, "covariates", binary=False)
        if self.outcome not in {0, 1} or type(self.outcome) is not int:
            raise ValueError("discovery outcome must be binary")
        if self.source_binding_sha256 is not None:
            _require_digest(self.source_binding_sha256, "source scope binding")
        _validate_source_gate_failures(self)

    @property
    def observation_id(self) -> str:
        return content_id("discovery_observation_", self)


@dataclass(frozen=True, slots=True)
class SelectorFailure:
    reason_code: str
    detail: str
    candidate_id: str | None = None

    def __post_init__(self) -> None:
        require_text(self.reason_code, "selector failure code")
        require_text(self.detail, "selector failure detail")
        if self.candidate_id is not None:
            require_text(self.candidate_id, "selector failure candidate_id")


@dataclass(frozen=True, slots=True)
class SelectorSlot:
    rank: int
    status: SlotStatus
    candidate_id: str | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("selector slot rank must be positive")
        if type(self.status) is not SlotStatus:
            raise TypeError("selector slot status must be a SlotStatus")
        if self.status is SlotStatus.FILLED:
            if self.candidate_id is None or self.reason_code is not None:
                raise ValueError("a filled selector slot requires only a candidate")
        elif self.candidate_id is not None or not self.reason_code:
            raise ValueError("an unfilled selector slot requires only a reason")


class AtomicSelectorVariant(StrEnum):
    FULL = "atomic_full"
    RD_ONLY = "atomic_rd_only"


class AtomicFCIGateStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NON_EVALUABLE = "NON_EVALUABLE"


class CandidateKind(StrEnum):
    ATOMIC = "ATOMIC"


class DiscoverabilityStatus(StrEnum):
    DISCOVERY_ELIGIBLE = "DISCOVERY_ELIGIBLE"
    DISCOVERY_INELIGIBLE = "DISCOVERY_INELIGIBLE"


class DiscoverabilityReason(StrEnum):
    SOURCE_SCOPE_SUPPORT_FAILED = "SOURCE_SCOPE_SUPPORT_FAILED"
    ATOMIC_NATURAL_SUPPORT_FAILED = "ATOMIC_NATURAL_SUPPORT_FAILED"
    MISSING_OBSERVATIONS = "MISSING_OBSERVATIONS"
    DUPLICATE_TASK_UNIT = "DUPLICATE_TASK_UNIT"
    CANDIDATE_COORDINATE_MISMATCH = "CANDIDATE_COORDINATE_MISMATCH"
    CONTEXT_NOT_PRESENT = "CONTEXT_NOT_PRESENT"
    COVARIATE_SCHEMA_MISMATCH = "COVARIATE_SCHEMA_MISMATCH"
    EXTRACTOR_RELIABILITY_BELOW_THRESHOLD = "EXTRACTOR_RELIABILITY_BELOW_THRESHOLD"
    FACTOR_STATE_NOT_BINARY = "FACTOR_STATE_NOT_BINARY"
    INSUFFICIENT_SOURCE_LINEAGE_OVERLAP = "INSUFFICIENT_SOURCE_LINEAGE_OVERLAP"
    LANGUAGE_NONOVERLAP = "LANGUAGE_NONOVERLAP"
    ARCHETYPE_NONOVERLAP = "ARCHETYPE_NONOVERLAP"
    API_FAMILY_NONOVERLAP = "API_FAMILY_NONOVERLAP"
    FOLD_NON_EVALUABLE = "FOLD_NON_EVALUABLE"


@dataclass(frozen=True, slots=True)
class CandidateCoverageSummary:
    """Outcome-blind candidate-level counts; insufficiency is not a null effect."""

    candidate_id: str
    candidate_kind: CandidateKind
    state_or_cell_task_units: tuple[tuple[str, int], ...]
    unique_source_lineages: int
    near_duplicate_safe_task_units: int
    representation_resolved_task_units: int
    total_task_units: int
    oracle_ready_task_units: int
    confirmation_baseline_task_units: int

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "coverage-summary candidate_id")
        if type(self.candidate_kind) is not CandidateKind:
            raise TypeError("coverage-summary candidate kind must be typed")
        expected_cells = ("0", "1")
        if tuple((cell for cell, _ in self.state_or_cell_task_units)) != expected_cells:
            raise ValueError("candidate coverage cells do not match Atomic kind")
        if any((type(value) is not int or value < 0 for _, value in self.state_or_cell_task_units)):
            raise ValueError("candidate coverage counts must be nonnegative")
        for value, name in (
            (self.unique_source_lineages, "unique source lineages"),
            (self.near_duplicate_safe_task_units, "near-duplicate-safe task units"),
            (self.representation_resolved_task_units, "representation-resolved task units"),
            (self.total_task_units, "total task units"),
            (self.oracle_ready_task_units, "Oracle-ready task units"),
            (self.confirmation_baseline_task_units, "confirmation baseline task units"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"candidate coverage {name} must be nonnegative")
        if sum((value for _, value in self.state_or_cell_task_units)) > self.total_task_units:
            raise ValueError(
                "candidate binary state/cell counts cannot exceed the complete task denominator"
            )
        if any(
            (
                value > self.total_task_units
                for value in (
                    self.unique_source_lineages,
                    self.near_duplicate_safe_task_units,
                    self.representation_resolved_task_units,
                    self.oracle_ready_task_units,
                    self.confirmation_baseline_task_units,
                )
            )
        ):
            raise ValueError("candidate coverage diagnostics cannot exceed total task units")

    @property
    def representation_resolved_rate(self) -> float:
        return (
            0.0
            if self.total_task_units == 0
            else self.representation_resolved_task_units / self.total_task_units
        )


@dataclass(frozen=True, slots=True)
class DiscoverabilityDecision:
    """Shared outcome-blind Atomic candidate eligibility record."""

    candidate_id: str
    candidate_kind: CandidateKind
    discovery_population_sha256: str
    universe_id: str
    support_evidence_sha256: str
    fold_evidence_sha256: str
    coverage_summary: CandidateCoverageSummary
    status: DiscoverabilityStatus
    reasons: tuple[DiscoverabilityReason, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "discoverability candidate_id")
        if type(self.candidate_kind) is not CandidateKind:
            raise TypeError("discoverability candidate kind must be typed")
        require_text(self.universe_id, "discoverability universe_id")
        for value, name in (
            (self.discovery_population_sha256, "discoverability population"),
            (self.support_evidence_sha256, "discoverability support evidence"),
            (self.fold_evidence_sha256, "discoverability fold evidence"),
        ):
            _require_digest(value, name)
        if type(self.status) is not DiscoverabilityStatus or any(
            type(item) is not DiscoverabilityReason for item in self.reasons
        ):
            raise TypeError("discoverability status and reasons must be typed")
        if (
            type(self.coverage_summary) is not CandidateCoverageSummary
            or self.coverage_summary.candidate_id != self.candidate_id
            or self.coverage_summary.candidate_kind is not self.candidate_kind
        ):
            raise ValueError("discoverability coverage summary drifted from candidate identity")
        if self.reasons != tuple(sorted(set(self.reasons), key=lambda item: item.value)):
            raise ValueError("discoverability reasons must be unique and canonical")
        if self.status is DiscoverabilityStatus.DISCOVERY_ELIGIBLE:
            if self.reasons:
                raise ValueError("a discoverable candidate cannot have failure reasons")
        elif not self.reasons:
            raise ValueError("a non-discoverable candidate requires failure reasons")


@dataclass(frozen=True, slots=True)
class AtomicCandidateUniverseManifest:
    """Direction-neutral v3 Atomic universe used by both Core variants."""

    policy_keys: tuple[AtomicPolicyKey, ...]
    supported_policy_keys: tuple[str, ...]
    coverage_summaries: tuple[CandidateCoverageSummary, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]
    realization_policy_ids: tuple[tuple[str, str], ...]
    candidate_family_ids: tuple[tuple[str, str], ...]
    preoutcome_data_sha256: str
    discovery_population_sha256: str
    positivity_audit_sha256: str
    information_budget_sha256: str
    top_k: int
    representation_adapter_id: str

    def __post_init__(self) -> None:
        if any((type(item) is not AtomicPolicyKey for item in self.policy_keys)):
            raise TypeError("Atomic universe requires typed policy keys")
        candidate_ids = tuple((item.policy_key for item in self.policy_keys))
        _canonical_unique(candidate_ids, "Atomic policy keys")
        _canonical_unique(self.supported_policy_keys, "supported Atomic policy keys")
        if not set(self.supported_policy_keys) <= set(candidate_ids):
            raise ValueError("supported Atomic policies must belong to the universe")
        if tuple((item.candidate_id for item in self.coverage_summaries)) != candidate_ids or any(
            (type(item) is not CandidateCoverageSummary for item in self.coverage_summaries)
        ):
            raise ValueError("Atomic coverage summaries must exactly follow the universe")
        if tuple((item.policy_key for item in self.model_bound_records)) != candidate_ids:
            raise ValueError("model-bound records must exactly follow Atomic policies")
        if any((type(item) is not ModelBoundCandidateRecord for item in self.model_bound_records)):
            raise TypeError("Atomic model-bound records must be typed")
        for bindings, name in (
            (self.realization_policy_ids, "realization-policy bindings"),
            (self.candidate_family_ids, "candidate-family bindings"),
        ):
            if tuple((candidate_id for candidate_id, _ in bindings)) != candidate_ids:
                raise ValueError(f"{name} must exactly follow Atomic policies")
            if any((not isinstance(value, str) or not value.strip() for _, value in bindings)):
                raise ValueError(f"{name} must contain non-empty values")
        for value, name in (
            (self.preoutcome_data_sha256, "Atomic discovery data"),
            (self.discovery_population_sha256, "Atomic Discovery population"),
            (self.positivity_audit_sha256, "Atomic positivity audit"),
            (self.information_budget_sha256, "Atomic information budget"),
        ):
            _require_digest(value, name)
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("Atomic top_k must be positive")
        require_text(self.representation_adapter_id, "Atomic representation adapter")

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.policy_key for item in self.policy_keys)

    @property
    def universe_id(self) -> str:
        return content_id("atomic_candidate_universe_", self)


@dataclass(frozen=True, slots=True)
class AtomicShadowPlan:
    model_id: str
    covariate_names: tuple[str, ...]
    cross_fit_folds: int
    ridge_lambda: float
    fold_seed: int
    fci_minimum_valid_fraction: float
    fci_adjacency_threshold: float

    def __post_init__(self) -> None:
        require_text(self.model_id, "Atomic shadow model_id")
        _canonical_unique(self.covariate_names, "Atomic covariate names")
        if type(self.cross_fit_folds) is not int or self.cross_fit_folds < 2:
            raise ValueError("Atomic cross_fit_folds must be at least two")
        if (
            type(self.ridge_lambda) not in {int, float}
            or not math.isfinite(float(self.ridge_lambda))
            or self.ridge_lambda <= 0
        ):
            raise ValueError("Atomic ridge_lambda must be finite and positive")
        if type(self.fold_seed) is not int:
            raise TypeError("Atomic fold_seed must be an integer")
        if (
            type(self.fci_minimum_valid_fraction) is not float
            or not 0.0 < self.fci_minimum_valid_fraction <= 1.0
        ):
            raise ValueError("Atomic FCI minimum valid fraction must be in (0, 1]")
        if (
            type(self.fci_adjacency_threshold) is not float
            or not 0.0 <= self.fci_adjacency_threshold <= 1.0
        ):
            raise ValueError("Atomic FCI adjacency threshold must be in [0, 1]")

    @property
    def plan_id(self) -> str:
        return content_id("atomic_shadow_plan_", self)


@dataclass(frozen=True, slots=True)
class AtomicPreOutcomeObservation:
    """Atomic fold input whose schema cannot carry a discovery outcome."""

    task_unit_id: str
    model_id: str
    family_id: str
    request_randomness_slot: int
    candidate_states: tuple[tuple[str, int], ...]
    covariates: tuple[tuple[str, float], ...]
    source_binding_sha256: str | None = field(default=None, metadata={"omit_if_none": True})
    source_gate_failures: tuple[tuple[str, tuple[str, ...]], ...] | None = field(default=None, metadata={"omit_if_none": True})

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "Atomic pre-outcome task_unit_id")
        require_text(self.model_id, "Atomic pre-outcome model_id")
        require_text(self.family_id, "Atomic pre-outcome family_id")
        if (
            type(self.request_randomness_slot) is not int
            or self.request_randomness_slot < 0
        ):
            raise ValueError("Atomic pre-outcome request slot must be nonnegative")
        _validate_numeric_pairs(
            self.candidate_states,
            "Atomic pre-outcome candidate states",
            binary=True,
        )

        _validate_numeric_pairs(self.covariates, "Atomic pre-outcome covariates", binary=False)
        if self.source_binding_sha256 is not None:
            _require_digest(self.source_binding_sha256, "source scope binding")
        _validate_source_gate_failures(self)

    @property
    def preoutcome_observation_id(self) -> str:
        return content_id("atomic_preoutcome_observation_", self)

    def with_outcome(self, outcome: int) -> DiscoveryObservation:
        """Attach the independently measured label without changing frozen source coordinates."""
        return DiscoveryObservation(self.task_unit_id, self.model_id, self.family_id,
            self.request_randomness_slot, self.candidate_states, self.covariates, outcome,
            self.source_binding_sha256, self.source_gate_failures)


@dataclass(frozen=True, slots=True)
class AtomicFoldAssignment:
    task_unit_id: str
    target_state: int
    fold: int

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "Atomic fold task_unit_id")
        if type(self.target_state) is not int or self.target_state not in {0, 1}:
            raise ValueError("Atomic target_state must be binary")
        if type(self.fold) is not int or self.fold < 0:
            raise ValueError("Atomic fold must be nonnegative")


@dataclass(frozen=True, slots=True)
class AtomicCandidateFoldManifest:
    candidate_id: str
    operation: Operation
    fold_count: int
    assignments: tuple[AtomicFoldAssignment, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "Atomic fold candidate_id")
        if type(self.operation) is not Operation:
            raise TypeError("Atomic fold operation must be typed")
        if type(self.fold_count) is not int or self.fold_count < 2:
            raise ValueError("Atomic fold_count must be at least two")
        if not self.assignments or tuple(
            sorted(self.assignments, key=lambda item: item.task_unit_id)
        ) != self.assignments:
            raise ValueError("Atomic fold assignments must use canonical task order")
        if len({item.task_unit_id for item in self.assignments}) != len(self.assignments):
            raise ValueError("Atomic fold task units must be unique")
        if {item.fold for item in self.assignments} != set(range(self.fold_count)):
            raise ValueError("Atomic fold manifest must use every frozen fold")
        for fold in range(self.fold_count):
            if {
                item.target_state for item in self.assignments if item.fold == fold
            } != {0, 1}:
                raise ValueError("every Atomic test fold must contain both states")

    @property
    def fold_manifest_id(self) -> str:
        return content_id("atomic_candidate_fold_manifest_", self)


@dataclass(frozen=True, slots=True)
class AtomicFoldFreeze:
    """Outcome-blind candidate folds sealed before Atomic discovery scoring."""

    universe_id: str
    plan_id: str
    preoutcome_data_sha256: str
    discovery_population_sha256: str
    manifests: tuple[AtomicCandidateFoldManifest, ...]
    failures: tuple[SelectorFailure, ...]
    discoverability: tuple[DiscoverabilityDecision, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.universe_id, "Atomic fold-freeze universe_id"),
            (self.plan_id, "Atomic fold-freeze plan_id"),
        ):
            require_text(value, name)
        _require_digest(self.preoutcome_data_sha256, "Atomic fold-freeze pre-outcome data")
        _require_digest(self.discovery_population_sha256, "Atomic fold-freeze Discovery population")
        if tuple(sorted(self.manifests, key=lambda item: item.candidate_id)) != self.manifests:
            raise ValueError("Atomic frozen folds must use canonical candidate order")
        if (
            tuple(
                sorted(self.failures, key=lambda item: (item.candidate_id or "", item.reason_code))
            )
            != self.failures
        ):
            raise ValueError("Atomic fold failures must use canonical candidate order")
        manifest_ids = tuple((item.candidate_id for item in self.manifests))
        failure_ids = tuple((item.candidate_id for item in self.failures))
        if (
            len(set(manifest_ids)) != len(manifest_ids)
            or any((candidate_id is None for candidate_id in failure_ids))
            or len(set(failure_ids)) != len(failure_ids)
            or set(manifest_ids) & set(failure_ids)
        ):
            raise ValueError("Atomic fold freeze must account for each candidate once")
        if any(
            (
                item.reason_code
                not in {"atomic_fold_non_evaluable", "scoped_source_support_failed"}
                for item in self.failures
            )
        ):
            raise ValueError("Atomic fold freeze contains an unknown source-support/fold failure")
        decision_ids = tuple((item.candidate_id for item in self.discoverability))
        if decision_ids != tuple(sorted(set(decision_ids))) or any(
            (
                type(item) is not DiscoverabilityDecision
                or item.discovery_population_sha256 != self.discovery_population_sha256
                or item.universe_id != self.universe_id
                for item in self.discoverability
            )
        ):
            raise ValueError("Atomic discoverability decisions are not canonical or bound")
        discoverable = {
            item.candidate_id
            for item in self.discoverability
            if item.status is DiscoverabilityStatus.DISCOVERY_ELIGIBLE
        }
        if discoverable != set(manifest_ids):
            raise ValueError("Atomic discoverability must exactly match frozen fold support")

    @property
    def fold_freeze_id(self) -> str:
        return content_id("atomic_fold_freeze_", self)


@dataclass(frozen=True, slots=True)
class AtomicRDScore:
    candidate_id: str
    signed_risk_difference: float
    absolute_risk_difference: float
    baseline_task_units: int
    fold_manifest_id: str

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "Atomic RD candidate_id")
        require_text(self.fold_manifest_id, "Atomic RD fold_manifest_id")
        if any(
            type(value) not in {int, float} or not math.isfinite(float(value))
            for value in (self.signed_risk_difference, self.absolute_risk_difference)
        ):
            raise ValueError("Atomic RD values must be finite")
        if self.absolute_risk_difference != abs(self.signed_risk_difference):
            raise ValueError("Atomic absolute RD does not match its signed value")
        if type(self.baseline_task_units) is not int or self.baseline_task_units <= 0:
            raise ValueError("Atomic RD requires held-out baseline task units")


@dataclass(frozen=True, slots=True)
class AtomicFCIBootstrapEvidence:
    universe_id: str
    candidate_draws: tuple[tuple[str, tuple[bool | None, ...]], ...]
    evidence_sha256: str

    def __post_init__(self) -> None:
        require_text(self.universe_id, "Atomic FCI universe_id")
        _require_digest(self.evidence_sha256, "Atomic FCI bootstrap evidence")
        candidate_ids = tuple(candidate_id for candidate_id, _ in self.candidate_draws)
        _canonical_unique(candidate_ids, "Atomic FCI candidate draws")
        if any(
            not draws
            or any(type(value) is not bool and value is not None for value in draws)
            for _, draws in self.candidate_draws
        ):
            raise ValueError("Atomic FCI draws must be non-empty bool/null tuples")


@dataclass(frozen=True, slots=True)
class AtomicFCIGate:
    candidate_id: str
    status: AtomicFCIGateStatus
    total_draws: int
    valid_draws: int
    adjacency_draws: int
    valid_fraction: float
    adjacency_stability: float | None

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "Atomic FCI gate candidate_id")
        if type(self.status) is not AtomicFCIGateStatus:
            raise TypeError("Atomic FCI gate status must be typed")
        if not (
            type(self.total_draws) is int
            and type(self.valid_draws) is int
            and type(self.adjacency_draws) is int
            and self.total_draws > 0
            and 0 <= self.adjacency_draws <= self.valid_draws <= self.total_draws
        ):
            raise ValueError("Atomic FCI draw accounting is invalid")
        if self.valid_fraction != self.valid_draws / self.total_draws:
            raise ValueError("Atomic FCI valid fraction is inconsistent")
        expected = (
            self.adjacency_draws / self.valid_draws if self.valid_draws else None
        )
        if self.adjacency_stability != expected:
            raise ValueError("Atomic FCI stability must use the valid-draw denominator")
        if self.status is AtomicFCIGateStatus.NON_EVALUABLE:
            if self.adjacency_stability is not None and not 0 <= self.adjacency_stability <= 1:
                raise ValueError("Atomic FCI stability must be on [0, 1]")
        elif self.adjacency_stability is None:
            raise ValueError("an evaluable Atomic FCI gate requires stability")


@dataclass(frozen=True, slots=True)
class AtomicShadowVariantResult:
    variant: AtomicSelectorVariant
    universe_id: str
    plan_id: str
    fold_manifests_sha256: str
    rd_scores_sha256: str
    fci_gate_evidence_sha256: str | None
    ranking: tuple[RankedCandidate, ...]
    slots: tuple[SelectorSlot, ...]

    def __post_init__(self) -> None:
        if type(self.variant) is not AtomicSelectorVariant:
            raise TypeError("Atomic selector variant must be typed")
        for value, name in (
            (self.universe_id, "Atomic result universe_id"),
            (self.plan_id, "Atomic result plan_id"),
        ):
            require_text(value, name)
        _require_digest(self.fold_manifests_sha256, "Atomic fold manifests")
        _require_digest(self.rd_scores_sha256, "Atomic RD scores")
        if self.variant is AtomicSelectorVariant.FULL:
            _require_digest(self.fci_gate_evidence_sha256, "Atomic Full FCI gate evidence")
        elif self.fci_gate_evidence_sha256 is not None:
            raise ValueError("Atomic RD-only cannot read FCI gate evidence")
        if tuple(item.rank for item in self.ranking) != tuple(
            range(1, len(self.ranking) + 1)
        ):
            raise ValueError("Atomic ranking must have complete ranks")
        if tuple(slot.rank for slot in self.slots) != tuple(
            range(1, len(self.slots) + 1)
        ):
            raise ValueError("Atomic slots must be complete")
        filled = tuple(
            slot.candidate_id for slot in self.slots if slot.status is SlotStatus.FILLED
        )
        if filled != tuple(item.candidate_id for item in self.ranking[: len(filled)]):
            raise ValueError("Atomic filled slots must follow the ranking")

    @property
    def result_id(self) -> str:
        return content_id("atomic_shadow_variant_result_", self)


@dataclass(frozen=True, slots=True)
class AtomicSoleDifferenceAudit:
    universe_id: str
    plan_id: str
    discovery_data_sha256: str
    fold_manifests_sha256: str
    rd_scores_sha256: str
    tie_break_rule: str
    top_k: int
    full_additional_read: str = "fci_gate"
    rd_only_additional_reads: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, name in (
            (self.universe_id, "Atomic audit universe_id"),
            (self.plan_id, "Atomic audit plan_id"),
            (self.tie_break_rule, "Atomic tie-break rule"),
        ):
            require_text(value, name)
        for value in (
            self.discovery_data_sha256,
            self.fold_manifests_sha256,
            self.rd_scores_sha256,
        ):
            _require_digest(value)
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("Atomic audit top_k must be positive")
        if self.full_additional_read != "fci_gate" or self.rd_only_additional_reads:
            raise ValueError("only Atomic Full may add the FCI Gate read")


@dataclass(frozen=True, slots=True)
class AtomicShadowQualificationResult:
    universe: AtomicCandidateUniverseManifest
    plan: AtomicShadowPlan
    fold_manifests: tuple[AtomicCandidateFoldManifest, ...]
    rd_scores: tuple[AtomicRDScore, ...]
    fci_gates: tuple[AtomicFCIGate, ...]
    failures: tuple[SelectorFailure, ...]
    full: AtomicShadowVariantResult
    rd_only: AtomicShadowVariantResult
    sole_difference: AtomicSoleDifferenceAudit

    def __post_init__(self) -> None:
        if self.full.variant is not AtomicSelectorVariant.FULL:
            raise ValueError("Atomic qualification Full result is missing")
        if self.rd_only.variant is not AtomicSelectorVariant.RD_ONLY:
            raise ValueError("Atomic qualification RD-only result is missing")
        if self.full.universe_id != self.universe.universe_id or self.rd_only.universe_id != self.universe.universe_id:
            raise ValueError("Atomic shadow results drift from their shared universe")
        if self.full.plan_id != self.plan.plan_id or self.rd_only.plan_id != self.plan.plan_id:
            raise ValueError("Atomic shadow results drift from their shared plan")
        if self.full.fold_manifests_sha256 != self.rd_only.fold_manifests_sha256:
            raise ValueError("Atomic Core variants must share fold manifests")
        if self.full.rd_scores_sha256 != self.rd_only.rd_scores_sha256:
            raise ValueError("Atomic Core variants must share RD scores")

    @property
    def qualification_result_id(self) -> str:
        return content_id("atomic_shadow_qualification_result_", self)


class PolicyTrack(StrEnum):
    ATOMIC = "atomic"


@dataclass(frozen=True, slots=True)
class FixedSlotSource:
    """One model-bound selector's immutable K-slot output."""

    track: PolicyTrack
    selector_id: str
    model_id: str
    universe_id: str
    slots: tuple[SelectorSlot, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("fixed-slot track must be typed")
        for value, name in (
            (self.selector_id, "fixed-slot selector_id"),
            (self.model_id, "fixed-slot model_id"),
            (self.universe_id, "fixed-slot universe_id"),
        ):
            require_text(value, name)
        if not self.slots or tuple(item.rank for item in self.slots) != tuple(
            range(1, len(self.slots) + 1)
        ):
            raise ValueError("fixed-slot source must retain a complete non-empty K ledger")
        if any(
            type(item) is not ModelBoundCandidateRecord
            for item in self.model_bound_records
        ):
            raise TypeError("fixed-slot source requires model-bound candidate records")
        policy_keys = tuple(item.policy_key for item in self.model_bound_records)
        _canonical_unique(policy_keys, "fixed-slot model-bound policy keys")
        if self.model_bound_records and {item.discovery_model_id for item in self.model_bound_records} != {
            self.model_id
        }:
            raise ValueError("fixed-slot candidates must dispatch only to the source model")
        if not {
            item.candidate_id
            for item in self.slots
            if item.status is SlotStatus.FILLED
        } <= set(policy_keys):
            raise ValueError("a filled slot falls outside its model-bound universe")

    @property
    def source_id(self) -> str:
        return content_id("fixed_slot_source_", self)


@dataclass(frozen=True, slots=True)
class FixedSlotRecord:
    source_id: str
    track: PolicyTrack
    selector_id: str
    model_id: str
    rank: int
    status: SlotStatus
    candidate_record_id: str | None
    policy_key: str | None
    effect_coordinate_id: str | None
    reason_code: str | None

    def __post_init__(self) -> None:
        for value, name in (
            (self.source_id, "slot source_id"),
            (self.selector_id, "slot selector_id"),
            (self.model_id, "slot model_id"),
        ):
            require_text(value, name)
        if type(self.track) is not PolicyTrack or type(self.status) is not SlotStatus:
            raise TypeError("fixed slot track and status must be typed")
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("fixed slot rank must be positive")
        bound = (
            self.candidate_record_id,
            self.policy_key,
            self.effect_coordinate_id,
        )
        if self.status is SlotStatus.FILLED:
            if any(value is None for value in bound) or self.reason_code is not None:
                raise ValueError("a filled fixed slot requires only its three candidate identities")
            for value, name in zip(
                bound,
                ("candidate_record_id", "policy_key", "effect_coordinate_id"),
                strict=True,
            ):
                require_text(value, name)
        elif any(value is not None for value in bound) or not self.reason_code:
            raise ValueError("an unfilled fixed slot requires only a reason")

    @property
    def slot_id(self) -> str:
        return content_id("fixed_selector_slot_", self)


@dataclass(frozen=True, slots=True)
class FixedSlotLedger:
    """All Atomic selector denominators before bridge or confirmation."""

    protocol_id: str
    schema_version: str
    sources: tuple[FixedSlotSource, ...]
    top_k_by_track: tuple[tuple[PolicyTrack, int], ...]
    slots: tuple[FixedSlotRecord, ...]

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "fixed-slot protocol_id")
        require_text(self.schema_version, "fixed-slot schema_version")
        if not self.sources or any(type(item) is not FixedSlotSource for item in self.sources):
            raise TypeError("fixed-slot ledger requires typed sources")
        source_order = lambda item: (item.track.value, item.model_id, item.selector_id)
        if tuple(sorted(self.sources, key=source_order)) != self.sources:
            raise ValueError("fixed-slot sources must use canonical track/model/selector order")
        source_ids = tuple(item.source_id for item in self.sources)
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("fixed-slot sources must be unique")
        expected_top_k = {}
        for source in self.sources:
            previous = expected_top_k.setdefault(source.track, len(source.slots))
            if previous != len(source.slots):
                raise ValueError("all selectors in one track must use the same K")
        if self.top_k_by_track != tuple(
            sorted(expected_top_k.items(), key=lambda item: item[0].value)
        ):
            raise ValueError("fixed-slot track K values do not replay from sources")
        slot_order = lambda item: (
            item.track.value,
            item.model_id,
            item.selector_id,
            item.rank,
        )
        if tuple(sorted(self.slots, key=slot_order)) != self.slots:
            raise ValueError("fixed slots must use canonical track/model/selector/rank order")
        if len({item.slot_id for item in self.slots}) != len(self.slots):
            raise ValueError("fixed slot identities must be unique")
        slots_by_source: dict[str, list[FixedSlotRecord]] = defaultdict(list)
        for slot in self.slots:
            slots_by_source[slot.source_id].append(slot)
        if set(slots_by_source) != set(source_ids):
            raise ValueError("fixed slots must bind every source exactly")
        for source in self.sources:
            fixed = tuple(slots_by_source[source.source_id])
            if tuple(item.rank for item in fixed) != tuple(range(1, len(source.slots) + 1)):
                raise ValueError("fixed slots do not preserve the source K denominator")
            for original, record in zip(source.slots, fixed, strict=True):
                if original.status is not record.status or original.reason_code != record.reason_code:
                    raise ValueError("fixed slot status or reason drifted from its source")
                if original.candidate_id != record.policy_key:
                    raise ValueError("fixed slot policy identity drifted from its source")

    @property
    def fixed_slot_ledger_id(self) -> str:
        return content_id("fixed_slot_ledger_", self)


@dataclass(frozen=True, slots=True)
class SharedCandidateUnionEntry:
    track: PolicyTrack
    candidate: ModelBoundCandidateRecord

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("shared candidate track must be typed")
        if type(self.candidate) is not ModelBoundCandidateRecord:
            raise TypeError("shared union entry requires a model-bound candidate")

    @property
    def candidate_record_id(self) -> str:
        return self.candidate.candidate_record_id

    @property
    def effect_coordinate_id(self) -> str:
        return self.candidate.effect_coordinate.effect_coordinate_id


@dataclass(frozen=True, slots=True)
class CandidateSlotFanout:
    candidate_record_id: str
    slot_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_record_id, "fan-out candidate_record_id")
        _canonical_unique(self.slot_ids, "fan-out slot_ids")


@dataclass(frozen=True, slots=True)
class SharedConfirmationUnion:
    """Unique model-effect union and exact fan-out back to fixed selector slots."""

    ledger: FixedSlotLedger
    entries: tuple[SharedCandidateUnionEntry, ...]
    candidate_to_slots: tuple[CandidateSlotFanout, ...]

    def __post_init__(self) -> None:
        if type(self.ledger) is not FixedSlotLedger:
            raise TypeError("shared confirmation union requires a fixed-slot ledger")
        if any(type(item) is not SharedCandidateUnionEntry for item in self.entries):
            raise TypeError("shared confirmation entries must be typed")
        entry_ids = tuple(item.candidate_record_id for item in self.entries)
        _canonical_unique(entry_ids, "shared confirmation candidate records")
        effect_ids = tuple(item.effect_coordinate_id for item in self.entries)
        if len(set(effect_ids)) != len(effect_ids):
            raise ValueError("one model effect may enter the confirmation union only once")
        if tuple(item.candidate_record_id for item in self.candidate_to_slots) != entry_ids:
            raise ValueError("candidate-to-slots must exactly follow the unique union")
        filled = {
            item.candidate_record_id: []
            for item in self.ledger.slots
            if item.status is SlotStatus.FILLED
        }
        for slot in self.ledger.slots:
            if slot.status is SlotStatus.FILLED:
                filled[slot.candidate_record_id].append(slot.slot_id)
        if set(filled) != set(entry_ids):
            raise ValueError("unique union must equal every filled candidate record")
        for fanout in self.candidate_to_slots:
            if fanout.slot_ids != tuple(sorted(filled[fanout.candidate_record_id])):
                raise ValueError("candidate-to-slots fan-out does not replay from the ledger")

    @property
    def shared_confirmation_union_id(self) -> str:
        return content_id("shared_confirmation_union_", self)


@dataclass(frozen=True, slots=True)
class ConfirmationDispatchRecord:
    candidate_record_id: str
    effect_coordinate_id: str
    policy_key: str
    model_id: str
    status: BridgeStatus
    protocol_record_id: str | None
    reason_code: str | None
    dispatch_count: int

    def __post_init__(self) -> None:
        for name in (
            "candidate_record_id",
            "effect_coordinate_id",
            "policy_key",
            "model_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.status) is not BridgeStatus:
            raise TypeError("confirmation dispatch status must be typed")
        if self.status is BridgeStatus.SUCCESS:
            require_text(self.protocol_record_id, "protocol_record_id")
            if self.reason_code is not None or self.dispatch_count != 1:
                raise ValueError("a successful model-bound candidate dispatches exactly once")
        elif (
            self.protocol_record_id is not None
            or not self.reason_code
            or self.dispatch_count != 0
        ):
            raise ValueError("a bridge/protocolization failure cannot be dispatched")


@dataclass(frozen=True, slots=True)
class ConfirmationDispatchManifest:
    union: SharedConfirmationUnion
    records: tuple[ConfirmationDispatchRecord, ...]

    def __post_init__(self) -> None:
        if type(self.union) is not SharedConfirmationUnion:
            raise TypeError("dispatch manifest requires a shared confirmation union")
        expected = self.union.entries
        if tuple(item.candidate_record_id for item in self.records) != tuple(
            item.candidate_record_id for item in expected
        ):
            raise ValueError("dispatch records must exactly follow the unique union")
        for entry, record in zip(expected, self.records, strict=True):
            candidate = entry.candidate
            if (
                record.effect_coordinate_id
                != candidate.effect_coordinate.effect_coordinate_id
                or record.policy_key != candidate.policy_key
                or record.model_id != candidate.discovery_model_id
            ):
                raise ValueError("dispatch drifted from the model-bound effect coordinate")
        if len({item.effect_coordinate_id for item in self.records}) != len(self.records):
            raise ValueError("a model effect cannot be dispatched more than once")
        shared_policy_result: dict[str, tuple[BridgeStatus, str | None, str | None]] = {}
        for record in self.records:
            result = (record.status, record.protocol_record_id, record.reason_code)
            previous = shared_policy_result.setdefault(record.policy_key, result)
            if previous != result:
                raise ValueError(
                    "one semantic policy must share one bridge/protocolization result across models"
                )

    @property
    def confirmation_dispatch_manifest_id(self) -> str:
        return content_id("confirmation_dispatch_manifest_", self)


def freeze_fixed_slot_ledger(
    protocol_id: str,
    schema_version: str,
    sources: Sequence[FixedSlotSource],
) -> FixedSlotLedger:
    """Bind model-specific Atomic selector slots without replacement."""

    frozen_sources = tuple(
        sorted(
            sources,
            key=lambda item: (item.track.value, item.model_id, item.selector_id),
        )
    )
    if len({(item.track, item.model_id, item.selector_id) for item in frozen_sources}) != len(
        frozen_sources
    ):
        raise ValueError("fixed-slot source coordinates must be unique")
    fixed = []
    for source in frozen_sources:
        record_by_policy = {item.policy_key: item for item in source.model_bound_records}
        for slot in source.slots:
            candidate = (
                record_by_policy[slot.candidate_id] if slot.status is SlotStatus.FILLED else None
            )
            fixed.append(
                FixedSlotRecord(
                    source.source_id,
                    source.track,
                    source.selector_id,
                    source.model_id,
                    slot.rank,
                    slot.status,
                    None if candidate is None else candidate.candidate_record_id,
                    None if candidate is None else candidate.policy_key,
                    (
                        None
                        if candidate is None
                        else candidate.effect_coordinate.effect_coordinate_id
                    ),
                    slot.reason_code,
                )
            )
    top_k = {}
    for source in frozen_sources:
        top_k.setdefault(source.track, len(source.slots))
    return FixedSlotLedger(
        protocol_id,
        schema_version,
        frozen_sources,
        tuple(sorted(top_k.items(), key=lambda item: item[0].value)),
        tuple(fixed),
    )


def freeze_shared_confirmation_union(
    ledger: FixedSlotLedger,
) -> SharedConfirmationUnion:
    """Deduplicate filled slots at the model-effect record, never at rank."""

    record_by_id = {
        record.candidate_record_id: (source.track, record)
        for source in ledger.sources
        for record in source.model_bound_records
    }
    selected_ids = tuple(
        sorted(
            {
                slot.candidate_record_id
                for slot in ledger.slots
                if slot.status is SlotStatus.FILLED
            }
        )
    )
    entries = tuple(
        SharedCandidateUnionEntry(*record_by_id[candidate_id])
        for candidate_id in selected_ids
    )
    fanout = tuple(
        CandidateSlotFanout(
            candidate_id,
            tuple(
                sorted(
                    slot.slot_id
                    for slot in ledger.slots
                    if slot.candidate_record_id == candidate_id
                )
            ),
        )
        for candidate_id in selected_ids
    )
    return SharedConfirmationUnion(ledger, entries, fanout)


def freeze_confirmation_dispatch(
    union: SharedConfirmationUnion,
    protocol_record_ids: Mapping[str, str],
    *,
    failures: Mapping[str, tuple[BridgeStatus, str]] | None = None,
) -> ConfirmationDispatchManifest:
    """Dispatch each selected record only to its discovery-bound model."""

    expected_ids = tuple(item.candidate_record_id for item in union.entries)
    frozen_failures = {} if failures is None else dict(failures)
    if set(protocol_record_ids) & set(frozen_failures) or (
        set(protocol_record_ids) | set(frozen_failures)
    ) != set(expected_ids):
        raise ValueError("successful and failed dispatch records must partition the union")
    if any(
        type(status) is not BridgeStatus or status is BridgeStatus.SUCCESS or not reason
        for status, reason in frozen_failures.values()
    ):
        raise ValueError("dispatch failures must be typed bridge/protocolization failures")
    records = tuple(
        ConfirmationDispatchRecord(
            entry.candidate_record_id,
            entry.effect_coordinate_id,
            entry.candidate.policy_key,
            entry.candidate.discovery_model_id,
            (
                BridgeStatus.SUCCESS
                if entry.candidate_record_id in protocol_record_ids
                else frozen_failures[entry.candidate_record_id][0]
            ),
            protocol_record_ids.get(entry.candidate_record_id),
            (
                None
                if entry.candidate_record_id in protocol_record_ids
                else frozen_failures[entry.candidate_record_id][1]
            ),
            1 if entry.candidate_record_id in protocol_record_ids else 0,
        )
        for entry in union.entries
    )
    return ConfirmationDispatchManifest(union, records)


def freeze_atomic_candidate_universe(
    policy_keys: Sequence[AtomicPolicyKey],
    model_bound_records: Sequence[ModelBoundCandidateRecord],
    *,
    supported_policy_keys: Sequence[str],
    coverage_summaries: Mapping[str, CandidateCoverageSummary],
    realization_policy_ids: Mapping[str, str],
    candidate_family_ids: Mapping[str, str],
    preoutcome_data_sha256: str,
    discovery_population_sha256: str,
    positivity_audit_sha256: str,
    information_budget_sha256: str,
    top_k: int,
    representation_adapter_id: str,
) -> AtomicCandidateUniverseManifest:
    """Freeze one direction-neutral Atomic universe for Full and RD-only."""

    ordered_keys = tuple(sorted(policy_keys, key=lambda item: item.policy_key))
    candidate_ids = tuple(item.policy_key for item in ordered_keys)
    records_by_key = {item.policy_key: item for item in model_bound_records}
    if len(records_by_key) != len(tuple(model_bound_records)) or set(records_by_key) != set(
        candidate_ids
    ):
        raise ValueError("Atomic model-bound records must bind every policy exactly once")
    for values, name in (
        (realization_policy_ids, "Atomic realization policies"),
        (candidate_family_ids, "Atomic family bindings"),
    ):
        if set(values) != set(candidate_ids):
            raise ValueError(f"{name} must bind every policy exactly once")
    if set(coverage_summaries) != set(candidate_ids):
        raise ValueError("Atomic coverage summaries must bind every policy exactly once")
    return AtomicCandidateUniverseManifest(
        ordered_keys,
        tuple(sorted(supported_policy_keys)),
        tuple(coverage_summaries[candidate_id] for candidate_id in candidate_ids),
        tuple(records_by_key[candidate_id] for candidate_id in candidate_ids),
        tuple((candidate_id, realization_policy_ids[candidate_id]) for candidate_id in candidate_ids),
        tuple((candidate_id, candidate_family_ids[candidate_id]) for candidate_id in candidate_ids),
        preoutcome_data_sha256,
        discovery_population_sha256,
        positivity_audit_sha256,
        information_budget_sha256,
        top_k,
        representation_adapter_id,
    )


def run_atomic_shadow_qualification(
    universe: AtomicCandidateUniverseManifest,
    observations: Sequence[DiscoveryObservation],
    plan: AtomicShadowPlan,
    fci_evidence: AtomicFCIBootstrapEvidence,
    *,
    fold_freeze: AtomicFoldFreeze,
) -> AtomicShadowQualificationResult:
    """Run Atomic Full/RD-only with one shared row, fold, and RD path."""

    if type(universe) is not AtomicCandidateUniverseManifest:
        raise TypeError("universe must be an AtomicCandidateUniverseManifest")
    if type(plan) is not AtomicShadowPlan:
        raise TypeError("plan must be an AtomicShadowPlan")
    if universe.model_bound_records and {item.discovery_model_id for item in universe.model_bound_records} != {plan.model_id}:
        raise ValueError("Atomic discovery plan model must match every model-bound candidate")
    if type(fci_evidence) is not AtomicFCIBootstrapEvidence:
        raise TypeError("fci_evidence must be AtomicFCIBootstrapEvidence")
    if atomic_preoutcome_data_sha256(atomic_preoutcome_observations(observations)) != universe.preoutcome_data_sha256:
        raise ValueError("Atomic discovery observations drift from the frozen universe")
    if fci_evidence.universe_id != universe.universe_id:
        raise ValueError("Atomic FCI evidence drifts from the frozen universe")
    if tuple(candidate_id for candidate_id, _ in fci_evidence.candidate_draws) != (
        universe.supported_policy_keys
    ):
        raise ValueError("Atomic FCI evidence must cover every supported policy in order")

    rows = _reference_observations(observations, plan.model_id)
    family_by_candidate = dict(universe.candidate_family_ids)
    if type(fold_freeze) is not AtomicFoldFreeze:
        raise TypeError("Atomic prioritization requires an explicit fold freeze")
    if fold_freeze != freeze_atomic_candidate_folds(
        universe,
        atomic_preoutcome_observations(observations),
        plan,
    ):
        raise ValueError("Atomic fold freeze failed outcome-blind replay")
    frozen_manifest_by_id = {
        item.candidate_id: item for item in fold_freeze.manifests
    }
    rd_scores: list[AtomicRDScore] = []
    failures: list[SelectorFailure] = list(fold_freeze.failures)
    for candidate_id in universe.supported_policy_keys:
        manifest = frozen_manifest_by_id.get(candidate_id)
        if manifest is None:
            continue
        candidate_rows = tuple(
            row
            for row in rows
            if row.family_id == family_by_candidate[candidate_id]
            and candidate_id in dict(row.candidate_states)
        )
        try:
            score = _atomic_cross_fitted_rd(candidate_id, candidate_rows, manifest, plan)
        except ValueError as exc:
            failures.append(
                SelectorFailure("atomic_rd_non_evaluable", str(exc), candidate_id)
            )
            continue
        rd_scores.append(score)

    frozen_folds = fold_freeze.manifests
    frozen_scores = tuple(sorted(rd_scores, key=lambda item: item.candidate_id))
    frozen_failures = tuple(
        sorted(failures, key=lambda item: (item.candidate_id or "", item.reason_code))
    )
    fold_sha256 = content_hash(frozen_folds)
    rd_sha256 = content_hash(frozen_scores)
    gates = _atomic_fci_gates(fci_evidence, plan)
    gate_sha256 = content_hash(
        {
            "source_evidence_sha256": fci_evidence.evidence_sha256,
            "minimum_valid_fraction": plan.fci_minimum_valid_fraction,
            "adjacency_threshold": plan.fci_adjacency_threshold,
            "gates": gates,
        }
    )
    full = _atomic_variant_result(
        AtomicSelectorVariant.FULL,
        universe,
        plan,
        frozen_scores,
        frozen_failures,
        fold_sha256,
        rd_sha256,
        gates,
        gate_sha256,
    )
    rd_only = _atomic_variant_result(
        AtomicSelectorVariant.RD_ONLY,
        universe,
        plan,
        frozen_scores,
        frozen_failures,
        fold_sha256,
        rd_sha256,
        (),
        None,
    )
    sole_difference = AtomicSoleDifferenceAudit(
        universe.universe_id,
        plan.plan_id,
        discovery_data_sha256(observations),
        fold_sha256,
        rd_sha256,
        "descending_absolute_rd_then_policy_key_v1",
        universe.top_k,
    )
    return AtomicShadowQualificationResult(
        universe,
        plan,
        frozen_folds,
        frozen_scores,
        gates,
        frozen_failures,
        full,
        rd_only,
        sole_difference,
    )


def freeze_atomic_candidate_folds(
    universe: AtomicCandidateUniverseManifest,
    observations: Sequence[AtomicPreOutcomeObservation],
    plan: AtomicShadowPlan,
) -> AtomicFoldFreeze:
    """Seal deterministic candidate/state folds from an outcome-free schema."""

    if type(universe) is not AtomicCandidateUniverseManifest:
        raise TypeError("universe must be an AtomicCandidateUniverseManifest")
    if type(plan) is not AtomicShadowPlan:
        raise TypeError("plan must be an AtomicShadowPlan")
    if universe.model_bound_records and {item.discovery_model_id for item in universe.model_bound_records} != {plan.model_id}:
        raise ValueError("Atomic discovery plan model must match every model-bound candidate")
    if any(type(item) is not AtomicPreOutcomeObservation for item in observations):
        raise TypeError("Atomic fold freeze requires pre-outcome observations")
    if atomic_preoutcome_data_sha256(observations) != universe.preoutcome_data_sha256:
        raise ValueError("pre-outcome observations drift from the frozen universe")
    rows = _reference_atomic_preoutcome_observations(observations, plan.model_id)
    family_by_candidate = dict(universe.candidate_family_ids)
    policy_by_id = {item.policy_key: item for item in universe.policy_keys}
    manifests = []
    failures = []
    for candidate_id in universe.supported_policy_keys:
        candidate_rows = tuple(
            row
            for row in rows
            if row.family_id == family_by_candidate[candidate_id]
            and candidate_id in dict(row.candidate_states)
        )
        if any(row.source_gate_failures is not None and dict(row.source_gate_failures)[candidate_id]
               for row in candidate_rows):
            failures.append(SelectorFailure("scoped_source_support_failed",
                "The frozen source-scope support rule failed before outcomes were read.", candidate_id))
            continue
        try:
            manifest = _atomic_candidate_fold_manifest(
                candidate_id,
                policy_by_id[candidate_id].factor.operation,
                candidate_rows,
                plan.cross_fit_folds,
                plan.fold_seed,
            )
        except ValueError as exc:
            failures.append(
                SelectorFailure("atomic_fold_non_evaluable", str(exc), candidate_id)
            )
            continue
        manifests.append(manifest)
    frozen_manifests = tuple(sorted(manifests, key=lambda item: item.candidate_id))
    frozen_failures = tuple(
        sorted(
            failures,
            key=lambda item: (item.candidate_id or "", item.reason_code),
        )
    )
    manifest_by_id = {item.candidate_id: item for item in frozen_manifests}
    failure_by_id = {item.candidate_id: item for item in frozen_failures}
    coverage_by_id = {
        item.candidate_id: item for item in universe.coverage_summaries
    }
    supported = set(universe.supported_policy_keys)
    discoverability = []
    for candidate_id in universe.candidate_ids:
        coverage = coverage_by_id[candidate_id]
        manifest = manifest_by_id.get(candidate_id)
        if manifest is not None:
            fold_counts = Counter(
                str(item.target_state) for item in manifest.assignments
            )
            if coverage.state_or_cell_task_units != (
                ("0", fold_counts["0"]),
                ("1", fold_counts["1"]),
            ):
                raise ValueError("Atomic coverage summary drifted from outcome-blind folds")
        reasons = []
        if candidate_id not in supported:
            reasons.append(DiscoverabilityReason.ATOMIC_NATURAL_SUPPORT_FAILED)
        if candidate_id in failure_by_id:
            reasons.append(DiscoverabilityReason.SOURCE_SCOPE_SUPPORT_FAILED
                if failure_by_id[candidate_id].reason_code == "scoped_source_support_failed"
                else DiscoverabilityReason.FOLD_NON_EVALUABLE)
        fold_evidence = manifest or failure_by_id.get(candidate_id) or {
            "candidate_id": candidate_id,
            "fold_status": "NOT_ATTEMPTED_SUPPORT_FAILED",
        }
        discoverability.append(
            DiscoverabilityDecision(
                candidate_id,
                CandidateKind.ATOMIC,
                universe.discovery_population_sha256,
                universe.universe_id,
                universe.positivity_audit_sha256,
                content_hash(fold_evidence),
                coverage,
                (
                    DiscoverabilityStatus.DISCOVERY_ELIGIBLE
                    if not reasons
                    else DiscoverabilityStatus.DISCOVERY_INELIGIBLE
                ),
                tuple(sorted(reasons, key=lambda item: item.value)),
            )
        )
    return AtomicFoldFreeze(
        universe.universe_id,
        plan.plan_id,
        atomic_preoutcome_data_sha256(observations),
        universe.discovery_population_sha256,
        frozen_manifests,
        frozen_failures,
        tuple(discoverability),
    )


def atomic_preoutcome_observations(
    observations: Sequence[DiscoveryObservation],
) -> tuple[AtomicPreOutcomeObservation, ...]:
    """Project natural discovery records before their outcome field is opened."""

    if any(
        type(item) is not DiscoveryObservation for item in observations
    ):
        raise TypeError("Atomic pre-outcome projection requires discovery observations")
    return tuple(
        sorted(
            (
                AtomicPreOutcomeObservation(
                    item.task_unit_id,
                    item.model_id,
                    item.family_id,
                    item.request_randomness_slot,
                    item.candidate_states,
                    item.covariates,
                    item.source_binding_sha256,
                    item.source_gate_failures,
                )
                for item in observations
            ),
            key=lambda item: item.preoutcome_observation_id,
        )
    )


def atomic_preoutcome_data_sha256(
    observations: Sequence[AtomicPreOutcomeObservation],
) -> str:
    """Hash only coordinates available before the outcome column is opened."""

    frozen = tuple(
        sorted(observations, key=lambda item: item.preoutcome_observation_id)
    )
    if any(
        type(item) is not AtomicPreOutcomeObservation for item in frozen
    ):
        raise TypeError("Atomic pre-outcome data requires typed observations")
    coordinates = {
        (item.task_unit_id, item.model_id, item.family_id, item.request_randomness_slot)
        for item in frozen
    }
    if len(coordinates) != len(frozen):
        raise ValueError("an Atomic pre-outcome coordinate is duplicated")
    return content_hash(frozen)


def _reference_atomic_preoutcome_observations(
    observations: Sequence[AtomicPreOutcomeObservation],
    model_id: str,
) -> tuple[AtomicPreOutcomeObservation, ...]:
    candidates = [item for item in observations if item.model_id == model_id]
    if observations and not candidates:
        raise ValueError("Atomic selector model has no pre-outcome observations")
    by_unit: dict[tuple[str, str], list[AtomicPreOutcomeObservation]] = {}
    for item in candidates:
        by_unit.setdefault((item.family_id, item.task_unit_id), []).append(item)
    return tuple(
        min(
            values,
            key=lambda item: (
                item.request_randomness_slot,
                item.preoutcome_observation_id,
            ),
        )
        for _, values in sorted(by_unit.items())
    )


def _atomic_candidate_fold_manifest(
    candidate_id: str,
    operation: Operation,
    rows: tuple[AtomicPreOutcomeObservation, ...],
    fold_count: int,
    fold_seed: int,
) -> AtomicCandidateFoldManifest:
    if not rows or len({row.task_unit_id for row in rows}) != len(rows):
        raise ValueError("Atomic candidate rows are empty or duplicate task units")
    by_state: dict[int, list[AtomicPreOutcomeObservation]] = {0: [], 1: []}
    for row in rows:
        raw_state = dict(row.candidate_states)[candidate_id]
        target_state = raw_state if operation is Operation.ADD else 1 - raw_state
        by_state[target_state].append(row)
    if any(len(values) < fold_count for values in by_state.values()):
        raise ValueError("Atomic candidate lacks state support for every frozen fold")
    assignments = []
    for state in (0, 1):
        ordered = sorted(
            by_state[state],
            key=lambda row: (
                content_hash(
                    {
                        "domain": "atomic_candidate_state_fold_v1",
                        "seed": fold_seed,
                        "candidate_id": candidate_id,
                        "target_state": state,
                        "task_unit_id": row.task_unit_id,
                    }
                ),
                row.task_unit_id,
            ),
        )
        assignments.extend(
            AtomicFoldAssignment(row.task_unit_id, state, index % fold_count)
            for index, row in enumerate(ordered)
        )
    return AtomicCandidateFoldManifest(
        candidate_id,
        operation,
        fold_count,
        tuple(sorted(assignments, key=lambda item: item.task_unit_id)),
    )


def _atomic_cross_fitted_rd(
    candidate_id: str,
    rows: tuple[DiscoveryObservation, ...],
    folds: AtomicCandidateFoldManifest,
    plan: AtomicShadowPlan,
) -> AtomicRDScore:
    fold_by_task = {item.task_unit_id: item.fold for item in folds.assignments}
    state_by_task = {item.task_unit_id: item.target_state for item in folds.assignments}
    contributions: list[float] = []
    for fold in range(folds.fold_count):
        training = tuple(row for row in rows if fold_by_task[row.task_unit_id] != fold)
        held_out = tuple(row for row in rows if fold_by_task[row.task_unit_id] == fold)
        if {state_by_task[row.task_unit_id] for row in training} != {0, 1}:
            raise ValueError("Atomic training fold lacks both target-relative states")
        if any(
            tuple(name for name, _ in row.covariates) != plan.covariate_names
            for row in (*training, *held_out)
        ):
            raise ValueError("Atomic covariate schema drifts from the frozen plan")
        baseline = tuple(
            row for row in held_out if state_by_task[row.task_unit_id] == 0
        )
        if not baseline:
            raise ValueError("Atomic held-out fold lacks baseline-eligible task units")
        train_raw = [
            [
                *(float(value) for _, value in row.covariates),
                float(state_by_task[row.task_unit_id]),
            ]
            for row in training
        ]
        test_raw = [
            [*(float(value) for _, value in row.covariates), target_state]
            for row in baseline
            for target_state in (0.0, 1.0)
        ]
        train_x, test_x = _normalize_design(train_raw, test_raw)
        probabilities = _ridge_probabilities(
            train_x,
            [row.outcome for row in training],
            test_x,
            float(plan.ridge_lambda),
        )
        contributions.extend(
            probabilities[index + 1] - probabilities[index]
            for index in range(0, len(probabilities), 2)
        )
    baseline_count = sum(item.target_state == 0 for item in folds.assignments)
    if len(contributions) != baseline_count or not contributions:
        raise ValueError("Atomic cross-fitting did not cover every baseline task unit")
    signed = sum(contributions) / len(contributions)
    return AtomicRDScore(
        candidate_id,
        signed,
        abs(signed),
        baseline_count,
        folds.fold_manifest_id,
    )


def _normalize_design(
    train_raw: list[list[float]],
    test_raw: list[list[float]],
) -> tuple[list[list[float]], list[list[float]]]:
    if not train_raw or not test_raw:
        raise ValueError("normalized design requires non-empty train and test rows")
    width = len(train_raw[0])
    if any(len(row) != width for row in (*train_raw, *test_raw)):
        raise ValueError("normalized design width is inconsistent")
    if width == 0:
        return train_raw, test_raw
    means = [
        sum(row[column] for row in train_raw) / len(train_raw)
        for column in range(width)
    ]
    scales = [
        math.sqrt(
            sum((row[column] - means[column]) ** 2 for row in train_raw)
            / len(train_raw)
        )
        or 1.0
        for column in range(width)
    ]

    def normalize(row: list[float]) -> list[float]:
        return [
            (value - means[index]) / scales[index]
            for index, value in enumerate(row)
        ]

    return [normalize(row) for row in train_raw], [normalize(row) for row in test_raw]


def _atomic_fci_gates(
    evidence: AtomicFCIBootstrapEvidence,
    plan: AtomicShadowPlan,
) -> tuple[AtomicFCIGate, ...]:
    gates = []
    for candidate_id, draws in evidence.candidate_draws:
        valid = tuple(value for value in draws if value is not None)
        valid_fraction = len(valid) / len(draws)
        stability = sum(valid) / len(valid) if valid else None
        if valid_fraction < plan.fci_minimum_valid_fraction:
            status = AtomicFCIGateStatus.NON_EVALUABLE
        elif stability is not None and stability >= plan.fci_adjacency_threshold:
            status = AtomicFCIGateStatus.PASSED
        else:
            status = AtomicFCIGateStatus.FAILED
        gates.append(
            AtomicFCIGate(
                candidate_id,
                status,
                len(draws),
                len(valid),
                sum(valid),
                valid_fraction,
                stability,
            )
        )
    return tuple(gates)


def _atomic_variant_result(
    variant: AtomicSelectorVariant,
    universe: AtomicCandidateUniverseManifest,
    plan: AtomicShadowPlan,
    scores: tuple[AtomicRDScore, ...],
    failures: tuple[SelectorFailure, ...],
    fold_sha256: str,
    rd_sha256: str,
    gates: tuple[AtomicFCIGate, ...],
    gate_sha256: str | None,
) -> AtomicShadowVariantResult:
    score_by_candidate = {item.candidate_id: item for item in scores}
    if variant is AtomicSelectorVariant.FULL:
        passed = {
            item.candidate_id
            for item in gates
            if item.status is AtomicFCIGateStatus.PASSED
        }
        rankable = set(score_by_candidate) & passed
    else:
        rankable = set(score_by_candidate)
    ordered = sorted(
        rankable,
        key=lambda candidate_id: (
            -score_by_candidate[candidate_id].absolute_risk_difference,
            candidate_id,
        ),
    )
    ranking = tuple(
        RankedCandidate(
            candidate_id,
            score_by_candidate[candidate_id].absolute_risk_difference,
            rank,
        )
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    slots = []
    gate_statuses = {item.status for item in gates}
    for rank in range(1, universe.top_k + 1):
        if rank <= len(ranking):
            slots.append(
                SelectorSlot(rank, SlotStatus.FILLED, ranking[rank - 1].candidate_id, None)
            )
        elif failures or AtomicFCIGateStatus.NON_EVALUABLE in gate_statuses:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.NON_EVALUABLE,
                    None,
                    "candidate_score_or_fci_gate_non_evaluable",
                )
            )
        elif variant is AtomicSelectorVariant.FULL and gates:
            slots.append(
                SelectorSlot(rank, SlotStatus.GATE_FAILED, None, "fci_gate_exhausted")
            )
        else:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.INSUFFICIENT_CANDIDATES,
                    None,
                    "rankable_universe_smaller_than_k",
                )
            )
    return AtomicShadowVariantResult(
        variant,
        universe.universe_id,
        plan.plan_id,
        fold_sha256,
        rd_sha256,
        gate_sha256,
        ranking,
        tuple(slots),
    )


def discovery_data_sha256(observations: Sequence[DiscoveryObservation]) -> str:
    frozen = tuple(sorted(observations, key=lambda item: item.observation_id))
    if len({item.observation_id for item in frozen}) != len(frozen):
        raise ValueError("discovery observations must be unique")
    coordinates = {
        (item.task_unit_id, item.model_id, item.family_id, item.request_randomness_slot)
        for item in frozen
    }
    if len(coordinates) != len(frozen):
        raise ValueError("a discovery task/model/family/request coordinate is duplicated")
    return content_hash(frozen)


def _reference_observations(
    observations: Sequence[DiscoveryObservation],
    model_id: str,
) -> tuple[DiscoveryObservation, ...]:
    candidates = [item for item in observations if item.model_id == model_id]
    if observations and not candidates:
        raise ValueError("selector model has no discovery observations")
    by_unit: dict[tuple[str, str], list[DiscoveryObservation]] = {}
    for item in candidates:
        by_unit.setdefault((item.family_id, item.task_unit_id), []).append(item)
    return tuple(
        min(values, key=lambda item: (item.request_randomness_slot, item.observation_id))
        for _, values in sorted(by_unit.items())
    )


def _causal_learn_version() -> str:
    from importlib.metadata import version

    return version("causal-learn")


def _encode_fci_covariates(
    rows: tuple[DiscoveryObservation, ...],
    names: tuple[str, ...],
) -> tuple[tuple[int, ...], ...]:
    columns = [
        [dict(row.covariates)[name] for row in rows]
        for name in names
    ]
    codes = [
        {value: index for index, value in enumerate(sorted(set(column)))}
        for column in columns
    ]
    return tuple(
        tuple(codes[column][dict(row.covariates)[name]] for column, name in enumerate(names))
        for row in rows
    )


def _run_causal_learn_family(
    matrix: tuple[tuple[int, ...], ...],
    *,
    alpha: float,
    depth: int,
    max_path_length: int,
    outcome_index: int,
) -> set[int]:
    variable_order = tuple(f"X{index + 1}" for index in range(outcome_index + 1))
    adjacent, _edges = _run_causal_learn_pag(
        matrix, alpha=alpha, depth=depth, max_path_length=max_path_length,
        outcome_index=outcome_index, variable_order=variable_order,
        forbidden_directions=tuple((variable_order[-1], item) for item in variable_order[:-1]),
    )
    return adjacent


def _run_causal_learn_pag(
    matrix: tuple[tuple[int, ...], ...],
    *,
    alpha: float,
    depth: int,
    max_path_length: int,
    outcome_index: int,
    variable_order: tuple[str, ...],
    forbidden_directions: tuple[tuple[str, str], ...],
) -> tuple[set[int], tuple[tuple[str, str, str, str], ...]]:
    import numpy as np  # type: ignore[import-not-found]
    from causallearn.graph.GraphNode import GraphNode  # type: ignore[import-not-found]
    from causallearn.search.ConstraintBased.FCI import fci  # type: ignore[import-not-found]
    from causallearn.utils.PCUtils.BackgroundKnowledge import (  # type: ignore[import-not-found]
        BackgroundKnowledge,
    )

    backend_knowledge = BackgroundKnowledge()
    if len(variable_order) != len(matrix[0]) or len(set(variable_order)) != len(variable_order):
        raise ValueError("FCI variable order does not bind the matrix")
    index_by_name = {name: index for index, name in enumerate(variable_order)}
    for source, target in forbidden_directions:
        if source not in index_by_name or target not in index_by_name or source == target:
            raise ValueError("FCI BK direction references an unknown or identical variable")
        backend_knowledge.add_forbidden_by_node(
            GraphNode(f"X{index_by_name[source] + 1}"),
            GraphNode(f"X{index_by_name[target] + 1}"),
        )
    graph, _edges = fci(
        np.asarray(matrix, dtype=np.int64),
        independence_test_method="gsq",
        alpha=alpha,
        depth=depth,
        max_path_length=max_path_length,
        verbose=False,
        background_knowledge=backend_knowledge,
        show_progress=False,
    )
    nodes = graph.get_nodes()
    adjacent = {
        index
        for index in range(outcome_index)
        if graph.get_edge(nodes[index], nodes[outcome_index]) is not None
    }
    edges = tuple(
        sorted(
            (
                variable_order[nodes.index(edge.get_node1())],
                str(edge.get_endpoint1()),
                variable_order[nodes.index(edge.get_node2())],
                str(edge.get_endpoint2()),
            )
            for edge in graph.get_graph_edges()
        )
    )
    return adjacent, edges


def _ridge_probabilities(
    train_x: list[list[float]],
    train_y: list[int],
    test_x: list[list[float]],
    ridge_lambda: float,
) -> list[float]:
    weights = fit_ridge_logit(
        [[1.0, *values] for values in train_x], train_y, ridge_lambda,
        maximum_iterations=300,
    )
    return [
        _sigmoid(weights[0] + sum(weight * value for weight, value in zip(weights[1:], row, strict=True)))
        for row in test_x
    ]


def _validate_source_gate_failures(row) -> None:
    if row.source_gate_failures is None:
        return
    if row.source_binding_sha256 is None or tuple(key for key, _ in row.source_gate_failures) != tuple(key for key, _ in row.candidate_states):
        raise ValueError("source Gate decisions must bind every Atomic state and its source identity")
    for _, reasons in row.source_gate_failures:
        _canonical_unique(reasons, "source Gate failure reasons")


def _validate_numeric_pairs(
    values: tuple[tuple[str, int], ...] | tuple[tuple[str, float], ...],
    name: str,
    *,
    binary: bool,
) -> None:
    keys = tuple(key for key, _ in values)
    _canonical_unique(keys, name)
    for _, value in values:
        if type(value) not in ({int} if binary else {int, float}) or not math.isfinite(float(value)):
            raise ValueError(f"{name} must contain finite numeric values")
        if binary and value not in {0, 1}:
            raise ValueError(f"{name} must contain binary values")


__all__ = [
    "AtomicCandidateFoldManifest",
    "AtomicCandidateUniverseManifest",
    "AtomicFCIBootstrapEvidence",
    "AtomicFCIGate",
    "AtomicFCIGateStatus",
    "AtomicFoldAssignment",
    "AtomicFoldFreeze",
    "AtomicPreOutcomeObservation",
    "AtomicRDScore",
    "AtomicSelectorVariant",
    "AtomicShadowPlan",
    "AtomicShadowQualificationResult",
    "AtomicShadowVariantResult",
    "AtomicSoleDifferenceAudit",
    "BridgeStatus",
    "CandidateCoverageSummary",
    "CandidateKind",
    "CandidateSlotFanout",
    "ConfirmationDispatchManifest",
    "ConfirmationDispatchRecord",
    "DiscoverabilityDecision",
    "DiscoverabilityReason",
    "DiscoverabilityStatus",
    "DiscoveryObservation",
    "FixedSlotLedger",
    "FixedSlotRecord",
    "FixedSlotSource",
    "PolicyTrack",
    "RankedCandidate",
    "SelectorFailure",
    "SelectorSlot",
    "SharedCandidateUnionEntry",
    "SharedConfirmationUnion",
    "SlotStatus",
    "atomic_preoutcome_data_sha256",
    "atomic_preoutcome_observations",
    "discovery_data_sha256",
    "freeze_atomic_candidate_folds",
    "freeze_atomic_candidate_universe",
    "freeze_confirmation_dispatch",
    "freeze_fixed_slot_ledger",
    "freeze_shared_confirmation_union",
    "run_atomic_shadow_qualification",
]

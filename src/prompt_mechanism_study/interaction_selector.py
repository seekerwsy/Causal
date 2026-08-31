"""Outcome-blind pair support gates and observational interaction ranking.

Prompt-TSG relation specs define the finite pair universe.  Each eligible pair
is fit separately.  Cross-fitted predicted probabilities are standardized on
the pair's operation-specific baseline task units and ranked on the risk-
difference interaction scale.  The ridge-logit interaction coefficient is kept
only as a diagnostic; randomized 2x2 evaluation remains the sole source of
causal interaction estimates.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.mechanisms import (
    FactorialCompatibility,
    PairCompatibilityDecision,
    PairRelationEvidence,
    PairStructuralRelationEvidence,
)
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.prioritization import (
    CandidateCoverageSummary,
    CandidateKind,
    DiscoverabilityDecision,
    DiscoverabilityReason,
    DiscoverabilityStatus,
    RankedCandidate,
    SelectorFailure,
    SelectorSlot,
    SlotStatus,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.representation import (
    ModelBoundCandidateRecord,
    Operation,
    PairPolicyKey,
)


PairRelationEvidenceRecord = PairRelationEvidence | PairStructuralRelationEvidence


@dataclass(frozen=True, slots=True)
class PairDiscoveryObservation:
    """One natural-Prompt observation for one candidate pair and task unit."""

    pair_id: str
    relation_spec_id: str
    relation_evidence_id: str
    task_unit_id: str
    model_id: str
    source_lineage_id: str
    language: str
    task_archetype: str
    api_family: str
    context_query_id: str
    context_state: QueryState
    factor_states: tuple[tuple[str, QueryState], tuple[str, QueryState]]
    factor_reliabilities: tuple[tuple[str, float], tuple[str, float]]
    covariates: tuple[tuple[str, float], ...]
    outcome: int

    def __post_init__(self) -> None:
        for name in (
            "pair_id",
            "relation_spec_id",
            "relation_evidence_id",
            "task_unit_id",
            "model_id",
            "source_lineage_id",
            "language",
            "task_archetype",
            "api_family",
            "context_query_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.context_state) is not QueryState:
            raise TypeError("context_state must be QueryState")
        if len(self.factor_states) != 2 or any(
            not isinstance(feature, str) or not feature or type(state) is not QueryState
            for feature, state in self.factor_states
        ):
            raise ValueError("pair observation requires two typed factor states")
        if self.factor_states[0][0] == self.factor_states[1][0]:
            raise ValueError("pair observation factors must be distinct")
        if tuple(feature for feature, _ in self.factor_reliabilities) != tuple(
            feature for feature, _ in self.factor_states
        ) or any(
            type(value) not in {int, float}
            or not math.isfinite(float(value))
            or not 0 <= value <= 1
            for _, value in self.factor_reliabilities
        ):
            raise ValueError("factor reliability must bind both factors on [0, 1]")
        names = tuple(name for name, _ in self.covariates)
        if (
            tuple(sorted(names)) != names
            or len(set(names)) != len(names)
            or any(
                not isinstance(name, str)
                or not name
                or type(value) not in {int, float}
                or not math.isfinite(float(value))
                for name, value in self.covariates
            )
        ):
            raise ValueError("covariates must be finite with unique canonical names")
        if type(self.outcome) is not int or self.outcome not in {0, 1}:
            raise ValueError("discovery outcome must be binary")

    @property
    def observation_id(self) -> str:
        return content_id("pair_discovery_observation_", self)


@dataclass(frozen=True, slots=True)
class PairSupportGate:
    pair_id: str
    passed: bool
    reasons: tuple[str, ...]
    cell_task_units: tuple[tuple[str, int], ...]
    shared_lineages: int
    shared_languages: int
    shared_archetypes: int
    shared_api_families: int

    def __post_init__(self) -> None:
        require_text(self.pair_id, "pair_id")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("support-gate reasons must be unique and sorted")
        if self.passed != (not self.reasons):
            raise ValueError("support-gate status must agree with its reasons")
        if tuple(name for name, _ in self.cell_task_units) != ("00", "01", "10", "11"):
            raise ValueError("support-gate cells must use canonical order")
        if any(type(value) is not int or value < 0 for _, value in self.cell_task_units):
            raise ValueError("support-gate counts must be nonnegative integers")


class PairSelectorVariant(StrEnum):
    FULL = "pair_full"
    NO_RELATION = "pair_no_relation"


class PairRelationGateStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NON_EVALUABLE = "NON_EVALUABLE"


@dataclass(frozen=True, slots=True)
class PairCandidateUniverseManifest:
    """Compatibility-first Pair registry shared by Full and No-Relation."""

    policy_keys: tuple[PairPolicyKey, ...]
    compatibility_decisions: tuple[PairCompatibilityDecision, ...]
    coverage_summaries: tuple[CandidateCoverageSummary, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]
    candidate_family_ids: tuple[tuple[str, str], ...]
    discovery_data_sha256: str
    discovery_population_sha256: str
    compatibility_evidence_sha256: str
    information_budget_sha256: str
    top_k: int

    def __post_init__(self) -> None:
        if not self.policy_keys or any(type(item) is not PairPolicyKey for item in self.policy_keys):
            raise TypeError("Pair universe requires typed policy keys")
        candidate_ids = tuple(item.policy_key for item in self.policy_keys)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("Pair policy keys must be unique and canonical")
        if tuple(item.policy_key for item in self.compatibility_decisions) != candidate_ids:
            raise ValueError("compatibility decisions must exactly follow Pair policies")
        if any(
            type(item) is not PairCompatibilityDecision
            for item in self.compatibility_decisions
        ):
            raise TypeError("Pair compatibility decisions must be typed")
        if tuple(item.candidate_id for item in self.coverage_summaries) != candidate_ids or any(
            type(item) is not CandidateCoverageSummary
            or item.candidate_kind is not CandidateKind.PAIR
            for item in self.coverage_summaries
        ):
            raise ValueError("Pair coverage summaries must exactly follow the universe")
        if tuple(item.policy_key for item in self.model_bound_records) != candidate_ids:
            raise ValueError("model-bound records must exactly follow Pair policies")
        if any(
            type(item) is not ModelBoundCandidateRecord
            for item in self.model_bound_records
        ):
            raise TypeError("Pair model-bound records must be typed")
        if tuple(candidate_id for candidate_id, _ in self.candidate_family_ids) != candidate_ids:
            raise ValueError("Pair family bindings must exactly follow Pair policies")
        if any(not isinstance(value, str) or not value.strip() for _, value in self.candidate_family_ids):
            raise ValueError("Pair family bindings must be non-empty")
        for value in (
            self.discovery_data_sha256,
            self.discovery_population_sha256,
            self.compatibility_evidence_sha256,
            self.information_budget_sha256,
        ):
            _require_digest(value)
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("Pair top_k must be positive")

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.policy_key for item in self.policy_keys)

    @property
    def compatible_policy_keys(self) -> tuple[str, ...]:
        return tuple(
            item.policy_key
            for item in self.compatibility_decisions
            if item.decision is FactorialCompatibility.COMPATIBLE
        )

    @property
    def universe_id(self) -> str:
        return content_id("pair_candidate_universe_", self)


@dataclass(frozen=True, slots=True)
class PairShadowObservation:
    """Natural Pair row with no relation field in its identity or RD table."""

    policy_key: str
    task_unit_id: str
    model_id: str
    source_lineage_id: str
    language: str
    task_archetype: str
    api_family: str
    context_query_id: str
    context_state: QueryState
    factor_states: tuple[tuple[str, QueryState], tuple[str, QueryState]]
    factor_reliabilities: tuple[tuple[str, float], tuple[str, float]]
    covariates: tuple[tuple[str, float], ...]
    outcome: int

    def __post_init__(self) -> None:
        _validate_pair_preoutcome_fields(self)
        if type(self.outcome) is not int or self.outcome not in {0, 1}:
            raise ValueError("Pair discovery outcome must be binary")

    @property
    def observation_id(self) -> str:
        return content_id("pair_shadow_observation_", self)


@dataclass(frozen=True, slots=True)
class PairPreOutcomeObservation:
    """Pair support/fold input whose schema cannot carry an outcome."""

    policy_key: str
    task_unit_id: str
    model_id: str
    source_lineage_id: str
    language: str
    task_archetype: str
    api_family: str
    context_query_id: str
    context_state: QueryState
    factor_states: tuple[tuple[str, QueryState], tuple[str, QueryState]]
    factor_reliabilities: tuple[tuple[str, float], tuple[str, float]]
    covariates: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        _validate_pair_preoutcome_fields(self)

    @property
    def preoutcome_observation_id(self) -> str:
        return content_id("pair_preoutcome_observation_", self)


def _validate_pair_preoutcome_fields(item: object) -> None:
    for name in (
        "policy_key",
        "task_unit_id",
        "model_id",
        "source_lineage_id",
        "language",
        "task_archetype",
        "api_family",
        "context_query_id",
    ):
        require_text(getattr(item, name), name)
    if type(item.context_state) is not QueryState:
        raise TypeError("Pair context_state must be typed")
    if len(item.factor_states) != 2 or any(
        not isinstance(feature, str)
        or not feature
        or type(state) is not QueryState
        for feature, state in item.factor_states
    ):
        raise ValueError("Pair observation requires two factor states")
    if tuple(feature for feature, _ in item.factor_reliabilities) != tuple(
        feature for feature, _ in item.factor_states
    ) or any(
        type(value) not in {int, float}
        or not math.isfinite(float(value))
        or not 0 <= value <= 1
        for _, value in item.factor_reliabilities
    ):
        raise ValueError("Pair reliability must bind both factors on [0, 1]")
    names = tuple(name for name, _ in item.covariates)
    if names != tuple(sorted(set(names))) or any(
        type(value) not in {int, float} or not math.isfinite(float(value))
        for _, value in item.covariates
    ):
        raise ValueError("Pair covariates must be finite and canonical")


@dataclass(frozen=True, slots=True)
class PairShadowPlan:
    model_id: str
    covariate_names: tuple[str, ...]
    minimum_cell_task_units: int
    minimum_shared_lineages: int
    minimum_feature_reliability: float
    cross_fit_folds: int
    fold_seed: int
    ridge_lambda: float
    bootstrap_draws: int
    bootstrap_seed: int
    minimum_resolved_relation_task_units: int
    minimum_relation_present_task_units: int
    minimum_relation_present_fraction: float
    maximum_relation_unresolved_fraction: float

    def __post_init__(self) -> None:
        require_text(self.model_id, "Pair shadow model_id")
        if self.covariate_names != tuple(sorted(set(self.covariate_names))):
            raise ValueError("Pair shadow covariates must be canonical")
        for value, name in (
            (self.minimum_cell_task_units, "minimum_cell_task_units"),
            (self.minimum_shared_lineages, "minimum_shared_lineages"),
            (self.cross_fit_folds, "cross_fit_folds"),
            (self.bootstrap_draws, "bootstrap_draws"),
            (
                self.minimum_resolved_relation_task_units,
                "minimum_resolved_relation_task_units",
            ),
            (
                self.minimum_relation_present_task_units,
                "minimum_relation_present_task_units",
            ),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"Pair {name} must be positive")
        if self.cross_fit_folds < 2 or self.minimum_cell_task_units < self.cross_fit_folds:
            raise ValueError("Pair cell support must cover at least two frozen folds")
        if type(self.fold_seed) is not int or type(self.bootstrap_seed) is not int:
            raise TypeError("Pair fold and bootstrap seeds must be integers")
        if self.bootstrap_draws < 10:
            raise ValueError("Pair bootstrap_draws must be at least ten")
        if (
            type(self.ridge_lambda) not in {int, float}
            or not math.isfinite(float(self.ridge_lambda))
            or self.ridge_lambda <= 0
        ):
            raise ValueError("Pair ridge_lambda must be finite and positive")
        for value, name in (
            (self.minimum_feature_reliability, "minimum_feature_reliability"),
            (
                self.minimum_relation_present_fraction,
                "minimum_relation_present_fraction",
            ),
            (
                self.maximum_relation_unresolved_fraction,
                "maximum_relation_unresolved_fraction",
            ),
        ):
            if type(value) not in {int, float} or not 0 <= value <= 1:
                raise ValueError(f"Pair {name} must be on [0, 1]")

    @property
    def plan_id(self) -> str:
        return content_id("pair_shadow_plan_", self)


@dataclass(frozen=True, slots=True)
class PairFoldAssignment:
    task_unit_id: str
    cell: str
    fold: int

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "Pair fold task_unit_id")
        if self.cell not in {"00", "01", "10", "11"}:
            raise ValueError("Pair fold cell must be one of four target-relative cells")
        if type(self.fold) is not int or self.fold < 0:
            raise ValueError("Pair fold must be nonnegative")


@dataclass(frozen=True, slots=True)
class PairCandidateFoldManifest:
    policy_key: str
    fold_count: int
    assignments: tuple[PairFoldAssignment, ...]

    def __post_init__(self) -> None:
        require_text(self.policy_key, "Pair fold policy_key")
        if type(self.fold_count) is not int or self.fold_count < 2:
            raise ValueError("Pair fold_count must be at least two")
        if not self.assignments or tuple(
            sorted(self.assignments, key=lambda item: item.task_unit_id)
        ) != self.assignments:
            raise ValueError("Pair fold assignments must use canonical task order")
        if len({item.task_unit_id for item in self.assignments}) != len(self.assignments):
            raise ValueError("Pair fold task units must be unique")
        for fold in range(self.fold_count):
            if {item.cell for item in self.assignments if item.fold == fold} != {
                "00",
                "01",
                "10",
                "11",
            }:
                raise ValueError("every Pair test fold must contain all four cells")

    @property
    def fold_manifest_id(self) -> str:
        return content_id("pair_candidate_fold_manifest_", self)


@dataclass(frozen=True, slots=True)
class PairPreOutcomeFreeze:
    """Support decisions and folds sealed before Pair discovery scoring."""

    universe_id: str
    plan_id: str
    preoutcome_data_sha256: str
    discovery_population_sha256: str
    support_gates: tuple[PairSupportGate, ...]
    fold_manifests: tuple[PairCandidateFoldManifest, ...]
    failures: tuple[SelectorFailure, ...]
    discoverability: tuple[DiscoverabilityDecision, ...]
    eligibility_inputs: tuple[str, ...] = (
        "FACTORIAL_COMPATIBILITY",
        "NATURAL_FOUR_CELL_SUPPORT",
        "PAIR_CONTEXT",
        "PAIR_FOLDS",
        "SOURCE_LINEAGE_OVERLAP",
    )
    atomic_evidence_read: bool = False

    def __post_init__(self) -> None:
        for value, name in (
            (self.universe_id, "Pair pre-outcome universe_id"),
            (self.plan_id, "Pair pre-outcome plan_id"),
        ):
            require_text(value, name)
        _require_digest(
            self.preoutcome_data_sha256,
            "Pair pre-outcome data",
        )
        _require_digest(
            self.discovery_population_sha256,
            "Pair pre-outcome Discovery population",
        )
        if tuple(sorted(self.support_gates, key=lambda item: item.pair_id)) != (
            self.support_gates
        ):
            raise ValueError("Pair support gates must use canonical policy order")
        if tuple(
            sorted(self.fold_manifests, key=lambda item: item.policy_key)
        ) != self.fold_manifests:
            raise ValueError("Pair frozen folds must use canonical policy order")
        if tuple(
            sorted(
                self.failures,
                key=lambda item: (item.candidate_id or "", item.reason_code),
            )
        ) != self.failures:
            raise ValueError("Pair pre-outcome failures must use canonical order")
        support_ids = tuple(item.pair_id for item in self.support_gates)
        fold_ids = tuple(item.policy_key for item in self.fold_manifests)
        failure_ids = tuple(item.candidate_id for item in self.failures)
        if (
            len(set(support_ids)) != len(support_ids)
            or len(set(fold_ids)) != len(fold_ids)
            or any(candidate_id is None for candidate_id in failure_ids)
            or len(set(failure_ids)) != len(failure_ids)
            or set(fold_ids) & set(failure_ids)
        ):
            raise ValueError("Pair pre-outcome freeze has duplicate candidate accounting")
        passed = {item.pair_id for item in self.support_gates if item.passed}
        if set(fold_ids) | set(failure_ids) != passed:
            raise ValueError("Pair passing support must have one fold or fold failure")
        if any(
            item.reason_code != "pair_fold_non_evaluable"
            for item in self.failures
        ):
            raise ValueError("Pair pre-outcome freeze contains a non-fold failure")
        decision_ids = tuple(item.candidate_id for item in self.discoverability)
        if decision_ids != tuple(sorted(set(decision_ids))) or any(
            type(item) is not DiscoverabilityDecision
            or item.candidate_kind is not CandidateKind.PAIR
            or item.discovery_population_sha256 != self.discovery_population_sha256
            or item.universe_id != self.universe_id
            for item in self.discoverability
        ):
            raise ValueError("Pair discoverability decisions are not canonical or bound")
        discoverable = {
            item.candidate_id
            for item in self.discoverability
            if item.status is DiscoverabilityStatus.DISCOVERY_ELIGIBLE
        }
        if discoverable != set(fold_ids):
            raise ValueError("Pair discoverability must exactly match frozen fold support")
        if self.eligibility_inputs != (
            "FACTORIAL_COMPATIBILITY",
            "NATURAL_FOUR_CELL_SUPPORT",
            "PAIR_CONTEXT",
            "PAIR_FOLDS",
            "SOURCE_LINEAGE_OVERLAP",
        ) or self.atomic_evidence_read is not False:
            raise ValueError("Pair eligibility cannot read Atomic evidence (no heredity)")

    @property
    def preoutcome_freeze_id(self) -> str:
        return content_id("pair_preoutcome_freeze_", self)


@dataclass(frozen=True, slots=True)
class PairRDScore:
    policy_key: str
    signed_risk_difference_interaction: float
    absolute_risk_difference_interaction: float
    logit_interaction_coefficient: float
    sign_stability: float
    median_bootstrap_absolute_risk_difference: float
    baseline_task_units: int
    fold_manifest_id: str

    def __post_init__(self) -> None:
        require_text(self.policy_key, "Pair RD policy_key")
        require_text(self.fold_manifest_id, "Pair RD fold_manifest_id")
        for value in (
            self.signed_risk_difference_interaction,
            self.absolute_risk_difference_interaction,
            self.logit_interaction_coefficient,
            self.sign_stability,
            self.median_bootstrap_absolute_risk_difference,
        ):
            if type(value) not in {int, float} or not math.isfinite(float(value)):
                raise ValueError("Pair RD diagnostics must be finite")
        if self.absolute_risk_difference_interaction != abs(
            self.signed_risk_difference_interaction
        ):
            raise ValueError("Pair absolute RD interaction is inconsistent")
        if not 0 <= self.sign_stability <= 1:
            raise ValueError("Pair sign stability must be on [0, 1]")
        if type(self.baseline_task_units) is not int or self.baseline_task_units <= 0:
            raise ValueError("Pair RD requires baseline task units")


@dataclass(frozen=True, slots=True)
class PairRelationGate:
    policy_key: str
    status: PairRelationGateStatus
    reasons: tuple[str, ...]
    total_task_units: int
    resolved_task_units: int
    present_task_units: int
    unresolved_fraction: float
    present_fraction_among_resolved: float | None

    def __post_init__(self) -> None:
        require_text(self.policy_key, "Pair relation gate policy_key")
        if type(self.status) is not PairRelationGateStatus:
            raise TypeError("Pair relation gate status must be typed")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("Pair relation gate reasons must be canonical")
        if self.status is PairRelationGateStatus.PASSED and self.reasons:
            raise ValueError("a passing Pair relation gate cannot have failure reasons")
        if self.status is not PairRelationGateStatus.PASSED and not self.reasons:
            raise ValueError("a non-passing Pair relation gate requires reasons")
        if not (
            type(self.total_task_units) is int
            and type(self.resolved_task_units) is int
            and type(self.present_task_units) is int
            and self.total_task_units >= 0
            and 0 <= self.present_task_units <= self.resolved_task_units <= self.total_task_units
        ):
            raise ValueError("Pair relation task accounting is invalid")
        if self.total_task_units == 0:
            if (
                self.status is not PairRelationGateStatus.NON_EVALUABLE
                or self.resolved_task_units != 0
                or self.present_task_units != 0
                or self.unresolved_fraction != 1.0
                or self.present_fraction_among_resolved is not None
            ):
                raise ValueError("an empty Pair relation population must be non-evaluable")
            return
        if self.unresolved_fraction != 1 - self.resolved_task_units / self.total_task_units:
            raise ValueError("Pair unresolved fraction is inconsistent")
        expected = (
            self.present_task_units / self.resolved_task_units
            if self.resolved_task_units
            else None
        )
        if self.present_fraction_among_resolved != expected:
            raise ValueError("Pair present relation fraction is inconsistent")


@dataclass(frozen=True, slots=True)
class PairShadowVariantResult:
    variant: PairSelectorVariant
    universe_id: str
    plan_id: str
    support_gates_sha256: str
    fold_manifests_sha256: str
    rd_scores_sha256: str
    relation_gate_evidence_sha256: str | None
    ranking: tuple[RankedCandidate, ...]
    slots: tuple[SelectorSlot, ...]

    def __post_init__(self) -> None:
        if type(self.variant) is not PairSelectorVariant:
            raise TypeError("Pair selector variant must be typed")
        require_text(self.universe_id, "Pair result universe_id")
        require_text(self.plan_id, "Pair result plan_id")
        for value in (
            self.support_gates_sha256,
            self.fold_manifests_sha256,
            self.rd_scores_sha256,
        ):
            _require_digest(value)
        if self.variant is PairSelectorVariant.FULL:
            _require_digest(self.relation_gate_evidence_sha256)
        elif self.relation_gate_evidence_sha256 is not None:
            raise ValueError("Pair No-Relation cannot read relation gate evidence")
        if tuple(item.rank for item in self.ranking) != tuple(range(1, len(self.ranking) + 1)):
            raise ValueError("Pair ranking must have complete ranks")
        if tuple(item.rank for item in self.slots) != tuple(range(1, len(self.slots) + 1)):
            raise ValueError("Pair slots must be complete")
        filled = tuple(
            item.candidate_id for item in self.slots if item.status is SlotStatus.FILLED
        )
        expected = tuple(item.candidate_id for item in self.ranking[: len(filled)])
        if filled != expected:
            raise ValueError("Pair filled slots must follow the frozen ranking")

    @property
    def result_id(self) -> str:
        return content_id("pair_shadow_variant_result_", self)


@dataclass(frozen=True, slots=True)
class PairSoleDifferenceAudit:
    universe_id: str
    plan_id: str
    discovery_data_sha256: str
    support_gates_sha256: str
    fold_manifests_sha256: str
    rd_scores_sha256: str
    tie_break_rule: str
    top_k: int
    full_additional_read: str = "relation_gate"
    no_relation_additional_reads: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_text(self.universe_id, "Pair audit universe_id")
        require_text(self.plan_id, "Pair audit plan_id")
        require_text(self.tie_break_rule, "Pair audit tie_break_rule")
        for value in (
            self.discovery_data_sha256,
            self.support_gates_sha256,
            self.fold_manifests_sha256,
            self.rd_scores_sha256,
        ):
            _require_digest(value)
        if self.full_additional_read != "relation_gate" or self.no_relation_additional_reads:
            raise ValueError("only Pair Full may add the relation Gate read")
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("Pair audit top_k must be positive")


@dataclass(frozen=True, slots=True)
class PairShadowQualificationResult:
    universe: PairCandidateUniverseManifest
    plan: PairShadowPlan
    support_gates: tuple[PairSupportGate, ...]
    fold_manifests: tuple[PairCandidateFoldManifest, ...]
    rd_scores: tuple[PairRDScore, ...]
    relation_gates: tuple[PairRelationGate, ...]
    failures: tuple[SelectorFailure, ...]
    full: PairShadowVariantResult
    no_relation: PairShadowVariantResult
    sole_difference: PairSoleDifferenceAudit

    def __post_init__(self) -> None:
        universe_id = self.universe.universe_id
        plan_id = self.plan.plan_id
        if self.full.variant is not PairSelectorVariant.FULL:
            raise ValueError("Pair Full result is missing")
        if self.no_relation.variant is not PairSelectorVariant.NO_RELATION:
            raise ValueError("Pair No-Relation result is missing")
        if any(
            result.universe_id != universe_id or result.plan_id != plan_id
            for result in (self.full, self.no_relation)
        ):
            raise ValueError("Pair variant results drift from the frozen universe or plan")
        if (
            self.sole_difference.universe_id != universe_id
            or self.sole_difference.plan_id != plan_id
        ):
            raise ValueError("Pair sole-difference audit drifts from the frozen coordinates")
        for name in (
            "support_gates_sha256",
            "fold_manifests_sha256",
            "rd_scores_sha256",
        ):
            if getattr(self.full, name) != getattr(self.no_relation, name):
                raise ValueError("Pair Core variants drift on a shared coordinate")

    @property
    def qualification_result_id(self) -> str:
        return content_id("pair_shadow_qualification_result_", self)


def freeze_pair_candidate_universe(
    policy_keys: Sequence[PairPolicyKey],
    compatibility_decisions: Sequence[PairCompatibilityDecision],
    model_bound_records: Sequence[ModelBoundCandidateRecord],
    *,
    coverage_summaries: Mapping[str, CandidateCoverageSummary],
    candidate_family_ids: Mapping[str, str],
    discovery_data_sha256: str,
    discovery_population_sha256: str,
    information_budget_sha256: str,
    top_k: int,
) -> PairCandidateUniverseManifest:
    """Freeze compatibility before any Prompt-TSG relation Gate is read."""

    ordered = tuple(sorted(policy_keys, key=lambda item: item.policy_key))
    candidate_ids = tuple(item.policy_key for item in ordered)
    decisions = {item.policy_key: item for item in compatibility_decisions}
    records = {item.policy_key: item for item in model_bound_records}
    if len(decisions) != len(tuple(compatibility_decisions)) or set(decisions) != set(
        candidate_ids
    ):
        raise ValueError("compatibility decisions must bind every Pair policy once")
    if len(records) != len(tuple(model_bound_records)) or set(records) != set(candidate_ids):
        raise ValueError("model-bound records must bind every Pair policy once")
    if set(candidate_family_ids) != set(candidate_ids):
        raise ValueError("Pair family bindings must bind every policy once")
    if set(coverage_summaries) != set(candidate_ids):
        raise ValueError("Pair coverage summaries must bind every policy once")
    frozen_decisions = tuple(decisions[candidate_id] for candidate_id in candidate_ids)
    return PairCandidateUniverseManifest(
        ordered,
        frozen_decisions,
        tuple(coverage_summaries[candidate_id] for candidate_id in candidate_ids),
        tuple(records[candidate_id] for candidate_id in candidate_ids),
        tuple((candidate_id, candidate_family_ids[candidate_id]) for candidate_id in candidate_ids),
        discovery_data_sha256,
        discovery_population_sha256,
        content_hash(frozen_decisions),
        information_budget_sha256,
        top_k,
    )


def pair_shadow_data_sha256(observations: Sequence[PairShadowObservation]) -> str:
    """Hash the common Pair RD table without relation evidence."""

    return content_hash(tuple(sorted(observations, key=lambda item: item.observation_id)))


@dataclass(frozen=True, slots=True)
class _PairPolicyAdapter:
    pair_id: str
    factors: tuple[str, str]
    operations: tuple[Operation, Operation]


def run_pair_shadow_qualification(
    universe: PairCandidateUniverseManifest,
    observations: Sequence[PairShadowObservation],
    relation_evidence: Sequence[PairRelationEvidenceRecord],
    plan: PairShadowPlan,
    *,
    preoutcome_freeze: PairPreOutcomeFreeze,
) -> PairShadowQualificationResult:
    """Run Pair Full/No-Relation from one compatibility-first RD table."""

    if type(universe) is not PairCandidateUniverseManifest:
        raise TypeError("universe must be a PairCandidateUniverseManifest")
    if type(plan) is not PairShadowPlan:
        raise TypeError("plan must be a PairShadowPlan")
    if not universe.compatible_policy_keys:
        raise ValueError("Pair shadow qualification has no compatible policy")
    if pair_shadow_data_sha256(observations) != universe.discovery_data_sha256:
        raise ValueError("Pair observations drift from the compatibility-first universe")
    compatible = set(universe.compatible_policy_keys)
    if any(row.policy_key not in compatible for row in observations):
        raise ValueError("Pair RD row falls outside the compatible common universe")
    if any(item.pair_id not in compatible for item in relation_evidence):
        raise ValueError("Pair relation evidence falls outside the compatible common universe")

    policy_by_id = {item.policy_key: item for item in universe.policy_keys}
    rows_by_policy = {candidate_id: [] for candidate_id in universe.compatible_policy_keys}
    for row in observations:
        rows_by_policy[row.policy_key].append(row)
    if type(preoutcome_freeze) is not PairPreOutcomeFreeze:
        raise TypeError("Pair prioritization requires an explicit pre-outcome freeze")
    if preoutcome_freeze != freeze_pair_preoutcome_design(
        universe,
        pair_preoutcome_observations(observations),
        plan,
    ):
        raise ValueError("Pair pre-outcome freeze failed outcome-blind replay")
    frozen_fold_by_id = {
        item.policy_key: item for item in preoutcome_freeze.fold_manifests
    }
    rd_scores = []
    failures = list(preoutcome_freeze.failures)
    for candidate_id in universe.compatible_policy_keys:
        policy = policy_by_id[candidate_id]
        candidate = _PairPolicyAdapter(
            candidate_id,
            tuple(item.actionable_feature_id for item in policy.factors),
            tuple(item.operation for item in policy.factors),
        )
        rows = tuple(rows_by_policy[candidate_id])
        gate = next(
            item
            for item in preoutcome_freeze.support_gates
            if item.pair_id == candidate_id
        )
        if not gate.passed:
            continue
        folds = frozen_fold_by_id.get(candidate_id)
        if folds is None:
            continue
        try:
            score = _pair_cross_fitted_rd(candidate, rows, folds, plan)
        except ValueError as exc:
            failures.append(
                SelectorFailure("pair_rd_non_evaluable", str(exc), candidate_id)
            )
            continue
        rd_scores.append(score)

    frozen_support = preoutcome_freeze.support_gates
    frozen_folds = preoutcome_freeze.fold_manifests
    frozen_scores = tuple(sorted(rd_scores, key=lambda item: item.policy_key))
    frozen_failures = tuple(
        sorted(failures, key=lambda item: (item.candidate_id or "", item.reason_code))
    )
    relation_gates = _pair_relation_gates(
        universe.compatible_policy_keys,
        rows_by_policy,
        relation_evidence,
        plan,
    )
    support_sha256 = content_hash(frozen_support)
    fold_sha256 = content_hash(frozen_folds)
    rd_sha256 = content_hash(frozen_scores)
    relation_sha256 = content_hash(
        {
            "evidence": tuple(sorted(relation_evidence, key=lambda item: item.evidence_id)),
            "gates": relation_gates,
            "minimum_resolved_task_units": plan.minimum_resolved_relation_task_units,
            "minimum_present_task_units": plan.minimum_relation_present_task_units,
            "minimum_present_fraction": plan.minimum_relation_present_fraction,
            "maximum_unresolved_fraction": plan.maximum_relation_unresolved_fraction,
        }
    )
    full = _pair_variant_result(
        PairSelectorVariant.FULL,
        universe,
        plan,
        frozen_scores,
        frozen_failures,
        frozen_support,
        support_sha256,
        fold_sha256,
        rd_sha256,
        relation_gates,
        relation_sha256,
    )
    no_relation = _pair_variant_result(
        PairSelectorVariant.NO_RELATION,
        universe,
        plan,
        frozen_scores,
        frozen_failures,
        frozen_support,
        support_sha256,
        fold_sha256,
        rd_sha256,
        (),
        None,
    )
    sole_difference = PairSoleDifferenceAudit(
        universe.universe_id,
        plan.plan_id,
        universe.discovery_data_sha256,
        support_sha256,
        fold_sha256,
        rd_sha256,
        "descending_absolute_second_order_rd_then_policy_key_v1",
        universe.top_k,
    )
    return PairShadowQualificationResult(
        universe,
        plan,
        frozen_support,
        frozen_folds,
        frozen_scores,
        relation_gates,
        frozen_failures,
        full,
        no_relation,
        sole_difference,
    )


def freeze_pair_preoutcome_design(
    universe: PairCandidateUniverseManifest,
    observations: Sequence[PairPreOutcomeObservation],
    plan: PairShadowPlan,
) -> PairPreOutcomeFreeze:
    """Seal Pair support and four-cell folds from an outcome-free schema."""

    if type(universe) is not PairCandidateUniverseManifest:
        raise TypeError("universe must be a PairCandidateUniverseManifest")
    if type(plan) is not PairShadowPlan:
        raise TypeError("plan must be a PairShadowPlan")
    if any(type(item) is not PairPreOutcomeObservation for item in observations):
        raise TypeError("Pair pre-outcome freeze requires outcome-free observations")
    compatible = set(universe.compatible_policy_keys)
    if any(row.policy_key not in compatible for row in observations):
        raise ValueError("Pair fold row falls outside the compatible common universe")
    policy_by_id = {item.policy_key: item for item in universe.policy_keys}
    rows_by_policy = {candidate_id: [] for candidate_id in universe.compatible_policy_keys}
    for row in observations:
        rows_by_policy[row.policy_key].append(row)
    gates = []
    folds = []
    failures = []
    for candidate_id in universe.compatible_policy_keys:
        policy = policy_by_id[candidate_id]
        candidate = _PairPolicyAdapter(
            candidate_id,
            tuple(item.actionable_feature_id for item in policy.factors),
            tuple(item.operation for item in policy.factors),
        )
        rows = tuple(rows_by_policy[candidate_id])
        gate = _pair_shared_support_gate(policy, candidate, rows, plan)
        gates.append(gate)
        if not gate.passed:
            continue
        try:
            fold_manifest = _pair_candidate_fold_manifest(candidate, rows, plan)
        except ValueError as exc:
            failures.append(
                SelectorFailure("pair_fold_non_evaluable", str(exc), candidate_id)
            )
            continue
        folds.append(fold_manifest)
    frozen_gates = tuple(sorted(gates, key=lambda item: item.pair_id))
    frozen_folds = tuple(sorted(folds, key=lambda item: item.policy_key))
    frozen_failures = tuple(
        sorted(
            failures,
            key=lambda item: (item.candidate_id or "", item.reason_code),
        )
    )
    compatibility_by_id = {
        item.policy_key: item for item in universe.compatibility_decisions
    }
    gate_by_id = {item.pair_id: item for item in frozen_gates}
    fold_by_id = {item.policy_key: item for item in frozen_folds}
    failure_by_id = {item.candidate_id: item for item in frozen_failures}
    coverage_by_id = {
        item.candidate_id: item for item in universe.coverage_summaries
    }
    decisions = []
    for candidate_id in universe.candidate_ids:
        compatibility = compatibility_by_id[candidate_id]
        gate = gate_by_id.get(candidate_id)
        coverage = coverage_by_id[candidate_id]
        if gate is not None and coverage.state_or_cell_task_units != gate.cell_task_units:
            raise ValueError("Pair coverage summary drifted from the four-cell support Gate")
        reasons = []
        if compatibility.decision is not FactorialCompatibility.COMPATIBLE:
            reasons.append(DiscoverabilityReason.FACTORIAL_INCOMPATIBLE)
        elif gate is None:
            reasons.append(DiscoverabilityReason.MISSING_OBSERVATIONS)
        else:
            reasons.extend(_pair_discoverability_reason(item) for item in gate.reasons)
        if candidate_id in failure_by_id:
            reasons.append(DiscoverabilityReason.FOLD_NON_EVALUABLE)
        support_evidence = gate if gate is not None else compatibility
        fold_evidence = fold_by_id.get(candidate_id) or failure_by_id.get(candidate_id) or {
            "candidate_id": candidate_id,
            "fold_status": "NOT_ATTEMPTED_SUPPORT_FAILED",
        }
        decisions.append(
            DiscoverabilityDecision(
                candidate_id,
                CandidateKind.PAIR,
                universe.discovery_population_sha256,
                universe.universe_id,
                content_hash(support_evidence),
                content_hash(fold_evidence),
                coverage,
                (
                    DiscoverabilityStatus.DISCOVERY_ELIGIBLE
                    if not reasons
                    else DiscoverabilityStatus.DISCOVERY_INELIGIBLE
                ),
                tuple(sorted(set(reasons), key=lambda item: item.value)),
            )
        )
    return PairPreOutcomeFreeze(
        universe.universe_id,
        plan.plan_id,
        pair_preoutcome_data_sha256(observations),
        universe.discovery_population_sha256,
        frozen_gates,
        frozen_folds,
        frozen_failures,
        tuple(decisions),
    )


def pair_preoutcome_observations(
    observations: Sequence[PairShadowObservation],
) -> tuple[PairPreOutcomeObservation, ...]:
    """Project Pair discovery records before their outcome field is opened."""

    if not observations or any(
        type(item) is not PairShadowObservation for item in observations
    ):
        raise TypeError("Pair pre-outcome projection requires discovery observations")
    return tuple(
        sorted(
            (
                PairPreOutcomeObservation(
                    item.policy_key,
                    item.task_unit_id,
                    item.model_id,
                    item.source_lineage_id,
                    item.language,
                    item.task_archetype,
                    item.api_family,
                    item.context_query_id,
                    item.context_state,
                    item.factor_states,
                    item.factor_reliabilities,
                    item.covariates,
                )
                for item in observations
            ),
            key=lambda item: item.preoutcome_observation_id,
        )
    )


def pair_preoutcome_data_sha256(
    observations: Sequence[PairPreOutcomeObservation],
) -> str:
    """Hash Pair support/fold inputs without admitting an outcome field."""

    frozen = tuple(
        sorted(observations, key=lambda item: item.preoutcome_observation_id)
    )
    if not frozen or any(
        type(item) is not PairPreOutcomeObservation for item in frozen
    ):
        raise TypeError("Pair pre-outcome data requires typed observations")
    coordinates = {(item.policy_key, item.task_unit_id) for item in frozen}
    if len(coordinates) != len(frozen):
        raise ValueError("a Pair pre-outcome policy/task coordinate is duplicated")
    return content_hash(frozen)


def _pair_discoverability_reason(reason: str) -> DiscoverabilityReason:
    mapping = {
        "missing_observations": DiscoverabilityReason.MISSING_OBSERVATIONS,
        "duplicate_task_unit": DiscoverabilityReason.DUPLICATE_TASK_UNIT,
        "candidate_coordinate_mismatch": (
            DiscoverabilityReason.CANDIDATE_COORDINATE_MISMATCH
        ),
        "context_not_present": DiscoverabilityReason.CONTEXT_NOT_PRESENT,
        "covariate_schema_mismatch": (
            DiscoverabilityReason.COVARIATE_SCHEMA_MISMATCH
        ),
        "extractor_reliability_below_threshold": (
            DiscoverabilityReason.EXTRACTOR_RELIABILITY_BELOW_THRESHOLD
        ),
        "factor_state_not_binary": DiscoverabilityReason.FACTOR_STATE_NOT_BINARY,
        "insufficient_four_cell_support": (
            DiscoverabilityReason.INSUFFICIENT_FOUR_CELL_SUPPORT
        ),
        "source_lineage_separation": (
            DiscoverabilityReason.INSUFFICIENT_SOURCE_LINEAGE_OVERLAP
        ),
        "language_nonoverlap": DiscoverabilityReason.LANGUAGE_NONOVERLAP,
        "archetype_nonoverlap": DiscoverabilityReason.ARCHETYPE_NONOVERLAP,
        "api_family_nonoverlap": DiscoverabilityReason.API_FAMILY_NONOVERLAP,
    }
    try:
        return mapping[reason]
    except KeyError:
        raise ValueError(f"unknown Pair discoverability reason: {reason}") from None


def _pair_shared_support_gate(
    policy: PairPolicyKey,
    candidate: _PairPolicyAdapter,
    rows: tuple[PairPreOutcomeObservation, ...],
    plan: PairShadowPlan,
) -> PairSupportGate:
    reasons = set()
    if not rows:
        reasons.add("missing_observations")
    if len({row.task_unit_id for row in rows}) != len(rows):
        reasons.add("duplicate_task_unit")
    cells: dict[str, list[PairPreOutcomeObservation]] = {
        cell: [] for cell in ("00", "01", "10", "11")
    }
    for row in rows:
        if (
            row.policy_key != policy.policy_key
            or row.context_query_id != policy.analysis_scope.context_query_id
            or row.model_id != plan.model_id
            or tuple(feature for feature, _ in row.factor_states) != candidate.factors
        ):
            reasons.add("candidate_coordinate_mismatch")
        if row.context_state is not QueryState.PRESENT:
            reasons.add("context_not_present")
        if tuple(name for name, _ in row.covariates) != plan.covariate_names:
            reasons.add("covariate_schema_mismatch")
        if any(
            value < plan.minimum_feature_reliability
            for _, value in row.factor_reliabilities
        ):
            reasons.add("extractor_reliability_below_threshold")
        states = tuple(state for _, state in row.factor_states)
        if any(state not in {QueryState.ABSENT, QueryState.PRESENT} for state in states):
            reasons.add("factor_state_not_binary")
            continue
        cells[_cell_key(states, candidate.operations)].append(row)
    cell_counts = tuple((cell, len(cells[cell])) for cell in ("00", "01", "10", "11"))
    if any(count < plan.minimum_cell_task_units for _, count in cell_counts):
        reasons.add("insufficient_four_cell_support")
    shared_lineages = _shared_count(cells, lambda row: row.source_lineage_id)
    shared_languages = _shared_count(cells, lambda row: row.language)
    shared_archetypes = _shared_count(cells, lambda row: row.task_archetype)
    shared_api_families = _shared_count(cells, lambda row: row.api_family)
    if shared_lineages < plan.minimum_shared_lineages:
        reasons.add("source_lineage_separation")
    if not shared_languages:
        reasons.add("language_nonoverlap")
    if not shared_archetypes:
        reasons.add("archetype_nonoverlap")
    if not shared_api_families:
        reasons.add("api_family_nonoverlap")
    return PairSupportGate(
        policy.policy_key,
        not reasons,
        tuple(sorted(reasons)),
        cell_counts,
        shared_lineages,
        shared_languages,
        shared_archetypes,
        shared_api_families,
    )


def _pair_candidate_fold_manifest(
    candidate: _PairPolicyAdapter,
    rows: tuple[PairPreOutcomeObservation, ...],
    plan: PairShadowPlan,
) -> PairCandidateFoldManifest:
    cells: dict[str, list[PairPreOutcomeObservation]] = {
        cell: [] for cell in ("00", "01", "10", "11")
    }
    for row in rows:
        states = tuple(state for _, state in row.factor_states)
        cells[_cell_key(states, candidate.operations)].append(row)
    assignments = []
    for cell, values in cells.items():
        ordered = sorted(
            values,
            key=lambda row: (
                content_hash(
                    {
                        "domain": "pair_candidate_cell_fold_v1",
                        "seed": plan.fold_seed,
                        "policy_key": candidate.pair_id,
                        "cell": cell,
                        "task_unit_id": row.task_unit_id,
                    }
                ),
                row.task_unit_id,
            ),
        )
        if len(ordered) < plan.cross_fit_folds:
            raise ValueError("Pair candidate lacks four-cell support for every fold")
        assignments.extend(
            PairFoldAssignment(row.task_unit_id, cell, index % plan.cross_fit_folds)
            for index, row in enumerate(ordered)
        )
    return PairCandidateFoldManifest(
        candidate.pair_id,
        plan.cross_fit_folds,
        tuple(sorted(assignments, key=lambda item: item.task_unit_id)),
    )


def _pair_cross_fitted_rd(
    candidate: _PairPolicyAdapter,
    rows: tuple[PairShadowObservation, ...],
    folds: PairCandidateFoldManifest,
    plan: PairShadowPlan,
) -> PairRDScore:
    fold_by_task = {item.task_unit_id: item.fold for item in folds.assignments}
    cell_by_task = {item.task_unit_id: item.cell for item in folds.assignments}
    contributions = []
    for fold in range(folds.fold_count):
        training = tuple(row for row in rows if fold_by_task[row.task_unit_id] != fold)
        held_out = tuple(row for row in rows if fold_by_task[row.task_unit_id] == fold)
        if {cell_by_task[row.task_unit_id] for row in training} != {
            "00",
            "01",
            "10",
            "11",
        }:
            raise ValueError("Pair training fold lacks four-cell support")
        model = _fit_logit(training, candidate.operations, float(plan.ridge_lambda))
        for row in held_out:
            if cell_by_task[row.task_unit_id] != "00":
                continue
            probabilities = {
                cell: model.probability(
                    row.covariates,
                    float(cell[0]),
                    float(cell[1]),
                )
                for cell in ("00", "01", "10", "11")
            }
            contributions.append(
                probabilities["11"]
                - probabilities["10"]
                - probabilities["01"]
                + probabilities["00"]
            )
    baseline_count = sum(item.cell == "00" for item in folds.assignments)
    if not contributions or len(contributions) != baseline_count:
        raise ValueError("Pair cross-fitting did not cover every baseline task unit")
    risk_difference = sum(contributions) / len(contributions)
    coefficient = _fit_logit(rows, candidate.operations, float(plan.ridge_lambda)).weights[-1]
    rng = random.Random(
        int(
            content_hash(
                {
                    "domain": "pair_rd_bootstrap_v1",
                    "seed": plan.bootstrap_seed,
                    "policy_key": candidate.pair_id,
                    "plan_id": plan.plan_id,
                }
            )[-16:],
            16,
        )
    )
    bootstrap = []
    for _ in range(plan.bootstrap_draws):
        draw = tuple(
            contributions[rng.randrange(len(contributions))] for _ in contributions
        )
        bootstrap.append(sum(draw) / len(draw))
    direction = _sign(risk_difference)
    stability = sum(_sign(value) == direction for value in bootstrap) / len(bootstrap)
    absolute = sorted(abs(value) for value in bootstrap)
    middle = len(absolute) // 2
    median = (
        absolute[middle]
        if len(absolute) % 2
        else (absolute[middle - 1] + absolute[middle]) / 2
    )
    return PairRDScore(
        candidate.pair_id,
        risk_difference,
        abs(risk_difference),
        coefficient,
        stability,
        median,
        baseline_count,
        folds.fold_manifest_id,
    )


def _pair_relation_gates(
    candidate_ids: tuple[str, ...],
    rows_by_policy: Mapping[str, Sequence[PairShadowObservation]],
    relation_evidence: Sequence[PairRelationEvidenceRecord],
    plan: PairShadowPlan,
) -> tuple[PairRelationGate, ...]:
    evidence_by_policy: dict[str, list[PairRelationEvidenceRecord]] = {
        candidate_id: [] for candidate_id in candidate_ids
    }
    for item in relation_evidence:
        evidence_by_policy[item.pair_id].append(item)
    gates = []
    for candidate_id in candidate_ids:
        rows = tuple(rows_by_policy[candidate_id])
        task_ids = {row.task_unit_id for row in rows}
        values = evidence_by_policy[candidate_id]
        if any(item.task_unit_id not in task_ids for item in values):
            raise ValueError("Pair relation evidence references a non-RD task unit")
        by_task: dict[str, list[PairRelationEvidenceRecord]] = {}
        for item in values:
            by_task.setdefault(item.task_unit_id, []).append(item)
        reasons = set()
        if any(len(items) != 1 for items in by_task.values()):
            reasons.add("multiple_relation_matches")
        resolved = sum(
            len(items) == 1
            and items[0].state in {QueryState.PRESENT, QueryState.ABSENT}
            for items in by_task.values()
        )
        present = sum(
            len(items) == 1 and items[0].state is QueryState.PRESENT
            for items in by_task.values()
        )
        total = len(rows)
        if total == 0:
            gates.append(
                PairRelationGate(
                    candidate_id,
                    PairRelationGateStatus.NON_EVALUABLE,
                    ("missing_relation_population",),
                    0,
                    0,
                    0,
                    1.0,
                    None,
                )
            )
            continue
        unresolved_fraction = 1 - resolved / total
        present_fraction = present / resolved if resolved else None
        if resolved < plan.minimum_resolved_relation_task_units:
            reasons.add("insufficient_resolved_relation_tasks")
        if unresolved_fraction > plan.maximum_relation_unresolved_fraction:
            reasons.add("relation_unresolved_fraction_exceeded")
        non_evaluable = bool(
            reasons
            & {
                "multiple_relation_matches",
                "insufficient_resolved_relation_tasks",
                "relation_unresolved_fraction_exceeded",
            }
        )
        if non_evaluable:
            status = PairRelationGateStatus.NON_EVALUABLE
        elif (
            present < plan.minimum_relation_present_task_units
            or present_fraction is None
            or present_fraction < plan.minimum_relation_present_fraction
        ):
            reasons.add("insufficient_present_relation_support")
            status = PairRelationGateStatus.FAILED
        else:
            status = PairRelationGateStatus.PASSED
        gates.append(
            PairRelationGate(
                candidate_id,
                status,
                tuple(sorted(reasons)),
                total,
                resolved,
                present,
                unresolved_fraction,
                present_fraction,
            )
        )
    return tuple(gates)


def _pair_variant_result(
    variant: PairSelectorVariant,
    universe: PairCandidateUniverseManifest,
    plan: PairShadowPlan,
    scores: tuple[PairRDScore, ...],
    failures: tuple[SelectorFailure, ...],
    support_gates: tuple[PairSupportGate, ...],
    support_sha256: str,
    fold_sha256: str,
    rd_sha256: str,
    relation_gates: tuple[PairRelationGate, ...],
    relation_sha256: str | None,
) -> PairShadowVariantResult:
    score_by_id = {item.policy_key: item for item in scores}
    if variant is PairSelectorVariant.FULL:
        passed = {
            item.policy_key
            for item in relation_gates
            if item.status is PairRelationGateStatus.PASSED
        }
        rankable = set(score_by_id) & passed
    else:
        rankable = set(score_by_id)
    ordered = sorted(
        rankable,
        key=lambda candidate_id: (
            -score_by_id[candidate_id].absolute_risk_difference_interaction,
            candidate_id,
        ),
    )
    ranking = tuple(
        RankedCandidate(
            candidate_id,
            score_by_id[candidate_id].absolute_risk_difference_interaction,
            rank,
        )
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    relation_statuses = {item.status for item in relation_gates}
    support_failed = any(not item.passed for item in support_gates)
    slots = []
    for rank in range(1, universe.top_k + 1):
        if rank <= len(ranking):
            slots.append(
                SelectorSlot(rank, SlotStatus.FILLED, ranking[rank - 1].candidate_id, None)
            )
        elif (
            failures
            or support_failed
            or PairRelationGateStatus.NON_EVALUABLE in relation_statuses
        ):
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.NON_EVALUABLE,
                    None,
                    "pair_support_score_or_relation_non_evaluable",
                )
            )
        elif variant is PairSelectorVariant.FULL and relation_gates:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.GATE_FAILED,
                    None,
                    "relation_gate_exhausted",
                )
            )
        else:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.INSUFFICIENT_CANDIDATES,
                    None,
                    "rankable_pair_universe_smaller_than_k",
                )
            )
    return PairShadowVariantResult(
        variant,
        universe.universe_id,
        plan.plan_id,
        support_sha256,
        fold_sha256,
        rd_sha256,
        relation_sha256,
        ranking,
        tuple(slots),
    )


def _shared_count(
    cells: Mapping[
        str,
        Sequence[PairDiscoveryObservation | PairPreOutcomeObservation],
    ],
    value: Callable[[PairDiscoveryObservation | PairPreOutcomeObservation], str],
) -> int:
    sets = [{value(row) for row in cells[cell]} for cell in ("00", "01", "10", "11")]
    return len(set.intersection(*sets)) if all(sets) else 0


@dataclass(frozen=True, slots=True)
class _RidgeLogitModel:
    covariate_names: tuple[str, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    weights: tuple[float, ...]

    def probability(
        self,
        covariates: tuple[tuple[str, float], ...],
        factor_1: float,
        factor_2: float,
    ) -> float:
        values = dict(covariates)
        normalized = [
            (float(values[name]) - self.means[index]) / self.scales[index]
            for index, name in enumerate(self.covariate_names)
        ]
        design = (1.0, *normalized, factor_1, factor_2, factor_1 * factor_2)
        return _sigmoid(sum(left * right for left, right in zip(self.weights, design, strict=True)))


def _fit_logit(
    rows: tuple[PairDiscoveryObservation, ...],
    operations: tuple[Operation, Operation],
    ridge_lambda: float,
) -> _RidgeLogitModel:
    if not rows:
        raise ValueError("interaction model requires discovery rows")
    covariate_names = tuple(name for name, _ in rows[0].covariates)
    raw_covariates = [
        [float(dict(row.covariates)[name]) for name in covariate_names]
        for row in rows
    ]
    means = [
        sum(values[column] for values in raw_covariates) / len(raw_covariates)
        for column in range(len(covariate_names))
    ]
    scales = [
        math.sqrt(
            sum((values[column] - means[column]) ** 2 for values in raw_covariates)
            / len(raw_covariates)
        )
        or 1.0
        for column in range(len(covariate_names))
    ]
    design = []
    for row, covariates in zip(rows, raw_covariates, strict=True):
        x1, x2 = tuple(
            float(_target_state(state, operation))
            for (_, state), operation in zip(row.factor_states, operations, strict=True)
        )
        normalized = [
            (covariates[index] - means[index]) / scales[index]
            for index in range(len(covariates))
        ]
        design.append([1.0, *normalized, x1, x2, x1 * x2])
    weights = [0.0] * len(design[0])
    max_norm = max(sum(value * value for value in row) for row in design)
    step = 1.0 / (0.25 * max_norm + ridge_lambda + 1.0)
    for _ in range(800):
        gradient = [0.0] * len(weights)
        for values, row in zip(design, rows, strict=True):
            probability = _sigmoid(
                sum(weight * value for weight, value in zip(weights, values, strict=True))
            )
            for index, value in enumerate(values):
                gradient[index] += (probability - row.outcome) * value / len(rows)
        for index in range(1, len(weights)):
            gradient[index] += ridge_lambda * weights[index]
        updated = [
            weight - step * derivative
            for weight, derivative in zip(weights, gradient, strict=True)
        ]
        if max(abs(left - right) for left, right in zip(updated, weights, strict=True)) < 1e-10:
            weights = updated
            break
        weights = updated
    return _RidgeLogitModel(
        covariate_names,
        tuple(means),
        tuple(scales),
        tuple(weights),
    )


def _cell_key(
    states: tuple[QueryState, QueryState], operations: tuple[Operation, Operation]
) -> str:
    return "".join(
        str(_target_state(state, operation))
        for state, operation in zip(states, operations, strict=True)
    )


def _target_state(state: QueryState, operation: Operation) -> int:
    if state not in {QueryState.ABSENT, QueryState.PRESENT}:
        raise ValueError("interaction factor state is not binary")
    target = QueryState.PRESENT if operation is Operation.ADD else QueryState.ABSENT
    return int(state is target)


def _sign(value: float) -> int:
    if value > 1e-12:
        return 1
    if value < -1e-12:
        return -1
    return 0


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-min(value, 700.0)))
    exponential = math.exp(max(value, -700.0))
    return exponential / (1.0 + exponential)


__all__ = [
    "PairCandidateFoldManifest",
    "PairCandidateUniverseManifest",
    "PairDiscoveryObservation",
    "PairFoldAssignment",
    "PairPreOutcomeFreeze",
    "PairPreOutcomeObservation",
    "PairRDScore",
    "PairRelationGate",
    "PairRelationGateStatus",
    "PairSelectorVariant",
    "PairShadowObservation",
    "PairShadowPlan",
    "PairShadowQualificationResult",
    "PairShadowVariantResult",
    "PairSoleDifferenceAudit",
    "PairSupportGate",
    "freeze_pair_candidate_universe",
    "freeze_pair_preoutcome_design",
    "pair_preoutcome_data_sha256",
    "pair_preoutcome_observations",
    "pair_shadow_data_sha256",
    "run_pair_shadow_qualification",
]

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
    InteractionScale,
    MechanismRelationSpec,
    PairCompatibilityDecision,
    PairRelationEvidence,
    PairStructuralRelationEvidence,
    PairSpec,
    pair_matches_relation_spec,
)
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.prioritization import RankedCandidate, SelectorFailure, SelectorSlot, SlotStatus
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.representation import (
    ModelBoundCandidateRecord,
    Operation,
    PairPolicyKey,
)


PairRelationEvidenceRecord = PairRelationEvidence | PairStructuralRelationEvidence


class InteractionLane(StrEnum):
    GRAPH_SUPPORTED = "graph_supported"
    PURE_INTERACTION = "pure_interaction"


@dataclass(frozen=True, slots=True)
class InteractionPairCandidate:
    pair_id: str
    relation_spec_id: str
    context_query_id: str
    factor_1_id: str
    factor_2_id: str
    operation_1: Operation
    operation_2: Operation

    def __post_init__(self) -> None:
        for name in (
            "pair_id",
            "relation_spec_id",
            "context_query_id",
            "factor_1_id",
            "factor_2_id",
        ):
            require_text(getattr(self, name), name)
        if self.factor_1_id == self.factor_2_id:
            raise ValueError("interaction candidate factors must be distinct")
        if type(self.operation_1) is not Operation or type(self.operation_2) is not Operation:
            raise TypeError("interaction candidate operations must be typed")

    @property
    def factors(self) -> tuple[str, str]:
        return self.factor_1_id, self.factor_2_id

    @property
    def operations(self) -> tuple[Operation, Operation]:
        return self.operation_1, self.operation_2


@dataclass(frozen=True, slots=True)
class InteractionPairUniverse:
    candidates: tuple[InteractionPairCandidate, ...]

    def __post_init__(self) -> None:
        if not self.candidates:
            raise ValueError("interaction pair universe cannot be empty")
        if tuple(sorted(self.candidates, key=lambda item: item.pair_id)) != self.candidates:
            raise ValueError("interaction candidates must use canonical pair-id order")
        if len({item.pair_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("interaction pair universe contains duplicate pairs")

    @property
    def universe_id(self) -> str:
        return content_id("interaction_pair_universe_", self)


def build_tsg_pair_universe(
    pairs: Sequence[PairSpec],
    relation_specs: Sequence[MechanismRelationSpec],
) -> InteractionPairUniverse:
    """Keep only pairs licensed by exactly one finite Prompt-TSG relation spec."""

    candidates = []
    for pair in pairs:
        matches = [spec for spec in relation_specs if pair_matches_relation_spec(pair, spec)]
        if len(matches) > 1:
            raise ValueError("a pair matches multiple mechanism relation specs")
        if not matches:
            continue
        spec = matches[0]
        if spec.factorial_compatibility is not FactorialCompatibility.COMPATIBLE:
            continue
        candidates.append(
            InteractionPairCandidate(
                pair.pair_id,
                spec.relation_spec_id,
                pair.pair_context_query_id,
                pair.factor_1_id,
                pair.factor_2_id,
                pair.operation_1,
                pair.operation_2,
            )
        )
    return InteractionPairUniverse(tuple(sorted(candidates, key=lambda item: item.pair_id)))


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
class InteractionSelectorPlan:
    model_id: str
    outcome_id: str
    covariate_names: tuple[str, ...]
    minimum_cell_task_units: int
    minimum_shared_lineages: int
    minimum_feature_reliability: float
    ridge_lambda: float
    cross_fit_folds: int
    bootstrap_draws: int
    bootstrap_seed: int
    top_l_per_lane: int

    def __post_init__(self) -> None:
        require_text(self.model_id, "model_id")
        require_text(self.outcome_id, "outcome_id")
        if (
            tuple(sorted(self.covariate_names)) != self.covariate_names
            or len(set(self.covariate_names)) != len(self.covariate_names)
            or any(not isinstance(name, str) or not name for name in self.covariate_names)
        ):
            raise ValueError("selector covariates must be unique and canonical")
        if type(self.minimum_cell_task_units) is not int or self.minimum_cell_task_units <= 0:
            raise ValueError("minimum_cell_task_units must be positive")
        if type(self.minimum_shared_lineages) is not int or self.minimum_shared_lineages <= 0:
            raise ValueError("minimum_shared_lineages must be positive")
        if (
            type(self.minimum_feature_reliability) not in {int, float}
            or not 0 <= self.minimum_feature_reliability <= 1
        ):
            raise ValueError("minimum_feature_reliability must be on [0, 1]")
        if type(self.ridge_lambda) not in {int, float} or self.ridge_lambda <= 0:
            raise ValueError("ridge_lambda must be positive")
        if type(self.cross_fit_folds) is not int or self.cross_fit_folds < 2:
            raise ValueError("cross_fit_folds must be at least two")
        if self.minimum_cell_task_units < self.cross_fit_folds:
            raise ValueError("minimum_cell_task_units must support every cross-fit fold")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 10:
            raise ValueError("bootstrap_draws must be at least 10")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.top_l_per_lane) is not int or self.top_l_per_lane <= 0:
            raise ValueError("top_l_per_lane must be positive")

    @property
    def plan_id(self) -> str:
        return content_id("interaction_selector_plan_", self)


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


@dataclass(frozen=True, slots=True)
class InteractionPairScore:
    pair_id: str
    lane: InteractionLane
    observational_score_scale: InteractionScale
    risk_difference_interaction: float
    absolute_risk_difference_interaction: float
    logit_interaction_coefficient: float
    sign_stability: float
    median_bootstrap_absolute_risk_difference: float
    baseline_task_units: int
    cross_fit_folds: int
    bootstrap_draws: int

    def __post_init__(self) -> None:
        require_text(self.pair_id, "pair_id")
        if type(self.lane) is not InteractionLane:
            raise TypeError("interaction lane must be typed")
        if self.observational_score_scale is not InteractionScale.RISK_DIFFERENCE:
            raise ValueError("interaction selector score must use the risk-difference scale")
        for value in (
            self.risk_difference_interaction,
            self.absolute_risk_difference_interaction,
            self.logit_interaction_coefficient,
            self.sign_stability,
            self.median_bootstrap_absolute_risk_difference,
        ):
            if type(value) not in {int, float} or not math.isfinite(float(value)):
                raise ValueError("interaction score values must be finite")
        if self.absolute_risk_difference_interaction != abs(
            self.risk_difference_interaction
        ):
            raise ValueError("absolute risk-difference interaction is inconsistent")
        if not 0 <= self.sign_stability <= 1:
            raise ValueError("sign stability must be on [0, 1]")
        if type(self.baseline_task_units) is not int or self.baseline_task_units <= 0:
            raise ValueError("baseline task-unit count must be positive")
        if type(self.cross_fit_folds) is not int or self.cross_fit_folds < 2:
            raise ValueError("cross-fit fold count must be at least two")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws <= 0:
            raise ValueError("bootstrap draw count must be positive")


@dataclass(frozen=True, slots=True)
class InteractionRank:
    rank: int
    pair_id: str
    lane: InteractionLane
    score: InteractionPairScore

    def __post_init__(self) -> None:
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("interaction rank must be positive")
        if self.pair_id != self.score.pair_id or self.lane is not self.score.lane:
            raise ValueError("interaction rank does not bind its score")


@dataclass(frozen=True, slots=True)
class InteractionSelectionFreeze:
    universe_id: str
    plan_id: str
    discovery_data_sha256: str
    graph_supported_factor_ids: tuple[str, ...]
    gates: tuple[PairSupportGate, ...]
    scores: tuple[InteractionPairScore, ...]
    graph_ranking: tuple[InteractionRank, ...]
    pure_interaction_ranking: tuple[InteractionRank, ...]
    top_l_per_lane: int

    def __post_init__(self) -> None:
        for name in ("universe_id", "plan_id"):
            require_text(getattr(self, name), name)
        _require_digest(self.discovery_data_sha256)
        if tuple(sorted(self.graph_supported_factor_ids)) != self.graph_supported_factor_ids or len(
            set(self.graph_supported_factor_ids)
        ) != len(self.graph_supported_factor_ids):
            raise ValueError("graph-supported factors must be unique and canonical")
        if tuple(sorted(self.gates, key=lambda item: item.pair_id)) != self.gates:
            raise ValueError("pair gates must use canonical pair-id order")
        if len({gate.pair_id for gate in self.gates}) != len(self.gates):
            raise ValueError("pair gates must be unique")
        passed = {gate.pair_id for gate in self.gates if gate.passed}
        if (
            len({score.pair_id for score in self.scores}) != len(self.scores)
            or {score.pair_id for score in self.scores} != passed
        ):
            raise ValueError("only and all gate-passing pairs may receive scores")
        score_by_id = {score.pair_id: score for score in self.scores}
        ranked_ids = set()
        for ranking, lane in (
            (self.graph_ranking, InteractionLane.GRAPH_SUPPORTED),
            (self.pure_interaction_ranking, InteractionLane.PURE_INTERACTION),
        ):
            if tuple(item.rank for item in ranking) != tuple(range(1, len(ranking) + 1)):
                raise ValueError("interaction ranking positions must be complete")
            if any(item.lane is not lane for item in ranking):
                raise ValueError("interaction ranking mixes discovery lanes")
            if len({item.pair_id for item in ranking}) != len(ranking) or any(
                score_by_id.get(item.pair_id) != item.score for item in ranking
            ):
                raise ValueError("interaction ranking does not exactly cover frozen scores")
            ranked_ids.update(item.pair_id for item in ranking)
        if ranked_ids != passed:
            raise ValueError("interaction rankings must cover every gate-passing pair")
        if type(self.top_l_per_lane) is not int or self.top_l_per_lane <= 0:
            raise ValueError("top_l_per_lane must be positive")

    @property
    def freeze_id(self) -> str:
        return content_id("interaction_selection_freeze_", self)

    @property
    def selected_graph_pair_ids(self) -> tuple[str, ...]:
        return tuple(item.pair_id for item in self.graph_ranking[: self.top_l_per_lane])

    @property
    def selected_pure_interaction_pair_ids(self) -> tuple[str, ...]:
        return tuple(item.pair_id for item in self.pure_interaction_ranking[: self.top_l_per_lane])


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
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]
    candidate_family_ids: tuple[tuple[str, str], ...]
    discovery_data_sha256: str
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
            require_text(getattr(self, name), name)
        if type(self.context_state) is not QueryState:
            raise TypeError("Pair context_state must be typed")
        if len(self.factor_states) != 2 or any(
            not isinstance(feature, str)
            or not feature
            or type(state) is not QueryState
            for feature, state in self.factor_states
        ):
            raise ValueError("Pair shadow observation requires two factor states")
        if tuple(feature for feature, _ in self.factor_reliabilities) != tuple(
            feature for feature, _ in self.factor_states
        ) or any(
            type(value) not in {int, float}
            or not math.isfinite(float(value))
            or not 0 <= value <= 1
            for _, value in self.factor_reliabilities
        ):
            raise ValueError("Pair reliability must bind both factors on [0, 1]")
        names = tuple(name for name, _ in self.covariates)
        if names != tuple(sorted(set(names))) or any(
            type(value) not in {int, float} or not math.isfinite(float(value))
            for _, value in self.covariates
        ):
            raise ValueError("Pair covariates must be finite and canonical")
        if type(self.outcome) is not int or self.outcome not in {0, 1}:
            raise ValueError("Pair discovery outcome must be binary")

    @property
    def observation_id(self) -> str:
        return content_id("pair_shadow_observation_", self)


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
    candidate_family_ids: Mapping[str, str],
    discovery_data_sha256: str,
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
    frozen_decisions = tuple(decisions[candidate_id] for candidate_id in candidate_ids)
    return PairCandidateUniverseManifest(
        ordered,
        frozen_decisions,
        tuple(records[candidate_id] for candidate_id in candidate_ids),
        tuple((candidate_id, candidate_family_ids[candidate_id]) for candidate_id in candidate_ids),
        discovery_data_sha256,
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
    support_gates = []
    fold_manifests = []
    rd_scores = []
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
        support_gates.append(gate)
        if not gate.passed:
            continue
        try:
            folds = _pair_candidate_fold_manifest(candidate, rows, plan)
            score = _pair_cross_fitted_rd(candidate, rows, folds, plan)
        except ValueError as exc:
            failures.append(
                SelectorFailure("pair_rd_non_evaluable", str(exc), candidate_id)
            )
            continue
        fold_manifests.append(folds)
        rd_scores.append(score)

    frozen_support = tuple(sorted(support_gates, key=lambda item: item.pair_id))
    frozen_folds = tuple(sorted(fold_manifests, key=lambda item: item.policy_key))
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


def _pair_shared_support_gate(
    policy: PairPolicyKey,
    candidate: _PairPolicyAdapter,
    rows: tuple[PairShadowObservation, ...],
    plan: PairShadowPlan,
) -> PairSupportGate:
    reasons = set()
    if not rows:
        reasons.add("missing_observations")
    if len({row.task_unit_id for row in rows}) != len(rows):
        reasons.add("duplicate_task_unit")
    cells: dict[str, list[PairShadowObservation]] = {
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
    rows: tuple[PairShadowObservation, ...],
    plan: PairShadowPlan,
) -> PairCandidateFoldManifest:
    cells: dict[str, list[PairShadowObservation]] = {
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


def run_interaction_selector(
    universe: InteractionPairUniverse,
    observations: Sequence[PairDiscoveryObservation],
    relation_evidence: Sequence[PairRelationEvidence],
    plan: InteractionSelectorPlan,
    *,
    graph_supported_factor_ids: tuple[str, ...] = (),
) -> InteractionSelectionFreeze:
    """Gate, score, and freeze two disjoint observational pair rankings."""

    if tuple(sorted(graph_supported_factor_ids)) != graph_supported_factor_ids or len(
        set(graph_supported_factor_ids)
    ) != len(graph_supported_factor_ids):
        raise ValueError("graph-supported factor IDs must be unique and canonical")
    candidate_by_id = {candidate.pair_id: candidate for candidate in universe.candidates}
    universe_factors = {
        factor for candidate in universe.candidates for factor in candidate.factors
    }
    if not set(graph_supported_factor_ids) <= universe_factors:
        raise ValueError("graph-supported factors fall outside the pair universe")
    if any(row.pair_id not in candidate_by_id for row in observations):
        raise ValueError("an observation falls outside the TSG-compatible pair universe")
    evidence_by_id = {item.evidence_id: item for item in relation_evidence}
    if len(evidence_by_id) != len(relation_evidence):
        raise ValueError("pair relation evidence IDs must be unique")
    rows_by_pair: dict[str, list[PairDiscoveryObservation]] = {
        pair_id: [] for pair_id in candidate_by_id
    }
    for row in observations:
        rows_by_pair[row.pair_id].append(row)
    gates = []
    scores = []
    for candidate in universe.candidates:
        rows = tuple(rows_by_pair[candidate.pair_id])
        gate = _support_gate(candidate, rows, evidence_by_id, plan)
        gates.append(gate)
        if not gate.passed:
            continue
        lane = (
            InteractionLane.GRAPH_SUPPORTED
            if set(candidate.factors) & set(graph_supported_factor_ids)
            else InteractionLane.PURE_INTERACTION
        )
        scores.append(_score_pair(candidate, rows, lane, plan))
    graph_ranking = _rank(
        tuple(score for score in scores if score.lane is InteractionLane.GRAPH_SUPPORTED)
    )
    pure_ranking = _rank(
        tuple(score for score in scores if score.lane is InteractionLane.PURE_INTERACTION)
    )
    discovery_sha256 = content_hash(
        {
            "observations": tuple(sorted(observations, key=lambda item: item.observation_id)),
            "relation_evidence": tuple(
                sorted(relation_evidence, key=lambda item: item.evidence_id)
            ),
        }
    )
    return InteractionSelectionFreeze(
        universe.universe_id,
        plan.plan_id,
        discovery_sha256,
        graph_supported_factor_ids,
        tuple(gates),
        tuple(sorted(scores, key=lambda item: item.pair_id)),
        graph_ranking,
        pure_ranking,
        plan.top_l_per_lane,
    )


def _support_gate(
    candidate: InteractionPairCandidate,
    rows: tuple[PairDiscoveryObservation, ...],
    evidence_by_id: Mapping[str, PairRelationEvidence],
    plan: InteractionSelectorPlan,
) -> PairSupportGate:
    reasons = set()
    if not rows:
        reasons.add("missing_observations")
    if len({row.task_unit_id for row in rows}) != len(rows):
        reasons.add("duplicate_task_unit")
    cells: dict[str, list[PairDiscoveryObservation]] = {
        "00": [],
        "01": [],
        "10": [],
        "11": [],
    }
    for row in rows:
        if (
            row.relation_spec_id != candidate.relation_spec_id
            or row.context_query_id != candidate.context_query_id
            or row.model_id != plan.model_id
            or tuple(feature for feature, _ in row.factor_states) != candidate.factors
        ):
            reasons.add("candidate_coordinate_mismatch")
        if row.context_state is not QueryState.PRESENT:
            reasons.add("context_not_present")
        if tuple(name for name, _ in row.covariates) != plan.covariate_names:
            reasons.add("covariate_schema_mismatch")
        if any(value < plan.minimum_feature_reliability for _, value in row.factor_reliabilities):
            reasons.add("extractor_reliability_below_threshold")
        evidence = evidence_by_id.get(row.relation_evidence_id)
        if (
            evidence is None
            or evidence.pair_id != candidate.pair_id
            or evidence.relation_spec_id != candidate.relation_spec_id
            or evidence.task_unit_id != row.task_unit_id
            or evidence.state is not QueryState.PRESENT
        ):
            reasons.add("relation_evidence_mismatch")
        states = tuple(state for _, state in row.factor_states)
        if any(state not in {QueryState.ABSENT, QueryState.PRESENT} for state in states):
            reasons.add("factor_state_not_binary")
            continue
        cell = _cell_key(states, candidate.operations)
        cells[cell].append(row)
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
        candidate.pair_id,
        not reasons,
        tuple(sorted(reasons)),
        cell_counts,
        shared_lineages,
        shared_languages,
        shared_archetypes,
        shared_api_families,
    )


def _shared_count(
    cells: Mapping[str, Sequence[PairDiscoveryObservation]],
    value: Callable[[PairDiscoveryObservation], str],
) -> int:
    sets = [{value(row) for row in cells[cell]} for cell in ("00", "01", "10", "11")]
    return len(set.intersection(*sets)) if all(sets) else 0


def _score_pair(
    candidate: InteractionPairCandidate,
    rows: tuple[PairDiscoveryObservation, ...],
    lane: InteractionLane,
    plan: InteractionSelectorPlan,
) -> InteractionPairScore:
    coefficient = _fit_logit(rows, candidate.operations, float(plan.ridge_lambda)).weights[-1]
    contributions = _cross_fitted_rd_contributions(candidate, rows, plan)
    risk_difference = sum(contributions) / len(contributions)
    rng = random.Random(
        int(
            content_hash(
                {
                    "bootstrap_seed": plan.bootstrap_seed,
                    "pair_id": candidate.pair_id,
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
    ordered_absolute = sorted(abs(value) for value in bootstrap)
    middle = len(ordered_absolute) // 2
    median = (
        ordered_absolute[middle]
        if len(ordered_absolute) % 2
        else (ordered_absolute[middle - 1] + ordered_absolute[middle]) / 2
    )
    return InteractionPairScore(
        candidate.pair_id,
        lane,
        InteractionScale.RISK_DIFFERENCE,
        risk_difference,
        abs(risk_difference),
        coefficient,
        stability,
        median,
        len(contributions),
        plan.cross_fit_folds,
        plan.bootstrap_draws,
    )


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


def _cross_fitted_rd_contributions(
    candidate: InteractionPairCandidate,
    rows: tuple[PairDiscoveryObservation, ...],
    plan: InteractionSelectorPlan,
) -> tuple[float, ...]:
    """Return one out-of-fold RD-interaction contribution per baseline task unit."""

    fold_by_id: dict[str, int] = {}
    cells: dict[str, list[PairDiscoveryObservation]] = {
        cell: [] for cell in ("00", "01", "10", "11")
    }
    for row in rows:
        states = tuple(state for _, state in row.factor_states)
        cells[_cell_key(states, candidate.operations)].append(row)
    for cell, values in cells.items():
        ordered = sorted(
            values,
            key=lambda item: content_hash(
                {
                    "pair_id": candidate.pair_id,
                    "task_unit_id": item.task_unit_id,
                    "cell": cell,
                    "rule": "cell_stratified_cross_fit_v1",
                }
            ),
        )
        if len(ordered) < plan.cross_fit_folds:
            raise ValueError("interaction selector lacks fold-level four-cell support")
        for index, row in enumerate(ordered):
            fold_by_id[row.observation_id] = index % plan.cross_fit_folds
    contributions = []
    for fold in range(plan.cross_fit_folds):
        training = tuple(row for row in rows if fold_by_id[row.observation_id] != fold)
        held_out = tuple(row for row in rows if fold_by_id[row.observation_id] == fold)
        training_cells = {
            _cell_key(tuple(state for _, state in row.factor_states), candidate.operations)
            for row in training
        }
        if training_cells != {"00", "01", "10", "11"}:
            raise ValueError("interaction selector training fold lacks four-cell support")
        model = _fit_logit(training, candidate.operations, float(plan.ridge_lambda))
        for row in held_out:
            states = tuple(state for _, state in row.factor_states)
            if _cell_key(states, candidate.operations) != "00":
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
    if len(contributions) != len(cells["00"]):
        raise ValueError("cross-fitted baseline contribution coverage is incomplete")
    return tuple(contributions)


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


def _rank(scores: tuple[InteractionPairScore, ...]) -> tuple[InteractionRank, ...]:
    ordered = sorted(
        scores,
        key=lambda item: (
            -item.sign_stability,
            -item.absolute_risk_difference_interaction,
            -item.median_bootstrap_absolute_risk_difference,
            -abs(item.logit_interaction_coefficient),
            item.pair_id,
        ),
    )
    return tuple(
        InteractionRank(rank, score.pair_id, score.lane, score)
        for rank, score in enumerate(ordered, start=1)
    )


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
    "InteractionLane",
    "InteractionPairCandidate",
    "InteractionPairScore",
    "InteractionPairUniverse",
    "InteractionRank",
    "InteractionSelectionFreeze",
    "InteractionSelectorPlan",
    "PairDiscoveryObservation",
    "PairCandidateFoldManifest",
    "PairCandidateUniverseManifest",
    "PairFoldAssignment",
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
    "build_tsg_pair_universe",
    "freeze_pair_candidate_universe",
    "pair_shadow_data_sha256",
    "run_interaction_selector",
    "run_pair_shadow_qualification",
]

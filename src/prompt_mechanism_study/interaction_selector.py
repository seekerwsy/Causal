"""Outcome-blind pair support gates and observational interaction ranking.

Prompt-TSG relation specs define the finite pair universe.  The ridge-logit
interaction coefficient is a discovery ranking signal only; randomized 2x2
factorial evaluation remains the sole source of causal interaction estimates.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from prompt_mechanism_study.mechanisms import (
    MechanismRelationSpec,
    PairRelationEvidence,
    PairSpec,
    pair_matches_relation_spec,
)
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.records import content_hash, content_id, require_text


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

    @property
    def factors(self) -> tuple[str, str]:
        return self.factor_1_id, self.factor_2_id


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
        candidates.append(
            InteractionPairCandidate(
                pair.pair_id,
                spec.relation_spec_id,
                pair.pair_context_query_id,
                pair.factor_1_id,
                pair.factor_2_id,
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
    interaction_coefficient: float
    absolute_interaction_coefficient: float
    sign_stability: float
    median_bootstrap_absolute_coefficient: float
    bootstrap_draws: int

    def __post_init__(self) -> None:
        require_text(self.pair_id, "pair_id")
        if type(self.lane) is not InteractionLane:
            raise TypeError("interaction lane must be typed")
        for value in (
            self.interaction_coefficient,
            self.absolute_interaction_coefficient,
            self.sign_stability,
            self.median_bootstrap_absolute_coefficient,
        ):
            if type(value) not in {int, float} or not math.isfinite(float(value)):
                raise ValueError("interaction score values must be finite")
        if self.absolute_interaction_coefficient != abs(self.interaction_coefficient):
            raise ValueError("absolute interaction coefficient is inconsistent")
        if not 0 <= self.sign_stability <= 1:
            raise ValueError("sign stability must be on [0, 1]")
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
        cell = "".join("1" if state is QueryState.PRESENT else "0" for state in states)
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
    coefficient = _interaction_coefficient(rows, float(plan.ridge_lambda))
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
        draw = tuple(rows[rng.randrange(len(rows))] for _ in rows)
        bootstrap.append(_interaction_coefficient(draw, float(plan.ridge_lambda)))
    direction = _sign(coefficient)
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
        coefficient,
        abs(coefficient),
        stability,
        median,
        plan.bootstrap_draws,
    )


def _interaction_coefficient(
    rows: tuple[PairDiscoveryObservation, ...], ridge_lambda: float
) -> float:
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
        x1, x2 = (
            1.0 if state is QueryState.PRESENT else 0.0 for _, state in row.factor_states
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
    return weights[-1]


def _rank(scores: tuple[InteractionPairScore, ...]) -> tuple[InteractionRank, ...]:
    ordered = sorted(
        scores,
        key=lambda item: (
            -item.sign_stability,
            -item.absolute_interaction_coefficient,
            -item.median_bootstrap_absolute_coefficient,
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


def _require_digest(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("discovery data SHA-256 must be a lowercase digest")


__all__ = [
    "InteractionLane",
    "InteractionPairCandidate",
    "InteractionPairScore",
    "InteractionPairUniverse",
    "InteractionRank",
    "InteractionSelectionFreeze",
    "InteractionSelectorPlan",
    "PairDiscoveryObservation",
    "PairSupportGate",
    "build_tsg_pair_universe",
    "run_interaction_selector",
]

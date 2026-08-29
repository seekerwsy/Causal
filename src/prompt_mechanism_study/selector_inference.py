"""Strict ConfirmedYield@K and fixed-ranking nested task-unit inference."""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Sequence
from dataclasses import dataclass

from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    SelectionFreezeManifest,
    SelectorKind,
    SharedBridgeMap,
    SlotStatus,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text


@dataclass(frozen=True, slots=True)
class ConfirmationCoordinate:
    final_hypothesis_id: str
    model_id: str
    expected_direction: int
    task_unit_effects: tuple[tuple[str, float], ...]
    minimum_task_units: int
    provenance_complete: bool

    def __post_init__(self) -> None:
        require_text(self.final_hypothesis_id, "final_hypothesis_id")
        require_text(self.model_id, "confirmation model_id")
        if self.expected_direction not in {-1, 1} or type(self.expected_direction) is not int:
            raise ValueError("expected_direction must be -1 or 1")
        ids = tuple(task_unit_id for task_unit_id, _ in self.task_unit_effects)
        if not ids or ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("task-unit effects must be non-empty, unique, and canonical")
        if any(
            type(value) not in {int, float}
            or not math.isfinite(float(value))
            or not -1.0 <= float(value) <= 1.0
            for _, value in self.task_unit_effects
        ):
            raise ValueError("task-unit effects must be finite values in [-1, 1]")
        if type(self.minimum_task_units) is not int or self.minimum_task_units < 2:
            raise ValueError("minimum_task_units must be at least two")
        if type(self.provenance_complete) is not bool:
            raise TypeError("provenance_complete must be boolean")

    @property
    def coordinate_id(self) -> str:
        return content_id("selector_confirmation_coordinate_", self)


@dataclass(frozen=True, slots=True)
class SelectorInferencePlan:
    bootstrap_seed: int
    inner_draws: int
    outer_draws: int
    alpha: float
    minimum_valid_fraction: float
    selector_pairs: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.inner_draws) is not int or self.inner_draws < 100:
            raise ValueError("inner_draws must be at least 100")
        if type(self.outer_draws) is not int or self.outer_draws < 100:
            raise ValueError("outer_draws must be at least 100")
        if type(self.alpha) is not float or not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be a float between zero and one")
        if type(self.minimum_valid_fraction) is not float or not 0.5 <= self.minimum_valid_fraction <= 1.0:
            raise ValueError("minimum_valid_fraction must be in [0.5, 1]")
        normalized = tuple(tuple(pair) for pair in self.selector_pairs)
        if normalized != self.selector_pairs or len(set(normalized)) != len(normalized):
            raise ValueError("selector pairs must be unique canonical tuples")
        if any(len(pair) != 2 or pair[0] == pair[1] or not all(isinstance(value, str) and value for value in pair) for pair in normalized):
            raise ValueError("selector pairs must contain two different selector ids")

    @property
    def plan_id(self) -> str:
        return content_id("selector_inference_plan_", self)


@dataclass(frozen=True, slots=True)
class ConfirmationStatus:
    final_hypothesis_id: str
    model_id: str
    point: float
    standard_error: float
    adjusted_lower: float | None
    adjusted_upper: float | None
    oriented_adjusted_lower: float | None
    task_units: int
    provenance_complete: bool
    confirmed: bool


@dataclass(frozen=True, slots=True)
class SlotContribution:
    selector_id: str
    ranking_id: str
    rank: int
    slot_status: SlotStatus
    candidate_id: str | None
    final_hypothesis_id: str | None
    confirmed_contribution: int
    reason_code: str


@dataclass(frozen=True, slots=True)
class SelectorYieldPoint:
    selector_id: str
    ranking_id: str
    model_id: str
    budget_k: int
    confirmed_slots: int
    confirmed_yield: float
    slot_contributions: tuple[SlotContribution, ...]


@dataclass(frozen=True, slots=True)
class SelectorMethodPoint:
    selector_id: str
    model_id: str
    ranking_count: int
    confirmed_yield: float


@dataclass(frozen=True, slots=True)
class SelectorPairPoint:
    pair_id: str
    left_selector_id: str
    right_selector_id: str
    difference: float


@dataclass(frozen=True, slots=True)
class SelectorPairInterval:
    pair_id: str
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class SelectorInferenceResult:
    plan_id: str
    selection_id: str
    bridge_map_id: str
    confirmation_input_sha256: str
    primary_critical_value: float | None
    primary_valid_draws: int
    primary_invalid_draws: int
    confirmation_statuses: tuple[ConfirmationStatus, ...]
    yield_points: tuple[SelectorYieldPoint, ...]
    method_points: tuple[SelectorMethodPoint, ...]
    pair_points: tuple[SelectorPairPoint, ...]
    selector_pair_critical_value: float | None
    pair_intervals: tuple[SelectorPairInterval, ...]
    valid_outer_draws: int
    invalid_outer_draws: int
    outer_pair_draws_sha256: str
    pair_inference_status: str

    @property
    def result_id(self) -> str:
        return content_id("selector_inference_result_", self)


def evaluate_selector_study(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
    coordinates: Sequence[ConfirmationCoordinate],
    plan: SelectorInferencePlan,
) -> SelectorInferenceResult:
    """Evaluate fixed selector slots without rerunning or reranking discovery."""

    if not selection.gate_passed:
        raise ValueError("ConfirmedYield@K is undefined when the selector support gate failed")
    if bridge.selection_id != selection.selection_id:
        raise ValueError("bridge map does not bind the selector freeze")
    frozen = tuple(sorted(coordinates, key=lambda item: item.coordinate_id))
    if not frozen or len({item.coordinate_id for item in frozen}) != len(frozen):
        raise ValueError("confirmation coordinates must be non-empty and unique")
    model_id = selection.plan.model_id
    if any(item.model_id != model_id for item in frozen):
        raise ValueError("confirmation model drifts from the selector suite")
    successful = {
        item.final_hypothesis_id
        for item in bridge.records
        if item.status is BridgeStatus.SUCCESS
    }
    if {item.final_hypothesis_id for item in frozen} != successful:
        raise ValueError("confirmation coordinates must cover every successful bridge exactly once")
    selector_ids = {run.selector_id for run in selection.runs}
    if any(left not in selector_ids or right not in selector_ids for left, right in plan.selector_pairs):
        raise ValueError("a selector pair references an unknown frozen selector")

    full_population = tuple(sorted({unit for item in frozen for unit, _ in item.task_unit_effects}))
    full_occurrences = tuple((index, task_unit_id) for index, task_unit_id in enumerate(full_population))
    primary_seed = _seed(plan.bootstrap_seed, "full_primary")
    statuses, critical, primary_valid, primary_invalid = _primary_statuses(
        frozen,
        full_occurrences,
        plan,
        random.Random(primary_seed),
    )
    yield_points, method_points = _yield_points(selection, bridge, statuses)
    pair_points = _pair_points(method_points, plan.selector_pairs)

    rng = random.Random(_seed(plan.bootstrap_seed, "outer"))
    outer_draws: list[dict[str, float]] = []
    invalid_outer = 0
    for draw_index in range(plan.outer_draws):
        sampled = [full_population[rng.randrange(len(full_population))] for _ in full_population]
        occurrences = tuple((index, task_unit_id) for index, task_unit_id in enumerate(sampled))
        outer_statuses, outer_critical, valid_inner, _invalid_inner = _primary_statuses(
            frozen,
            occurrences,
            plan,
            random.Random(_seed(plan.bootstrap_seed, f"outer_inner_{draw_index}")),
        )
        if outer_critical is None or valid_inner < math.ceil(plan.inner_draws * plan.minimum_valid_fraction):
            invalid_outer += 1
            continue
        _outer_yields, outer_methods = _yield_points(selection, bridge, outer_statuses)
        outer_draws.append({item.pair_id: item.difference for item in _pair_points(outer_methods, plan.selector_pairs)})

    intervals, pair_critical, pair_status = _pair_intervals(
        pair_points,
        outer_draws,
        plan,
    )
    return SelectorInferenceResult(
        plan.plan_id,
        selection.selection_id,
        bridge.bridge_map_id,
        content_hash(frozen),
        critical,
        primary_valid,
        primary_invalid,
        statuses,
        yield_points,
        method_points,
        pair_points,
        pair_critical,
        intervals,
        len(outer_draws),
        invalid_outer,
        content_hash(outer_draws),
        pair_status,
    )


def _primary_statuses(
    coordinates: tuple[ConfirmationCoordinate, ...],
    occurrences: tuple[tuple[int, str], ...],
    plan: SelectorInferencePlan,
    rng: random.Random,
) -> tuple[tuple[ConfirmationStatus, ...], float | None, int, int]:
    effect_maps = {
        item.final_hypothesis_id: {unit: float(value) for unit, value in item.task_unit_effects}
        for item in coordinates
    }
    full_stats = {}
    testable = []
    for item in coordinates:
        values = [effect_maps[item.final_hypothesis_id][unit] for _, unit in occurrences if unit in effect_maps[item.final_hypothesis_id]]
        point, standard_error = _mean_standard_error(values)
        full_stats[item.final_hypothesis_id] = (point, standard_error, len(values))
        if item.provenance_complete and len(values) >= item.minimum_task_units and standard_error > 0.0:
            testable.append(item)
    maxima = []
    invalid = 0
    for _ in range(plan.inner_draws):
        sample = [occurrences[rng.randrange(len(occurrences))] for _ in occurrences]
        values = []
        valid = True
        for item in testable:
            draw_values = [effect_maps[item.final_hypothesis_id][unit] for _, unit in sample if unit in effect_maps[item.final_hypothesis_id]]
            if len(draw_values) < item.minimum_task_units:
                valid = False
                break
            draw_point, draw_se = _mean_standard_error(draw_values)
            if draw_se <= 0.0:
                valid = False
                break
            values.append(abs(draw_point - full_stats[item.final_hypothesis_id][0]) / draw_se)
        if valid and values:
            maxima.append(max(values))
        else:
            invalid += 1
    critical = None
    if maxima and len(maxima) >= math.ceil(plan.inner_draws * plan.minimum_valid_fraction):
        critical = _quantile(maxima, 1.0 - plan.alpha)
    statuses = []
    for item in coordinates:
        point, standard_error, count = full_stats[item.final_hypothesis_id]
        eligible = item in testable and critical is not None
        lower = max(-1.0, point - critical * standard_error) if eligible else None
        upper = min(1.0, point + critical * standard_error) if eligible else None
        oriented = None if lower is None or upper is None else (lower if item.expected_direction == 1 else -upper)
        statuses.append(
            ConfirmationStatus(
                item.final_hypothesis_id,
                item.model_id,
                point,
                standard_error,
                lower,
                upper,
                oriented,
                count,
                item.provenance_complete,
                bool(oriented is not None and oriented > 0.0 and count >= item.minimum_task_units and item.provenance_complete),
            )
        )
    return tuple(statuses), critical, len(maxima), invalid


def _yield_points(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
    statuses: tuple[ConfirmationStatus, ...],
) -> tuple[tuple[SelectorYieldPoint, ...], tuple[SelectorMethodPoint, ...]]:
    bridge_by_candidate = {item.candidate_id: item for item in bridge.records}
    status_by_hypothesis = {item.final_hypothesis_id: item for item in statuses}
    points = []
    for run in selection.runs:
        for ranking in run.rankings:
            contributions = []
            for slot in ranking.slots:
                final_id = None
                contribution = 0
                reason = slot.reason_code or "not_confirmed"
                if slot.status is SlotStatus.FILLED and slot.candidate_id is not None:
                    bridge_record = bridge_by_candidate[slot.candidate_id]
                    if bridge_record.status is BridgeStatus.SUCCESS:
                        final_id = bridge_record.final_hypothesis_id
                        status = status_by_hypothesis[final_id]
                        contribution = int(status.confirmed)
                        reason = "confirmed" if contribution else "randomized_effect_not_confirmed"
                    else:
                        reason = bridge_record.reason_code or bridge_record.status.value
                contributions.append(
                    SlotContribution(
                        run.selector_id,
                        ranking.ranking_id,
                        slot.rank,
                        slot.status,
                        slot.candidate_id,
                        final_id,
                        contribution,
                        reason,
                    )
                )
            count = sum(item.confirmed_contribution for item in contributions)
            points.append(
                SelectorYieldPoint(
                    run.selector_id,
                    ranking.ranking_id,
                    run.model_id,
                    selection.universe.top_k,
                    count,
                    count / selection.universe.top_k,
                    tuple(contributions),
                )
            )
    methods = []
    for run in selection.runs:
        values = [item.confirmed_yield for item in points if item.selector_id == run.selector_id]
        methods.append(SelectorMethodPoint(run.selector_id, run.model_id, len(values), sum(values) / len(values)))
    return tuple(points), tuple(methods)


def _pair_points(
    methods: tuple[SelectorMethodPoint, ...],
    pairs: tuple[tuple[str, str], ...],
) -> tuple[SelectorPairPoint, ...]:
    by_selector = {item.selector_id: item.confirmed_yield for item in methods}
    return tuple(
        SelectorPairPoint(
            content_id("selector_pair_", {"left": left, "right": right}),
            left,
            right,
            by_selector[left] - by_selector[right],
        )
        for left, right in pairs
    )


def _pair_intervals(
    points: tuple[SelectorPairPoint, ...],
    draws: list[dict[str, float]],
    plan: SelectorInferencePlan,
) -> tuple[tuple[SelectorPairInterval, ...], float | None, str]:
    required = math.ceil(plan.outer_draws * plan.minimum_valid_fraction)
    if not points:
        return (), None, "no_preregistered_selector_pairs"
    if len(draws) < required:
        return (), None, "insufficient_valid_outer_draws"
    errors = {
        item.pair_id: statistics.stdev(draw[item.pair_id] for draw in draws)
        for item in points
    }
    evaluable = tuple(item for item in points if errors[item.pair_id] > 0.0)
    if not evaluable:
        return (), None, "zero_selector_pair_variance"
    maxima = [
        max(abs(draw[item.pair_id] - item.difference) / errors[item.pair_id] for item in evaluable)
        for draw in draws
    ]
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SelectorPairInterval(
            item.pair_id,
            errors[item.pair_id],
            max(-1.0, item.difference - critical * errors[item.pair_id]),
            min(1.0, item.difference + critical * errors[item.pair_id]),
        )
        for item in evaluable
    )
    status = "complete" if len(evaluable) == len(points) else "partial_zero_variance"
    return intervals, critical, status


def _mean_standard_error(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        raise ValueError("a confirmation coordinate has no retained task units")
    point = sum(values) / len(values)
    if len(values) < 2:
        return point, 0.0
    standard_error = math.sqrt(sum((value - point) ** 2 for value in values) / (len(values) * (len(values) - 1)))
    return point, standard_error


def _seed(seed: int, domain: str) -> int:
    return int(content_hash({"seed": seed, "domain": domain})[-16:], 16)


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


def canonical_selector_pairs() -> tuple[tuple[str, str], ...]:
    """Primary FCI comparisons against the other four frozen selectors."""

    left = f"{SelectorKind.FCI.value}.v1"
    return tuple(
        (
            left,
            "association.v3"
            if kind is SelectorKind.ASSOCIATION
            else f"{kind.value}.v1",
        )
        for kind in tuple(SelectorKind)[1:]
    )


__all__ = [
    "ConfirmationCoordinate",
    "ConfirmationStatus",
    "SelectorInferencePlan",
    "SelectorInferenceResult",
    "SelectorMethodPoint",
    "SelectorPairInterval",
    "SelectorPairPoint",
    "SelectorYieldPoint",
    "SlotContribution",
    "canonical_selector_pairs",
    "evaluate_selector_study",
]

"""Independent recomputation for stored selector-study results."""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Sequence

from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    SelectionFreezeManifest,
    SharedBridgeMap,
    SlotStatus,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.selector_inference import (
    ConfirmationCoordinate,
    ConfirmationStatus,
    SelectorInferencePlan,
    SelectorInferenceResult,
    SelectorMethodPoint,
    SelectorPairInterval,
    SelectorPairPoint,
    SelectorYieldPoint,
    SlotContribution,
)


def verify_selector_result(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
    coordinates: Sequence[ConfirmationCoordinate],
    plan: SelectorInferencePlan,
    result: SelectorInferenceResult,
) -> dict[str, object]:
    """Recompute every status, K denominator, draw, and paired interval."""

    if not selection.gate_passed or bridge.selection_id != selection.selection_id:
        raise ValueError("selector verifier received an unbound or gate-failed study")
    frozen = tuple(sorted(coordinates, key=lambda item: item.coordinate_id))
    if (
        result.plan_id != plan.plan_id
        or result.selection_id != selection.selection_id
        or result.bridge_map_id != bridge.bridge_map_id
        or result.confirmation_input_sha256 != content_hash(frozen)
    ):
        raise ValueError("selector result provenance mismatch")
    successful = {
        record.final_hypothesis_id
        for record in bridge.records
        if record.status is BridgeStatus.SUCCESS
    }
    if {item.final_hypothesis_id for item in frozen} != successful:
        raise ValueError("selector verifier lacks an exact successful-bridge coordinate set")

    population = tuple(sorted({unit for item in frozen for unit, _ in item.task_unit_effects}))
    occurrences = tuple((index, unit) for index, unit in enumerate(population))
    statuses, primary_critical, primary_valid, primary_invalid = _statuses(
        frozen,
        occurrences,
        plan,
        random.Random(_seed(plan.bootstrap_seed, "full_primary")),
    )
    yields, methods = _points(selection, bridge, statuses)
    pair_points = _pairs(methods, plan.selector_pairs)

    rng = random.Random(_seed(plan.bootstrap_seed, "outer"))
    outer = []
    invalid_outer = 0
    for draw_index in range(plan.outer_draws):
        sampled = [population[rng.randrange(len(population))] for _ in population]
        sampled_occurrences = tuple((index, unit) for index, unit in enumerate(sampled))
        draw_statuses, critical, valid, _invalid = _statuses(
            frozen,
            sampled_occurrences,
            plan,
            random.Random(_seed(plan.bootstrap_seed, f"outer_inner_{draw_index}")),
        )
        if critical is None or valid < math.ceil(plan.inner_draws * plan.minimum_valid_fraction):
            invalid_outer += 1
            continue
        _draw_yields, draw_methods = _points(selection, bridge, draw_statuses)
        outer.append({item.pair_id: item.difference for item in _pairs(draw_methods, plan.selector_pairs)})
    intervals, pair_critical, pair_status = _intervals(pair_points, outer, plan)

    checks = (
        (result.primary_critical_value, primary_critical, "primary critical value"),
        (result.primary_valid_draws, primary_valid, "primary valid draws"),
        (result.primary_invalid_draws, primary_invalid, "primary invalid draws"),
        (result.confirmation_statuses, statuses, "confirmation statuses"),
        (result.yield_points, yields, "strict ConfirmedYield@K"),
        (result.method_points, methods, "selector method points"),
        (result.pair_points, pair_points, "selector pair points"),
        (result.selector_pair_critical_value, pair_critical, "selector pair critical value"),
        (result.pair_intervals, intervals, "selector pair intervals"),
        (result.valid_outer_draws, len(outer), "valid outer draws"),
        (result.invalid_outer_draws, invalid_outer, "invalid outer draws"),
        (result.outer_pair_draws_sha256, content_hash(outer), "outer draw digest"),
        (result.pair_inference_status, pair_status, "pair inference status"),
    )
    for actual, expected, name in checks:
        if actual != expected:
            raise ValueError(f"selector result {name} does not independently recompute")
    return {
        "status": "SELECTOR_RESULT_VERIFIED",
        "selectors": len(selection.runs),
        "rankings": sum(len(run.rankings) for run in selection.runs),
        "budget_slots": sum(
            len(ranking.slots) for run in selection.runs for ranking in run.rankings
        ),
        "confirmation_coordinates": len(frozen),
        "valid_outer_draws": len(outer),
    }


def _statuses(coordinates, occurrences, plan, rng):
    maps = {
        item.final_hypothesis_id: {unit: float(value) for unit, value in item.task_unit_effects}
        for item in coordinates
    }
    summary = {}
    testable = []
    for item in coordinates:
        values = [maps[item.final_hypothesis_id][unit] for _, unit in occurrences if unit in maps[item.final_hypothesis_id]]
        point, error = _stats(values)
        summary[item.final_hypothesis_id] = (point, error, len(values))
        if item.provenance_complete and len(values) >= item.minimum_task_units and error > 0.0:
            testable.append(item)
    maxima = []
    invalid = 0
    for _ in range(plan.inner_draws):
        sampled = [occurrences[rng.randrange(len(occurrences))] for _ in occurrences]
        statistics_for_draw = []
        for item in testable:
            values = [maps[item.final_hypothesis_id][unit] for _, unit in sampled if unit in maps[item.final_hypothesis_id]]
            if len(values) < item.minimum_task_units:
                statistics_for_draw = []
                break
            point, error = _stats(values)
            if error <= 0.0:
                statistics_for_draw = []
                break
            statistics_for_draw.append(abs(point - summary[item.final_hypothesis_id][0]) / error)
        if statistics_for_draw and len(statistics_for_draw) == len(testable):
            maxima.append(max(statistics_for_draw))
        else:
            invalid += 1
    critical = _q(maxima, 1.0 - plan.alpha) if len(maxima) >= math.ceil(plan.inner_draws * plan.minimum_valid_fraction) else None
    statuses = []
    for item in coordinates:
        point, error, count = summary[item.final_hypothesis_id]
        eligible = item in testable and critical is not None
        lower = max(-1.0, point - critical * error) if eligible else None
        upper = min(1.0, point + critical * error) if eligible else None
        oriented = None if lower is None or upper is None else (lower if item.expected_direction == 1 else -upper)
        statuses.append(
            ConfirmationStatus(
                item.final_hypothesis_id,
                item.model_id,
                point,
                error,
                lower,
                upper,
                oriented,
                count,
                item.provenance_complete,
                bool(oriented is not None and oriented > 0.0 and count >= item.minimum_task_units and item.provenance_complete),
            )
        )
    return tuple(statuses), critical, len(maxima), invalid


def _points(selection, bridge, statuses):
    bridge_by_candidate = {record.candidate_id: record for record in bridge.records}
    status_by_hypothesis = {status.final_hypothesis_id: status for status in statuses}
    points = []
    for run in selection.runs:
        for ranking in run.rankings:
            contributions = []
            for slot in ranking.slots:
                hypothesis_id = None
                contribution = 0
                reason = slot.reason_code or "not_confirmed"
                if slot.status is SlotStatus.FILLED:
                    record = bridge_by_candidate[slot.candidate_id]
                    if record.status is BridgeStatus.SUCCESS:
                        hypothesis_id = record.final_hypothesis_id
                        contribution = int(status_by_hypothesis[hypothesis_id].confirmed)
                        reason = "confirmed" if contribution else "randomized_effect_not_confirmed"
                    else:
                        reason = record.reason_code or record.status.value
                contributions.append(SlotContribution(run.selector_id, ranking.ranking_id, slot.rank, slot.status, slot.candidate_id, hypothesis_id, contribution, reason))
            count = sum(item.confirmed_contribution for item in contributions)
            points.append(SelectorYieldPoint(run.selector_id, ranking.ranking_id, run.model_id, selection.universe.top_k, count, count / selection.universe.top_k, tuple(contributions)))
    methods = []
    for run in selection.runs:
        values = [point.confirmed_yield for point in points if point.selector_id == run.selector_id]
        methods.append(SelectorMethodPoint(run.selector_id, run.model_id, len(values), sum(values) / len(values)))
    return tuple(points), tuple(methods)


def _pairs(methods, pairs):
    values = {item.selector_id: item.confirmed_yield for item in methods}
    return tuple(
        SelectorPairPoint(content_id("selector_pair_", {"left": left, "right": right}), left, right, values[left] - values[right])
        for left, right in pairs
    )


def _intervals(points, draws, plan):
    if not points:
        return (), None, "no_preregistered_selector_pairs"
    if len(draws) < math.ceil(plan.outer_draws * plan.minimum_valid_fraction):
        return (), None, "insufficient_valid_outer_draws"
    errors = {point.pair_id: statistics.stdev(draw[point.pair_id] for draw in draws) for point in points}
    evaluable = tuple(point for point in points if errors[point.pair_id] > 0.0)
    if not evaluable:
        return (), None, "zero_selector_pair_variance"
    maxima = [max(abs(draw[point.pair_id] - point.difference) / errors[point.pair_id] for point in evaluable) for draw in draws]
    critical = _q(maxima, 1.0 - plan.alpha)
    intervals = tuple(SelectorPairInterval(point.pair_id, errors[point.pair_id], max(-1.0, point.difference - critical * errors[point.pair_id]), min(1.0, point.difference + critical * errors[point.pair_id])) for point in evaluable)
    return intervals, critical, "complete" if len(evaluable) == len(points) else "partial_zero_variance"


def _stats(values):
    if not values:
        raise ValueError("independent verifier retained no task unit")
    point = sum(values) / len(values)
    error = 0.0 if len(values) < 2 else math.sqrt(sum((value - point) ** 2 for value in values) / (len(values) * (len(values) - 1)))
    return point, error


def _seed(seed, domain):
    return int(content_hash({"seed": seed, "domain": domain})[-16:], 16)


def _q(values, probability):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]


__all__ = ["verify_selector_result"]

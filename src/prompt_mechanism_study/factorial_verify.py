"""Independent recomputation of the pairwise factorial result.

This module deliberately does not import the production inference module.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from prompt_mechanism_study.intervention import FACTORIAL_CELL_ORDER, FactorialCell
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.records import content_id


def verify_factorial_inference(
    randomization: Any,
    outcomes: Iterable[Outcome],
    policies: Iterable[Any],
    tasks: Iterable[Any],
    plan: Any,
    reported: Any,
) -> dict[str, Any]:
    """Recompute assignment support, four cell means, delta, and max-|T| intervals."""

    assignments = tuple(randomization.assignments)
    frozen_outcomes = tuple(outcomes)
    outcome_by_id = {item.assignment_id: item for item in frozen_outcomes}
    if len(outcome_by_id) != len(frozen_outcomes) or set(outcome_by_id) != {
        item.assignment_id for item in assignments
    }:
        raise ValueError("independent verifier found incomplete or duplicate outcomes")
    policy_by_pair = {item.pair.pair_id: item for item in policies}
    task_by_id = {item.task_id: item for item in tasks}
    _verify_assignment_support(randomization, policy_by_pair)

    recomputed = []
    for estimate in reported.estimates:
        pair_id = estimate.pair_id
        model_id = estimate.model_id
        metric = _name(estimate.metric)
        policy = policy_by_pair.get(pair_id)
        if policy is None:
            raise ValueError("reported factorial pair is not frozen")
        coordinate_assignments = tuple(
            item
            for item in assignments
            if item.block.pair_id == pair_id and item.block.model_id == model_id
        )
        unit_ids = sorted({item.block.task_unit_id for item in coordinate_assignments})
        unit_rows = []
        for unit_id in unit_ids:
            cells = {
                cell: _unit_cell(
                    coordinate_assignments,
                    outcome_by_id,
                    policy,
                    task_by_id,
                    unit_id,
                    cell,
                    metric,
                )
                for cell in FACTORIAL_CELL_ORDER
            }
            points = {cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER}
            unit_rows.append(
                {
                    "task_unit_id": unit_id,
                    "cells": cells,
                    "interaction": _interaction(points),
                }
            )
        cell_rows = {
            cell: (
                _mean_or_none([row["cells"][cell][0] for row in unit_rows]),
                _mean([row["cells"][cell][1] for row in unit_rows]),
                _mean([row["cells"][cell][2] for row in unit_rows]),
                sum(item.cell is cell for item in coordinate_assignments),
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        points = {cell: cell_rows[cell][0] for cell in FACTORIAL_CELL_ORDER}
        expected = {
            "cells": cell_rows,
            "factor_1": _difference(points[FactorialCell.A10], points[FactorialCell.A00]),
            "factor_2": _difference(points[FactorialCell.A01], points[FactorialCell.A00]),
            "joint": _difference(points[FactorialCell.A11], points[FactorialCell.A00]),
            "interaction": _interaction(points),
            "interaction_bounds": _interaction_bounds(cell_rows),
            "unit_rows": unit_rows,
        }
        _verify_estimate(estimate, expected)
        recomputed.append((estimate, expected))

    intervals, critical = _bootstrap_intervals(recomputed, plan)
    _same(critical, reported.simultaneous_critical_value)
    stored_intervals = {item.coordinate_id: item for item in reported.intervals}
    if set(stored_intervals) != set(intervals):
        raise ValueError("independent verifier found interval coordinate drift")
    for coordinate_id, expected in intervals.items():
        stored = stored_intervals[coordinate_id]
        _same(expected[0], stored.standard_error)
        _same(expected[1], stored.lower)
        _same(expected[2], stored.upper)
    secondary, secondary_critical = _secondary_bootstrap_intervals(recomputed, plan)
    _same(secondary_critical, reported.secondary_critical_value)
    stored_secondary = {
        (item.coordinate_id, _name(item.effect)): item
        for item in reported.secondary_intervals
    }
    if set(stored_secondary) != set(secondary):
        raise ValueError("independent verifier found secondary interval drift")
    for key, expected in secondary.items():
        stored = stored_secondary[key]
        _same(expected[0], stored.standard_error)
        _same(expected[1], stored.lower)
        _same(expected[2], stored.upper)
    return {
        "status": "FACTORIAL_INFERENCE_VERIFIED",
        "assignments": len(assignments),
        "coordinates": len(recomputed),
        "primary_intervals": len(intervals),
        "secondary_intervals": len(secondary),
    }


def _verify_assignment_support(randomization: Any, policies: Mapping[str, Any]) -> None:
    expected_blocks = {}
    for policy in policies.values():
        for bundle in policy.bundles:
            for model_id in randomization.models:
                key = (
                    bundle.task_unit_id,
                    bundle.task_id,
                    policy.pair.pair_id,
                    policy.pair.pair_context_query_id,
                    bundle.realization_id,
                    bundle.task_bundle_id,
                    model_id,
                    policy.factorial_protocol_id,
                )
                expected_blocks[key] = bundle
    observed_blocks: dict[tuple[str, ...], list[Any]] = {}
    for assignment in randomization.assignments:
        block = assignment.block
        key = (
            block.task_unit_id,
            block.task_instance_id,
            block.pair_id,
            block.pair_context_query_id,
            block.joint_realization_id,
            block.factorial_task_bundle_id,
            block.model_id,
            block.factorial_protocol_id,
        )
        observed_blocks.setdefault(key, []).append(assignment)
    if set(observed_blocks) != set(expected_blocks):
        raise ValueError("independent verifier found factorial block support drift")
    for key, block in observed_blocks.items():
        bundle = expected_blocks[key]
        if len(block) != len(randomization.slots) or {item.request_slot for item in block} != set(
            randomization.slots
        ):
            raise ValueError("independent verifier found slot support drift")
        counts = Counter(item.cell for item in block)
        if set(counts) != set(FACTORIAL_CELL_ORDER) or len(set(counts.values())) != 1:
            raise ValueError("independent verifier found unbalanced factorial cells")
        if any(
            item.variant_sha256 != bundle.variant(item.cell).variant_sha256 for item in block
        ):
            raise ValueError("independent verifier found replaced prompt variant")


def _unit_cell(
    assignments: tuple[Any, ...],
    outcomes: Mapping[str, Outcome],
    policy: Any,
    tasks: Mapping[str, Any],
    task_unit_id: str,
    cell: FactorialCell,
    metric: str,
) -> tuple[float | None, float, float]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realization_total = sum(item.weight for item in policy.realizations)
    point = lower = upper = 0.0
    known = True
    for task_id in task_ids:
        for realization in policy.realizations:
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.joint_realization_id == realization.realization_id
                and item.cell is cell
            ]
            if not block:
                raise ValueError("independent verifier found missing task-realization cell")
            values = [_metric(outcomes[item.assignment_id], metric) for item in block]
            weight = tasks[task_id].weight / task_total * realization.weight / realization_total
            if any(value[0] is None for value in values):
                known = False
            else:
                point += weight * _mean([float(value[0]) for value in values])
            lower += weight * _mean([value[1] for value in values])
            upper += weight * _mean([value[2] for value in values])
    return point if known else None, lower, upper


def _metric(outcome: Outcome, metric: str) -> tuple[int | None, int, int]:
    if metric == "secure_yield":
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric == "joint":
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric)
    return (None, 0, 1) if value is None else (value, value, value)


def _verify_estimate(estimate: Any, expected: Mapping[str, Any]) -> None:
    stored_cells = {item.cell: item for item in estimate.cells}
    if set(stored_cells) != set(FACTORIAL_CELL_ORDER):
        raise ValueError("reported factorial cells are incomplete")
    for cell, values in expected["cells"].items():
        stored = stored_cells[cell]
        _same(values[0], stored.point)
        _same(values[1], stored.lower)
        _same(values[2], stored.upper)
        if values[3] != stored.assignments:
            raise ValueError("reported factorial assignment count drift")
    for name in ("factor_1", "factor_2", "joint", "interaction"):
        _same(expected[name], getattr(estimate, name))
    _same(expected["interaction_bounds"], estimate.interaction_bounds)
    stored_units = {item.task_unit_id: item for item in estimate.task_unit_effects}
    if set(stored_units) != {item["task_unit_id"] for item in expected["unit_rows"]}:
        raise ValueError("reported task-unit support drift")
    for row in expected["unit_rows"]:
        _same(row["interaction"], stored_units[row["task_unit_id"]].interaction)


def _bootstrap_intervals(
    rows: list[tuple[Any, Mapping[str, Any]]], plan: Any
) -> tuple[dict[str, tuple[float, float, float]], float]:
    eligible = [
        row
        for row in rows
        if _name(row[0].metric) == _name(plan.primary_metric)
        and row[0].interaction is not None
        and all(unit["interaction"] is not None for unit in row[1]["unit_rows"])
    ]
    if not eligible:
        return {}, 0.0
    support_by_coordinate = {
        estimate.coordinate_id: tuple(unit["task_unit_id"] for unit in expected["unit_rows"])
        for estimate, expected in eligible
    }
    rng_by_support = {
        support: random.Random(
            int(content_id("bootstrap_", {"seed": plan.bootstrap_seed, "support": support})[-16:], 16)
        )
        for support in set(support_by_coordinate.values())
    }
    draws = {estimate.coordinate_id: [] for estimate, _ in eligible}
    for _ in range(plan.bootstrap_draws):
        indexes = {
            support: [rng.randrange(len(support)) for _ in support]
            for support, rng in rng_by_support.items()
        }
        for estimate, expected in eligible:
            values = [unit["interaction"] for unit in expected["unit_rows"]]
            sample = indexes[support_by_coordinate[estimate.coordinate_id]]
            draws[estimate.coordinate_id].append(_mean([float(values[index]) for index in sample]))
    errors = {coordinate: statistics.stdev(values) for coordinate, values in draws.items()}
    maxima = []
    for draw in range(plan.bootstrap_draws):
        values = []
        for estimate, _ in eligible:
            error = errors[estimate.coordinate_id]
            if error > 0.0:
                values.append(
                    abs(draws[estimate.coordinate_id][draw] - float(estimate.interaction)) / error
                )
        maxima.append(max(values, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return {
        estimate.coordinate_id: (
            errors[estimate.coordinate_id],
            max(-2.0, float(estimate.interaction) - critical * errors[estimate.coordinate_id]),
            min(2.0, float(estimate.interaction) + critical * errors[estimate.coordinate_id]),
        )
        for estimate, _ in eligible
    }, critical


def _secondary_bootstrap_intervals(
    rows: list[tuple[Any, Mapping[str, Any]]], plan: Any
) -> tuple[dict[tuple[str, str], tuple[float, float, float]], float]:
    effects = tuple(_name(item) for item in plan.secondary_effects)
    eligible = [
        (estimate, expected, effect)
        for estimate, expected in rows
        if _name(estimate.metric) == _name(plan.primary_metric)
        for effect in effects
        if expected[effect] is not None
        and all(_unit_effect(unit, effect) is not None for unit in expected["unit_rows"])
    ]
    if not eligible:
        return {}, 0.0
    keys = [(estimate.coordinate_id, effect) for estimate, _, effect in eligible]
    support_by_key = {
        key: tuple(unit["task_unit_id"] for unit in expected["unit_rows"])
        for key, (_, expected, _) in zip(keys, eligible, strict=True)
    }
    rng_by_support = {
        support: random.Random(
            int(
                content_id(
                    "factorial_secondary_bootstrap_",
                    {"seed": plan.bootstrap_seed, "support": support},
                )[-16:],
                16,
            )
        )
        for support in set(support_by_key.values())
    }
    draws = {key: [] for key in keys}
    for _ in range(plan.bootstrap_draws):
        indexes = {
            support: [rng.randrange(len(support)) for _ in support]
            for support, rng in rng_by_support.items()
        }
        for key, (_, expected, effect) in zip(keys, eligible, strict=True):
            values = [_unit_effect(unit, effect) for unit in expected["unit_rows"]]
            sample = indexes[support_by_key[key]]
            draws[key].append(_mean([float(values[index]) for index in sample]))
    errors = {key: statistics.stdev(values) for key, values in draws.items()}
    maxima = []
    for draw in range(plan.bootstrap_draws):
        values = []
        for key, (_, expected, effect) in zip(keys, eligible, strict=True):
            error = errors[key]
            if error > 0.0:
                values.append(abs(draws[key][draw] - float(expected[effect])) / error)
        maxima.append(max(values, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return {
        key: (
            errors[key],
            max(-1.0, float(expected[effect]) - critical * errors[key]),
            min(1.0, float(expected[effect]) + critical * errors[key]),
        )
        for key, (_, expected, effect) in zip(keys, eligible, strict=True)
    }, critical


def _unit_effect(unit: Mapping[str, Any], effect: str) -> float | None:
    cells = unit["cells"]
    if effect == "factor_1":
        return _difference(cells[FactorialCell.A10][0], cells[FactorialCell.A00][0])
    if effect == "factor_2":
        return _difference(cells[FactorialCell.A01][0], cells[FactorialCell.A00][0])
    if effect == "joint":
        return _difference(cells[FactorialCell.A11][0], cells[FactorialCell.A00][0])
    return unit["interaction"]


def _interaction(values: Mapping[FactorialCell, float | None]) -> float | None:
    if any(values[cell] is None for cell in FACTORIAL_CELL_ORDER):
        return None
    return (
        float(values[FactorialCell.A11])
        - float(values[FactorialCell.A10])
        - float(values[FactorialCell.A01])
        + float(values[FactorialCell.A00])
    )


def _interaction_bounds(cells: Mapping[FactorialCell, tuple[Any, float, float, Any]]) -> tuple[float, float]:
    return (
        cells[FactorialCell.A11][1]
        - cells[FactorialCell.A10][2]
        - cells[FactorialCell.A01][2]
        + cells[FactorialCell.A00][1],
        cells[FactorialCell.A11][2]
        - cells[FactorialCell.A10][1]
        - cells[FactorialCell.A01][1]
        + cells[FactorialCell.A00][2],
    )


def _difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _mean_or_none(values: list[float | None]) -> float | None:
    return None if any(value is None for value in values) else _mean([float(value) for value in values])


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]


def _name(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _same(expected: Any, observed: Any) -> None:
    if isinstance(expected, tuple):
        if not isinstance(observed, tuple) or len(expected) != len(observed):
            raise ValueError("independent verifier found sequence drift")
        for left, right in zip(expected, observed, strict=True):
            _same(left, right)
    elif isinstance(expected, float):
        if not isinstance(observed, (int, float)) or not math.isclose(
            expected, observed, rel_tol=0.0, abs_tol=1e-12
        ):
            raise ValueError("independent verifier found numeric drift")
    elif expected != observed:
        raise ValueError("independent verifier found value drift")


__all__ = ["verify_factorial_inference"]

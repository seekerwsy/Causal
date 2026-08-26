"""Semantic-cluster weighted policy effects and simultaneous bootstrap intervals."""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Mapping

from prompt_mechanism_study.intervention import (
    FACTORIAL_CELL_ORDER,
    Arm,
    FactorialCell,
    FactorialPolicy,
    InterventionPolicy,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import (
    Assignment,
    FactorialAssignment,
    FactorialRandomization,
    Randomization,
)
from prompt_mechanism_study.records import content_id
from prompt_mechanism_study.representation import Task


class Metric(StrEnum):
    CODE_VALID = "code_valid"
    ORACLE_EVALUABLE = "oracle_evaluable"
    SECURE_YIELD = "secure_yield"
    FUNCTIONALITY = "functionality"
    JOINT = "joint"


class FactorialEffect(StrEnum):
    FACTOR_1 = "factor_1"
    FACTOR_2 = "factor_2"
    JOINT = "joint"
    INTERACTION = "interaction"


@dataclass(frozen=True, slots=True)
class AnalysisPlan:
    metrics: tuple[Metric, ...]
    bootstrap_seed: int
    bootstrap_draws: int
    alpha: float

    def __post_init__(self) -> None:
        if not self.metrics or len(self.metrics) != len(set(self.metrics)):
            raise ValueError("analysis metrics must be non-empty and unique")
        if any(type(metric) is not Metric for metric in self.metrics):
            raise TypeError("analysis metrics must be Metric values")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("bootstrap_draws must be at least 100")
        if type(self.alpha) is not float or not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be a float strictly between zero and one")

    @property
    def analysis_plan_id(self) -> str:
        return content_id("analysis_plan_", self)


@dataclass(frozen=True, slots=True)
class FactorialAnalysisPlan:
    metrics: tuple[Metric, ...]
    primary_metric: Metric
    bootstrap_seed: int
    bootstrap_draws: int
    alpha: float
    secondary_effects: tuple[FactorialEffect, ...] = (
        FactorialEffect.FACTOR_1,
        FactorialEffect.FACTOR_2,
        FactorialEffect.JOINT,
    )

    def __post_init__(self) -> None:
        if not self.metrics or len(self.metrics) != len(set(self.metrics)):
            raise ValueError("factorial analysis metrics must be non-empty and unique")
        if any(type(metric) is not Metric for metric in self.metrics):
            raise TypeError("factorial analysis metrics must be Metric values")
        if self.primary_metric is not Metric.SECURE_YIELD or self.primary_metric not in self.metrics:
            raise ValueError("factorial primary metric must be secure yield")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("bootstrap_draws must be at least 100")
        if type(self.alpha) is not float or not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be a float strictly between zero and one")
        if (
            not self.secondary_effects
            or len(self.secondary_effects) != len(set(self.secondary_effects))
            or any(
                type(effect) is not FactorialEffect
                or effect is FactorialEffect.INTERACTION
                for effect in self.secondary_effects
            )
        ):
            raise ValueError("secondary factorial effects must be unique non-interactions")

    @property
    def analysis_plan_id(self) -> str:
        return content_id("factorial_analysis_plan_", self)


@dataclass(frozen=True, slots=True)
class ArmEstimate:
    arm: Arm
    point: float | None
    lower: float
    upper: float
    assignments: int


@dataclass(frozen=True, slots=True)
class ClusterEffect:
    semantic_cluster_id: str
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class PolicyEstimate:
    candidate_id: str
    model_id: str
    metric: Metric
    target: ArmEstimate
    control: ArmEstimate
    difference: float | None
    lower: float
    upper: float
    cluster_effects: tuple[ClusterEffect, ...]

    @property
    def coordinate_id(self) -> str:
        return content_id(
            "coordinate_",
            {
                "candidate_id": self.candidate_id,
                "model_id": self.model_id,
                "metric": self.metric,
            },
        )


@dataclass(frozen=True, slots=True)
class SimultaneousInterval:
    coordinate_id: str
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class InferenceResult:
    plan_id: str
    estimates: tuple[PolicyEstimate, ...]
    intervals: tuple[SimultaneousInterval, ...]
    simultaneous_critical_value: float

    @property
    def inference_id(self) -> str:
        return content_id("inference_", self)


@dataclass(frozen=True, slots=True)
class FactorialCellEstimate:
    cell: FactorialCell
    point: float | None
    lower: float
    upper: float
    assignments: int


@dataclass(frozen=True, slots=True)
class TaskUnitFactorialEffect:
    task_unit_id: str
    cell_points: tuple[tuple[FactorialCell, float | None], ...]
    interaction: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialCoordinateEstimate:
    pair_id: str
    model_id: str
    metric: Metric
    cells: tuple[FactorialCellEstimate, ...]
    factor_1: float | None
    factor_2: float | None
    joint: float | None
    interaction: float | None
    factor_1_bounds: tuple[float, float]
    factor_2_bounds: tuple[float, float]
    joint_bounds: tuple[float, float]
    interaction_bounds: tuple[float, float]
    task_unit_effects: tuple[TaskUnitFactorialEffect, ...]

    @property
    def coordinate_id(self) -> str:
        return content_id(
            "factorial_coordinate_",
            {"pair_id": self.pair_id, "model_id": self.model_id, "metric": self.metric},
        )


@dataclass(frozen=True, slots=True)
class FactorialSimultaneousInterval:
    coordinate_id: str
    effect: FactorialEffect
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialInferenceResult:
    plan_id: str
    estimates: tuple[FactorialCoordinateEstimate, ...]
    intervals: tuple[FactorialSimultaneousInterval, ...]
    simultaneous_critical_value: float
    secondary_intervals: tuple[FactorialSimultaneousInterval, ...] = ()
    secondary_critical_value: float = 0.0

    @property
    def inference_id(self) -> str:
        return content_id("factorial_inference_", self)


def estimate_policy_effects(
    randomization: Randomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[InterventionPolicy],
    tasks: Iterable[Task],
    plan: AnalysisPlan,
) -> InferenceResult:
    frozen_outcomes = tuple(outcomes)
    by_outcome = {item.assignment_id: item for item in frozen_outcomes}
    expected = {item.assignment_id for item in randomization.assignments}
    if len(by_outcome) != len(frozen_outcomes) or set(by_outcome) != expected:
        raise ValueError("outcomes must cover every randomized assignment exactly once")
    task_by_id = {item.task_id: item for item in tasks}
    policy_by_candidate = {item.candidate_id: item for item in policies}
    estimates = tuple(
        _coordinate(
            randomization,
            by_outcome,
            policy_by_candidate[candidate_id],
            task_by_id,
            model_id,
            metric,
        )
        for candidate_id in sorted(policy_by_candidate)
        for model_id in randomization.models
        for metric in plan.metrics
    )
    _common_cluster_support(estimates)
    intervals, critical = _simultaneous_intervals(estimates, plan)
    return InferenceResult(plan.analysis_plan_id, estimates, intervals, critical)


def estimate_factorial_effects(
    randomization: FactorialRandomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[FactorialPolicy],
    tasks: Iterable[Task],
    plan: FactorialAnalysisPlan,
) -> FactorialInferenceResult:
    """Estimate four-cell task-unit ITT effects without diagnostic filtering."""

    frozen_outcomes = tuple(outcomes)
    by_outcome = {item.assignment_id: item for item in frozen_outcomes}
    expected = {item.assignment_id for item in randomization.assignments}
    if len(by_outcome) != len(frozen_outcomes) or set(by_outcome) != expected:
        raise ValueError("outcomes must cover every factorial assignment exactly once")
    task_by_id = {item.task_id: item for item in tasks}
    frozen_policies = tuple(policies)
    policy_by_pair = {item.pair.pair_id: item for item in frozen_policies}
    if len(policy_by_pair) != len(frozen_policies):
        raise ValueError("factorial policies must bind unique pair IDs")
    estimates = tuple(
        _factorial_coordinate(
            randomization,
            by_outcome,
            policy_by_pair[pair_id],
            task_by_id,
            model_id,
            metric,
        )
        for pair_id in sorted(policy_by_pair)
        for model_id in randomization.models
        for metric in plan.metrics
    )
    _validate_factorial_support(estimates)
    intervals, critical = _factorial_simultaneous_intervals(estimates, plan)
    secondary, secondary_critical = _factorial_secondary_intervals(estimates, plan)
    return FactorialInferenceResult(
        plan.analysis_plan_id,
        estimates,
        intervals,
        critical,
        secondary,
        secondary_critical,
    )


def _factorial_coordinate(
    randomization: FactorialRandomization,
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    model_id: str,
    metric: Metric,
) -> FactorialCoordinateEstimate:
    assignments = tuple(
        item
        for item in randomization.assignments
        if item.block.pair_id == policy.pair.pair_id and item.block.model_id == model_id
    )
    task_unit_ids = sorted({item.block.task_unit_id for item in assignments})
    if not task_unit_ids:
        raise ValueError("factorial analysis coordinate has no randomized assignments")
    unit_cells: dict[str, dict[FactorialCell, tuple[float | None, float, float, int]]] = {}
    unit_effects: list[TaskUnitFactorialEffect] = []
    for task_unit_id in task_unit_ids:
        cells = {
            cell: _task_unit_cell(
                assignments, outcomes, policy, tasks, task_unit_id, cell, metric
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        unit_cells[task_unit_id] = cells
        points = {cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER}
        interaction = _interaction(points)
        lower, upper = _interaction_bounds(cells)
        unit_effects.append(
            TaskUnitFactorialEffect(
                task_unit_id,
                tuple((cell, points[cell]) for cell in FACTORIAL_CELL_ORDER),
                interaction,
                lower,
                upper,
            )
        )
    cell_estimates = tuple(
        _factorial_cell_estimate(assignments, cell, [unit_cells[unit][cell] for unit in task_unit_ids])
        for cell in FACTORIAL_CELL_ORDER
    )
    means = {item.cell: item.point for item in cell_estimates}
    lower = {item.cell: item.lower for item in cell_estimates}
    upper = {item.cell: item.upper for item in cell_estimates}
    return FactorialCoordinateEstimate(
        policy.pair.pair_id,
        model_id,
        metric,
        cell_estimates,
        _difference(means[FactorialCell.A10], means[FactorialCell.A00]),
        _difference(means[FactorialCell.A01], means[FactorialCell.A00]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A00]),
        _interaction(means),
        (lower[FactorialCell.A10] - upper[FactorialCell.A00], upper[FactorialCell.A10] - lower[FactorialCell.A00]),
        (lower[FactorialCell.A01] - upper[FactorialCell.A00], upper[FactorialCell.A01] - lower[FactorialCell.A00]),
        (lower[FactorialCell.A11] - upper[FactorialCell.A00], upper[FactorialCell.A11] - lower[FactorialCell.A00]),
        _interaction_bounds({cell: (None, lower[cell], upper[cell], 0) for cell in FACTORIAL_CELL_ORDER}),
        tuple(unit_effects),
    )


def _task_unit_cell(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    cell: FactorialCell,
    metric: Metric,
) -> tuple[float | None, float, float, int]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise ValueError("factorial task unit lacks frozen task records")
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realization_total = sum(item.weight for item in policy.realizations)
    point = lower = upper = 0.0
    point_known = True
    count = 0
    for task_id in task_ids:
        task_weight = tasks[task_id].weight / task_total
        for realization in policy.realizations:
            realization_weight = realization.weight / realization_total
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.joint_realization_id == realization.realization_id
                and item.cell is cell
            ]
            if not block:
                raise ValueError("factorial randomization lacks common task-realization support")
            values = [_metric_value(outcomes[item.assignment_id], metric) for item in block]
            count += len(block)
            weight = task_weight * realization_weight
            if any(value[0] is None for value in values):
                point_known = False
            else:
                point += weight * sum(value[0] for value in values if value[0] is not None) / len(values)
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return point if point_known else None, lower, upper, count


def _factorial_cell_estimate(
    assignments: tuple[FactorialAssignment, ...],
    cell: FactorialCell,
    units: list[tuple[float | None, float, float, int]],
) -> FactorialCellEstimate:
    point = None if any(item[0] is None for item in units) else sum(
        item[0] for item in units if item[0] is not None
    ) / len(units)
    return FactorialCellEstimate(
        cell,
        point,
        sum(item[1] for item in units) / len(units),
        sum(item[2] for item in units) / len(units),
        sum(item.cell is cell for item in assignments),
    )


def _difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _interaction(values: Mapping[FactorialCell, float | None]) -> float | None:
    if any(values[cell] is None for cell in FACTORIAL_CELL_ORDER):
        return None
    return (
        float(values[FactorialCell.A11])
        - float(values[FactorialCell.A10])
        - float(values[FactorialCell.A01])
        + float(values[FactorialCell.A00])
    )


def _interaction_bounds(
    cells: Mapping[FactorialCell, tuple[float | None, float, float, int]],
) -> tuple[float, float]:
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


def _validate_factorial_support(
    estimates: tuple[FactorialCoordinateEstimate, ...],
) -> None:
    supports = {
        estimate.coordinate_id: {item.task_unit_id for item in estimate.task_unit_effects}
        for estimate in estimates
        if estimate.metric is Metric.SECURE_YIELD
    }
    values = list(supports.values())
    for index, left in enumerate(values):
        for right in values[index + 1 :]:
            if left & right and left != right:
                raise ValueError("primary factorial coordinates must have identical or disjoint task-unit support")


def _factorial_simultaneous_intervals(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    eligible = tuple(
        item
        for item in estimates
        if item.metric is plan.primary_metric
        and item.interaction is not None
        and all(unit.interaction is not None for unit in item.task_unit_effects)
    )
    if not eligible:
        return (), 0.0
    support_keys = {
        item.coordinate_id: tuple(unit.task_unit_id for unit in item.task_unit_effects)
        for item in eligible
    }
    rng_by_support: dict[tuple[str, ...], random.Random] = {}
    replicates: dict[str, list[float]] = {item.coordinate_id: [] for item in eligible}
    for support in set(support_keys.values()):
        seed = int(content_id("bootstrap_", {"seed": plan.bootstrap_seed, "support": support})[-16:], 16)
        rng_by_support[support] = random.Random(seed)
    for _ in range(plan.bootstrap_draws):
        samples: dict[tuple[str, ...], list[int]] = {}
        for support, rng in rng_by_support.items():
            samples[support] = [rng.randrange(len(support)) for _ in support]
        for estimate in eligible:
            sample = samples[support_keys[estimate.coordinate_id]]
            effects = [estimate.task_unit_effects[index].interaction for index in sample]
            replicates[estimate.coordinate_id].append(
                sum(float(value) for value in effects) / len(effects)
            )
    standard_errors = {
        item.coordinate_id: statistics.stdev(replicates[item.coordinate_id])
        for item in eligible
    }
    maxima = []
    for draw in range(plan.bootstrap_draws):
        statistics_for_draw = []
        for estimate in eligible:
            standard_error = standard_errors[estimate.coordinate_id]
            if standard_error > 0.0:
                statistics_for_draw.append(
                    abs(replicates[estimate.coordinate_id][draw] - float(estimate.interaction))
                    / standard_error
                )
        maxima.append(max(statistics_for_draw, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        FactorialSimultaneousInterval(
            item.coordinate_id,
            FactorialEffect.INTERACTION,
            standard_errors[item.coordinate_id],
            max(-2.0, float(item.interaction) - critical * standard_errors[item.coordinate_id]),
            min(2.0, float(item.interaction) + critical * standard_errors[item.coordinate_id]),
        )
        for item in eligible
    )
    return intervals, critical


def _factorial_secondary_intervals(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    """Max-|T| intervals for the preregistered secure-yield main/joint family."""

    eligible = tuple(
        (estimate, effect)
        for estimate in estimates
        if estimate.metric is plan.primary_metric
        for effect in plan.secondary_effects
        if _factorial_effect(estimate, effect) is not None
        and all(
            _task_unit_factorial_effect(unit, effect) is not None
            for unit in estimate.task_unit_effects
        )
    )
    if not eligible:
        return (), 0.0
    keys = tuple((estimate.coordinate_id, effect) for estimate, effect in eligible)
    support_by_key = {
        key: tuple(unit.task_unit_id for unit in estimate.task_unit_effects)
        for key, (estimate, _) in zip(keys, eligible, strict=True)
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
    replicates: dict[tuple[str, FactorialEffect], list[float]] = {
        key: [] for key in keys
    }
    for _ in range(plan.bootstrap_draws):
        samples = {
            support: [rng.randrange(len(support)) for _ in support]
            for support, rng in rng_by_support.items()
        }
        for key, (estimate, effect) in zip(keys, eligible, strict=True):
            values = [
                _task_unit_factorial_effect(unit, effect)
                for unit in estimate.task_unit_effects
            ]
            sample = samples[support_by_key[key]]
            replicates[key].append(
                sum(float(values[index]) for index in sample) / len(sample)
            )
    errors = {key: statistics.stdev(values) for key, values in replicates.items()}
    maxima = []
    for draw in range(plan.bootstrap_draws):
        values = []
        for key, (estimate, effect) in zip(keys, eligible, strict=True):
            error = errors[key]
            if error > 0.0:
                values.append(
                    abs(
                        replicates[key][draw]
                        - float(_factorial_effect(estimate, effect))
                    )
                    / error
                )
        maxima.append(max(values, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = []
    for key, (estimate, effect) in zip(keys, eligible, strict=True):
        point = float(_factorial_effect(estimate, effect))
        error = errors[key]
        lower_limit, upper_limit = _factorial_effect_limits(effect)
        intervals.append(
            FactorialSimultaneousInterval(
                estimate.coordinate_id,
                effect,
                error,
                max(lower_limit, point - critical * error),
                min(upper_limit, point + critical * error),
            )
        )
    return tuple(intervals), critical


def _factorial_effect(
    estimate: FactorialCoordinateEstimate,
    effect: FactorialEffect,
) -> float | None:
    return getattr(estimate, effect.value)


def _task_unit_factorial_effect(
    unit: TaskUnitFactorialEffect,
    effect: FactorialEffect,
) -> float | None:
    cells = dict(unit.cell_points)
    if effect is FactorialEffect.FACTOR_1:
        return _difference(cells[FactorialCell.A10], cells[FactorialCell.A00])
    if effect is FactorialEffect.FACTOR_2:
        return _difference(cells[FactorialCell.A01], cells[FactorialCell.A00])
    if effect is FactorialEffect.JOINT:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A00])
    return unit.interaction


def _factorial_effect_limits(effect: FactorialEffect) -> tuple[float, float]:
    return (-2.0, 2.0) if effect is FactorialEffect.INTERACTION else (-1.0, 1.0)


def _coordinate(
    randomization: Randomization,
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicy,
    tasks: Mapping[str, Task],
    model_id: str,
    metric: Metric,
) -> PolicyEstimate:
    assignments = tuple(
        item
        for item in randomization.assignments
        if item.block.candidate_id == policy.candidate_id and item.block.model_id == model_id
    )
    cluster_ids = sorted({item.block.semantic_cluster_id for item in assignments})
    if not cluster_ids:
        raise ValueError("analysis coordinate has no randomized assignments")
    target_clusters: list[tuple[float | None, float, float]] = []
    control_clusters: list[tuple[float | None, float, float]] = []
    cluster_effects: list[ClusterEffect] = []
    for cluster_id in cluster_ids:
        target = _cluster_arm(
            assignments,
            outcomes,
            policy,
            tasks,
            cluster_id,
            Arm.TARGET,
            metric,
        )
        control = _cluster_arm(
            assignments,
            outcomes,
            policy,
            tasks,
            cluster_id,
            Arm.NOOP,
            metric,
        )
        target_clusters.append(target)
        control_clusters.append(control)
        point = None if target[0] is None or control[0] is None else target[0] - control[0]
        cluster_effects.append(
            ClusterEffect(cluster_id, point, target[1] - control[2], target[2] - control[1])
        )
    target = _arm_estimate(assignments, Arm.TARGET, target_clusters)
    control = _arm_estimate(assignments, Arm.NOOP, control_clusters)
    point = None if target.point is None or control.point is None else target.point - control.point
    return PolicyEstimate(
        policy.candidate_id,
        model_id,
        metric,
        target,
        control,
        point,
        target.lower - control.upper,
        target.upper - control.lower,
        tuple(cluster_effects),
    )


def _cluster_arm(
    assignments: tuple[Assignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicy,
    tasks: Mapping[str, Task],
    cluster_id: str,
    arm: Arm,
    metric: Metric,
) -> tuple[float | None, float, float]:
    cluster_tasks = sorted(
        {item.block.task_id for item in assignments if item.block.semantic_cluster_id == cluster_id}
    )
    task_total = sum(tasks[task_id].weight for task_id in cluster_tasks)
    realization_total = sum(item.weight for item in policy.realizations)
    point = 0.0
    lower = 0.0
    upper = 0.0
    point_known = True
    for task_id in cluster_tasks:
        task_weight = tasks[task_id].weight / task_total
        for realization in policy.realizations:
            realization_weight = realization.weight / realization_total
            block = [
                item
                for item in assignments
                if item.block.semantic_cluster_id == cluster_id
                and item.block.task_id == task_id
                and item.block.realization_id == realization.realization_id
                and item.arm is arm
            ]
            if not block:
                raise ValueError("randomization lacks common task-realization support")
            values = [_metric_value(outcomes[item.assignment_id], metric) for item in block]
            block_point = (
                None
                if any(value[0] is None for value in values)
                else sum(value[0] for value in values if value[0] is not None) / len(values)
            )
            weight = task_weight * realization_weight
            if block_point is None:
                point_known = False
            else:
                point += weight * block_point
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return (point if point_known else None, lower, upper)


def _metric_value(outcome: Outcome, metric: Metric) -> tuple[int | None, int, int]:
    if metric is Metric.SECURE_YIELD:
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric is Metric.JOINT:
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric.value)
    if value is None:
        return None, 0, 1
    return value, value, value


def _arm_estimate(
    assignments: tuple[Assignment, ...],
    arm: Arm,
    clusters: list[tuple[float | None, float, float]],
) -> ArmEstimate:
    point = (
        None
        if any(item[0] is None for item in clusters)
        else sum(item[0] for item in clusters if item[0] is not None) / len(clusters)
    )
    return ArmEstimate(
        arm,
        point,
        sum(item[1] for item in clusters) / len(clusters),
        sum(item[2] for item in clusters) / len(clusters),
        sum(item.arm is arm for item in assignments),
    )


def _common_cluster_support(estimates: tuple[PolicyEstimate, ...]) -> None:
    supports = {
        tuple(item.semantic_cluster_id for item in estimate.cluster_effects)
        for estimate in estimates
    }
    if len(supports) != 1:
        raise ValueError("all analysis coordinates require common semantic-cluster support")


def _simultaneous_intervals(
    estimates: tuple[PolicyEstimate, ...],
    plan: AnalysisPlan,
) -> tuple[tuple[SimultaneousInterval, ...], float]:
    eligible = tuple(
        item
        for item in estimates
        if item.difference is not None
        and all(cluster.point is not None for cluster in item.cluster_effects)
    )
    if not eligible:
        return (), 0.0
    cluster_count = len(eligible[0].cluster_effects)
    rng = random.Random(plan.bootstrap_seed)
    replicates: dict[str, list[float]] = {item.coordinate_id: [] for item in eligible}
    for _ in range(plan.bootstrap_draws):
        sample = [rng.randrange(cluster_count) for _ in range(cluster_count)]
        for estimate in eligible:
            effects = [estimate.cluster_effects[index].point for index in sample]
            replicates[estimate.coordinate_id].append(
                sum(value for value in effects if value is not None) / cluster_count
            )
    standard_errors = {
        item.coordinate_id: statistics.stdev(replicates[item.coordinate_id]) for item in eligible
    }
    maxima: list[float] = []
    for draw in range(plan.bootstrap_draws):
        values = []
        for estimate in eligible:
            standard_error = standard_errors[estimate.coordinate_id]
            if standard_error > 0.0:
                values.append(
                    abs(replicates[estimate.coordinate_id][draw] - estimate.difference)
                    / standard_error
                )
        maxima.append(max(values, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SimultaneousInterval(
            item.coordinate_id,
            standard_errors[item.coordinate_id],
            max(-1.0, item.difference - critical * standard_errors[item.coordinate_id]),
            min(1.0, item.difference + critical * standard_errors[item.coordinate_id]),
        )
        for item in eligible
    )
    return intervals, critical


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


__all__ = [
    "AnalysisPlan",
    "ArmEstimate",
    "ClusterEffect",
    "FactorialAnalysisPlan",
    "FactorialCellEstimate",
    "FactorialCoordinateEstimate",
    "FactorialEffect",
    "FactorialInferenceResult",
    "FactorialSimultaneousInterval",
    "InferenceResult",
    "Metric",
    "PolicyEstimate",
    "SimultaneousInterval",
    "estimate_policy_effects",
    "estimate_factorial_effects",
]

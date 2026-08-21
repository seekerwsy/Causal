"""Semantic-cluster weighted policy effects and simultaneous bootstrap intervals."""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Mapping

from prompt_mechanism_study.intervention import Arm, InterventionPolicy
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import Assignment, Randomization
from prompt_mechanism_study.records import content_id
from prompt_mechanism_study.representation import Task


class Metric(StrEnum):
    CODE_VALID = "code_valid"
    ORACLE_EVALUABLE = "oracle_evaluable"
    SECURE_YIELD = "secure_yield"
    FUNCTIONALITY = "functionality"
    JOINT = "joint"


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
    "InferenceResult",
    "Metric",
    "PolicyEstimate",
    "SimultaneousInterval",
    "estimate_policy_effects",
]

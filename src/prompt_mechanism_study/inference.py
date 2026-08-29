"""Task-unit ITT and simultaneous inference for active successor studies."""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from prompt_mechanism_study.intervention import (
    FACTORIAL_CELL_ORDER,
    SUCCESSOR_ARM_ROLE_ORDER,
    FactorialCell,
    FactorialPolicy,
    InterventionPolicyV2,
    PolicyArmRoleV2,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import (
    FactorialAssignment,
    FactorialRandomization,
    SuccessorAssignment,
    SuccessorRandomization,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import ExpectedDirection, Task


class Metric(StrEnum):
    CODE_VALID = "code_valid"
    ORACLE_EVALUABLE = "oracle_evaluable"
    SECURE_YIELD = "secure_yield"
    FUNCTIONALITY = "functionality"
    JOINT = "joint"


class FactorialEffect(StrEnum):
    FACTOR_1 = "factor_1"
    FACTOR_2 = "factor_2"
    FACTOR_1_GIVEN_FACTOR_2 = "factor_1_given_factor_2"
    FACTOR_2_GIVEN_FACTOR_1 = "factor_2_given_factor_1"
    JOINT = "joint"
    INTERACTION = "interaction"


class FactorialPattern(StrEnum):
    """Descriptive response-surface patterns; never an assignment filter."""

    ADDITIVE = "additive"
    POSITIVE_INTERACTION = "positive_interaction"
    NEGATIVE_INTERACTION = "negative_interaction"
    XOR = "xor"
    REDUNDANT = "redundant"
    PREREQUISITE = "prerequisite"
    REVERSAL = "reversal"
    NOT_EVALUABLE = "not_evaluable"


class FactorialMetricFamily(StrEnum):
    """Separate multiplicity families for distinct scientific endpoints."""

    FUNCTIONALITY = "functionality"
    JOINT = "joint"


class SuccessorContrast(StrEnum):
    """Frozen four-arm contrasts; only Target-Noop is confirmatory primary."""

    TARGET_NOOP = "target_minus_noop"
    TARGET_PLACEBO = "target_minus_placebo"
    TARGET_GENERIC = "target_minus_generic"

    @property
    def roles(self) -> tuple[PolicyArmRoleV2, PolicyArmRoleV2]:
        return {
            SuccessorContrast.TARGET_NOOP: (
                PolicyArmRoleV2.TARGET,
                PolicyArmRoleV2.NOOP,
            ),
            SuccessorContrast.TARGET_PLACEBO: (
                PolicyArmRoleV2.TARGET,
                PolicyArmRoleV2.PLACEBO,
            ),
            SuccessorContrast.TARGET_GENERIC: (
                PolicyArmRoleV2.TARGET,
                PolicyArmRoleV2.GENERIC,
            ),
        }[self]


class SuccessorIntervalFamily(StrEnum):
    PRIMARY_SECURITY = "primary_target_noop_secure_yield"
    SECURITY_SPECIFICITY = "target_specificity_secure_yield"
    JOINT_OUTCOME = "target_noop_joint_outcome"


class FamilyInferenceStatus(StrEnum):
    EVALUABLE = "evaluable"
    NO_ELIGIBLE_COORDINATES = "no_eligible_coordinates"
    ZERO_STANDARD_ERROR = "zero_standard_error"
    INSUFFICIENT_VALID_BOOTSTRAP = "insufficient_valid_bootstrap"


class SuccessorRobustnessComponent(StrEnum):
    """Members of the frozen global realization-robustness family."""

    REALIZATION = "realization"
    LEAVE_ONE_REALIZATION_OUT = "leave_one_realization_out"


class FunctionalityGateStatus(StrEnum):
    """Status of the optional, separately powered functionality gate."""

    NOT_REQUESTED = "not_requested"
    NOT_EVALUABLE = "not_evaluable"
    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SuccessorAnalysisPlan:
    """Pre-outcome analysis contract for atomic ADD/REMOVE four-arm policies."""

    metrics: tuple[Metric, ...]
    primary_metric: Metric
    bootstrap_seed: int
    bootstrap_draws: int
    alpha: float
    minimum_task_units: int = 2
    minimum_valid_bootstrap_fraction: float = 0.9
    practical_effect_margin: float = 0.0
    functionality_noninferiority_margin: float = 0.1
    minimum_realizations: int = 2
    minimum_task_units_per_realization: int = 2
    realization_practical_equivalence_margin: float = 0.1
    realization_direction_consistency_threshold: float = 1.0
    functionality_noninferiority_separately_powered: bool = False
    minimum_replication_models: int = 2
    cross_model_replication_rule: str = (
        "oriented_simultaneous_target_noop_each_model_no_pooling"
    )

    def __post_init__(self) -> None:
        if not self.metrics or len(self.metrics) != len(set(self.metrics)):
            raise ValueError("successor analysis metrics must be non-empty and unique")
        if any(type(metric) is not Metric for metric in self.metrics):
            raise TypeError("successor analysis metrics must be Metric values")
        if self.primary_metric is not Metric.SECURE_YIELD or self.primary_metric not in self.metrics:
            raise ValueError("successor primary metric must be secure yield")
        if Metric.JOINT not in self.metrics or Metric.FUNCTIONALITY not in self.metrics:
            raise ValueError("successor analysis requires joint and functionality diagnostics")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("bootstrap_draws must be at least 100")
        if type(self.alpha) is not float or not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be a float strictly between zero and one")
        if type(self.minimum_task_units) is not int or self.minimum_task_units < 2:
            raise ValueError("minimum_task_units must be at least two")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0.0 < self.minimum_valid_bootstrap_fraction <= 1.0
        ):
            raise ValueError("minimum_valid_bootstrap_fraction must be in (0, 1]")
        for name in (
            "practical_effect_margin",
            "functionality_noninferiority_margin",
            "realization_practical_equivalence_margin",
            "realization_direction_consistency_threshold",
        ):
            value = getattr(self, name)
            if type(value) is not float or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be a float in [0, 1]")
        if type(self.minimum_realizations) is not int or self.minimum_realizations < 2:
            raise ValueError("minimum_realizations must be at least two")
        if (
            type(self.minimum_task_units_per_realization) is not int
            or self.minimum_task_units_per_realization < 2
        ):
            raise ValueError(
                "minimum_task_units_per_realization must be at least two"
            )
        if type(self.functionality_noninferiority_separately_powered) is not bool:
            raise TypeError(
                "functionality_noninferiority_separately_powered must be boolean"
            )
        if type(self.minimum_replication_models) is not int or self.minimum_replication_models < 2:
            raise ValueError("minimum_replication_models must be at least two")
        if self.cross_model_replication_rule != (
            "oriented_simultaneous_target_noop_each_model_no_pooling"
        ):
            raise ValueError("unsupported successor cross-model replication rule")
        if self.realization_direction_consistency_threshold <= 0.0:
            raise ValueError(
                "realization_direction_consistency_threshold must be in (0, 1]"
            )

    @property
    def analysis_plan_id(self) -> str:
        return content_id("successor_analysis_plan_v2_", self)


@dataclass(frozen=True, slots=True)
class FactorialAnalysisPlan:
    """Prospectively frozen factorial inference contract."""

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
    minimum_task_units: int = 2
    minimum_valid_bootstrap_fraction: float = 0.9
    bootstrap_quantile_method: str = "higher"
    practical_interaction_margin: float = 0.0
    maximum_unknown_fraction: float = 1.0
    functionality_noninferiority_margin: float = 0.1
    functionality_noninferiority_separately_powered: bool = False
    functionality_power_qualification_sha256: str | None = None

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
        if type(self.minimum_task_units) is not int or self.minimum_task_units < 2:
            raise ValueError("factorial minimum_task_units must be at least two")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0.0 < self.minimum_valid_bootstrap_fraction <= 1.0
        ):
            raise ValueError(
                "factorial minimum_valid_bootstrap_fraction must be in (0, 1]"
            )
        if self.bootstrap_quantile_method != "higher":
            raise ValueError("factorial bootstrap quantile method must be higher")
        for name in (
            "practical_interaction_margin",
            "maximum_unknown_fraction",
            "functionality_noninferiority_margin",
        ):
            value = getattr(self, name)
            if type(value) is not float or not 0.0 <= value <= 1.0:
                raise ValueError(f"factorial {name} must be a float in [0, 1]")
        if type(self.functionality_noninferiority_separately_powered) is not bool:
            raise TypeError(
                "factorial functionality_noninferiority_separately_powered must be boolean"
            )
        qualification = self.functionality_power_qualification_sha256
        if self.functionality_noninferiority_separately_powered:
            if (
                not isinstance(qualification, str)
                or len(qualification) != 64
                or any(character not in "0123456789abcdef" for character in qualification)
            ):
                raise ValueError(
                    "a separately powered functionality gate requires a frozen power qualification"
                )
        elif qualification is not None:
            raise ValueError(
                "an unrequested functionality gate cannot bind a power qualification"
            )

    @property
    def analysis_plan_id(self) -> str:
        return content_id("factorial_analysis_plan_v2_", self)


@dataclass(frozen=True, slots=True)
class SuccessorArmEstimate:
    role: PolicyArmRoleV2
    point: float | None
    lower: float
    upper: float
    assignments: int


@dataclass(frozen=True, slots=True)
class SuccessorContrastEstimate:
    contrast: SuccessorContrast
    point: float | None
    lower_bound: float
    upper_bound: float


@dataclass(frozen=True, slots=True)
class TaskUnitSuccessorContribution:
    task_unit_id: str
    arm_values: tuple[tuple[PolicyArmRoleV2, float | None, float, float], ...]
    contrast_values: tuple[tuple[SuccessorContrast, float | None, float, float], ...]

    def contrast(self, value: SuccessorContrast) -> tuple[float | None, float, float]:
        return next((point, lower, upper) for item, point, lower, upper in self.contrast_values if item is value)


@dataclass(frozen=True, slots=True)
class RealizationSuccessorEffect:
    realization_spec_id: str
    point: float | None
    lower_bound: float
    upper_bound: float
    task_unit_effects: tuple[tuple[str, float | None, float, float], ...] = ()


@dataclass(frozen=True, slots=True)
class LeaveOneRealizationOutSuccessorEffect:
    omitted_realization_spec_id: str
    point: float | None
    lower_bound: float
    upper_bound: float
    task_unit_effects: tuple[tuple[str, float | None, float, float], ...] = ()


@dataclass(frozen=True, slots=True)
class SuccessorCoordinateEstimate:
    hypothesis_id: str
    model_id: str
    metric: Metric
    expected_direction: ExpectedDirection
    arms: tuple[SuccessorArmEstimate, ...]
    contrasts: tuple[SuccessorContrastEstimate, ...]
    task_unit_contributions: tuple[TaskUnitSuccessorContribution, ...]
    realization_effects: tuple[RealizationSuccessorEffect, ...]
    robustness_label: str
    leave_one_realization_out: tuple[
        LeaveOneRealizationOutSuccessorEffect, ...
    ] = ()

    def __post_init__(self) -> None:
        if tuple(item.role for item in self.arms) != SUCCESSOR_ARM_ROLE_ORDER:
            raise ValueError("successor arm estimates must use canonical four-role order")
        if tuple(item.contrast for item in self.contrasts) != tuple(SuccessorContrast):
            raise ValueError("successor contrasts must use canonical order")

    @property
    def coordinate_id(self) -> str:
        return content_id(
            "successor_coordinate_v2_",
            {
                "hypothesis_id": self.hypothesis_id,
                "model_id": self.model_id,
                "metric": self.metric,
            },
        )

    def contrast(self, value: SuccessorContrast) -> SuccessorContrastEstimate:
        return next(item for item in self.contrasts if item.contrast is value)


@dataclass(frozen=True, slots=True)
class SuccessorSimultaneousInterval:
    coordinate_id: str
    contrast: SuccessorContrast
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class SuccessorFamilyInference:
    family: SuccessorIntervalFamily
    status: FamilyInferenceStatus
    simultaneous_critical_value: float | None
    valid_bootstrap_draws: int
    invalid_bootstrap_draws: int
    intervals: tuple[SuccessorSimultaneousInterval, ...]


@dataclass(frozen=True, slots=True)
class SuccessorRobustnessInterval:
    coordinate_id: str
    component: SuccessorRobustnessComponent
    realization_spec_id: str
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class SuccessorRobustnessAssessment:
    coordinate_id: str
    direction_consistency_proportion: float | None
    direction_consistency_passed: bool
    simultaneous_direction_passed: bool
    minimum_support_passed: bool
    heterogeneity_max_deviation: float | None
    heterogeneity_simultaneous_upper: float | None
    heterogeneity_equivalence_passed: bool
    arm_realization_interaction_statistic: float | None
    arm_realization_randomization_p_value: float | None
    arm_realization_interaction_passed: bool
    functionality_gate_status: FunctionalityGateStatus
    functionality_point: float | None
    functionality_simultaneous_lower: float | None
    robustness_label: str
    practical_success_label: str


@dataclass(frozen=True, slots=True)
class SuccessorRobustnessInference:
    status: FamilyInferenceStatus
    simultaneous_critical_value: float | None
    valid_bootstrap_draws: int
    invalid_bootstrap_draws: int
    intervals: tuple[SuccessorRobustnessInterval, ...]
    functionality_simultaneous_critical_value: float | None
    assessments: tuple[SuccessorRobustnessAssessment, ...]


@dataclass(frozen=True, slots=True)
class SuccessorInferenceResult:
    plan_id: str
    estimates: tuple[SuccessorCoordinateEstimate, ...]
    families: tuple[SuccessorFamilyInference, ...]
    robustness: SuccessorRobustnessInference | None = None

    @property
    def inference_id(self) -> str:
        return content_id("successor_inference_v2_", self)


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
class FactorialRealizationInteraction:
    realization_id: str
    application_order: tuple[int, int]
    weight: int
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialOrderInteraction:
    application_order: tuple[int, int]
    total_weight: int
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialLeaveOneRealizationOut:
    omitted_realization_id: str
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialRealizationDiagnostics:
    realization_interactions: tuple[FactorialRealizationInteraction, ...]
    order_interactions: tuple[FactorialOrderInteraction, ...]
    leave_one_realization_out: tuple[FactorialLeaveOneRealizationOut, ...]
    direction_robustness: str


@dataclass(frozen=True, slots=True)
class FactorialCoordinateEstimate:
    pair_id: str
    model_id: str
    metric: Metric
    cells: tuple[FactorialCellEstimate, ...]
    factor_1: float | None
    factor_2: float | None
    factor_1_given_factor_2: float | None
    factor_2_given_factor_1: float | None
    joint: float | None
    interaction: float | None
    factor_1_bounds: tuple[float, float]
    factor_2_bounds: tuple[float, float]
    factor_1_given_factor_2_bounds: tuple[float, float]
    factor_2_given_factor_1_bounds: tuple[float, float]
    joint_bounds: tuple[float, float]
    interaction_bounds: tuple[float, float]
    task_unit_effects: tuple[TaskUnitFactorialEffect, ...]
    response_pattern: FactorialPattern
    realization_diagnostics: FactorialRealizationDiagnostics

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
class FactorialMetricFamilyInference:
    family: FactorialMetricFamily
    metric: Metric
    intervals: tuple[FactorialSimultaneousInterval, ...]
    simultaneous_critical_value: float


@dataclass(frozen=True, slots=True)
class FactorialInferenceResult:
    plan_id: str
    estimates: tuple[FactorialCoordinateEstimate, ...]
    intervals: tuple[FactorialSimultaneousInterval, ...]
    simultaneous_critical_value: float
    secondary_intervals: tuple[FactorialSimultaneousInterval, ...] = ()
    secondary_critical_value: float = 0.0
    metric_families: tuple[FactorialMetricFamilyInference, ...] = ()

    @property
    def inference_id(self) -> str:
        return content_id("factorial_inference_", self)


def estimate_successor_effects(
    randomization: SuccessorRandomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[InterventionPolicyV2],
    tasks: Iterable[Task],
    plan: SuccessorAnalysisPlan,
) -> SuccessorInferenceResult:
    """Estimate assigned-arm task-unit ITT for successor ADD/REMOVE policies."""

    frozen_outcomes = tuple(outcomes)
    by_outcome = {item.assignment_id: item for item in frozen_outcomes}
    expected = {item.assignment_id for item in randomization.assignments}
    if len(by_outcome) != len(frozen_outcomes) or set(by_outcome) != expected:
        raise ValueError("outcomes must cover every successor assignment exactly once")
    frozen_policies = tuple(policies)
    policy_by_hypothesis = {item.hypothesis_id: item for item in frozen_policies}
    if len(policy_by_hypothesis) != len(frozen_policies):
        raise ValueError("successor policies must bind unique hypotheses")
    frozen_tasks = tuple(tasks)
    task_by_id = {item.task_id: item for item in frozen_tasks}
    if len(task_by_id) != len(frozen_tasks):
        raise ValueError("successor task ids must be unique")
    estimates = tuple(
        _successor_coordinate(
            randomization,
            by_outcome,
            policy_by_hypothesis[hypothesis_id],
            task_by_id,
            model_id,
            metric,
            plan,
        )
        for hypothesis_id in sorted(policy_by_hypothesis)
        for model_id in randomization.models
        for metric in plan.metrics
    )
    families = tuple(
        _successor_family(estimates, family, plan)
        for family in SuccessorIntervalFamily
    )
    robustness = _successor_robustness_inference(
        estimates,
        policy_by_hypothesis,
        plan,
    )
    label_by_coordinate = {
        item.coordinate_id: item.robustness_label
        for item in robustness.assessments
    }
    estimates = tuple(
        replace(
            item,
            robustness_label=(
                label_by_coordinate.get(item.coordinate_id, "not_evaluable")
                if item.metric is plan.primary_metric
                else "not_applicable_non_primary"
            ),
        )
        for item in estimates
    )
    return SuccessorInferenceResult(
        plan.analysis_plan_id,
        estimates,
        families,
        robustness,
    )


def _successor_coordinate(
    randomization: SuccessorRandomization,
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    model_id: str,
    metric: Metric,
    plan: SuccessorAnalysisPlan,
) -> SuccessorCoordinateEstimate:
    assignments = tuple(
        item
        for item in randomization.assignments
        if item.block.hypothesis_id == policy.hypothesis_id
        and item.block.model_id == model_id
    )
    task_unit_ids = sorted({item.block.task_unit_id for item in assignments})
    if not task_unit_ids:
        raise ValueError("successor analysis coordinate has no assignments")
    unit_arms: dict[
        str,
        dict[PolicyArmRoleV2, tuple[float | None, float, float, int]],
    ] = {}
    contributions = []
    for task_unit_id in task_unit_ids:
        arms = {
            role: _successor_unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                role,
                metric,
            )
            for role in SUCCESSOR_ARM_ROLE_ORDER
        }
        unit_arms[task_unit_id] = arms
        contrast_values = []
        for contrast in SuccessorContrast:
            left, right = contrast.roles
            contrast_values.append(
                (
                    contrast,
                    _difference(arms[left][0], arms[right][0]),
                    arms[left][1] - arms[right][2],
                    arms[left][2] - arms[right][1],
                )
            )
        contributions.append(
            TaskUnitSuccessorContribution(
                task_unit_id,
                tuple(
                    (role, arms[role][0], arms[role][1], arms[role][2])
                    for role in SUCCESSOR_ARM_ROLE_ORDER
                ),
                tuple(contrast_values),
            )
        )
    arm_estimates = tuple(
        _successor_arm_estimate(
            assignments,
            role,
            [unit_arms[unit_id][role] for unit_id in task_unit_ids],
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    )
    arm_by_role = {item.role: item for item in arm_estimates}
    contrast_estimates = tuple(
        SuccessorContrastEstimate(
            contrast,
            _difference(
                arm_by_role[contrast.roles[0]].point,
                arm_by_role[contrast.roles[1]].point,
            ),
            arm_by_role[contrast.roles[0]].lower
            - arm_by_role[contrast.roles[1]].upper,
            arm_by_role[contrast.roles[0]].upper
            - arm_by_role[contrast.roles[1]].lower,
        )
        for contrast in SuccessorContrast
    )
    realization_effects = tuple(
        _successor_realization_effect(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            realization.realization_spec_id,
            metric,
        )
        for realization in policy.realization_policy.realizations
    )
    leave_one_realization_out = tuple(
        _successor_leave_one_realization_out_effect(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            realization.realization_spec_id,
            metric,
        )
        for realization in policy.realization_policy.realizations
        if len(policy.realization_policy.realizations) >= 2
    )
    return SuccessorCoordinateEstimate(
        policy.hypothesis_id,
        model_id,
        metric,
        policy.hypothesis.skeleton.expected_direction,
        arm_estimates,
        contrast_estimates,
        tuple(contributions),
        realization_effects,
        _successor_point_robustness_label(
            contrast_estimates[0],
            realization_effects,
            len(task_unit_ids),
            policy.hypothesis.skeleton.expected_direction,
            plan,
        ),
        leave_one_realization_out,
    )


def _successor_unit_arm(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    role: PolicyArmRoleV2,
    metric: Metric,
    *,
    only_realization_id: str | None = None,
) -> tuple[float | None, float, float, int]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise ValueError("successor task unit lacks frozen task records")
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realizations = tuple(
        item
        for item in policy.realization_policy.realizations
        if only_realization_id is None
        or item.realization_spec_id == only_realization_id
    )
    if not realizations:
        raise ValueError("successor realization support is empty")
    realization_total = sum(item.weight for item in realizations)
    point = lower = upper = 0.0
    point_known = True
    count = 0
    for task_id in task_ids:
        task_weight = tasks[task_id].weight / task_total
        for realization in realizations:
            realization_weight = realization.weight / realization_total
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.realization_spec_id == realization.realization_spec_id
                and item.arm_role is role
            ]
            if not block:
                raise ValueError("successor randomization lacks common task-realization support")
            values = [_metric_value(outcomes[item.assignment_id], metric) for item in block]
            weight = task_weight * realization_weight
            count += len(block)
            if any(value[0] is None for value in values):
                point_known = False
            else:
                point += weight * sum(
                    value[0] for value in values if value[0] is not None
                ) / len(values)
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return point if point_known else None, lower, upper, count


def _successor_arm_estimate(
    assignments: tuple[SuccessorAssignment, ...],
    role: PolicyArmRoleV2,
    units: list[tuple[float | None, float, float, int]],
) -> SuccessorArmEstimate:
    point = None if any(item[0] is None for item in units) else sum(
        item[0] for item in units if item[0] is not None
    ) / len(units)
    return SuccessorArmEstimate(
        role,
        point,
        sum(item[1] for item in units) / len(units),
        sum(item[2] for item in units) / len(units),
        sum(item.arm_role is role for item in assignments),
    )


def _successor_realization_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_id: str,
    metric: Metric,
) -> RealizationSuccessorEffect:
    values = _successor_subset_effect_values(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        (realization_spec_id,),
        metric,
    )
    point = None if any(item[0] is None for item in values) else sum(
        item[0] for item in values if item[0] is not None
    ) / len(values)
    return RealizationSuccessorEffect(
        realization_spec_id,
        point,
        sum(item[1] for item in values) / len(values),
        sum(item[2] for item in values) / len(values),
        tuple(
            (task_unit_id, *value)
            for task_unit_id, value in zip(task_unit_ids, values, strict=True)
        ),
    )


def _successor_leave_one_realization_out_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    omitted_realization_spec_id: str,
    metric: Metric,
) -> LeaveOneRealizationOutSuccessorEffect:
    included = tuple(
        item.realization_spec_id
        for item in policy.realization_policy.realizations
        if item.realization_spec_id != omitted_realization_spec_id
    )
    values = _successor_subset_effect_values(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        included,
        metric,
    )
    point = None if any(item[0] is None for item in values) else sum(
        item[0] for item in values if item[0] is not None
    ) / len(values)
    return LeaveOneRealizationOutSuccessorEffect(
        omitted_realization_spec_id,
        point,
        sum(item[1] for item in values) / len(values),
        sum(item[2] for item in values) / len(values),
        tuple(
            (task_unit_id, *value)
            for task_unit_id, value in zip(task_unit_ids, values, strict=True)
        ),
    )


def _successor_subset_effect_values(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_ids: tuple[str, ...],
    metric: Metric,
) -> list[tuple[float | None, float, float]]:
    selected = tuple(
        item
        for item in policy.realization_policy.realizations
        if item.realization_spec_id in realization_spec_ids
    )
    if not selected or len(selected) != len(realization_spec_ids):
        raise ValueError("successor realization subset is invalid")
    selected_total = sum(item.weight for item in selected)
    values = []
    for task_unit_id in task_unit_ids:
        point = lower = upper = 0.0
        point_known = True
        for realization in selected:
            target = _successor_unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.TARGET,
                metric,
                only_realization_id=realization.realization_spec_id,
            )
            noop = _successor_unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.NOOP,
                metric,
                only_realization_id=realization.realization_spec_id,
            )
            weight = realization.weight / selected_total
            difference = _difference(target[0], noop[0])
            if difference is None:
                point_known = False
            else:
                point += weight * difference
            lower += weight * (target[1] - noop[2])
            upper += weight * (target[2] - noop[1])
        values.append((point if point_known else None, lower, upper))
    return values


def _successor_point_robustness_label(
    primary: SuccessorContrastEstimate,
    realizations: tuple[RealizationSuccessorEffect, ...],
    task_units: int,
    expected_direction: ExpectedDirection,
    plan: SuccessorAnalysisPlan,
) -> str:
    if primary.point is None or task_units < plan.minimum_task_units:
        return "not_evaluable"
    if len(realizations) < 2 or any(item.point is None for item in realizations):
        return "average_effect_only"
    multiplier = 1.0 if expected_direction is ExpectedDirection.INCREASE else -1.0
    values = [multiplier * float(item.point) for item in realizations]
    if any(value <= plan.practical_effect_margin for value in values):
        return "average_effect_only"
    leave_one_out = [
        sum(value for index, value in enumerate(values) if index != omitted)
        / (len(values) - 1)
        for omitted in range(len(values))
    ]
    return (
        "direction_consistent_diagnostic"
        if all(value > 0.0 for value in leave_one_out)
        else "average_effect_only"
    )


def _successor_robustness_inference(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    policies: Mapping[str, InterventionPolicyV2],
    plan: SuccessorAnalysisPlan,
) -> SuccessorRobustnessInference:
    """Build the global realization/LORO max-|T| family and claim gates."""

    secure = tuple(item for item in estimates if item.metric is plan.primary_metric)
    functionality = {
        (item.hypothesis_id, item.model_id): item
        for item in estimates
        if item.metric is Metric.FUNCTIONALITY
    }
    (
        functionality_status,
        functionality_critical,
        functionality_intervals,
    ) = _successor_functionality_gate_family(functionality, plan)

    members: dict[
        tuple[str, SuccessorRobustnessComponent, str],
        tuple[tuple[str, ...], tuple[float, ...]],
    ] = {}
    coordinate_weights: dict[str, dict[str, float]] = {}
    structurally_eligible: set[str] = set()
    for estimate in secure:
        policy = policies[estimate.hypothesis_id]
        realization_ids = tuple(
            item.realization_spec_id
            for item in policy.realization_policy.realizations
        )
        weights = {
            item.realization_spec_id: item.weight
            for item in policy.realization_policy.realizations
        }
        total_weight = sum(weights.values())
        coordinate_weights[estimate.coordinate_id] = {
            key: value / total_weight for key, value in weights.items()
        }
        if (
            len(realization_ids) < plan.minimum_realizations
            or len(estimate.task_unit_contributions) < plan.minimum_task_units
            or len(estimate.realization_effects) != len(realization_ids)
            or len(estimate.leave_one_realization_out) != len(realization_ids)
        ):
            continue
        candidate_members = tuple(
            (
                SuccessorRobustnessComponent.REALIZATION,
                item.realization_spec_id,
                item.task_unit_effects,
            )
            for item in estimate.realization_effects
        ) + tuple(
            (
                SuccessorRobustnessComponent.LEAVE_ONE_REALIZATION_OUT,
                item.omitted_realization_spec_id,
                item.task_unit_effects,
            )
            for item in estimate.leave_one_realization_out
        )
        if any(
            len(values) < plan.minimum_task_units_per_realization
            or any(value[1] is None for value in values)
            for _, _, values in candidate_members
        ):
            continue
        structurally_eligible.add(estimate.coordinate_id)
        for component, realization_id, values in candidate_members:
            members[(estimate.coordinate_id, component, realization_id)] = (
                tuple(value[0] for value in values),
                tuple(float(value[1]) for value in values),
            )

    status = FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES
    critical: float | None = None
    valid_draws = 0
    invalid_draws = plan.bootstrap_draws
    intervals: tuple[SuccessorRobustnessInterval, ...] = ()
    heterogeneity: dict[str, tuple[float, float]] = {}
    if members:
        (
            status,
            critical,
            valid_draws,
            invalid_draws,
            intervals,
            heterogeneity,
        ) = _successor_global_robustness_family(
            members,
            coordinate_weights,
            plan,
        )

    interval_by_key = {
        (item.coordinate_id, item.component, item.realization_spec_id): item
        for item in intervals
    }
    assessments = []
    for estimate in secure:
        coordinate_id = estimate.coordinate_id
        multiplier = (
            1.0
            if estimate.expected_direction is ExpectedDirection.INCREASE
            else -1.0
        )
        realization_points = tuple(
            multiplier * float(item.point)
            for item in estimate.realization_effects
            if item.point is not None
        )
        direction_proportion = (
            None
            if not estimate.realization_effects
            or len(realization_points) != len(estimate.realization_effects)
            else sum(value > 0.0 for value in realization_points)
            / len(realization_points)
        )
        direction_passed = (
            direction_proportion is not None
            and direction_proportion
            >= plan.realization_direction_consistency_threshold
        )
        minimum_support_passed = coordinate_id in structurally_eligible
        coordinate_intervals = tuple(
            value
            for key, value in interval_by_key.items()
            if key[0] == coordinate_id
        )
        simultaneous_direction_passed = (
            minimum_support_passed
            and len(coordinate_intervals)
            == len(estimate.realization_effects)
            + len(estimate.leave_one_realization_out)
            and all(
                (item.lower > 0.0)
                if multiplier > 0.0
                else (item.upper < 0.0)
                for item in coordinate_intervals
            )
        )
        heterogeneity_point, heterogeneity_upper = heterogeneity.get(
            coordinate_id,
            (None, None),
        )
        heterogeneity_passed = (
            heterogeneity_upper is not None
            and heterogeneity_upper
            <= plan.realization_practical_equivalence_margin
        )
        interaction_statistic, interaction_p = _arm_realization_randomization_test(
            estimate,
            plan,
        )
        interaction_passed = (
            interaction_p is not None and interaction_p > plan.alpha
        )
        realization_robust = (
            status is FamilyInferenceStatus.EVALUABLE
            and minimum_support_passed
            and direction_passed
            and simultaneous_direction_passed
            and heterogeneity_passed
            and interaction_passed
        )
        if realization_robust:
            robustness_label = "realization_robust"
        elif estimate.contrast(SuccessorContrast.TARGET_NOOP).point is None:
            robustness_label = "not_evaluable"
        elif direction_passed and minimum_support_passed:
            robustness_label = "direction_consistent_diagnostic"
        else:
            robustness_label = "average_effect_only"

        function_coordinate = functionality.get(
            (estimate.hypothesis_id, estimate.model_id)
        )
        function_point = (
            None
            if function_coordinate is None
            else function_coordinate.contrast(SuccessorContrast.TARGET_NOOP).point
        )
        function_interval = functionality_intervals.get(
            (estimate.hypothesis_id, estimate.model_id)
        )
        if not plan.functionality_noninferiority_separately_powered:
            gate_status = FunctionalityGateStatus.NOT_REQUESTED
            function_lower = None
        elif (
            functionality_status is not FamilyInferenceStatus.EVALUABLE
            or function_interval is None
        ):
            gate_status = FunctionalityGateStatus.NOT_EVALUABLE
            function_lower = None
        else:
            function_lower = function_interval[1]
            gate_status = (
                FunctionalityGateStatus.PASSED
                if function_lower >= -plan.functionality_noninferiority_margin
                else FunctionalityGateStatus.FAILED
            )
        if not realization_robust:
            practical_success_label = "security_robustness_not_established"
        elif gate_status is FunctionalityGateStatus.PASSED:
            practical_success_label = "practical_success"
        elif gate_status is FunctionalityGateStatus.NOT_REQUESTED:
            practical_success_label = "functionality_gate_not_requested"
        elif gate_status is FunctionalityGateStatus.FAILED:
            practical_success_label = "functionality_noninferiority_failed"
        else:
            practical_success_label = "functionality_gate_not_evaluable"
        assessments.append(
            SuccessorRobustnessAssessment(
                coordinate_id,
                direction_proportion,
                direction_passed,
                simultaneous_direction_passed,
                minimum_support_passed,
                heterogeneity_point,
                heterogeneity_upper,
                heterogeneity_passed,
                interaction_statistic,
                interaction_p,
                interaction_passed,
                gate_status,
                function_point,
                function_lower,
                robustness_label,
                practical_success_label,
            )
        )
    return SuccessorRobustnessInference(
        status,
        critical,
        valid_draws,
        invalid_draws,
        intervals,
        functionality_critical,
        tuple(assessments),
    )


def _arm_realization_randomization_test(
    estimate: SuccessorCoordinateEstimate,
    plan: SuccessorAnalysisPlan,
) -> tuple[float | None, float | None]:
    """Task-unit Rademacher reference for arm-by-realization heterogeneity."""

    rows = {
        item.realization_spec_id: {
            task_id: point for task_id, point, _lower, _upper in item.task_unit_effects
        }
        for item in estimate.realization_effects
    }
    if len(rows) < plan.minimum_realizations:
        return None, None
    task_ids = tuple(sorted(set.intersection(*(set(value) for value in rows.values()))))
    if len(task_ids) < plan.minimum_task_units_per_realization or any(
        rows[realization_id][task_id] is None
        for realization_id in rows
        for task_id in task_ids
    ):
        return None, None
    residuals = {
        realization_id: tuple(
            float(rows[realization_id][task_id])
            - sum(float(rows[other][task_id]) for other in rows) / len(rows)
            for task_id in task_ids
        )
        for realization_id in rows
    }
    statistic = max(
        abs(sum(values) / len(values)) for values in residuals.values()
    )
    rng = random.Random(
        int(content_hash({
            "seed": plan.bootstrap_seed,
            "coordinate_id": estimate.coordinate_id,
            "domain": "arm-realization-rademacher",
        })[-16:], 16)
    )
    exceedances = 0
    for _ in range(plan.bootstrap_draws):
        signs = tuple(1.0 if rng.randrange(2) else -1.0 for _ in task_ids)
        replicate = max(
            abs(sum(sign * value for sign, value in zip(signs, values, strict=True)) / len(values))
            for values in residuals.values()
        )
        exceedances += replicate >= statistic - 1e-15
    return statistic, (exceedances + 1) / (plan.bootstrap_draws + 1)


def _successor_global_robustness_family(
    members: Mapping[
        tuple[str, SuccessorRobustnessComponent, str],
        tuple[tuple[str, ...], tuple[float, ...]],
    ],
    coordinate_weights: Mapping[str, Mapping[str, float]],
    plan: SuccessorAnalysisPlan,
) -> tuple[
    FamilyInferenceStatus,
    float | None,
    int,
    int,
    tuple[SuccessorRobustnessInterval, ...],
    dict[str, tuple[float, float]],
]:
    supports = {key: value[0] for key, value in members.items()}
    values = {key: value[1] for key, value in members.items()}
    points = {key: sum(value) / len(value) for key, value in values.items()}
    errors = {key: _mean_standard_error(value) for key, value in values.items()}
    if any(value <= 0.0 for value in errors.values()):
        return (
            FamilyInferenceStatus.ZERO_STANDARD_ERROR,
            None,
            0,
            plan.bootstrap_draws,
            (),
            {},
        )
    realization_keys = {
        coordinate_id: tuple(
            key
            for key in members
            if key[0] == coordinate_id
            and key[1] is SuccessorRobustnessComponent.REALIZATION
        )
        for coordinate_id in {key[0] for key in members}
    }
    heterogeneity_points = {
        coordinate_id: _successor_max_realization_deviation(
            {key[2]: points[key] for key in keys},
            coordinate_weights[coordinate_id],
        )
        for coordinate_id, keys in realization_keys.items()
    }
    value_by_unit = {
        key: dict(zip(supports[key], values[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_robustness_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(
                        (key[0], key[1].value, key[2]) for key in supports
                    ),
                },
            )[-16:],
            16,
        )
    )
    draws: list[
        tuple[
            dict[tuple[str, SuccessorRobustnessComponent, str], float],
            dict[tuple[str, SuccessorRobustnessComponent, str], float],
            dict[str, float],
        ]
    ] = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        replicate_points = {}
        replicate_errors = {}
        valid = True
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units_per_realization:
                valid = False
                break
            error = _mean_standard_error(sample)
            if error <= 0.0:
                valid = False
                break
            replicate_points[key] = sum(sample) / len(sample)
            replicate_errors[key] = error
        if not valid:
            invalid += 1
            continue
        replicate_heterogeneity = {
            coordinate_id: _successor_max_realization_deviation(
                {key[2]: replicate_points[key] for key in keys},
                coordinate_weights[coordinate_id],
            )
            for coordinate_id, keys in realization_keys.items()
        }
        draws.append(
            (replicate_points, replicate_errors, replicate_heterogeneity)
        )
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(draws) < minimum_valid:
        return (
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(draws),
            invalid,
            (),
            {},
        )
    heterogeneity_errors = {
        coordinate_id: statistics.stdev(
            draw[2][coordinate_id] for draw in draws
        )
        for coordinate_id in realization_keys
    }
    maxima = []
    for replicate_points, replicate_errors, replicate_heterogeneity in draws:
        statistics_for_draw = [
            abs(replicate_points[key] - points[key]) / replicate_errors[key]
            for key in members
        ]
        statistics_for_draw.extend(
            abs(
                replicate_heterogeneity[coordinate_id]
                - heterogeneity_points[coordinate_id]
            )
            / error
            for coordinate_id, error in heterogeneity_errors.items()
            if error > 0.0
        )
        maxima.append(max(statistics_for_draw))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SuccessorRobustnessInterval(
            key[0],
            key[1],
            key[2],
            errors[key],
            max(-1.0, points[key] - critical * errors[key]),
            min(1.0, points[key] + critical * errors[key]),
        )
        for key in members
    )
    heterogeneity = {
        coordinate_id: (
            point,
            min(
                2.0,
                point + critical * heterogeneity_errors[coordinate_id],
            ),
        )
        for coordinate_id, point in heterogeneity_points.items()
    }
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(draws),
        invalid,
        intervals,
        heterogeneity,
    )


def _successor_max_realization_deviation(
    realization_points: Mapping[str, float],
    weights: Mapping[str, float],
) -> float:
    average = sum(weights[key] * value for key, value in realization_points.items())
    return max(abs(value - average) for value in realization_points.values())


def _successor_functionality_gate_family(
    functionality: Mapping[tuple[str, str], SuccessorCoordinateEstimate],
    plan: SuccessorAnalysisPlan,
) -> tuple[
    FamilyInferenceStatus,
    float | None,
    dict[tuple[str, str], tuple[float, float, float]],
]:
    if not plan.functionality_noninferiority_separately_powered:
        return FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES, None, {}
    vectors = {
        key: tuple(
            float(item.contrast(SuccessorContrast.TARGET_NOOP)[0])
            for item in estimate.task_unit_contributions
        )
        for key, estimate in functionality.items()
        if len(estimate.task_unit_contributions) >= plan.minimum_task_units
        and all(
            item.contrast(SuccessorContrast.TARGET_NOOP)[0] is not None
            for item in estimate.task_unit_contributions
        )
    }
    supports = {
        key: tuple(item.task_unit_id for item in functionality[key].task_unit_contributions)
        for key in vectors
    }
    if not vectors:
        return FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES, None, {}
    points = {key: sum(value) / len(value) for key, value in vectors.items()}
    errors = {key: _mean_standard_error(value) for key, value in vectors.items()}
    if any(value <= 0.0 for value in errors.values()):
        return FamilyInferenceStatus.ZERO_STANDARD_ERROR, None, {}
    value_by_unit = {
        key: dict(zip(supports[key], vectors[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_functionality_gate_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(sorted(supports)),
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        draw_statistics = []
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units:
                invalid += 1
                break
            replicate_error = _mean_standard_error(sample)
            if replicate_error <= 0.0:
                invalid += 1
                break
            draw_statistics.append(
                abs(sum(sample) / len(sample) - points[key]) / replicate_error
            )
        else:
            maxima.append(max(draw_statistics))
    if len(maxima) < math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    ):
        return FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP, None, {}
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        {
            key: (
                errors[key],
                max(-1.0, points[key] - critical * errors[key]),
                min(1.0, points[key] + critical * errors[key]),
            )
            for key in vectors
        },
    )


def _successor_family(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    family: SuccessorIntervalFamily,
    plan: SuccessorAnalysisPlan,
) -> SuccessorFamilyInference:
    if family is SuccessorIntervalFamily.PRIMARY_SECURITY:
        members = tuple(
            (item, SuccessorContrast.TARGET_NOOP)
            for item in estimates
            if item.metric is plan.primary_metric
        )
    elif family is SuccessorIntervalFamily.SECURITY_SPECIFICITY:
        members = tuple(
            (item, contrast)
            for item in estimates
            if item.metric is plan.primary_metric
            for contrast in (
                SuccessorContrast.TARGET_PLACEBO,
                SuccessorContrast.TARGET_GENERIC,
            )
        )
    else:
        members = tuple(
            (item, SuccessorContrast.TARGET_NOOP)
            for item in estimates
            if item.metric is Metric.JOINT
        )
    eligible = tuple(
        (estimate, contrast)
        for estimate, contrast in members
        if len(estimate.task_unit_contributions) >= plan.minimum_task_units
        and estimate.contrast(contrast).point is not None
        and all(
            item.contrast(contrast)[0] is not None
            for item in estimate.task_unit_contributions
        )
    )
    if not eligible:
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES,
            None,
            0,
            plan.bootstrap_draws,
            (),
        )
    supports = {
        (estimate.coordinate_id, contrast): tuple(
            item.task_unit_id for item in estimate.task_unit_contributions
        )
        for estimate, contrast in eligible
    }
    points = {
        key: float(estimate.contrast(contrast).point)
        for key, (estimate, contrast) in zip(supports, eligible, strict=True)
    }
    values = {
        key: tuple(
            float(item.contrast(contrast)[0])
            for item in estimate.task_unit_contributions
        )
        for key, (estimate, contrast) in zip(supports, eligible, strict=True)
    }
    standard_errors = {key: _mean_standard_error(item) for key, item in values.items()}
    if any(error <= 0.0 for error in standard_errors.values()):
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.ZERO_STANDARD_ERROR,
            None,
            0,
            plan.bootstrap_draws,
            (),
        )
    value_by_unit = {
        key: dict(zip(supports[key], values[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "family": family,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(
                        (key[0], key[1].value) for key in supports
                    ),
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        statistics_for_draw = []
        valid = True
        for key in supports:
            sample_values = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample_values) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _mean_standard_error(sample_values)
            if replicate_error <= 0.0:
                valid = False
                break
            replicate_point = sum(sample_values) / len(sample_values)
            statistics_for_draw.append(
                abs(replicate_point - points[key]) / replicate_error
            )
        if valid:
            maxima.append(max(statistics_for_draw))
        else:
            invalid += 1
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(maxima) < minimum_valid:
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(maxima),
            invalid,
            (),
        )
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SuccessorSimultaneousInterval(
            estimate.coordinate_id,
            contrast,
            standard_errors[(estimate.coordinate_id, contrast)],
            max(
                -1.0,
                points[(estimate.coordinate_id, contrast)]
                - critical * standard_errors[(estimate.coordinate_id, contrast)],
            ),
            min(
                1.0,
                points[(estimate.coordinate_id, contrast)]
                + critical * standard_errors[(estimate.coordinate_id, contrast)],
            ),
        )
        for estimate, contrast in eligible
    )
    return SuccessorFamilyInference(
        family,
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(maxima),
        invalid,
        intervals,
    )


def _mean_standard_error(values: tuple[float, ...]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(
        sum((value - mean) ** 2 for value in values)
        / (len(values) * (len(values) - 1))
    )


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
    intervals, critical = _factorial_simultaneous_intervals(estimates, plan)
    secondary, secondary_critical = _factorial_secondary_intervals(estimates, plan)
    metric_families = _factorial_metric_families(estimates, plan)
    return FactorialInferenceResult(
        plan.analysis_plan_id,
        estimates,
        intervals,
        critical,
        secondary,
        secondary_critical,
        metric_families,
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
        _factorial_cell_estimate(
            assignments,
            cell,
            [unit_cells[unit][cell] for unit in task_unit_ids],
        )
        for cell in FACTORIAL_CELL_ORDER
    )
    means = {item.cell: item.point for item in cell_estimates}
    lower = {item.cell: item.lower for item in cell_estimates}
    upper = {item.cell: item.upper for item in cell_estimates}
    realization_diagnostics = _factorial_realization_diagnostics(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        metric,
        _interaction(means),
    )
    return FactorialCoordinateEstimate(
        policy.pair.pair_id,
        model_id,
        metric,
        cell_estimates,
        _difference(means[FactorialCell.A10], means[FactorialCell.A00]),
        _difference(means[FactorialCell.A01], means[FactorialCell.A00]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A01]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A10]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A00]),
        _interaction(means),
        (
            lower[FactorialCell.A10] - upper[FactorialCell.A00],
            upper[FactorialCell.A10] - lower[FactorialCell.A00],
        ),
        (
            lower[FactorialCell.A01] - upper[FactorialCell.A00],
            upper[FactorialCell.A01] - lower[FactorialCell.A00],
        ),
        (
            lower[FactorialCell.A11] - upper[FactorialCell.A01],
            upper[FactorialCell.A11] - lower[FactorialCell.A01],
        ),
        (
            lower[FactorialCell.A11] - upper[FactorialCell.A10],
            upper[FactorialCell.A11] - lower[FactorialCell.A10],
        ),
        (
            lower[FactorialCell.A11] - upper[FactorialCell.A00],
            upper[FactorialCell.A11] - lower[FactorialCell.A00],
        ),
        _interaction_bounds(
            {
                cell: (None, lower[cell], upper[cell], 0)
                for cell in FACTORIAL_CELL_ORDER
            }
        ),
        tuple(unit_effects),
        classify_factorial_pattern(means),
        realization_diagnostics,
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
    return _task_unit_cell_for_realizations(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_id,
        cell,
        metric,
        policy.realizations,
    )


def _task_unit_cell_for_realizations(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    cell: FactorialCell,
    metric: Metric,
    realizations: tuple[object, ...],
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
    if not realizations:
        raise ValueError("factorial realization subset cannot be empty")
    realization_total = sum(item.weight for item in realizations)
    point = lower = upper = 0.0
    point_known = True
    count = 0
    for task_id in task_ids:
        task_weight = tasks[task_id].weight / task_total
        for realization in realizations:
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
                point += (
                    weight
                    * sum(value[0] for value in values if value[0] is not None)
                    / len(values)
                )
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


def classify_factorial_pattern(
    values: Mapping[FactorialCell, float | None],
    *,
    tolerance: float = 1e-12,
) -> FactorialPattern:
    """Classify a four-cell surface without changing its numeric estimand."""

    if any(values.get(cell) is None for cell in FACTORIAL_CELL_ORDER):
        return FactorialPattern.NOT_EVALUABLE
    cells = tuple(float(values[cell]) for cell in FACTORIAL_CELL_ORDER)
    binary = tuple(
        round(value) if abs(value - round(value)) <= tolerance else None
        for value in cells
    )
    if binary == (0, 1, 1, 0):
        return FactorialPattern.XOR
    if binary == (0, 1, 1, 1):
        return FactorialPattern.REDUNDANT
    if binary == (0, 0, 0, 1):
        return FactorialPattern.PREREQUISITE
    factor_1_at_0 = cells[1] - cells[0]
    factor_1_at_1 = cells[3] - cells[2]
    factor_2_at_0 = cells[2] - cells[0]
    factor_2_at_1 = cells[3] - cells[1]
    if (
        factor_1_at_0 * factor_1_at_1 < -(tolerance**2)
        or factor_2_at_0 * factor_2_at_1 < -(tolerance**2)
    ):
        return FactorialPattern.REVERSAL
    interaction = cells[3] - cells[1] - cells[2] + cells[0]
    if abs(interaction) <= tolerance:
        return FactorialPattern.ADDITIVE
    return (
        FactorialPattern.POSITIVE_INTERACTION
        if interaction > 0.0
        else FactorialPattern.NEGATIVE_INTERACTION
    )


def _factorial_realization_diagnostics(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    aggregate_interaction: float | None,
) -> FactorialRealizationDiagnostics:
    realization_rows = tuple(
        _factorial_realization_interaction(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            metric,
            (realization,),
            realization.realization_id,
            realization.application_order,
            realization.weight,
        )
        for realization in policy.realizations
    )
    orders = tuple(sorted({item.application_order for item in policy.realizations}))
    order_rows = tuple(
        _factorial_order_interaction(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            metric,
            order,
        )
        for order in orders
    )
    leave_one_out = tuple(
        _factorial_leave_one_out(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            metric,
            omitted.realization_id,
        )
        for omitted in policy.realizations
        if len(policy.realizations) > 1
    )
    diagnostic_points = tuple(item.point for item in realization_rows) + tuple(
        item.point for item in order_rows
    ) + tuple(item.point for item in leave_one_out)
    return FactorialRealizationDiagnostics(
        realization_rows,
        order_rows,
        leave_one_out,
        _factorial_direction_robustness(aggregate_interaction, diagnostic_points),
    )


def _factorial_realization_interaction(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    realizations: tuple[object, ...],
    realization_id: str,
    application_order: tuple[int, int],
    weight: int,
) -> FactorialRealizationInteraction:
    point, lower, upper = _factorial_subset_interaction(
        assignments, outcomes, policy, tasks, task_unit_ids, metric, realizations
    )
    return FactorialRealizationInteraction(
        realization_id, application_order, weight, point, lower, upper
    )


def _factorial_order_interaction(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    application_order: tuple[int, int],
) -> FactorialOrderInteraction:
    realizations = tuple(
        item for item in policy.realizations if item.application_order == application_order
    )
    point, lower, upper = _factorial_subset_interaction(
        assignments, outcomes, policy, tasks, task_unit_ids, metric, realizations
    )
    return FactorialOrderInteraction(
        application_order,
        sum(item.weight for item in realizations),
        point,
        lower,
        upper,
    )


def _factorial_leave_one_out(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    omitted_realization_id: str,
) -> FactorialLeaveOneRealizationOut:
    realizations = tuple(
        item
        for item in policy.realizations
        if item.realization_id != omitted_realization_id
    )
    point, lower, upper = _factorial_subset_interaction(
        assignments, outcomes, policy, tasks, task_unit_ids, metric, realizations
    )
    return FactorialLeaveOneRealizationOut(
        omitted_realization_id, point, lower, upper
    )


def _factorial_subset_interaction(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    realizations: tuple[object, ...],
) -> tuple[float | None, float, float]:
    unit_cells = tuple(
        {
            cell: _task_unit_cell_for_realizations(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                cell,
                metric,
                realizations,
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        for task_unit_id in task_unit_ids
    )
    points = tuple(
        _interaction({cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER})
        for cells in unit_cells
    )
    bounds = tuple(_interaction_bounds(cells) for cells in unit_cells)
    point = (
        None
        if any(value is None for value in points)
        else sum(float(value) for value in points) / len(points)
    )
    return (
        point,
        sum(item[0] for item in bounds) / len(bounds),
        sum(item[1] for item in bounds) / len(bounds),
    )


def _factorial_direction_robustness(
    aggregate: float | None,
    diagnostics: tuple[float | None, ...],
    *,
    tolerance: float = 1e-12,
) -> str:
    if aggregate is None or any(item is None for item in diagnostics):
        return "not_evaluable"
    if len(diagnostics) <= 2:
        return "average_effect_only"
    if abs(aggregate) <= tolerance:
        return "no_average_direction"
    signed = tuple(float(item) * aggregate for item in diagnostics)
    if any(item < -(tolerance**2) for item in signed):
        return "direction_reversal"
    if all(item > tolerance**2 for item in signed):
        return "direction_robust"
    return "direction_fragile"


def _factorial_simultaneous_intervals(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    return _factorial_studentized_effect_family(
        estimates,
        plan,
        metric=plan.primary_metric,
        effects=(FactorialEffect.INTERACTION,),
        seed_namespace="factorial_primary_studentized_v2_",
    )


def _factorial_secondary_intervals(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    return _factorial_studentized_effect_family(
        estimates,
        plan,
        metric=plan.primary_metric,
        effects=plan.secondary_effects,
        seed_namespace="factorial_secondary_studentized_v2_",
    )


def _factorial_metric_families(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[FactorialMetricFamilyInference, ...]:
    if not {
        FactorialEffect.FACTOR_1_GIVEN_FACTOR_2,
        FactorialEffect.FACTOR_2_GIVEN_FACTOR_1,
    } <= set(plan.secondary_effects):
        return ()
    effects = (FactorialEffect.INTERACTION, *plan.secondary_effects)
    families = []
    for family, metric in (
        (FactorialMetricFamily.FUNCTIONALITY, Metric.FUNCTIONALITY),
        (FactorialMetricFamily.JOINT, Metric.JOINT),
    ):
        if metric not in plan.metrics:
            continue
        intervals, critical = _factorial_studentized_effect_family(
            estimates,
            plan,
            metric=metric,
            effects=effects,
            seed_namespace=f"factorial_{family.value}_studentized_v2_",
        )
        families.append(
            FactorialMetricFamilyInference(family, metric, intervals, critical)
        )
    return tuple(families)


def _factorial_studentized_effect_family(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
    *,
    metric: Metric,
    effects: tuple[FactorialEffect, ...],
    seed_namespace: str,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    """Global task-unit bootstrap with replicate-specific studentization.

    A single draw is taken from the union of task units and all descendants move
    together.  This preserves dependence when pair supports partially overlap.
    A draw is valid only when every tested coordinate has adequate sampled
    support and a positive replicate standard error.
    """

    entries = []
    for estimate in estimates:
        if estimate.metric is not metric:
            continue
        for effect in effects:
            point = _factorial_effect(estimate, effect)
            values = tuple(
                (unit.task_unit_id, _task_unit_factorial_effect(unit, effect))
                for unit in estimate.task_unit_effects
            )
            if (
                point is None
                or len(values) < plan.minimum_task_units
                or any(value is None for _, value in values)
            ):
                continue
            numeric = tuple(float(value) for _, value in values)
            standard_error = _mean_standard_error(numeric)
            if standard_error <= 0.0:
                continue
            entries.append(
                (
                    estimate.coordinate_id,
                    effect,
                    float(point),
                    {unit_id: float(value) for unit_id, value in values},
                    standard_error,
                )
            )
    if not entries:
        return (), 0.0

    task_unit_union = tuple(
        sorted({unit_id for _, _, _, values, _ in entries for unit_id in values})
    )
    family_members = tuple((coordinate_id, effect.value) for coordinate_id, effect, *_ in entries)
    rng = random.Random(
        int(
            content_id(
                seed_namespace,
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": family_members,
                    "quantile_method": plan.bootstrap_quantile_method,
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        statistics_for_draw = []
        valid = True
        for _, _, point, value_by_unit, _ in entries:
            sample = tuple(
                value_by_unit[unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit
            )
            if len(sample) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _mean_standard_error(sample)
            if replicate_error <= 0.0:
                valid = False
                break
            replicate_point = sum(sample) / len(sample)
            statistics_for_draw.append(
                abs(replicate_point - point) / replicate_error
            )
        if valid:
            maxima.append(max(statistics_for_draw))

    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(maxima) < minimum_valid:
        return (), 0.0
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = []
    for coordinate_id, effect, point, _, standard_error in entries:
        lower_limit, upper_limit = _factorial_effect_limits(effect)
        intervals.append(
            FactorialSimultaneousInterval(
                coordinate_id,
                effect,
                standard_error,
                max(lower_limit, point - critical * standard_error),
                min(upper_limit, point + critical * standard_error),
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
    if effect is FactorialEffect.FACTOR_1_GIVEN_FACTOR_2:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A01])
    if effect is FactorialEffect.FACTOR_2_GIVEN_FACTOR_1:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A10])
    if effect is FactorialEffect.JOINT:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A00])
    return unit.interaction


def _factorial_effect_limits(effect: FactorialEffect) -> tuple[float, float]:
    return (-2.0, 2.0) if effect is FactorialEffect.INTERACTION else (-1.0, 1.0)


def _metric_value(outcome: Outcome, metric: Metric) -> tuple[int | None, int, int]:
    if metric is Metric.SECURE_YIELD:
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric is Metric.JOINT:
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric.value)
    if value is None:
        return None, 0, 1
    return value, value, value


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


__all__ = [
    "FactorialAnalysisPlan",
    "FactorialCellEstimate",
    "FactorialCoordinateEstimate",
    "FactorialEffect",
    "FactorialInferenceResult",
    "FactorialLeaveOneRealizationOut",
    "FactorialMetricFamily",
    "FactorialMetricFamilyInference",
    "FactorialOrderInteraction",
    "FactorialPattern",
    "FactorialRealizationDiagnostics",
    "FactorialRealizationInteraction",
    "FactorialSimultaneousInterval",
    "FamilyInferenceStatus",
    "FunctionalityGateStatus",
    "LeaveOneRealizationOutSuccessorEffect",
    "Metric",
    "RealizationSuccessorEffect",
    "SuccessorAnalysisPlan",
    "SuccessorArmEstimate",
    "SuccessorContrast",
    "SuccessorContrastEstimate",
    "SuccessorCoordinateEstimate",
    "SuccessorFamilyInference",
    "SuccessorInferenceResult",
    "SuccessorIntervalFamily",
    "SuccessorRobustnessAssessment",
    "SuccessorRobustnessComponent",
    "SuccessorRobustnessInference",
    "SuccessorRobustnessInterval",
    "SuccessorSimultaneousInterval",
    "TaskUnitSuccessorContribution",
    "classify_factorial_pattern",
    "estimate_factorial_effects",
    "estimate_successor_effects",
]

"""Independent verifier for successor four-arm inference.

This module deliberately does not import the production estimator.  It
reconstructs block support, task-unit arm values, contrasts, unknown bounds,
and the three bootstrap families from the frozen scientific records.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import replace

from prompt_mechanism_study.inference import (
    FamilyInferenceStatus,
    FunctionalityGateStatus,
    LeaveOneRealizationOutSuccessorEffect,
    Metric,
    RealizationSuccessorEffect,
    SuccessorAnalysisPlan,
    SuccessorArmEstimate,
    SuccessorContrast,
    SuccessorContrastEstimate,
    SuccessorCoordinateEstimate,
    SuccessorFamilyInference,
    SuccessorInferenceResult,
    SuccessorIntervalFamily,
    SuccessorRobustnessAssessment,
    SuccessorRobustnessComponent,
    SuccessorRobustnessInference,
    SuccessorRobustnessInterval,
    SuccessorSimultaneousInterval,
    TaskUnitSuccessorContribution,
)
from prompt_mechanism_study.intervention import (
    SUCCESSOR_ARM_ROLE_ORDER,
    InterventionPolicyV2,
    PolicyArmRoleV2,
    TaskRealizationBundleV2,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import (
    SuccessorAssignment,
    SuccessorBlockKey,
    SuccessorRandomization,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import ExpectedDirection, Task


class SuccessorVerificationError(ValueError):
    """A stored successor result does not replay from its frozen inputs."""


def _replace_robustness_label(
    estimate: SuccessorCoordinateEstimate,
    label: str | None,
) -> SuccessorCoordinateEstimate:
    return estimate if label is None else replace(estimate, robustness_label=label)


def verify_successor_inference(
    randomization: SuccessorRandomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[InterventionPolicyV2],
    tasks: Iterable[Task],
    plan: SuccessorAnalysisPlan,
    observed: SuccessorInferenceResult,
    *,
    maximum_unknown_fraction: float | None = None,
    scientific_claim_allowed: bool | None = None,
    functionality_power_qualification_sha256: str | None = None,
) -> dict[str, object]:
    """Independently reconstruct and compare one successor inference result."""

    frozen_policies = tuple(policies)
    frozen_tasks = tuple(tasks)
    frozen_outcomes = tuple(outcomes)
    _verify_randomization(randomization, frozen_policies, frozen_tasks)

    assignment_ids = tuple(item.assignment_id for item in randomization.assignments)
    outcome_by_assignment = {item.assignment_id: item for item in frozen_outcomes}
    if (
        len(outcome_by_assignment) != len(frozen_outcomes)
        or set(outcome_by_assignment) != set(assignment_ids)
    ):
        raise SuccessorVerificationError(
            "outcomes must cover every successor assignment exactly once"
        )
    policy_by_hypothesis = {item.hypothesis_id: item for item in frozen_policies}
    if len(policy_by_hypothesis) != len(frozen_policies):
        raise SuccessorVerificationError("successor policies bind duplicate hypotheses")
    task_by_id = {item.task_id: item for item in frozen_tasks}
    if len(task_by_id) != len(frozen_tasks):
        raise SuccessorVerificationError("successor tasks contain duplicate task ids")

    estimates = tuple(
        _coordinate(
            randomization,
            outcome_by_assignment,
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
    families = tuple(_family(estimates, family, plan) for family in SuccessorIntervalFamily)
    robustness = _robustness_inference(estimates, policy_by_hypothesis, plan)
    labels = {
        item.coordinate_id: item.robustness_label
        for item in robustness.assessments
    }
    estimates = tuple(
        _replace_robustness_label(
            item,
            (
                labels.get(item.coordinate_id, "not_evaluable")
                if item.metric is plan.primary_metric
                else "not_applicable_non_primary"
            ),
        )
        for item in estimates
    )
    if observed.plan_id != plan.analysis_plan_id:
        raise SuccessorVerificationError("stored successor analysis plan identity drift")
    if observed.estimates != estimates:
        raise SuccessorVerificationError("stored successor estimate drift")
    if observed.families != families:
        raise SuccessorVerificationError("stored successor bootstrap family drift")
    if observed.robustness != robustness:
        raise SuccessorVerificationError("stored successor robustness family drift")
    claim_assessments = (
        []
        if maximum_unknown_fraction is None and scientific_claim_allowed is None
        else _claim_assessments(
            estimates,
            robustness,
            plan,
            maximum_unknown_fraction,
            scientific_claim_allowed,
            functionality_power_qualification_sha256,
        )
    )
    return {
        "status": "SUCCESSOR_INFERENCE_VERIFIED",
        "assignments": len(randomization.assignments),
        "outcomes": len(frozen_outcomes),
        "coordinates": len(estimates),
        "families": len(families),
        "family_statuses": {
            item.family.value: item.status.value for item in families
        },
        "intervals": sum(len(item.intervals) for item in families),
        "robustness_intervals": len(robustness.intervals),
        "claim_assessments": claim_assessments,
        "security_claim_ready_coordinates": [
            item["coordinate_id"]
            for item in claim_assessments
            if item["gate"]["security_claim_ready"]
        ],
        "practical_success_claim_ready_coordinates": [
            item["coordinate_id"]
            for item in claim_assessments
            if item["gate"]["practical_success_claim_ready"]
        ],
    }


def _claim_assessments(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    robustness: SuccessorRobustnessInference,
    plan: SuccessorAnalysisPlan,
    maximum_unknown_fraction: float | None,
    scientific_claim_allowed: bool | None,
    functionality_power_qualification_sha256: str | None,
) -> list[dict[str, object]]:
    """Rebuild claim gates from task-unit endpoint estimates, not raw failures."""

    if (
        type(maximum_unknown_fraction) is not float
        or not 0.0 <= maximum_unknown_fraction <= 1.0
        or type(scientific_claim_allowed) is not bool
    ):
        raise SuccessorVerificationError("successor claim gate configuration is invalid")
    if plan.functionality_noninferiority_separately_powered:
        if not isinstance(functionality_power_qualification_sha256, str):
            raise SuccessorVerificationError(
                "powered functionality gate lacks frozen qualification"
            )
    elif functionality_power_qualification_sha256 is not None:
        raise SuccessorVerificationError(
            "unrequested functionality power qualification entered inference"
        )
    by_key = {
        (item.hypothesis_id, item.model_id, item.metric): item
        for item in estimates
    }
    assessment_by_coordinate = {
        item.coordinate_id: item for item in robustness.assessments
    }
    rows: list[dict[str, object]] = []
    for secure in sorted(
        (item for item in estimates if item.metric is Metric.SECURE_YIELD),
        key=lambda item: (item.hypothesis_id, item.model_id),
    ):
        key = (secure.hypothesis_id, secure.model_id)
        code_valid = by_key.get((*key, Metric.CODE_VALID))
        evaluable = by_key.get((*key, Metric.ORACLE_EVALUABLE))
        if code_valid is None or evaluable is None:
            raise SuccessorVerificationError(
                "successor claim gate lacks code-validity or Oracle-evaluability endpoint"
            )
        code_by_arm = {item.role.value: item.point for item in code_valid.arms}
        evaluable_by_arm = {item.role.value: item.point for item in evaluable.arms}
        if set(code_by_arm) != set(evaluable_by_arm):
            raise SuccessorVerificationError("successor claim gate arm support drifts")
        unknown: dict[str, float | None] = {}
        for role in sorted(code_by_arm):
            valid = code_by_arm[role]
            oracle = evaluable_by_arm[role]
            if valid is None or oracle is None:
                unknown[role] = None
            elif not 0.0 <= oracle <= valid <= 1.0:
                raise SuccessorVerificationError(
                    "Oracle evaluability is not a subset of valid code"
                )
            else:
                unknown[role] = None if valid == 0.0 else (valid - oracle) / valid
        observed_unknown = [item for item in unknown.values() if item is not None]
        unknown_evaluable = len(observed_unknown) == len(unknown)
        maximum = max(observed_unknown) if observed_unknown else None
        unknown_passed = bool(
            unknown_evaluable
            and maximum is not None
            and maximum <= maximum_unknown_fraction
        )
        robustness_assessment = assessment_by_coordinate.get(secure.coordinate_id)
        if robustness_assessment is None:
            raise SuccessorVerificationError(
                "successor claim gate lacks robustness assessment"
            )
        security_passed = robustness_assessment.robustness_label == "realization_robust"
        functionality_status = robustness_assessment.functionality_gate_status.value
        functionality_passed = (
            plan.functionality_noninferiority_separately_powered
            and robustness_assessment.functionality_gate_status
            is FunctionalityGateStatus.PASSED
            and robustness_assessment.functionality_simultaneous_lower is not None
            and robustness_assessment.functionality_simultaneous_lower
            >= -plan.functionality_noninferiority_margin
        )
        security_claim_ready = bool(
            scientific_claim_allowed and security_passed and unknown_passed
        )
        practical_ready = bool(security_claim_ready and functionality_passed)
        rows.append(
            {
                "coordinate_id": secure.coordinate_id,
                "hypothesis_id": secure.hypothesis_id,
                "model_id": secure.model_id,
                "gate": {
                    "security_gate_passed": security_passed,
                    "code_valid_yield_by_arm": code_by_arm,
                    "oracle_evaluable_yield_by_arm": evaluable_by_arm,
                    "unknown_fraction_among_valid_code_by_arm": unknown,
                    "maximum_unknown_fraction": maximum_unknown_fraction,
                    "maximum_observed_unknown_fraction_among_valid_code": maximum,
                    "unknown_gate_evaluable": unknown_evaluable,
                    "unknown_gate_passed": unknown_passed,
                    "functionality_noninferiority_separately_powered": plan.functionality_noninferiority_separately_powered,
                    "functionality_power_qualification_sha256": functionality_power_qualification_sha256,
                    "functionality_noninferiority_margin": plan.functionality_noninferiority_margin,
                    "functionality_simultaneous_lower": robustness_assessment.functionality_simultaneous_lower,
                    "functionality_gate_status": functionality_status,
                    "functionality_gate_passed": functionality_passed,
                    "security_claim_ready": security_claim_ready,
                    "practical_success_claim_ready": practical_ready,
                },
            }
        )
    return rows


def _verify_randomization(
    randomization: SuccessorRandomization,
    policies: tuple[InterventionPolicyV2, ...],
    tasks: tuple[Task, ...],
) -> None:
    assignment_ids = tuple(item.assignment_id for item in randomization.assignments)
    if len(assignment_ids) != len(set(assignment_ids)):
        raise SuccessorVerificationError("successor randomization has duplicate assignments")
    if len({item.provider_seed is None for item in randomization.assignments}) > 1:
        raise SuccessorVerificationError("successor provider-seed support is inconsistent")
    task_by_id = {item.task_id: item for item in tasks}
    if len(task_by_id) != len(tasks):
        raise SuccessorVerificationError("successor tasks contain duplicate task ids")
    expected = {
        _block(policy, bundle, model_id).block_id: (
            _block(policy, bundle, model_id),
            policy,
            bundle,
        )
        for policy in policies
        for bundle in policy.bundles
        for model_id in randomization.models
    }
    actual_block_ids = {item.block.block_id for item in randomization.assignments}
    if actual_block_ids != set(expected):
        raise SuccessorVerificationError("successor randomization block support drift")
    for block_id, (expected_block, policy, bundle) in expected.items():
        block = [
            item for item in randomization.assignments if item.block.block_id == block_id
        ]
        if len(block) != len(randomization.request_randomness_slots) or {
            item.request_randomness_slot for item in block
        } != set(randomization.request_randomness_slots):
            raise SuccessorVerificationError("successor randomization slot support drift")
        counts = Counter(item.arm_role for item in block)
        if set(counts) != set(SUCCESSOR_ARM_ROLE_ORDER) or len(set(counts.values())) != 1:
            raise SuccessorVerificationError("successor four-arm balance drift")
        protocol = policy.realization_policy.arm_protocol
        if any(
            item.block != expected_block
            or item.arm_label != protocol.label(item.arm_role)
            or item.variant_sha256 != bundle.variant(item.arm_role).variant_sha256
            for item in block
        ):
            raise SuccessorVerificationError(
                "successor assignment block, arm, or variant binding drift"
            )
        task = task_by_id.get(bundle.task_id)
        if task is None or task.semantic_cluster_id != bundle.task_unit_id:
            raise SuccessorVerificationError("successor task-unit population binding drift")


def _block(
    policy: InterventionPolicyV2,
    bundle: TaskRealizationBundleV2,
    model_id: str,
) -> SuccessorBlockKey:
    return SuccessorBlockKey(
        bundle.task_unit_id,
        bundle.task_id,
        policy.hypothesis_id,
        policy.hypothesis.target_spec.target_spec_id,
        bundle.realization_spec_id,
        bundle.task_realization_bundle_id,
        model_id,
        policy.realization_policy.arm_protocol.arm_protocol_id,
    )


def _coordinate(
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
        raise SuccessorVerificationError("successor coordinate has no assignments")
    values_by_unit: dict[
        str,
        dict[PolicyArmRoleV2, tuple[float | None, float, float]],
    ] = {}
    contributions = []
    for task_unit_id in task_unit_ids:
        arms = {
            role: _unit_arm(
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
        values_by_unit[task_unit_id] = arms
        contributions.append(
            TaskUnitSuccessorContribution(
                task_unit_id,
                tuple(
                    (role, *arms[role]) for role in SUCCESSOR_ARM_ROLE_ORDER
                ),
                tuple(
                    (
                        contrast,
                        _difference(
                            arms[contrast.roles[0]][0],
                            arms[contrast.roles[1]][0],
                        ),
                        arms[contrast.roles[0]][1] - arms[contrast.roles[1]][2],
                        arms[contrast.roles[0]][2] - arms[contrast.roles[1]][1],
                    )
                    for contrast in SuccessorContrast
                ),
            )
        )
    arms = tuple(
        _arm_estimate(
            assignments,
            role,
            tuple(values_by_unit[task_unit_id][role] for task_unit_id in task_unit_ids),
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    )
    arm_by_role = {item.role: item for item in arms}
    contrasts = tuple(
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
        _realization_effect(
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
        _leave_one_realization_out_effect(
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
        arms,
        contrasts,
        tuple(contributions),
        realization_effects,
        _point_robustness_label(
            contrasts[0],
            realization_effects,
            len(task_unit_ids),
            policy.hypothesis.skeleton.expected_direction,
            plan,
        ),
        leave_one_realization_out,
    )


def _unit_arm(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    role: PolicyArmRoleV2,
    metric: Metric,
    *,
    realization_spec_id: str | None = None,
) -> tuple[float | None, float, float]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise SuccessorVerificationError("successor task unit lacks frozen tasks")
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realizations = tuple(
        item
        for item in policy.realization_policy.realizations
        if realization_spec_id is None
        or item.realization_spec_id == realization_spec_id
    )
    if not realizations:
        raise SuccessorVerificationError("successor realization support is empty")
    realization_total = sum(item.weight for item in realizations)
    point = lower = upper = 0.0
    point_known = True
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
                raise SuccessorVerificationError(
                    "successor randomization lacks common task-realization support"
                )
            values = tuple(_metric_value(outcomes[item.assignment_id], metric) for item in block)
            weight = task_weight * realization_weight
            if any(value[0] is None for value in values):
                point_known = False
            else:
                point += weight * sum(
                    value[0] for value in values if value[0] is not None
                ) / len(values)
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return point if point_known else None, lower, upper


def _arm_estimate(
    assignments: tuple[SuccessorAssignment, ...],
    role: PolicyArmRoleV2,
    units: tuple[tuple[float | None, float, float], ...],
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


def _realization_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_id: str,
    metric: Metric,
) -> RealizationSuccessorEffect:
    values = _subset_effect_values(
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


def _leave_one_realization_out_effect(
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
    values = _subset_effect_values(
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


def _subset_effect_values(
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
        raise SuccessorVerificationError("successor realization subset is invalid")
    selected_total = sum(item.weight for item in selected)
    values = []
    for task_unit_id in task_unit_ids:
        point = lower = upper = 0.0
        point_known = True
        for realization in selected:
            target = _unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.TARGET,
                metric,
                realization_spec_id=realization.realization_spec_id,
            )
            noop = _unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.NOOP,
                metric,
                realization_spec_id=realization.realization_spec_id,
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


def _point_robustness_label(
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


def _robustness_inference(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    policies: Mapping[str, InterventionPolicyV2],
    plan: SuccessorAnalysisPlan,
) -> SuccessorRobustnessInference:
    secure = tuple(item for item in estimates if item.metric is plan.primary_metric)
    functionality = {
        (item.hypothesis_id, item.model_id): item
        for item in estimates
        if item.metric is Metric.FUNCTIONALITY
    }
    functionality_status, functionality_critical, functionality_intervals = (
        _functionality_gate_family(functionality, plan)
    )
    members = {}
    weights_by_coordinate = {}
    eligible_coordinates = set()
    for estimate in secure:
        policy = policies[estimate.hypothesis_id]
        weights = {
            item.realization_spec_id: item.weight
            for item in policy.realization_policy.realizations
        }
        total = sum(weights.values())
        weights_by_coordinate[estimate.coordinate_id] = {
            key: value / total for key, value in weights.items()
        }
        expected_count = len(policy.realization_policy.realizations)
        if (
            expected_count < plan.minimum_realizations
            or len(estimate.task_unit_contributions) < plan.minimum_task_units
            or len(estimate.realization_effects) != expected_count
            or len(estimate.leave_one_realization_out) != expected_count
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
        eligible_coordinates.add(estimate.coordinate_id)
        for component, realization_id, values in candidate_members:
            members[(estimate.coordinate_id, component, realization_id)] = (
                tuple(value[0] for value in values),
                tuple(float(value[1]) for value in values),
            )
    status = FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES
    critical = None
    valid_draws = 0
    invalid_draws = plan.bootstrap_draws
    intervals = ()
    heterogeneity = {}
    if members:
        (
            status,
            critical,
            valid_draws,
            invalid_draws,
            intervals,
            heterogeneity,
        ) = _global_robustness_family(
            members,
            weights_by_coordinate,
            plan,
        )
    interval_by_key = {
        (item.coordinate_id, item.component, item.realization_spec_id): item
        for item in intervals
    }
    assessments = []
    for estimate in secure:
        multiplier = (
            1.0
            if estimate.expected_direction is ExpectedDirection.INCREASE
            else -1.0
        )
        oriented = tuple(
            multiplier * float(item.point)
            for item in estimate.realization_effects
            if item.point is not None
        )
        direction_proportion = (
            None
            if not estimate.realization_effects
            or len(oriented) != len(estimate.realization_effects)
            else sum(value > 0.0 for value in oriented) / len(oriented)
        )
        direction_passed = (
            direction_proportion is not None
            and direction_proportion
            >= plan.realization_direction_consistency_threshold
        )
        support_passed = estimate.coordinate_id in eligible_coordinates
        coordinate_intervals = tuple(
            value
            for key, value in interval_by_key.items()
            if key[0] == estimate.coordinate_id
        )
        interval_passed = (
            support_passed
            and len(coordinate_intervals)
            == len(estimate.realization_effects)
            + len(estimate.leave_one_realization_out)
            and all(
                item.lower > 0.0 if multiplier > 0.0 else item.upper < 0.0
                for item in coordinate_intervals
            )
        )
        h_point, h_upper = heterogeneity.get(estimate.coordinate_id, (None, None))
        h_passed = (
            h_upper is not None
            and h_upper <= plan.realization_practical_equivalence_margin
        )
        interaction_statistic, interaction_p = _arm_realization_randomization_test(
            estimate, plan
        )
        interaction_passed = interaction_p is not None and interaction_p > plan.alpha
        robust = (
            status is FamilyInferenceStatus.EVALUABLE
            and support_passed
            and direction_passed
            and interval_passed
            and h_passed
            and interaction_passed
        )
        if robust:
            label = "realization_robust"
        elif estimate.contrast(SuccessorContrast.TARGET_NOOP).point is None:
            label = "not_evaluable"
        elif direction_passed and support_passed:
            label = "direction_consistent_diagnostic"
        else:
            label = "average_effect_only"
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
            gate = FunctionalityGateStatus.NOT_REQUESTED
            function_lower = None
        elif (
            functionality_status is not FamilyInferenceStatus.EVALUABLE
            or function_interval is None
        ):
            gate = FunctionalityGateStatus.NOT_EVALUABLE
            function_lower = None
        else:
            function_lower = function_interval[1]
            gate = (
                FunctionalityGateStatus.PASSED
                if function_lower >= -plan.functionality_noninferiority_margin
                else FunctionalityGateStatus.FAILED
            )
        if not robust:
            practical_label = "security_robustness_not_established"
        elif gate is FunctionalityGateStatus.PASSED:
            practical_label = "practical_success"
        elif gate is FunctionalityGateStatus.NOT_REQUESTED:
            practical_label = "functionality_gate_not_requested"
        elif gate is FunctionalityGateStatus.FAILED:
            practical_label = "functionality_noninferiority_failed"
        else:
            practical_label = "functionality_gate_not_evaluable"
        assessments.append(
            SuccessorRobustnessAssessment(
                estimate.coordinate_id,
                direction_proportion,
                direction_passed,
                interval_passed,
                support_passed,
                h_point,
                h_upper,
                h_passed,
                interaction_statistic,
                interaction_p,
                interaction_passed,
                gate,
                function_point,
                function_lower,
                label,
                practical_label,
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


def _arm_realization_randomization_test(estimate, plan):
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
        for realization_id in rows for task_id in task_ids
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
    statistic = max(abs(sum(values) / len(values)) for values in residuals.values())
    rng = random.Random(int(content_hash({
        "seed": plan.bootstrap_seed,
        "coordinate_id": estimate.coordinate_id,
        "domain": "arm-realization-rademacher",
    })[-16:], 16))
    exceedances = 0
    for _ in range(plan.bootstrap_draws):
        signs = tuple(1.0 if rng.randrange(2) else -1.0 for _ in task_ids)
        replicate = max(
            abs(sum(sign * value for sign, value in zip(signs, values, strict=True)) / len(values))
            for values in residuals.values()
        )
        exceedances += replicate >= statistic - 1e-15
    return statistic, (exceedances + 1) / (plan.bootstrap_draws + 1)


def _global_robustness_family(members, weights_by_coordinate, plan):
    supports = {key: value[0] for key, value in members.items()}
    values = {key: value[1] for key, value in members.items()}
    points = {key: sum(value) / len(value) for key, value in values.items()}
    errors = {key: _standard_error(value) for key, value in values.items()}
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
    h_points = {
        coordinate_id: _max_deviation(
            {key[2]: points[key] for key in keys},
            weights_by_coordinate[coordinate_id],
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
    draws = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        replicate_points = {}
        replicate_errors = {}
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units_per_realization:
                invalid += 1
                break
            error = _standard_error(sample)
            if error <= 0.0:
                invalid += 1
                break
            replicate_points[key] = sum(sample) / len(sample)
            replicate_errors[key] = error
        else:
            replicate_h = {
                coordinate_id: _max_deviation(
                    {key[2]: replicate_points[key] for key in keys},
                    weights_by_coordinate[coordinate_id],
                )
                for coordinate_id, keys in realization_keys.items()
            }
            draws.append((replicate_points, replicate_errors, replicate_h))
    if len(draws) < math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    ):
        return (
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(draws),
            invalid,
            (),
            {},
        )
    h_errors = {
        coordinate_id: statistics.stdev(draw[2][coordinate_id] for draw in draws)
        for coordinate_id in realization_keys
    }
    maxima = []
    for replicate_points, replicate_errors, replicate_h in draws:
        statistics_for_draw = [
            abs(replicate_points[key] - points[key]) / replicate_errors[key]
            for key in members
        ]
        statistics_for_draw.extend(
            abs(replicate_h[coordinate_id] - h_points[coordinate_id]) / error
            for coordinate_id, error in h_errors.items()
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
            min(2.0, point + critical * h_errors[coordinate_id]),
        )
        for coordinate_id, point in h_points.items()
    }
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(draws),
        invalid,
        intervals,
        heterogeneity,
    )


def _max_deviation(points, weights):
    average = sum(weights[key] * value for key, value in points.items())
    return max(abs(value - average) for value in points.values())


def _functionality_gate_family(functionality, plan):
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
    errors = {key: _standard_error(value) for key, value in vectors.items()}
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
                break
            error = _standard_error(sample)
            if error <= 0.0:
                break
            draw_statistics.append(
                abs(sum(sample) / len(sample) - points[key]) / error
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


def _family(
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
            contribution.contrast(contrast)[0] is not None
            for contribution in estimate.task_unit_contributions
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
    standard_errors = {key: _standard_error(item) for key, item in values.items()}
    if any(value <= 0.0 for value in standard_errors.values()):
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
        draw_statistics = []
        valid = True
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _standard_error(sample)
            if replicate_error <= 0.0:
                valid = False
                break
            replicate_point = sum(sample) / len(sample)
            draw_statistics.append(
                abs(replicate_point - points[key]) / replicate_error
            )
        if valid:
            maxima.append(max(draw_statistics))
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


def _metric_value(outcome: Outcome, metric: Metric) -> tuple[int | None, int, int]:
    if metric is Metric.SECURE_YIELD:
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric is Metric.JOINT:
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric.value)
    if value is None:
        return None, 0, 1
    return value, value, value


def _difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _standard_error(values: tuple[float, ...]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(
        sum((value - mean) ** 2 for value in values)
        / (len(values) * (len(values) - 1))
    )


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


__all__ = [
    "SuccessorVerificationError",
    "verify_successor_inference",
]

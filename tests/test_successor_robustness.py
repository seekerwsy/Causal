from __future__ import annotations

from dataclasses import replace

import pytest

from prompt_mechanism_study.inference import (
    FamilyInferenceStatus,
    FunctionalityGateStatus,
    Metric,
    SuccessorAnalysisPlan,
    SuccessorRobustnessComponent,
    estimate_successor_effects,
)
from prompt_mechanism_study.intervention import (
    SUCCESSOR_ARM_ROLE_ORDER,
    ArmSemanticValidationV2,
    BundleValidationV2,
    InterventionExecution,
    PolicyArmRoleV2,
    RealizationPolicyV2,
    RealizationSpecV2,
    SemanticVerdict,
    arm_protocol_v2,
    freeze_successor_bundle,
    freeze_successor_policy,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import randomize_successor
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    QueryState,
    Split,
    TargetSpecV2,
    Task,
    source_eligibility_v2,
)
from prompt_mechanism_study.successor_verify import verify_successor_inference


@pytest.mark.reviewer
def test_strong_label_requires_global_intervals_and_heterogeneity_equivalence() -> None:
    randomization, outcomes, policy, tasks = _study()
    plan = _plan(realization_margin=0.5, functionality_margin=0.3)
    result = estimate_successor_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
    )

    assert result.robustness is not None
    assert result.robustness.status is FamilyInferenceStatus.EVALUABLE
    assert {
        item.component for item in result.robustness.intervals
    } == set(SuccessorRobustnessComponent)
    secure = next(item for item in result.estimates if item.metric is Metric.SECURE_YIELD)
    assert len(secure.realization_effects) == 2
    assert len(secure.leave_one_realization_out) == 2
    assert all(len(item.task_unit_effects) == 20 for item in secure.realization_effects)
    assessment = result.robustness.assessments[0]
    assert assessment.direction_consistency_passed
    assert assessment.simultaneous_direction_passed
    assert assessment.heterogeneity_equivalence_passed
    assert assessment.arm_realization_interaction_statistic == 0.0
    assert assessment.arm_realization_randomization_p_value == 1.0
    assert assessment.arm_realization_interaction_passed
    assert assessment.robustness_label == "realization_robust"
    assert assessment.functionality_gate_status is FunctionalityGateStatus.PASSED
    assert assessment.practical_success_label == "practical_success"
    assert secure.robustness_label == "realization_robust"
    assert all(
        item.robustness_label == "not_applicable_non_primary"
        for item in result.estimates
        if item.metric is not Metric.SECURE_YIELD
    )
    assert verify_successor_inference(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
        result,
    )["status"] == "SUCCESSOR_INFERENCE_VERIFIED"
    changed_assessment = replace(
        assessment,
        heterogeneity_simultaneous_upper=float(
            assessment.heterogeneity_simultaneous_upper
        )
        + 0.01,
    )
    tampered = replace(
        result,
        robustness=replace(
            result.robustness,
            assessments=(changed_assessment,),
        ),
    )
    with pytest.raises(ValueError, match="robustness family drift"):
        verify_successor_inference(
            randomization,
            outcomes,
            (policy,),
            tasks,
            plan,
            tampered,
        )


@pytest.mark.reviewer
def test_point_direction_alone_never_awards_strong_label() -> None:
    randomization, outcomes, policy, tasks = _study()
    plan = _plan(realization_margin=0.0, functionality_margin=0.3)
    result = estimate_successor_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
    )

    assessment = result.robustness.assessments[0]
    assert assessment.direction_consistency_passed
    assert assessment.simultaneous_direction_passed
    assert not assessment.heterogeneity_equivalence_passed
    assert assessment.robustness_label == "direction_consistent_diagnostic"
    assert assessment.practical_success_label == "security_robustness_not_established"


@pytest.mark.reviewer
def test_functionality_gate_limits_only_practical_success_label() -> None:
    randomization, outcomes, policy, tasks = _study()
    plan = _plan(realization_margin=0.5, functionality_margin=0.01)
    result = estimate_successor_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
    )

    assessment = result.robustness.assessments[0]
    assert assessment.robustness_label == "realization_robust"
    assert assessment.functionality_gate_status is FunctionalityGateStatus.FAILED
    assert assessment.practical_success_label == "functionality_noninferiority_failed"
    secure = next(item for item in result.estimates if item.metric is Metric.SECURE_YIELD)
    assert secure.robustness_label == "realization_robust"

    not_powered = estimate_successor_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        replace(plan, functionality_noninferiority_separately_powered=False),
    )
    not_powered_assessment = not_powered.robustness.assessments[0]
    assert (
        not_powered_assessment.functionality_gate_status
        is FunctionalityGateStatus.NOT_REQUESTED
    )
    assert (
        not_powered_assessment.practical_success_label
        == "functionality_gate_not_requested"
    )


@pytest.mark.reviewer
def test_strong_label_requires_overall_and_per_realization_support() -> None:
    randomization, outcomes, policy, tasks = _study()
    plan = replace(
        _plan(realization_margin=0.5, functionality_margin=0.3),
        minimum_task_units=21,
        minimum_task_units_per_realization=10,
    )
    result = estimate_successor_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
    )

    assessment = result.robustness.assessments[0]
    assert not assessment.minimum_support_passed
    assert assessment.robustness_label != "realization_robust"
    assert result.robustness.status is FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES
    assert verify_successor_inference(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
        result,
    )["status"] == "SUCCESSOR_INFERENCE_VERIFIED"


def _plan(
    *,
    realization_margin: float,
    functionality_margin: float,
) -> SuccessorAnalysisPlan:
    return SuccessorAnalysisPlan(
        metrics=(Metric.SECURE_YIELD, Metric.FUNCTIONALITY, Metric.JOINT),
        primary_metric=Metric.SECURE_YIELD,
        bootstrap_seed=7221,
        bootstrap_draws=500,
        alpha=0.05,
        minimum_task_units=10,
        minimum_valid_bootstrap_fraction=0.8,
        practical_effect_margin=0.0,
        functionality_noninferiority_margin=functionality_margin,
        minimum_realizations=2,
        minimum_task_units_per_realization=10,
        realization_practical_equivalence_margin=realization_margin,
        realization_direction_consistency_threshold=1.0,
        functionality_noninferiority_separately_powered=True,
    )


def _study():
    protocol = arm_protocol_v2(
        Operation.ADD,
        protocol_policy_sha256=_digest("arm.protocol"),
    )
    realizations = tuple(
        RealizationSpecV2(
            label,
            1,
            "executor.v2",
            tuple(
                (role, f"Implement {label} {role.value}.")
                for role in SUCCESSOR_ARM_ROLE_ORDER
            ),
            _digest(f"matching.{label}"),
            _digest(f"validation.{label}"),
        )
        for label in ("direct", "constraint")
    )
    realization_policy = RealizationPolicyV2(
        "add.two-realization",
        protocol,
        realizations,
    )
    skeleton = CandidateSkeletonV2(
        "sql.parameterization.add",
        "context.sql.user_input",
        ("guard.sql.parameterization",),
        Operation.ADD,
        "CWE-89",
        "database",
        "oracle_evaluable_secure_code_yield",
        ExpectedDirection.INCREASE,
        realization_policy.realization_policy_id,
    )
    target = TargetSpecV2(
        skeleton.candidate_skeleton_id,
        skeleton.context_query_id,
        skeleton.actionable_feature_id,
        Operation.ADD,
        _digest("context.catalog"),
        _digest("feature.catalog"),
        _digest("allowed.delta"),
    )
    hypothesis = FrozenHypothesisV2(skeleton, target)
    tasks = tuple(
        Task(
            f"task.{index}",
            f"unit.{index}",
            "CWE-89",
            "database",
            Split.CONFIRM,
            f"Implement database lookup {index}.",
        )
        for index in range(20)
    )
    eligibilities = []
    bundles = []
    for index, task in enumerate(tasks):
        eligibility = source_eligibility_v2(
            hypothesis,
            task_id=task.task_id,
            task_unit_id=task.semantic_cluster_id,
            prompt_tsg_id=f"tsg.{index}",
            prompt_sha256=task.prompt_sha256,
            context_state=QueryState.PRESENT,
            feature_state=QueryState.ABSENT,
            eligibility_policy_sha256=_digest("eligibility"),
        )
        eligibilities.append(eligibility)
        for realization in realizations:
            bundles.append(
                freeze_successor_bundle(
                    hypothesis,
                    eligibility=eligibility,
                    source_prompt=task.prompt,
                    realization=realization,
                    arm_protocol=protocol,
                    executions={
                        role: InterventionExecution(
                            f"Task {index} {realization.label} {role.value}.",
                            realization.executor_adapter_id,
                            _digest(
                                f"execution.{index}.{realization.label}.{role.value}"
                            ),
                        )
                        for role in SUCCESSOR_ARM_ROLE_ORDER
                    },
                    validations={
                        role: _arm_validation(index, realization.label, role)
                        for role in SUCCESSOR_ARM_ROLE_ORDER
                    },
                    bundle_validation=BundleValidationV2(
                        SemanticVerdict.YES,
                        SemanticVerdict.YES,
                        SemanticVerdict.YES,
                        "validator.v2",
                        _digest(f"bundle.{index}.{realization.label}"),
                    ),
                )
            )
    policy = freeze_successor_policy(
        hypothesis,
        realization_policy,
        tuple(eligibilities),
        tuple(bundles),
    )
    randomization = randomize_successor(
        (policy,),
        population_id="population.v2",
        selection_id="selection.v2",
        models=("model.a",),
        request_randomness_slots=(0, 1, 2, 3),
        seed=8891,
        provider_seed=None,
    )
    secure_zeros = {
        realizations[0].realization_spec_id: {0, 5, 10, 15},
        realizations[1].realization_spec_id: {1, 6, 11, 16},
    }
    outcomes = []
    for assignment in randomization.assignments:
        index = int(assignment.block.task_instance_id.rsplit(".", 1)[1])
        if assignment.arm_role is PolicyArmRoleV2.TARGET:
            secure = int(
                index
                not in secure_zeros[assignment.block.realization_spec_id]
            )
            functionality = int(index not in {0, 10})
        else:
            secure = 0
            functionality = 1
        outcomes.append(
            Outcome(
                assignment.assignment_id,
                code_valid=1,
                oracle_evaluable=1,
                secure_yield=secure,
                latent_secure_upper=secure,
                functionality=functionality,
                joint=secure * functionality,
                latent_joint_upper=secure * functionality,
                terminal_status=None,
            )
        )
    return randomization, tuple(outcomes), policy, tasks


def _arm_validation(
    index: int,
    realization: str,
    role: PolicyArmRoleV2,
) -> ArmSemanticValidationV2:
    return ArmSemanticValidationV2(
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.NO,
        "validator.v2",
        _digest(f"arm.{index}.{realization}.{role.value}"),
    )


def _digest(label: str) -> str:
    return content_hash(label)

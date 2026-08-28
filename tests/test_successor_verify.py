from __future__ import annotations

from dataclasses import replace

import pytest

from prompt_mechanism_study.inference import (
    FamilyInferenceStatus,
    Metric,
    SuccessorAnalysisPlan,
    SuccessorContrast,
    SuccessorIntervalFamily,
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
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.randomization import randomize_successor
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    Split,
    TargetSpecV2,
    Task,
    source_eligibility_v2,
)
from prompt_mechanism_study.successor_verify import verify_successor_inference


@pytest.mark.reviewer
def test_independent_successor_verifier_recomputes_bounds_and_three_families() -> None:
    randomization, outcomes, policy, tasks, plan, observed = _study()
    report = verify_successor_inference(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
        observed,
    )

    assert report["status"] == "SUCCESSOR_INFERENCE_VERIFIED"
    assert report["assignments"] == 24
    assert report["intervals"] == 4
    assert set(report["family_statuses"].values()) == {
        FamilyInferenceStatus.EVALUABLE.value
    }
    secure = next(item for item in observed.estimates if item.metric is Metric.SECURE_YIELD)
    specificity = secure.contrast(SuccessorContrast.TARGET_GENERIC)
    assert specificity.point == pytest.approx(1 / 3)
    assert specificity.lower_bound == pytest.approx(1 / 6)
    assert specificity.upper_bound == pytest.approx(1 / 3)
    assert tuple(item.family for item in observed.families) == tuple(
        SuccessorIntervalFamily
    )


@pytest.mark.reviewer
def test_independent_successor_verifier_rejects_missing_duplicate_and_replaced_rows() -> None:
    randomization, outcomes, policy, tasks, plan, observed = _study()
    missing_randomization = replace(
        randomization,
        assignments=randomization.assignments[:-1],
    )
    kept = {item.assignment_id for item in missing_randomization.assignments}
    with pytest.raises(ValueError, match="slot support"):
        verify_successor_inference(
            missing_randomization,
            tuple(item for item in outcomes if item.assignment_id in kept),
            (policy,),
            tasks,
            plan,
            observed,
        )

    with pytest.raises(ValueError, match="exactly once"):
        verify_successor_inference(
            randomization,
            (*outcomes, outcomes[0]),
            (policy,),
            tasks,
            plan,
            observed,
        )

    original = randomization.assignments[0]
    replaced_assignment = replace(original, variant_sha256="0" * 64)
    replaced_randomization = replace(
        randomization,
        assignments=(replaced_assignment, *randomization.assignments[1:]),
    )
    replaced_outcomes = tuple(
        replace(item, assignment_id=replaced_assignment.assignment_id)
        if item.assignment_id == original.assignment_id
        else item
        for item in outcomes
    )
    with pytest.raises(ValueError, match="variant binding"):
        verify_successor_inference(
            replaced_randomization,
            replaced_outcomes,
            (policy,),
            tasks,
            plan,
            observed,
        )


@pytest.mark.reviewer
def test_independent_successor_verifier_rejects_estimate_and_interval_tampering() -> None:
    randomization, outcomes, policy, tasks, plan, observed = _study()
    estimate = observed.estimates[0]
    primary = estimate.contrasts[0]
    changed_estimate = replace(
        estimate,
        contrasts=(
            replace(primary, point=float(primary.point) + 0.1),
            *estimate.contrasts[1:],
        ),
    )
    changed_result = replace(
        observed,
        estimates=(changed_estimate, *observed.estimates[1:]),
    )
    with pytest.raises(ValueError, match="estimate drift"):
        verify_successor_inference(
            randomization,
            outcomes,
            (policy,),
            tasks,
            plan,
            changed_result,
        )

    family = observed.families[0]
    interval = family.intervals[0]
    changed_family = replace(
        family,
        intervals=(replace(interval, lower=interval.lower + 0.01),),
    )
    changed_result = replace(
        observed,
        families=(changed_family, *observed.families[1:]),
    )
    with pytest.raises(ValueError, match="bootstrap family drift"):
        verify_successor_inference(
            randomization,
            outcomes,
            (policy,),
            tasks,
            plan,
            changed_result,
        )


@pytest.mark.reviewer
def test_successor_claim_gate_fails_closed_when_one_arm_has_zero_valid_code() -> None:
    randomization, outcomes, policy, tasks, plan, _observed = _study()
    plan = replace(
        plan,
        metrics=(
            Metric.SECURE_YIELD,
            Metric.CODE_VALID,
            Metric.ORACLE_EVALUABLE,
            Metric.FUNCTIONALITY,
            Metric.JOINT,
        ),
    )
    target_ids = {
        item.assignment_id
        for item in randomization.assignments
        if item.arm_role is PolicyArmRoleV2.TARGET
    }
    zero_valid_outcomes = tuple(
        replace(
            outcome,
            code_valid=0,
            oracle_evaluable=0,
            secure_yield=0,
            latent_secure_upper=0,
            functionality=0,
            joint=0,
            latent_joint_upper=0,
            terminal_status="invalid",
        )
        if outcome.assignment_id in target_ids
        else outcome
        for outcome in outcomes
    )
    observed = estimate_successor_effects(
        randomization,
        zero_valid_outcomes,
        (policy,),
        tasks,
        plan,
    )

    report = verify_successor_inference(
        randomization,
        zero_valid_outcomes,
        (policy,),
        tasks,
        plan,
        observed,
        maximum_unknown_fraction=0.25,
        scientific_claim_allowed=True,
    )

    assert report["claim_assessments"]
    for assessment in report["claim_assessments"]:
        gate = assessment["gate"]
        assert gate["code_valid_yield_by_arm"]["target"] == 0.0
        assert gate["unknown_fraction_among_valid_code_by_arm"]["target"] is None
        assert gate["unknown_gate_evaluable"] is False
        assert gate["unknown_gate_passed"] is False
        assert gate["security_claim_ready"] is False
        assert gate["practical_success_claim_ready"] is False


def _study():
    protocol = arm_protocol_v2(
        Operation.ADD,
        protocol_policy_sha256=_digest("arm.protocol"),
    )
    realization = RealizationSpecV2(
        "direct",
        1,
        "executor.v2",
        tuple(
            (role, f"Implement the frozen {role.value} role.")
            for role in SUCCESSOR_ARM_ROLE_ORDER
        ),
        _digest("matching"),
        _digest("validation"),
    )
    realization_policy = RealizationPolicyV2(
        "add.direct",
        protocol,
        (realization,),
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
        for index in range(6)
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
        bundles.append(
            freeze_successor_bundle(
                hypothesis,
                eligibility=eligibility,
                source_prompt=task.prompt,
                realization=realization,
                arm_protocol=protocol,
                executions={
                    role: InterventionExecution(
                        f"Task {index} {role.value} requirement.",
                        realization.executor_adapter_id,
                        _digest(f"execution.{index}.{role.value}"),
                    )
                    for role in SUCCESSOR_ARM_ROLE_ORDER
                },
                validations={
                    role: _arm_validation(index, role)
                    for role in SUCCESSOR_ARM_ROLE_ORDER
                },
                bundle_validation=BundleValidationV2(
                    SemanticVerdict.YES,
                    SemanticVerdict.YES,
                    SemanticVerdict.YES,
                    "validator.v2",
                    _digest(f"bundle.validation.{index}"),
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
        seed=20260828,
        provider_seed=None,
    )
    secure = {
        PolicyArmRoleV2.TARGET: (1, 1, 1, 1, 0, 0),
        PolicyArmRoleV2.NOOP: (0, 0, 1, 0, 0, 1),
        PolicyArmRoleV2.PLACEBO: (0, 1, 0, 1, 0, 0),
        PolicyArmRoleV2.GENERIC: (0, 0, 0, 1, 1, 0),
    }
    outcomes = []
    for assignment in randomization.assignments:
        index = int(assignment.block.task_instance_id.rsplit(".", 1)[1])
        value = secure[assignment.arm_role][index]
        unknown = assignment.arm_role is PolicyArmRoleV2.GENERIC and index == 5
        outcomes.append(
            Outcome(
                assignment.assignment_id,
                code_valid=1,
                oracle_evaluable=0 if unknown else 1,
                secure_yield=value,
                latent_secure_upper=1 if unknown else value,
                functionality=1,
                joint=None if unknown else value,
                latent_joint_upper=1 if unknown else value,
                terminal_status=None,
            )
        )
    plan = SuccessorAnalysisPlan(
        (Metric.SECURE_YIELD, Metric.FUNCTIONALITY, Metric.JOINT),
        Metric.SECURE_YIELD,
        93017,
        300,
        0.05,
        minimum_task_units=2,
        minimum_valid_bootstrap_fraction=0.8,
        practical_effect_margin=0.0,
        functionality_noninferiority_margin=0.1,
    )
    observed = estimate_successor_effects(
        randomization,
        tuple(outcomes),
        (policy,),
        tasks,
        plan,
    )
    return randomization, tuple(outcomes), policy, tasks, plan, observed


def _arm_validation(index: int, role: PolicyArmRoleV2) -> ArmSemanticValidationV2:
    return ArmSemanticValidationV2(
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.NO,
        "validator.v2",
        _digest(f"arm.validation.{index}.{role.value}"),
    )


def _digest(label: str) -> str:
    return content_hash(label)

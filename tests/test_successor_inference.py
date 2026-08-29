from __future__ import annotations

import pytest

from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.inference import (
    FamilyInferenceStatus,
    Metric,
    SuccessorAnalysisPlan,
    SuccessorContrast,
    SuccessorIntervalFamily,
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
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.prompt_tsg import QueryState
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
from prompt_mechanism_study.workflow import (
    SuccessorSelectionProvenance,
    analyze_successor,
    freeze_successor_study,
)
from prompt_mechanism_study.successor_verify import verify_successor_inference

pytestmark = pytest.mark.extended


@pytest.mark.reviewer
def test_successor_workflow_estimates_four_arms_and_preserves_unknown_bounds() -> None:
    tasks = tuple(
        Task(
            f"task.{index}",
            f"unit.{index}",
            "CWE-89",
            "database",
            Split.CONFIRM,
            f"Implement database lookup {index}.",
        )
        for index in range(1, 9)
    )
    adapters = _adapters()
    policy, hypothesis, eligibilities = _policy(
        tasks,
        adapters.intervention_executor.adapter_id,
        adapters.intervention_validator.adapter_id,
    )
    plan = SuccessorAnalysisPlan(
        (Metric.SECURE_YIELD, Metric.FUNCTIONALITY, Metric.JOINT),
        Metric.SECURE_YIELD,
        8801,
        300,
        0.05,
        minimum_task_units=4,
        minimum_valid_bootstrap_fraction=0.75,
        practical_effect_margin=0.0,
        functionality_noninferiority_margin=0.1,
    )
    study = freeze_successor_study(
        tasks,
        (hypothesis,),
        eligibilities,
        (policy,),
        adapters,
        plan,
        selection_provenance=SuccessorSelectionProvenance(
            "frozen_registry",
            "candidate-universe.v2",
            "selection-freeze.v2",
            content_hash("selection-registry.v2"),
            selected_predecessor_ids=(hypothesis.skeleton.candidate_key,),
        ),
        models=("model.a",),
        request_randomness_slots=(0, 1, 2, 3),
        randomization_seed=991,
        provider_seed=None,
    )
    analysis = analyze_successor(study, _measurements(study))

    estimate = next(
        item for item in analysis.inference.estimates if item.metric is Metric.SECURE_YIELD
    )
    arms = {item.role: item for item in estimate.arms}
    assert arms[PolicyArmRoleV2.TARGET].point == pytest.approx(5 / 8)
    assert arms[PolicyArmRoleV2.NOOP].point == pytest.approx(2 / 8)
    assert arms[PolicyArmRoleV2.PLACEBO].point == pytest.approx(2 / 8)
    assert arms[PolicyArmRoleV2.GENERIC].point == pytest.approx(3 / 8)
    assert estimate.contrast(SuccessorContrast.TARGET_NOOP).point == pytest.approx(3 / 8)
    assert estimate.contrast(SuccessorContrast.TARGET_PLACEBO).point == pytest.approx(3 / 8)
    assert estimate.contrast(SuccessorContrast.TARGET_GENERIC).point == pytest.approx(2 / 8)
    primary = estimate.contrast(SuccessorContrast.TARGET_NOOP)
    assert primary.lower_bound == pytest.approx(3 / 8)
    assert primary.upper_bound == pytest.approx(4 / 8)
    assert estimate.robustness_label == "average_effect_only"

    families = {item.family: item for item in analysis.inference.families}
    assert families[SuccessorIntervalFamily.PRIMARY_SECURITY].status is (
        FamilyInferenceStatus.EVALUABLE
    )
    assert families[SuccessorIntervalFamily.SECURITY_SPECIFICITY].status is (
        FamilyInferenceStatus.EVALUABLE
    )
    assert families[SuccessorIntervalFamily.JOINT_OUTCOME].status is (
        FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES
    )
    assert len(analysis.outcomes) == len(study.randomization.assignments) == 32
    unknown_assignment = next(
        item
        for item in study.randomization.assignments
        if item.block.task_instance_id == "task.8"
        and item.arm_role is PolicyArmRoleV2.TARGET
    )
    unknown = next(
        item for item in analysis.outcomes if item.assignment_id == unknown_assignment.assignment_id
    )
    assert unknown.secure_yield == 0
    assert unknown.latent_secure_upper == 1


def test_successor_primary_family_preserves_partial_support_dependence() -> None:
    tasks = tuple(
        Task(
            f"task.{index}",
            f"unit.{index}",
            "CWE-89",
            "database",
            Split.CONFIRM,
            f"Implement database lookup {index}.",
        )
        for index in range(1, 9)
    )
    adapters = _adapters()
    first = _policy(
        tasks,
        adapters.intervention_executor.adapter_id,
        adapters.intervention_validator.adapter_id,
    )
    second = _policy(
        tasks[1:],
        adapters.intervention_executor.adapter_id,
        adapters.intervention_validator.adapter_id,
        candidate_name="sql.parameterization.add.replication",
    )
    policies = tuple(
        sorted((first[0], second[0]), key=lambda item: item.intervention_policy_id)
    )
    hypotheses = tuple(
        sorted((first[1], second[1]), key=lambda item: item.hypothesis_id)
    )
    missing_gate = source_eligibility_v2(
        second[1],
        task_id=tasks[0].task_id,
        task_unit_id=tasks[0].semantic_cluster_id,
        prompt_tsg_id=f"tsg.{tasks[0].task_id}",
        prompt_sha256=tasks[0].prompt_sha256,
        context_state=QueryState.ABSENT,
        feature_state=QueryState.ABSENT,
        eligibility_policy_sha256=_hash("eligibility"),
    )
    eligibilities = tuple(
        sorted(
            (*first[2], *second[2], missing_gate),
            key=lambda item: (item.hypothesis_id, item.task_id),
        )
    )
    plan = SuccessorAnalysisPlan(
        (Metric.SECURE_YIELD, Metric.FUNCTIONALITY, Metric.JOINT),
        Metric.SECURE_YIELD,
        8802,
        300,
        0.05,
        minimum_task_units=4,
        minimum_valid_bootstrap_fraction=0.75,
    )
    study = freeze_successor_study(
        tasks,
        hypotheses,
        eligibilities,
        policies,
        adapters,
        plan,
        selection_provenance=SuccessorSelectionProvenance(
            "frozen_registry",
            "candidate-universe.v2",
            "selection-freeze.v2",
            content_hash("selection-registry.partial.v2"),
            selected_predecessor_ids=tuple(
                sorted(item.skeleton.candidate_key for item in hypotheses)
            ),
        ),
        models=("model.a",),
        request_randomness_slots=(0, 1, 2, 3),
        randomization_seed=992,
        provider_seed=None,
    )
    analysis = analyze_successor(study, _measurements(study))

    verification = verify_successor_inference(
        study.randomization,
        analysis.outcomes,
        policies,
        tasks,
        plan,
        analysis.inference,
    )
    primary = next(
        item
        for item in analysis.inference.families
        if item.family is SuccessorIntervalFamily.PRIMARY_SECURITY
    )

    assert primary.status is FamilyInferenceStatus.EVALUABLE
    assert len(primary.intervals) == 2
    assert verification["status"] == "SUCCESSOR_INFERENCE_VERIFIED"


def _policy(
    tasks: tuple[Task, ...],
    executor_id: str,
    validator_id: str,
    *,
    candidate_name: str = "sql.parameterization.add",
):
    protocol = arm_protocol_v2(Operation.ADD, protocol_policy_sha256=_hash("protocol"))
    realization = RealizationSpecV2(
        "direct",
        1,
        executor_id,
        tuple((role, f"Apply the {role.value} policy.") for role in SUCCESSOR_ARM_ROLE_ORDER),
        _hash("matching"),
        _hash("validation"),
    )
    realization_policy = RealizationPolicyV2("add.direct", protocol, (realization,))
    skeleton = CandidateSkeletonV2(
        candidate_name,
        "context.sql.user_input",
        ("guard.sql.value_parameterization",),
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
        _hash("context-catalog"),
        _hash("feature-catalog"),
        _hash("allowed-delta"),
    )
    hypothesis = FrozenHypothesisV2(skeleton, target)
    eligibilities = tuple(
        source_eligibility_v2(
            hypothesis,
            task_id=task.task_id,
            task_unit_id=task.semantic_cluster_id,
            prompt_tsg_id=f"tsg.{task.task_id}",
            prompt_sha256=task.prompt_sha256,
            context_state=QueryState.PRESENT,
            feature_state=QueryState.ABSENT,
            eligibility_policy_sha256=_hash("eligibility"),
        )
        for task in tasks
    )
    bundles = tuple(
        freeze_successor_bundle(
            hypothesis,
            eligibility=eligibility,
            source_prompt=task.prompt,
            realization=realization,
            arm_protocol=protocol,
            executions={
                role: InterventionExecution(
                    f"{task.task_id}: {role.value} instruction.",
                    realization.executor_adapter_id,
                    _hash(f"execution:{task.task_id}:{role.value}"),
                )
                for role in SUCCESSOR_ARM_ROLE_ORDER
            },
            validations={
                role: ArmSemanticValidationV2(
                    SemanticVerdict.YES,
                    SemanticVerdict.YES,
                    SemanticVerdict.YES,
                    SemanticVerdict.YES,
                    SemanticVerdict.NO,
                    validator_id,
                    _hash(f"arm-validation:{task.task_id}:{role.value}"),
                )
                for role in SUCCESSOR_ARM_ROLE_ORDER
            },
            bundle_validation=BundleValidationV2(
                SemanticVerdict.YES,
                SemanticVerdict.YES,
                SemanticVerdict.YES,
                validator_id,
                _hash(f"bundle-validation:{task.task_id}"),
            ),
        )
        for task, eligibility in zip(tasks, eligibilities, strict=True)
    )
    return (
        freeze_successor_policy(
            hypothesis,
            realization_policy,
            eligibilities,
            bundles,
        ),
        hypothesis,
        eligibilities,
    )


def _measurements(study) -> tuple[Measurement, ...]:
    secure = {
        1: {"target"},
        2: {"target", "placebo"},
        3: set(),
        4: {"target", "noop", "generic"},
        5: {"target", "generic"},
        6: {"noop"},
        7: {"target", "placebo", "generic"},
        8: set(),
    }
    rows = []
    for assignment in study.randomization.assignments:
        index = int(assignment.block.task_instance_id.rsplit(".", 1)[1])
        if index == 8 and assignment.arm_role is PolicyArmRoleV2.TARGET:
            oracle = OracleStatus.UNKNOWN
        else:
            oracle = (
                OracleStatus.SECURE
                if assignment.arm_role.value in secure[index]
                else OracleStatus.INSECURE
            )
        rows.append(
            Measurement(
                assignment.assignment_id,
                CodeStatus.VALID,
                oracle,
                FunctionalStatus.PASS,
                _hash(f"generator:{assignment.assignment_id}"),
                _hash(f"code:{assignment.assignment_id}"),
                _hash(f"oracle:{assignment.assignment_id}"),
                _hash(f"functional:{assignment.assignment_id}"),
            )
        )
    return tuple(rows)


def _adapters() -> AdapterBundle:
    return AdapterBundle(
        _adapter(AdapterKind.REPRESENTATION, "representation"),
        _adapter(AdapterKind.SELECTOR, "selector"),
        _adapter(AdapterKind.INTERVENTION_EXECUTOR, "executor.v2"),
        _adapter(AdapterKind.INTERVENTION_VALIDATOR, "validator.v2"),
        _adapter(AdapterKind.GENERATOR, "generator"),
        _adapter(AdapterKind.SECURITY_ORACLE, "oracle"),
        _adapter(AdapterKind.FUNCTIONAL_EVALUATOR, "functional"),
    )


def _adapter(kind: AdapterKind, name: str) -> AdapterSpec:
    return AdapterSpec(kind, name, "1", _hash(name))


def _hash(value: str) -> str:
    return content_hash(value)

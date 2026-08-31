from __future__ import annotations

from dataclasses import replace

import pytest

from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.inference import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    FamilyInferenceStatus,
    Metric,
    SuccessorAnalysisPlan,
    SuccessorContrast,
    SuccessorIntervalFamily,
    TargetFamilyStatus,
    TargetITTPlan,
    build_target_selector_yields,
    classify_confirmatory_interval,
    estimate_target_itt,
    freeze_assigned_arm_evidence,
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
    InfrastructureFailure,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
)
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.selector_analysis import build_target_rq_tables
from prompt_mechanism_study.selector_verify import (
    verify_target_rq_tables,
    verify_target_shared_evidence,
)
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    ModelBoundCandidateRecord,
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


def _target_v3_fixture():
    atomic_record = ModelBoundCandidateRecord(
        "atomic-policy-v3",
        "model.atomic",
        "phase-context-policy-v3",
        "3.0",
    )
    pair_record = ModelBoundCandidateRecord(
        "pair-policy-v3",
        "model.pair",
        "phase-context-policy-v3",
        "3.0",
    )
    sources = (
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_full",
            atomic_record.discovery_model_id,
            "atomic-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, atomic_record.policy_key, None),),
            (atomic_record,),
        ),
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_rd_only",
            atomic_record.discovery_model_id,
            "atomic-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, atomic_record.policy_key, None),),
            (atomic_record,),
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_full",
            pair_record.discovery_model_id,
            "pair-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, pair_record.policy_key, None),),
            (pair_record,),
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_no_relation",
            pair_record.discovery_model_id,
            "pair-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, pair_record.policy_key, None),),
            (pair_record,),
        ),
    )
    ledger = freeze_fixed_slot_ledger(
        "phase-context-policy-v3",
        "3.0",
        sources,
    )
    union = freeze_shared_confirmation_union(ledger)
    dispatch = freeze_confirmation_dispatch(
        union,
        {
            atomic_record.candidate_record_id: "atomic-protocol-record-v3",
            pair_record.candidate_record_id: "pair-protocol-record-v3",
        },
    )
    entry_by_track = {item.track: item for item in union.entries}
    dispatch_by_candidate = {
        item.candidate_record_id: item for item in dispatch.records
    }
    assignments = []
    outcomes = []
    for track, arms in (
        (PolicyTrack.ATOMIC, ATOMIC_CONFIRMATORY_ARMS),
        (PolicyTrack.PAIR, PAIR_CONFIRMATORY_ARMS),
    ):
        entry = entry_by_track[track]
        dispatched = dispatch_by_candidate[entry.candidate_record_id]
        for index in range(12):
            for request_slot, arm in enumerate(arms):
                assignment = AssignedArmITTRecord(
                    entry.candidate_record_id,
                    entry.effect_coordinate_id,
                    entry.candidate.policy_key,
                    entry.candidate.discovery_model_id,
                    track,
                    f"{track.value}-unit-{index:02d}",
                    f"{track.value}-task-{index:02d}",
                    "synthetic-stratum",
                    f"{track.value}-realization-v1",
                    f"{track.value}-bundle-{index:02d}",
                    dispatched.protocol_record_id,
                    request_slot,
                    arm,
                    1.0,
                    1.0,
                    content_hash((track.value, index, arm.value)),
                )
                assignments.append(assignment)
                if track is PolicyTrack.ATOMIC:
                    secure = (
                        index < 10
                        if arm.value == "atomic_target"
                        else index < 1
                        if arm.value == "atomic_noop"
                        else index % 3 == 0
                    )
                    unknown = arm.value == "atomic_target" and index == 11
                else:
                    secure = (
                        index < 10
                        if arm.value == "pair_11"
                        else index < 1
                    )
                    unknown = False
                outcomes.append(
                    Outcome(
                        assignment.assignment_id,
                        1,
                        0 if unknown else 1,
                        int(secure and not unknown),
                        int(secure or unknown),
                        1,
                        None if unknown else int(secure),
                        int(secure or unknown),
                        None,
                    )
                )
    evidence = freeze_assigned_arm_evidence(dispatch, assignments, outcomes)
    plan = TargetITTPlan(
        20260831,
        300,
        0.05,
        4,
        0.8,
        0.05,
        0.05,
        0.5,
    )
    return evidence, plan


@pytest.mark.reviewer
def test_target_v3_shared_itt_confirms_each_unique_effect_once_and_fans_out() -> None:
    evidence, plan = _target_v3_fixture()

    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)
    verification = verify_target_shared_evidence(result, yields)

    assert tuple(item.status for item in result.families) == (
        TargetFamilyStatus.EVALUABLE,
        TargetFamilyStatus.EVALUABLE,
    )
    estimates = tuple(item for family in result.families for item in family.estimates)
    assert len(estimates) == 2
    assert all(item.status is ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL for item in estimates)
    assert all(item.assignments == 48 and item.task_units == 12 for item in estimates)
    atomic = next(item for item in estimates if item.track is PolicyTrack.ATOMIC)
    assert atomic.point == pytest.approx(0.75)
    assert atomic.latent_upper > atomic.point
    target_summary = atomic.arm_summaries[0]
    assert target_summary.oracle_unknown_valid_assignments == 1
    assert len(yields.slots) == 4
    assert all(item.meaningful_yield == 1 for item in yields.slots)
    assert all(item.top_k == 1 and item.meaningful_yield_at_k == 1 for item in yields.selectors)
    assert verification["status"] == "TARGET_SHARED_EVIDENCE_VERIFIED"


@pytest.mark.reviewer
def test_target_v3_rq_tables_are_fixed_denominator_and_claim_gated() -> None:
    evidence, plan = _target_v3_fixture()
    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)

    report = build_target_rq_tables(result, yields)
    verification = verify_target_rq_tables(result, yields, report)

    assert report["report_status"] == "NON_CLAIM_TEST_ARTIFACT"
    assert report["scientific_claim_allowed"] is False
    assert len(report["rq1_selector_rows"]) == 4
    assert len(report["rq2_full_minus_ablation_rows"]) == 2
    assert all(
        row["top_k"] == 1 and row["meaningful_yield_at_k"] == 1.0
        for row in report["rq1_selector_rows"]
    )
    assert all(
        row["full_minus_ablation_yield_at_k"] == 0.0
        and row["comparison_semantics"]
        == "descriptive_fixed_discovery_split_no_rank_pairing"
        for row in report["rq2_full_minus_ablation_rows"]
    )
    assert verification["status"] == "TARGET_RQ_TABLES_VERIFIED"

    tampered = {
        **report,
        "rq2_full_minus_ablation_rows": [
            {**report["rq2_full_minus_ablation_rows"][0], "top_k": 99},
            *report["rq2_full_minus_ablation_rows"][1:],
        ],
    }
    tampered["target_rq_tables_id"] = content_hash(tampered)
    with pytest.raises(ValueError, match="failed independent replay"):
        verify_target_rq_tables(result, yields, tampered)


@pytest.mark.reviewer
def test_target_v3_independent_verifier_rejects_effect_drift() -> None:
    evidence, plan = _target_v3_fixture()
    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    estimate = result.families[0].estimates[0]
    tampered_estimate = replace(estimate, point=estimate.point + 0.01)
    tampered_family = replace(
        result.families[0],
        estimates=(tampered_estimate,),
    )
    tampered = replace(
        result,
        families=(tampered_family, result.families[1]),
    )
    yields = build_target_selector_yields(tampered)

    with pytest.raises(ValueError, match="point estimate"):
        verify_target_shared_evidence(tampered, yields)


@pytest.mark.reviewer
def test_target_v3_missing_assigned_outcome_invalidates_only_its_frozen_family() -> None:
    evidence, plan = _target_v3_fixture()
    missing = next(
        item
        for item in evidence.assignments
        if item.track is PolicyTrack.ATOMIC
    )
    outcomes = tuple(
        item for item in evidence.outcomes if item.assignment_id != missing.assignment_id
    )
    incomplete = freeze_assigned_arm_evidence(
        evidence.dispatch,
        evidence.assignments,
        outcomes,
        (InfrastructureFailure(missing.assignment_id, "generator", "synthetic failure"),),
    )

    result = estimate_target_itt(incomplete, plan, evidence_level=EvidenceLevel.TESTED)

    assert result.families[0].status is TargetFamilyStatus.INVALID_PROVENANCE
    assert result.families[0].estimates[0].status is ConfirmatoryEffectStatus.NON_EVALUABLE
    assert result.families[1].status is TargetFamilyStatus.EVALUABLE
    assert len(incomplete.outcomes) + len(incomplete.infrastructure_failures) == len(
        incomplete.assignments
    )


@pytest.mark.reviewer
def test_target_v3_protocolization_failure_keeps_slots_but_creates_no_test() -> None:
    evidence, plan = _target_v3_fixture()
    entry_by_track = {
        item.track: item for item in evidence.dispatch.union.entries
    }
    atomic = entry_by_track[PolicyTrack.ATOMIC]
    pair = entry_by_track[PolicyTrack.PAIR]
    dispatch = freeze_confirmation_dispatch(
        evidence.dispatch.union,
        {atomic.candidate_record_id: "atomic-protocol-record-v3"},
        failures={
            pair.candidate_record_id: (
                BridgeStatus.PROTOCOLIZATION_FAILED,
                "synthetic protocolization failure",
            )
        },
    )
    assignments = tuple(
        item
        for item in evidence.assignments
        if item.candidate_record_id == atomic.candidate_record_id
    )
    assignment_ids = {item.assignment_id for item in assignments}
    outcomes = tuple(
        item for item in evidence.outcomes if item.assignment_id in assignment_ids
    )
    atomic_only = freeze_assigned_arm_evidence(dispatch, assignments, outcomes)

    result = estimate_target_itt(atomic_only, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)
    verification = verify_target_shared_evidence(result, yields)

    assert result.families[1].status is TargetFamilyStatus.NO_ELIGIBLE_COORDINATES
    assert not result.families[1].estimates
    pair_slots = [item for item in yields.slots if item.track is PolicyTrack.PAIR]
    assert len(pair_slots) == 2
    assert all(item.meaningful_yield == 0 and item.effect_status is None for item in pair_slots)
    assert verification["unique_effects"] == 1


@pytest.mark.reviewer
def test_target_v3_five_status_boundaries_are_direction_free() -> None:
    margin = 0.1

    assert classify_confirmatory_interval(0.100001, 0.3, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL
    )
    assert classify_confirmatory_interval(-0.3, -0.100001, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL
    )
    assert classify_confirmatory_interval(-0.1, 0.1, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.PRACTICALLY_NULL
    )
    assert classify_confirmatory_interval(0.1, 0.1, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.PRACTICALLY_NULL
    )
    assert classify_confirmatory_interval(-0.2, 0.2, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.INCONCLUSIVE
    )
    assert classify_confirmatory_interval(None, None, margin, evaluable=False) is (
        ConfirmatoryEffectStatus.NON_EVALUABLE
    )

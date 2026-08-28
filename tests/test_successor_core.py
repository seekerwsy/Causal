from __future__ import annotations

from collections import Counter
from dataclasses import replace

import pytest

from prompt_mechanism_study.intervention import (
    ADD_ARM_LABELS_V2,
    REMOVE_ARM_LABELS_V2,
    SUCCESSOR_ARM_ROLE_ORDER,
    ArmProtocolV2,
    ArmSemanticValidationV2,
    BundleValidationV2,
    InterventionExecution,
    InterventionPolicyV2,
    PolicyArmRoleV2,
    RealizationPolicyV2,
    RealizationSpecV2,
    SemanticVerdict,
    arm_protocol_v2,
    freeze_successor_bundle,
    freeze_successor_policy,
)
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.randomization import (
    randomize_successor,
    verify_successor_randomization,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    EligibilityDecisionV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    SourceEligibilityV2,
    TargetSpecV2,
    source_eligibility_v2,
)


@pytest.mark.reviewer
def test_successor_candidate_is_atomic_and_add_remove_have_distinct_identities() -> None:
    add_policy = _realization_policy(Operation.ADD)
    remove_policy = _realization_policy(Operation.REMOVE)
    add = _hypothesis(Operation.ADD, add_policy)
    remove = _hypothesis(Operation.REMOVE, remove_policy)

    assert add.hypothesis_id != remove.hypothesis_id
    assert add.target_spec.target_spec_id != remove.target_spec.target_spec_id
    assert add_policy.arm_protocol.arm_labels == ADD_ARM_LABELS_V2
    assert remove_policy.arm_protocol.arm_labels == REMOVE_ARM_LABELS_V2

    with pytest.raises(ValueError, match="exactly one actionable feature"):
        CandidateSkeletonV2(
            "composite",
            "context.sql",
            ("guard.value", "guard.identifier"),
            Operation.ADD,
            "CWE-89",
            "database",
            "secure_yield",
            ExpectedDirection.INCREASE,
            add_policy.realization_policy_id,
        )


@pytest.mark.reviewer
def test_source_gate_requires_absent_for_add_and_attested_present_for_remove() -> None:
    prompt = "Implement a database lookup."
    add = _hypothesis(Operation.ADD, _realization_policy(Operation.ADD))
    add_pass = _eligibility(add, prompt=prompt, feature_state=QueryState.ABSENT)
    add_fail = _eligibility(add, prompt=prompt, feature_state=QueryState.PRESENT)
    assert add_pass.eligible
    assert add_fail.decision is EligibilityDecisionV2.EXCLUDED
    assert add_fail.exclusion_reason == "add_source_present"
    with pytest.raises(ValueError, match="does not satisfy"):
        replace(
            add_fail,
            decision=EligibilityDecisionV2.ELIGIBLE,
            exclusion_reason=None,
        )

    remove = _hypothesis(Operation.REMOVE, _realization_policy(Operation.REMOVE))
    no_evidence = _eligibility(
        remove,
        prompt=prompt,
        feature_state=QueryState.PRESENT,
        counterpart="Keep the functional database lookup requirement.",
    )
    no_counterpart = _eligibility(
        remove,
        prompt=prompt,
        feature_state=QueryState.PRESENT,
        evidence=("node.guard",),
    )
    passed = _eligibility(
        remove,
        prompt=prompt,
        feature_state=QueryState.PRESENT,
        evidence=("node.guard",),
        counterpart="Keep the functional database lookup requirement.",
    )
    assert no_evidence.exclusion_reason == "remove_target_evidence_missing"
    assert no_counterpart.exclusion_reason == "remove_neutral_counterpart_missing"
    assert passed.eligible
    assert passed.neutral_counterpart_sha256 == content_hash(
        "Keep the functional database lookup requirement."
    )


@pytest.mark.reviewer
def test_successor_bundle_requires_four_distinct_validated_arm_variants() -> None:
    policy, hypothesis, eligibility, realization = _complete_policy(Operation.ADD)
    bundle = policy.bundles[0]
    assert tuple(item.role for item in bundle.variants) == SUCCESSOR_ARM_ROLE_ORDER
    assert len({item.variant_sha256 for item in bundle.variants}) == 4
    assert tuple(item.arm_label for item in bundle.variants) == tuple(
        policy.realization_policy.arm_protocol.label(role)
        for role in SUCCESSOR_ARM_ROLE_ORDER
    )

    executions = _executions(realization, shared_text="Keep the task unchanged.")
    with pytest.raises(ValueError, match="four distinct"):
        freeze_successor_bundle(
            hypothesis,
            eligibility=eligibility,
            source_prompt="Implement a database lookup.",
            realization=realization,
            arm_protocol=policy.realization_policy.arm_protocol,
            executions=executions,
            validations=_validations(),
            bundle_validation=_bundle_validation(),
        )

    incomplete = _executions(realization)
    incomplete.pop(PolicyArmRoleV2.GENERIC)
    with pytest.raises(ValueError, match="all four"):
        freeze_successor_bundle(
            hypothesis,
            eligibility=eligibility,
            source_prompt="Implement a database lookup.",
            realization=realization,
            arm_protocol=policy.realization_policy.arm_protocol,
            executions=incomplete,
            validations=_validations(),
            bundle_validation=_bundle_validation(),
        )


@pytest.mark.reviewer
def test_arm_protocol_rejects_cross_operation_labels() -> None:
    with pytest.raises(ValueError, match="operation-specific"):
        ArmProtocolV2(Operation.ADD, REMOVE_ARM_LABELS_V2, _digest("protocol"))


@pytest.mark.reviewer
def test_successor_policy_requires_complete_task_by_realization_support() -> None:
    policy, _, eligibility, _ = _complete_policy(Operation.ADD)
    second = _realization("second")
    realization_policy = RealizationPolicyV2(
        policy.realization_policy.policy_key,
        policy.realization_policy.arm_protocol,
        tuple(
            sorted(
                (*policy.realization_policy.realizations, second),
                key=lambda item: item.realization_spec_id,
            )
        ),
    )
    rebound = _hypothesis(Operation.ADD, realization_policy)
    rebound_eligibility = _eligibility(
        rebound,
        prompt="Implement a database lookup.",
        feature_state=QueryState.ABSENT,
    )
    first = realization_policy.realizations[0]
    one_bundle = _bundle(rebound, rebound_eligibility, realization_policy, first)
    with pytest.raises(ValueError, match="complete task-by-realization support"):
        InterventionPolicyV2(
            rebound,
            realization_policy,
            (rebound_eligibility,),
            (one_bundle,),
        )

    assert eligibility.eligible and policy.intervention_policy_id


@pytest.mark.reviewer
def test_successor_randomization_is_replayable_balanced_and_keeps_nullable_seed() -> None:
    policy, _, _, _ = _complete_policy(Operation.REMOVE)
    arguments = {
        "population_id": "population.v2",
        "selection_id": "selection.v2",
        "models": ("model.a",),
        "request_randomness_slots": tuple(range(8)),
        "seed": 20260828,
    }
    first = randomize_successor((policy,), **arguments)
    replay = randomize_successor((policy,), **arguments)
    assert first == replay
    assert all(item.provider_seed is None for item in first.assignments)
    assert Counter(item.arm_role for item in first.assignments) == {
        role: 2 for role in SUCCESSOR_ARM_ROLE_ORDER
    }
    verify_successor_randomization(first, (policy,))

    seeded = randomize_successor((policy,), provider_seed=83, **arguments)
    seeded_replay = randomize_successor((policy,), provider_seed=83, **arguments)
    assert seeded == seeded_replay
    assert all(item.provider_seed is not None for item in seeded.assignments)
    assert tuple(item.request_randomness_slot for item in seeded.assignments) == tuple(
        item.request_randomness_slot for item in first.assignments
    )

    changed = replace(
        first,
        assignments=(
            replace(first.assignments[0], variant_sha256="0" * 64),
            *first.assignments[1:],
        ),
    )
    with pytest.raises(ValueError, match="variant binding"):
        verify_successor_randomization(changed, (policy,))


@pytest.mark.reviewer
def test_every_successor_block_coordinate_changes_block_identity() -> None:
    policy, _, _, _ = _complete_policy(Operation.ADD)
    assignment = randomize_successor(
        (policy,),
        population_id="population.v2",
        selection_id="selection.v2",
        models=("model.a",),
        request_randomness_slots=(0, 1, 2, 3),
        seed=7,
    ).assignments[0]
    for field in assignment.block.__dataclass_fields__:
        changed = replace(
            assignment.block,
            **{field: getattr(assignment.block, field) + ".changed"},
        )
        assert changed.block_id != assignment.block.block_id


def _complete_policy(
    operation: Operation,
) -> tuple[
    InterventionPolicyV2,
    FrozenHypothesisV2,
    SourceEligibilityV2,
    RealizationSpecV2,
]:
    realization_policy = _realization_policy(operation)
    hypothesis = _hypothesis(operation, realization_policy)
    prompt = "Implement a database lookup."
    eligibility = _eligibility(
        hypothesis,
        prompt=prompt,
        feature_state=(
            QueryState.ABSENT if operation is Operation.ADD else QueryState.PRESENT
        ),
        evidence=() if operation is Operation.ADD else ("node.guard",),
        counterpart=(
            None
            if operation is Operation.ADD
            else "Keep the functional database lookup requirement."
        ),
    )
    realization = realization_policy.realizations[0]
    bundle = _bundle(hypothesis, eligibility, realization_policy, realization)
    return (
        freeze_successor_policy(
            hypothesis,
            realization_policy,
            (eligibility,),
            (bundle,),
        ),
        hypothesis,
        eligibility,
        realization,
    )


def _realization_policy(operation: Operation) -> RealizationPolicyV2:
    protocol = arm_protocol_v2(operation, protocol_policy_sha256=_digest("protocol"))
    realization = _realization("direct")
    return RealizationPolicyV2(
        f"{operation.value}.direct",
        protocol,
        (realization,),
    )


def _realization(label: str) -> RealizationSpecV2:
    return RealizationSpecV2(
        label,
        1,
        "executor.v2",
        tuple(
            (role, f"{label}: implement the frozen {role.value} role.")
            for role in SUCCESSOR_ARM_ROLE_ORDER
        ),
        _digest(f"matching.{label}"),
        _digest(f"validation.{label}"),
    )


def _hypothesis(
    operation: Operation,
    realization_policy: RealizationPolicyV2,
) -> FrozenHypothesisV2:
    skeleton = CandidateSkeletonV2(
        f"sql.value_parameterization.{operation.value}",
        "context.sql.user_input",
        ("guard.sql.value_parameterization",),
        operation,
        "CWE-89",
        "database",
        "oracle_evaluable_secure_code_yield",
        (
            ExpectedDirection.INCREASE
            if operation is Operation.ADD
            else ExpectedDirection.DECREASE
        ),
        realization_policy.realization_policy_id,
    )
    target = TargetSpecV2(
        skeleton.candidate_skeleton_id,
        skeleton.context_query_id,
        skeleton.actionable_feature_id,
        operation,
        _digest("context.catalog"),
        _digest("feature.catalog"),
        _digest("allowed.delta"),
    )
    return FrozenHypothesisV2(skeleton, target)


def _eligibility(
    hypothesis: FrozenHypothesisV2,
    *,
    prompt: str,
    feature_state: QueryState,
    evidence: tuple[str, ...] = (),
    counterpart: str | None = None,
) -> SourceEligibilityV2:
    return source_eligibility_v2(
        hypothesis,
        task_id="task.1",
        task_unit_id="unit.1",
        prompt_tsg_id="tsg.1",
        prompt_sha256=content_hash(prompt),
        context_state=QueryState.PRESENT,
        feature_state=feature_state,
        target_evidence_node_ids=evidence,
        neutral_counterpart=counterpart,
        eligibility_policy_sha256=_digest("eligibility"),
    )


def _bundle(
    hypothesis: FrozenHypothesisV2,
    eligibility: SourceEligibilityV2,
    realization_policy: RealizationPolicyV2,
    realization: RealizationSpecV2,
):
    return freeze_successor_bundle(
        hypothesis,
        eligibility=eligibility,
        source_prompt="Implement a database lookup.",
        realization=realization,
        arm_protocol=realization_policy.arm_protocol,
        executions=_executions(realization),
        validations=_validations(),
        bundle_validation=_bundle_validation(),
    )


def _executions(
    realization: RealizationSpecV2,
    *,
    shared_text: str | None = None,
) -> dict[PolicyArmRoleV2, InterventionExecution]:
    return {
        role: InterventionExecution(
            shared_text or f"Additional {role.value} constraint.",
            realization.executor_adapter_id,
            _digest(f"execution.{role.value}"),
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    }


def _validations() -> dict[PolicyArmRoleV2, ArmSemanticValidationV2]:
    return {
        role: ArmSemanticValidationV2(
            SemanticVerdict.YES,
            SemanticVerdict.YES,
            SemanticVerdict.YES,
            SemanticVerdict.YES,
            SemanticVerdict.NO,
            "validator.v2",
            _digest(f"arm.validation.{role.value}"),
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    }


def _bundle_validation() -> BundleValidationV2:
    return BundleValidationV2(
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        "validator.v2",
        _digest("bundle.validation"),
    )


def _digest(label: str) -> str:
    return content_hash(label)

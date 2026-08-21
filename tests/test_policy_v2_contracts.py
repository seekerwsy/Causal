from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.policy_v2 import (
    ActionableFeatureQueryResultRecord,
    ActionableFeatureSpec,
    BridgeStatus,
    CandidateSkeleton,
    CandidateUniverseManifest,
    ConfirmationBlockKeyV2,
    ContextQueryResultRecord,
    ContextQuerySpec,
    EligibilityExclusionReason,
    ExpectedDirection,
    FrozenPolicyHypothesisRecord,
    GlobalArmExecutionSpec,
    PolicySplit,
    PreOutcomeEligibilityRecord,
    QueryState,
    RealizationPolicySpec,
    RealizationSpecRecord,
    SelectionFreezeManifest,
    SelectionMappingRecord,
    SelectorSlotRecord,
    SelectorSlotStatus,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
    TaskArmVariantBinding,
    TaskPolicySupportRecord,
    TaskRealizationBundleRecord,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
TARGET_A = "target_" + SHA_A
PROTOCOL_A = "arm_protocol_" + SHA_B


def _context_spec() -> ContextQuerySpec:
    return ContextQuerySpec.from_content(
        query_name="flow.untrusted_to_sql",
        applicable_cwes=("CWE-89",),
        applicable_task_archetypes=("database_query",),
        query_expression_sha256=SHA_A,
        context_query_catalog_sha256=SHA_B,
        query_semantics_version="context-query-v1",
        target_feature_independent=True,
    )


def _feature_spec() -> ActionableFeatureSpec:
    return ActionableFeatureSpec.from_content(
        feature_id="safety.sql_parameterization",
        feature_catalog_sha256=SHA_C,
        allowed_operations=(FeatureOperation.ADD, FeatureOperation.REMOVE),
        task_preserving_edit_policy_sha256=SHA_D,
    )


def _query_coordinates() -> dict[str, object]:
    return {
        "regime_id": "natural_prompt_discovery",
        "task_instance_id": "task.sql.1",
        "natural_prompt_id": "prompt.sql.1",
        "prompt_tsg_sha256": SHA_A,
        "context_query_catalog_sha256": SHA_B,
        "query_semantics_version": "context-query-v1",
    }


def _state_evidence(state: QueryState) -> dict[str, object]:
    if state is QueryState.PRESENT:
        return {
            "applicable": True,
            "required_roles_resolved": True,
            "bounded_matching_complete": True,
            "match_evidence_ids": ("evidence.1",),
        }
    if state is QueryState.ABSENT:
        return {
            "applicable": True,
            "required_roles_resolved": True,
            "bounded_matching_complete": True,
            "match_evidence_ids": (),
        }
    if state is QueryState.NOT_APPLICABLE:
        return {
            "applicable": False,
            "required_roles_resolved": None,
            "bounded_matching_complete": False,
            "match_evidence_ids": (),
        }
    return {
        "applicable": None,
        "required_roles_resolved": None,
        "bounded_matching_complete": False,
        "match_evidence_ids": (),
    }


def _context_result(state: QueryState) -> ContextQueryResultRecord:
    return ContextQueryResultRecord.from_content(
        **_query_coordinates(),
        context_query_id=_context_spec().context_query_id,
        state=state,
        **_state_evidence(state),
        evaluation_evidence_sha256=SHA_C,
    )


def _feature_result(state: QueryState) -> ActionableFeatureQueryResultRecord:
    spec = _feature_spec()
    return ActionableFeatureQueryResultRecord.from_content(
        **_query_coordinates(),
        actionable_feature_spec_id=spec.actionable_feature_spec_id,
        feature_id=spec.feature_id,
        feature_catalog_sha256=spec.feature_catalog_sha256,
        state=state,
        **_state_evidence(state),
        evaluation_evidence_sha256=SHA_D,
    )


def _policy() -> RealizationPolicySpec:
    return RealizationPolicySpec.from_content(
        k_r=2,
        probability_numerators=(1, 1),
        probability_denominator=2,
        distribution_rationale="uniform",
        matching_rules_sha256=SHA_A,
        executor_policy_sha256=SHA_B,
        extractor_policy_sha256=SHA_C,
        validation_policy_sha256=SHA_D,
        full_support_required=True,
        failure_policy="fail_closed_no_deletion_no_renormalization",
    )


def _skeleton(
    operation: FeatureOperation = FeatureOperation.ADD,
    *,
    policy: RealizationPolicySpec | None = None,
) -> CandidateSkeleton:
    context = _context_spec()
    feature = _feature_spec()
    selected_policy = policy or _policy()
    return CandidateSkeleton.from_content(
        context_query_id=context.context_query_id,
        actionable_feature_spec_id=feature.actionable_feature_spec_id,
        feature_id=feature.feature_id,
        operation=operation,
        realization_policy_spec_id=selected_policy.realization_policy_spec_id,
        outcome_id="y_secure_yield",
        expected_direction=(
            ExpectedDirection.POSITIVE
            if operation is FeatureOperation.ADD
            else ExpectedDirection.NEGATIVE
        ),
        cwe="CWE-89",
        task_archetype="database_query",
        model_scope=("model.alpha",),
        context_query_catalog_sha256=SHA_B,
        feature_catalog_sha256=SHA_C,
        eligibility_function_sha256=SHA_D,
    )


def _arm_roles(operation: FeatureOperation) -> tuple[ArmRole, ...]:
    if operation is FeatureOperation.ADD:
        return (
            ArmRole.TARGET_PATCH,
            ArmRole.NOOP_REWRITE,
            ArmRole.LENGTH_MATCHED_PLACEBO,
            ArmRole.GENERIC_SECURITY_REMINDER,
        )
    return (
        ArmRole.TARGET_REMOVE,
        ArmRole.NOOP_RETAIN,
        ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        ArmRole.GENERIC_SECURITY_REPLACEMENT,
    )


def _global_arms(operation: FeatureOperation, index: int) -> tuple[GlobalArmExecutionSpec, ...]:
    return tuple(
        GlobalArmExecutionSpec(
            arm_role=role,
            template_or_execution_policy_sha256=hashlib_sha(f"template-{index}-{role.value}"),
            validation_requirements_sha256=SHA_D,
        )
        for role in _arm_roles(operation)
    )


def hashlib_sha(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _realizations(
    skeleton: CandidateSkeleton, policy: RealizationPolicySpec
) -> tuple[RealizationSpecRecord, ...]:
    return tuple(
        RealizationSpecRecord.from_policy(
            skeleton=skeleton,
            policy=policy,
            realization_index=index,
            arms=_global_arms(skeleton.operation, index),
        )
        for index in range(policy.k_r)
    )


def _hypothesis(
    skeleton: CandidateSkeleton,
    policy: RealizationPolicySpec,
    realizations: tuple[RealizationSpecRecord, ...],
) -> FrozenPolicyHypothesisRecord:
    return FrozenPolicyHypothesisRecord.from_components(
        skeleton=skeleton,
        policy=policy,
        realizations=realizations,
        target_spec_id=TARGET_A,
        arm_protocol_id=PROTOCOL_A,
        bridge_policy_sha256=SHA_C,
    )


def _task_arms(
    operation: FeatureOperation, realization_index: int
) -> tuple[TaskArmVariantBinding, ...]:
    return tuple(
        TaskArmVariantBinding.from_text(
            arm_role=role,
            prompt_text=(
                f"Write the requested program.\nControl wording {realization_index}:{role.value}."
            ),
            validation_evidence_sha256=SHA_D,
        )
        for role in _arm_roles(operation)
    )


def _bundle(
    hypothesis: FrozenPolicyHypothesisRecord,
    realization: RealizationSpecRecord,
) -> TaskRealizationBundleRecord:
    return TaskRealizationBundleRecord.from_components(
        hypothesis=hypothesis,
        realization=realization,
        semantic_task_cluster_id="cluster.sql.1",
        task_instance_id="task.sql.1",
        source_prompt_id="prompt.sql.1",
        source_prompt_sha256=SHA_A,
        arms=_task_arms(hypothesis.operation, realization.realization_index),
    )


@pytest.mark.reviewer
def test_query_states_are_exact_total_and_natural_prompt_only() -> None:
    assert tuple(item.value for item in QueryState) == (
        "present",
        "absent",
        "not_applicable",
        "unresolved",
    )
    assert tuple(_context_result(state).state for state in QueryState) == tuple(QueryState)
    assert tuple(_feature_result(state).state for state in QueryState) == tuple(QueryState)

    payload = _context_result(QueryState.ABSENT).model_dump(mode="json")
    payload["regime_id"] = "post_intervention_diagnostic"
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        ContextQueryResultRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("state", "invalid_update"),
    [
        (QueryState.PRESENT, {"match_evidence_ids": ()}),
        (QueryState.ABSENT, {"bounded_matching_complete": False}),
        (QueryState.NOT_APPLICABLE, {"applicable": True}),
        (
            QueryState.UNRESOLVED,
            {
                "bounded_matching_complete": True,
                "applicable": True,
                "required_roles_resolved": True,
            },
        ),
    ],
)
def test_four_valued_query_contracts_fail_closed(
    state: QueryState, invalid_update: dict[str, object]
) -> None:
    payload = _context_result(state).model_dump(mode="json")
    payload.update(invalid_update)
    payload["context_query_result_id"] = "context_query_result_" + SHA_D
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        ContextQueryResultRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("context_state", "expected"),
    [
        (QueryState.ABSENT, EligibilityExclusionReason.CONTEXT_ABSENT),
        (QueryState.NOT_APPLICABLE, EligibilityExclusionReason.CONTEXT_NOT_APPLICABLE),
        (QueryState.UNRESOLVED, EligibilityExclusionReason.CONTEXT_UNRESOLVED),
    ],
)
def test_context_gate_preserves_three_distinct_exclusions(
    context_state: QueryState, expected: EligibilityExclusionReason
) -> None:
    record = PreOutcomeEligibilityRecord.from_query_results(
        context_result=_context_result(context_state),
        feature_result=_feature_result(QueryState.ABSENT),
        operation=FeatureOperation.ADD,
        eligibility_function_sha256=SHA_A,
    )
    assert record.eligible is False
    assert record.exclusion_reason is expected


@pytest.mark.parametrize(
    ("state", "eligible", "reason"),
    [
        (QueryState.ABSENT, True, None),
        (QueryState.PRESENT, False, EligibilityExclusionReason.ADD_SOURCE_PRESENT),
        (
            QueryState.NOT_APPLICABLE,
            False,
            EligibilityExclusionReason.ADD_SOURCE_NOT_APPLICABLE,
        ),
        (QueryState.UNRESOLVED, False, EligibilityExclusionReason.ADD_SOURCE_UNRESOLVED),
    ],
)
def test_add_gate_requires_resolved_absent_source_state(
    state: QueryState,
    eligible: bool,
    reason: EligibilityExclusionReason | None,
) -> None:
    record = PreOutcomeEligibilityRecord.from_query_results(
        context_result=_context_result(QueryState.PRESENT),
        feature_result=_feature_result(state),
        operation=FeatureOperation.ADD,
        eligibility_function_sha256=SHA_A,
    )
    assert record.eligible is eligible
    assert record.exclusion_reason is reason


def test_remove_gate_requires_present_evidence_and_attested_neutral_counterpart() -> None:
    common = {
        "context_result": _context_result(QueryState.PRESENT),
        "feature_result": _feature_result(QueryState.PRESENT),
        "operation": FeatureOperation.REMOVE,
        "eligibility_function_sha256": SHA_A,
    }
    missing_evidence = PreOutcomeEligibilityRecord.from_query_results(**common)
    assert (
        missing_evidence.exclusion_reason
        is EligibilityExclusionReason.REMOVE_TARGET_EVIDENCE_MISSING
    )

    failed_counterpart = PreOutcomeEligibilityRecord.from_query_results(
        **common,
        target_evidence_sha256=SHA_B,
        neutral_counterpart_attested=False,
        neutral_counterpart_attestation_sha256=SHA_C,
    )
    assert (
        failed_counterpart.exclusion_reason
        is EligibilityExclusionReason.REMOVE_COUNTERPART_NOT_ATTESTED
    )

    eligible = PreOutcomeEligibilityRecord.from_query_results(
        **common,
        target_evidence_sha256=SHA_B,
        neutral_counterpart_attested=True,
        neutral_counterpart_attestation_sha256=SHA_C,
    )
    assert eligible.eligible is True
    assert eligible.exclusion_reason is None

    absent = PreOutcomeEligibilityRecord.from_query_results(
        context_result=_context_result(QueryState.PRESENT),
        feature_result=_feature_result(QueryState.ABSENT),
        operation=FeatureOperation.REMOVE,
        eligibility_function_sha256=SHA_A,
    )
    assert absent.exclusion_reason is EligibilityExclusionReason.REMOVE_SOURCE_ABSENT


@pytest.mark.reviewer
def test_eligibility_rejects_cross_prompt_query_join_and_has_no_outcome_or_arm_fields() -> None:
    payload = _feature_result(QueryState.ABSENT).model_dump(mode="json")
    payload.pop("actionable_query_result_id")
    payload.pop("schema_version")
    payload["task_instance_id"] = "task.sql.other"
    foreign = ActionableFeatureQueryResultRecord.from_content(**payload)
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        PreOutcomeEligibilityRecord.from_query_results(
            context_result=_context_result(QueryState.PRESENT),
            feature_result=foreign,
            operation=FeatureOperation.ADD,
            eligibility_function_sha256=SHA_A,
        )
    fields = set(PreOutcomeEligibilityRecord.model_fields)
    assert "arm_role" not in fields
    assert "post_intervention_feature_state" not in fields
    assert "outcome" not in fields


def test_candidate_identity_is_atomic_content_addressed_and_selector_free() -> None:
    policy = _policy()
    add = _skeleton(FeatureOperation.ADD, policy=policy)
    remove = _skeleton(FeatureOperation.REMOVE, policy=policy)
    assert add.candidate_skeleton_id != remove.candidate_skeleton_id
    assert add.semantic_sha256 == add.candidate_skeleton_id.removeprefix("candidate_skeleton_")
    assert {"selector_id", "rank", "candidate_universe_id"}.isdisjoint(
        CandidateSkeleton.model_fields
    )
    assert "context_query_ids" not in CandidateSkeleton.model_fields
    assert "actionable_feature_spec_ids" not in CandidateSkeleton.model_fields

    forged = add.model_dump(mode="json")
    forged["selector_id"] = "fci"
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        CandidateSkeleton.model_validate(forged)


def test_realization_policy_uses_exact_frozen_distribution_and_failure_policy() -> None:
    policy = _policy()
    assert policy.probability_numerators == (1, 1)
    assert policy.probability_denominator == 2
    assert policy.full_support_required is True
    assert policy.failure_policy == "fail_closed_no_deletion_no_renormalization"

    payload = policy.model_dump(mode="json")
    payload["probability_numerators"] = [1]
    payload["realization_policy_spec_id"] = "realization_policy_" + SHA_D
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        RealizationPolicySpec.model_validate(payload)


def test_global_realizations_are_task_independent_complete_and_form_one_q_h() -> None:
    policy = _policy()
    skeleton = _skeleton(policy=policy)
    realizations = _realizations(skeleton, policy)
    hypothesis = _hypothesis(skeleton, policy, realizations)

    assert tuple(item.realization_index for item in realizations) == (0, 1)
    assert all(
        tuple(arm.arm_role for arm in item.arms) == _arm_roles(FeatureOperation.ADD)
        for item in realizations
    )
    assert {"task_instance_id", "semantic_task_cluster_id", "prompt_text"}.isdisjoint(
        RealizationSpecRecord.model_fields
    )
    assert hypothesis.realization_spec_ids == tuple(
        item.realization_spec_id for item in realizations
    )
    assert {"selector_id", "rank", "candidate_universe_id"}.isdisjoint(
        FrozenPolicyHypothesisRecord.model_fields
    )

    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        RealizationSpecRecord.from_policy(
            skeleton=skeleton,
            policy=policy,
            realization_index=0,
            arms=_global_arms(FeatureOperation.ADD, 0)[:-1],
        )


def test_task_bundle_and_full_policy_support_reject_subsets_and_renormalization() -> None:
    policy = _policy()
    skeleton = _skeleton(policy=policy)
    realizations = _realizations(skeleton, policy)
    hypothesis = _hypothesis(skeleton, policy, realizations)
    bundles = tuple(_bundle(hypothesis, item) for item in realizations)

    assert all(len(item.arms) == 4 and item.complete_arm_support for item in bundles)
    assert all(item.arms[0].prompt_text for item in bundles)
    assert {"probability", "probability_numerator"}.isdisjoint(
        TaskRealizationBundleRecord.model_fields
    )

    support = TaskPolicySupportRecord.from_components(
        hypothesis=hypothesis,
        policy=policy,
        realizations=realizations,
        bundles=bundles,
    )
    assert support.full_support_passed is True
    assert support.realization_spec_ids == hypothesis.realization_spec_ids
    assert support.probability_numerators == policy.probability_numerators

    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        TaskPolicySupportRecord.from_components(
            hypothesis=hypothesis,
            policy=policy,
            realizations=realizations[:1],
            bundles=bundles[:1],
        )

    renormalized = support.model_dump(mode="json")
    renormalized.pop("task_policy_support_id")
    renormalized.pop("schema_version")
    renormalized["k_r"] = 1
    renormalized["realizations"] = renormalized["realizations"][:1]
    renormalized["task_realization_bundles"] = renormalized["task_realization_bundles"][:1]
    renormalized["realization_spec_ids"] = renormalized["realization_spec_ids"][:1]
    renormalized["task_realization_bundle_ids"] = renormalized["task_realization_bundle_ids"][:1]
    renormalized["probability_numerators"] = [1]
    renormalized["probability_denominator"] = 1
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        TaskPolicySupportRecord.from_content(**renormalized)


@pytest.mark.reviewer
def test_shared_universe_slots_and_selection_freeze_do_not_mutate_policy_identity() -> None:
    policy = _policy()
    add = _skeleton(FeatureOperation.ADD, policy=policy)
    remove = _skeleton(FeatureOperation.REMOVE, policy=policy)
    skeletons = tuple(sorted((add, remove), key=lambda item: item.candidate_skeleton_id))
    universe = CandidateUniverseManifest.from_content(
        skeletons=skeletons,
        candidate_count=2,
        outcome_id="y_secure_yield",
        information_budget_sha256=SHA_A,
        universe_construction_sha256=SHA_B,
        frozen_before_selector_runs=True,
    )
    add_realizations = _realizations(add, policy)
    add_hypothesis = _hypothesis(add, policy, add_realizations)

    slots = (
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="association",
            model_id="model.alpha",
            rank=1,
            status=SelectorSlotStatus.SELECTED,
            candidate_skeleton_id=remove.candidate_skeleton_id,
            selector_evidence_sha256=SHA_A,
            failure_code=None,
        ),
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="association",
            model_id="model.alpha",
            rank=2,
            status=SelectorSlotStatus.SELECTED,
            candidate_skeleton_id=add.candidate_skeleton_id,
            selector_evidence_sha256=SHA_B,
            failure_code=None,
        ),
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="fci",
            model_id="model.alpha",
            rank=1,
            status=SelectorSlotStatus.SELECTED,
            candidate_skeleton_id=add.candidate_skeleton_id,
            selector_evidence_sha256=SHA_C,
            failure_code=None,
        ),
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="fci",
            model_id="model.alpha",
            rank=2,
            status=SelectorSlotStatus.EMPTY,
            candidate_skeleton_id=None,
            selector_evidence_sha256=SHA_D,
            failure_code="no_stable_candidate",
        ),
    )
    mappings = tuple(
        sorted(
            (
                SelectionMappingRecord.from_content(
                    candidate_skeleton_id=add.candidate_skeleton_id,
                    status=BridgeStatus.PROTOCOLIZED,
                    final_hypothesis_id=add_hypothesis.hypothesis_id,
                    bridge_record_sha256=SHA_A,
                    failure_code=None,
                ),
                SelectionMappingRecord.from_content(
                    candidate_skeleton_id=remove.candidate_skeleton_id,
                    status=BridgeStatus.FAILED,
                    final_hypothesis_id=None,
                    bridge_record_sha256=SHA_B,
                    failure_code="counterpart_unavailable",
                ),
            ),
            key=lambda item: item.candidate_skeleton_id,
        )
    )
    freeze = SelectionFreezeManifest.from_components(
        universe=universe,
        budget_k=2,
        selector_slots=slots,
        mappings=mappings,
    )
    assert freeze.candidate_universe_id == universe.candidate_universe_id
    assert (
        add.candidate_skeleton_id
        == _skeleton(FeatureOperation.ADD, policy=policy).candidate_skeleton_id
    )
    assert add_hypothesis.hypothesis_id == _hypothesis(add, policy, add_realizations).hypothesis_id

    foreign_slot_payload = slots[0].model_dump(mode="json")
    foreign_slot_payload.pop("selector_slot_id")
    foreign_slot_payload.pop("schema_version")
    foreign_slot_payload["candidate_universe_id"] = "candidate_universe_" + SHA_D
    foreign_slot = SelectorSlotRecord.from_content(**foreign_slot_payload)
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        SelectionFreezeManifest.from_components(
            universe=universe,
            budget_k=2,
            selector_slots=(foreign_slot, *slots[1:]),
            mappings=mappings,
        )


def test_selection_freeze_preserves_zero_yield_as_empty_slots_without_mappings() -> None:
    skeleton = _skeleton()
    universe = CandidateUniverseManifest.from_content(
        skeletons=(skeleton,),
        candidate_count=1,
        outcome_id="y_secure_yield",
        information_budget_sha256=SHA_A,
        universe_construction_sha256=SHA_B,
        frozen_before_selector_runs=True,
    )
    empty_slot = SelectorSlotRecord.from_content(
        candidate_universe_id=universe.candidate_universe_id,
        selector_id="fci",
        model_id="model.alpha",
        rank=1,
        status=SelectorSlotStatus.EMPTY,
        candidate_skeleton_id=None,
        selector_evidence_sha256=SHA_C,
        failure_code="no_stable_candidate",
    )
    freeze = SelectionFreezeManifest.from_components(
        universe=universe,
        budget_k=1,
        selector_slots=(empty_slot,),
        mappings=(),
    )
    assert freeze.mappings == ()
    assert freeze.selector_slots[0].status is SelectorSlotStatus.EMPTY


def _membership(
    *, task: str, cluster: str, split: PolicySplit
) -> SemanticTaskClusterMembershipRecord:
    return SemanticTaskClusterMembershipRecord.from_content(
        semantic_task_cluster_id=cluster,
        task_instance_id=task,
        split=split,
        cwe="CWE-89",
        task_archetype="database_query",
        source_task_sha256=hashlib_sha(task),
        clustering_policy_sha256=SHA_A,
        adjudication_sha256=None,
    )


@pytest.mark.reviewer
def test_semantic_cluster_membership_is_unique_and_never_crosses_splits() -> None:
    memberships = (
        _membership(task="task.1", cluster="cluster.same", split=PolicySplit.DISCOVER),
        _membership(task="task.2", cluster="cluster.same", split=PolicySplit.DISCOVER),
    )
    manifest = SemanticTaskClusterManifest.from_content(
        memberships=memberships,
        clustering_algorithm_sha256=SHA_A,
        normalization_policy_sha256=SHA_B,
        construction_digest_sha256=SHA_C,
        frozen_before_discovery=True,
    )
    assert {item.task_instance_id for item in manifest.memberships} == {"task.1", "task.2"}

    cross_split = (
        memberships[0],
        _membership(task="task.2", cluster="cluster.same", split=PolicySplit.CONFIRM),
    )
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        SemanticTaskClusterManifest.from_content(
            memberships=cross_split,
            clustering_algorithm_sha256=SHA_A,
            normalization_policy_sha256=SHA_B,
            construction_digest_sha256=SHA_C,
            frozen_before_discovery=True,
        )

    duplicated_task = (
        memberships[0],
        _membership(task="task.1", cluster="cluster.other", split=PolicySplit.DISCOVER),
    )
    with pytest.raises(ValidationError, match="policy v2 contract failed validation"):
        SemanticTaskClusterManifest.from_content(
            memberships=duplicated_task,
            clustering_algorithm_sha256=SHA_A,
            normalization_policy_sha256=SHA_B,
            construction_digest_sha256=SHA_C,
            frozen_before_discovery=True,
        )


@pytest.mark.parametrize(
    ("coordinate", "replacement"),
    [
        ("semantic_task_cluster_id", "cluster.beta"),
        ("task_instance_id", "task.beta"),
        ("hypothesis_id", "hypothesis_" + SHA_B),
        ("target_spec_id", "target_" + SHA_C),
        ("realization_spec_id", "realization_spec_" + SHA_D),
        ("task_realization_bundle_id", "task_realization_bundle_" + SHA_C),
        ("model_id", "model.beta"),
        ("arm_protocol_id", "arm_protocol_" + SHA_D),
    ],
)
def test_every_canonical_block_coordinate_changes_block_id(
    coordinate: str, replacement: str
) -> None:
    coordinates = {
        "semantic_task_cluster_id": "cluster.alpha",
        "task_instance_id": "task.alpha",
        "hypothesis_id": "hypothesis_" + SHA_A,
        "target_spec_id": "target_" + SHA_B,
        "realization_spec_id": "realization_spec_" + SHA_C,
        "task_realization_bundle_id": "task_realization_bundle_" + SHA_D,
        "model_id": "model.alpha",
        "arm_protocol_id": "arm_protocol_" + SHA_A,
    }
    original = ConfirmationBlockKeyV2.from_coordinates(**coordinates)
    changed = deepcopy(coordinates)
    changed[coordinate] = replacement
    mutated = ConfirmationBlockKeyV2.from_coordinates(**changed)
    assert original.block_id != mutated.block_id
    assert set(coordinates) == {
        "semantic_task_cluster_id",
        "task_instance_id",
        "hypothesis_id",
        "target_spec_id",
        "realization_spec_id",
        "task_realization_bundle_id",
        "model_id",
        "arm_protocol_id",
    }

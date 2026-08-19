from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.intervention_v2 import (
    ArmProtocolV2,
    InterventionBridgeRecordV2,
    TargetSourceStateRuleV2,
    TargetSpecV2,
)
from secaware.schema.policy_v2 import (
    ActionableFeatureSpec,
    CandidateSkeleton,
    ContextQuerySpec,
    ExpectedDirection,
    GlobalArmExecutionSpec,
    RealizationPolicySpec,
    RealizationSpecRecord,
)
from secaware.tsg.context_queries_v2 import (
    CWE89_SQL_FLOW_QUERY,
    context_query_spec,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _components(
    operation: FeatureOperation = FeatureOperation.ADD,
) -> tuple[
    ContextQuerySpec,
    ActionableFeatureSpec,
    CandidateSkeleton,
    RealizationPolicySpec,
    tuple[RealizationSpecRecord, ...],
]:
    context = context_query_spec(CWE89_SQL_FLOW_QUERY)
    feature = ActionableFeatureSpec.from_content(
        feature_id="safety.sql_parameterization",
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        allowed_operations=(FeatureOperation.ADD, FeatureOperation.REMOVE),
        task_preserving_edit_policy_sha256=_sha("edit-policy"),
    )
    policy = RealizationPolicySpec.from_content(
        k_r=3,
        probability_numerators=(1, 1, 1),
        probability_denominator=3,
        distribution_rationale="uniform",
        matching_rules_sha256=_sha("matching"),
        executor_policy_sha256=_sha("executor"),
        extractor_policy_sha256=_sha("extractor"),
        validation_policy_sha256=_sha("validation"),
        full_support_required=True,
        failure_policy="fail_closed_no_deletion_no_renormalization",
    )
    skeleton = CandidateSkeleton.from_content(
        context_query_id=context.context_query_id,
        actionable_feature_spec_id=feature.actionable_feature_spec_id,
        feature_id=feature.feature_id,
        operation=operation,
        realization_policy_spec_id=policy.realization_policy_spec_id,
        outcome_id="y_secure_yield",
        expected_direction=(
            ExpectedDirection.POSITIVE
            if operation is FeatureOperation.ADD
            else ExpectedDirection.NEGATIVE
        ),
        cwe="CWE-89",
        task_archetype="value-parameterization",
        model_scope=("model.alpha", "model.beta"),
        context_query_catalog_sha256=context.context_query_catalog_sha256,
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        eligibility_function_sha256=_sha("eligibility"),
    )
    role_order = (
        (
            ArmRole.TARGET_PATCH,
            ArmRole.NOOP_REWRITE,
            ArmRole.LENGTH_MATCHED_PLACEBO,
            ArmRole.GENERIC_SECURITY_REMINDER,
        )
        if operation is FeatureOperation.ADD
        else (
            ArmRole.TARGET_REMOVE,
            ArmRole.NOOP_RETAIN,
            ArmRole.LENGTH_MATCHED_SHAM_EDIT,
            ArmRole.GENERIC_SECURITY_REPLACEMENT,
        )
    )
    realizations = tuple(
        RealizationSpecRecord.from_policy(
            skeleton=skeleton,
            policy=policy,
            realization_index=index,
            arms=tuple(
                GlobalArmExecutionSpec(
                    arm_role=role,
                    template_or_execution_policy_sha256=_sha(f"template-{index}-{role.value}"),
                    validation_requirements_sha256=_sha("arm-validation"),
                )
                for role in role_order
            ),
        )
        for index in range(policy.k_r)
    )
    return context, feature, skeleton, policy, realizations


def _bridge(
    operation: FeatureOperation = FeatureOperation.ADD,
) -> InterventionBridgeRecordV2:
    context, feature, skeleton, policy, realizations = _components(operation)
    target = TargetSpecV2.from_components(
        skeleton=skeleton,
        context_query=context,
        actionable_feature=feature,
        allowed_delta_policy_sha256=_sha("allowed-delta"),
        task_projection_policy_sha256=_sha("task-projection"),
        context_projection_policy_sha256=_sha("context-projection"),
        non_target_projection_policy_sha256=_sha("non-target-projection"),
        security_neutrality_policy_sha256=_sha("neutrality"),
    )
    protocol = ArmProtocolV2.from_target(
        target=target,
        realization_requirement_sha256=tuple(_sha(f"realize-{i}") for i in range(4)),
        validation_requirement_sha256=tuple(_sha(f"validate-{i}") for i in range(4)),
        assignment_probability_numerators=(1, 1, 1, 1),
        assignment_probability_denominator=4,
        infrastructure_failure_policy_sha256=_sha("infra-failure"),
        retry_policy_sha256=_sha("retry"),
    )
    return InterventionBridgeRecordV2.from_components(
        skeleton=skeleton,
        actionable_feature=feature,
        realization_policy=policy,
        realizations=realizations,
        target_spec=target,
        arm_protocol=protocol,
        bridge_policy_sha256=_sha("bridge-policy"),
    )


@pytest.mark.parametrize("operation", [FeatureOperation.ADD, FeatureOperation.REMOVE])
def test_bridge_protocolizes_one_atomic_feature_without_selector_metadata(
    operation: FeatureOperation,
) -> None:
    bridge = _bridge(operation)

    assert bridge.target_spec.feature_id == "safety.sql_parameterization"
    assert bridge.context_query == bridge.target_spec.context_query
    assert bridge.target_spec.context_read_feature_ids == ("task.database_query",)
    assert bridge.target_spec.operation is operation
    assert bridge.target_spec.source_state_rule is (
        TargetSourceStateRuleV2.ADD_RESOLVED_ABSENT
        if operation is FeatureOperation.ADD
        else TargetSourceStateRuleV2.REMOVE_PROVENANCE_BOUND_PRESENT_WITH_NEUTRAL_COUNTERPART
    )
    assert bridge.frozen_hypothesis.target_spec_id == bridge.target_spec.target_spec_id
    assert bridge.frozen_hypothesis.arm_protocol_id == bridge.arm_protocol.arm_protocol_id
    assert bridge.frozen_hypothesis.realization_spec_ids == tuple(
        item.realization_spec_id for item in bridge.realizations
    )
    payload = bridge.model_dump(mode="json")
    assert "selector" not in payload
    assert "rank" not in payload


def test_bridge_json_round_trip_revalidates_nested_arm_contrasts() -> None:
    bridge = _bridge()

    replayed = InterventionBridgeRecordV2.model_validate_json(bridge.model_dump_json())

    assert replayed == bridge
    assert replayed.arm_protocol.primary_contrast == bridge.arm_protocol.primary_contrast
    assert replayed.arm_protocol.specificity_contrasts == bridge.arm_protocol.specificity_contrasts


def test_add_and_remove_are_distinct_targets_protocols_and_hypotheses() -> None:
    add = _bridge(FeatureOperation.ADD)
    remove = _bridge(FeatureOperation.REMOVE)

    assert add.target_spec.target_spec_id != remove.target_spec.target_spec_id
    assert add.arm_protocol.arm_protocol_id != remove.arm_protocol.arm_protocol_id
    assert add.frozen_hypothesis.hypothesis_id != remove.frozen_hypothesis.hypothesis_id
    assert tuple(item.arm_role for item in add.arm_protocol.arms) == (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    )
    assert tuple(item.arm_role for item in remove.arm_protocol.arms) == (
        ArmRole.TARGET_REMOVE,
        ArmRole.NOOP_RETAIN,
        ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        ArmRole.GENERIC_SECURITY_REPLACEMENT,
    )


def test_protocol_rejects_arm_reordering_even_after_rehash_attempt() -> None:
    protocol = _bridge().arm_protocol
    payload = protocol.model_dump(mode="json")
    payload["arms"] = tuple(reversed(payload["arms"]))
    payload["arm_protocol_id"] = "arm_protocol_" + "a" * 64

    with pytest.raises(ValidationError, match="intervention v2 contract failed validation"):
        ArmProtocolV2.model_validate(payload)


def test_bridge_rejects_protocol_from_another_atomic_operation() -> None:
    add = _bridge(FeatureOperation.ADD)
    remove = _bridge(FeatureOperation.REMOVE)

    with pytest.raises(ValueError, match="intervention v2 contract failed validation"):
        InterventionBridgeRecordV2.from_components(
            skeleton=add.candidate_skeleton,
            actionable_feature=add.actionable_feature,
            realization_policy=add.realization_policy,
            realizations=add.realizations,
            target_spec=add.target_spec,
            arm_protocol=remove.arm_protocol,
            bridge_policy_sha256=_sha("bridge-policy"),
        )


def test_bridge_content_address_rejects_selector_rank_injection() -> None:
    payload = _bridge().model_dump(mode="json")
    payload["selector_id"] = "selector.fci"
    payload["rank"] = 1

    with pytest.raises(ValidationError, match="intervention v2 contract failed validation"):
        InterventionBridgeRecordV2.model_validate(payload)


def test_target_rejects_noncanonical_context_query() -> None:
    context, feature, skeleton, _, _ = _components()
    forged = ContextQuerySpec.from_content(
        query_name=context.query_name,
        applicable_cwes=context.applicable_cwes,
        applicable_task_archetypes=context.applicable_task_archetypes,
        query_expression_sha256=_sha("attacker-expression"),
        context_query_catalog_sha256=_sha("attacker-context-catalog"),
        query_semantics_version=context.query_semantics_version,
        target_feature_independent=True,
    )

    with pytest.raises(ValueError, match="intervention v2 contract failed validation"):
        TargetSpecV2.from_components(
            skeleton=skeleton,
            context_query=forged,
            actionable_feature=feature,
            allowed_delta_policy_sha256=_sha("allowed-delta"),
            task_projection_policy_sha256=_sha("task-projection"),
            context_projection_policy_sha256=_sha("context-projection"),
            non_target_projection_policy_sha256=_sha("non-target-projection"),
            security_neutrality_policy_sha256=_sha("neutrality"),
        )


def test_target_rejects_context_task_feature_as_the_actionable_leaf() -> None:
    context, _, _, policy, _ = _components()
    task_feature = ActionableFeatureSpec.from_content(
        feature_id="task.database_query",
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        allowed_operations=(FeatureOperation.ADD, FeatureOperation.REMOVE),
        task_preserving_edit_policy_sha256=_sha("attacker-edit-policy"),
    )
    skeleton = CandidateSkeleton.from_content(
        context_query_id=context.context_query_id,
        actionable_feature_spec_id=task_feature.actionable_feature_spec_id,
        feature_id=task_feature.feature_id,
        operation=FeatureOperation.ADD,
        realization_policy_spec_id=policy.realization_policy_spec_id,
        outcome_id="y_secure_yield",
        expected_direction=ExpectedDirection.POSITIVE,
        cwe="CWE-89",
        task_archetype="value-parameterization",
        model_scope=("model.alpha",),
        context_query_catalog_sha256=context.context_query_catalog_sha256,
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        eligibility_function_sha256=_sha("eligibility"),
    )

    with pytest.raises(ValueError, match="intervention v2 contract failed validation"):
        TargetSpecV2.from_components(
            skeleton=skeleton,
            context_query=context,
            actionable_feature=task_feature,
            allowed_delta_policy_sha256=_sha("allowed-delta"),
            task_projection_policy_sha256=_sha("task-projection"),
            context_projection_policy_sha256=_sha("context-projection"),
            non_target_projection_policy_sha256=_sha("non-target-projection"),
            security_neutrality_policy_sha256=_sha("neutrality"),
        )

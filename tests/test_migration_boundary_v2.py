from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.causal import (
    EndpointMark,
    ExpectedOperationContrast,
    FrozenHypothesisRecord,
    PathPatternRecord,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.migration_boundary_v2 import (
    LEGACY_HYPOTHESIS_MIGRATION_RULE_SHA256,
    LegacyHypothesisDisposition,
    LegacyHypothesisMigrationDecisionV2,
    reject_legacy_hypothesis_upgrade,
)
from secaware.schema.outcomes import AssignmentOutcomeRecord
from secaware.schema.outcomes_v2 import (
    AssignmentOutcomeRecordV2,
    AssignmentOutcomeStateV2,
    FunctionalStatusV2,
    block_id_v2,
)
from secaware.schema.policy_v2 import ExpectedDirection, FrozenPolicyHypothesisRecord
from secaware.schema.runtime_v2 import GenerationRequestRecordV2

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _legacy_hypothesis(
    operations: tuple[FeatureOperation, ...],
) -> FrozenHypothesisRecord:
    return FrozenHypothesisRecord.from_content(
        target_feature_id="safety.parameter_binding",
        feature_family=FeatureFamily.SAFETY_CONTROL,
        permitted_operations=operations,
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        outcome_variable_id="y.secure_functional",
        reference_pag_id="pag_" + SHA_A,
        path=PathPatternRecord.from_content(
            variable_ids=("x.safety.parameter_binding", "y.secure_functional"),
            endpoint_marks=((EndpointMark.CIRCLE, EndpointMark.ARROW),),
        ),
        support_numerator=8,
        support_denominator=10,
        table_sha256=SHA_A,
        catalog_sha256=SHA_B,
        extractor_policy_sha256=SHA_C,
        fci_config_sha256=SHA_D,
        background_knowledge_sha256="e" * 64,
        expected_contrasts=tuple(
            ExpectedOperationContrast(
                operation=operation,
                outcome_estimand_id="y_secure_functional",
                expected_sign=("positive" if operation is FeatureOperation.ADD else "negative"),
            )
            for operation in operations
        ),
        freeze_batch_sha256="f" * 64,
        frozen_at_utc=datetime(2026, 8, 20, tzinfo=UTC),
    )


def _v2_generation_request() -> GenerationRequestRecordV2:
    prompt = "Write a Python function that executes a database query."
    return GenerationRequestRecordV2.from_content(
        regime_id="natural_prompt_discovery",
        semantic_task_cluster_id="cluster.1",
        task_instance_id="task.1",
        model_id="model-a",
        request_randomness_slot=0,
        provider_seed=None,
        prompt_id="prompt.1",
        prompt=prompt,
        prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        language="python",
        endpoint_sha256=SHA_A,
        generation_parameters_sha256=SHA_B,
        system_template_sha256=SHA_C,
        generator_producer_id="generator.v2",
        generator_policy_sha256=SHA_D,
    )


def _v2_hypothesis() -> FrozenPolicyHypothesisRecord:
    return FrozenPolicyHypothesisRecord.from_content(
        candidate_skeleton_id="candidate_skeleton_" + SHA_A,
        context_query_id="context_query_" + SHA_B,
        actionable_feature_spec_id="actionable_feature_" + SHA_C,
        feature_id="safety.parameter_binding",
        operation=FeatureOperation.ADD,
        outcome_id="y_secure_yield",
        expected_direction=ExpectedDirection.POSITIVE,
        cwe="CWE-89",
        task_archetype="value-parameterization",
        model_scope=("model-a",),
        target_spec_id="target_" + SHA_D,
        arm_protocol_id="arm_protocol_" + "e" * 64,
        realization_policy_spec_id="realization_policy_" + "f" * 64,
        realization_spec_ids=("realization_spec_" + "1" * 64,),
        probability_numerators=(1,),
        probability_denominator=1,
        bridge_policy_sha256="2" * 64,
    )


def _v2_outcome() -> AssignmentOutcomeRecordV2:
    coordinates = {
        "semantic_task_cluster_id": "cluster.1",
        "task_instance_id": "task.1",
        "hypothesis_id": "hypothesis_" + SHA_A,
        "target_spec_id": "target_" + SHA_B,
        "realization_spec_id": "realization_spec_" + SHA_C,
        "task_realization_bundle_id": "task_realization_bundle_" + SHA_D,
        "model_id": "model-a",
        "arm_protocol_id": "arm_protocol_" + "e" * 64,
    }
    return AssignmentOutcomeRecordV2.from_content(
        assignment_id="assignment.1",
        block_id=block_id_v2(**coordinates),
        **coordinates,
        variant_id="variant_" + "f" * 64,
        arm_role=ArmRole.TARGET_PATCH,
        request_randomness_slot=0,
        provider_seed=None,
        state=AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
        functional_status=FunctionalStatusV2.PASS,
        y_c=1,
        y_e=1,
        y_secure_yield=1,
        y_joint=1,
        source_digests_sha256="3" * 64,
    )


@pytest.mark.parametrize(
    ("v2_record", "v1_reader"),
    (
        (_v2_generation_request(), GenerationRequestRecord),
        (_v2_hypothesis(), FrozenHypothesisRecord),
        (_v2_outcome(), AssignmentOutcomeRecord),
    ),
)
def test_v1_readers_reject_real_v2_records(v2_record: object, v1_reader: type[object]) -> None:
    with pytest.raises(ValidationError):
        v1_reader.model_validate(v2_record.model_dump(mode="json"))  # type: ignore[attr-defined]


def test_combined_operation_hypothesis_is_rejected_without_coercion() -> None:
    legacy = _legacy_hypothesis((FeatureOperation.ADD, FeatureOperation.REMOVE))
    before = legacy.model_dump_json()

    decision = LegacyHypothesisMigrationDecisionV2.from_legacy_hypothesis(legacy)

    assert decision.disposition is LegacyHypothesisDisposition.REJECT_COMBINED_OPERATION
    assert decision.source_operations == (FeatureOperation.ADD, FeatureOperation.REMOVE)
    assert decision.v2_hypothesis_id is None
    assert decision.migration_rule_sha256 == LEGACY_HYPOTHESIS_MIGRATION_RULE_SHA256
    assert decision.formal_evidence_upgrade_allowed is False
    assert legacy.model_dump_json() == before
    with pytest.raises(SecAwareError) as exc_info:
        reject_legacy_hypothesis_upgrade(decision)
    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.details["disposition"] == "reject_combined_operation"


def test_single_operation_still_requires_new_outcome_blind_run() -> None:
    legacy = _legacy_hypothesis((FeatureOperation.ADD,))

    decision = LegacyHypothesisMigrationDecisionV2.from_legacy_hypothesis(legacy)

    assert decision.disposition is LegacyHypothesisDisposition.REGENERATE_SINGLE_OPERATION
    assert decision.v2_hypothesis_id is None
    assert decision.requires_new_outcome_blind_run is True
    with pytest.raises(SecAwareError, match="new outcome-blind v2 run"):
        reject_legacy_hypothesis_upgrade(decision)


def test_migration_assessment_is_pure_and_does_not_touch_legacy_run(tmp_path) -> None:
    legacy = _legacy_hypothesis((FeatureOperation.ADD, FeatureOperation.REMOVE))
    legacy_run = tmp_path / "legacy-run"
    legacy_run.mkdir()
    artifact = legacy_run / "hypothesis.json"
    artifact.write_text(legacy.model_dump_json(), encoding="utf-8")
    before = artifact.read_bytes()
    before_names = tuple(item.name for item in legacy_run.iterdir())

    first = LegacyHypothesisMigrationDecisionV2.from_legacy_hypothesis(legacy)
    second = LegacyHypothesisMigrationDecisionV2.from_legacy_hypothesis(legacy)

    assert first == second
    assert artifact.read_bytes() == before
    assert tuple(item.name for item in legacy_run.iterdir()) == before_names


def test_migration_decision_is_content_addressed_and_tamper_evident() -> None:
    decision = LegacyHypothesisMigrationDecisionV2.from_legacy_hypothesis(
        _legacy_hypothesis((FeatureOperation.ADD,))
    )
    payload = decision.model_dump(mode="json")
    payload["migration_rule_sha256"] = "9" * 64

    with pytest.raises(ValidationError):
        LegacyHypothesisMigrationDecisionV2.model_validate(payload)

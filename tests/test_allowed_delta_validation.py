from __future__ import annotations

from m5_executor_fixtures import proposal_graph, request
from secaware.config import TSGConfig
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors.factory import extraction_policy
from secaware.intervention.executors import (
    DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    DeterministicInterventionExecutor,
)
from secaware.intervention.variant_validation import validate_variant
from secaware.schema.experiments import ArmRole, FeatureFamily, FeatureOperation


def _validate(candidate_text: str, *, role: ArmRole = ArmRole.TARGET_PATCH):
    execution = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        role,
    )
    candidate = (
        DeterministicInterventionExecutor()
        .execute(execution)
        .model_copy(update={"text": candidate_text})
    )
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    return validate_variant(
        candidate=candidate,
        source_prompt=execution.source_prompt,
        target=execution.target,
        target_instance=execution.target_instance,
        protocol=execution.protocol,
        protocol_instance=execution.protocol_instance,
        arm=execution.arm,
        source_proposal=execution.source_proposal,
        source_graph=execution.source_graph,
        source_attestation=next(
            item
            for item in execution.attestations
            if item.prompt_id == execution.source_prompt.prompt_id
        ),
        extractor=DeterministicCatalogExtractor(),
        extraction_policy=policy,
        expected_executor_policy_sha256=DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    )


def test_target_not_changed_is_frozen_as_diagnostic_not_hard_failure() -> None:
    execution = request()
    result = _validate(execution.source_prompt.prompt)

    assert result.hard_valid is True
    assert result.target_changed is False
    assert result.semantic_compliance is False
    assert result.variant is not None
    assert result.delta is not None


def test_undeclared_cross_family_change_is_hard_invalid() -> None:
    execution = request()
    result = _validate(execution.source_prompt.prompt + " Apply a no-op rewrite.")

    assert result.hard_valid is False
    assert result.variant is None
    assert result.failure_code.value == "allowed_delta_violation"


def test_independent_extractor_receives_only_prompt_and_locked_policy() -> None:
    execution = request()
    candidate = DeterministicInterventionExecutor().execute(execution)
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))

    class CapturingExtractor:
        def __init__(self) -> None:
            self.calls: list[tuple[object, object]] = []

        def extract(self, prompt, extraction_policy):
            self.calls.append((prompt, extraction_policy))
            return DeterministicCatalogExtractor().extract(prompt, extraction_policy)

    extractor = CapturingExtractor()
    result = validate_variant(
        candidate=candidate,
        source_prompt=execution.source_prompt,
        target=execution.target,
        target_instance=execution.target_instance,
        protocol=execution.protocol,
        protocol_instance=execution.protocol_instance,
        arm=execution.arm,
        source_proposal=execution.source_proposal,
        source_graph=execution.source_graph,
        source_attestation=next(
            item
            for item in execution.attestations
            if item.prompt_id == execution.source_prompt.prompt_id
        ),
        extractor=extractor,
        extraction_policy=policy,
        expected_executor_policy_sha256=DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    )

    assert result.hard_valid is True
    assert len(extractor.calls) == 1
    extracted_prompt, extracted_policy = extractor.calls[0]
    assert extracted_policy == policy
    assert "arm_role" not in type(extracted_prompt).model_fields
    assert "target_spec_id" not in type(extracted_prompt).model_fields
    assert "outcome" not in extracted_prompt.model_dump_json().casefold()


def test_source_graph_must_exactly_round_trip_from_committed_proposal() -> None:
    execution = request()
    _other_proposal, other_graph = proposal_graph(
        execution.source_prompt.model_copy(
            update={"prompt": execution.source_prompt.prompt + " Apply a no-op rewrite."}
        )
    )
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    candidate = DeterministicInterventionExecutor().execute(execution)

    result = validate_variant(
        candidate=candidate,
        source_prompt=execution.source_prompt,
        target=execution.target,
        target_instance=execution.target_instance,
        protocol=execution.protocol,
        protocol_instance=execution.protocol_instance,
        arm=execution.arm,
        source_proposal=execution.source_proposal,
        source_graph=other_graph,
        source_attestation=next(
            item
            for item in execution.attestations
            if item.prompt_id == execution.source_prompt.prompt_id
        ),
        extractor=DeterministicCatalogExtractor(),
        extraction_policy=policy,
        expected_executor_policy_sha256=DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    )

    assert result.hard_valid is False
    assert result.failure_code.value == "source_provenance_mismatch"


def test_executor_policy_mismatch_has_its_own_typed_failure() -> None:
    execution = request()
    candidate = (
        DeterministicInterventionExecutor()
        .execute(execution)
        .model_copy(update={"executor_policy_sha256": "0" * 64})
    )
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))

    result = validate_variant(
        candidate=candidate,
        source_prompt=execution.source_prompt,
        target=execution.target,
        target_instance=execution.target_instance,
        protocol=execution.protocol,
        protocol_instance=execution.protocol_instance,
        arm=execution.arm,
        source_proposal=execution.source_proposal,
        source_graph=execution.source_graph,
        source_attestation=next(
            item
            for item in execution.attestations
            if item.prompt_id == execution.source_prompt.prompt_id
        ),
        extractor=DeterministicCatalogExtractor(),
        extraction_policy=policy,
        expected_executor_policy_sha256=DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    )

    assert result.hard_valid is False
    assert result.failure_code.value == "executor_policy_mismatch"

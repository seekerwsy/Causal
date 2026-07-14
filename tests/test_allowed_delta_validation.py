from __future__ import annotations

import hashlib
import json

import pytest

from m5_executor_fixtures import proposal_graph, request
import secaware.intervention.variant_validation as variant_validation
from secaware.config import TSGConfig
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors.factory import extraction_policy
from secaware.intervention.executors import (
    DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    DeterministicInterventionExecutor,
)
from secaware.intervention.variant_validation import validate_variant
from secaware.schema.experiments import (
    ArmRole,
    FeatureFamily,
    FeatureOperation,
    FeatureState,
)
from secaware.schema.prompt_extraction import (
    PromptExtractionProposalRecord,
    SemanticFact,
    proposal_id_for_payload,
)
from secaware.schema.records import PromptRecord


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


class _StateOverrideExtractor:
    def __init__(self, feature_id: str) -> None:
        self.feature_id = feature_id

    def extract(self, prompt, policy):
        proposal = DeterministicCatalogExtractor().extract(prompt, policy)
        facts = tuple(
            SemanticFact.model_validate(
                {
                    **fact.model_dump(mode="python"),
                    "state": FeatureState.UNRESOLVED,
                    "evidence": (),
                }
            )
            if fact.feature_id == self.feature_id
            else fact
            for fact in proposal.facts
        )
        raw_response = json.dumps(
            {"facts": [fact.model_dump(mode="json") for fact in facts]},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        payload = proposal.model_dump(mode="python", exclude={"proposal_id"})
        payload.update(
            {
                "raw_response": raw_response,
                "response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
                "facts": facts,
            }
        )
        payload["proposal_id"] = proposal_id_for_payload(payload)
        return PromptExtractionProposalRecord.model_validate(payload)


def _validate_with_extractor(candidate_text: str, extractor):
    execution = request()
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
        extractor=extractor,
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


def test_fixed_family_presentation_drift_is_hard_invalid() -> None:
    execution = request()
    result = _validate(execution.source_prompt.prompt + " Apply a no-op rewrite.")

    assert result.hard_valid is False
    assert result.variant is None
    assert result.failure_code.value == "allowed_delta_violation"


def test_fixed_feature_id_non_target_safety_drift_is_hard_invalid() -> None:
    execution = request()
    result = _validate(
        execution.source_prompt.prompt + " Normalize the path. Follow security best practices."
    )

    assert result.hard_valid is False
    assert result.failure_code.value == "allowed_delta_violation"


def test_target_unresolved_is_frozen_as_unknown_diagnostic() -> None:
    execution = request()
    candidate = execution.source_prompt.prompt + " Normalize the path."

    result = _validate_with_extractor(
        candidate,
        _StateOverrideExtractor("safety.path_normalization"),
    )

    assert result.hard_valid is True
    assert result.target_changed is None
    assert result.semantic_compliance is None
    assert result.variant is not None


def test_fixed_projection_unresolved_is_hard_invalid() -> None:
    execution = request()
    candidate = execution.source_prompt.prompt + " Normalize the path."

    result = _validate_with_extractor(
        candidate,
        _StateOverrideExtractor("presentation.noop_rewrite"),
    )

    assert result.hard_valid is False
    assert result.failure_code.value == "fixed_projection_unresolved"


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


def test_extractor_policy_mismatch_has_its_own_typed_failure() -> None:
    execution = request()

    class WrongPolicyExtractor:
        def extract(self, prompt, policy):
            proposal = DeterministicCatalogExtractor().extract(prompt, policy)
            payload = proposal.model_dump(mode="python", exclude={"proposal_id"})
            payload["policy_sha256"] = "1" * 64
            payload["proposal_id"] = proposal_id_for_payload(payload)
            return PromptExtractionProposalRecord.model_validate(payload)

    result = _validate_with_extractor(
        execution.source_prompt.prompt + " Normalize the path.",
        WrongPolicyExtractor(),
    )

    assert result.hard_valid is False
    assert result.failure_code.value == "extractor_policy_mismatch"


def test_after_extraction_proposal_must_exactly_bind_candidate_prompt() -> None:
    execution = request()

    class OtherPromptExtractor:
        def extract(self, prompt, policy):
            other = PromptRecord.model_validate(
                {
                    **prompt.model_dump(mode="python"),
                    "prompt": prompt.prompt + " unrelated",
                }
            )
            return DeterministicCatalogExtractor().extract(other, policy)

    result = _validate_with_extractor(
        execution.source_prompt.prompt + " Normalize the path.",
        OtherPromptExtractor(),
    )

    assert result.hard_valid is False
    assert result.failure_code.value == "extractor_policy_mismatch"


def test_after_graph_must_exactly_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = request()
    original = variant_validation.build_prompt_tsg
    calls = 0

    def corrupt_after_graph(proposal, prompt):
        nonlocal calls
        calls += 1
        graph = original(proposal, prompt)
        if calls == 2:
            return graph.model_copy(update={"graph_sha256": "0" * 64})
        return graph

    monkeypatch.setattr(variant_validation, "build_prompt_tsg", corrupt_after_graph)

    result = _validate(execution.source_prompt.prompt + " Normalize the path.")

    assert result.hard_valid is False
    assert result.failure_code.value == "graph_roundtrip_failed"


def test_source_task_mismatch_is_hard_invalid() -> None:
    execution = request()
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    candidate = DeterministicInterventionExecutor().execute(execution)

    result = validate_variant(
        candidate=candidate,
        source_prompt=execution.source_prompt.model_copy(update={"task_id": "other-task"}),
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
    assert result.failure_code.value == "source_provenance_mismatch"


def test_source_split_mismatch_is_hard_invalid() -> None:
    execution = request()
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    candidate = DeterministicInterventionExecutor().execute(execution)

    result = validate_variant(
        candidate=candidate,
        source_prompt=execution.source_prompt.model_copy(update={"split": "discover"}),
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
    assert result.failure_code.value == "source_provenance_mismatch"

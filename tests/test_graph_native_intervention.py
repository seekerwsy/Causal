from __future__ import annotations

import json
import pytest
from pydantic import ValidationError

from m5_executor_fixtures import request
from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.executors import (
    DeterministicInterventionExecutor,
    GraphNativeExecutor,
    PromptCandidate,
    LLMInterventionExecutor,
)
from secaware.intervention.graph_patch import (
    IntendedGraphPatchRecord,
    allowed_delta_sha256,
)
from secaware.schema.experiments import (
    ArmRole,
    FeatureFamily,
    FeatureOperation,
    InterventionMode,
)
from m5_executor_fixtures import CapturingTransport, structured_policy


class RecordingRenderer:
    def __init__(self) -> None:
        self.calls: list[tuple[object, IntendedGraphPatchRecord]] = []
        self.delegate = DeterministicInterventionExecutor()

    def render(self, execution_request: object, patch: IntendedGraphPatchRecord) -> PromptCandidate:
        assert isinstance(patch, IntendedGraphPatchRecord)
        self.calls.append((execution_request, patch))
        return self.delegate.render(execution_request, patch)


def test_graph_native_executor_records_intended_patch_before_rendering() -> None:
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        ArmRole.TARGET_PATCH,
        mode=InterventionMode.GRAPH_NATIVE,
    )
    source_before = execution_request.source_graph.model_dump(mode="json")
    renderer = RecordingRenderer()

    patch, candidate = GraphNativeExecutor(renderer).execute(execution_request)

    assert len(renderer.calls) == 1
    assert renderer.calls[0][0].target.target_spec_id == execution_request.target.target_spec_id
    assert renderer.calls[0][1] == patch
    assert patch.before_graph_sha256 == execution_request.source_graph.graph_sha256
    assert patch.target_spec_id == execution_request.target.target_spec_id
    assert patch.target_instance_id == execution_request.target_instance.target_instance_id
    assert patch.arm_protocol_id == execution_request.protocol.arm_protocol_id
    assert patch.protocol_instance_id == execution_request.protocol_instance.protocol_instance_id
    assert patch.arm_role is ArmRole.TARGET_PATCH
    assert patch.allowed_delta_sha256 == allowed_delta_sha256(execution_request.arm.allowed_delta)
    assert patch.intended_transitions == execution_request.arm.allowed_delta.allowed_transitions
    assert candidate.mode is InterventionMode.GRAPH_NATIVE
    assert candidate.intended_patch_id == patch.patch_id
    assert execution_request.source_graph.model_dump(mode="json") == source_before


def test_graph_native_llm_request_binds_the_frozen_intended_patch() -> None:
    execution_request = request(mode=InterventionMode.GRAPH_NATIVE)
    transport = CapturingTransport({"candidate_text": execution_request.source_prompt.prompt})

    patch, candidate = GraphNativeExecutor(
        LLMInterventionExecutor(transport, structured_policy())
    ).execute(execution_request)

    payload = json.loads(transport.requests[0])
    assert payload["mode"] == "graph_native"
    assert payload["intended_patch"] == {
        "allowed_delta_sha256": patch.allowed_delta_sha256,
        "before_graph_sha256": patch.before_graph_sha256,
        "intended_transitions": [
            item.model_dump(mode="json") for item in patch.intended_transitions
        ],
        "patch_id": patch.patch_id,
    }
    assert (
        payload["allowed_delta"]["allowed_delta_sha256"]
        == payload["intended_patch"]["allowed_delta_sha256"]
    )
    assert candidate.intended_patch_id == patch.patch_id


def test_text_native_executor_rejects_graph_mode_without_intended_patch() -> None:
    execution_request = request(mode=InterventionMode.GRAPH_NATIVE)
    with pytest.raises(SecAwareError) as exc_info:
        DeterministicInterventionExecutor().execute(execution_request)
    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize(
    "field",
    (
        "patch_id",
        "target_spec_id",
        "target_instance_id",
        "arm_protocol_id",
        "protocol_instance_id",
        "arm_role",
        "before_graph_sha256",
        "allowed_delta_sha256",
        "intended_transitions",
    ),
)
def test_intended_graph_patch_is_content_addressed_and_mutation_closed(field: str) -> None:
    execution_request = request(mode=InterventionMode.GRAPH_NATIVE)
    patch, _candidate = GraphNativeExecutor(DeterministicInterventionExecutor()).execute(
        execution_request
    )
    payload = patch.model_dump(mode="python")
    if field == "patch_id":
        payload[field] = "patch_" + "0" * 64
    elif field in {
        "target_spec_id",
        "target_instance_id",
        "arm_protocol_id",
        "protocol_instance_id",
    }:
        prefix = str(payload[field]).split("_")[0] + "_"
        if field == "target_instance_id":
            prefix = "target_instance_"
        elif field == "arm_protocol_id":
            prefix = "arm_protocol_"
        elif field == "protocol_instance_id":
            prefix = "protocol_instance_"
        payload[field] = prefix + "0" * 64
    elif field == "arm_role":
        payload[field] = ArmRole.NOOP_REWRITE
    elif field in {"before_graph_sha256", "allowed_delta_sha256"}:
        payload[field] = "0" * 64
    else:
        payload[field] = ()

    with pytest.raises(ValidationError):
        IntendedGraphPatchRecord.model_validate(payload)


def test_intended_graph_patch_round_trips_strict_json() -> None:
    execution_request = request(mode=InterventionMode.GRAPH_NATIVE)
    patch, _candidate = GraphNativeExecutor(DeterministicInterventionExecutor()).execute(
        execution_request
    )

    restored = IntendedGraphPatchRecord.model_validate_json(patch.model_dump_json())

    assert restored == patch


class ForgingRenderer:
    def __init__(self, mutation: str) -> None:
        self.mutation = mutation
        self.delegate = DeterministicInterventionExecutor()

    def render(self, execution_request: object, patch: IntendedGraphPatchRecord) -> PromptCandidate:
        candidate = self.delegate.render(execution_request, patch)
        if self.mutation == "patch_id":
            return candidate.model_copy(update={"intended_patch_id": "patch_" + "0" * 64})
        if self.mutation == "coordinate":
            return candidate.model_copy(update={"target_spec_id": "target_" + "0" * 64})
        if self.mutation == "mode":
            return candidate.model_copy(update={"mode": InterventionMode.TEXT_NATIVE})
        if self.mutation == "patch":
            object.__setattr__(patch, "before_graph_sha256", "0" * 64)
            return candidate
        object.__setattr__(execution_request.source_graph, "graph_sha256", "0" * 64)
        return candidate


@pytest.mark.parametrize(
    "mutation",
    ("patch_id", "coordinate", "mode", "patch", "source_graph"),
)
def test_graph_native_revalidates_renderer_output_and_source_immutability(
    mutation: str,
) -> None:
    execution_request = request(mode=InterventionMode.GRAPH_NATIVE)
    with pytest.raises(SecAwareError) as exc_info:
        GraphNativeExecutor(ForgingRenderer(mutation)).execute(execution_request)
    assert exc_info.value.code in {ErrorCode.CONTRACT, ErrorCode.POLICY_MISMATCH}


def test_prompt_candidate_is_frozen_strict_and_hides_private_text() -> None:
    execution_request = request(mode=InterventionMode.GRAPH_NATIVE)
    _patch, candidate = GraphNativeExecutor(DeterministicInterventionExecutor()).execute(
        execution_request
    )
    secret = candidate.text
    assert secret not in repr(candidate)
    assert secret not in str(candidate)
    with pytest.raises(ValidationError):
        candidate.text = "mutated"  # type: ignore[misc]
    payload = candidate.model_dump(mode="python")
    payload["extra"] = "forbidden"
    with pytest.raises(ValidationError):
        PromptCandidate.model_validate(payload)


def test_graph_renderer_failure_is_sanitized_without_hiding_fatal_exceptions() -> None:
    secret = "private-renderer-failure"

    class FailingRenderer:
        def render(self, _request: object, _patch: object) -> PromptCandidate:
            raise RuntimeError(secret)

    with pytest.raises(SecAwareError) as exc_info:
        GraphNativeExecutor(FailingRenderer()).execute(request(mode=InterventionMode.GRAPH_NATIVE))
    assert exc_info.value.code is ErrorCode.CONTRACT
    assert secret not in str(exc_info.value)

    class FatalRenderer:
        def render(self, _request: object, _patch: object) -> PromptCandidate:
            raise MemoryError

    with pytest.raises(MemoryError):
        GraphNativeExecutor(FatalRenderer()).execute(request(mode=InterventionMode.GRAPH_NATIVE))

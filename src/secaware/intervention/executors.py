"""Locked deterministic and structured-LLM prompt intervention executors."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from importlib import resources
import json
import re
from typing import ClassVar, Protocol, Self

from pydantic import ConfigDict, Field, model_validator

from secaware.config import InterventionLLMConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.attestation import (
    PromptRoleAttestationRecord,
    attested_feature_id,
    counterpart_for,
    validate_prompt_role_attestations,
)
from secaware.intervention.graph_patch import (
    IntendedGraphPatchRecord,
    allowed_delta_sha256,
)
from secaware.llm.structured_transport import (
    StructuredJSONTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiments import (
    ArmSpecRecord,
    ArmRole,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FeatureState,
    InterventionMode,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)
from secaware.tsg.graph import record_to_multidigraph


_STAGE = "intervention.execute"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CANDIDATE_BYTES = 262_144
_OUTPUT_SCHEMA = {
    "schema_version": "1.0",
    "top_level_keys": ["candidate_text"],
    "candidate_text": {"type": "string", "min_utf8_bytes": 1, "max_utf8_bytes": 262_144},
}
_RESPONSE_KEYS = frozenset({"candidate_text"})


def _template_text() -> str:
    return (
        resources.files("secaware.intervention")
        .joinpath("prompts/intervention_executor_v1.txt")
        .read_text(encoding="utf-8")
    )


INTERVENTION_EXECUTOR_TEMPLATE_VERSION = "intervention-executor-v1"
INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE = _template_text()
INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256 = hashlib.sha256(
    INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE.encode("utf-8")
).hexdigest()
INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256 = hashlib.sha256(
    canonical_request_bytes(_OUTPUT_SCHEMA)
).hexdigest()


def _error(code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message="prompt intervention execution validation failed",
    )


def _structured_policy_payload(policy: StructuredLLMPolicy) -> dict[str, object]:
    return {field: getattr(policy, field) for field in StructuredLLMPolicy.__dataclass_fields__}


def intervention_executor_policy_sha256(
    policy: StructuredLLMPolicy,
    catalog_sha256: str = PROMPT_FEATURE_CATALOG_SHA256,
) -> str:
    """Bind executor template, catalog, model, endpoint, and decoding coordinates."""

    try:
        if type(policy) is not StructuredLLMPolicy:
            raise ValueError
        checked = StructuredLLMPolicy(**_structured_policy_payload(policy))
        if type(catalog_sha256) is not str or _SHA256.fullmatch(catalog_sha256) is None:
            raise ValueError
        return hashlib.sha256(
            canonical_request_bytes(
                {
                    "executor_kind": "llm",
                    "executor_template_version": INTERVENTION_EXECUTOR_TEMPLATE_VERSION,
                    "catalog_sha256": catalog_sha256,
                    "structured_llm_policy": _structured_policy_payload(checked),
                }
            )
        ).hexdigest()
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error(ErrorCode.POLICY_MISMATCH) from None


DETERMINISTIC_INTERVENTION_POLICY_SHA256 = hashlib.sha256(
    canonical_request_bytes(
        {
            "executor_kind": "deterministic",
            "executor_version": "catalog-clause-and-attested-byte-range-v1",
            "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        }
    )
).hexdigest()


def structured_policy_from_config(config: InterventionLLMConfig) -> StructuredLLMPolicy:
    """Materialize the executor's shared-transport policy from one frozen run config."""

    try:
        if type(config) is not InterventionLLMConfig:
            raise ValueError
        checked = InterventionLLMConfig.model_validate(config.model_dump(mode="python"))
        return StructuredLLMPolicy(
            endpoint_sha256=hashlib.sha256(checked.base_url.encode("utf-8")).hexdigest(),
            model_id=checked.model_id,
            system_template_sha256=INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256,
            output_schema_sha256=INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
            temperature=checked.temperature,
            top_p=checked.top_p,
            seed=checked.seed,
            timeout_seconds=checked.timeout_seconds,
            max_attempts=checked.max_attempts,
            max_response_bytes=checked.max_response_bytes,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error(ErrorCode.CONFIG) from None


class InterventionExecutionRequest(SafeValidationMixin, StrictModel):
    """Complete task-bound input to one pre-randomization arm executor."""

    _safe_validation_message: ClassVar[str] = "intervention execution request failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    target: TargetSpecRecord
    target_instance: TargetInstanceRecord
    protocol: ConfirmationProtocolRecord
    protocol_instance: ConfirmationProtocolInstanceRecord
    arm: ArmSpecRecord
    source_prompt: PromptRecord = Field(repr=False)
    source_graph: PromptTSGRecord = Field(repr=False)
    counterpart_prompt: PromptRecord | None = Field(default=None, repr=False)
    attestations: tuple[PromptRoleAttestationRecord, ...] = Field(repr=False)
    mode: InterventionMode

    def __repr__(self) -> str:
        return "InterventionExecutionRequest()"

    def __str__(self) -> str:
        return "InterventionExecutionRequest()"


class PromptCandidate(SafeValidationMixin, StrictModel):
    """One unvalidated executor candidate; Task 4 performs blind extraction."""

    _safe_validation_message: ClassVar[str] = "prompt candidate validation failed"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    source_prompt_id: str
    target_spec_id: str = Field(pattern=r"^target_[0-9a-f]{64}$")
    target_instance_id: str = Field(pattern=r"^target_instance_[0-9a-f]{64}$")
    arm_protocol_id: str = Field(pattern=r"^arm_protocol_[0-9a-f]{64}$")
    protocol_instance_id: str = Field(pattern=r"^protocol_instance_[0-9a-f]{64}$")
    arm_role: ArmRole
    mode: InterventionMode
    executor_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intended_patch_id: str | None = Field(default=None, pattern=r"^patch_[0-9a-f]{64}$")
    text: str = Field(min_length=1, max_length=_MAX_CANDIDATE_BYTES, repr=False)

    @model_validator(mode="after")
    def validate_mode_patch_and_text(self) -> Self:
        if type(self.arm_role) is not ArmRole:
            raise ValueError(self._safe_validation_message)
        if (self.mode is InterventionMode.GRAPH_NATIVE) != (self.intended_patch_id is not None):
            raise ValueError(self._safe_validation_message)
        try:
            encoded = self.text.encode("utf-8")
        except Exception:
            raise ValueError(self._safe_validation_message) from None
        if not encoded or len(encoded) > _MAX_CANDIDATE_BYTES:
            raise ValueError(self._safe_validation_message)
        return self

    def __repr__(self) -> str:
        return "PromptCandidate()"

    def __str__(self) -> str:
        return "PromptCandidate()"


def _snapshot_prompt(value: object) -> PromptRecord:
    if type(value) is not PromptRecord:
        raise ValueError
    return PromptRecord.model_validate(value.model_dump(mode="python"))


def _trusted_request(value: object) -> InterventionExecutionRequest:
    """Deep-revalidate every coordinate and canonical source graph."""

    try:
        if type(value) is not InterventionExecutionRequest:
            raise ValueError
        target = TargetSpecRecord.model_validate(value.target.model_dump(mode="python"))
        target_instance = TargetInstanceRecord.model_validate(
            value.target_instance.model_dump(mode="python")
        )
        protocol = ConfirmationProtocolRecord.model_validate(
            value.protocol.model_dump(mode="python")
        )
        protocol_instance = ConfirmationProtocolInstanceRecord.model_validate(
            value.protocol_instance.model_dump(mode="python")
        )
        arm = ArmSpecRecord.model_validate(value.arm.model_dump(mode="python"))
        source = _snapshot_prompt(value.source_prompt)
        counterpart = (
            _snapshot_prompt(value.counterpart_prompt)
            if value.counterpart_prompt is not None
            else None
        )
        attestations = tuple(
            PromptRoleAttestationRecord.model_validate(item.model_dump(mode="python"))
            for item in value.attestations
        )
        graph = PromptTSGRecord.model_validate(value.source_graph.model_dump(mode="python"))
        record_to_multidigraph(graph)
        mode = InterventionMode(value.mode)
        expected_arms = tuple(item for item in protocol.arms if item.role is arm.role)
        if (
            target.target_spec_id != target_instance.target_spec_id
            or protocol.target_spec_id != target.target_spec_id
            or protocol.hypothesis_id != target.hypothesis_id
            or protocol.feature_family is not target.feature_family
            or protocol.operation is not target.operation
            or protocol_instance.arm_protocol_id != protocol.arm_protocol_id
            or protocol_instance.target_instance_id != target_instance.target_instance_id
            or target_instance.task_id != source.task_id
            or target_instance.source_prompt_id != source.prompt_id
            or target_instance.source_prompt_sha256 != source.prompt_sha256
            or target_instance.source_prompt_role is not source.prompt_role
            or protocol_instance.task_id != source.task_id
            or protocol_instance.source_prompt_id != source.prompt_id
            or protocol_instance.source_prompt_sha256 != source.prompt_sha256
            or len(expected_arms) != 1
            or expected_arms[0] != arm
            or source.split != "confirm"
            or graph.prompt_id != source.prompt_id
            or graph.task_id != source.task_id
            or graph.task_family != source.task_family
            or graph.cwe != source.cwe
        ):
            raise ValueError
        source_attestations = tuple(
            item for item in attestations if item.prompt_id == source.prompt_id
        )
        if (
            len(source_attestations) != 1
            or source_attestations[0].task_id != source.task_id
            or source_attestations[0].prompt_sha256 != source.prompt_sha256
            or source_attestations[0].prompt_role is not source.prompt_role
            or source_attestations[0].catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or source_attestations[0].contrast_owner_operation is not target.operation
        ):
            raise ValueError
        if target_instance.counterpart_required:
            if counterpart is None:
                raise ValueError
            validated_attestations = validate_prompt_role_attestations(
                (counterpart, source),
                attestations,
            )
            resolved = counterpart_for(target_instance, validated_attestations)
            if (
                resolved.prompt_id != counterpart.prompt_id
                or resolved.prompt_sha256 != counterpart.prompt_sha256
                or target_instance.counterpart_prompt_id != counterpart.prompt_id
                or target_instance.counterpart_prompt_sha256 != counterpart.prompt_sha256
                or protocol_instance.counterpart_prompt_id != counterpart.prompt_id
                or protocol_instance.counterpart_prompt_sha256 != counterpart.prompt_sha256
            ):
                raise ValueError
            if attested_feature_id(source_attestations[0]) != target.feature_id:
                raise ValueError
        else:
            if counterpart is not None or len(attestations) != 2:
                raise ValueError
            peer_matches = tuple(
                item
                for item in attestations
                if item.prompt_id != source.prompt_id
                and item.counterpart_prompt_id == source.prompt_id
                and item.counterpart_prompt_sha256 == source.prompt_sha256
                and item.task_id == source.task_id
                and item.contrast_owner_operation is target.operation
                and item.catalog_sha256 == PROMPT_FEATURE_CATALOG_SHA256
            )
            if len(peer_matches) != 1 or attested_feature_id(peer_matches[0]) != target.feature_id:
                raise ValueError
        return InterventionExecutionRequest(
            target=target,
            target_instance=target_instance,
            protocol=protocol,
            protocol_instance=protocol_instance,
            arm=arm,
            source_prompt=source,
            source_graph=graph,
            counterpart_prompt=counterpart,
            attestations=attestations,
            mode=mode,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None


def _attested_neutral_text(request: InterventionExecutionRequest) -> str:
    """Remove the exact attested UTF-8 byte interval and verify its counterpart."""

    counterpart = request.counterpart_prompt
    if counterpart is None:
        raise _error() from None
    source_matches = tuple(
        item for item in request.attestations if item.prompt_id == request.source_prompt.prompt_id
    )
    if len(source_matches) != 1:
        raise _error() from None
    attestation = source_matches[0]
    start = attestation.variant_clause_start
    end = attestation.variant_clause_end
    clause_sha256 = attestation.variant_clause_sha256
    source_bytes = request.source_prompt.prompt.encode("utf-8")
    if start is None or end is None or clause_sha256 is None:
        raise _error() from None
    try:
        clause = source_bytes[start:end]
        restored = source_bytes[:start] + source_bytes[end:]
        text = restored.decode("utf-8")
    except Exception:
        raise _error() from None
    if (
        hashlib.sha256(clause).hexdigest() != clause_sha256
        or restored != counterpart.prompt.encode("utf-8")
        or text != counterpart.prompt
    ):
        raise _error() from None
    return text


def _deterministic_text(request: InterventionExecutionRequest) -> str:
    transitions = request.arm.allowed_delta.allowed_transitions
    removes = tuple(item for item in transitions if item.to_states == (FeatureState.ABSENT,))
    text = _attested_neutral_text(request) if removes else request.source_prompt.prompt
    for transition in transitions:
        if transition.to_states != (FeatureState.PRESENT,):
            continue
        spec = prompt_feature_spec(transition.feature_id)
        if not spec.intervenable or not spec.intervention_clauses:
            raise _error() from None
        text += spec.intervention_clauses[0]
    return text


def _candidate(
    request: InterventionExecutionRequest,
    *,
    policy_sha256: str,
    text: str,
    patch: IntendedGraphPatchRecord | None,
) -> PromptCandidate:
    return PromptCandidate(
        source_prompt_id=request.source_prompt.prompt_id,
        target_spec_id=request.target.target_spec_id,
        target_instance_id=request.target_instance.target_instance_id,
        arm_protocol_id=request.protocol.arm_protocol_id,
        protocol_instance_id=request.protocol_instance.protocol_instance_id,
        arm_role=request.arm.role,
        mode=request.mode,
        executor_policy_sha256=policy_sha256,
        intended_patch_id=patch.patch_id if patch is not None else None,
        text=text,
    )


def _validate_candidate_binding(
    candidate: object,
    request: InterventionExecutionRequest,
    patch: IntendedGraphPatchRecord | None,
) -> PromptCandidate:
    try:
        if type(candidate) is not PromptCandidate:
            raise ValueError
        checked = PromptCandidate.model_validate(candidate.model_dump(mode="python"))
        if (
            checked.source_prompt_id != request.source_prompt.prompt_id
            or checked.target_spec_id != request.target.target_spec_id
            or checked.target_instance_id != request.target_instance.target_instance_id
            or checked.arm_protocol_id != request.protocol.arm_protocol_id
            or checked.protocol_instance_id != request.protocol_instance.protocol_instance_id
            or checked.arm_role is not request.arm.role
            or checked.mode is not request.mode
            or checked.intended_patch_id != (patch.patch_id if patch is not None else None)
        ):
            raise ValueError
        return checked
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None


class DeterministicInterventionExecutor:
    """Render only catalog-owned clauses and attested exact removals."""

    def __repr__(self) -> str:
        return "DeterministicInterventionExecutor()"

    def execute(self, execution_request: InterventionExecutionRequest) -> PromptCandidate:
        trusted = _trusted_request(execution_request)
        if trusted.mode is not InterventionMode.TEXT_NATIVE:
            raise _error() from None
        return self.render(trusted, None)

    def render(
        self,
        execution_request: InterventionExecutionRequest,
        patch: IntendedGraphPatchRecord | None,
    ) -> PromptCandidate:
        trusted = _trusted_request(execution_request)
        if (trusted.mode is InterventionMode.GRAPH_NATIVE) != (patch is not None):
            raise _error() from None
        text = _deterministic_text(trusted)
        result = _candidate(
            trusted,
            policy_sha256=DETERMINISTIC_INTERVENTION_POLICY_SHA256,
            text=text,
            patch=patch,
        )
        return _validate_candidate_binding(result, trusted, patch)


def _request_payload(
    request: InterventionExecutionRequest,
    patch: IntendedGraphPatchRecord | None,
) -> dict[str, object]:
    delta = request.arm.allowed_delta
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "request_kind": "bounded_prompt_intervention",
        "source_prompt": {
            "content": request.source_prompt.prompt,
            "content_sha256": request.source_prompt.prompt_sha256,
            "interpretation": "inert_data",
        },
        "target_spec_id": request.target.target_spec_id,
        "target_instance_id": request.target_instance.target_instance_id,
        "arm_protocol_id": request.protocol.arm_protocol_id,
        "protocol_instance_id": request.protocol_instance.protocol_instance_id,
        "target": {
            "feature_id": request.target.feature_id,
            "feature_family": request.target.feature_family.value,
        },
        "operation": request.target.operation.value,
        "arm_role": request.arm.role.value,
        "mode": request.mode.value,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "allowed_delta": {
            "allowed_transitions": [
                item.model_dump(mode="json") for item in delta.allowed_transitions
            ],
            "fixed_families": [item.value for item in delta.fixed_families],
            "all_unlisted_features_fixed": True,
        },
        "output_schema": _OUTPUT_SCHEMA,
    }
    if patch is not None:
        payload["intended_patch"] = {
            "patch_id": patch.patch_id,
            "before_graph_sha256": patch.before_graph_sha256,
            "allowed_delta_sha256": patch.allowed_delta_sha256,
            "intended_transitions": [
                item.model_dump(mode="json") for item in patch.intended_transitions
            ],
        }
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _parse_response(raw: bytes, maximum: int) -> str:
    try:
        if type(raw) is not bytes or not raw or len(raw) > maximum:
            raise ValueError
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(payload, Mapping) or frozenset(payload) != _RESPONSE_KEYS:
            raise ValueError
        text = payload["candidate_text"]
        if type(text) is not str:
            raise ValueError
        encoded = text.encode("utf-8")
        if not encoded or len(encoded) > _MAX_CANDIDATE_BYTES:
            raise ValueError
        return text
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None


def _new_occurrences(candidate: str, source: str, fragment: str) -> bool:
    return candidate.casefold().count(fragment.casefold()) > source.casefold().count(
        fragment.casefold()
    )


def _validate_llm_text(text: str, request: InterventionExecutionRequest) -> None:
    allowed = {item.feature_id for item in request.arm.allowed_delta.allowed_transitions}
    source = request.source_prompt.prompt
    for spec in PROMPT_FEATURE_CATALOG:
        if spec.feature_id in allowed:
            continue
        catalog_text = (*spec.intervention_clauses, *spec.deterministic_terms)
        if any(_new_occurrences(text, source, fragment) for fragment in catalog_text):
            raise _error() from None
    removes = tuple(
        item
        for item in request.arm.allowed_delta.allowed_transitions
        if item.to_states == (FeatureState.ABSENT,)
    )
    if removes:
        neutral = _attested_neutral_text(request)
        source_match = tuple(
            item
            for item in request.attestations
            if item.prompt_id == request.source_prompt.prompt_id
        )[0]
        start = source_match.variant_clause_start
        end = source_match.variant_clause_end
        if start is None or end is None:
            raise _error() from None
        removed_clause = request.source_prompt.prompt.encode("utf-8")[start:end].decode("utf-8")
        if not text.startswith(neutral) or removed_clause in text:
            raise _error() from None
        has_add = any(
            item.to_states == (FeatureState.PRESENT,)
            for item in request.arm.allowed_delta.allowed_transitions
        )
        if not has_add and text != neutral:
            raise _error() from None


class LLMInterventionExecutor:
    """Obtain exactly one candidate through the shared byte-locked transport."""

    __slots__ = ("_executor_policy_sha256", "_structured_policy", "_transport")

    def __init__(
        self,
        transport: StructuredJSONTransport,
        structured_policy: StructuredLLMPolicy,
    ) -> None:
        try:
            if not callable(getattr(transport, "complete", None)):
                raise ValueError
            if type(structured_policy) is not StructuredLLMPolicy:
                raise ValueError
            checked = StructuredLLMPolicy(**_structured_policy_payload(structured_policy))
            if (
                checked.system_template_sha256 != INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256
                or checked.output_schema_sha256 != INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256
            ):
                raise _error(ErrorCode.POLICY_MISMATCH)
            self._transport = transport
            self._structured_policy = checked
            self._executor_policy_sha256 = intervention_executor_policy_sha256(checked)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error(ErrorCode.CONFIG) from None

    def __repr__(self) -> str:
        return "LLMInterventionExecutor()"

    def _validate_policy_lock(self) -> None:
        if (
            self._structured_policy.system_template_sha256
            != INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256
            or self._structured_policy.output_schema_sha256
            != INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256
            or intervention_executor_policy_sha256(self._structured_policy)
            != self._executor_policy_sha256
        ):
            raise _error(ErrorCode.POLICY_MISMATCH) from None

    def execute(self, execution_request: InterventionExecutionRequest) -> PromptCandidate:
        trusted = _trusted_request(execution_request)
        if trusted.mode is not InterventionMode.TEXT_NATIVE:
            raise _error() from None
        return self.render(trusted, None)

    def render(
        self,
        execution_request: InterventionExecutionRequest,
        patch: IntendedGraphPatchRecord | None,
    ) -> PromptCandidate:
        trusted = _trusted_request(execution_request)
        if (trusted.mode is InterventionMode.GRAPH_NATIVE) != (patch is not None):
            raise _error() from None
        self._validate_policy_lock()
        request_bytes = canonical_request_bytes(_request_payload(trusted, patch))
        call_policy = StructuredLLMPolicy(**_structured_policy_payload(self._structured_policy))
        expected_call_policy = _structured_policy_payload(call_policy)
        try:
            raw = self._transport.complete(request_bytes, call_policy)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error(ErrorCode.API_INVALID_RESPONSE) from None
        if _structured_policy_payload(call_policy) != expected_call_policy:
            raise _error(ErrorCode.POLICY_MISMATCH) from None
        self._validate_policy_lock()
        text = _parse_response(raw, self._structured_policy.max_response_bytes)
        _validate_llm_text(text, trusted)
        result = _candidate(
            trusted,
            policy_sha256=self._executor_policy_sha256,
            text=text,
            patch=patch,
        )
        return _validate_candidate_binding(result, trusted, patch)


class GraphRenderer(Protocol):
    def render(
        self,
        execution_request: InterventionExecutionRequest,
        patch: IntendedGraphPatchRecord,
    ) -> PromptCandidate:
        raise NotImplementedError


class GraphNativeExecutor:
    """Freeze an intended graph patch before delegating graph-to-text rendering."""

    __slots__ = ("_renderer",)

    def __init__(self, renderer: GraphRenderer) -> None:
        try:
            if not callable(getattr(renderer, "render", None)):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _error(ErrorCode.CONFIG) from None
        self._renderer = renderer

    def __repr__(self) -> str:
        return "GraphNativeExecutor()"

    def execute(
        self,
        execution_request: InterventionExecutionRequest,
    ) -> tuple[IntendedGraphPatchRecord, PromptCandidate]:
        trusted = _trusted_request(execution_request)
        if trusted.mode is not InterventionMode.GRAPH_NATIVE:
            raise _error() from None
        source_snapshot = trusted.source_graph.model_dump(mode="json")
        request_snapshot = trusted.model_dump(mode="json")
        patch = IntendedGraphPatchRecord.from_content(
            target_spec_id=trusted.target.target_spec_id,
            target_instance_id=trusted.target_instance.target_instance_id,
            arm_protocol_id=trusted.protocol.arm_protocol_id,
            protocol_instance_id=trusted.protocol_instance.protocol_instance_id,
            arm_role=trusted.arm.role,
            before_graph_sha256=trusted.source_graph.graph_sha256,
            allowed_delta_sha256=allowed_delta_sha256(trusted.arm.allowed_delta),
            intended_transitions=trusted.arm.allowed_delta.allowed_transitions,
        )
        patch_snapshot = patch.model_dump(mode="json")
        try:
            candidate = self._renderer.render(trusted, patch)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error() from None
        if (
            trusted.source_graph.model_dump(mode="json") != source_snapshot
            or trusted.model_dump(mode="json") != request_snapshot
            or patch.model_dump(mode="json") != patch_snapshot
        ):
            raise _error() from None
        IntendedGraphPatchRecord.model_validate(patch.model_dump(mode="python"))
        _trusted_request(trusted)
        checked = _validate_candidate_binding(candidate, trusted, patch)
        return patch, checked


__all__ = [
    "DETERMINISTIC_INTERVENTION_POLICY_SHA256",
    "INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256",
    "INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE",
    "INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256",
    "INTERVENTION_EXECUTOR_TEMPLATE_VERSION",
    "DeterministicInterventionExecutor",
    "GraphNativeExecutor",
    "InterventionExecutionRequest",
    "LLMInterventionExecutor",
    "PromptCandidate",
    "intervention_executor_policy_sha256",
    "structured_policy_from_config",
]

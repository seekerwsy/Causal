"""Independent Prompt-TSG validation for pre-randomization arm variants.

Executor candidates are untrusted text.  This module rebuilds their Prompt TSGs
with the run-locked M4A extractor, validates the finite graph delta, and only
then creates content-addressed records that later stages may randomize.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from typing import ClassVar, NoReturn

import networkx as nx
from pydantic import ConfigDict, Field

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy, PromptExtractor
from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.intervention.executors import PromptCandidate
from secaware.intervention.graph_patch import (
    IntendedGraphPatchRecord,
    allowed_delta_sha256,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import SafeValidationMixin, StrictModel, model_shape_is_intact
from secaware.schema.experiments import (
    ArmRole,
    ArmSpecRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FeatureState,
    FeatureTransition,
    GraphDeltaRecord,
    InterventionMode,
    LengthMatchRecord,
    PreRandomizationFailureCode,
    PromptVariantRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph
from secaware.tsg.proposal_validator import validate_proposal
from secaware.tsg.queries import feature_state, feature_state_vector


_STAGE = "prompt_variant_validation"
BLIND_EXTRACTION_ORDER_VERSION = "blind-extraction-order-v1"
_SENTINEL_FEATURE_IDS = (
    "safety.prohibited_unsafe_request",
    "safety.vulnerability_disclosure",
    "safety.expected_outcome_leakage",
)
_MATCHED_REFERENCE_ROLE = {
    ArmRole.LENGTH_MATCHED_PLACEBO: ArmRole.TARGET_PATCH,
    ArmRole.LENGTH_MATCHED_SHAM_EDIT: ArmRole.TARGET_REMOVE,
    ArmRole.TASK_LENGTH_PLACEBO: ArmRole.TASK_TARGET,
    ArmRole.PRESENTATION_MATCHED_CONTROL: ArmRole.PRESENTATION_TARGET,
}


def _error(message: str = "prompt variant validation failed") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


class _HardInvalid(Exception):
    __slots__ = ("code",)

    def __init__(self, code: PreRandomizationFailureCode) -> None:
        self.code = code
        super().__init__(code.value)


def _hard(code: PreRandomizationFailureCode) -> NoReturn:
    raise _HardInvalid(code)


class VariantValidationInput(SafeValidationMixin, StrictModel):
    """Complete pre-outcome input for one arm candidate validation."""

    _safe_validation_message: ClassVar[str] = "variant validation input failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    candidate: PromptCandidate = Field(repr=False)
    source_prompt: PromptRecord = Field(repr=False)
    target: TargetSpecRecord
    target_instance: TargetInstanceRecord
    protocol: ConfirmationProtocolRecord
    protocol_instance: ConfirmationProtocolInstanceRecord
    arm: ArmSpecRecord
    source_proposal: PromptExtractionProposalRecord = Field(repr=False)
    source_graph: PromptTSGRecord = Field(repr=False)
    source_attestation: PromptRoleAttestationRecord = Field(repr=False)
    intended_patch: IntendedGraphPatchRecord | None = Field(default=None, repr=False)

    def __repr__(self) -> str:
        return "VariantValidationInput()"

    def __str__(self) -> str:
        return "VariantValidationInput()"


@dataclass(frozen=True, slots=True, repr=False)
class VariantValidationResult:
    hard_valid: bool
    failure_code: PreRandomizationFailureCode | None
    target_changed: bool | None
    semantic_compliance: bool | None
    proposal: PromptExtractionProposalRecord | None
    graph: PromptTSGRecord | None
    delta: GraphDeltaRecord | None
    variant: PromptVariantRecord | None


@dataclass(frozen=True, slots=True, repr=False)
class FrozenProtocolVariants:
    intended_patches: tuple[IntendedGraphPatchRecord, ...]
    proposals: tuple[PromptExtractionProposalRecord, ...]
    graphs: tuple[PromptTSGRecord, ...]
    deltas: tuple[GraphDeltaRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    length_matches: tuple[LengthMatchRecord, ...]


class ProtocolFreezeError(Exception):
    """Sanitized whole-block hard invalidity; never carries prompt text."""

    __slots__ = ("failed_arm_roles", "failure_codes", "protocol_instance_id")

    def __init__(
        self,
        protocol_instance_id: str,
        failed_arm_roles: tuple[ArmRole, ...],
        failure_codes: tuple[PreRandomizationFailureCode, ...],
    ) -> None:
        self.protocol_instance_id = protocol_instance_id
        self.failed_arm_roles = failed_arm_roles
        self.failure_codes = failure_codes
        super().__init__("prompt protocol failed pre-randomization validation")

    def __repr__(self) -> str:
        return "ProtocolFreezeError()"


def _snapshot_model(model: type, value: object):
    if type(value) is not model or not model_shape_is_intact(value):
        raise ValueError
    return model.model_validate(value.model_dump(mode="python", round_trip=True, warnings=False))


def _snapshot_input(value: object) -> VariantValidationInput:
    if type(value) is not VariantValidationInput or not model_shape_is_intact(value):
        raise ValueError
    return VariantValidationInput.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings=False)
    )


def _roundtrip_graph(record: PromptTSGRecord) -> PromptTSGRecord:
    graph = record_to_multidigraph(record)
    rebuilt = multidigraph_to_record(
        graph,
        prompt_id=record.prompt_id,
        task_id=record.task_id,
        task_family=record.task_family,
        cwe=record.cwe,
        extractor_backend=record.extractor_backend,
        extractor_policy_sha256=record.extractor_policy_sha256,
        proposal_id=record.proposal_id,
    )
    if rebuilt != record:
        raise ValueError
    return rebuilt


def _attestation_is_current(value: object) -> bool:
    try:
        checked = _snapshot_model(PromptRoleAttestationRecord, value)
        return checked.catalog_sha256 == PROMPT_FEATURE_CATALOG_SHA256
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def security_neutral_prompt_invariant(
    graph: nx.MultiDiGraph,
    attestation: PromptRoleAttestationRecord,
) -> bool:
    """Require all security-neutral sentinels absent and current provenance."""

    try:
        return _attestation_is_current(attestation) and all(
            feature_state(graph, feature_id) is FeatureState.ABSENT
            for feature_id in _SENTINEL_FEATURE_IDS
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def actual_feature_transitions(
    before: nx.MultiDiGraph,
    after: nx.MultiDiGraph,
) -> tuple[FeatureTransition, ...]:
    """Return the complete catalog-closed state delta in feature-ID order."""

    try:
        before_states = dict(feature_state_vector(before))
        after_states = dict(feature_state_vector(after))
        if set(before_states) != {item.feature_id for item in PROMPT_FEATURE_CATALOG} or set(
            after_states
        ) != set(before_states):
            raise ValueError
        return tuple(
            FeatureTransition(
                feature_id=feature_id,
                from_states=(before_states[feature_id],),
                to_states=(after_states[feature_id],),
            )
            for feature_id in sorted(before_states)
            if before_states[feature_id] is not after_states[feature_id]
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("prompt graph delta failed validation") from None


def canonical_changed_span_utf8_bytes(before: str, after: str) -> int:
    """Measure one canonical minimal contiguous UTF-8 edit footprint."""

    try:
        if type(before) is not str or type(after) is not str:
            raise ValueError
        left = before.encode("utf-8")
        right = after.encode("utf-8")
        prefix = 0
        while prefix < len(left) and prefix < len(right) and left[prefix] == right[prefix]:
            prefix += 1
        suffix = 0
        while (
            suffix < len(left) - prefix
            and suffix < len(right) - prefix
            and left[len(left) - 1 - suffix] == right[len(right) - 1 - suffix]
        ):
            suffix += 1
        return (len(left) - prefix - suffix) + (len(right) - prefix - suffix)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("prompt length-match metric failed validation") from None


def make_length_match_record(
    *,
    arm_protocol_id: str,
    protocol_instance_id: str,
    reference_arm_role: ArmRole,
    matched_arm_role: ArmRole,
    source_text: str,
    reference_text: str,
    matched_text: str,
) -> LengthMatchRecord:
    """Recompute and freeze one finite matched-arm length decision."""

    try:
        reference_delta = canonical_changed_span_utf8_bytes(source_text, reference_text)
        matched_delta = canonical_changed_span_utf8_bytes(source_text, matched_text)
        tolerance = max(4, (reference_delta + 19) // 20)
        if abs(reference_delta - matched_delta) > tolerance:
            raise ValueError
        return LengthMatchRecord.from_content(
            arm_protocol_id=arm_protocol_id,
            protocol_instance_id=protocol_instance_id,
            reference_arm_role=reference_arm_role,
            matched_arm_role=matched_arm_role,
            metric="canonical_changed_span_utf8_bytes_v1",
            reference_delta_bytes=reference_delta,
            matched_delta_bytes=matched_delta,
            tolerance_bytes=tolerance,
            within_tolerance=True,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("prompt length match failed validation") from None


def validate_length_match_record(
    record: LengthMatchRecord,
    *,
    source_text: str,
    reference_text: str,
    matched_text: str,
) -> None:
    """Authenticate a persisted decision against the frozen prompt bytes."""

    try:
        checked = _snapshot_model(LengthMatchRecord, record)
        expected = make_length_match_record(
            arm_protocol_id=checked.arm_protocol_id,
            protocol_instance_id=checked.protocol_instance_id,
            reference_arm_role=checked.reference_arm_role,
            matched_arm_role=checked.matched_arm_role,
            source_text=source_text,
            reference_text=reference_text,
            matched_text=matched_text,
        )
        if checked != expected:
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("prompt length-match record failed readback validation") from None


def _blind_extraction_key(
    source_prompt: PromptRecord,
    candidate: PromptCandidate,
    policy: ExtractionPolicy,
) -> tuple[str, str, str, str]:
    return (
        BLIND_EXTRACTION_ORDER_VERSION,
        source_prompt.prompt_sha256,
        hashlib.sha256(candidate.text.encode("utf-8")).hexdigest(),
        policy.policy_sha256,
    )


def _blind_candidate_commitment(candidate: PromptCandidate) -> str:
    return canonical_sha256(candidate.model_dump(mode="json", round_trip=True, warnings=False))


def blind_variant_prompt_id(
    source_prompt: PromptRecord,
    candidate: PromptCandidate,
    policy: ExtractionPolicy,
    occurrence_rank: int,
) -> str:
    """Create an opaque extractor-visible alias without arm or target coordinates."""

    if type(occurrence_rank) is not int or occurrence_rank < 0:
        raise _error("blind extraction alias failed validation")
    version, source_sha256, text_sha256, policy_sha256 = _blind_extraction_key(
        source_prompt,
        candidate,
        policy,
    )
    return "variant_prompt_" + canonical_sha256(
        {
            "schema_version": "1.0",
            "blind_order_version": version,
            "source_prompt_sha256": source_sha256,
            "candidate_text_sha256": text_sha256,
            "extractor_policy_sha256": policy_sha256,
            "occurrence_rank": occurrence_rank,
        }
    )


def blind_extractor_task_id(
    source_prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> str:
    """Hide source task identifiers from the validation extractor."""

    return "blind_task_" + canonical_sha256(
        {
            "schema_version": "1.0",
            "blind_order_version": BLIND_EXTRACTION_ORDER_VERSION,
            "source_task_id_sha256": hashlib.sha256(
                source_prompt.task_id.encode("utf-8")
            ).hexdigest(),
            "source_prompt_sha256": source_prompt.prompt_sha256,
            "extractor_policy_sha256": policy.policy_sha256,
        }
    )


def _blind_extraction_plan(
    values: tuple[VariantValidationInput, ...],
    policy: ExtractionPolicy,
    occurrence_ranks: Mapping[str, int] | None = None,
) -> tuple[tuple[VariantValidationInput, str], ...]:
    ordered = sorted(
        values,
        key=lambda item: (
            _blind_extraction_key(item.source_prompt, item.candidate, policy),
            _blind_candidate_commitment(item.candidate),
        ),
    )
    occurrences: dict[tuple[str, str, str, str], int] = {}
    seen_ranks: set[tuple[tuple[str, str, str, str], int]] = set()
    plan: list[tuple[VariantValidationInput, str]] = []
    for item in ordered:
        key = _blind_extraction_key(item.source_prompt, item.candidate, policy)
        commitment = _blind_candidate_commitment(item.candidate)
        if occurrence_ranks is None:
            rank = occurrences.get(key, 0)
            occurrences[key] = rank + 1
        else:
            rank = occurrence_ranks.get(commitment, -1)
            if type(rank) is not int or rank < 0 or (key, rank) in seen_ranks:
                raise _error("blind extraction rank failed validation")
        seen_ranks.add((key, rank))
        plan.append(
            (
                item,
                blind_variant_prompt_id(
                    item.source_prompt,
                    item.candidate,
                    policy,
                    rank,
                ),
            )
        )
    return tuple(plan)


def blind_occurrence_ranks(
    values: Sequence[VariantValidationInput],
    policy: ExtractionPolicy,
) -> dict[str, int]:
    """Assign stable global ranks without exposing candidate commitments."""

    if type(values) not in {tuple, list} or not values:
        raise _error("blind extraction rank failed validation")
    try:
        checked = tuple(_snapshot_input(item) for item in values)
        ordered = sorted(
            checked,
            key=lambda item: (
                _blind_extraction_key(item.source_prompt, item.candidate, policy),
                _blind_candidate_commitment(item.candidate),
            ),
        )
        occurrences: dict[tuple[str, str, str, str], int] = {}
        result: dict[str, int] = {}
        for item in ordered:
            key = _blind_extraction_key(item.source_prompt, item.candidate, policy)
            commitment = _blind_candidate_commitment(item.candidate)
            if commitment in result:
                raise ValueError
            rank = occurrences.get(key, 0)
            occurrences[key] = rank + 1
            result[commitment] = rank
        return result
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("blind extraction rank failed validation") from None


def _validate_source_and_bindings(
    item: VariantValidationInput,
    policy: ExtractionPolicy,
    expected_executor_policy_sha256: str,
) -> tuple[
    PromptRecord,
    PromptExtractionProposalRecord,
    PromptTSGRecord,
    PromptCandidate,
]:
    try:
        source = _snapshot_model(PromptRecord, item.source_prompt)
        target = _snapshot_model(TargetSpecRecord, item.target)
        target_instance = _snapshot_model(TargetInstanceRecord, item.target_instance)
        protocol = _snapshot_model(ConfirmationProtocolRecord, item.protocol)
        protocol_instance = _snapshot_model(
            ConfirmationProtocolInstanceRecord,
            item.protocol_instance,
        )
        arm = _snapshot_model(ArmSpecRecord, item.arm)
        candidate = _snapshot_model(PromptCandidate, item.candidate)
        attestation = _snapshot_model(PromptRoleAttestationRecord, item.source_attestation)
        source_proposal = validate_proposal(
            _snapshot_model(PromptExtractionProposalRecord, item.source_proposal),
            source,
        )
        source_graph = _snapshot_model(PromptTSGRecord, item.source_graph)
        if (
            type(policy) is not ExtractionPolicy
            or type(expected_executor_policy_sha256) is not str
            or len(expected_executor_policy_sha256) != 64
            or source.split != "confirm"
            or source_proposal.backend is not policy.backend
            or source_proposal.policy_sha256 != policy.policy_sha256
            or source_proposal.catalog_sha256 != policy.catalog_sha256
            or policy.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or build_prompt_tsg(source_proposal, source) != source_graph
            or _roundtrip_graph(source_graph) != source_graph
            or source_graph.prompt_id != source.prompt_id
            or source_graph.task_id != source.task_id
            or source_graph.proposal_id != source_proposal.proposal_id
            or target_instance.target_spec_id != target.target_spec_id
            or target_instance.task_id != source.task_id
            or target_instance.source_prompt_id != source.prompt_id
            or target_instance.source_prompt_sha256 != source.prompt_sha256
            or protocol.target_spec_id != target.target_spec_id
            or protocol.hypothesis_id != target.hypothesis_id
            or protocol_instance.arm_protocol_id != protocol.arm_protocol_id
            or protocol_instance.target_instance_id != target_instance.target_instance_id
            or protocol_instance.task_id != source.task_id
            or protocol_instance.source_prompt_id != source.prompt_id
            or protocol_instance.source_prompt_sha256 != source.prompt_sha256
            or tuple(value for value in protocol.arms if value.role is arm.role) != (arm,)
            or candidate.source_prompt_id != source.prompt_id
            or candidate.target_spec_id != target.target_spec_id
            or candidate.target_instance_id != target_instance.target_instance_id
            or candidate.arm_protocol_id != protocol.arm_protocol_id
            or candidate.protocol_instance_id != protocol_instance.protocol_instance_id
            or candidate.arm_role is not arm.role
            or attestation.prompt_id != source.prompt_id
            or attestation.task_id != source.task_id
            or attestation.prompt_sha256 != source.prompt_sha256
            or attestation.prompt_role is not source.prompt_role
            or not _attestation_is_current(attestation)
        ):
            raise ValueError
        if candidate.executor_policy_sha256 != expected_executor_policy_sha256:
            _hard(PreRandomizationFailureCode.EXECUTOR_POLICY_MISMATCH)
        patch = item.intended_patch
        if candidate.mode is InterventionMode.GRAPH_NATIVE:
            checked_patch = _snapshot_model(IntendedGraphPatchRecord, patch)
            if (
                candidate.intended_patch_id != checked_patch.patch_id
                or checked_patch.target_spec_id != target.target_spec_id
                or checked_patch.target_instance_id != target_instance.target_instance_id
                or checked_patch.arm_protocol_id != protocol.arm_protocol_id
                or checked_patch.protocol_instance_id != protocol_instance.protocol_instance_id
                or checked_patch.arm_role is not arm.role
                or checked_patch.before_graph_sha256 != source_graph.graph_sha256
                or checked_patch.allowed_delta_sha256 != allowed_delta_sha256(arm.allowed_delta)
                or checked_patch.intended_transitions != arm.allowed_delta.allowed_transitions
            ):
                raise ValueError
        elif patch is not None or candidate.intended_patch_id is not None:
            raise ValueError
        return source, source_proposal, source_graph, candidate
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except _HardInvalid:
        raise
    except Exception:
        _hard(PreRandomizationFailureCode.SOURCE_PROVENANCE_MISMATCH)


def _validate_actual_delta(
    *,
    before: nx.MultiDiGraph,
    after: nx.MultiDiGraph,
    target: TargetSpecRecord,
    arm: ArmSpecRecord,
    transitions: tuple[FeatureTransition, ...],
) -> tuple[bool | None, bool | None, tuple[str, ...]]:
    allowed = {item.feature_id: item for item in arm.allowed_delta.allowed_transitions}
    before_states = dict(feature_state_vector(before))
    after_states = dict(feature_state_vector(after))
    fixed_families = set(arm.allowed_delta.fixed_families)
    fixed_ids = set(arm.allowed_delta.fixed_feature_ids)
    for feature_id, old in before_states.items():
        new = after_states[feature_id]
        spec = prompt_feature_spec(feature_id)
        fixed = spec.feature_family in fixed_families or feature_id in fixed_ids
        if fixed and (old is FeatureState.UNRESOLVED or new is FeatureState.UNRESOLVED):
            _hard(PreRandomizationFailureCode.FIXED_PROJECTION_UNRESOLVED)
        if fixed and old is not new:
            _hard(PreRandomizationFailureCode.ALLOWED_DELTA_VIOLATION)
    for transition in transitions:
        permitted = allowed.get(transition.feature_id)
        if permitted is None:
            _hard(PreRandomizationFailureCode.ALLOWED_DELTA_VIOLATION)
        old = transition.from_states[0]
        new = transition.to_states[0]
        if old not in permitted.from_states:
            _hard(PreRandomizationFailureCode.ALLOWED_DELTA_VIOLATION)
        if new not in permitted.to_states and new is not FeatureState.UNRESOLVED:
            _hard(PreRandomizationFailureCode.ALLOWED_DELTA_VIOLATION)

    checks: list[bool | None] = []
    for transition in arm.allowed_delta.allowed_transitions:
        old = before_states[transition.feature_id]
        new = after_states[transition.feature_id]
        if new is FeatureState.UNRESOLVED:
            checks.append(None)
        else:
            checks.append(old in transition.from_states and new in transition.to_states)
    if any(value is False for value in checks):
        semantic_compliance: bool | None = False
    elif any(value is None for value in checks):
        semantic_compliance = None
    else:
        semantic_compliance = True

    target_transition = next(
        (
            transition
            for transition in arm.allowed_delta.allowed_transitions
            if transition.feature_id == target.feature_id
        ),
        None,
    )
    if target_transition is None:
        target_changed: bool | None = False
    else:
        old = before_states[target.feature_id]
        new = after_states[target.feature_id]
        target_changed = (
            None
            if new is FeatureState.UNRESOLVED
            else old in target_transition.from_states and new in target_transition.to_states
        )
    permissible = tuple(
        sorted(
            transition.feature_id
            for transition in transitions
            if transition.feature_id in allowed and transition.feature_id != target.feature_id
        )
    )
    return target_changed, semantic_compliance, permissible


def validate_graph_delta_record(
    record: GraphDeltaRecord,
    *,
    before_graph: PromptTSGRecord,
    after_graph: PromptTSGRecord,
    target: TargetSpecRecord,
    arm: ArmSpecRecord,
    expected_length_match_id: str | None,
) -> GraphDeltaRecord:
    """Recompute one frozen delta from its exact before/after graph pair."""

    try:
        checked = _snapshot_model(GraphDeltaRecord, record)
        checked_before = _snapshot_model(PromptTSGRecord, before_graph)
        checked_after = _snapshot_model(PromptTSGRecord, after_graph)
        checked_target = _snapshot_model(TargetSpecRecord, target)
        checked_arm = _snapshot_model(ArmSpecRecord, arm)
        before_live = record_to_multidigraph(checked_before)
        after_live = record_to_multidigraph(checked_after)
        transitions = actual_feature_transitions(before_live, after_live)
        target_changed, semantic_compliance, permissible = _validate_actual_delta(
            before=before_live,
            after=after_live,
            target=checked_target,
            arm=checked_arm,
            transitions=transitions,
        )
        expected = GraphDeltaRecord.from_content(
            target_spec_id=checked.target_spec_id,
            target_instance_id=checked.target_instance_id,
            arm_protocol_id=checked.arm_protocol_id,
            protocol_instance_id=checked.protocol_instance_id,
            arm_role=checked.arm_role,
            before_graph_sha256=checked_before.graph_sha256,
            after_graph_sha256=checked_after.graph_sha256,
            actual_transitions=transitions,
            target_changed=target_changed,
            semantic_compliance=semantic_compliance,
            permissible_non_target_drift=permissible,
            length_match_id=expected_length_match_id,
        )
        if checked != expected:
            raise ValueError
        return checked
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("graph delta record failed recomputation") from None


def validate_variant(
    *,
    candidate: PromptCandidate,
    source_prompt: PromptRecord,
    target: TargetSpecRecord,
    target_instance: TargetInstanceRecord,
    protocol: ConfirmationProtocolRecord,
    protocol_instance: ConfirmationProtocolInstanceRecord,
    arm: ArmSpecRecord,
    source_proposal: PromptExtractionProposalRecord,
    source_graph: PromptTSGRecord,
    source_attestation: PromptRoleAttestationRecord,
    extractor: PromptExtractor,
    extraction_policy: ExtractionPolicy,
    expected_executor_policy_sha256: str,
    intended_patch: IntendedGraphPatchRecord | None = None,
    length_match: LengthMatchRecord | None = None,
) -> VariantValidationResult:
    """Blindly re-extract one candidate and freeze it only after hard gates pass."""

    try:
        item = VariantValidationInput(
            candidate=candidate,
            source_prompt=source_prompt,
            target=target,
            target_instance=target_instance,
            protocol=protocol,
            protocol_instance=protocol_instance,
            arm=arm,
            source_proposal=source_proposal,
            source_graph=source_graph,
            source_attestation=source_attestation,
            intended_patch=intended_patch,
        )
        return _validate_variant_input(
            item,
            extractor=extractor,
            extraction_policy=extraction_policy,
            expected_executor_policy_sha256=expected_executor_policy_sha256,
            length_match=length_match,
            variant_prompt_id=blind_variant_prompt_id(
                item.source_prompt,
                item.candidate,
                extraction_policy,
                0,
            ),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except _HardInvalid as failure:
        return VariantValidationResult(
            hard_valid=False,
            failure_code=failure.code,
            target_changed=None,
            semantic_compliance=None,
            proposal=None,
            graph=None,
            delta=None,
            variant=None,
        )
    except Exception:
        return VariantValidationResult(
            hard_valid=False,
            failure_code=PreRandomizationFailureCode.SOURCE_PROVENANCE_MISMATCH,
            target_changed=None,
            semantic_compliance=None,
            proposal=None,
            graph=None,
            delta=None,
            variant=None,
        )


def _validate_variant_input(
    item: VariantValidationInput,
    *,
    extractor: PromptExtractor,
    extraction_policy: ExtractionPolicy,
    expected_executor_policy_sha256: str,
    length_match: LengthMatchRecord | None,
    variant_prompt_id: str,
) -> VariantValidationResult:
    source, _source_proposal, source_graph, candidate = _validate_source_and_bindings(
        item,
        extraction_policy,
        expected_executor_policy_sha256,
    )
    matched_reference = _MATCHED_REFERENCE_ROLE.get(item.arm.role)
    if (matched_reference is None) != (length_match is None):
        _hard(PreRandomizationFailureCode.LENGTH_MISMATCH)
    checked_length: LengthMatchRecord | None = None
    if length_match is not None:
        try:
            checked_length = _snapshot_model(LengthMatchRecord, length_match)
            if (
                checked_length.arm_protocol_id != item.protocol.arm_protocol_id
                or checked_length.protocol_instance_id
                != item.protocol_instance.protocol_instance_id
                or checked_length.reference_arm_role is not matched_reference
                or checked_length.matched_arm_role is not item.arm.role
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            _hard(PreRandomizationFailureCode.LENGTH_MISMATCH)

    variant_prompt = PromptRecord.model_validate(
        {
            **source.model_dump(mode="python"),
            "prompt_id": variant_prompt_id,
            "task_id": blind_extractor_task_id(source, extraction_policy),
            "prompt": candidate.text,
        }
    )
    try:
        proposal = extractor.extract(variant_prompt, extraction_policy)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _hard(PreRandomizationFailureCode.EXTRACTION_FAILED)
    try:
        proposal = validate_proposal(
            _snapshot_model(PromptExtractionProposalRecord, proposal),
            variant_prompt,
        )
        if (
            proposal.backend is not extraction_policy.backend
            or proposal.policy_sha256 != extraction_policy.policy_sha256
            or proposal.catalog_sha256 != extraction_policy.catalog_sha256
        ):
            _hard(PreRandomizationFailureCode.EXTRACTOR_POLICY_MISMATCH)
    except _HardInvalid:
        raise
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _hard(PreRandomizationFailureCode.EXTRACTOR_POLICY_MISMATCH)
    try:
        graph = build_prompt_tsg(proposal, variant_prompt)
        _roundtrip_graph(graph)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _hard(PreRandomizationFailureCode.GRAPH_ROUNDTRIP_FAILED)
    before_live = record_to_multidigraph(source_graph)
    after_live = record_to_multidigraph(graph)
    if not security_neutral_prompt_invariant(after_live, item.source_attestation):
        _hard(PreRandomizationFailureCode.SECURITY_NEUTRALITY_VIOLATION)
    transitions = actual_feature_transitions(before_live, after_live)
    target_changed, semantic_compliance, permissible = _validate_actual_delta(
        before=before_live,
        after=after_live,
        target=item.target,
        arm=item.arm,
        transitions=transitions,
    )
    length_match_id = checked_length.length_match_id if checked_length is not None else None
    delta = GraphDeltaRecord.from_content(
        target_spec_id=item.target.target_spec_id,
        target_instance_id=item.target_instance.target_instance_id,
        arm_protocol_id=item.protocol.arm_protocol_id,
        protocol_instance_id=item.protocol_instance.protocol_instance_id,
        arm_role=item.arm.role,
        before_graph_sha256=source_graph.graph_sha256,
        after_graph_sha256=graph.graph_sha256,
        actual_transitions=transitions,
        target_changed=target_changed,
        semantic_compliance=semantic_compliance,
        permissible_non_target_drift=permissible,
        length_match_id=length_match_id,
    )
    variant = PromptVariantRecord.from_content(
        task_id=source.task_id,
        source_prompt_id=source.prompt_id,
        variant_prompt_id=variant_prompt.prompt_id,
        hypothesis_id=item.target.hypothesis_id,
        target_spec_id=item.target.target_spec_id,
        target_instance_id=item.target_instance.target_instance_id,
        arm_protocol_id=item.protocol.arm_protocol_id,
        protocol_instance_id=item.protocol_instance.protocol_instance_id,
        arm_role=item.arm.role,
        prompt_sha256=variant_prompt.prompt_sha256,
        prompt_text=variant_prompt.prompt,
        proposal_id=proposal.proposal_id,
        graph_id=graph.graph_id,
        delta_id=delta.delta_id,
        executor_policy_sha256=candidate.executor_policy_sha256,
        extractor_policy_sha256=proposal.policy_sha256,
        length_match_id=length_match_id,
    )
    return VariantValidationResult(
        hard_valid=True,
        failure_code=None,
        target_changed=target_changed,
        semantic_compliance=semantic_compliance,
        proposal=proposal,
        graph=graph,
        delta=delta,
        variant=variant,
    )


def _coverage_failure(values: Sequence[VariantValidationInput]) -> ProtocolFreezeError:
    protocol_instance_id = (
        values[0].protocol_instance.protocol_instance_id
        if values and type(values[0]) is VariantValidationInput
        else "protocol_instance_" + "0" * 64
    )
    roles = tuple(
        sorted(
            {
                item.arm.role
                for item in values
                if type(item) is VariantValidationInput and type(item.arm.role) is ArmRole
            },
            key=lambda item: item.value,
        )
    ) or (ArmRole.TARGET_PATCH,)
    return ProtocolFreezeError(
        protocol_instance_id,
        roles,
        tuple(PreRandomizationFailureCode.PROTOCOL_COVERAGE_INVALID for _ in roles),
    )


def freeze_protocol_variants(
    values: Sequence[VariantValidationInput],
    *,
    extractor: PromptExtractor,
    extraction_policy: ExtractionPolicy,
    expected_executor_policy_sha256: str,
    blind_rank_by_candidate_sha256: Mapping[str, int] | None = None,
) -> FrozenProtocolVariants:
    """Freeze all arms or reject the complete task-level protocol block."""

    if type(values) not in {tuple, list} or not values:
        raise _coverage_failure(())
    try:
        checked = tuple(_snapshot_input(item) for item in values)
        first = checked[0]
        roles = tuple(item.arm.role for item in checked)
        expected_roles = first.protocol.arm_roles
        if (
            len(checked) != len(expected_roles)
            or len(roles) != len(set(roles))
            or set(roles) != set(expected_roles)
            or any(
                item.protocol != first.protocol
                or item.protocol_instance != first.protocol_instance
                or item.target != first.target
                or item.target_instance != first.target_instance
                or item.source_prompt != first.source_prompt
                or item.source_proposal != first.source_proposal
                or item.source_graph != first.source_graph
                or item.source_attestation != first.source_attestation
                for item in checked
            )
        ):
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _coverage_failure(tuple(values)) from None

    by_role = {item.arm.role: item for item in checked}
    lengths: dict[ArmRole, LengthMatchRecord] = {}
    length_failures: list[tuple[ArmRole, PreRandomizationFailureCode]] = []
    for matched_role, reference_role in _MATCHED_REFERENCE_ROLE.items():
        matched = by_role.get(matched_role)
        if matched is None:
            continue
        reference = by_role.get(reference_role)
        if reference is None:
            length_failures.append(
                (matched_role, PreRandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
            )
            continue
        try:
            lengths[matched_role] = make_length_match_record(
                arm_protocol_id=first.protocol.arm_protocol_id,
                protocol_instance_id=first.protocol_instance.protocol_instance_id,
                reference_arm_role=reference_role,
                matched_arm_role=matched_role,
                source_text=first.source_prompt.prompt,
                reference_text=reference.candidate.text,
                matched_text=matched.candidate.text,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            length_failures.append((matched_role, PreRandomizationFailureCode.LENGTH_MISMATCH))
    if length_failures:
        raise ProtocolFreezeError(
            first.protocol_instance.protocol_instance_id,
            tuple(item[0] for item in length_failures),
            tuple(item[1] for item in length_failures),
        )

    results: list[tuple[VariantValidationInput, VariantValidationResult]] = []
    failures: list[tuple[ArmRole, PreRandomizationFailureCode]] = []
    blind_plan = _blind_extraction_plan(
        checked,
        extraction_policy,
        blind_rank_by_candidate_sha256,
    )
    for item, variant_prompt_id in blind_plan:
        try:
            result = _validate_variant_input(
                item,
                extractor=extractor,
                extraction_policy=extraction_policy,
                expected_executor_policy_sha256=expected_executor_policy_sha256,
                length_match=lengths.get(item.arm.role),
                variant_prompt_id=variant_prompt_id,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except _HardInvalid as failure:
            result = VariantValidationResult(
                hard_valid=False,
                failure_code=failure.code,
                target_changed=None,
                semantic_compliance=None,
                proposal=None,
                graph=None,
                delta=None,
                variant=None,
            )
        results.append((item, result))
        if not result.hard_valid or result.failure_code is not None:
            failures.append(
                (
                    item.arm.role,
                    result.failure_code or PreRandomizationFailureCode.EXTRACTION_FAILED,
                )
            )
    if failures:
        role_order = {role: index for index, role in enumerate(first.protocol.arm_roles)}
        failures.sort(key=lambda item: role_order[item[0]])
        raise ProtocolFreezeError(
            first.protocol_instance.protocol_instance_id,
            tuple(item[0] for item in failures),
            tuple(item[1] for item in failures),
        )

    proposals = tuple(result.proposal for _item, result in results)
    graphs = tuple(result.graph for _item, result in results)
    deltas = tuple(result.delta for _item, result in results)
    variants = tuple(result.variant for _item, result in results)
    if any(item is None for item in (*proposals, *graphs, *deltas, *variants)):
        raise _coverage_failure(checked)
    for matched_role, record in lengths.items():
        validate_length_match_record(
            record,
            source_text=first.source_prompt.prompt,
            reference_text=by_role[record.reference_arm_role].candidate.text,
            matched_text=by_role[matched_role].candidate.text,
        )
    return FrozenProtocolVariants(
        intended_patches=tuple(
            sorted(
                (item.intended_patch for item in checked if item.intended_patch is not None),
                key=lambda item: item.patch_id,
            )
        ),
        proposals=tuple(sorted(proposals, key=lambda item: item.proposal_id)),  # type: ignore[arg-type]
        graphs=tuple(sorted(graphs, key=lambda item: item.graph_id)),  # type: ignore[arg-type]
        deltas=tuple(sorted(deltas, key=lambda item: item.delta_id)),  # type: ignore[arg-type]
        variants=tuple(sorted(variants, key=lambda item: item.variant_id)),  # type: ignore[arg-type]
        length_matches=tuple(sorted(lengths.values(), key=lambda item: item.length_match_id)),
    )


__all__ = [
    "FrozenProtocolVariants",
    "ProtocolFreezeError",
    "VariantValidationInput",
    "VariantValidationResult",
    "actual_feature_transitions",
    "BLIND_EXTRACTION_ORDER_VERSION",
    "blind_extractor_task_id",
    "blind_occurrence_ranks",
    "blind_variant_prompt_id",
    "canonical_changed_span_utf8_bytes",
    "freeze_protocol_variants",
    "make_length_match_record",
    "security_neutral_prompt_invariant",
    "validate_length_match_record",
    "validate_graph_delta_record",
    "validate_variant",
]

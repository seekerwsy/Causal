"""Replayable pre-generation invariant evidence for v2 Prompt variants.

The population contracts freeze exact arm texts, but a text plus an opaque
``validation_evidence_sha256`` is not proof that the text survived the
pre-randomization Prompt-TSG checks.  This module closes that edge.  Each
receipt embeds the source query evidence and the exact blind extraction
artifacts, then replays the authoritative v1 ``AllowedDelta`` validator.  The
manifest proves that every retained task has every realization and every arm;
an incomplete realization can only exclude the whole task upstream.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.extractors.base import ExtractionPolicy, PromptExtractor
from secaware.intervention.arm_catalog import materialize_safety_arm_specs
from secaware.intervention.variant_validation import (
    blind_variant_prompt_record_from_text,
    make_length_match_record,
    recompute_graph_delta_record,
    validate_graph_delta_record,
    validate_length_match_record,
)
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiments import (
    ArmRole,
    ArmSpecRecord,
    ConfirmationProtocolInstanceRecord,
    FeatureFamily,
    GraphDeltaRecord,
    LengthMatchRecord,
    PromptVariantRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.features import FeatureState
from secaware.schema.intervention_v2 import InterventionBridgeRecordV2
from secaware.schema.policy_v2 import (
    ExpectedDirection,
    RealizationSpecRecord,
    SemanticTaskClusterMembershipRecord,
    TaskArmVariantBinding,
    TaskPolicySupportRecord,
    TaskRealizationBundleRecord,
)
from secaware.schema.population_v2 import PopulationFreezeManifestV2
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.query_evidence_v2 import (
    QueryEvidenceManifestV2,
    QueryEvidenceTaskRecordV2,
)
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.context_queries_v2 import ContextQueryEvaluation, evaluate_context_query
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
from secaware.tsg.proposal_validator import validate_proposal

VARIANT_EVIDENCE_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_RECEIPT_ID_PATTERN = r"^variant_invariant_receipt_v2_[0-9a-f]{64}$"
_MANIFEST_ID_PATTERN = r"^variant_evidence_manifest_v2_[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,1023}$")

_MATCHED_REFERENCE_ROLE = {
    ArmRole.LENGTH_MATCHED_PLACEBO: ArmRole.TARGET_PATCH,
    ArmRole.LENGTH_MATCHED_SHAM_EDIT: ArmRole.TARGET_REMOVE,
}


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _snapshot_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_arrays(item) for item in value)
    return value


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


class _VariantEvidenceV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "variant evidence v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = VARIANT_EVIDENCE_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedVariantEvidenceV2(_VariantEvidenceV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": VARIANT_EVIDENCE_V2_SCHEMA_VERSION, **content}
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public evidence boundary
            content.clear()
            if payload is not None:
                payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class ContextPathSignatureV2(_VariantEvidenceV2Contract):
    """Identifier-free typed path signature used to compare one Cq replay."""

    node_types: tuple[str, ...] = Field(min_length=1)
    node_labels: tuple[str, ...] = Field(min_length=1)
    edge_types: tuple[str, ...]

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        if len(self.node_types) != len(self.node_labels) or len(self.edge_types) + 1 != len(
            self.node_types
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ContextQuerySemanticProjectionV2(_VariantEvidenceV2Contract):
    """The Cq semantics after removing prompt-content identifiers and spans."""

    context_query_id: str
    state: str
    applicable: bool
    task_feature_state: FeatureState | None
    required_roles_resolved: bool | None
    bounded_matching_complete: bool
    paths: tuple[ContextPathSignatureV2, ...]

    @field_validator("task_feature_state", mode="before")
    @classmethod
    def parse_feature_state(cls, value: object) -> object:
        if value is None or type(value) is FeatureState:
            return value
        if type(value) is str:
            return next((item for item in FeatureState if item.value == value), value)
        return value

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if not _valid_identifier(self.context_query_id) or not _valid_identifier(self.state):
            raise ValueError(self._safe_validation_message)
        return self


def _context_projection(
    graph: PromptTSGRecord,
    evaluation: ContextQueryEvaluation,
) -> ContextQuerySemanticProjectionV2:
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}
    definition = evaluation.definition
    task_states = tuple(
        FeatureState(str(item.attributes["feature_state"]))
        for item in graph.nodes
        if item.attributes.get("feature_id") == definition.task_feature_id
    )
    task_state = task_states[0] if len(task_states) == 1 else None
    paths = tuple(
        sorted(
            (
                ContextPathSignatureV2(
                    node_types=tuple(nodes[node_id].node_type.value for node_id in match.node_path),
                    node_labels=tuple(nodes[node_id].label for node_id in match.node_path),
                    edge_types=tuple(edges[edge_id].edge_type.value for edge_id in match.edge_path),
                )
                for match in evaluation.matches
            ),
            key=lambda item: (item.node_types, item.node_labels, item.edge_types),
        )
    )
    return ContextQuerySemanticProjectionV2(
        context_query_id=evaluation.spec.context_query_id,
        state=evaluation.result.state.value,
        applicable=evaluation.result.applicable,
        task_feature_state=task_state,
        required_roles_resolved=evaluation.result.required_roles_resolved,
        bounded_matching_complete=evaluation.result.bounded_matching_complete,
        paths=paths,
    )


def _legacy_target(bridge: InterventionBridgeRecordV2) -> TargetSpecRecord:
    hypothesis = bridge.frozen_hypothesis
    direction = hypothesis.expected_direction
    if direction not in {ExpectedDirection.POSITIVE, ExpectedDirection.NEGATIVE}:
        raise ValueError
    return TargetSpecRecord.from_content(
        hypothesis_id=hypothesis.hypothesis_id,
        frozen_hypothesis_sha256=hypothesis.semantic_sha256,
        feature_family=FeatureFamily.SAFETY_CONTROL,
        feature_id=hypothesis.feature_id,
        operation=hypothesis.operation,
        hypothesis_outcome_variable_id="y.cwe_security",
        hypothesis_outcome_estimand_id="y_cwe_secure",
        expected_hypothesis_contrast_sign=direction.value,
    )


def _target_instance(*, source: PromptRecord, target: TargetSpecRecord) -> TargetInstanceRecord:
    return TargetInstanceRecord.from_content(
        target_spec_id=target.target_spec_id,
        task_id=source.task_id,
        source_prompt_id=source.prompt_id,
        source_prompt_sha256=source.prompt_sha256,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
        source_prompt_role=source.prompt_role,
        counterpart_required=False,
    )


def _protocol_instance(
    *,
    source: PromptRecord,
    target_instance: TargetInstanceRecord,
    bridge: InterventionBridgeRecordV2,
) -> ConfirmationProtocolInstanceRecord:
    return ConfirmationProtocolInstanceRecord.from_content(
        arm_protocol_id=bridge.arm_protocol.arm_protocol_id,
        target_instance_id=target_instance.target_instance_id,
        task_id=source.task_id,
        source_prompt_id=source.prompt_id,
        source_prompt_sha256=source.prompt_sha256,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
    )


def _variant_membership(
    source: SemanticTaskClusterMembershipRecord,
    variant_prompt: PromptRecord,
) -> SemanticTaskClusterMembershipRecord:
    return SemanticTaskClusterMembershipRecord.from_content(
        semantic_task_cluster_id=source.semantic_task_cluster_id,
        task_instance_id=variant_prompt.task_id,
        split=source.split,
        cwe=source.cwe,
        task_archetype=source.task_archetype,
        source_task_sha256=source.source_task_sha256,
        clustering_policy_sha256=source.clustering_policy_sha256,
        adjudication_sha256=source.adjudication_sha256,
    )


def _arm_spec(bridge: InterventionBridgeRecordV2, arm_role: ArmRole) -> ArmSpecRecord:
    matches = tuple(
        item
        for item in materialize_safety_arm_specs(
            bridge.target_spec.feature_id, bridge.target_spec.operation
        )
        if item.role is arm_role
    )
    if len(matches) != 1:
        raise ValueError
    return matches[0]


class ArmVariantInvariantReceiptV2(_ContentAddressedVariantEvidenceV2):
    """Exact replayable evidence for one ``(task, h, r, arm)`` variant."""

    _id_field = "variant_invariant_receipt_id"
    _id_prefix = "variant_invariant_receipt_v2_"

    variant_invariant_receipt_id: str = Field(pattern=_RECEIPT_ID_PATTERN)
    source_query_evidence: QueryEvidenceTaskRecordV2
    intervention_bridge: InterventionBridgeRecordV2
    realization: RealizationSpecRecord
    arm_role: ArmRole
    allowed_arm: ArmSpecRecord
    extractor_max_response_chars: StrictInt = Field(ge=1, le=16_777_216)
    variant_prompt: PromptRecord = Field(repr=False)
    extraction_proposal: PromptExtractionProposalRecord = Field(repr=False)
    prompt_tsg: PromptTSGRecord = Field(repr=False)
    variant_membership: SemanticTaskClusterMembershipRecord
    source_context_projection: ContextQuerySemanticProjectionV2
    variant_context_projection: ContextQuerySemanticProjectionV2
    legacy_target: TargetSpecRecord
    target_instance: TargetInstanceRecord
    protocol_instance: ConfirmationProtocolInstanceRecord
    length_match: LengthMatchRecord | None
    length_match_reference_prompt_text: str | None = Field(default=None, repr=False)
    graph_delta: GraphDeltaRecord
    prompt_variant: PromptVariantRecord = Field(repr=False)
    hard_validation_passed: Literal[True]
    target_changed_is_diagnostic_only: Literal[True]
    semantic_validity_is_diagnostic_only: Literal[True]
    frozen_before_generation: Literal[True]

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        if type(value) is ArmRole:
            return value
        if type(value) is str:
            return next((item for item in ArmRole if item.value == value), value)
        return value

    @property
    def semantic_sha256(self) -> str:
        return self.variant_invariant_receipt_id.removeprefix("variant_invariant_receipt_v2_")

    @classmethod
    def from_variant_text(
        cls,
        *,
        source_query_evidence: QueryEvidenceTaskRecordV2,
        intervention_bridge: InterventionBridgeRecordV2,
        realization: RealizationSpecRecord,
        arm_role: ArmRole,
        prompt_text: str,
        extractor: PromptExtractor,
        extractor_max_response_chars: int = 262_144,
        length_match_reference_prompt_text: str | None = None,
    ) -> Self:
        try:
            source_evidence = QueryEvidenceTaskRecordV2.model_validate(
                source_query_evidence, strict=True
            )
            bridge = InterventionBridgeRecordV2.model_validate(intervention_bridge, strict=True)
            checked_realization = RealizationSpecRecord.model_validate(realization, strict=True)
            source = source_evidence.natural_prompt.to_prompt_record()
            policy = ExtractionPolicy(
                backend=source_evidence.extraction_proposal.backend,
                policy_sha256=bridge.realization_policy.extractor_policy_sha256,
                catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
                max_response_chars=extractor_max_response_chars,
            )
            variant_prompt = blind_variant_prompt_record_from_text(source, prompt_text, policy)
            proposal = extractor.extract(variant_prompt, policy)
            graph = build_prompt_tsg(proposal, variant_prompt)
            target = _legacy_target(bridge)
            target_instance = _target_instance(source=source, target=target)
            protocol_instance = _protocol_instance(
                source=source, target_instance=target_instance, bridge=bridge
            )
            arm = _arm_spec(bridge, arm_role)
            reference_role = _MATCHED_REFERENCE_ROLE.get(arm_role)
            if reference_role is None:
                if length_match_reference_prompt_text is not None:
                    raise ValueError
                length_match = None
            else:
                if length_match_reference_prompt_text is None:
                    raise ValueError
                length_match = make_length_match_record(
                    arm_protocol_id=bridge.arm_protocol.arm_protocol_id,
                    protocol_instance_id=protocol_instance.protocol_instance_id,
                    reference_arm_role=reference_role,
                    matched_arm_role=arm_role,
                    source_text=source.prompt,
                    reference_text=length_match_reference_prompt_text,
                    matched_text=prompt_text,
                )
            delta = recompute_graph_delta_record(
                before_graph=source_evidence.prompt_tsg,
                after_graph=graph,
                target=target,
                arm=arm,
                target_instance_id=target_instance.target_instance_id,
                arm_protocol_id=bridge.arm_protocol.arm_protocol_id,
                protocol_instance_id=protocol_instance.protocol_instance_id,
                expected_length_match_id=(
                    None if length_match is None else length_match.length_match_id
                ),
            )
            variant = PromptVariantRecord.from_content(
                task_id=source.task_id,
                source_prompt_id=source.prompt_id,
                language=source.language,
                variant_prompt_id=variant_prompt.prompt_id,
                hypothesis_id=bridge.frozen_hypothesis.hypothesis_id,
                target_spec_id=target.target_spec_id,
                target_instance_id=target_instance.target_instance_id,
                arm_protocol_id=bridge.arm_protocol.arm_protocol_id,
                protocol_instance_id=protocol_instance.protocol_instance_id,
                arm_role=arm_role,
                prompt_sha256=variant_prompt.prompt_sha256,
                prompt_text=prompt_text,
                proposal_id=proposal.proposal_id,
                graph_id=graph.graph_id,
                delta_id=delta.delta_id,
                executor_policy_sha256=next(
                    item.template_or_execution_policy_sha256
                    for item in checked_realization.arms
                    if item.arm_role is arm_role
                ),
                extractor_policy_sha256=policy.policy_sha256,
                length_match_id=(None if length_match is None else length_match.length_match_id),
            )
            source_evaluation = evaluate_context_query(
                source_evidence.prompt_tsg,
                bridge.context_query.query_name,
                semantic_membership=source_evidence.membership,
            )
            membership = _variant_membership(source_evidence.membership, variant_prompt)
            variant_evaluation = evaluate_context_query(
                graph,
                bridge.context_query.query_name,
                semantic_membership=membership,
            )
            return cls.from_content(
                source_query_evidence=source_evidence,
                intervention_bridge=bridge,
                realization=checked_realization,
                arm_role=arm_role,
                allowed_arm=arm,
                extractor_max_response_chars=extractor_max_response_chars,
                variant_prompt=variant_prompt,
                extraction_proposal=proposal,
                prompt_tsg=graph,
                variant_membership=membership,
                source_context_projection=_context_projection(
                    source_evidence.prompt_tsg, source_evaluation
                ),
                variant_context_projection=_context_projection(graph, variant_evaluation),
                legacy_target=target,
                target_instance=target_instance,
                protocol_instance=protocol_instance,
                length_match=length_match,
                length_match_reference_prompt_text=length_match_reference_prompt_text,
                graph_delta=delta,
                prompt_variant=variant,
                hard_validation_passed=True,
                target_changed_is_diagnostic_only=True,
                semantic_validity_is_diagnostic_only=True,
                frozen_before_generation=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize Prompt-bearing validation failures
            raise cls._safe_error() from None

    def to_task_arm_variant_binding(self) -> TaskArmVariantBinding:
        return TaskArmVariantBinding.from_text(
            arm_role=self.arm_role,
            prompt_text=self.prompt_variant.prompt_text,
            validation_evidence_sha256=self.semantic_sha256,
        )

    @model_validator(mode="after")
    def validate_replay(self) -> Self:
        try:
            source_evidence = QueryEvidenceTaskRecordV2.model_validate(
                self.source_query_evidence, strict=True
            )
            bridge = InterventionBridgeRecordV2.model_validate(
                self.intervention_bridge, strict=True
            )
            realization = RealizationSpecRecord.model_validate(self.realization, strict=True)
            source = source_evidence.natural_prompt.to_prompt_record()
            if (
                not source_evidence.eligibility.eligible
                or source_evidence.context_query != bridge.context_query
                or source_evidence.actionable_feature != bridge.actionable_feature
                or source_evidence.eligibility.operation is not bridge.target_spec.operation
                or realization not in bridge.realizations
                or realization.realization_spec_id
                not in bridge.frozen_hypothesis.realization_spec_ids
            ):
                raise ValueError
            global_arm = tuple(item for item in realization.arms if item.arm_role is self.arm_role)
            protocol_arm = tuple(
                item for item in bridge.arm_protocol.arms if item.arm_role is self.arm_role
            )
            if len(global_arm) != 1 or len(protocol_arm) != 1:
                raise ValueError
            canonical_arm = _arm_spec(bridge, self.arm_role)
            if self.allowed_arm != canonical_arm:
                raise ValueError
            target_role = bridge.arm_protocol.arms[0].arm_role
            target_allowed = _arm_spec(bridge, target_role).allowed_delta.allowed_transitions
            if (
                len(target_allowed) != 1
                or target_allowed[0].feature_id != bridge.target_spec.feature_id
                or len(target_allowed[0].from_states) != 1
                or len(target_allowed[0].to_states) != 1
            ):
                raise ValueError

            policy = ExtractionPolicy(
                backend=source_evidence.extraction_proposal.backend,
                policy_sha256=bridge.realization_policy.extractor_policy_sha256,
                catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
                max_response_chars=self.extractor_max_response_chars,
            )
            expected_prompt = blind_variant_prompt_record_from_text(
                source, self.prompt_variant.prompt_text, policy
            )
            proposal = validate_proposal(self.extraction_proposal, expected_prompt)
            graph = build_prompt_tsg(proposal, expected_prompt)
            target = _legacy_target(bridge)
            target_instance = _target_instance(source=source, target=target)
            protocol_instance = _protocol_instance(
                source=source, target_instance=target_instance, bridge=bridge
            )
            membership = _variant_membership(source_evidence.membership, expected_prompt)
            source_evaluation = evaluate_context_query(
                source_evidence.prompt_tsg,
                bridge.context_query.query_name,
                semantic_membership=source_evidence.membership,
            )
            variant_evaluation = evaluate_context_query(
                graph,
                bridge.context_query.query_name,
                semantic_membership=membership,
            )
            source_projection = _context_projection(source_evidence.prompt_tsg, source_evaluation)
            variant_projection = _context_projection(graph, variant_evaluation)
            if (
                expected_prompt != self.variant_prompt
                or proposal != self.extraction_proposal
                or graph != self.prompt_tsg
                or membership != self.variant_membership
                or target != self.legacy_target
                or target_instance != self.target_instance
                or protocol_instance != self.protocol_instance
                or source_projection != self.source_context_projection
                or variant_projection != self.variant_context_projection
                or source_projection != variant_projection
            ):
                raise ValueError

            reference_role = _MATCHED_REFERENCE_ROLE.get(self.arm_role)
            if reference_role is None:
                if (
                    self.length_match is not None
                    or self.length_match_reference_prompt_text is not None
                ):
                    raise ValueError
                expected_length_match_id = None
            else:
                if self.length_match is None or self.length_match_reference_prompt_text is None:
                    raise ValueError
                validate_length_match_record(
                    self.length_match,
                    source_text=source.prompt,
                    reference_text=self.length_match_reference_prompt_text,
                    matched_text=self.prompt_variant.prompt_text,
                )
                if (
                    self.length_match.arm_protocol_id != bridge.arm_protocol.arm_protocol_id
                    or self.length_match.protocol_instance_id
                    != protocol_instance.protocol_instance_id
                    or self.length_match.reference_arm_role is not reference_role
                ):
                    raise ValueError
                expected_length_match_id = self.length_match.length_match_id

            delta = validate_graph_delta_record(
                self.graph_delta,
                before_graph=source_evidence.prompt_tsg,
                after_graph=graph,
                target=target,
                arm=canonical_arm,
                expected_length_match_id=expected_length_match_id,
            )
            expected_variant = PromptVariantRecord.from_content(
                task_id=source.task_id,
                source_prompt_id=source.prompt_id,
                language=source.language,
                variant_prompt_id=expected_prompt.prompt_id,
                hypothesis_id=bridge.frozen_hypothesis.hypothesis_id,
                target_spec_id=target.target_spec_id,
                target_instance_id=target_instance.target_instance_id,
                arm_protocol_id=bridge.arm_protocol.arm_protocol_id,
                protocol_instance_id=protocol_instance.protocol_instance_id,
                arm_role=self.arm_role,
                prompt_sha256=expected_prompt.prompt_sha256,
                prompt_text=expected_prompt.prompt,
                proposal_id=proposal.proposal_id,
                graph_id=graph.graph_id,
                delta_id=delta.delta_id,
                executor_policy_sha256=global_arm[0].template_or_execution_policy_sha256,
                extractor_policy_sha256=policy.policy_sha256,
                length_match_id=expected_length_match_id,
            )
            if expected_variant != self.prompt_variant:
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize all replay failures
            raise ValueError(self._safe_validation_message) from None
        return self


class VariantInvariantEvidenceManifestV2(_ContentAddressedVariantEvidenceV2):
    """Complete receipt closure for the task support retained in one population."""

    _id_field = "variant_evidence_manifest_id"
    _id_prefix = "variant_evidence_manifest_v2_"

    variant_evidence_manifest_id: str = Field(pattern=_MANIFEST_ID_PATTERN)
    intervention_bridge: InterventionBridgeRecordV2
    query_evidence: QueryEvidenceManifestV2
    population: PopulationFreezeManifestV2
    receipts: tuple[ArmVariantInvariantReceiptV2, ...] = Field(min_length=4)
    eligible_task_ids: tuple[str, ...] = Field(min_length=1)
    retained_task_ids: tuple[str, ...] = Field(min_length=1)
    pre_randomization_excluded_eligible_task_ids: tuple[str, ...]
    receipt_count: StrictInt = Field(ge=4)
    expected_retained_receipt_count: StrictInt = Field(ge=4)
    complete_qh_arm_support: Literal[True]
    task_atomic_failure_policy: Literal["exclude_entire_task_before_randomization"]
    realization_failure_policy: Literal["no_deletion_no_renormalization"]
    target_changed_is_diagnostic_only: Literal[True]
    frozen_before_generation: Literal[True]

    @property
    def semantic_sha256(self) -> str:
        return self.variant_evidence_manifest_id.removeprefix("variant_evidence_manifest_v2_")

    @classmethod
    def from_components(
        cls,
        *,
        intervention_bridge: InterventionBridgeRecordV2,
        query_evidence: QueryEvidenceManifestV2,
        population: PopulationFreezeManifestV2,
        receipts: tuple[ArmVariantInvariantReceiptV2, ...],
    ) -> Self:
        try:
            bridge = InterventionBridgeRecordV2.model_validate(intervention_bridge, strict=True)
            query = QueryEvidenceManifestV2.model_validate(query_evidence, strict=True)
            checked_population = PopulationFreezeManifestV2.model_validate(population, strict=True)
            checked_receipts = tuple(
                sorted(
                    (
                        ArmVariantInvariantReceiptV2.model_validate(item, strict=True)
                        for item in receipts
                    ),
                    key=lambda item: (
                        item.source_query_evidence.membership.task_instance_id,
                        item.realization.realization_index,
                        next(
                            arm.arm_index
                            for arm in bridge.arm_protocol.arms
                            if arm.arm_role is item.arm_role
                        ),
                    ),
                )
            )
            eligible = tuple(
                sorted(
                    item.membership.task_instance_id
                    for item in query.tasks
                    if item.eligibility.eligible
                )
            )
            retained = checked_population.gate_pass_task_ids
            excluded = tuple(sorted(set(eligible) - set(retained)))
            expected_count = len(retained) * len(bridge.realizations) * 4
            return cls.from_content(
                intervention_bridge=bridge,
                query_evidence=query,
                population=checked_population,
                receipts=checked_receipts,
                eligible_task_ids=eligible,
                retained_task_ids=retained,
                pre_randomization_excluded_eligible_task_ids=excluded,
                receipt_count=len(checked_receipts),
                expected_retained_receipt_count=expected_count,
                complete_qh_arm_support=True,
                task_atomic_failure_policy="exclude_entire_task_before_randomization",
                realization_failure_policy="no_deletion_no_renormalization",
                target_changed_is_diagnostic_only=True,
                frozen_before_generation=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the manifest boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        try:
            bridge = self.intervention_bridge
            query = self.query_evidence
            population = self.population
            hypothesis = bridge.frozen_hypothesis
            if (
                query.context_query != bridge.context_query
                or query.actionable_feature != bridge.actionable_feature
                or query.operation is not hypothesis.operation
                or population.hypothesis != hypothesis
                or population.common_model_scope != hypothesis.model_scope
            ):
                raise ValueError
            query_by_task = {item.membership.task_instance_id: item for item in query.tasks}
            gate_by_task = {item.task_instance_id: item for item in population.task_gates}
            eligible = tuple(
                sorted(
                    task_id for task_id, item in query_by_task.items() if item.eligibility.eligible
                )
            )
            retained = population.gate_pass_task_ids
            excluded_eligible = tuple(sorted(set(eligible) - set(retained)))
            if (
                set(query_by_task) != set(gate_by_task)
                or self.eligible_task_ids != eligible
                or self.retained_task_ids != retained
                or self.pre_randomization_excluded_eligible_task_ids != excluded_eligible
                or not set(retained) <= set(eligible)
                or any(
                    gate_by_task[task_id].task_policy_support is not None
                    for task_id in excluded_eligible
                )
            ):
                raise ValueError

            arm_order = tuple(item.arm_role for item in bridge.arm_protocol.arms)
            expected_keys = tuple(
                (task_id, realization.realization_spec_id, arm_role)
                for task_id in retained
                for realization in bridge.realizations
                for arm_role in arm_order
            )
            receipt_keys = tuple(
                (
                    item.source_query_evidence.membership.task_instance_id,
                    item.realization.realization_spec_id,
                    item.arm_role,
                )
                for item in self.receipts
            )
            if (
                receipt_keys != expected_keys
                or len(receipt_keys) != len(set(receipt_keys))
                or self.receipt_count != len(self.receipts)
                or self.expected_retained_receipt_count != len(expected_keys)
                or self.receipt_count != self.expected_retained_receipt_count
            ):
                raise ValueError

            receipt_by_key = dict(zip(receipt_keys, self.receipts, strict=True))
            for task_id in retained:
                source_evidence = query_by_task[task_id]
                gate = gate_by_task[task_id]
                support = gate.task_policy_support
                if support is None:
                    raise ValueError
                expected_bundles = []
                for realization in bridge.realizations:
                    arm_receipts = tuple(
                        receipt_by_key[(task_id, realization.realization_spec_id, arm_role)]
                        for arm_role in arm_order
                    )
                    if any(
                        item.intervention_bridge != bridge
                        or item.source_query_evidence != source_evidence
                        or item.realization != realization
                        for item in arm_receipts
                    ):
                        raise ValueError
                    target_text = arm_receipts[0].prompt_variant.prompt_text
                    for item in arm_receipts:
                        if item.arm_role in _MATCHED_REFERENCE_ROLE and (
                            item.length_match_reference_prompt_text != target_text
                        ):
                            raise ValueError
                    expected_bundles.append(
                        TaskRealizationBundleRecord.from_components(
                            hypothesis=hypothesis,
                            realization=realization,
                            semantic_task_cluster_id=(
                                source_evidence.membership.semantic_task_cluster_id
                            ),
                            task_instance_id=task_id,
                            source_prompt_id=source_evidence.natural_prompt.prompt_id,
                            source_prompt_sha256=source_evidence.natural_prompt.prompt_sha256,
                            arms=tuple(item.to_task_arm_variant_binding() for item in arm_receipts),
                        )
                    )
                expected_support = TaskPolicySupportRecord.from_components(
                    hypothesis=hypothesis,
                    policy=bridge.realization_policy,
                    realizations=bridge.realizations,
                    bundles=tuple(expected_bundles),
                )
                if support != expected_support:
                    raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize all closure failures
            raise ValueError(self._safe_validation_message) from None
        return self


__all__ = [
    "VARIANT_EVIDENCE_V2_SCHEMA_VERSION",
    "ArmVariantInvariantReceiptV2",
    "ContextPathSignatureV2",
    "ContextQuerySemanticProjectionV2",
    "VariantInvariantEvidenceManifestV2",
]

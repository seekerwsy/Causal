"""Prospective v2 contracts for context-conditioned intervention policies.

These records are deliberately independent of the legacy v1 experiment schemas.  They
encode pre-outcome policy identity, selector freezes, realization support, semantic
clusters, and the realization-aware confirmation block key described by the v3
framework.  They do not encode generated-code outcomes or post-assignment diagnostics.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from secaware.records import (
    ContentAddressedResearchRecord,
    SnapshotResearchRecord,
    parse_exact_enum as _exact_enum,
    raise_record_validation_error as _raise_contract_error,
    record_sha256 as _digest,
    snapshot_json_arrays as _snapshot_json_arrays,
    valid_identifier as _valid_identifier,
)
from secaware.schema.common import is_valid_model_id
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation

POLICY_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_OUTCOME_RE = re.compile(r"^y_[a-z0-9][a-z0-9_]{0,126}$")

_CONTEXT_QUERY_RESULT_PATTERN = r"^context_query_result_[0-9a-f]{64}$"
_ACTIONABLE_QUERY_RESULT_PATTERN = r"^actionable_query_result_[0-9a-f]{64}$"
_ELIGIBILITY_PATTERN = r"^pre_outcome_eligibility_[0-9a-f]{64}$"
_CONTEXT_QUERY_SPEC_PATTERN = r"^context_query_[0-9a-f]{64}$"
_ACTIONABLE_FEATURE_SPEC_PATTERN = r"^actionable_feature_[0-9a-f]{64}$"
_REALIZATION_POLICY_PATTERN = r"^realization_policy_[0-9a-f]{64}$"
_CANDIDATE_SKELETON_PATTERN = r"^candidate_skeleton_[0-9a-f]{64}$"
_UNIVERSE_PATTERN = r"^candidate_universe_[0-9a-f]{64}$"
_SELECTOR_SLOT_PATTERN = r"^selector_slot_[0-9a-f]{64}$"
_SELECTION_MAPPING_PATTERN = r"^selection_mapping_[0-9a-f]{64}$"
_SELECTION_FREEZE_PATTERN = r"^selection_freeze_[0-9a-f]{64}$"
_REALIZATION_SPEC_PATTERN = r"^realization_spec_[0-9a-f]{64}$"
_HYPOTHESIS_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_TARGET_PATTERN = r"^target_[0-9a-f]{64}$"
_ARM_PROTOCOL_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_VARIANT_PATTERN = r"^variant_[0-9a-f]{64}$"
_VARIANT_PROMPT_PATTERN = r"^variant_prompt_[0-9a-f]{64}$"
_TASK_BUNDLE_PATTERN = r"^task_realization_bundle_[0-9a-f]{64}$"
_TASK_SUPPORT_PATTERN = r"^task_policy_support_[0-9a-f]{64}$"
_CLUSTER_MEMBERSHIP_PATTERN = r"^cluster_membership_[0-9a-f]{64}$"
_CLUSTER_MANIFEST_PATTERN = r"^semantic_cluster_manifest_[0-9a-f]{64}$"
_BLOCK_PATTERN = r"^block_[0-9a-f]{64}$"

_ADD_ARM_ORDER = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)
_REMOVE_ARM_ORDER = (
    ArmRole.TARGET_REMOVE,
    ArmRole.NOOP_RETAIN,
    ArmRole.LENGTH_MATCHED_SHAM_EDIT,
    ArmRole.GENERIC_SECURITY_REPLACEMENT,
)


class _PolicyV2Contract(SnapshotResearchRecord):
    _safe_validation_message: ClassVar[str] = "policy v2 contract failed validation"


class _ContentAddressedV2Contract(ContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "policy v2 contract failed validation"
    _schema_version = POLICY_V2_SCHEMA_VERSION
    schema_version: Literal["2.0"]


class QueryState(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


class ExpectedDirection(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class EligibilityExclusionReason(StrEnum):
    CONTEXT_ABSENT = "context_absent"
    CONTEXT_NOT_APPLICABLE = "context_not_applicable"
    CONTEXT_UNRESOLVED = "context_unresolved"
    ADD_SOURCE_PRESENT = "add_source_present"
    ADD_SOURCE_NOT_APPLICABLE = "add_source_not_applicable"
    ADD_SOURCE_UNRESOLVED = "add_source_unresolved"
    REMOVE_SOURCE_ABSENT = "remove_source_absent"
    REMOVE_SOURCE_NOT_APPLICABLE = "remove_source_not_applicable"
    REMOVE_SOURCE_UNRESOLVED = "remove_source_unresolved"
    REMOVE_TARGET_EVIDENCE_MISSING = "remove_target_evidence_missing"
    REMOVE_COUNTERPART_NOT_ATTESTED = "remove_counterpart_not_attested"


class SelectorSlotStatus(StrEnum):
    SELECTED = "selected"
    EMPTY = "empty"


class BridgeStatus(StrEnum):
    PROTOCOLIZED = "protocolized"
    FAILED = "failed"


class PolicySplit(StrEnum):
    DISCOVER = "discover"
    CONFIRM = "confirm"
    REPLICATION = "replication"


def _validate_query_semantics(
    *,
    state: QueryState,
    applicable: bool | None,
    required_roles_resolved: bool | None,
    bounded_matching_complete: bool,
    match_evidence_ids: tuple[str, ...],
) -> None:
    if (
        match_evidence_ids != tuple(sorted(match_evidence_ids))
        or len(match_evidence_ids) != len(set(match_evidence_ids))
        or any(not _valid_identifier(item) for item in match_evidence_ids)
    ):
        raise ValueError("policy v2 contract failed validation")
    if state is QueryState.PRESENT:
        valid = (
            applicable is True
            and required_roles_resolved is True
            and bounded_matching_complete
            and bool(match_evidence_ids)
        )
    elif state is QueryState.ABSENT:
        valid = (
            applicable is True
            and required_roles_resolved is True
            and bounded_matching_complete
            and not match_evidence_ids
        )
    elif state is QueryState.NOT_APPLICABLE:
        valid = (
            applicable is False
            and required_roles_resolved is None
            and not bounded_matching_complete
            and not match_evidence_ids
        )
    else:
        valid = (
            applicable is not False
            and not match_evidence_ids
            and not (
                applicable is True and required_roles_resolved is True and bounded_matching_complete
            )
        )
    if not valid:
        raise ValueError("policy v2 contract failed validation")


class ContextQuerySpec(_ContentAddressedV2Contract):
    """One target-independent, non-editable context query."""

    _id_field: ClassVar[str] = "context_query_id"
    _id_prefix: ClassVar[str] = "context_query_"

    context_query_id: str = Field(pattern=_CONTEXT_QUERY_SPEC_PATTERN)
    query_name: str
    applicable_cwes: tuple[str, ...] = Field(min_length=1, max_length=128)
    applicable_task_archetypes: tuple[str, ...] = Field(min_length=1, max_length=128)
    query_expression_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_query_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_semantics_version: str
    target_feature_independent: Literal[True]

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if (
            not _valid_identifier(self.query_name)
            or not _valid_identifier(self.query_semantics_version)
            or self.applicable_cwes != tuple(sorted(self.applicable_cwes))
            or len(self.applicable_cwes) != len(set(self.applicable_cwes))
            or any(_CWE_RE.fullmatch(item) is None for item in self.applicable_cwes)
            or self.applicable_task_archetypes != tuple(sorted(self.applicable_task_archetypes))
            or len(self.applicable_task_archetypes) != len(set(self.applicable_task_archetypes))
            or any(not _valid_identifier(item) for item in self.applicable_task_archetypes)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ActionableFeatureSpec(_ContentAddressedV2Contract):
    """Immutable adapter from v2 policy space to exactly one feature-catalog leaf."""

    _id_field: ClassVar[str] = "actionable_feature_spec_id"
    _id_prefix: ClassVar[str] = "actionable_feature_"

    actionable_feature_spec_id: str = Field(pattern=_ACTIONABLE_FEATURE_SPEC_PATTERN)
    feature_id: str
    feature_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    allowed_operations: tuple[FeatureOperation, ...] = Field(min_length=1, max_length=2)
    task_preserving_edit_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("allowed_operations", mode="before")
    @classmethod
    def parse_operations(cls, value: object) -> object:
        snapshot = _snapshot_json_arrays(value)
        if type(snapshot) is not tuple:
            return snapshot
        return tuple(_exact_enum(item, FeatureOperation) for item in snapshot)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        values = tuple(item.value for item in self.allowed_operations)
        if (
            not _valid_identifier(self.feature_id)
            or values != tuple(sorted(values))
            or len(values) != len(set(values))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ContextQueryResultRecord(_ContentAddressedV2Contract):
    """A four-valued natural-Prompt context result; never an assigned treatment."""

    _id_field: ClassVar[str] = "context_query_result_id"
    _id_prefix: ClassVar[str] = "context_query_result_"

    context_query_result_id: str = Field(pattern=_CONTEXT_QUERY_RESULT_PATTERN)
    regime_id: Literal["natural_prompt_discovery"]
    task_instance_id: str
    natural_prompt_id: str
    prompt_tsg_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_query_id: str = Field(pattern=_CONTEXT_QUERY_SPEC_PATTERN)
    context_query_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_semantics_version: str
    state: QueryState
    applicable: bool | None
    required_roles_resolved: bool | None
    bounded_matching_complete: bool
    match_evidence_ids: tuple[str, ...]
    evaluation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("state", mode="before")
    @classmethod
    def parse_state(cls, value: object) -> object:
        return _exact_enum(value, QueryState)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if (
            not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.natural_prompt_id)
            or not _valid_identifier(self.query_semantics_version)
        ):
            raise ValueError(self._safe_validation_message)
        _validate_query_semantics(
            state=self.state,
            applicable=self.applicable,
            required_roles_resolved=self.required_roles_resolved,
            bounded_matching_complete=self.bounded_matching_complete,
            match_evidence_ids=self.match_evidence_ids,
        )
        return self


class ActionableFeatureQueryResultRecord(_ContentAddressedV2Contract):
    """A four-valued natural-Prompt actionable-feature result."""

    _id_field: ClassVar[str] = "actionable_query_result_id"
    _id_prefix: ClassVar[str] = "actionable_query_result_"

    actionable_query_result_id: str = Field(pattern=_ACTIONABLE_QUERY_RESULT_PATTERN)
    regime_id: Literal["natural_prompt_discovery"]
    task_instance_id: str
    natural_prompt_id: str
    prompt_tsg_sha256: str = Field(pattern=_SHA256_PATTERN)
    actionable_feature_spec_id: str = Field(pattern=_ACTIONABLE_FEATURE_SPEC_PATTERN)
    feature_id: str
    feature_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_query_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_semantics_version: str
    state: QueryState
    applicable: bool | None
    required_roles_resolved: bool | None
    bounded_matching_complete: bool
    match_evidence_ids: tuple[str, ...]
    evaluation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("state", mode="before")
    @classmethod
    def parse_state(cls, value: object) -> object:
        return _exact_enum(value, QueryState)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if (
            not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.natural_prompt_id)
            or not _valid_identifier(self.feature_id)
            or not _valid_identifier(self.query_semantics_version)
        ):
            raise ValueError(self._safe_validation_message)
        _validate_query_semantics(
            state=self.state,
            applicable=self.applicable,
            required_roles_resolved=self.required_roles_resolved,
            bounded_matching_complete=self.bounded_matching_complete,
            match_evidence_ids=self.match_evidence_ids,
        )
        return self


_CONTEXT_EXCLUSIONS = {
    QueryState.ABSENT: EligibilityExclusionReason.CONTEXT_ABSENT,
    QueryState.NOT_APPLICABLE: EligibilityExclusionReason.CONTEXT_NOT_APPLICABLE,
    QueryState.UNRESOLVED: EligibilityExclusionReason.CONTEXT_UNRESOLVED,
}
_ADD_EXCLUSIONS = {
    QueryState.PRESENT: EligibilityExclusionReason.ADD_SOURCE_PRESENT,
    QueryState.NOT_APPLICABLE: EligibilityExclusionReason.ADD_SOURCE_NOT_APPLICABLE,
    QueryState.UNRESOLVED: EligibilityExclusionReason.ADD_SOURCE_UNRESOLVED,
}
_REMOVE_EXCLUSIONS = {
    QueryState.ABSENT: EligibilityExclusionReason.REMOVE_SOURCE_ABSENT,
    QueryState.NOT_APPLICABLE: EligibilityExclusionReason.REMOVE_SOURCE_NOT_APPLICABLE,
    QueryState.UNRESOLVED: EligibilityExclusionReason.REMOVE_SOURCE_UNRESOLVED,
}


def _eligibility_reason(
    *,
    context_state: QueryState,
    feature_state: QueryState,
    operation: FeatureOperation,
    target_evidence_sha256: str | None,
    neutral_counterpart_attested: bool | None,
) -> EligibilityExclusionReason | None:
    if context_state is not QueryState.PRESENT:
        return _CONTEXT_EXCLUSIONS[context_state]
    if operation is FeatureOperation.ADD:
        if feature_state is QueryState.ABSENT:
            return None
        return _ADD_EXCLUSIONS[feature_state]
    if feature_state is not QueryState.PRESENT:
        return _REMOVE_EXCLUSIONS[feature_state]
    if target_evidence_sha256 is None:
        return EligibilityExclusionReason.REMOVE_TARGET_EVIDENCE_MISSING
    if neutral_counterpart_attested is not True:
        return EligibilityExclusionReason.REMOVE_COUNTERPART_NOT_ATTESTED
    return None


class PreOutcomeEligibilityRecord(_ContentAddressedV2Contract):
    """Total pre-randomization context and operation eligibility decision."""

    _id_field: ClassVar[str] = "eligibility_id"
    _id_prefix: ClassVar[str] = "pre_outcome_eligibility_"

    eligibility_id: str = Field(pattern=_ELIGIBILITY_PATTERN)
    task_instance_id: str
    natural_prompt_id: str
    prompt_tsg_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_query_result_id: str = Field(pattern=_CONTEXT_QUERY_RESULT_PATTERN)
    actionable_query_result_id: str = Field(pattern=_ACTIONABLE_QUERY_RESULT_PATTERN)
    context_state: QueryState
    actionable_feature_state: QueryState
    operation: FeatureOperation
    target_evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    neutral_counterpart_attested: bool | None = None
    neutral_counterpart_attestation_sha256: str | None = Field(
        default=None, pattern=_SHA256_PATTERN
    )
    eligibility_function_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible: bool
    exclusion_reason: EligibilityExclusionReason | None

    @field_validator("context_state", "actionable_feature_state", mode="before")
    @classmethod
    def parse_state(cls, value: object) -> object:
        return _exact_enum(value, QueryState)

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @field_validator("exclusion_reason", mode="before")
    @classmethod
    def parse_exclusion_reason(cls, value: object) -> object:
        if value is None:
            return None
        return _exact_enum(value, EligibilityExclusionReason)

    @classmethod
    def from_query_results(
        cls,
        *,
        context_result: ContextQueryResultRecord,
        feature_result: ActionableFeatureQueryResultRecord,
        operation: FeatureOperation,
        eligibility_function_sha256: str,
        target_evidence_sha256: str | None = None,
        neutral_counterpart_attested: bool | None = None,
        neutral_counterpart_attestation_sha256: str | None = None,
    ) -> Self:
        try:
            context = ContextQueryResultRecord.model_validate(context_result, strict=True)
            feature = ActionableFeatureQueryResultRecord.model_validate(feature_result, strict=True)
            parsed_operation = _exact_enum(operation, FeatureOperation)
            if type(parsed_operation) is not FeatureOperation:
                raise ValueError
            coordinates = (
                context.task_instance_id,
                context.natural_prompt_id,
                context.prompt_tsg_sha256,
                context.context_query_catalog_sha256,
                context.query_semantics_version,
            )
            feature_coordinates = (
                feature.task_instance_id,
                feature.natural_prompt_id,
                feature.prompt_tsg_sha256,
                feature.context_query_catalog_sha256,
                feature.query_semantics_version,
            )
            if coordinates != feature_coordinates:
                raise ValueError
            reason = _eligibility_reason(
                context_state=context.state,
                feature_state=feature.state,
                operation=parsed_operation,
                target_evidence_sha256=target_evidence_sha256,
                neutral_counterpart_attested=neutral_counterpart_attested,
            )
            return cls.from_content(
                task_instance_id=context.task_instance_id,
                natural_prompt_id=context.natural_prompt_id,
                prompt_tsg_sha256=context.prompt_tsg_sha256,
                context_query_result_id=context.context_query_result_id,
                actionable_query_result_id=feature.actionable_query_result_id,
                context_state=context.state,
                actionable_feature_state=feature.state,
                operation=parsed_operation,
                target_evidence_sha256=target_evidence_sha256,
                neutral_counterpart_attested=neutral_counterpart_attested,
                neutral_counterpart_attestation_sha256=(neutral_counterpart_attestation_sha256),
                eligibility_function_sha256=eligibility_function_sha256,
                eligible=reason is None,
                exclusion_reason=reason,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        expected_reason = _eligibility_reason(
            context_state=self.context_state,
            feature_state=self.actionable_feature_state,
            operation=self.operation,
            target_evidence_sha256=self.target_evidence_sha256,
            neutral_counterpart_attested=self.neutral_counterpart_attested,
        )
        remove = self.operation is FeatureOperation.REMOVE
        if (
            not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.natural_prompt_id)
            or self.eligible != (expected_reason is None)
            or self.exclusion_reason is not expected_reason
            or (self.neutral_counterpart_attested is None)
            != (self.neutral_counterpart_attestation_sha256 is None)
            or (not remove and self.target_evidence_sha256 is not None)
            or (not remove and self.neutral_counterpart_attested is not None)
            or (
                remove
                and self.actionable_feature_state is not QueryState.PRESENT
                and (
                    self.target_evidence_sha256 is not None
                    or self.neutral_counterpart_attested is not None
                )
            )
            or (self.neutral_counterpart_attested is True and self.target_evidence_sha256 is None)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class RealizationPolicySpec(_ContentAddressedV2Contract):
    """Task-independent finite realization distribution and fail-closed policy."""

    _id_field: ClassVar[str] = "realization_policy_spec_id"
    _id_prefix: ClassVar[str] = "realization_policy_"

    realization_policy_spec_id: str = Field(pattern=_REALIZATION_POLICY_PATTERN)
    k_r: StrictInt = Field(ge=1, le=32)
    probability_numerators: tuple[StrictInt, ...] = Field(min_length=1, max_length=32)
    probability_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    distribution_rationale: Literal["uniform", "preregistered_nonuniform"]
    matching_rules_sha256: str = Field(pattern=_SHA256_PATTERN)
    executor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    extractor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    validation_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    full_support_required: Literal[True]
    failure_policy: Literal["fail_closed_no_deletion_no_renormalization"]

    @model_validator(mode="after")
    def validate_distribution(self) -> Self:
        if (
            len(self.probability_numerators) != self.k_r
            or any(item <= 0 for item in self.probability_numerators)
            or sum(self.probability_numerators) != self.probability_denominator
            or (
                self.distribution_rationale == "uniform"
                and len(set(self.probability_numerators)) != 1
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CandidateSkeleton(_ContentAddressedV2Contract):
    """Selector-invariant skeleton ``(C_q, f, a, Q_policy, Y)``."""

    _id_field: ClassVar[str] = "candidate_skeleton_id"
    _id_prefix: ClassVar[str] = "candidate_skeleton_"

    candidate_skeleton_id: str = Field(pattern=_CANDIDATE_SKELETON_PATTERN)
    context_query_id: str = Field(pattern=_CONTEXT_QUERY_SPEC_PATTERN)
    actionable_feature_spec_id: str = Field(pattern=_ACTIONABLE_FEATURE_SPEC_PATTERN)
    feature_id: str
    operation: FeatureOperation
    realization_policy_spec_id: str = Field(pattern=_REALIZATION_POLICY_PATTERN)
    outcome_id: str
    expected_direction: ExpectedDirection
    cwe: str
    task_archetype: str
    model_scope: tuple[str, ...] = Field(min_length=1, max_length=64)
    context_query_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    feature_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligibility_function_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @field_validator("expected_direction", mode="before")
    @classmethod
    def parse_direction(cls, value: object) -> object:
        return _exact_enum(value, ExpectedDirection)

    @property
    def semantic_sha256(self) -> str:
        return self.candidate_skeleton_id.removeprefix("candidate_skeleton_")

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if (
            not _valid_identifier(self.feature_id)
            or not _valid_identifier(self.task_archetype)
            or _OUTCOME_RE.fullmatch(self.outcome_id) is None
            or _CWE_RE.fullmatch(self.cwe) is None
            or self.model_scope != tuple(sorted(self.model_scope))
            or len(self.model_scope) != len(set(self.model_scope))
            or any(not is_valid_model_id(item) for item in self.model_scope)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CandidateUniverseManifest(_ContentAddressedV2Contract):
    """The one exact candidate universe consumed by every primary selector."""

    _id_field: ClassVar[str] = "candidate_universe_id"
    _id_prefix: ClassVar[str] = "candidate_universe_"

    candidate_universe_id: str = Field(pattern=_UNIVERSE_PATTERN)
    skeletons: tuple[CandidateSkeleton, ...] = Field(min_length=1, max_length=10_000)
    candidate_count: StrictInt = Field(ge=1, le=10_000)
    outcome_id: str
    information_budget_sha256: str = Field(pattern=_SHA256_PATTERN)
    universe_construction_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_before_selector_runs: Literal[True]

    @model_validator(mode="after")
    def validate_universe(self) -> Self:
        skeleton_ids = tuple(item.candidate_skeleton_id for item in self.skeletons)
        if (
            self.candidate_count != len(self.skeletons)
            or skeleton_ids != tuple(sorted(skeleton_ids))
            or len(skeleton_ids) != len(set(skeleton_ids))
            or _OUTCOME_RE.fullmatch(self.outcome_id) is None
            or any(item.outcome_id != self.outcome_id for item in self.skeletons)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SelectorSlotRecord(_ContentAddressedV2Contract):
    """One frozen method/model/rank budget slot; empty slots remain explicit."""

    _id_field: ClassVar[str] = "selector_slot_id"
    _id_prefix: ClassVar[str] = "selector_slot_"

    selector_slot_id: str = Field(pattern=_SELECTOR_SLOT_PATTERN)
    candidate_universe_id: str = Field(pattern=_UNIVERSE_PATTERN)
    selector_id: str
    model_id: str
    rank: StrictInt = Field(ge=1, le=10_000)
    status: SelectorSlotStatus
    candidate_skeleton_id: str | None = Field(default=None, pattern=_CANDIDATE_SKELETON_PATTERN)
    selector_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    failure_code: str | None = None

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, value: object) -> object:
        return _exact_enum(value, SelectorSlotStatus)

    @model_validator(mode="after")
    def validate_slot(self) -> Self:
        selected = self.status is SelectorSlotStatus.SELECTED
        if (
            not _valid_identifier(self.selector_id)
            or not is_valid_model_id(self.model_id)
            or selected != (self.candidate_skeleton_id is not None)
            or selected == (self.failure_code is not None)
            or (self.failure_code is not None and not _valid_identifier(self.failure_code))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SelectionMappingRecord(_ContentAddressedV2Contract):
    """Selector-invariant bridge result for one selected skeleton."""

    _id_field: ClassVar[str] = "selection_mapping_id"
    _id_prefix: ClassVar[str] = "selection_mapping_"

    selection_mapping_id: str = Field(pattern=_SELECTION_MAPPING_PATTERN)
    candidate_skeleton_id: str = Field(pattern=_CANDIDATE_SKELETON_PATTERN)
    status: BridgeStatus
    final_hypothesis_id: str | None = Field(default=None, pattern=_HYPOTHESIS_PATTERN)
    bridge_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    failure_code: str | None = None

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, value: object) -> object:
        return _exact_enum(value, BridgeStatus)

    @model_validator(mode="after")
    def validate_mapping(self) -> Self:
        protocolized = self.status is BridgeStatus.PROTOCOLIZED
        if (
            protocolized != (self.final_hypothesis_id is not None)
            or protocolized == (self.failure_code is not None)
            or (self.failure_code is not None and not _valid_identifier(self.failure_code))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SelectionFreezeManifest(_ContentAddressedV2Contract):
    """Frozen selector slots plus one shared skeleton-to-hypothesis mapping."""

    _id_field: ClassVar[str] = "selection_freeze_id"
    _id_prefix: ClassVar[str] = "selection_freeze_"

    selection_freeze_id: str = Field(pattern=_SELECTION_FREEZE_PATTERN)
    candidate_universe_id: str = Field(pattern=_UNIVERSE_PATTERN)
    budget_k: StrictInt = Field(ge=1, le=10_000)
    selector_slots: tuple[SelectorSlotRecord, ...] = Field(min_length=1, max_length=100_000)
    mappings: tuple[SelectionMappingRecord, ...] = Field(max_length=10_000)
    frozen_before_confirm_outcomes: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        universe: CandidateUniverseManifest,
        budget_k: int,
        selector_slots: Sequence[SelectorSlotRecord],
        mappings: Sequence[SelectionMappingRecord],
    ) -> Self:
        try:
            checked_universe = CandidateUniverseManifest.model_validate(universe, strict=True)
            slots = tuple(selector_slots)
            mapped = tuple(mappings)
            universe_ids = {item.candidate_skeleton_id for item in checked_universe.skeletons}
            if any(
                item.candidate_skeleton_id is not None
                and item.candidate_skeleton_id not in universe_ids
                for item in slots
            ) or any(item.candidate_skeleton_id not in universe_ids for item in mapped):
                raise ValueError
            return cls.from_content(
                candidate_universe_id=checked_universe.candidate_universe_id,
                budget_k=budget_k,
                selector_slots=slots,
                mappings=mapped,
                frozen_before_confirm_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_freeze(self) -> Self:
        slot_order = tuple(
            (item.selector_id, item.model_id, item.rank) for item in self.selector_slots
        )
        mapping_order = tuple(item.candidate_skeleton_id for item in self.mappings)
        selected_ids = {
            item.candidate_skeleton_id
            for item in self.selector_slots
            if item.candidate_skeleton_id is not None
        }
        mapped_ids = {item.candidate_skeleton_id for item in self.mappings}
        groups: dict[tuple[str, str], list[int]] = {}
        for item in self.selector_slots:
            groups.setdefault((item.selector_id, item.model_id), []).append(item.rank)
        if (
            any(
                item.candidate_universe_id != self.candidate_universe_id
                for item in self.selector_slots
            )
            or slot_order != tuple(sorted(slot_order))
            or len(slot_order) != len(set(slot_order))
            or mapping_order != tuple(sorted(mapping_order))
            or len(mapping_order) != len(set(mapping_order))
            or selected_ids != mapped_ids
            or any(sorted(ranks) != list(range(1, self.budget_k + 1)) for ranks in groups.values())
        ):
            raise ValueError(self._safe_validation_message)
        return self


class GlobalArmExecutionSpec(_PolicyV2Contract):
    """Task-independent execution policy for one arm of one realization."""

    arm_role: ArmRole
    template_or_execution_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    validation_requirements_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)


class RealizationSpecRecord(_ContentAddressedV2Contract):
    """One global task-independent coordinate in a frozen realization policy."""

    _id_field: ClassVar[str] = "realization_spec_id"
    _id_prefix: ClassVar[str] = "realization_spec_"

    realization_spec_id: str = Field(pattern=_REALIZATION_SPEC_PATTERN)
    candidate_skeleton_id: str = Field(pattern=_CANDIDATE_SKELETON_PATTERN)
    realization_policy_spec_id: str = Field(pattern=_REALIZATION_POLICY_PATTERN)
    realization_index: StrictInt = Field(ge=0, le=31)
    probability_numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    probability_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    operation: FeatureOperation
    arms: tuple[GlobalArmExecutionSpec, ...] = Field(min_length=4, max_length=4)

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @classmethod
    def from_policy(
        cls,
        *,
        skeleton: CandidateSkeleton,
        policy: RealizationPolicySpec,
        realization_index: int,
        arms: Sequence[GlobalArmExecutionSpec],
    ) -> Self:
        try:
            checked_skeleton = CandidateSkeleton.model_validate(skeleton, strict=True)
            checked_policy = RealizationPolicySpec.model_validate(policy, strict=True)
            if (
                checked_skeleton.realization_policy_spec_id
                != checked_policy.realization_policy_spec_id
                or type(realization_index) is not int
                or not 0 <= realization_index < checked_policy.k_r
            ):
                raise ValueError
            return cls.from_content(
                candidate_skeleton_id=checked_skeleton.candidate_skeleton_id,
                realization_policy_spec_id=checked_policy.realization_policy_spec_id,
                realization_index=realization_index,
                probability_numerator=checked_policy.probability_numerators[realization_index],
                probability_denominator=checked_policy.probability_denominator,
                operation=checked_skeleton.operation,
                arms=tuple(arms),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_realization(self) -> Self:
        expected = _ADD_ARM_ORDER if self.operation is FeatureOperation.ADD else _REMOVE_ARM_ORDER
        if (
            self.probability_numerator > self.probability_denominator
            or tuple(item.arm_role for item in self.arms) != expected
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FrozenPolicyHypothesisRecord(_ContentAddressedV2Contract):
    """Final selector-independent hypothesis after common bridge protocolization."""

    _id_field: ClassVar[str] = "hypothesis_id"
    _id_prefix: ClassVar[str] = "hypothesis_"

    hypothesis_id: str = Field(pattern=_HYPOTHESIS_PATTERN)
    candidate_skeleton_id: str = Field(pattern=_CANDIDATE_SKELETON_PATTERN)
    context_query_id: str = Field(pattern=_CONTEXT_QUERY_SPEC_PATTERN)
    actionable_feature_spec_id: str = Field(pattern=_ACTIONABLE_FEATURE_SPEC_PATTERN)
    feature_id: str
    operation: FeatureOperation
    outcome_id: str
    expected_direction: ExpectedDirection
    cwe: str
    task_archetype: str
    model_scope: tuple[str, ...]
    target_spec_id: str = Field(pattern=_TARGET_PATTERN)
    arm_protocol_id: str = Field(pattern=_ARM_PROTOCOL_PATTERN)
    realization_policy_spec_id: str = Field(pattern=_REALIZATION_POLICY_PATTERN)
    realization_spec_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    probability_numerators: tuple[StrictInt, ...] = Field(min_length=1, max_length=32)
    probability_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    bridge_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @field_validator("expected_direction", mode="before")
    @classmethod
    def parse_direction(cls, value: object) -> object:
        return _exact_enum(value, ExpectedDirection)

    @property
    def semantic_sha256(self) -> str:
        return self.hypothesis_id.removeprefix("hypothesis_")

    @classmethod
    def from_components(
        cls,
        *,
        skeleton: CandidateSkeleton,
        policy: RealizationPolicySpec,
        realizations: Sequence[RealizationSpecRecord],
        target_spec_id: str,
        arm_protocol_id: str,
        bridge_policy_sha256: str,
    ) -> Self:
        try:
            checked_skeleton = CandidateSkeleton.model_validate(skeleton, strict=True)
            checked_policy = RealizationPolicySpec.model_validate(policy, strict=True)
            specs = tuple(realizations)
            if (
                checked_skeleton.realization_policy_spec_id
                != checked_policy.realization_policy_spec_id
                or len(specs) != checked_policy.k_r
                or tuple(item.realization_index for item in specs)
                != tuple(range(checked_policy.k_r))
                or any(
                    item.candidate_skeleton_id != checked_skeleton.candidate_skeleton_id
                    or item.realization_policy_spec_id != checked_policy.realization_policy_spec_id
                    or item.operation is not checked_skeleton.operation
                    or item.probability_numerator
                    != checked_policy.probability_numerators[item.realization_index]
                    or item.probability_denominator != checked_policy.probability_denominator
                    for item in specs
                )
            ):
                raise ValueError
            return cls.from_content(
                candidate_skeleton_id=checked_skeleton.candidate_skeleton_id,
                context_query_id=checked_skeleton.context_query_id,
                actionable_feature_spec_id=checked_skeleton.actionable_feature_spec_id,
                feature_id=checked_skeleton.feature_id,
                operation=checked_skeleton.operation,
                outcome_id=checked_skeleton.outcome_id,
                expected_direction=checked_skeleton.expected_direction,
                cwe=checked_skeleton.cwe,
                task_archetype=checked_skeleton.task_archetype,
                model_scope=checked_skeleton.model_scope,
                target_spec_id=target_spec_id,
                arm_protocol_id=arm_protocol_id,
                realization_policy_spec_id=checked_policy.realization_policy_spec_id,
                realization_spec_ids=tuple(item.realization_spec_id for item in specs),
                probability_numerators=checked_policy.probability_numerators,
                probability_denominator=checked_policy.probability_denominator,
                bridge_policy_sha256=bridge_policy_sha256,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_hypothesis(self) -> Self:
        if (
            not _valid_identifier(self.feature_id)
            or not _valid_identifier(self.task_archetype)
            or _OUTCOME_RE.fullmatch(self.outcome_id) is None
            or _CWE_RE.fullmatch(self.cwe) is None
            or self.model_scope != tuple(sorted(self.model_scope))
            or len(self.model_scope) != len(set(self.model_scope))
            or any(not is_valid_model_id(item) for item in self.model_scope)
            or len(self.realization_spec_ids) != len(self.probability_numerators)
            or len(self.realization_spec_ids) != len(set(self.realization_spec_ids))
            or any(
                re.fullmatch(_REALIZATION_SPEC_PATTERN, item) is None
                for item in self.realization_spec_ids
            )
            or any(item <= 0 for item in self.probability_numerators)
            or sum(self.probability_numerators) != self.probability_denominator
        ):
            raise ValueError(self._safe_validation_message)
        return self


class TaskArmVariantBinding(_ContentAddressedV2Contract):
    """Exact validated text for one task-specific arm."""

    _id_field: ClassVar[str] = "variant_id"
    _id_prefix: ClassVar[str] = "variant_"

    variant_id: str = Field(pattern=_VARIANT_PATTERN)
    variant_prompt_id: str = Field(pattern=_VARIANT_PROMPT_PATTERN)
    arm_role: ArmRole
    prompt_text: str = Field(min_length=1, max_length=262_144, repr=False)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    validation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    validation_passed: Literal[True]

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @classmethod
    def from_text(
        cls,
        *,
        arm_role: ArmRole,
        prompt_text: str,
        validation_evidence_sha256: str,
    ) -> Self:
        try:
            prompt_sha256 = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
            variant_prompt_id = "variant_prompt_" + _digest(
                {"arm_role": arm_role.value, "prompt_sha256": prompt_sha256}
            )
            return cls.from_content(
                variant_prompt_id=variant_prompt_id,
                arm_role=arm_role,
                prompt_text=prompt_text,
                prompt_sha256=prompt_sha256,
                validation_evidence_sha256=validation_evidence_sha256,
                validation_passed=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_text_digest(self) -> Self:
        expected_sha256 = hashlib.sha256(self.prompt_text.encode("utf-8")).hexdigest()
        expected_prompt_id = "variant_prompt_" + _digest(
            {"arm_role": self.arm_role.value, "prompt_sha256": expected_sha256}
        )
        if self.prompt_sha256 != expected_sha256 or self.variant_prompt_id != expected_prompt_id:
            raise ValueError(self._safe_validation_message)
        return self


class TaskRealizationBundleRecord(_ContentAddressedV2Contract):
    """Complete task-specific arm texts for exactly one ``(h, i, r)``."""

    _id_field: ClassVar[str] = "task_realization_bundle_id"
    _id_prefix: ClassVar[str] = "task_realization_bundle_"

    task_realization_bundle_id: str = Field(pattern=_TASK_BUNDLE_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_PATTERN)
    candidate_skeleton_id: str = Field(pattern=_CANDIDATE_SKELETON_PATTERN)
    semantic_task_cluster_id: str
    task_instance_id: str
    realization_spec_id: str = Field(pattern=_REALIZATION_SPEC_PATTERN)
    operation: FeatureOperation
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    arms: tuple[TaskArmVariantBinding, ...] = Field(min_length=4, max_length=4)
    complete_arm_support: Literal[True]

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @classmethod
    def from_components(
        cls,
        *,
        hypothesis: FrozenPolicyHypothesisRecord,
        realization: RealizationSpecRecord,
        semantic_task_cluster_id: str,
        task_instance_id: str,
        source_prompt_id: str,
        source_prompt_sha256: str,
        arms: Sequence[TaskArmVariantBinding],
    ) -> Self:
        try:
            checked_hypothesis = FrozenPolicyHypothesisRecord.model_validate(
                hypothesis, strict=True
            )
            checked_realization = RealizationSpecRecord.model_validate(realization, strict=True)
            if (
                checked_realization.realization_spec_id
                not in checked_hypothesis.realization_spec_ids
                or checked_realization.candidate_skeleton_id
                != checked_hypothesis.candidate_skeleton_id
                or checked_realization.operation is not checked_hypothesis.operation
            ):
                raise ValueError
            return cls.from_content(
                hypothesis_id=checked_hypothesis.hypothesis_id,
                candidate_skeleton_id=checked_hypothesis.candidate_skeleton_id,
                semantic_task_cluster_id=semantic_task_cluster_id,
                task_instance_id=task_instance_id,
                realization_spec_id=checked_realization.realization_spec_id,
                operation=checked_hypothesis.operation,
                source_prompt_id=source_prompt_id,
                source_prompt_sha256=source_prompt_sha256,
                arms=tuple(arms),
                complete_arm_support=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        expected = _ADD_ARM_ORDER if self.operation is FeatureOperation.ADD else _REMOVE_ARM_ORDER
        if (
            not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.source_prompt_id)
            or tuple(item.arm_role for item in self.arms) != expected
        ):
            raise ValueError(self._safe_validation_message)
        return self


class TaskPolicySupportRecord(_ContentAddressedV2Contract):
    """Proof that one task retains the complete immutable support of ``Q_h``."""

    _id_field: ClassVar[str] = "task_policy_support_id"
    _id_prefix: ClassVar[str] = "task_policy_support_"

    task_policy_support_id: str = Field(pattern=_TASK_SUPPORT_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_PATTERN)
    semantic_task_cluster_id: str
    task_instance_id: str
    realization_policy_spec_id: str = Field(pattern=_REALIZATION_POLICY_PATTERN)
    realization_policy: RealizationPolicySpec
    k_r: StrictInt = Field(ge=1, le=32)
    realizations: tuple[RealizationSpecRecord, ...] = Field(min_length=1, max_length=32)
    task_realization_bundles: tuple[TaskRealizationBundleRecord, ...] = Field(
        min_length=1, max_length=32
    )
    realization_spec_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    task_realization_bundle_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    probability_numerators: tuple[StrictInt, ...] = Field(min_length=1, max_length=32)
    probability_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    full_support_passed: Literal[True]
    failure_policy: Literal["fail_closed_no_deletion_no_renormalization"]

    @classmethod
    def from_components(
        cls,
        *,
        hypothesis: FrozenPolicyHypothesisRecord,
        policy: RealizationPolicySpec,
        realizations: Sequence[RealizationSpecRecord],
        bundles: Sequence[TaskRealizationBundleRecord],
    ) -> Self:
        try:
            checked_hypothesis = FrozenPolicyHypothesisRecord.model_validate(
                hypothesis, strict=True
            )
            checked_policy = RealizationPolicySpec.model_validate(policy, strict=True)
            specs = tuple(realizations)
            task_bundles = tuple(bundles)
            if (
                checked_hypothesis.realization_policy_spec_id
                != checked_policy.realization_policy_spec_id
                or len(specs) != checked_policy.k_r
                or len(task_bundles) != checked_policy.k_r
                or tuple(item.realization_spec_id for item in specs)
                != checked_hypothesis.realization_spec_ids
                or tuple(item.realization_spec_id for item in task_bundles)
                != checked_hypothesis.realization_spec_ids
                or len({item.semantic_task_cluster_id for item in task_bundles}) != 1
                or len({item.task_instance_id for item in task_bundles}) != 1
                or any(
                    item.hypothesis_id != checked_hypothesis.hypothesis_id for item in task_bundles
                )
            ):
                raise ValueError
            return cls.from_content(
                hypothesis_id=checked_hypothesis.hypothesis_id,
                semantic_task_cluster_id=task_bundles[0].semantic_task_cluster_id,
                task_instance_id=task_bundles[0].task_instance_id,
                realization_policy_spec_id=checked_policy.realization_policy_spec_id,
                realization_policy=checked_policy,
                k_r=checked_policy.k_r,
                realizations=specs,
                task_realization_bundles=task_bundles,
                realization_spec_ids=checked_hypothesis.realization_spec_ids,
                task_realization_bundle_ids=tuple(
                    item.task_realization_bundle_id for item in task_bundles
                ),
                probability_numerators=checked_policy.probability_numerators,
                probability_denominator=checked_policy.probability_denominator,
                full_support_passed=True,
                failure_policy=checked_policy.failure_policy,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed contract boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        policy = self.realization_policy
        realization_ids = tuple(item.realization_spec_id for item in self.realizations)
        bundle_ids = tuple(
            item.task_realization_bundle_id for item in self.task_realization_bundles
        )
        if (
            not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or self.realization_policy_spec_id != policy.realization_policy_spec_id
            or self.k_r != policy.k_r
            or len(self.realization_spec_ids) != self.k_r
            or len(self.task_realization_bundle_ids) != self.k_r
            or len(self.probability_numerators) != self.k_r
            or len(self.realizations) != self.k_r
            or len(self.task_realization_bundles) != self.k_r
            or realization_ids != self.realization_spec_ids
            or bundle_ids != self.task_realization_bundle_ids
            or tuple(item.realization_index for item in self.realizations) != tuple(range(self.k_r))
            or tuple(item.realization_spec_id for item in self.task_realization_bundles)
            != self.realization_spec_ids
            or len(self.realization_spec_ids) != len(set(self.realization_spec_ids))
            or len(self.task_realization_bundle_ids) != len(set(self.task_realization_bundle_ids))
            or any(
                re.fullmatch(_REALIZATION_SPEC_PATTERN, item) is None
                for item in self.realization_spec_ids
            )
            or any(
                re.fullmatch(_TASK_BUNDLE_PATTERN, item) is None
                for item in self.task_realization_bundle_ids
            )
            or any(item <= 0 for item in self.probability_numerators)
            or sum(self.probability_numerators) != self.probability_denominator
            or self.probability_numerators != policy.probability_numerators
            or self.probability_denominator != policy.probability_denominator
            or self.failure_policy != policy.failure_policy
            or any(
                item.realization_policy_spec_id != policy.realization_policy_spec_id
                or item.probability_numerator
                != policy.probability_numerators[item.realization_index]
                or item.probability_denominator != policy.probability_denominator
                for item in self.realizations
            )
            or any(
                item.hypothesis_id != self.hypothesis_id
                or item.semantic_task_cluster_id != self.semantic_task_cluster_id
                or item.task_instance_id != self.task_instance_id
                for item in self.task_realization_bundles
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SemanticTaskClusterMembershipRecord(_ContentAddressedV2Contract):
    """One immutable task-to-highest-resampling-cluster membership."""

    _id_field: ClassVar[str] = "cluster_membership_id"
    _id_prefix: ClassVar[str] = "cluster_membership_"

    cluster_membership_id: str = Field(pattern=_CLUSTER_MEMBERSHIP_PATTERN)
    semantic_task_cluster_id: str
    task_instance_id: str
    split: PolicySplit
    cwe: str
    task_archetype: str
    source_task_sha256: str = Field(pattern=_SHA256_PATTERN)
    clustering_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    adjudication_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @field_validator("split", mode="before")
    @classmethod
    def parse_split(cls, value: object) -> object:
        return _exact_enum(value, PolicySplit)

    @model_validator(mode="after")
    def validate_membership(self) -> Self:
        if (
            not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or _CWE_RE.fullmatch(self.cwe) is None
            or not _valid_identifier(self.task_archetype)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SemanticTaskClusterManifest(_ContentAddressedV2Contract):
    """Content-addressed membership freeze; one cluster cannot cross data splits."""

    _id_field: ClassVar[str] = "semantic_cluster_manifest_id"
    _id_prefix: ClassVar[str] = "semantic_cluster_manifest_"

    semantic_cluster_manifest_id: str = Field(pattern=_CLUSTER_MANIFEST_PATTERN)
    memberships: tuple[SemanticTaskClusterMembershipRecord, ...] = Field(
        min_length=1, max_length=1_000_000
    )
    clustering_algorithm_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalization_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    construction_digest_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_before_discovery: Literal[True]

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        order = tuple(
            (item.semantic_task_cluster_id, item.task_instance_id) for item in self.memberships
        )
        task_ids = tuple(item.task_instance_id for item in self.memberships)
        cluster_splits: dict[str, set[PolicySplit]] = {}
        for item in self.memberships:
            cluster_splits.setdefault(item.semantic_task_cluster_id, set()).add(item.split)
        if (
            order != tuple(sorted(order))
            or len(task_ids) != len(set(task_ids))
            or any(len(splits) != 1 for splits in cluster_splits.values())
            or any(
                item.clustering_policy_sha256 != self.clustering_algorithm_sha256
                for item in self.memberships
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ConfirmationBlockKeyV2(_ContentAddressedV2Contract):
    """The canonical realization-aware eight-coordinate complete-block key."""

    _id_field: ClassVar[str] = "block_id"
    _id_prefix: ClassVar[str] = "block_"

    block_id: str = Field(pattern=_BLOCK_PATTERN)
    block_key_version: Literal["confirmation-block-key-v2"]
    semantic_task_cluster_id: str
    task_instance_id: str
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_PATTERN)
    realization_spec_id: str = Field(pattern=_REALIZATION_SPEC_PATTERN)
    task_realization_bundle_id: str = Field(pattern=_TASK_BUNDLE_PATTERN)
    model_id: str
    arm_protocol_id: str = Field(pattern=_ARM_PROTOCOL_PATTERN)

    @classmethod
    def from_coordinates(
        cls,
        *,
        semantic_task_cluster_id: str,
        task_instance_id: str,
        hypothesis_id: str,
        target_spec_id: str,
        realization_spec_id: str,
        task_realization_bundle_id: str,
        model_id: str,
        arm_protocol_id: str,
    ) -> Self:
        return cls.from_content(
            block_key_version="confirmation-block-key-v2",
            semantic_task_cluster_id=semantic_task_cluster_id,
            task_instance_id=task_instance_id,
            hypothesis_id=hypothesis_id,
            target_spec_id=target_spec_id,
            realization_spec_id=realization_spec_id,
            task_realization_bundle_id=task_realization_bundle_id,
            model_id=model_id,
            arm_protocol_id=arm_protocol_id,
        )

    @model_validator(mode="after")
    def validate_coordinates(self) -> Self:
        if (
            not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or not is_valid_model_id(self.model_id)
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "POLICY_V2_SCHEMA_VERSION",
    "ActionableFeatureQueryResultRecord",
    "ActionableFeatureSpec",
    "BridgeStatus",
    "CandidateSkeleton",
    "CandidateUniverseManifest",
    "ConfirmationBlockKeyV2",
    "ContextQueryResultRecord",
    "ContextQuerySpec",
    "EligibilityExclusionReason",
    "ExpectedDirection",
    "FrozenPolicyHypothesisRecord",
    "GlobalArmExecutionSpec",
    "PolicySplit",
    "PreOutcomeEligibilityRecord",
    "QueryState",
    "RealizationPolicySpec",
    "RealizationSpecRecord",
    "SelectionFreezeManifest",
    "SelectionMappingRecord",
    "SelectorSlotRecord",
    "SelectorSlotStatus",
    "SemanticTaskClusterManifest",
    "SemanticTaskClusterMembershipRecord",
    "TaskArmVariantBinding",
    "TaskPolicySupportRecord",
    "TaskRealizationBundleRecord",
]

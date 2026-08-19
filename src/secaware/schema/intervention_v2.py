"""Selector-invariant v2 intervention bridge and four-arm protocol contracts.

The prospective policy schema freezes candidate semantics and realization support.
This module closes the next boundary: it proves that exactly one actionable feature
becomes a target, that the four randomized arms have operation-appropriate meanings,
and that the final hypothesis is produced without selector/rank metadata.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum, StrEnum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.policy_v2 import (
    ActionableFeatureSpec,
    CandidateSkeleton,
    FrozenPolicyHypothesisRecord,
    RealizationPolicySpec,
    RealizationSpecRecord,
)

INTERVENTION_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_TARGET_PATTERN = r"^target_[0-9a-f]{64}$"
_ARM_PROTOCOL_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_BRIDGE_PATTERN = r"^intervention_bridge_[0-9a-f]{64}$"

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


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _exact_enum(value: object, enum_type: type[Enum]) -> object:
    if type(value) is enum_type:
        return value
    if type(value) is str:
        return next((item for item in enum_type if item.value == value), value)
    return value


class _InterventionV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message = "intervention v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = INTERVENTION_V2_SCHEMA_VERSION

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedInterventionV2(_InterventionV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": INTERVENTION_V2_SCHEMA_VERSION, **content}
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            content.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class ArmSemanticRoleV2(StrEnum):
    TARGET_POLICY = "target_policy"
    NO_OP_CONTROL = "no_op_control"
    LENGTH_MATCHED_CONTROL = "length_matched_control"
    GENERIC_SECURITY_CONTROL = "generic_security_control"


class TargetSourceStateRuleV2(StrEnum):
    ADD_RESOLVED_ABSENT = "add_resolved_absent"
    REMOVE_PROVENANCE_BOUND_PRESENT_WITH_NEUTRAL_COUNTERPART = (
        "remove_provenance_bound_present_with_neutral_counterpart"
    )


_SEMANTIC_ROLE_ORDER = (
    ArmSemanticRoleV2.TARGET_POLICY,
    ArmSemanticRoleV2.NO_OP_CONTROL,
    ArmSemanticRoleV2.LENGTH_MATCHED_CONTROL,
    ArmSemanticRoleV2.GENERIC_SECURITY_CONTROL,
)


class TargetSpecV2(_ContentAddressedInterventionV2):
    """Exactly one editable feature and its frozen extractor-relative invariants."""

    _id_field = "target_spec_id"
    _id_prefix = "target_"

    target_spec_id: str = Field(pattern=_TARGET_PATTERN)
    candidate_skeleton_id: str
    context_query_id: str
    actionable_feature_spec_id: str
    feature_id: str
    operation: FeatureOperation
    outcome_id: str
    expected_direction: str
    source_state_rule: TargetSourceStateRuleV2
    allowed_delta_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_projection_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_projection_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    non_target_projection_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    security_neutrality_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    one_actionable_leaf: Literal[True]
    task_context_immutable: Literal[True]
    frozen_before_variant_generation: Literal[True]

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @field_validator("source_state_rule", mode="before")
    @classmethod
    def parse_source_rule(cls, value: object) -> object:
        return _exact_enum(value, TargetSourceStateRuleV2)

    @classmethod
    def from_components(
        cls,
        *,
        skeleton: CandidateSkeleton,
        actionable_feature: ActionableFeatureSpec,
        allowed_delta_policy_sha256: str,
        task_projection_policy_sha256: str,
        context_projection_policy_sha256: str,
        non_target_projection_policy_sha256: str,
        security_neutrality_policy_sha256: str,
    ) -> Self:
        try:
            candidate = CandidateSkeleton.model_validate(skeleton, strict=True)
            feature = ActionableFeatureSpec.model_validate(actionable_feature, strict=True)
            if (
                candidate.actionable_feature_spec_id != feature.actionable_feature_spec_id
                or candidate.feature_id != feature.feature_id
                or candidate.operation not in feature.allowed_operations
                or candidate.feature_catalog_sha256 != feature.feature_catalog_sha256
            ):
                raise ValueError
            source_rule = (
                TargetSourceStateRuleV2.ADD_RESOLVED_ABSENT
                if candidate.operation is FeatureOperation.ADD
                else TargetSourceStateRuleV2.REMOVE_PROVENANCE_BOUND_PRESENT_WITH_NEUTRAL_COUNTERPART
            )
            return cls.from_content(
                candidate_skeleton_id=candidate.candidate_skeleton_id,
                context_query_id=candidate.context_query_id,
                actionable_feature_spec_id=feature.actionable_feature_spec_id,
                feature_id=feature.feature_id,
                operation=candidate.operation,
                outcome_id=candidate.outcome_id,
                expected_direction=candidate.expected_direction.value,
                source_state_rule=source_rule,
                allowed_delta_policy_sha256=allowed_delta_policy_sha256,
                task_projection_policy_sha256=task_projection_policy_sha256,
                context_projection_policy_sha256=context_projection_policy_sha256,
                non_target_projection_policy_sha256=non_target_projection_policy_sha256,
                security_neutrality_policy_sha256=security_neutrality_policy_sha256,
                one_actionable_leaf=True,
                task_context_immutable=True,
                frozen_before_variant_generation=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        expected_rule = (
            TargetSourceStateRuleV2.ADD_RESOLVED_ABSENT
            if self.operation is FeatureOperation.ADD
            else TargetSourceStateRuleV2.REMOVE_PROVENANCE_BOUND_PRESENT_WITH_NEUTRAL_COUNTERPART
        )
        if (
            not _valid_identifier(self.candidate_skeleton_id)
            or not _valid_identifier(self.context_query_id)
            or not _valid_identifier(self.actionable_feature_spec_id)
            or not _valid_identifier(self.feature_id)
            or not _valid_identifier(self.outcome_id)
            or self.expected_direction not in {"positive", "negative"}
            or self.source_state_rule is not expected_rule
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ArmDefinitionV2(_InterventionV2Contract):
    arm_index: StrictInt = Field(ge=0, le=3)
    arm_role: ArmRole
    semantic_role: ArmSemanticRoleV2
    realization_requirement_sha256: str = Field(pattern=_SHA256_PATTERN)
    validation_requirement_sha256: str = Field(pattern=_SHA256_PATTERN)
    assignment_probability_numerator: StrictInt = Field(ge=1, le=2**31 - 1)

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @field_validator("semantic_role", mode="before")
    @classmethod
    def parse_semantic_role(cls, value: object) -> object:
        return _exact_enum(value, ArmSemanticRoleV2)


class ArmProtocolV2(_ContentAddressedInterventionV2):
    """The complete four-arm design; diagnostics never change assigned-arm ITT."""

    _id_field = "arm_protocol_id"
    _id_prefix = "arm_protocol_"

    arm_protocol_id: str = Field(pattern=_ARM_PROTOCOL_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_PATTERN)
    operation: FeatureOperation
    arms: tuple[ArmDefinitionV2, ...] = Field(min_length=4, max_length=4)
    assignment_probability_denominator: StrictInt = Field(ge=4, le=2**31 - 1)
    primary_contrast: tuple[ArmRole, ArmRole]
    specificity_contrasts: tuple[tuple[ArmRole, ArmRole], ...] = Field(min_length=2, max_length=2)
    assigned_arm_itt_required: Literal[True]
    target_changed_is_diagnostic_only: Literal[True]
    semantic_validity_is_diagnostic_only: Literal[True]
    infrastructure_failure_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    retry_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_before_randomization: Literal[True]

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @classmethod
    def from_target(
        cls,
        *,
        target: TargetSpecV2,
        realization_requirement_sha256: tuple[str, str, str, str],
        validation_requirement_sha256: tuple[str, str, str, str],
        assignment_probability_numerators: tuple[int, int, int, int],
        assignment_probability_denominator: int,
        infrastructure_failure_policy_sha256: str,
        retry_policy_sha256: str,
    ) -> Self:
        try:
            checked = TargetSpecV2.model_validate(target, strict=True)
            role_order = (
                _ADD_ARM_ORDER if checked.operation is FeatureOperation.ADD else _REMOVE_ARM_ORDER
            )
            if (
                len(realization_requirement_sha256) != 4
                or len(validation_requirement_sha256) != 4
                or len(assignment_probability_numerators) != 4
                or any(value <= 0 for value in assignment_probability_numerators)
                or sum(assignment_probability_numerators) != assignment_probability_denominator
            ):
                raise ValueError
            arms = tuple(
                ArmDefinitionV2(
                    schema_version=INTERVENTION_V2_SCHEMA_VERSION,
                    arm_index=index,
                    arm_role=role,
                    semantic_role=_SEMANTIC_ROLE_ORDER[index],
                    realization_requirement_sha256=realization_requirement_sha256[index],
                    validation_requirement_sha256=validation_requirement_sha256[index],
                    assignment_probability_numerator=assignment_probability_numerators[index],
                )
                for index, role in enumerate(role_order)
            )
            return cls.from_content(
                target_spec_id=checked.target_spec_id,
                operation=checked.operation,
                arms=arms,
                assignment_probability_denominator=assignment_probability_denominator,
                primary_contrast=(role_order[0], role_order[1]),
                specificity_contrasts=(
                    (role_order[0], role_order[2]),
                    (role_order[0], role_order[3]),
                ),
                assigned_arm_itt_required=True,
                target_changed_is_diagnostic_only=True,
                semantic_validity_is_diagnostic_only=True,
                infrastructure_failure_policy_sha256=infrastructure_failure_policy_sha256,
                retry_policy_sha256=retry_policy_sha256,
                frozen_before_randomization=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        role_order = _ADD_ARM_ORDER if self.operation is FeatureOperation.ADD else _REMOVE_ARM_ORDER
        if (
            tuple(item.arm_index for item in self.arms) != tuple(range(4))
            or tuple(item.arm_role for item in self.arms) != role_order
            or tuple(item.semantic_role for item in self.arms) != _SEMANTIC_ROLE_ORDER
            or sum(item.assignment_probability_numerator for item in self.arms)
            != self.assignment_probability_denominator
            or self.primary_contrast != (role_order[0], role_order[1])
            or self.specificity_contrasts
            != ((role_order[0], role_order[2]), (role_order[0], role_order[3]))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class InterventionBridgeRecordV2(_ContentAddressedInterventionV2):
    """Complete selector-invariant bridge from one skeleton to one final hypothesis."""

    _id_field = "intervention_bridge_id"
    _id_prefix = "intervention_bridge_"

    intervention_bridge_id: str = Field(pattern=_BRIDGE_PATTERN)
    candidate_skeleton: CandidateSkeleton
    actionable_feature: ActionableFeatureSpec
    realization_policy: RealizationPolicySpec
    realizations: tuple[RealizationSpecRecord, ...] = Field(min_length=1, max_length=32)
    target_spec: TargetSpecV2
    arm_protocol: ArmProtocolV2
    frozen_hypothesis: FrozenPolicyHypothesisRecord
    bridge_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    selector_invariant: Literal[True]
    outcome_blind: Literal[True]
    frozen_before_confirmation_outcomes: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        skeleton: CandidateSkeleton,
        actionable_feature: ActionableFeatureSpec,
        realization_policy: RealizationPolicySpec,
        realizations: tuple[RealizationSpecRecord, ...],
        target_spec: TargetSpecV2,
        arm_protocol: ArmProtocolV2,
        bridge_policy_sha256: str,
    ) -> Self:
        try:
            candidate = CandidateSkeleton.model_validate(skeleton, strict=True)
            feature = ActionableFeatureSpec.model_validate(actionable_feature, strict=True)
            policy = RealizationPolicySpec.model_validate(realization_policy, strict=True)
            specs = tuple(
                RealizationSpecRecord.model_validate(item, strict=True) for item in realizations
            )
            target = TargetSpecV2.model_validate(target_spec, strict=True)
            protocol = ArmProtocolV2.model_validate(arm_protocol, strict=True)
            if (
                target.candidate_skeleton_id != candidate.candidate_skeleton_id
                or target.actionable_feature_spec_id != feature.actionable_feature_spec_id
                or protocol.target_spec_id != target.target_spec_id
                or protocol.operation is not candidate.operation
            ):
                raise ValueError
            hypothesis = FrozenPolicyHypothesisRecord.from_components(
                skeleton=candidate,
                policy=policy,
                realizations=specs,
                target_spec_id=target.target_spec_id,
                arm_protocol_id=protocol.arm_protocol_id,
                bridge_policy_sha256=bridge_policy_sha256,
            )
            return cls.from_content(
                candidate_skeleton=candidate,
                actionable_feature=feature,
                realization_policy=policy,
                realizations=specs,
                target_spec=target,
                arm_protocol=protocol,
                frozen_hypothesis=hypothesis,
                bridge_policy_sha256=bridge_policy_sha256,
                selector_invariant=True,
                outcome_blind=True,
                frozen_before_confirmation_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_bridge(self) -> Self:
        candidate = self.candidate_skeleton
        feature = self.actionable_feature
        policy = self.realization_policy
        target = self.target_spec
        protocol = self.arm_protocol
        hypothesis = self.frozen_hypothesis
        realization_ids = tuple(item.realization_spec_id for item in self.realizations)
        if (
            candidate.actionable_feature_spec_id != feature.actionable_feature_spec_id
            or candidate.feature_id != feature.feature_id
            or candidate.operation not in feature.allowed_operations
            or candidate.realization_policy_spec_id != policy.realization_policy_spec_id
            or target.candidate_skeleton_id != candidate.candidate_skeleton_id
            or target.context_query_id != candidate.context_query_id
            or target.actionable_feature_spec_id != candidate.actionable_feature_spec_id
            or target.feature_id != candidate.feature_id
            or target.operation is not candidate.operation
            or target.outcome_id != candidate.outcome_id
            or protocol.target_spec_id != target.target_spec_id
            or protocol.operation is not candidate.operation
            or hypothesis.candidate_skeleton_id != candidate.candidate_skeleton_id
            or hypothesis.target_spec_id != target.target_spec_id
            or hypothesis.arm_protocol_id != protocol.arm_protocol_id
            or hypothesis.realization_policy_spec_id != policy.realization_policy_spec_id
            or hypothesis.realization_spec_ids != realization_ids
            or hypothesis.bridge_policy_sha256 != self.bridge_policy_sha256
            or len(realization_ids) != policy.k_r
            or tuple(item.realization_index for item in self.realizations)
            != tuple(range(policy.k_r))
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "INTERVENTION_V2_SCHEMA_VERSION",
    "ArmDefinitionV2",
    "ArmProtocolV2",
    "ArmSemanticRoleV2",
    "InterventionBridgeRecordV2",
    "TargetSourceStateRuleV2",
    "TargetSpecV2",
]

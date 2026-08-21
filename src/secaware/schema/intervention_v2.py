"""Selector-invariant v2 intervention bridge and four-arm protocol contracts.

The prospective policy schema freezes candidate semantics and realization support.
This module closes the next boundary: it proves that exactly one actionable feature
becomes a target, that the four randomized arms have operation-appropriate meanings,
and that the final hypothesis is produced without selector/rank metadata.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from secaware.records import (
    ContentAddressedResearchRecord,
    FrozenResearchRecord,
    parse_exact_enum as _exact_enum,
    valid_identifier as _valid_identifier,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.schema.policy_v2 import (
    ActionableFeatureSpec,
    CandidateSkeleton,
    ContextQuerySpec,
    FrozenPolicyHypothesisRecord,
    RealizationPolicySpec,
    RealizationSpecRecord,
)
from secaware.schema.tsg import NodeType

INTERVENTION_V2_SCHEMA_VERSION = "2.1"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
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


class _InterventionV2Contract(FrozenResearchRecord):
    _safe_validation_message = "intervention v2 contract failed validation"
    schema_version: Literal["2.1"] = INTERVENTION_V2_SCHEMA_VERSION


class _ContentAddressedInterventionV2(ContentAddressedResearchRecord):
    _safe_validation_message = "intervention v2 contract failed validation"
    _schema_version = INTERVENTION_V2_SCHEMA_VERSION
    schema_version: Literal["2.1"] = INTERVENTION_V2_SCHEMA_VERSION


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


def _canonical_target_binding(
    *,
    context_query: ContextQuerySpec,
    actionable_feature: ActionableFeatureSpec,
    cwe: str,
    task_archetype: str,
    operation: FeatureOperation,
) -> tuple[ContextQuerySpec, ActionableFeatureSpec, tuple[str, ...]]:
    """Resolve the exact reviewed context and editable security leaf or fail closed."""

    try:
        from secaware.tsg.context_queries_v2 import (
            context_query_definition,
            context_query_spec,
        )
        from secaware.tsg.feature_catalog import (
            PROMPT_FEATURE_CATALOG_SHA256,
            prompt_feature_spec,
        )

        context = ContextQuerySpec.model_validate(context_query, strict=True)
        feature = ActionableFeatureSpec.model_validate(actionable_feature, strict=True)
        canonical_context = context_query_spec(context.query_name)
        definition = context_query_definition(context.query_name)
        catalog_feature = prompt_feature_spec(feature.feature_id)
        read_feature_ids = (definition.task_feature_id,)
        if (
            context != canonical_context
            or context.context_query_catalog_sha256
            != canonical_context.context_query_catalog_sha256
            or context.query_semantics_version != canonical_context.query_semantics_version
            or cwe not in context.applicable_cwes
            or task_archetype not in context.applicable_task_archetypes
            or feature.feature_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or catalog_feature.feature_family is not FeatureFamily.SAFETY_CONTROL
            or not catalog_feature.intervenable
            or NodeType.GUARD not in catalog_feature.structural_node_types
            or operation not in catalog_feature.operations
            or operation not in feature.allowed_operations
            or not set(feature.allowed_operations) <= set(catalog_feature.operations)
            or cwe not in catalog_feature.applicable_cwes
            or feature.feature_id in read_feature_ids
        ):
            raise ValueError
        return context, feature, read_feature_ids
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 - sanitize catalog/registry boundary failures
        raise ValueError(
            "intervention target is not a canonical context/security-leaf binding"
        ) from None


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
    context_query: ContextQuerySpec
    context_query_id: str
    context_read_feature_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    actionable_feature: ActionableFeatureSpec
    actionable_feature_spec_id: str
    feature_id: str
    operation: FeatureOperation
    outcome_id: str
    expected_direction: str
    cwe: str
    task_archetype: str
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

    @field_validator("context_read_feature_ids", mode="before")
    @classmethod
    def snapshot_context_read_feature_ids(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @classmethod
    def from_components(
        cls,
        *,
        skeleton: CandidateSkeleton,
        context_query: ContextQuerySpec,
        actionable_feature: ActionableFeatureSpec,
        allowed_delta_policy_sha256: str,
        task_projection_policy_sha256: str,
        context_projection_policy_sha256: str,
        non_target_projection_policy_sha256: str,
        security_neutrality_policy_sha256: str,
    ) -> Self:
        try:
            candidate = CandidateSkeleton.model_validate(skeleton, strict=True)
            context, feature, read_feature_ids = _canonical_target_binding(
                context_query=context_query,
                actionable_feature=actionable_feature,
                cwe=candidate.cwe,
                task_archetype=candidate.task_archetype,
                operation=candidate.operation,
            )
            if (
                candidate.context_query_id != context.context_query_id
                or candidate.actionable_feature_spec_id != feature.actionable_feature_spec_id
                or candidate.feature_id != feature.feature_id
                or candidate.operation not in feature.allowed_operations
                or candidate.feature_catalog_sha256 != feature.feature_catalog_sha256
                or candidate.context_query_catalog_sha256 != context.context_query_catalog_sha256
            ):
                raise ValueError
            source_rule = (
                TargetSourceStateRuleV2.ADD_RESOLVED_ABSENT
                if candidate.operation is FeatureOperation.ADD
                else TargetSourceStateRuleV2.REMOVE_PROVENANCE_BOUND_PRESENT_WITH_NEUTRAL_COUNTERPART
            )
            return cls.from_content(
                candidate_skeleton_id=candidate.candidate_skeleton_id,
                context_query=context,
                context_query_id=candidate.context_query_id,
                context_read_feature_ids=read_feature_ids,
                actionable_feature=feature,
                actionable_feature_spec_id=feature.actionable_feature_spec_id,
                feature_id=feature.feature_id,
                operation=candidate.operation,
                outcome_id=candidate.outcome_id,
                expected_direction=candidate.expected_direction.value,
                cwe=candidate.cwe,
                task_archetype=candidate.task_archetype,
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
        try:
            context, feature, read_feature_ids = _canonical_target_binding(
                context_query=self.context_query,
                actionable_feature=self.actionable_feature,
                cwe=self.cwe,
                task_archetype=self.task_archetype,
                operation=self.operation,
            )
        except ValueError:
            raise ValueError(self._safe_validation_message) from None
        expected_rule = (
            TargetSourceStateRuleV2.ADD_RESOLVED_ABSENT
            if self.operation is FeatureOperation.ADD
            else TargetSourceStateRuleV2.REMOVE_PROVENANCE_BOUND_PRESENT_WITH_NEUTRAL_COUNTERPART
        )
        if (
            not _valid_identifier(self.candidate_skeleton_id)
            or self.context_query != context
            or self.context_query_id != context.context_query_id
            or self.context_read_feature_ids != read_feature_ids
            or self.actionable_feature != feature
            or not _valid_identifier(self.actionable_feature_spec_id)
            or self.actionable_feature_spec_id != feature.actionable_feature_spec_id
            or not _valid_identifier(self.feature_id)
            or self.feature_id != feature.feature_id
            or not _valid_identifier(self.outcome_id)
            or not _valid_identifier(self.task_archetype)
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

    @field_validator("arms", mode="before")
    @classmethod
    def snapshot_arms(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        return tuple(
            item
            if type(item) is ArmDefinitionV2
            else ArmDefinitionV2.model_validate(item, strict=True)
            for item in value
        )

    @field_validator("primary_contrast", mode="before")
    @classmethod
    def parse_primary_contrast(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        return tuple(_exact_enum(item, ArmRole) for item in value)

    @field_validator("specificity_contrasts", mode="before")
    @classmethod
    def parse_specificity_contrasts(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        parsed = []
        for contrast in value:
            if type(contrast) not in {tuple, list}:
                return value
            parsed.append(tuple(_exact_enum(item, ArmRole) for item in contrast))
        return tuple(parsed)

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
    context_query: ContextQuerySpec
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

    @field_validator("realizations", mode="before")
    @classmethod
    def snapshot_realizations(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        return tuple(
            item
            if type(item) is RealizationSpecRecord
            else RealizationSpecRecord.model_validate(item, strict=True)
            for item in value
        )

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
                or target.context_query_id != candidate.context_query_id
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
                context_query=target.context_query,
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
        context = self.context_query
        feature = self.actionable_feature
        policy = self.realization_policy
        target = self.target_spec
        protocol = self.arm_protocol
        hypothesis = self.frozen_hypothesis
        realization_ids = tuple(item.realization_spec_id for item in self.realizations)
        if (
            candidate.actionable_feature_spec_id != feature.actionable_feature_spec_id
            or candidate.context_query_id != context.context_query_id
            or candidate.context_query_catalog_sha256 != context.context_query_catalog_sha256
            or candidate.feature_id != feature.feature_id
            or candidate.operation not in feature.allowed_operations
            or candidate.realization_policy_spec_id != policy.realization_policy_spec_id
            or target.candidate_skeleton_id != candidate.candidate_skeleton_id
            or target.context_query != context
            or target.context_query_id != candidate.context_query_id
            or target.cwe != candidate.cwe
            or target.task_archetype != candidate.task_archetype
            or target.actionable_feature != feature
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

"""Typed pre-randomization failure provenance for task realization bundles.

The successful-variant manifest deliberately contains only complete retained
task support.  This companion artifact explains every otherwise-eligible task
that was atomically excluded because at least one required realization/arm
could not pass the frozen Prompt-variant validation pipeline.  It never deletes
or renormalizes a realization and it never treats the failed task as an
assigned experimental unit.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import Field, field_validator, model_validator

from secaware.records import SnapshotContentAddressedResearchRecord, parse_exact_enum as _exact_enum
from secaware.schema.experiments import ArmRole
from secaware.schema.intervention_v2 import InterventionBridgeRecordV2
from secaware.schema.policy_v2 import RealizationSpecRecord
from secaware.schema.population_v2 import PopulationFreezeManifestV2
from secaware.schema.query_evidence_v2 import (
    QueryEvidenceManifestV2,
    QueryEvidenceTaskRecordV2,
)

VARIANT_FAILURE_EVIDENCE_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_RECEIPT_ID_PATTERN = r"^task_bundle_failure_receipt_v2_[0-9a-f]{64}$"
_MANIFEST_ID_PATTERN = r"^variant_failure_evidence_manifest_v2_[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,1023}$")


class VariantBundleFailureStageV2(StrEnum):
    RENDERER = "renderer"
    BLIND_REEXTRACTION = "blind_reextraction"
    TSG_BUILD = "tsg_build"
    CONTEXT_QUERY = "context_query"
    ACTIONABLE_QUERY = "actionable_query"
    ALLOWED_DELTA = "allowed_delta"
    TASK_INVARIANT = "task_invariant"
    NON_TARGET_SAFETY = "non_target_safety"
    LENGTH_MATCH = "length_match"
    BUNDLE_ASSEMBLY = "bundle_assembly"


class VariantBundleFailureReasonV2(StrEnum):
    RENDERER_REJECTED = "renderer_rejected"
    EXTRACTION_UNRESOLVED = "extraction_unresolved"
    GRAPH_INVALID = "graph_invalid"
    CONTEXT_DRIFT = "context_drift"
    ACTIONABLE_STATE_UNRESOLVED = "actionable_state_unresolved"
    TARGET_DELTA_INVALID = "target_delta_invalid"
    TASK_DRIFT = "task_drift"
    NON_TARGET_SAFETY_DRIFT = "non_target_safety_drift"
    LENGTH_MATCH_FAILED = "length_match_failed"
    ARM_BUNDLE_INCOMPLETE = "arm_bundle_incomplete"


_STAGE_REASON = {
    VariantBundleFailureStageV2.RENDERER: VariantBundleFailureReasonV2.RENDERER_REJECTED,
    VariantBundleFailureStageV2.BLIND_REEXTRACTION: (
        VariantBundleFailureReasonV2.EXTRACTION_UNRESOLVED
    ),
    VariantBundleFailureStageV2.TSG_BUILD: VariantBundleFailureReasonV2.GRAPH_INVALID,
    VariantBundleFailureStageV2.CONTEXT_QUERY: VariantBundleFailureReasonV2.CONTEXT_DRIFT,
    VariantBundleFailureStageV2.ACTIONABLE_QUERY: (
        VariantBundleFailureReasonV2.ACTIONABLE_STATE_UNRESOLVED
    ),
    VariantBundleFailureStageV2.ALLOWED_DELTA: (VariantBundleFailureReasonV2.TARGET_DELTA_INVALID),
    VariantBundleFailureStageV2.TASK_INVARIANT: VariantBundleFailureReasonV2.TASK_DRIFT,
    VariantBundleFailureStageV2.NON_TARGET_SAFETY: (
        VariantBundleFailureReasonV2.NON_TARGET_SAFETY_DRIFT
    ),
    VariantBundleFailureStageV2.LENGTH_MATCH: (VariantBundleFailureReasonV2.LENGTH_MATCH_FAILED),
    VariantBundleFailureStageV2.BUNDLE_ASSEMBLY: (
        VariantBundleFailureReasonV2.ARM_BUNDLE_INCOMPLETE
    ),
}


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


class _ContentAddressedVariantFailureEvidenceV2(SnapshotContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = (
        "variant failure evidence v2 contract failed validation"
    )
    _schema_version = VARIANT_FAILURE_EVIDENCE_V2_SCHEMA_VERSION
    schema_version: Literal["2.0"] = VARIANT_FAILURE_EVIDENCE_V2_SCHEMA_VERSION


class TaskBundleFailureReceiptV2(_ContentAddressedVariantFailureEvidenceV2):
    """One typed failed attempt for an otherwise eligible task/r/arm."""

    _id_field = "task_bundle_failure_receipt_id"
    _id_prefix = "task_bundle_failure_receipt_v2_"

    task_bundle_failure_receipt_id: str = Field(pattern=_RECEIPT_ID_PATTERN)
    query_evidence_task_id: str
    semantic_task_cluster_id: str
    task_instance_id: str
    hypothesis_id: str
    realization_spec_id: str
    arm_role: ArmRole
    failure_stage: VariantBundleFailureStageV2
    failure_reason: VariantBundleFailureReasonV2
    producer_id: str
    producer_version: str
    producer_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    attempt_sha256: str = Field(pattern=_SHA256_PATTERN)
    attempted_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    diagnostic_sha256: str = Field(pattern=_SHA256_PATTERN)
    pre_randomization: Literal[True]
    generated_code_absent: Literal[True]
    task_atomic_exclusion_required: Literal[True]
    realization_deletion_or_renormalization_forbidden: Literal[True]

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @field_validator("failure_stage", mode="before")
    @classmethod
    def parse_failure_stage(cls, value: object) -> object:
        return _exact_enum(value, VariantBundleFailureStageV2)

    @field_validator("failure_reason", mode="before")
    @classmethod
    def parse_failure_reason(cls, value: object) -> object:
        return _exact_enum(value, VariantBundleFailureReasonV2)

    @classmethod
    def from_failure(
        cls,
        *,
        source_query_evidence: QueryEvidenceTaskRecordV2,
        intervention_bridge: InterventionBridgeRecordV2,
        realization: RealizationSpecRecord,
        arm_role: ArmRole,
        failure_stage: VariantBundleFailureStageV2,
        failure_reason: VariantBundleFailureReasonV2,
        producer_id: str,
        producer_version: str,
        producer_policy_sha256: str,
        attempt_sha256: str,
        attempted_prompt_sha256: str | None,
        diagnostic_sha256: str,
    ) -> Self:
        try:
            source = QueryEvidenceTaskRecordV2.model_validate(source_query_evidence, strict=True)
            bridge = InterventionBridgeRecordV2.model_validate(intervention_bridge, strict=True)
            checked_realization = RealizationSpecRecord.model_validate(realization, strict=True)
            checked_arm = ArmRole(arm_role)
            checked_stage = VariantBundleFailureStageV2(failure_stage)
            checked_reason = VariantBundleFailureReasonV2(failure_reason)
            if (
                not source.eligibility.eligible
                or checked_realization not in bridge.realizations
                or checked_arm not in tuple(item.arm_role for item in bridge.arm_protocol.arms)
                or _STAGE_REASON[checked_stage] is not checked_reason
            ):
                raise ValueError
            return cls.from_content(
                query_evidence_task_id=source.query_evidence_task_id,
                semantic_task_cluster_id=source.membership.semantic_task_cluster_id,
                task_instance_id=source.membership.task_instance_id,
                hypothesis_id=bridge.frozen_hypothesis.hypothesis_id,
                realization_spec_id=checked_realization.realization_spec_id,
                arm_role=checked_arm,
                failure_stage=checked_stage,
                failure_reason=checked_reason,
                producer_id=producer_id,
                producer_version=producer_version,
                producer_policy_sha256=producer_policy_sha256,
                attempt_sha256=attempt_sha256,
                attempted_prompt_sha256=attempted_prompt_sha256,
                diagnostic_sha256=diagnostic_sha256,
                pre_randomization=True,
                generated_code_absent=True,
                task_atomic_exclusion_required=True,
                realization_deletion_or_renormalization_forbidden=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the failure receipt boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        if (
            not _valid_identifier(self.query_evidence_task_id)
            or not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.hypothesis_id)
            or not _valid_identifier(self.realization_spec_id)
            or not _valid_identifier(self.producer_id)
            or not _valid_identifier(self.producer_version)
            or _STAGE_REASON[self.failure_stage] is not self.failure_reason
            or (
                self.failure_stage is VariantBundleFailureStageV2.RENDERER
                and self.attempted_prompt_sha256 is not None
            )
            or (
                self.failure_stage is not VariantBundleFailureStageV2.RENDERER
                and self.attempted_prompt_sha256 is None
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class VariantFailureEvidenceManifestV2(_ContentAddressedVariantFailureEvidenceV2):
    """Exact failed-task coverage for one frozen population and bridge."""

    _id_field = "variant_failure_evidence_manifest_id"
    _id_prefix = "variant_failure_evidence_manifest_v2_"

    variant_failure_evidence_manifest_id: str = Field(pattern=_MANIFEST_ID_PATTERN)
    intervention_bridge: InterventionBridgeRecordV2
    query_evidence: QueryEvidenceManifestV2
    population: PopulationFreezeManifestV2
    failure_receipts: tuple[TaskBundleFailureReceiptV2, ...]
    eligible_task_ids: tuple[str, ...] = Field(min_length=1)
    retained_task_ids: tuple[str, ...] = Field(min_length=1)
    excluded_eligible_task_ids: tuple[str, ...]
    failed_task_ids: tuple[str, ...]
    failure_receipt_count: int = Field(ge=0, le=1_000_000)
    complete_failed_task_coverage: Literal[True]
    retained_tasks_have_no_failure_receipt: Literal[True]
    no_partial_realization_salvage: Literal[True]
    frozen_before_randomization: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        intervention_bridge: InterventionBridgeRecordV2,
        query_evidence: QueryEvidenceManifestV2,
        population: PopulationFreezeManifestV2,
        failure_receipts: tuple[TaskBundleFailureReceiptV2, ...],
    ) -> Self:
        try:
            bridge = InterventionBridgeRecordV2.model_validate(intervention_bridge, strict=True)
            query = QueryEvidenceManifestV2.model_validate(query_evidence, strict=True)
            checked_population = PopulationFreezeManifestV2.model_validate(population, strict=True)
            realization_index = {
                item.realization_spec_id: item.realization_index for item in bridge.realizations
            }
            arm_index = {item.arm_role: item.arm_index for item in bridge.arm_protocol.arms}
            receipts = tuple(
                sorted(
                    (
                        TaskBundleFailureReceiptV2.model_validate(item, strict=True)
                        for item in failure_receipts
                    ),
                    key=lambda item: (
                        item.task_instance_id,
                        realization_index.get(item.realization_spec_id, 2**31 - 1),
                        arm_index.get(item.arm_role, 2**31 - 1),
                        item.failure_stage.value,
                        item.failure_reason.value,
                        item.attempt_sha256,
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
            return cls.from_content(
                intervention_bridge=bridge,
                query_evidence=query,
                population=checked_population,
                failure_receipts=receipts,
                eligible_task_ids=eligible,
                retained_task_ids=retained,
                excluded_eligible_task_ids=excluded,
                failed_task_ids=tuple(sorted({item.task_instance_id for item in receipts})),
                failure_receipt_count=len(receipts),
                complete_failed_task_coverage=True,
                retained_tasks_have_no_failure_receipt=True,
                no_partial_realization_salvage=True,
                frozen_before_randomization=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the failure manifest boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        bridge = self.intervention_bridge
        query = self.query_evidence
        population = self.population
        hypothesis = bridge.frozen_hypothesis
        query_by_task = {item.membership.task_instance_id: item for item in query.tasks}
        gate_by_task = {item.task_instance_id: item for item in population.task_gates}
        eligible = tuple(
            sorted(task_id for task_id, item in query_by_task.items() if item.eligibility.eligible)
        )
        retained = population.gate_pass_task_ids
        excluded = tuple(sorted(set(eligible) - set(retained)))
        receipt_ids = tuple(item.task_bundle_failure_receipt_id for item in self.failure_receipts)
        failed_tasks = tuple(sorted({item.task_instance_id for item in self.failure_receipts}))
        realization_ids = {item.realization_spec_id for item in bridge.realizations}
        arm_roles = {item.arm_role for item in bridge.arm_protocol.arms}
        if (
            query.context_query != bridge.context_query
            or query.actionable_feature != bridge.actionable_feature
            or population.hypothesis != hypothesis
            or set(query_by_task) != set(gate_by_task)
            or self.eligible_task_ids != eligible
            or self.retained_task_ids != retained
            or self.excluded_eligible_task_ids != excluded
            or self.failed_task_ids != failed_tasks
            or failed_tasks != excluded
            or self.failure_receipt_count != len(self.failure_receipts)
            or len(receipt_ids) != len(set(receipt_ids))
        ):
            raise ValueError(self._safe_validation_message)
        for task_id in excluded:
            gate = gate_by_task[task_id]
            if (
                not gate.eligibility.eligible
                or gate.task_policy_support is not None
                or gate.exclusion_reason != "task_policy_support_missing"
            ):
                raise ValueError(self._safe_validation_message)
        for receipt in self.failure_receipts:
            source = query_by_task.get(receipt.task_instance_id)
            if (
                source is None
                or receipt.task_instance_id not in excluded
                or receipt.query_evidence_task_id != source.query_evidence_task_id
                or receipt.semantic_task_cluster_id != source.membership.semantic_task_cluster_id
                or receipt.hypothesis_id != hypothesis.hypothesis_id
                or receipt.realization_spec_id not in realization_ids
                or receipt.arm_role not in arm_roles
            ):
                raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "VARIANT_FAILURE_EVIDENCE_V2_SCHEMA_VERSION",
    "TaskBundleFailureReceiptV2",
    "VariantBundleFailureReasonV2",
    "VariantBundleFailureStageV2",
    "VariantFailureEvidenceManifestV2",
]

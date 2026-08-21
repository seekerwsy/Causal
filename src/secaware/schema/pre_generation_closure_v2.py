"""Pre-generation closure for complete variant success and failure provenance.

The per-hypothesis protocol root already authenticates every retained
``task x realization x arm`` Prompt variant.  This artifact adds the exact
companion failure manifest for every protocolized hypothesis, including an
explicit empty manifest when no otherwise-eligible task was excluded.  It is
frozen after randomization is recorded but before any generation request is
issued, so downstream analysis cannot silently omit failed task bundles.
"""

from __future__ import annotations

from typing import ClassVar, Literal, Self

from pydantic import Field, StrictInt, model_validator

from secaware.records import SnapshotContentAddressedResearchRecord
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from secaware.schema.variant_failure_evidence_v2 import VariantFailureEvidenceManifestV2

PRE_GENERATION_CLOSURE_V2_SCHEMA_VERSION = "2.0"

_CLOSURE_ID_PATTERN = r"^confirmatory_pre_generation_closure_v2_[0-9a-f]{64}$"
_BINDING_ID_PATTERN = r"^hypothesis_variant_evidence_binding_v2_[0-9a-f]{64}$"


class _ContentAddressedPreGenerationClosureV2(SnapshotContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "pre-generation closure v2 contract failed validation"
    _schema_version = PRE_GENERATION_CLOSURE_V2_SCHEMA_VERSION
    schema_version: Literal["2.0"] = PRE_GENERATION_CLOSURE_V2_SCHEMA_VERSION


class HypothesisVariantEvidenceBindingV2(_ContentAddressedPreGenerationClosureV2):
    """Audit summary joining one protocol root to its exact failure manifest."""

    _id_field = "hypothesis_variant_evidence_binding_id"
    _id_prefix = "hypothesis_variant_evidence_binding_v2_"

    hypothesis_variant_evidence_binding_id: str = Field(pattern=_BINDING_ID_PATTERN)
    hypothesis_id: str
    protocol_freeze_id: str
    population_freeze_manifest_id: str
    retained_variant_evidence_manifest_id: str
    variant_failure_evidence_manifest_id: str
    eligible_task_count: StrictInt = Field(ge=1)
    retained_task_count: StrictInt = Field(ge=1)
    excluded_eligible_task_count: StrictInt = Field(ge=0)
    failure_receipt_count: StrictInt = Field(ge=0)
    complete_success_and_failure_partition: Literal[True]

    @classmethod
    def from_binding(
        cls,
        *,
        protocol_root: ProtocolFreezeRootV2,
        failure_evidence: VariantFailureEvidenceManifestV2,
    ) -> Self:
        try:
            root = ProtocolFreezeRootV2.model_validate(protocol_root, strict=True)
            failure = VariantFailureEvidenceManifestV2.model_validate(failure_evidence, strict=True)
            hypothesis = root.intervention_bridge.frozen_hypothesis
            if (
                failure.intervention_bridge != root.intervention_bridge
                or failure.query_evidence != root.query_evidence
                or failure.population != root.population
                or failure.eligible_task_ids != root.variant_evidence.eligible_task_ids
                or failure.retained_task_ids != root.variant_evidence.retained_task_ids
                or failure.excluded_eligible_task_ids
                != root.variant_evidence.pre_randomization_excluded_eligible_task_ids
            ):
                raise ValueError
            return cls.from_content(
                hypothesis_id=hypothesis.hypothesis_id,
                protocol_freeze_id=root.protocol_freeze_id,
                population_freeze_manifest_id=root.population.population_freeze_manifest_id,
                retained_variant_evidence_manifest_id=(
                    root.variant_evidence.variant_evidence_manifest_id
                ),
                variant_failure_evidence_manifest_id=(failure.variant_failure_evidence_manifest_id),
                eligible_task_count=len(failure.eligible_task_ids),
                retained_task_count=len(failure.retained_task_ids),
                excluded_eligible_task_count=len(failure.excluded_eligible_task_ids),
                failure_receipt_count=failure.failure_receipt_count,
                complete_success_and_failure_partition=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public binding boundary
            raise cls._safe_error() from None


class ConfirmatoryPreGenerationClosureV2(_ContentAddressedPreGenerationClosureV2):
    """Mandatory run root joining every hypothesis to typed variant failures."""

    _id_field = "confirmatory_pre_generation_closure_id"
    _id_prefix = "confirmatory_pre_generation_closure_v2_"

    confirmatory_pre_generation_closure_id: str = Field(pattern=_CLOSURE_ID_PATTERN)
    experiment_freeze: ConfirmatoryExperimentFreezeV2
    variant_failure_evidence_manifests: tuple[VariantFailureEvidenceManifestV2, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_variant_evidence_bindings: tuple[HypothesisVariantEvidenceBindingV2, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    variant_failure_evidence_manifest_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    hypothesis_count: StrictInt = Field(ge=1, le=10_000)
    eligible_task_count: StrictInt = Field(ge=1)
    retained_task_count: StrictInt = Field(ge=1)
    excluded_eligible_task_count: StrictInt = Field(ge=0)
    failure_receipt_count: StrictInt = Field(ge=0)
    one_failure_manifest_per_protocol_root: Literal[True]
    empty_failure_manifest_required_when_no_exclusions: Literal[True]
    complete_success_and_failure_partition: Literal[True]
    task_atomic_pre_randomization_exclusion: Literal[True]
    realization_deletion_or_renormalization_forbidden: Literal[True]
    formal_analysis_requires_this_root: Literal[True]
    frozen_before_generation: Literal[True]
    frozen_before_outcomes: Literal[True]
    downstream_records_excluded: Literal["generation_runtime_outcome_analysis"]

    @classmethod
    def from_components(
        cls,
        *,
        experiment_freeze: ConfirmatoryExperimentFreezeV2,
        variant_failure_evidence_manifests: tuple[VariantFailureEvidenceManifestV2, ...],
    ) -> Self:
        try:
            experiment = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment_freeze, strict=True
            )
            manifests = tuple(
                sorted(
                    (
                        VariantFailureEvidenceManifestV2.model_validate(item, strict=True)
                        for item in variant_failure_evidence_manifests
                    ),
                    key=lambda item: item.population.hypothesis.hypothesis_id,
                )
            )
            root_by_hypothesis = {
                item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
                for item in experiment.protocol_roots
            }
            manifest_by_hypothesis = {
                item.population.hypothesis.hypothesis_id: item for item in manifests
            }
            bindings = tuple(
                HypothesisVariantEvidenceBindingV2.from_binding(
                    protocol_root=root_by_hypothesis[hypothesis_id],
                    failure_evidence=manifest_by_hypothesis[hypothesis_id],
                )
                for hypothesis_id in experiment.hypothesis_ids
            )
            return cls.from_content(
                experiment_freeze=experiment,
                variant_failure_evidence_manifests=manifests,
                hypothesis_variant_evidence_bindings=bindings,
                hypothesis_ids=experiment.hypothesis_ids,
                variant_failure_evidence_manifest_ids=tuple(
                    item.variant_failure_evidence_manifest_id for item in manifests
                ),
                hypothesis_count=experiment.hypothesis_count,
                eligible_task_count=sum(item.eligible_task_count for item in bindings),
                retained_task_count=sum(item.retained_task_count for item in bindings),
                excluded_eligible_task_count=sum(
                    item.excluded_eligible_task_count for item in bindings
                ),
                failure_receipt_count=sum(item.failure_receipt_count for item in bindings),
                one_failure_manifest_per_protocol_root=True,
                empty_failure_manifest_required_when_no_exclusions=True,
                complete_success_and_failure_partition=True,
                task_atomic_pre_randomization_exclusion=True,
                realization_deletion_or_renormalization_forbidden=True,
                formal_analysis_requires_this_root=True,
                frozen_before_generation=True,
                frozen_before_outcomes=True,
                downstream_records_excluded="generation_runtime_outcome_analysis",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_closure(self) -> Self:
        experiment = self.experiment_freeze
        roots = {
            item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
            for item in experiment.protocol_roots
        }
        manifests = {
            item.population.hypothesis.hypothesis_id: item
            for item in self.variant_failure_evidence_manifests
        }
        if (
            len(roots) != len(experiment.protocol_roots)
            or len(manifests) != len(self.variant_failure_evidence_manifests)
            or tuple(sorted(manifests)) != experiment.hypothesis_ids
            or self.hypothesis_ids != experiment.hypothesis_ids
            or self.hypothesis_count != experiment.hypothesis_count
            or self.hypothesis_count != len(self.variant_failure_evidence_manifests)
            or self.variant_failure_evidence_manifest_ids
            != tuple(
                item.variant_failure_evidence_manifest_id
                for item in self.variant_failure_evidence_manifests
            )
        ):
            raise ValueError(self._safe_validation_message)

        expected_bindings = []
        for hypothesis_id in experiment.hypothesis_ids:
            root = roots[hypothesis_id]
            failure = manifests[hypothesis_id]
            if (
                failure.intervention_bridge != root.intervention_bridge
                or failure.query_evidence != root.query_evidence
                or failure.population != root.population
                or failure.eligible_task_ids != root.variant_evidence.eligible_task_ids
                or failure.retained_task_ids != root.variant_evidence.retained_task_ids
                or failure.excluded_eligible_task_ids
                != root.variant_evidence.pre_randomization_excluded_eligible_task_ids
                or failure.retained_task_ids != root.population.gate_pass_task_ids
                or len(failure.eligible_task_ids)
                != len(failure.retained_task_ids) + len(failure.excluded_eligible_task_ids)
            ):
                raise ValueError(self._safe_validation_message)
            expected_bindings.append(
                HypothesisVariantEvidenceBindingV2.from_binding(
                    protocol_root=root,
                    failure_evidence=failure,
                )
            )

        expected = tuple(expected_bindings)
        if (
            self.hypothesis_variant_evidence_bindings != expected
            or self.eligible_task_count != sum(item.eligible_task_count for item in expected)
            or self.retained_task_count != sum(item.retained_task_count for item in expected)
            or self.excluded_eligible_task_count
            != sum(item.excluded_eligible_task_count for item in expected)
            or self.failure_receipt_count != sum(item.failure_receipt_count for item in expected)
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "PRE_GENERATION_CLOSURE_V2_SCHEMA_VERSION",
    "ConfirmatoryPreGenerationClosureV2",
    "HypothesisVariantEvidenceBindingV2",
]

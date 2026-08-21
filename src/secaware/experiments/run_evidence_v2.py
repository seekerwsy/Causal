"""Run-level provenance closure for a frozen confirmatory experiment.

``ConfirmatoryExperimentFreezeV2`` fixes the complete hypothesis-by-model
universe before generation.  ``TotalAssignmentAccountingManifestV2`` closes
every randomized assignment with either an authenticated outcome or an
immutable terminal infrastructure-failure receipt.  This module joins those
two trust boundaries without permitting a caller to substitute a favorable
coverage subset, hypothesis subset, or model subset.

The resulting manifest is evidence closure, not an analysis result.  In
particular, terminal infrastructure failures remain in the manifest and make
formal point estimation unavailable; they are never deleted or regenerated.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import ClassVar, Literal, Self

from pydantic import Field, StrictInt, model_validator

from secaware.experiments.execution_v2 import TotalAssignmentAccountingManifestV2
from secaware.records import (
    ContentAddressedResearchRecord,
    SnapshotResearchRecord,
    raise_record_validation_error as _raise_contract_error,
)
from secaware.schema.experiment_freeze_v2 import (
    ConfirmatoryExperimentFreezeV2,
    ConfirmatoryHypothesisModelCoordinateV2,
)

RUN_EVIDENCE_V2_SCHEMA_VERSION = "2.0"

_RUN_EVIDENCE_ID_PATTERN = r"^confirmatory_run_evidence_v2_[0-9a-f]{64}$"
_HYPOTHESIS_EVIDENCE_ID_PATTERN = r"^hypothesis_run_evidence_v2_[0-9a-f]{64}$"

_TERMINAL_STAGES = (
    "artifact_storage",
    "functional_evaluator",
    "provider_response",
    "provider_transport",
    "security_oracle",
    "syntax_validation",
)


class _RunEvidenceV2Contract(SnapshotResearchRecord):
    _safe_validation_message: ClassVar[str] = "run evidence v2 contract failed validation"
    schema_version: Literal["2.0"] = RUN_EVIDENCE_V2_SCHEMA_VERSION


class _ContentAddressedRunEvidenceV2(ContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "run evidence v2 contract failed validation"
    _schema_version = RUN_EVIDENCE_V2_SCHEMA_VERSION
    schema_version: Literal["2.0"] = RUN_EVIDENCE_V2_SCHEMA_VERSION


class TerminalFailureStageCountV2(_RunEvidenceV2Contract):
    """A fixed-domain failure count; zero-valued stages remain explicit."""

    stage: Literal[
        "provider_transport",
        "provider_response",
        "syntax_validation",
        "security_oracle",
        "functional_evaluator",
        "artifact_storage",
    ]
    count: StrictInt = Field(ge=0)


def _accounting_hypothesis_id(accounting: TotalAssignmentAccountingManifestV2) -> str:
    return accounting.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id


def _failure_stage_counts(
    accountings: Sequence[TotalAssignmentAccountingManifestV2],
) -> tuple[TerminalFailureStageCountV2, ...]:
    counts = Counter(
        receipt.terminal_stage
        for accounting in accountings
        for receipt in accounting.infrastructure_failure_receipts
    )
    return tuple(
        TerminalFailureStageCountV2(stage=stage, count=counts[stage]) for stage in _TERMINAL_STAGES
    )


class HypothesisRunEvidenceBindingV2(_ContentAddressedRunEvidenceV2):
    """Exact identity and terminal accounting for one frozen hypothesis."""

    _id_field = "hypothesis_run_evidence_binding_id"
    _id_prefix = "hypothesis_run_evidence_v2_"

    hypothesis_run_evidence_binding_id: str = Field(pattern=_HYPOTHESIS_EVIDENCE_ID_PATTERN)
    hypothesis_id: str
    protocol_freeze_id: str
    execution_policy_freeze_manifest_id: str
    population_freeze_manifest_id: str
    randomization_manifest_id: str
    total_assignment_accounting_manifest_id: str
    provenance_closed_coverage_manifest_id: str | None
    model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    hypothesis_model_coordinate_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    assignment_ids: tuple[str, ...] = Field(min_length=1)
    outcome_assignment_ids: tuple[str, ...]
    failure_assignment_ids: tuple[str, ...]
    outcome_assembly_receipt_ids: tuple[str, ...]
    infrastructure_failure_receipt_ids: tuple[str, ...]
    expected_assignment_count: StrictInt = Field(ge=1)
    terminally_accounted_assignment_count: StrictInt = Field(ge=1)
    outcome_count: StrictInt = Field(ge=0)
    failure_count: StrictInt = Field(ge=0)
    unresolved_assignment_count: Literal[0]
    terminal_failure_stage_counts: tuple[TerminalFailureStageCountV2, ...]
    formal_point_estimation_ready: bool
    accounting_rule: Literal[
        "exact_one_total_accounting_per_hypothesis_with_no_assignment_deletion_v1"
    ]

    @classmethod
    def from_binding(
        cls,
        *,
        experiment_freeze: ConfirmatoryExperimentFreezeV2,
        hypothesis_id: str,
        accounting: TotalAssignmentAccountingManifestV2,
    ) -> Self:
        try:
            experiment = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment_freeze, strict=True
            )
            checked = TotalAssignmentAccountingManifestV2.model_validate(accounting, strict=True)
            roots = {
                item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
                for item in experiment.protocol_roots
            }
            executions = {
                item.randomization.population.hypothesis.hypothesis_id: item
                for item in experiment.execution_policy_freezes
            }
            root = roots[hypothesis_id]
            execution = executions[hypothesis_id]
            if (
                _accounting_hypothesis_id(checked) != hypothesis_id
                or checked.execution_policy_freeze != execution
                or checked.execution_policy_freeze.randomization != execution.randomization
                or checked.execution_policy_freeze.randomization.population != root.population
                or checked.assignment_ids
                != tuple(sorted(item.assignment_id for item in execution.randomization.assignments))
                or any(
                    receipt.retry_policy_sha256
                    != root.intervention_bridge.arm_protocol.retry_policy_sha256
                    for receipt in checked.infrastructure_failure_receipts
                )
            ):
                raise ValueError
            coordinates = tuple(
                item
                for item in experiment.hypothesis_model_coordinates
                if item.hypothesis_id == hypothesis_id
            )
            failures = checked.infrastructure_failure_receipts
            outcome_receipt_ids = tuple(
                item.outcome_assembly_receipt_id for item in checked.outcome_assembly_receipts
            )
            failure_receipt_ids = tuple(item.infrastructure_failure_receipt_id for item in failures)
            return cls.from_content(
                hypothesis_id=hypothesis_id,
                protocol_freeze_id=root.protocol_freeze_id,
                execution_policy_freeze_manifest_id=(execution.execution_policy_freeze_manifest_id),
                population_freeze_manifest_id=root.population.population_freeze_manifest_id,
                randomization_manifest_id=execution.randomization.randomization_manifest_id,
                total_assignment_accounting_manifest_id=(
                    checked.total_assignment_accounting_manifest_id
                ),
                provenance_closed_coverage_manifest_id=(
                    checked.confirmatory_coverage.provenance_closed_coverage_manifest_id
                    if checked.confirmatory_coverage is not None
                    else None
                ),
                model_ids=experiment.model_ids,
                hypothesis_model_coordinate_ids=tuple(
                    item.hypothesis_model_coordinate_id for item in coordinates
                ),
                assignment_ids=checked.assignment_ids,
                outcome_assignment_ids=checked.outcome_assignment_ids,
                failure_assignment_ids=checked.failure_assignment_ids,
                outcome_assembly_receipt_ids=outcome_receipt_ids,
                infrastructure_failure_receipt_ids=failure_receipt_ids,
                expected_assignment_count=len(execution.randomization.assignments),
                terminally_accounted_assignment_count=(
                    checked.outcome_count + checked.failure_count
                ),
                outcome_count=checked.outcome_count,
                failure_count=checked.failure_count,
                unresolved_assignment_count=0,
                terminal_failure_stage_counts=_failure_stage_counts((checked,)),
                formal_point_estimation_ready=(
                    checked.confirmatory_coverage is not None and checked.failure_count == 0
                ),
                accounting_rule=(
                    "exact_one_total_accounting_per_hypothesis_with_no_assignment_deletion_v1"
                ),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_binding_summary(self) -> Self:
        terminal_count = self.outcome_count + self.failure_count
        expected_stage_counts = tuple(sorted(_TERMINAL_STAGES))
        actual_stage_counts = tuple(item.stage for item in self.terminal_failure_stage_counts)
        if (
            self.assignment_ids != tuple(sorted(self.assignment_ids))
            or len(self.assignment_ids) != len(set(self.assignment_ids))
            or self.outcome_assignment_ids != tuple(sorted(self.outcome_assignment_ids))
            or self.failure_assignment_ids != tuple(sorted(self.failure_assignment_ids))
            or tuple(sorted((*self.outcome_assignment_ids, *self.failure_assignment_ids)))
            != self.assignment_ids
            or self.expected_assignment_count != len(self.assignment_ids)
            or self.terminally_accounted_assignment_count != terminal_count
            or terminal_count != self.expected_assignment_count
            or self.outcome_count != len(self.outcome_assignment_ids)
            or self.failure_count != len(self.failure_assignment_ids)
            or self.outcome_count != len(self.outcome_assembly_receipt_ids)
            or self.failure_count != len(self.infrastructure_failure_receipt_ids)
            or len(self.outcome_assembly_receipt_ids) != len(set(self.outcome_assembly_receipt_ids))
            or len(self.infrastructure_failure_receipt_ids)
            != len(set(self.infrastructure_failure_receipt_ids))
            or actual_stage_counts != expected_stage_counts
            or sum(item.count for item in self.terminal_failure_stage_counts) != self.failure_count
            or (self.provenance_closed_coverage_manifest_id is None) != bool(self.failure_count)
            or self.formal_point_estimation_ready
            != (
                self.provenance_closed_coverage_manifest_id is not None
                and self.failure_count == 0
                and self.unresolved_assignment_count == 0
            )
            or self.model_ids != tuple(sorted(self.model_ids))
            or len(self.model_ids) != len(set(self.model_ids))
            or len(self.hypothesis_model_coordinate_ids) != len(self.model_ids)
            or len(self.hypothesis_model_coordinate_ids)
            != len(set(self.hypothesis_model_coordinate_ids))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ConfirmatoryRunEvidenceManifestV2(_ContentAddressedRunEvidenceV2):
    """Complete, failure-preserving evidence root for one frozen run."""

    _id_field = "confirmatory_run_evidence_manifest_id"
    _id_prefix = "confirmatory_run_evidence_v2_"

    confirmatory_run_evidence_manifest_id: str = Field(pattern=_RUN_EVIDENCE_ID_PATTERN)
    experiment_freeze: ConfirmatoryExperimentFreezeV2
    total_assignment_accountings: tuple[TotalAssignmentAccountingManifestV2, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_run_evidence_bindings: tuple[HypothesisRunEvidenceBindingV2, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    hypothesis_model_coordinates: tuple[ConfirmatoryHypothesisModelCoordinateV2, ...] = Field(
        min_length=1, max_length=640_000
    )
    hypothesis_model_coordinate_ids: tuple[str, ...] = Field(min_length=1, max_length=640_000)
    total_assignment_accounting_manifest_ids: tuple[str, ...] = Field(
        min_length=1, max_length=10_000
    )
    provenance_closed_coverage_manifest_ids: tuple[str, ...]
    outcome_assembly_receipt_ids: tuple[str, ...]
    infrastructure_failure_receipt_ids: tuple[str, ...]
    hypothesis_count: StrictInt = Field(ge=1, le=10_000)
    model_count: StrictInt = Field(ge=1, le=64)
    hypothesis_model_coordinate_count: StrictInt = Field(ge=1, le=640_000)
    expected_assignment_count: StrictInt = Field(ge=1)
    terminally_accounted_assignment_count: StrictInt = Field(ge=1)
    outcome_count: StrictInt = Field(ge=0)
    failure_count: StrictInt = Field(ge=0)
    unresolved_assignment_count: Literal[0]
    terminal_failure_stage_counts: tuple[TerminalFailureStageCountV2, ...]
    formal_point_estimation_ready: bool
    complete_hypothesis_model_universe_preserved: Literal[True]
    all_assignments_terminally_accounted: Literal[True]
    evidence_closure_rule: Literal[
        "experiment_freeze_plus_exact_total_accounting_per_hypothesis_v1"
    ]
    failure_policy: Literal[
        "preserve_terminal_failure_disable_formal_point_estimation_no_regeneration_v1"
    ]

    @classmethod
    def from_components(
        cls,
        *,
        experiment_freeze: ConfirmatoryExperimentFreezeV2,
        total_assignment_accountings: Sequence[TotalAssignmentAccountingManifestV2],
    ) -> Self:
        try:
            experiment = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment_freeze, strict=True
            )
            accountings = tuple(
                sorted(
                    (
                        TotalAssignmentAccountingManifestV2.model_validate(item, strict=True)
                        for item in total_assignment_accountings
                    ),
                    key=_accounting_hypothesis_id,
                )
            )
            accounting_by_hypothesis = {
                _accounting_hypothesis_id(item): item for item in accountings
            }
            bindings = tuple(
                HypothesisRunEvidenceBindingV2.from_binding(
                    experiment_freeze=experiment,
                    hypothesis_id=hypothesis_id,
                    accounting=accounting_by_hypothesis[hypothesis_id],
                )
                for hypothesis_id in experiment.hypothesis_ids
            )
            outcome_receipt_ids = tuple(
                receipt.outcome_assembly_receipt_id
                for accounting in accountings
                for receipt in accounting.outcome_assembly_receipts
            )
            failure_receipt_ids = tuple(
                receipt.infrastructure_failure_receipt_id
                for accounting in accountings
                for receipt in accounting.infrastructure_failure_receipts
            )
            coverage_ids = tuple(
                accounting.confirmatory_coverage.provenance_closed_coverage_manifest_id
                for accounting in accountings
                if accounting.confirmatory_coverage is not None
            )
            expected_count = sum(len(item.assignment_ids) for item in accountings)
            outcome_count = sum(item.outcome_count for item in accountings)
            failure_count = sum(item.failure_count for item in accountings)
            return cls.from_content(
                experiment_freeze=experiment,
                total_assignment_accountings=accountings,
                hypothesis_run_evidence_bindings=bindings,
                hypothesis_ids=experiment.hypothesis_ids,
                model_ids=experiment.model_ids,
                hypothesis_model_coordinates=experiment.hypothesis_model_coordinates,
                hypothesis_model_coordinate_ids=tuple(
                    item.hypothesis_model_coordinate_id
                    for item in experiment.hypothesis_model_coordinates
                ),
                total_assignment_accounting_manifest_ids=tuple(
                    item.total_assignment_accounting_manifest_id for item in accountings
                ),
                provenance_closed_coverage_manifest_ids=coverage_ids,
                outcome_assembly_receipt_ids=outcome_receipt_ids,
                infrastructure_failure_receipt_ids=failure_receipt_ids,
                hypothesis_count=experiment.hypothesis_count,
                model_count=experiment.model_count,
                hypothesis_model_coordinate_count=(experiment.hypothesis_model_coordinate_count),
                expected_assignment_count=expected_count,
                terminally_accounted_assignment_count=outcome_count + failure_count,
                outcome_count=outcome_count,
                failure_count=failure_count,
                unresolved_assignment_count=0,
                terminal_failure_stage_counts=_failure_stage_counts(accountings),
                formal_point_estimation_ready=(
                    bool(accountings)
                    and all(item.confirmatory_coverage is not None for item in accountings)
                    and failure_count == 0
                ),
                complete_hypothesis_model_universe_preserved=True,
                all_assignments_terminally_accounted=True,
                evidence_closure_rule=(
                    "experiment_freeze_plus_exact_total_accounting_per_hypothesis_v1"
                ),
                failure_policy=(
                    "preserve_terminal_failure_disable_formal_point_estimation_no_regeneration_v1"
                ),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_run_evidence(self) -> Self:
        experiment = self.experiment_freeze
        accountings = self.total_assignment_accountings
        accounting_hypothesis_ids = tuple(_accounting_hypothesis_id(item) for item in accountings)
        accounting_by_hypothesis = {_accounting_hypothesis_id(item): item for item in accountings}
        roots = {
            item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
            for item in experiment.protocol_roots
        }
        executions = {
            item.randomization.population.hypothesis.hypothesis_id: item
            for item in experiment.execution_policy_freezes
        }

        if (
            accounting_hypothesis_ids != experiment.hypothesis_ids
            or len(accounting_by_hypothesis) != len(accountings)
            or self.hypothesis_ids != experiment.hypothesis_ids
            or self.model_ids != experiment.model_ids
            or self.hypothesis_model_coordinates != experiment.hypothesis_model_coordinates
            or self.hypothesis_model_coordinate_ids
            != tuple(
                item.hypothesis_model_coordinate_id
                for item in experiment.hypothesis_model_coordinates
            )
            or self.hypothesis_count != experiment.hypothesis_count
            or self.model_count != experiment.model_count
            or self.hypothesis_model_coordinate_count
            != experiment.hypothesis_model_coordinate_count
            or self.hypothesis_model_coordinate_count != self.hypothesis_count * self.model_count
        ):
            raise ValueError(self._safe_validation_message)

        expected_bindings = []
        for hypothesis_id in experiment.hypothesis_ids:
            root = roots.get(hypothesis_id)
            execution = executions.get(hypothesis_id)
            accounting = accounting_by_hypothesis.get(hypothesis_id)
            if (
                root is None
                or execution is None
                or accounting is None
                or accounting.execution_policy_freeze != execution
                or accounting.execution_policy_freeze.randomization != execution.randomization
                or accounting.execution_policy_freeze.randomization.population != root.population
                or accounting.assignment_ids
                != tuple(sorted(item.assignment_id for item in execution.randomization.assignments))
                or any(
                    receipt.retry_policy_sha256
                    != root.intervention_bridge.arm_protocol.retry_policy_sha256
                    for receipt in accounting.infrastructure_failure_receipts
                )
            ):
                raise ValueError(self._safe_validation_message)
            expected_bindings.append(
                HypothesisRunEvidenceBindingV2.from_binding(
                    experiment_freeze=experiment,
                    hypothesis_id=hypothesis_id,
                    accounting=accounting,
                )
            )

        outcome_receipt_ids = tuple(
            receipt.outcome_assembly_receipt_id
            for accounting in accountings
            for receipt in accounting.outcome_assembly_receipts
        )
        failure_receipt_ids = tuple(
            receipt.infrastructure_failure_receipt_id
            for accounting in accountings
            for receipt in accounting.infrastructure_failure_receipts
        )
        coverage_ids = tuple(
            accounting.confirmatory_coverage.provenance_closed_coverage_manifest_id
            for accounting in accountings
            if accounting.confirmatory_coverage is not None
        )
        expected_count = sum(len(item.assignment_ids) for item in accountings)
        outcome_count = sum(item.outcome_count for item in accountings)
        failure_count = sum(item.failure_count for item in accountings)
        formal_ready = (
            all(item.confirmatory_coverage is not None for item in accountings)
            and failure_count == 0
            and self.unresolved_assignment_count == 0
        )
        if (
            self.hypothesis_run_evidence_bindings != tuple(expected_bindings)
            or self.total_assignment_accounting_manifest_ids
            != tuple(item.total_assignment_accounting_manifest_id for item in accountings)
            or self.provenance_closed_coverage_manifest_ids != coverage_ids
            or self.outcome_assembly_receipt_ids != outcome_receipt_ids
            or self.infrastructure_failure_receipt_ids != failure_receipt_ids
            or len(outcome_receipt_ids) != len(set(outcome_receipt_ids))
            or len(failure_receipt_ids) != len(set(failure_receipt_ids))
            or self.expected_assignment_count != expected_count
            or self.terminally_accounted_assignment_count != outcome_count + failure_count
            or self.terminally_accounted_assignment_count != expected_count
            or self.outcome_count != outcome_count
            or self.failure_count != failure_count
            or self.terminal_failure_stage_counts != _failure_stage_counts(accountings)
            or self.formal_point_estimation_ready != formal_ready
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "RUN_EVIDENCE_V2_SCHEMA_VERSION",
    "ConfirmatoryRunEvidenceManifestV2",
    "HypothesisRunEvidenceBindingV2",
    "TerminalFailureStageCountV2",
]

"""Single post-run trust root with pre-randomization failure provenance.

This wrapper preserves the existing versioned run-evidence schema while making
the pre-generation closure mandatory for formal analysis.  Its dependency DAG
is strictly one-way::

    protocol + randomization -> experiment freeze
    experiment freeze + variant failures -> pre-generation closure
    experiment freeze + terminal accounting -> run evidence
    pre-generation closure + run evidence -> closed run evidence

No execution, runtime, or outcome artifact points back to this wrapper.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from secaware.experiments.run_evidence_v2 import ConfirmatoryRunEvidenceManifestV2
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.pre_generation_closure_v2 import ConfirmatoryPreGenerationClosureV2

CLOSED_RUN_EVIDENCE_V2_SCHEMA_VERSION = "2.0"

_CLOSED_RUN_ID_PATTERN = r"^confirmatory_closed_run_evidence_v2_[0-9a-f]{64}$"


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


class _ClosedRunEvidenceV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "closed run evidence v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = CLOSED_RUN_EVIDENCE_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class ConfirmatoryClosedRunEvidenceV2(_ClosedRunEvidenceV2Contract):
    """Complete formal-analysis input root for one confirmatory run."""

    confirmatory_closed_run_evidence_id: str = Field(pattern=_CLOSED_RUN_ID_PATTERN)
    pre_generation_closure: ConfirmatoryPreGenerationClosureV2
    run_evidence: ConfirmatoryRunEvidenceManifestV2
    confirmatory_pre_generation_closure_id: str
    confirmatory_run_evidence_manifest_id: str
    hypothesis_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    hypothesis_variant_evidence_binding_ids: tuple[str, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_run_evidence_binding_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    variant_failure_evidence_manifest_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    total_assignment_accounting_manifest_ids: tuple[str, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_count: StrictInt = Field(ge=1, le=10_000)
    pre_randomization_excluded_eligible_task_count: StrictInt = Field(ge=0)
    pre_randomization_failure_receipt_count: StrictInt = Field(ge=0)
    runtime_expected_assignment_count: StrictInt = Field(ge=1)
    runtime_terminally_accounted_assignment_count: StrictInt = Field(ge=1)
    runtime_failure_count: StrictInt = Field(ge=0)
    formal_point_estimation_ready: bool
    external_pre_generation_closure_pin_required: Literal[True]
    exact_pre_generation_and_runtime_lineage: Literal[True]
    pre_randomization_exclusions_do_not_filter_assigned_arm_itt: Literal[True]
    all_runtime_assignments_terminally_accounted: Literal[True]
    formal_analysis_requires_this_root: Literal[True]
    downstream_analysis_records_excluded: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        pre_generation_closure: ConfirmatoryPreGenerationClosureV2,
        run_evidence: ConfirmatoryRunEvidenceManifestV2,
    ) -> Self:
        try:
            closure = ConfirmatoryPreGenerationClosureV2.model_validate(
                pre_generation_closure, strict=True
            )
            evidence = ConfirmatoryRunEvidenceManifestV2.model_validate(run_evidence, strict=True)
            if evidence.experiment_freeze != closure.experiment_freeze:
                raise ValueError
            payload = {
                "schema_version": CLOSED_RUN_EVIDENCE_V2_SCHEMA_VERSION,
                "pre_generation_closure": closure,
                "run_evidence": evidence,
                "confirmatory_pre_generation_closure_id": (
                    closure.confirmatory_pre_generation_closure_id
                ),
                "confirmatory_run_evidence_manifest_id": (
                    evidence.confirmatory_run_evidence_manifest_id
                ),
                "hypothesis_ids": closure.hypothesis_ids,
                "hypothesis_variant_evidence_binding_ids": tuple(
                    item.hypothesis_variant_evidence_binding_id
                    for item in closure.hypothesis_variant_evidence_bindings
                ),
                "hypothesis_run_evidence_binding_ids": tuple(
                    item.hypothesis_run_evidence_binding_id
                    for item in evidence.hypothesis_run_evidence_bindings
                ),
                "variant_failure_evidence_manifest_ids": (
                    closure.variant_failure_evidence_manifest_ids
                ),
                "total_assignment_accounting_manifest_ids": (
                    evidence.total_assignment_accounting_manifest_ids
                ),
                "hypothesis_count": closure.hypothesis_count,
                "pre_randomization_excluded_eligible_task_count": (
                    closure.excluded_eligible_task_count
                ),
                "pre_randomization_failure_receipt_count": closure.failure_receipt_count,
                "runtime_expected_assignment_count": evidence.expected_assignment_count,
                "runtime_terminally_accounted_assignment_count": (
                    evidence.terminally_accounted_assignment_count
                ),
                "runtime_failure_count": evidence.failure_count,
                "formal_point_estimation_ready": evidence.formal_point_estimation_ready,
                "external_pre_generation_closure_pin_required": True,
                "exact_pre_generation_and_runtime_lineage": True,
                "pre_randomization_exclusions_do_not_filter_assigned_arm_itt": True,
                "all_runtime_assignments_terminally_accounted": True,
                "formal_analysis_requires_this_root": True,
                "downstream_analysis_records_excluded": True,
            }
            return cls(
                **payload,
                confirmatory_closed_run_evidence_id=(
                    "confirmatory_closed_run_evidence_v2_" + _digest(payload)
                ),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_closed_run(self) -> Self:
        closure = self.pre_generation_closure
        evidence = self.run_evidence
        expected = {
            "confirmatory_pre_generation_closure_id": (
                closure.confirmatory_pre_generation_closure_id
            ),
            "confirmatory_run_evidence_manifest_id": (
                evidence.confirmatory_run_evidence_manifest_id
            ),
            "hypothesis_ids": closure.hypothesis_ids,
            "hypothesis_variant_evidence_binding_ids": tuple(
                item.hypothesis_variant_evidence_binding_id
                for item in closure.hypothesis_variant_evidence_bindings
            ),
            "hypothesis_run_evidence_binding_ids": tuple(
                item.hypothesis_run_evidence_binding_id
                for item in evidence.hypothesis_run_evidence_bindings
            ),
            "variant_failure_evidence_manifest_ids": (
                closure.variant_failure_evidence_manifest_ids
            ),
            "total_assignment_accounting_manifest_ids": (
                evidence.total_assignment_accounting_manifest_ids
            ),
            "hypothesis_count": closure.hypothesis_count,
            "pre_randomization_excluded_eligible_task_count": (
                closure.excluded_eligible_task_count
            ),
            "pre_randomization_failure_receipt_count": closure.failure_receipt_count,
            "runtime_expected_assignment_count": evidence.expected_assignment_count,
            "runtime_terminally_accounted_assignment_count": (
                evidence.terminally_accounted_assignment_count
            ),
            "runtime_failure_count": evidence.failure_count,
            "formal_point_estimation_ready": evidence.formal_point_estimation_ready,
        }
        actual = {key: getattr(self, key) for key in expected}
        if (
            evidence.experiment_freeze != closure.experiment_freeze
            or evidence.hypothesis_ids != closure.hypothesis_ids
            or evidence.hypothesis_count != closure.hypothesis_count
            or actual != expected
            or self.runtime_terminally_accounted_assignment_count
            != self.runtime_expected_assignment_count
        ):
            raise ValueError(self._safe_validation_message)
        content = self.model_dump(mode="json", exclude={"confirmatory_closed_run_evidence_id"})
        if self.confirmatory_closed_run_evidence_id != (
            "confirmatory_closed_run_evidence_v2_" + _digest(content)
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "CLOSED_RUN_EVIDENCE_V2_SCHEMA_VERSION",
    "ConfirmatoryClosedRunEvidenceV2",
]

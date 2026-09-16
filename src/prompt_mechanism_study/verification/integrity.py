"""Exact package identity, schema decoding, and index reconstruction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints

from prompt_mechanism_study.artifact_io import read_json_exact
from prompt_mechanism_study.inference import (
    SharedEvidenceRecord,
    TargetSelectorYieldResult,
)
from prompt_mechanism_study.prioritization import (
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    SharedConfirmationUnion,
)
from prompt_mechanism_study.randomization import (
    AssignedArmITTRecord,
    TargetRandomizationPlan,
    TargetTaskBundle,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import DataRoleManifest
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    StudyFreezeIndex,
)
from prompt_mechanism_study.study_planning import RQ1BudgetQualification

TARGET_RESULT_PACKAGE_FILES = frozenset(
    {
        "package_index.json",
        "data_role_manifest.json",
        "rq1_budget_qualification.json",
        "discovery_design_freeze.json",
        "fixed_slot_ledger.json",
        "shared_confirmation_union.json",
        "confirmation_dispatch_manifest.json",
        "target_randomization_plan.json",
        "confirmation_task_bundles.json",
        "assignments.json",
        "formal_budget_preflight.json",
        "confirmation_freeze.json",
        "study_freeze_index.json",
        "shared_evidence_record.json",
        "target_selector_yield_result.json",
        "formal_report_authorization.json",
        "execution_artifacts.json",
        "rq_tables.json",
        "verification.json",
    }
)

def target_result_package_index(
    *,
    manifest: DataRoleManifest,
    budget: RQ1BudgetQualification,
    discovery: DiscoveryDesignFreeze,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
    confirmation: ConfirmationFreeze,
    index: StudyFreezeIndex,
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    verification: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
    execution_artifacts: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the content-addressed index used by the writer and read-only verifier."""

    frozen_assignments = tuple(assignments)
    table_id = report.get("target_rq_tables_id")
    if not isinstance(table_id, str) or not table_id:
        raise ValueError("target result package requires a verified RQ table ID")
    refs: dict[str, object] = {
        "data_role_manifest": _target_ref(
            manifest.data_role_manifest_id,
            manifest,
        ),
        "rq1_budget_qualification": _target_ref(
            budget.rq1_budget_qualification_id,
            budget,
        ),
        "discovery_design_freeze": _target_ref(
            discovery.discovery_design_freeze_id,
            discovery,
        ),
        "fixed_slot_ledger": _target_ref(ledger.fixed_slot_ledger_id, ledger),
        "shared_confirmation_union": _target_ref(
            union.shared_confirmation_union_id,
            union,
        ),
        "confirmation_dispatch_manifest": _target_ref(
            dispatch.confirmation_dispatch_manifest_id,
            dispatch,
        ),
        "target_randomization_plan": _target_ref(
            randomization_plan.target_randomization_plan_id,
            randomization_plan,
        ),
        "confirmation_task_bundles": _target_ref(
            content_id("target_task_bundles_", tuple(task_bundles)),
            tuple(task_bundles),
        ),
        "assignments": _target_ref(
            confirmation.model_bound_assignments.artifact_id,
            frozen_assignments,
        ),
        "formal_budget_preflight": _target_ref(
            preflight.formal_budget_preflight_id,
            preflight,
        ),
        "confirmation_design_freeze": _target_ref(
            confirmation.confirmation_freeze_id,
            confirmation,
        ),
        "study_freeze_index": _target_ref(index.study_freeze_index_id, index),
        "shared_evidence_record": _target_ref(
            evidence.shared_evidence_record_id,
            evidence,
        ),
        "evidence_ledger": _target_ref(
            evidence.ledger.evidence_ledger_id,
            evidence.ledger,
        ),
        "target_selector_yields": _target_ref(
            yields.target_selector_yield_result_id,
            yields,
        ),
        "formal_report_authorization": (
            None
            if authorization is None
            else _target_ref(
                authorization.formal_report_authorization_id,
                authorization,
            )
        ),
        "execution_artifacts": (
            None if execution_artifacts is None else
            _target_ref(content_id("execution_artifacts_", execution_artifacts), execution_artifacts)
        ),
        "rq_tables": _target_ref(table_id, report),
        "verification": _target_ref(
            content_id("target_result_verification_", verification),
            verification,
        ),
    }
    payload: dict[str, object] = {
        "schema_version": "3.0",
        "package_kind": "PHASE_TARGET_RESULT",
        "protocol_id": manifest.protocol_id,
        "evidence_level": evidence.evidence_level.value,
        "package_status": report.get("report_status"),
        "scientific_claim_allowed": authorization is not None,
        "artifacts": refs,
    }
    payload["target_result_package_id"] = content_id(
        "target_result_package_",
        payload,
    )
    return payload

def _target_ref(artifact_id: str, value: object) -> dict[str, str]:
    return {"artifact_id": artifact_id, "sha256": content_hash(value)}


def _decode_target_file(path: Path, expected_type: type[Any]) -> Any:
    return _decode_target_value(read_json_exact(path), expected_type, path.name)


def _decode_target_value(value: Any, annotation: Any, path: str) -> Any:
    """Strictly reconstruct one known typed record without artifact-selected classes."""

    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is tuple:
        if not isinstance(value, list):
            raise ValueError(f"{path} must be a JSON array")
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return tuple(
                _decode_target_value(item, arguments[0], f"{path}[{index}]")
                for index, item in enumerate(value)
            )
        if len(value) != len(arguments):
            raise ValueError(f"{path} has the wrong fixed tuple length")
        return tuple(
            _decode_target_value(item, item_type, f"{path}[{index}]")
            for index, (item, item_type) in enumerate(zip(value, arguments, strict=True))
        )
    if origin in {UnionType, Union}:
        failures = []
        for option in arguments:
            try:
                return _decode_target_value(value, option, path)
            except (TypeError, ValueError) as error:
                failures.append(str(error))
        raise ValueError(f"{path} does not match its frozen union type: {failures}")
    if annotation is type(None):
        if value is not None:
            raise ValueError(f"{path} must be null")
        return None
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except (TypeError, ValueError):
            raise ValueError(f"{path} has an invalid {annotation.__name__} value") from None
    if isinstance(annotation, type) and is_dataclass(annotation):
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be a JSON object")
        expected_fields = fields(annotation)
        expected_names = {item.name for item in expected_fields}
        # Only explicitly declared, absent extensions preserve older frozen bytes.
        optional_names = {item.name for item in expected_fields
                          if item.metadata.get("omit_if_none") and item.default is None}
        if not expected_names - optional_names <= set(value) <= expected_names:
            raise ValueError(f"{path} fields are not exact for {annotation.__name__}")
        if any(name in value and value[name] is None for name in optional_names):
            raise ValueError(f"{path} absent extensions must be omitted, not null")
        hints = get_type_hints(annotation)
        return annotation(
            **{
                item.name: _decode_target_value(
                    value.get(item.name),
                    hints[item.name],
                    f"{path}.{item.name}",
                )
                for item in expected_fields
            }
        )
    if annotation in {str, int, float, bool}:
        if type(value) is not annotation:
            raise ValueError(f"{path} must be an exact {annotation.__name__}")
        return value
    raise TypeError(f"{path} uses unsupported frozen type {annotation!r}")

__all__ = [
    "TARGET_RESULT_PACKAGE_FILES",
    "target_result_package_index",
]

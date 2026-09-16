"""Single orchestrator for independently verifying a schema-3 result package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json_exact,
    verify_bundle,
)
from prompt_mechanism_study.inference import (
    EvidenceLevel,
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
from prompt_mechanism_study.representation import DataRole, DataRoleManifest
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    StudyFreezeIndex,
)
from prompt_mechanism_study.study_planning import RQ1BudgetQualification

from prompt_mechanism_study.verification.design import _check_target_study_freezes
from prompt_mechanism_study.verification.effects import verify_target_shared_evidence
from prompt_mechanism_study.verification.integrity import (
    TARGET_RESULT_PACKAGE_FILES,
    _decode_target_file,
    _decode_target_value,
    target_result_package_index,
)
from prompt_mechanism_study.verification.qualification import (
    _check_formal_budget_preflight,
    verify_rq1_budget_qualification,
)
from prompt_mechanism_study.verification.reporting import (
    _check_formal_authorization,
    _check_target_rq_tables,
    verify_target_execution_artifacts,
)

def verify_target_result_components(
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
    authorization: FormalReportAuthorization | None = None,
    execution_artifacts: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Independently verify every component, including shared statistical evidence."""
    evidence_verification = verify_target_shared_evidence(evidence, yields)
    return _check_target_result_components(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        authorization=authorization,
        execution_artifacts=execution_artifacts,
        evidence_verification=evidence_verification,
    )


def _check_target_result_components(
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
    evidence_verification: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
    execution_artifacts: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Independently close every scientific boundary in one target result package."""

    roots = (
        (manifest, DataRoleManifest, "data-role manifest"),
        (budget, RQ1BudgetQualification, "RQ1 budget"),
        (discovery, DiscoveryDesignFreeze, "discovery freeze"),
        (ledger, FixedSlotLedger, "fixed-slot ledger"),
        (union, SharedConfirmationUnion, "shared union"),
        (dispatch, ConfirmationDispatchManifest, "confirmation dispatch"),
        (randomization_plan, TargetRandomizationPlan, "randomization plan"),
        (preflight, FormalBudgetPreflight, "formal budget preflight"),
        (confirmation, ConfirmationFreeze, "confirmation freeze"),
        (index, StudyFreezeIndex, "study-freeze index"),
        (evidence, SharedEvidenceRecord, "shared evidence"),
        (yields, TargetSelectorYieldResult, "selector yields"),
    )
    for value, expected_type, label in roots:
        if type(value) is not expected_type:
            raise TypeError(f"target result package requires a typed {label}")
    if authorization is not None and type(authorization) is not FormalReportAuthorization:
        raise TypeError("target result package authorization must be typed or null")
    if evidence.evidence_level in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED} and authorization is None:
        raise ValueError("executed result packages require verified execution evidence and authorization")
    if authorization is None and execution_artifacts is not None:
        raise ValueError("test result packages cannot attach formal execution artifacts")

    frozen_assignments = tuple(assignments)
    if any(type(item) is not AssignedArmITTRecord for item in frozen_assignments):
        raise TypeError("target result package assignments must be assigned-arm records")
    canonical_assignments = tuple(
        sorted(frozen_assignments, key=lambda item: item.assignment_id)
    )
    if frozen_assignments != canonical_assignments:
        raise ValueError("target result package assignments must use canonical order")

    budget_verification = verify_rq1_budget_qualification(budget)
    preflight_verification = _check_formal_budget_preflight(
        budget,
        dispatch,
        canonical_assignments,
        preflight,
    )
    freeze_verification = _check_target_study_freezes(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=canonical_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
    )
    expected_plan = budget.power_and_margin_memo.target_itt_plan()
    confirmation_task_units = {
        item.task_unit_id
        for binding in manifest.bindings
        if binding.role is DataRole.CONFIRMATION
        for item in binding.task_units
    }
    assigned_task_units = {item.task_unit_id for item in canonical_assignments}
    if (
        evidence.ledger.dispatch != dispatch
        or evidence.ledger.assignments != canonical_assignments
        or evidence.plan != expected_plan
        or not assigned_task_units <= confirmation_task_units
    ):
        raise ValueError("target result evidence is outside the frozen confirmation boundary")
    authorization_verification = None
    if authorization is not None:
        if preflight.actual_power_results is None:
            raise ValueError("formal claims require independently verified actual task-support power")
        verify_target_execution_artifacts(
            discovery=discovery, confirmation=confirmation, evidence=evidence,
            environment_reference=authorization.execution_environment,
            command_reference=authorization.execution_command,
            provider_ledger_reference=authorization.provider_call_ledger,
            execution_artifacts=execution_artifacts,
        )
        authorization_verification = _check_formal_authorization(
            index, evidence, yields, authorization, freeze_verification, evidence_verification,
        )
    table_verification = _check_target_rq_tables(
        evidence, yields, report, authorization, evidence_verification,
    )
    return {
        "status": "TARGET_RESULT_COMPONENTS_VERIFIED",
        "protocol_id": manifest.protocol_id,
        "evidence_level": evidence.evidence_level.value,
        "scientific_claim_allowed": authorization is not None,
        "data_role_manifest_id": manifest.data_role_manifest_id,
        "rq1_budget_qualification_id": budget.rq1_budget_qualification_id,
        "study_freeze_index_id": index.study_freeze_index_id,
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
        "target_selector_yield_result_id": yields.target_selector_yield_result_id,
        "target_rq_tables_id": table_verification["target_rq_tables_id"],
        "assignment_count": len(canonical_assignments),
        "task_unit_count": len(assigned_task_units),
        "budget_verification_status": budget_verification["status"],
        "preflight_verification_status": preflight_verification["status"],
        "freeze_verification_status": freeze_verification["status"],
        "evidence_verification_status": evidence_verification["status"],
        "authorization_verification_status": (
            None
            if authorization_verification is None
            else authorization_verification["status"]
        ),
        "table_verification_status": table_verification["status"],
    }

def load_and_verify_target_result_bundle(root: Path) -> dict[str, object]:
    """Read an exact schema-3.0 package and independently replay all target results."""

    root = Path(root).resolve()
    stored_manifest = verify_bundle(root)
    if set(stored_manifest.get("files", {})) != TARGET_RESULT_PACKAGE_FILES:
        raise ValueError("target result package file set is not exact")

    manifest = _decode_target_file(
        root / "data_role_manifest.json",
        DataRoleManifest,
    )
    budget = _decode_target_file(
        root / "rq1_budget_qualification.json",
        RQ1BudgetQualification,
    )
    discovery = _decode_target_file(
        root / "discovery_design_freeze.json",
        DiscoveryDesignFreeze,
    )
    ledger = _decode_target_file(root / "fixed_slot_ledger.json", FixedSlotLedger)
    union = _decode_target_file(
        root / "shared_confirmation_union.json",
        SharedConfirmationUnion,
    )
    dispatch = _decode_target_file(
        root / "confirmation_dispatch_manifest.json",
        ConfirmationDispatchManifest,
    )
    randomization_plan = _decode_target_file(
        root / "target_randomization_plan.json",
        TargetRandomizationPlan,
    )
    task_bundles = _decode_target_value(
        read_json_exact(root / "confirmation_task_bundles.json"),
        tuple[TargetTaskBundle, ...],
        "confirmation_task_bundles.json",
    )
    assignments = _decode_target_value(
        read_json_exact(root / "assignments.json"),
        tuple[AssignedArmITTRecord, ...],
        "assignments.json",
    )
    preflight = _decode_target_file(
        root / "formal_budget_preflight.json",
        FormalBudgetPreflight,
    )
    confirmation = _decode_target_file(
        root / "confirmation_freeze.json",
        ConfirmationFreeze,
    )
    index = _decode_target_file(root / "study_freeze_index.json", StudyFreezeIndex)
    evidence = _decode_target_file(
        root / "shared_evidence_record.json",
        SharedEvidenceRecord,
    )
    yields = _decode_target_file(
        root / "target_selector_yield_result.json",
        TargetSelectorYieldResult,
    )
    raw_authorization = read_json_exact(root / "formal_report_authorization.json")
    execution_artifacts = read_json_exact(root / "execution_artifacts.json")
    authorization = (
        None
        if raw_authorization is None
        else _decode_target_value(
            raw_authorization,
            FormalReportAuthorization,
            "formal_report_authorization.json",
        )
    )
    report = read_json_exact(root / "rq_tables.json")
    stored_verification = read_json_exact(root / "verification.json")
    stored_index = read_json_exact(root / "package_index.json")
    for value, label in (
        (report, "rq_tables.json"),
        (stored_verification, "verification.json"),
        (stored_index, "package_index.json"),
    ):
        if not isinstance(value, dict):
            raise ValueError(f"{label} must contain a JSON object")

    verification = verify_target_result_components(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        authorization=authorization,
        execution_artifacts=execution_artifacts,
    )
    if stored_verification != verification:
        raise ValueError("target result verification receipt failed independent replay")
    expected_index = target_result_package_index(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        verification=verification,
        authorization=authorization,
        execution_artifacts=execution_artifacts,
    )
    if stored_index != expected_index:
        raise ValueError("target result package index failed independent replay")
    return {
        "status": "TARGET_RESULT_BUNDLE_VERIFIED",
        "target_result_package_id": expected_index["target_result_package_id"],
        "bundle_sha256": bundle_digest(root),
        "protocol_id": expected_index["protocol_id"],
        "evidence_level": expected_index["evidence_level"],
        "package_status": expected_index["package_status"],
        "scientific_claim_allowed": expected_index["scientific_claim_allowed"],
        "assignment_count": verification["assignment_count"],
        "task_unit_count": verification["task_unit_count"],
    }

__all__ = [
    "load_and_verify_target_result_bundle",
    "verify_target_result_components",
]

"""Result tables and reviewer bundle for the active schema-3 study."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import write_bundle
from prompt_mechanism_study.inference import (
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    SharedEvidenceRecord,
    TargetSelectorYieldResult,
)
from prompt_mechanism_study.prioritization import (
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    PolicyTrack,
    SharedConfirmationUnion,
    SlotStatus,
)
from prompt_mechanism_study.randomization import (
    AssignedArmITTRecord,
    TargetRandomizationPlan,
    TargetTaskBundle,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import DataRole, DataRoleManifest
from prompt_mechanism_study.verification import (
    load_and_verify_target_result_bundle,
    target_result_package_index,
    verify_target_result_components,
    verify_target_shared_evidence,
    verify_target_study_freezes,
)
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    FreezeArtifactReference,
    RQ1BudgetQualification,
    StudyDesignError,
    StudyFreezeIndex,
)


def authorize_target_report(
    *,
    manifest: DataRoleManifest,
    budget: RQ1BudgetQualification,
    discovery: DiscoveryDesignFreeze,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: Any,
    task_bundles: Sequence[Any],
    assignments: Sequence[Any],
    preflight: FormalBudgetPreflight,
    confirmation: ConfirmationFreeze,
    index: StudyFreezeIndex,
    evidence: Any,
    yields: Any,
    execution_environment: FreezeArtifactReference,
    execution_command: FreezeArtifactReference,
    provider_call_ledger: FreezeArtifactReference,
) -> FormalReportAuthorization:
    """Authorize claim-bearing tables only after the exact formal chain verifies."""

    if type(evidence) is not SharedEvidenceRecord:
        raise TypeError("formal report authorization requires shared target evidence")
    if type(yields) is not TargetSelectorYieldResult:
        raise TypeError("formal report authorization requires target selector yields")
    if evidence.evidence_level not in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}:
        raise StudyDesignError("tested, demo, or calibration evidence cannot authorize claims")
    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    if (
        evidence.ledger.dispatch != dispatch
        or evidence.ledger.assignments != frozen_assignments
        or evidence.plan != budget.power_and_margin_memo.target_itt_plan()
    ):
        raise StudyDesignError("report evidence drifted from the formal confirmation freeze")
    confirmation_task_units = {
        task.task_unit_id
        for binding in manifest.bindings
        if binding.role is DataRole.CONFIRMATION
        for task in binding.task_units
    }
    assigned_task_units = {item.task_unit_id for item in frozen_assignments}
    if not assigned_task_units or not assigned_task_units <= confirmation_task_units:
        raise StudyDesignError("formal evidence contains a non-CONFIRMATION task unit")
    freeze_verification = verify_target_study_freezes(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=frozen_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
    )
    evidence_verification = verify_target_shared_evidence(evidence, yields)
    if (
        freeze_verification.get("status") != "TARGET_STUDY_FREEZE_VERIFIED"
        or evidence_verification.get("status") != "TARGET_SHARED_EVIDENCE_VERIFIED"
    ):
        raise StudyDesignError("formal report inputs did not independently verify")
    return FormalReportAuthorization(
        manifest.protocol_id,
        FreezeArtifactReference(
            index.study_freeze_index_id,
            content_hash(index),
        ),
        FreezeArtifactReference(
            evidence.shared_evidence_record_id,
            content_hash(evidence),
        ),
        FreezeArtifactReference(
            yields.target_selector_yield_result_id,
            content_hash(yields),
        ),
        FreezeArtifactReference(
            evidence.ledger.evidence_ledger_id,
            content_hash(evidence.ledger),
        ),
        execution_environment,
        execution_command,
        provider_call_ledger,
        content_hash(freeze_verification),
        content_hash(evidence_verification),
        evidence.evidence_level.value,
    )


def build_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, Any]:
    """Build claim-gated RQ tables from the one independently verified v3 record."""

    if type(evidence) is not SharedEvidenceRecord or type(yields) is not TargetSelectorYieldResult:
        raise TypeError("target RQ tables require shared evidence and fixed-slot yields")
    verification = verify_target_shared_evidence(evidence, yields)
    if verification.get("status") != "TARGET_SHARED_EVIDENCE_VERIFIED":
        raise ValueError("target shared evidence did not verify")
    slots_by_selector: dict[tuple[PolicyTrack, str, str], list[Any]] = {}
    for slot in yields.slots:
        slots_by_selector.setdefault(
            (slot.track, slot.model_id, slot.selector_id), []
        ).append(slot)
    selector_rows = []
    for selector in sorted(
        yields.selectors,
        key=lambda item: (item.track.value, item.model_id, item.selector_id),
    ):
        key = (selector.track, selector.model_id, selector.selector_id)
        slots = sorted(slots_by_selector.get(key, []), key=lambda item: item.rank)
        if len(slots) != selector.top_k:
            raise ValueError("target selector table lost a fixed K slot")
        status_counts = Counter(
            (
                slot.effect_status.value
                if slot.effect_status is not None
                else (
                    "SELECTOR_EMPTY_OR_FAILURE"
                    if slot.slot_status is not SlotStatus.FILLED
                    else "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                )
            )
            for slot in slots
        )
        selector_rows.append(
            {
                "track": selector.track.value,
                "model_id": selector.model_id,
                "selector_id": selector.selector_id,
                "top_k": selector.top_k,
                "meaningful_slots": selector.meaningful_slots,
                "meaningful_yield_at_k": selector.meaningful_yield_at_k,
                "positive_meaningful_slots": status_counts[
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL.value
                ],
                "negative_meaningful_slots": status_counts[
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL.value
                ],
                "practically_null_slots": status_counts[
                    ConfirmatoryEffectStatus.PRACTICALLY_NULL.value
                ],
                "inconclusive_slots": status_counts[
                    ConfirmatoryEffectStatus.INCONCLUSIVE.value
                ],
                "non_evaluable_slots": status_counts[
                    ConfirmatoryEffectStatus.NON_EVALUABLE.value
                ],
                "selector_empty_or_failure_slots": status_counts[
                    "SELECTOR_EMPTY_OR_FAILURE"
                ],
                "bridge_or_protocolization_failure_slots": status_counts[
                    "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                ],
            }
        )
    selector_by_key = {
        (row["track"], row["model_id"], row["selector_id"]): row
        for row in selector_rows
    }
    rq2_rows = []
    for track, full_id, ablation_id in (
        (PolicyTrack.ATOMIC, "atomic_full", "atomic_rd_only"),
        (PolicyTrack.PAIR, "pair_full", "pair_no_relation"),
    ):
        models = sorted(
            {
                model_id
                for row_track, model_id, selector_id in selector_by_key
                if row_track == track.value and selector_id in {full_id, ablation_id}
            }
        )
        for model_id in models:
            full = selector_by_key.get((track.value, model_id, full_id))
            ablation = selector_by_key.get((track.value, model_id, ablation_id))
            if full is None or ablation is None or full["top_k"] != ablation["top_k"]:
                raise ValueError(
                    "RQ2 requires both sole-difference variants with the same K"
                )
            rq2_rows.append(
                {
                    "track": track.value,
                    "model_id": model_id,
                    "full_selector_id": full_id,
                    "ablation_selector_id": ablation_id,
                    "top_k": full["top_k"],
                    "full_meaningful_yield_at_k": full["meaningful_yield_at_k"],
                    "ablation_meaningful_yield_at_k": ablation[
                        "meaningful_yield_at_k"
                    ],
                    "full_minus_ablation_yield_at_k": (
                        full["meaningful_yield_at_k"]
                        - ablation["meaningful_yield_at_k"]
                    ),
                    "comparison_semantics": (
                        "descriptive_fixed_discovery_split_no_rank_pairing"
                    ),
                }
            )
    family_rows = []
    effect_rows = []
    for family in evidence.families:
        family_rows.append(
            {
                "track": family.track.value,
                "family_status": family.status.value,
                "simultaneous_critical_value": family.simultaneous_critical_value,
                "valid_bootstrap_draws": family.valid_bootstrap_draws,
                "invalid_bootstrap_draws": family.invalid_bootstrap_draws,
                "unique_effects": len(family.estimates),
            }
        )
        for estimate in family.estimates:
            effect_rows.append(
                {
                    "track": estimate.track.value,
                    "candidate_record_id": estimate.candidate_record_id,
                    "effect_coordinate_id": estimate.effect_coordinate_id,
                    "policy_key": estimate.policy_key,
                    "model_id": estimate.model_id,
                    "estimand": (
                        "assigned_arm_task_unit_target_minus_noop_itt"
                        if estimate.track is PolicyTrack.ATOMIC
                        else "assigned_cell_task_unit_risk_difference_interaction_itt"
                    ),
                    "primary_endpoint": "oracle_evaluable_secure_code_yield",
                    "point": estimate.point,
                    "standard_error": estimate.standard_error,
                    "simultaneous_lower": estimate.simultaneous_lower,
                    "simultaneous_upper": estimate.simultaneous_upper,
                    "latent_lower": estimate.latent_lower,
                    "latent_upper": estimate.latent_upper,
                    "practical_margin": estimate.practical_margin,
                    "effect_status": estimate.status.value,
                    "reasons": list(estimate.reasons),
                    "task_units": estimate.task_units,
                    "assignments": estimate.assignments,
                    "response_pattern_classification_status": (
                        estimate.response_pattern.status.value
                    ),
                    "response_pattern": estimate.response_pattern.label,
                    "response_pattern_predicate_sha256": (
                        estimate.response_pattern.predicate_sha256
                    ),
                    "response_pattern_reasons": list(
                        estimate.response_pattern.reasons
                    ),
                    "pair_response_surface": (
                        None
                        if estimate.response_pattern.surface is None
                        else {
                            "mean_00": estimate.response_pattern.surface.mean_00,
                            "mean_10": estimate.response_pattern.surface.mean_10,
                            "mean_01": estimate.response_pattern.surface.mean_01,
                            "mean_11": estimate.response_pattern.surface.mean_11,
                            "factor_1_at_0": estimate.response_pattern.surface.factor_1_at_0,
                            "factor_2_at_0": estimate.response_pattern.surface.factor_2_at_0,
                            "joint": estimate.response_pattern.surface.joint,
                            "factor_1_at_1": estimate.response_pattern.surface.factor_1_at_1,
                            "factor_2_at_1": estimate.response_pattern.surface.factor_2_at_1,
                            "interaction": estimate.response_pattern.surface.interaction,
                        }
                    ),
                    "arms": [
                        {
                            "arm": arm.arm.value,
                            "assignments": arm.assignments,
                            "secure_yield": arm.secure_yield,
                            "code_validity": arm.code_validity,
                            "oracle_evaluability": arm.oracle_evaluability,
                            "functionality_yield": arm.functionality_yield,
                            "joint_success_yield": arm.joint_success_yield,
                            "oracle_unknown_valid_assignments": (
                                arm.oracle_unknown_valid_assignments
                            ),
                            "terminal_assignments": arm.terminal_assignments,
                        }
                        for arm in estimate.arm_summaries
                    ],
                }
            )
    claim_allowed = authorization is not None
    if authorization is not None:
        if type(authorization) is not FormalReportAuthorization:
            raise TypeError("target RQ authorization must be a formal receipt")
        if (
            authorization.protocol_id
            != evidence.ledger.dispatch.union.ledger.protocol_id
            or authorization.shared_evidence_record.artifact_id
            != evidence.shared_evidence_record_id
            or authorization.shared_evidence_record.sha256 != content_hash(evidence)
            or authorization.target_selector_yield_result.artifact_id
            != yields.target_selector_yield_result_id
            or authorization.target_selector_yield_result.sha256
            != content_hash(yields)
            or authorization.evidence_ledger.artifact_id
            != evidence.ledger.evidence_ledger_id
            or authorization.evidence_ledger.sha256 != content_hash(evidence.ledger)
            or authorization.evidence_level != evidence.evidence_level.value
            or authorization.scientific_claim_allowed is not True
        ):
            raise ValueError(
                "formal report authorization drifted from target evidence"
            )
        report_status = "FORMAL_REPORT_AUTHORIZED"
    else:
        report_status = (
            "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
            if evidence.evidence_level
            in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
            else "NON_CLAIM_TEST_ARTIFACT"
        )
    report: dict[str, Any] = {
        "schema_version": "3.0",
        "protocol_id": evidence.ledger.dispatch.union.ledger.protocol_id,
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
        "target_selector_yield_result_id": yields.target_selector_yield_result_id,
        "evidence_level": evidence.evidence_level.value,
        "report_status": report_status,
        "scientific_claim_allowed": claim_allowed,
        "formal_report_authorization_id": (
            None
            if authorization is None
            else authorization.formal_report_authorization_id
        ),
        "endpoint_order": [item.value for item in evidence.plan.metrics],
        "context_analysis_status": evidence.plan.context_analysis.status.value,
        "context_modifier_rows": [],
        "pair_response_pattern_plan_status": (
            evidence.plan.pair_response_patterns.status.value
        ),
        "rq1_selector_rows": selector_rows,
        "rq2_full_minus_ablation_rows": rq2_rows,
        "primary_family_rows": family_rows,
        "unique_effect_rows": sorted(
            effect_rows,
            key=lambda row: (row["track"], row["candidate_record_id"]),
        ),
        "independent_verification": verification,
    }
    report["target_rq_tables_id"] = content_id("target_rq_tables_", report)
    return report


def write_target_result_bundle(
    output: Path,
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
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Write the one exact target-v3 reviewer package and verify its stored bytes."""

    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    frozen_task_bundles = tuple(
        sorted(
            task_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    report = build_target_rq_tables(evidence, yields, authorization)
    verification = verify_target_result_components(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=frozen_task_bundles,
        assignments=frozen_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        authorization=authorization,
    )
    package_index = target_result_package_index(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=frozen_task_bundles,
        assignments=frozen_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        verification=verification,
        authorization=authorization,
    )
    write_bundle(
        output,
        {
            "package_index.json": package_index,
            "data_role_manifest.json": manifest,
            "rq1_budget_qualification.json": budget,
            "discovery_design_freeze.json": discovery,
            "fixed_slot_ledger.json": ledger,
            "shared_confirmation_union.json": union,
            "confirmation_dispatch_manifest.json": dispatch,
            "target_randomization_plan.json": randomization_plan,
            "confirmation_task_bundles.json": frozen_task_bundles,
            "assignments.json": frozen_assignments,
            "formal_budget_preflight.json": preflight,
            "confirmation_freeze.json": confirmation,
            "study_freeze_index.json": index,
            "shared_evidence_record.json": evidence,
            "target_selector_yield_result.json": yields,
            "formal_report_authorization.json": authorization,
            "rq_tables.json": report,
            "verification.json": verification,
        },
    )
    return load_and_verify_target_result_bundle(output)

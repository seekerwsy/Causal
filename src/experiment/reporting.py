"""Pure result-table assembly; execution and independent verification live outside."""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any
from prompt_mechanism_study.experiment.inference import (
    ConfirmatoryEffectStatus, EvidenceLevel, SharedEvidenceRecord, TargetSelectorYieldResult,
)
from prompt_mechanism_study.discovery.prioritization import PolicyTrack, SlotStatus
from prompt_mechanism_study.experiment.study_design import FormalReportAuthorization
from prompt_mechanism_study.records import content_hash, content_id


def build_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization | None = None,
    *, verification: Mapping[str, object],
) -> dict[str, Any]:
    """Assemble tables from evidence and the caller's independent verification result."""
    slots_by_selector: dict[tuple[PolicyTrack, str, str], list[Any]] = {}
    for slot in yields.slots:
        slots_by_selector.setdefault((slot.track, slot.model_id, slot.selector_id), []).append(slot)
    selector_rows = []
    for selector in sorted(
        yields.selectors, key=lambda item: (item.track.value, item.model_id, item.selector_id)
    ):
        key = (selector.track, selector.model_id, selector.selector_id)
        slots = sorted(slots_by_selector.get(key, []), key=lambda item: item.rank)
        if len(slots) != selector.top_k:
            raise ValueError("target selector table lost a fixed K slot")
        status_counts = Counter(
            (
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
                "inconclusive_slots": status_counts[ConfirmatoryEffectStatus.INCONCLUSIVE.value],
                "non_evaluable_slots": status_counts[ConfirmatoryEffectStatus.NON_EVALUABLE.value],
                "selector_empty_or_failure_slots": status_counts["SELECTOR_EMPTY_OR_FAILURE"],
                "bridge_or_protocolization_failure_slots": status_counts[
                    "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                ],
            }
        )
    selector_by_key = {
        (row["track"], row["model_id"], row["selector_id"]): row for row in selector_rows
    }
    rq2_rows = []
    for track, full_id, ablation_id in ((PolicyTrack.ATOMIC, "atomic_full", "atomic_rd_only"),):
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
                raise ValueError("RQ2 requires both sole-difference variants with the same K")
            rq2_rows.append(
                {
                    "track": track.value,
                    "model_id": model_id,
                    "full_selector_id": full_id,
                    "ablation_selector_id": ablation_id,
                    "top_k": full["top_k"],
                    "full_meaningful_yield_at_k": full["meaningful_yield_at_k"],
                    "ablation_meaningful_yield_at_k": ablation["meaningful_yield_at_k"],
                    "full_minus_ablation_yield_at_k": full["meaningful_yield_at_k"]
                    - ablation["meaningful_yield_at_k"],
                    "comparison_semantics": "descriptive_fixed_discovery_split_no_rank_pairing",
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
                    "estimand": "assigned_arm_task_unit_target_minus_noop_itt",
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
                    "warnings": list(estimate.warnings),
                    "critical_value": estimate.critical_value,
                    "valid_bootstrap_draws": estimate.valid_bootstrap_draws,
                    "invalid_bootstrap_draws": estimate.invalid_bootstrap_draws,
                    "task_units": estimate.task_units,
                    "assignments": estimate.assignments,
                    "arms": [
                        {
                            "arm": arm.arm.value,
                            "assignments": arm.assignments,
                            "secure_yield": arm.secure_yield,
                            "code_validity": arm.code_validity,
                            "oracle_evaluability": arm.oracle_evaluability,
                            "functionality_yield": arm.functionality_yield,
                            "joint_success_yield": arm.joint_success_yield,
                            "oracle_unknown_valid_assignments": arm.oracle_unknown_valid_assignments,
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
            authorization.protocol_id != evidence.ledger.dispatch.union.ledger.protocol_id
            or authorization.shared_evidence_record.artifact_id
            != evidence.shared_evidence_record_id
            or authorization.shared_evidence_record.sha256 != content_hash(evidence)
            or (
                authorization.target_selector_yield_result.artifact_id
                != yields.target_selector_yield_result_id
            )
            or (authorization.target_selector_yield_result.sha256 != content_hash(yields))
            or (authorization.evidence_ledger.artifact_id != evidence.ledger.evidence_ledger_id)
            or (authorization.evidence_ledger.sha256 != content_hash(evidence.ledger))
            or (authorization.evidence_level != evidence.evidence_level.value)
            or (authorization.scientific_claim_allowed is not True)
        ):
            raise ValueError("formal report authorization drifted from target evidence")
        report_status = "FORMAL_REPORT_AUTHORIZED"
    else:
        report_status = (
            "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
            if evidence.evidence_level in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
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
            None if authorization is None else authorization.formal_report_authorization_id
        ),
        "endpoint_order": [item.value for item in evidence.plan.metrics],
        "inference_method": evidence.plan.inference_method,
        "context_analysis_status": evidence.plan.context_analysis.status.value,
        "context_modifier_rows": [],
        "rq1_selector_rows": selector_rows,
        "rq2_full_minus_ablation_rows": rq2_rows,
        "primary_family_rows": family_rows,
        "unique_effect_rows": sorted(
            effect_rows, key=lambda row: (row["track"], row["candidate_record_id"])
        ),
        "independent_verification": verification,
    }
    report["target_rq_tables_id"] = content_id("target_rq_tables_", report)
    return report

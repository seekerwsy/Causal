"""Independent RQ-table and formal-claim authorization reconstruction."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from prompt_mechanism_study.inference import (
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    SharedEvidenceRecord,
    TargetITTPlan,
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
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    RQ1BudgetQualification,
    StudyFreezeIndex,
)

from prompt_mechanism_study.verification.design import verify_target_study_freezes
from prompt_mechanism_study.verification.effects import verify_target_shared_evidence

def verify_formal_report_authorization(
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
    authorization: FormalReportAuthorization,
) -> dict[str, object]:
    """Independently verify the only receipt that can enable paper-facing claims."""

    if type(authorization) is not FormalReportAuthorization:
        raise TypeError("report authorization verifier requires a formal receipt")
    freeze_verification = verify_target_study_freezes(
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
    )
    evidence_verification = verify_target_shared_evidence(evidence, yields)
    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    confirmation_task_units = {
        task.task_unit_id
        for binding in manifest.bindings
        if binding.role is DataRole.CONFIRMATION
        for task in binding.task_units
    }
    assigned_task_units = {item.task_unit_id for item in frozen_assignments}
    plan = TargetITTPlan(
        budget.power_and_margin_memo.bootstrap_seed,
        budget.power_and_margin_memo.bootstrap_draws,
        budget.power_and_margin_memo.alpha,
        budget.power_and_margin_memo.atomic_power.plan.minimum_task_units_per_stratum,
        budget.power_and_margin_memo.minimum_valid_bootstrap_fraction,
        budget.power_and_margin_memo.atomic_power.plan.practical_margin,
        budget.power_and_margin_memo.pair_power.plan.practical_margin,
        budget.power_and_margin_memo.maximum_unknown_fraction_among_valid,
    )
    if (
        evidence.evidence_level not in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
        or evidence.ledger.dispatch != dispatch
        or evidence.ledger.assignments != frozen_assignments
        or evidence.plan != plan
        or not assigned_task_units
        or not assigned_task_units <= confirmation_task_units
    ):
        raise ValueError("formal report evidence boundary failed independent replay")
    expected = (
        manifest.protocol_id,
        index.study_freeze_index_id,
        content_hash(index),
        evidence.shared_evidence_record_id,
        content_hash(evidence),
        yields.target_selector_yield_result_id,
        content_hash(yields),
        evidence.ledger.evidence_ledger_id,
        content_hash(evidence.ledger),
        content_hash(freeze_verification),
        content_hash(evidence_verification),
        evidence.evidence_level.value,
        "AUTHORIZED",
        True,
    )
    observed = (
        authorization.protocol_id,
        authorization.study_freeze_index.artifact_id,
        authorization.study_freeze_index.sha256,
        authorization.shared_evidence_record.artifact_id,
        authorization.shared_evidence_record.sha256,
        authorization.target_selector_yield_result.artifact_id,
        authorization.target_selector_yield_result.sha256,
        authorization.evidence_ledger.artifact_id,
        authorization.evidence_ledger.sha256,
        authorization.freeze_verification_sha256,
        authorization.evidence_verification_sha256,
        authorization.evidence_level,
        authorization.authorization_status,
        authorization.scientific_claim_allowed,
    )
    if observed != expected:
        raise ValueError("formal report authorization failed independent replay")
    return {
        "status": "FORMAL_REPORT_AUTHORIZATION_VERIFIED",
        "formal_report_authorization_id": (
            authorization.formal_report_authorization_id
        ),
        "scientific_claim_allowed": True,
        "evidence_level": evidence.evidence_level.value,
    }


def verify_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Independently rebuild every target RQ row and its claim-level Gate."""

    verification = verify_target_shared_evidence(evidence, yields)
    slots_by_selector: dict[tuple[PolicyTrack, str, str], list[object]] = defaultdict(list)
    for slot in yields.slots:
        slots_by_selector[(slot.track, slot.model_id, slot.selector_id)].append(slot)
    selector_rows = []
    for selector in sorted(
        yields.selectors,
        key=lambda item: (item.track.value, item.model_id, item.selector_id),
    ):
        slots = sorted(
            slots_by_selector[(selector.track, selector.model_id, selector.selector_id)],
            key=lambda item: item.rank,
        )
        if len(slots) != selector.top_k:
            raise ValueError("RQ verifier lost a fixed selector slot")
        counts = Counter(
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
                "positive_meaningful_slots": counts[
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL.value
                ],
                "negative_meaningful_slots": counts[
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL.value
                ],
                "practically_null_slots": counts[
                    ConfirmatoryEffectStatus.PRACTICALLY_NULL.value
                ],
                "inconclusive_slots": counts[
                    ConfirmatoryEffectStatus.INCONCLUSIVE.value
                ],
                "non_evaluable_slots": counts[
                    ConfirmatoryEffectStatus.NON_EVALUABLE.value
                ],
                "selector_empty_or_failure_slots": counts[
                    "SELECTOR_EMPTY_OR_FAILURE"
                ],
                "bridge_or_protocolization_failure_slots": counts[
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
                model
                for row_track, model, selector in selector_by_key
                if row_track == track.value and selector in {full_id, ablation_id}
            }
        )
        for model in models:
            full = selector_by_key.get((track.value, model, full_id))
            ablation = selector_by_key.get((track.value, model, ablation_id))
            if full is None or ablation is None or full["top_k"] != ablation["top_k"]:
                raise ValueError("RQ2 verifier lacks a sole-difference selector pair")
            rq2_rows.append(
                {
                    "track": track.value,
                    "model_id": model,
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
    families = []
    effects = []
    for family in evidence.families:
        families.append(
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
            effects.append(
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
            raise TypeError("RQ verifier requires a formal authorization receipt")
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
            raise ValueError("RQ authorization failed independent evidence binding")
        report_status = "FORMAL_REPORT_AUTHORIZED"
    else:
        report_status = (
            "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
            if evidence.evidence_level
            in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
            else "NON_CLAIM_TEST_ARTIFACT"
        )
    expected = {
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
        "primary_family_rows": families,
        "unique_effect_rows": sorted(
            effects,
            key=lambda row: (row["track"], row["candidate_record_id"]),
        ),
        "independent_verification": verification,
    }
    expected["target_rq_tables_id"] = content_id("target_rq_tables_", expected)
    if dict(report) != expected:
        raise ValueError("target RQ tables failed independent replay")
    return {
        "status": "TARGET_RQ_TABLES_VERIFIED",
        "target_rq_tables_id": expected["target_rq_tables_id"],
        "scientific_claim_allowed": claim_allowed,
        "selector_rows": len(selector_rows),
        "rq2_rows": len(rq2_rows),
        "unique_effect_rows": len(effects),
    }

__all__ = [
    "verify_formal_report_authorization",
    "verify_target_rq_tables",
]

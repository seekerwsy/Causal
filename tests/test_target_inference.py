"""Schema-3 assigned-arm ITT, fixed-K reporting, and verifier invariants."""

from __future__ import annotations

from dataclasses import replace

import pytest

from prompt_mechanism_study.inference import (
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    TargetFamilyStatus,
    TargetITTPlan,
    build_target_selector_yields,
    classify_confirmatory_interval,
    estimate_target_itt,
    freeze_assigned_arm_evidence,
)
from prompt_mechanism_study.measurement import InfrastructureFailure
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
)
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import ModelBoundCandidateRecord
from prompt_mechanism_study.selector_analysis import build_target_rq_tables
from prompt_mechanism_study.selector_verify import (
    verify_target_rq_tables,
    verify_target_shared_evidence,
)


def _target_v3_fixture():
    atomic_record = ModelBoundCandidateRecord(
        "atomic-policy-v3",
        "model.atomic",
        "phase-context-policy-v3",
        "3.0",
    )
    pair_record = ModelBoundCandidateRecord(
        "pair-policy-v3",
        "model.pair",
        "phase-context-policy-v3",
        "3.0",
    )
    sources = (
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_full",
            atomic_record.discovery_model_id,
            "atomic-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, atomic_record.policy_key, None),),
            (atomic_record,),
        ),
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_rd_only",
            atomic_record.discovery_model_id,
            "atomic-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, atomic_record.policy_key, None),),
            (atomic_record,),
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_full",
            pair_record.discovery_model_id,
            "pair-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, pair_record.policy_key, None),),
            (pair_record,),
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_no_relation",
            pair_record.discovery_model_id,
            "pair-universe-v3",
            (SelectorSlot(1, SlotStatus.FILLED, pair_record.policy_key, None),),
            (pair_record,),
        ),
    )
    ledger = freeze_fixed_slot_ledger(
        "phase-context-policy-v3",
        "3.0",
        sources,
    )
    union = freeze_shared_confirmation_union(ledger)
    dispatch = freeze_confirmation_dispatch(
        union,
        {
            atomic_record.candidate_record_id: "atomic-protocol-record-v3",
            pair_record.candidate_record_id: "pair-protocol-record-v3",
        },
    )
    entry_by_track = {item.track: item for item in union.entries}
    dispatch_by_candidate = {
        item.candidate_record_id: item for item in dispatch.records
    }
    assignments = []
    outcomes = []
    for track, arms in (
        (PolicyTrack.ATOMIC, ATOMIC_CONFIRMATORY_ARMS),
        (PolicyTrack.PAIR, PAIR_CONFIRMATORY_ARMS),
    ):
        entry = entry_by_track[track]
        dispatched = dispatch_by_candidate[entry.candidate_record_id]
        for index in range(12):
            for request_slot, arm in enumerate(arms):
                assignment = AssignedArmITTRecord(
                    entry.candidate_record_id,
                    entry.effect_coordinate_id,
                    entry.candidate.policy_key,
                    entry.candidate.discovery_model_id,
                    track,
                    f"{track.value}-unit-{index:02d}",
                    f"{track.value}-task-{index:02d}",
                    "synthetic-stratum",
                    f"{track.value}-realization-v1",
                    f"{track.value}-bundle-{index:02d}",
                    dispatched.protocol_record_id,
                    request_slot,
                    arm,
                    1.0,
                    1.0,
                    content_hash((track.value, index, arm.value)),
                )
                assignments.append(assignment)
                if track is PolicyTrack.ATOMIC:
                    secure = (
                        index < 10
                        if arm.value == "atomic_target"
                        else index < 1
                        if arm.value == "atomic_noop"
                        else index % 3 == 0
                    )
                    unknown = arm.value == "atomic_target" and index == 11
                else:
                    secure = (
                        index < 10
                        if arm.value == "pair_11"
                        else index < 1
                    )
                    unknown = False
                outcomes.append(
                    Outcome(
                        assignment.assignment_id,
                        1,
                        0 if unknown else 1,
                        int(secure and not unknown),
                        int(secure or unknown),
                        1,
                        None if unknown else int(secure),
                        int(secure or unknown),
                        None,
                    )
                )
    evidence = freeze_assigned_arm_evidence(dispatch, assignments, outcomes)
    plan = TargetITTPlan(
        20260831,
        300,
        0.05,
        4,
        0.8,
        0.05,
        0.05,
        0.5,
    )
    return evidence, plan


@pytest.mark.reviewer
def test_target_v3_shared_itt_confirms_each_unique_effect_once_and_fans_out() -> None:
    evidence, plan = _target_v3_fixture()

    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)
    verification = verify_target_shared_evidence(result, yields)

    assert tuple(item.status for item in result.families) == (
        TargetFamilyStatus.EVALUABLE,
        TargetFamilyStatus.EVALUABLE,
    )
    estimates = tuple(item for family in result.families for item in family.estimates)
    assert len(estimates) == 2
    assert all(item.status is ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL for item in estimates)
    assert all(item.assignments == 48 and item.task_units == 12 for item in estimates)
    atomic = next(item for item in estimates if item.track is PolicyTrack.ATOMIC)
    assert atomic.point == pytest.approx(0.75)
    assert atomic.latent_upper > atomic.point
    target_summary = atomic.arm_summaries[0]
    assert target_summary.oracle_unknown_valid_assignments == 1
    assert len(yields.slots) == 4
    assert all(item.meaningful_yield == 1 for item in yields.slots)
    assert all(item.top_k == 1 and item.meaningful_yield_at_k == 1 for item in yields.selectors)
    assert verification["status"] == "TARGET_SHARED_EVIDENCE_VERIFIED"


@pytest.mark.reviewer
def test_target_v3_rq_tables_are_fixed_denominator_and_claim_gated() -> None:
    evidence, plan = _target_v3_fixture()
    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)

    report = build_target_rq_tables(result, yields)
    verification = verify_target_rq_tables(result, yields, report)

    assert report["report_status"] == "NON_CLAIM_TEST_ARTIFACT"
    assert report["scientific_claim_allowed"] is False
    assert len(report["rq1_selector_rows"]) == 4
    assert len(report["rq2_full_minus_ablation_rows"]) == 2
    assert all(
        row["top_k"] == 1 and row["meaningful_yield_at_k"] == 1.0
        for row in report["rq1_selector_rows"]
    )
    assert all(
        row["full_minus_ablation_yield_at_k"] == 0.0
        and row["comparison_semantics"]
        == "descriptive_fixed_discovery_split_no_rank_pairing"
        for row in report["rq2_full_minus_ablation_rows"]
    )
    assert verification["status"] == "TARGET_RQ_TABLES_VERIFIED"

    tampered = {
        **report,
        "rq2_full_minus_ablation_rows": [
            {**report["rq2_full_minus_ablation_rows"][0], "top_k": 99},
            *report["rq2_full_minus_ablation_rows"][1:],
        ],
    }
    tampered["target_rq_tables_id"] = content_hash(tampered)
    with pytest.raises(ValueError, match="failed independent replay"):
        verify_target_rq_tables(result, yields, tampered)


@pytest.mark.reviewer
def test_target_v3_independent_verifier_rejects_effect_drift() -> None:
    evidence, plan = _target_v3_fixture()
    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    estimate = result.families[0].estimates[0]
    tampered_estimate = replace(estimate, point=estimate.point + 0.01)
    tampered_family = replace(
        result.families[0],
        estimates=(tampered_estimate,),
    )
    tampered = replace(
        result,
        families=(tampered_family, result.families[1]),
    )
    yields = build_target_selector_yields(tampered)

    with pytest.raises(ValueError, match="point estimate"):
        verify_target_shared_evidence(tampered, yields)


@pytest.mark.reviewer
def test_target_v3_missing_assigned_outcome_invalidates_only_its_frozen_family() -> None:
    evidence, plan = _target_v3_fixture()
    missing = next(
        item
        for item in evidence.assignments
        if item.track is PolicyTrack.ATOMIC
    )
    outcomes = tuple(
        item for item in evidence.outcomes if item.assignment_id != missing.assignment_id
    )
    incomplete = freeze_assigned_arm_evidence(
        evidence.dispatch,
        evidence.assignments,
        outcomes,
        (InfrastructureFailure(missing.assignment_id, "generator", "synthetic failure"),),
    )

    result = estimate_target_itt(incomplete, plan, evidence_level=EvidenceLevel.TESTED)

    assert result.families[0].status is TargetFamilyStatus.INVALID_PROVENANCE
    assert result.families[0].estimates[0].status is ConfirmatoryEffectStatus.NON_EVALUABLE
    assert result.families[1].status is TargetFamilyStatus.EVALUABLE
    assert len(incomplete.outcomes) + len(incomplete.infrastructure_failures) == len(
        incomplete.assignments
    )


@pytest.mark.reviewer
def test_target_v3_protocolization_failure_keeps_slots_but_creates_no_test() -> None:
    evidence, plan = _target_v3_fixture()
    entry_by_track = {
        item.track: item for item in evidence.dispatch.union.entries
    }
    atomic = entry_by_track[PolicyTrack.ATOMIC]
    pair = entry_by_track[PolicyTrack.PAIR]
    dispatch = freeze_confirmation_dispatch(
        evidence.dispatch.union,
        {atomic.candidate_record_id: "atomic-protocol-record-v3"},
        failures={
            pair.candidate_record_id: (
                BridgeStatus.PROTOCOLIZATION_FAILED,
                "synthetic protocolization failure",
            )
        },
    )
    assignments = tuple(
        item
        for item in evidence.assignments
        if item.candidate_record_id == atomic.candidate_record_id
    )
    assignment_ids = {item.assignment_id for item in assignments}
    outcomes = tuple(
        item for item in evidence.outcomes if item.assignment_id in assignment_ids
    )
    atomic_only = freeze_assigned_arm_evidence(dispatch, assignments, outcomes)

    result = estimate_target_itt(atomic_only, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)
    verification = verify_target_shared_evidence(result, yields)

    assert result.families[1].status is TargetFamilyStatus.NO_ELIGIBLE_COORDINATES
    assert not result.families[1].estimates
    pair_slots = [item for item in yields.slots if item.track is PolicyTrack.PAIR]
    assert len(pair_slots) == 2
    assert all(item.meaningful_yield == 0 and item.effect_status is None for item in pair_slots)
    assert verification["unique_effects"] == 1


@pytest.mark.reviewer
def test_target_v3_five_status_boundaries_are_direction_free() -> None:
    margin = 0.1

    assert classify_confirmatory_interval(0.100001, 0.3, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL
    )
    assert classify_confirmatory_interval(-0.3, -0.100001, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL
    )
    assert classify_confirmatory_interval(-0.1, 0.1, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.PRACTICALLY_NULL
    )
    assert classify_confirmatory_interval(0.1, 0.1, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.PRACTICALLY_NULL
    )
    assert classify_confirmatory_interval(-0.2, 0.2, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.INCONCLUSIVE
    )
    assert classify_confirmatory_interval(None, None, margin, evaluable=False) is (
        ConfirmatoryEffectStatus.NON_EVALUABLE
    )

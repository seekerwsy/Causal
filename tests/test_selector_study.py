"""Atomic schema-3 prioritization, baseline, slot, and backend invariants."""

from __future__ import annotations

from dataclasses import replace

import pytest

from prompt_mechanism_study import prioritization
from prompt_mechanism_study.prioritization import (
    AtomicFCIBootstrapEvidence,
    AtomicFCIGateStatus,
    AtomicSelectorVariant,
    AtomicShadowPlan,
    ConfirmationDispatchManifest,
    DiscoveryObservation,
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
    atomic_preoutcome_observations,
    discovery_data_sha256,
    freeze_atomic_candidate_folds,
    freeze_atomic_candidate_universe,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
    run_atomic_shadow_qualification,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.rq1_baselines import (
    BlindExpertRankingCard,
    SeededRandomRankingPlan,
    freeze_atomic_baseline_universe,
    run_blind_expert_baseline,
    run_seeded_random_baseline,
    verify_rq1_baseline_result,
)
from prompt_mechanism_study.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    ModelBoundCandidateRecord,
    Operation,
    PolicyFactor,
)


def _atomic_shadow_fixture():
    outcome_id = "oracle_evaluable_secure_code_yield"
    first = AtomicPolicyKey(
        AnalysisScope(
            "security-pattern-a",
            "context-a",
            ("python",),
            ("local-api",),
            ("family-a",),
        ),
        PolicyFactor("feature.first", Operation.ADD),
        outcome_id,
    )
    second = AtomicPolicyKey(
        AnalysisScope(
            "security-pattern-b",
            "context-b",
            ("python",),
            ("local-api",),
            ("family-b",),
        ),
        PolicyFactor("feature.second", Operation.REMOVE),
        outcome_id,
    )
    policies = (first, second)
    family_by_policy = {
        first.policy_key: "family-a",
        second.policy_key: "family-b",
    }
    rows = []
    for policy in policies:
        for index in range(24):
            target_state = index % 2
            natural_state = (
                target_state
                if policy.factor.operation is Operation.ADD
                else 1 - target_state
            )
            outcome = (
                target_state
                if policy.policy_key == first.policy_key
                else 1 - target_state
            )
            rows.append(
                DiscoveryObservation(
                    f"{family_by_policy[policy.policy_key]}-task-{index:02d}",
                    "model-a",
                    family_by_policy[policy.policy_key],
                    0,
                    ((policy.policy_key, natural_state),),
                    (("source_code", float((index // 2) % 2)),),
                    outcome,
                )
            )
    observations = tuple(rows)
    records = tuple(
        ModelBoundCandidateRecord(policy.policy_key, "model-a", "phase-context-policy-v3", "3.0")
        for policy in policies
    )
    universe = freeze_atomic_candidate_universe(
        policies,
        records,
        supported_policy_keys=tuple(policy.policy_key for policy in policies),
        realization_policy_ids={
            policy.policy_key: f"realization-{index}"
            for index, policy in enumerate(policies)
        },
        candidate_family_ids=family_by_policy,
        discovery_data_sha256=discovery_data_sha256(observations),
        positivity_audit_sha256=content_hash("atomic-positivity"),
        information_budget_sha256=content_hash("atomic-info-budget"),
        top_k=2,
        representation_adapter_id="prompt-tsg-v3",
    )
    draws = {
        first.policy_key: (True,) * 8 + (None,) * 2,
        second.policy_key: (False,) * 10,
    }
    evidence = AtomicFCIBootstrapEvidence(
        universe.universe_id,
        tuple((candidate_id, draws[candidate_id]) for candidate_id in universe.supported_policy_keys),
        content_hash("atomic-fci-bootstrap"),
    )
    plan = AtomicShadowPlan(
        "model-a",
        ("source_code",),
        4,
        0.05,
        2026083101,
        0.8,
        0.5,
    )
    return universe, observations, plan, evidence, first.policy_key, second.policy_key


@pytest.mark.reviewer
@pytest.mark.extended
def test_atomic_full_and_rd_only_share_everything_except_fci_gate() -> None:
    universe, rows, plan, evidence, positive_id, negative_id = _atomic_shadow_fixture()

    result = run_atomic_shadow_qualification(
        universe,
        rows,
        plan,
        evidence,
        fold_freeze=freeze_atomic_candidate_folds(
            universe,
            atomic_preoutcome_observations(rows),
            plan,
        ),
    )
    score_by_id = {item.candidate_id: item for item in result.rd_scores}
    gate_by_id = {item.candidate_id: item for item in result.fci_gates}

    assert score_by_id[positive_id].signed_risk_difference > 0
    assert score_by_id[negative_id].signed_risk_difference < 0
    assert gate_by_id[positive_id].valid_fraction == 0.8
    assert gate_by_id[positive_id].adjacency_stability == 1.0
    assert gate_by_id[positive_id].status is AtomicFCIGateStatus.PASSED
    assert gate_by_id[negative_id].status is AtomicFCIGateStatus.FAILED
    assert result.full.variant is AtomicSelectorVariant.FULL
    assert result.rd_only.variant is AtomicSelectorVariant.RD_ONLY
    assert result.full.fold_manifests_sha256 == result.rd_only.fold_manifests_sha256
    assert result.full.rd_scores_sha256 == result.rd_only.rd_scores_sha256
    assert result.full.fci_gate_evidence_sha256 is not None
    assert result.rd_only.fci_gate_evidence_sha256 is None
    assert result.full.slots[0].candidate_id == positive_id
    assert {item.candidate_id for item in result.rd_only.ranking} == {
        positive_id,
        negative_id,
    }
    assert result.sole_difference.full_additional_read == "fci_gate"
    assert result.sole_difference.rd_only_additional_reads == ()
    for manifest in result.fold_manifests:
        for fold in range(manifest.fold_count):
            assert {
                item.target_state for item in manifest.assignments if item.fold == fold
            } == {0, 1}


@pytest.mark.reviewer
@pytest.mark.extended
def test_atomic_rq1_baselines_share_universe_and_replay_blind_rankings() -> None:
    universe, rows, plan, evidence, _positive_id, _negative_id = (
        _atomic_shadow_fixture()
    )
    core = run_atomic_shadow_qualification(
        universe,
        rows,
        plan,
        evidence,
        fold_freeze=freeze_atomic_candidate_folds(
            universe,
            atomic_preoutcome_observations(rows),
            plan,
        ),
    )
    baseline_universe = freeze_atomic_baseline_universe(universe)
    expert_card = BlindExpertRankingCard(
        baseline_universe.protocol_id,
        baseline_universe.schema_version,
        PolicyTrack.ATOMIC,
        "atomic_blind_expert",
        baseline_universe.model_id,
        baseline_universe.baseline_universe_id,
        baseline_universe.candidate_material_sha256,
        (
            "analysis_scope",
            "candidate_family",
            "factor_operations",
            "mechanism_realization",
            "support_summary",
        ),
        (
            "confirmation_assignments",
            "confirmation_outcomes",
            "discovery_outcomes",
            "fci_evidence",
            "rd_scores",
            "relation_evidence",
            "selector_rankings",
        ),
        tuple(reversed(baseline_universe.eligible_policy_keys)),
        content_hash("atomic-expert-identity"),
        content_hash("atomic-expert-instructions"),
        content_hash("atomic-expert-independent-review"),
    )
    expert = run_blind_expert_baseline(baseline_universe, expert_card)
    expert_receipt = verify_rq1_baseline_result(
        baseline_universe,
        expert,
        expert_card=expert_card,
    )

    random_plan = SeededRandomRankingPlan(
        baseline_universe.protocol_id,
        baseline_universe.schema_version,
        PolicyTrack.ATOMIC,
        "atomic_seeded_random",
        baseline_universe.model_id,
        baseline_universe.baseline_universe_id,
        baseline_universe.candidate_material_sha256,
        20260831,
        content_hash("atomic-random-seed-source"),
    )
    random_result = run_seeded_random_baseline(baseline_universe, random_plan)
    random_receipt = verify_rq1_baseline_result(
        baseline_universe,
        random_result,
        random_plan=random_plan,
    )

    assert expert.source.universe_id == universe.universe_id
    assert tuple(
        item.policy_key for item in baseline_universe.expert_candidate_cards
    ) == baseline_universe.eligible_policy_keys
    assert all(
        item.support_summary == (("support_gate_passed", 1),)
        for item in baseline_universe.expert_candidate_cards
    )
    assert random_result.source.universe_id == universe.universe_id
    assert expert.source.model_bound_records == universe.model_bound_records
    assert random_result == run_seeded_random_baseline(
        baseline_universe,
        random_plan,
    )
    assert expert_receipt.status == random_receipt.status == "PASS"
    ledger = freeze_fixed_slot_ledger(
        baseline_universe.protocol_id,
        baseline_universe.schema_version,
        (
            FixedSlotSource(
                PolicyTrack.ATOMIC,
                "atomic_full",
                baseline_universe.model_id,
                universe.universe_id,
                core.full.slots,
                universe.model_bound_records,
            ),
            FixedSlotSource(
                PolicyTrack.ATOMIC,
                "atomic_rd_only",
                baseline_universe.model_id,
                universe.universe_id,
                core.rd_only.slots,
                universe.model_bound_records,
            ),
            expert.source,
            random_result.source,
        ),
    )
    union = freeze_shared_confirmation_union(ledger)
    assert {source.selector_id for source in ledger.sources} == {
        "atomic_blind_expert",
        "atomic_full",
        "atomic_rd_only",
        "atomic_seeded_random",
    }
    assert len(union.entries) == len(
        {
            slot.candidate_record_id
            for slot in ledger.slots
            if slot.candidate_record_id is not None
        }
    )
    with pytest.raises(ValueError, match="cannot use discovery or confirmation"):
        replace(expert_card, arms_or_outcomes_used=True)
    with pytest.raises(ValueError, match="drifts from the frozen eligible universe"):
        run_blind_expert_baseline(
            baseline_universe,
            replace(expert_card, protocol_id="another-protocol"),
        )
    with pytest.raises(ValueError, match="failed independent replay"):
        verify_rq1_baseline_result(
            baseline_universe,
            random_result,
            random_plan=replace(random_plan, ranking_seed=20260830),
        )


@pytest.mark.reviewer
@pytest.mark.extended
def test_atomic_fci_insufficient_valid_fraction_is_non_evaluable() -> None:
    universe, rows, plan, evidence, positive_id, _negative_id = _atomic_shadow_fixture()
    insufficient = replace(
        evidence,
        candidate_draws=tuple(
            (
                candidate_id,
                (True,) * 7 + (None,) * 3
                if candidate_id == positive_id
                else draws,
            )
            for candidate_id, draws in evidence.candidate_draws
        ),
        evidence_sha256=content_hash("atomic-fci-insufficient-valid-draws"),
    )

    result = run_atomic_shadow_qualification(
        universe,
        rows,
        plan,
        insufficient,
        fold_freeze=freeze_atomic_candidate_folds(
            universe,
            atomic_preoutcome_observations(rows),
            plan,
        ),
    )
    gate = next(item for item in result.fci_gates if item.candidate_id == positive_id)

    assert gate.valid_fraction == 0.7
    assert gate.adjacency_stability == 1.0
    assert gate.status is AtomicFCIGateStatus.NON_EVALUABLE
    assert not any(slot.candidate_id == positive_id for slot in result.full.slots)
    assert any(slot.candidate_id == positive_id for slot in result.rd_only.slots)


@pytest.mark.reviewer
def test_fixed_slots_deduplicate_one_model_effect_and_preserve_fanout() -> None:
    universe, observations, plan, evidence, first, second = _atomic_shadow_fixture()
    atomic = run_atomic_shadow_qualification(
        universe,
        observations,
        plan,
        evidence,
        fold_freeze=freeze_atomic_candidate_folds(
            universe,
            atomic_preoutcome_observations(observations),
            plan,
        ),
    )
    pair_record = ModelBoundCandidateRecord(
        "pair-policy-synthetic",
        "model-b",
        "phase-context-policy-v3",
        "3.0",
    )
    pair_slots = (
        SelectorSlot(1, SlotStatus.FILLED, pair_record.policy_key, None),
        SelectorSlot(2, SlotStatus.NON_EVALUABLE, None, "pair_rd_non_evaluable"),
    )
    sources = (
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_full",
            "model-a",
            universe.universe_id,
            atomic.full.slots,
            universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_rd_only",
            "model-a",
            universe.universe_id,
            atomic.rd_only.slots,
            universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_full",
            "model-b",
            "pair-universe-synthetic",
            pair_slots,
            (pair_record,),
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_no_relation",
            "model-b",
            "pair-universe-synthetic",
            pair_slots,
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
            item.candidate_record_id: f"protocol-{index}"
            for index, item in enumerate(union.entries)
        },
    )

    assert len(ledger.slots) == 8
    assert sum(item.status is SlotStatus.NON_EVALUABLE for item in ledger.slots) == 2
    assert {item.candidate.policy_key for item in union.entries} == {
        first,
        second,
        pair_record.policy_key,
    }
    fanout = {
        item.candidate_record_id: item.slot_ids for item in union.candidate_to_slots
    }
    first_record = next(
        item for item in universe.model_bound_records if item.policy_key == first
    )
    assert len(fanout[first_record.candidate_record_id]) == 2
    assert len(fanout[pair_record.candidate_record_id]) == 2
    assert len(dispatch.records) == len(union.entries)
    assert {item.model_id for item in dispatch.records} == {"model-a", "model-b"}
    assert all(item.dispatch_count == 1 for item in dispatch.records)

    tampered = replace(dispatch.records[0], model_id="wrong-model")
    with pytest.raises(ValueError, match="model-bound effect coordinate"):
        ConfirmationDispatchManifest(
            union,
            (tampered, *dispatch.records[1:]),
        )



@pytest.mark.milestone
def test_pinned_causal_learn_backend_capability_when_installed() -> None:
    pytest.importorskip("causallearn")
    assert prioritization._causal_learn_version() == "0.1.4.7"
    matrix = tuple((index % 2, (index // 2) % 2, index % 2) for index in range(40))
    adjacent = prioritization._run_causal_learn_family(
        matrix,
        alpha=0.05,
        depth=-1,
        max_path_length=-1,
        outcome_index=2,
    )
    assert isinstance(adjacent, set)
    pag_adjacent, edges = prioritization._run_causal_learn_pag(
        matrix,
        alpha=0.05,
        depth=-1,
        max_path_length=-1,
        outcome_index=2,
        variable_order=("W:group", "X:feature", "Y:outcome"),
        forbidden_directions=(("Y:outcome", "W:group"), ("Y:outcome", "X:feature")),
    )
    assert isinstance(pag_adjacent, set)
    assert isinstance(edges, tuple)

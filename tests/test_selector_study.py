from __future__ import annotations

from dataclasses import replace

import pytest

from prompt_mechanism_study import prioritization
from prompt_mechanism_study.prioritization import (
    BackgroundKnowledgeRule,
    BridgeRecord,
    BridgeStatus,
    DiscoveryObservation,
    ExpertRankingInput,
    FrozenFCIRelationScores,
    SelectorKind,
    SelectorRunStatus,
    SelectorSuitePlan,
    SlotStatus,
    discovery_data_sha256,
    freeze_candidate_universe_manifest,
    freeze_shared_bridge_map,
    run_selector_suite,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import (
    Candidate,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    TargetSpecV2,
    freeze_universe,
)
from prompt_mechanism_study.selector_inference import (
    ConfirmationCoordinate,
    SelectorInferencePlan,
    evaluate_selector_study,
)
from prompt_mechanism_study.selector_verify import verify_selector_result


def _fixture(*, supported: bool = True):
    catalog_candidates = (
        (
            "context.untrusted_argument_to_fixed_process.v1",
            "feature.argv_without_shell",
            "CWE-78",
        ),
        (
            "context.untrusted_argument_to_finite_process_choice.v1",
            "feature.executable_allowlist_and_argv",
            "CWE-78",
        ),
        (
            "context.untrusted_value_to_fixed_sql.v1",
            "feature.sql_value_parameterization",
            "CWE-89",
        ),
        (
            "context.finite_dynamic_identifier_sql.v1",
            "feature.sql_identifier_allowlist_and_values",
            "CWE-89",
        ),
    )
    candidates = tuple(
        Candidate(
            f"candidate.{index}",
            context_query_id,
            feature_id,
            Operation.ADD if index % 2 == 0 else Operation.REMOVE,
            cwe,
            "oracle_evaluable_secure_code_yield",
            ExpectedDirection.INCREASE,
        )
        for index, (context_query_id, feature_id, cwe) in enumerate(
            catalog_candidates
        )
    )
    universe = freeze_universe(candidates, representation_adapter_id="prompt-tsg-v2")
    candidate_ids = tuple(item.candidate_id for item in universe.candidates)
    rows = []
    for index in range(40):
        outcome = index % 2
        states = {
            candidate_ids[0]: outcome,
            candidate_ids[1]: (index // 2) % 2,
            candidate_ids[2]: (index // 3) % 2,
            candidate_ids[3]: (index // 5) % 2,
        }
        for family_id, family_candidates in (
            ("family-a", (candidate_ids[0], candidate_ids[2])),
            ("family-b", (candidate_ids[1], candidate_ids[3])),
        ):
            rows.append(
                DiscoveryObservation(
                    f"task-unit-{index:02d}-{family_id}",
                    "model-a",
                    family_id,
                    0,
                    tuple((candidate_id, states[candidate_id]) for candidate_id in family_candidates),
                    (("source_group", float(index % 3)),),
                    outcome,
                )
            )
    frozen_rows = tuple(rows)
    manifest = freeze_candidate_universe_manifest(
        universe,
        supported_candidate_ids=candidate_ids if supported else (),
        realization_policy_ids={candidate_id: f"realization-policy-{index}" for index, candidate_id in enumerate(candidate_ids)},
        candidate_family_ids={
            candidate_id: ("family-a" if index in {0, 2} else "family-b")
            for index, candidate_id in enumerate(candidate_ids)
        },
        discovery_data_sha256=discovery_data_sha256(frozen_rows),
        positivity_audit_sha256=content_hash("positivity-audit"),
        information_budget_sha256=content_hash("same-information-budget"),
        outcome_id="oracle_evaluable_secure_code_yield",
        top_k=3,
    )
    plan = SelectorSuitePlan("model-a", 1.0, 4, (11, 22, 33))
    fci_scores = FrozenFCIRelationScores(
        manifest.manifest_id,
        plan.plan_id,
        content_hash("frozen-fci-relation-evidence"),
        tuple(
            (candidate_id, float(4 - index))
            for index, candidate_id in enumerate(candidate_ids)
        ),
    )
    expert = ExpertRankingInput(
        manifest.manifest_id,
        "model-a",
        content_hash("blinded-candidate-cards"),
        tuple(reversed(candidate_ids)),
        True,
        False,
    )
    return manifest, frozen_rows, plan, candidate_ids, fci_scores, expert


@pytest.mark.extended
def test_association_score_respects_remove_baseline_and_expected_direction() -> None:
    manifest, _rows, _plan, candidate_ids, _fci, _expert = _fixture()
    candidate_id = candidate_ids[0]
    skeleton = replace(
        dict(manifest.candidate_skeletons)[candidate_id],
        operation=Operation.REMOVE,
        expected_direction=ExpectedDirection.DECREASE,
    )
    observations = (
        DiscoveryObservation(
            "baseline-present",
            "model-a",
            "family-a",
            0,
            ((candidate_id, 1),),
            (("source_group", 0.0),),
            1,
        ),
        DiscoveryObservation(
            "target-absent",
            "model-a",
            "family-a",
            0,
            ((candidate_id, 0),),
            (("source_group", 0.0),),
            0,
        ),
    )

    decrease_scores, failures, _evidence = prioritization._association_scores(
        observations,
        (candidate_id,),
        {candidate_id: skeleton},
    )
    increase_scores, _failures, _evidence = prioritization._association_scores(
        observations,
        (candidate_id,),
        {
            candidate_id: replace(
                skeleton,
                expected_direction=ExpectedDirection.INCREASE,
            )
        },
    )

    assert failures == ()
    assert decrease_scores[candidate_id] == 1.0
    assert increase_scores[candidate_id] == -1.0


@pytest.mark.reviewer
@pytest.mark.extended
def test_gate_failure_is_closed_before_any_selector_ranking() -> None:
    manifest, rows, plan, _ids, _scores, _expert = _fixture(supported=False)
    result = run_selector_suite(
        manifest,
        rows,
        plan,
        fci_relation_scores=FrozenFCIRelationScores(
            manifest.manifest_id,
            plan.plan_id,
            content_hash("unread-because-gate-failed"),
            (("deliberately-invalid-and-unread", 1.0),),
        ),
    )

    assert result.gate_passed is False
    assert result.runs == ()
    assert result.selected_union_candidate_ids == ()
    assert result.gate_failure_reason == "no_candidate_passed_the_frozen_positivity_gate"


@pytest.mark.extended
def test_five_selectors_share_one_universe_and_keep_explicit_k_slots() -> None:
    manifest, rows, plan, candidate_ids, fci_scores, _expert = _fixture()
    result = run_selector_suite(
        manifest,
        rows,
        plan,
        fci_relation_scores=fci_scores,
        expert_input=None,
    )
    replay = run_selector_suite(
        manifest,
        tuple(reversed(rows)),
        plan,
        fci_relation_scores=fci_scores,
        expert_input=None,
    )

    assert result == replay
    assert tuple(run.kind for run in result.runs) == tuple(SelectorKind)
    assert all(run.universe_manifest_id == manifest.manifest_id for run in result.runs)
    assert all(
        len(ranking.slots) == manifest.top_k
        for run in result.runs
        for ranking in run.rankings
    )
    random_run = next(run for run in result.runs if run.kind is SelectorKind.RANDOM)
    assert len(random_run.rankings) == len(plan.random_seeds)
    expert_run = next(run for run in result.runs if run.kind is SelectorKind.EXPERT)
    assert expert_run.status is SelectorRunStatus.FAILED
    assert all(
        slot.status is SlotStatus.SELECTOR_FAILED
        for slot in expert_run.rankings[0].slots
    )
    assert set(result.selected_union_candidate_ids) <= set(candidate_ids)


@pytest.mark.extended
def test_fci_uses_family_local_task_unit_bootstrap_stability(monkeypatch) -> None:
    manifest, rows, plan, candidate_ids, _frozen_scores, _expert = _fixture()
    calls = []

    monkeypatch.setattr(prioritization, "_causal_learn_version", lambda: "0.1.4.7")

    def fake_backend(matrix, *, alpha, depth, max_path_length, outcome_index, variable_order, forbidden_directions):
        calls.append((len(matrix), len(matrix[0]), alpha, depth, max_path_length, outcome_index))
        assert len(matrix) == 40
        assert len(matrix[0]) == 4  # one W, two family-local X values, and Y
        assert outcome_index == 3
        return {1}, ((variable_order[1], "CIRCLE", variable_order[-1], "CIRCLE"),)

    monkeypatch.setattr(prioritization, "_run_causal_learn_pag", fake_backend)
    result = run_selector_suite(manifest, rows, plan, expert_input=None)
    fci = next(run for run in result.runs if run.kind is SelectorKind.FCI)
    scores = {item.candidate_id: item.score for item in fci.rankings[0].scores}

    # raw, temporal, full, wrong, then every primary bootstrap draw (legacy v1 has no domain family).
    assert len(calls) == 2 * (4 + plan.fci_bootstrap_draws)
    assert scores[candidate_ids[0]] == scores[candidate_ids[1]] == 1.0
    assert scores[candidate_ids[2]] == scores[candidate_ids[3]] == 0.0
    assert fci.rankings[0].evidence_sha256 != content_hash(scores)


@pytest.mark.extended
def test_prospective_v2_freezes_slot_and_real_pag_bk_sensitivities(monkeypatch) -> None:
    manifest, rows, legacy, candidate_ids, _scores, _expert = _fixture()
    rows = tuple(
        item
        for row in rows
        for item in (row, replace(row, request_randomness_slot=1, outcome=1 - row.outcome))
    )
    manifest = replace(manifest, discovery_data_sha256=discovery_data_sha256(rows))
    rules = []
    wrong = []
    by_family = dict(manifest.candidate_family_ids)
    for family_id in sorted(set(by_family.values())):
        first, second = tuple(candidate for candidate in candidate_ids if by_family[candidate] == family_id)
        rules.extend((
            BackgroundKnowledgeRule(f"temporal-{family_id}", family_id, "temporal", "temporal_order", "Y:discovery_outcome", f"X:{first}"),
            BackgroundKnowledgeRule(f"domain-{family_id}", family_id, "domain-order", "reviewed_domain", f"X:{first}", f"X:{second}"),
        ))
        wrong.append(BackgroundKnowledgeRule(f"wrong-{family_id}", family_id, "wrong-direction", "wrong_plausible", f"X:{first}", "Y:discovery_outcome"))
    plan = replace(
        legacy,
        behavior_version="shared-selector-suite-v2",
        fci_background_knowledge=tuple(rules),
        fci_wrong_bk_perturbation=tuple(wrong),
    )
    monkeypatch.setattr(prioritization, "_causal_learn_version", lambda: "0.1.4.7")

    def fake_pag(matrix, *, outcome_index, variable_order, forbidden_directions, **_kwargs):
        feature = next(index for index, name in enumerate(variable_order) if name.startswith("X:"))
        return {feature}, ((variable_order[feature], "CIRCLE", variable_order[outcome_index], "CIRCLE"),)

    monkeypatch.setattr(prioritization, "_run_causal_learn_pag", fake_pag)
    frozen = run_selector_suite(manifest, rows, plan)

    assert frozen.sensitivity_audit is not None
    assert frozen.sensitivity_audit.common_request_randomness_slots == (0, 1)
    assert len(frozen.sensitivity_audit.multi_slot_task_means) == 80
    assert {item.analysis for item in frozen.sensitivity_audit.rankings} == {
        "fixed_reference", "two_level_slot", "multi_slot"
    }
    assert frozen.fci_background_knowledge_audit_json is not None
    assert '"raw_minimal"' in frozen.fci_background_knowledge_audit_json
    assert '"temporal_only"' in frozen.fci_background_knowledge_audit_json
    assert '"full_typed"' in frozen.fci_background_knowledge_audit_json
    assert '"wrong_plausible"' in frozen.fci_background_knowledge_audit_json
    assert '"domain_family_removals"' in frozen.fci_background_knowledge_audit_json
    assert '"changed_candidate_ids_vs_full"' in frozen.fci_background_knowledge_audit_json
    assert '"rank_change":"not_estimated"' in frozen.fci_background_knowledge_audit_json

    hypotheses = {}
    for candidate_id in frozen.selected_union_candidate_ids:
        skeleton = dict(frozen.universe.candidate_skeletons)[candidate_id]
        hypotheses[candidate_id] = FrozenHypothesisV2(
            skeleton,
            TargetSpecV2(
                skeleton.candidate_skeleton_id, skeleton.context_query_id,
                skeleton.actionable_feature_id, skeleton.operation,
                content_hash("context-catalog"), content_hash("feature-catalog"),
                content_hash("allowed-delta"),
            ),
        )
    bridge = freeze_shared_bridge_map(frozen, tuple(
        BridgeRecord(candidate_id, BridgeStatus.SUCCESS, hypothesis.hypothesis_id, None, hypothesis)
        for candidate_id, hypothesis in hypotheses.items()
    ))
    assert len(bridge.records) == len(frozen.selected_union_candidate_ids)
    first = frozen.selected_union_candidate_ids[0]
    other = next(value for key, value in hypotheses.items() if key != first)
    bad = tuple(
        BridgeRecord(candidate_id, BridgeStatus.SUCCESS, (other if candidate_id == first else hypothesis).hypothesis_id, None, other if candidate_id == first else hypothesis)
        for candidate_id, hypothesis in hypotheses.items()
    )
    with pytest.raises(ValueError, match="predecessor skeleton"):
        freeze_shared_bridge_map(frozen, bad)



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


@pytest.mark.extended
def test_blind_expert_contract_rejects_confirm_outcome_access() -> None:
    manifest, rows, plan, candidate_ids, fci_scores, expert = _fixture()
    with pytest.raises(ValueError, match="confirm-outcome blind"):
        ExpertRankingInput(
            manifest.manifest_id,
            plan.model_id,
            expert.candidate_card_sha256,
            candidate_ids,
            True,
            True,
        )
    complete = run_selector_suite(
        manifest,
        rows,
        plan,
        fci_relation_scores=fci_scores,
        expert_input=expert,
    )
    assert next(run for run in complete.runs if run.kind is SelectorKind.EXPERT).status is SelectorRunStatus.COMPLETE


def _evaluated_result():
    manifest, rows, suite_plan, candidate_ids, fci_scores, expert = _fixture()
    selection = run_selector_suite(
        manifest,
        rows,
        suite_plan,
        fci_relation_scores=fci_scores,
        expert_input=expert,
    )
    records = []
    coordinates = []
    task_units = tuple(f"confirm-unit-{index:02d}" for index in range(40))
    for index, candidate_id in enumerate(selection.selected_union_candidate_ids):
        if candidate_id == candidate_ids[2]:
            records.append(BridgeRecord(candidate_id, BridgeStatus.BRIDGE_FAILED, None, "no_common_task_bundle"))
            continue
        hypothesis_id = f"hypothesis-{index}"
        records.append(BridgeRecord(candidate_id, BridgeStatus.SUCCESS, hypothesis_id, None))
        if candidate_id == candidate_ids[0]:
            effects = tuple((unit, 1.0 if position % 4 else 0.5) for position, unit in enumerate(task_units))
        elif candidate_id == candidate_ids[1]:
            effects = tuple((unit, 0.2 if position % 2 else -0.2) for position, unit in enumerate(task_units))
        else:
            effects = tuple((unit, -0.4 if position % 3 else -0.1) for position, unit in enumerate(task_units))
        coordinates.append(
            ConfirmationCoordinate(
                hypothesis_id,
                suite_plan.model_id,
                1,
                effects,
                10,
                True,
            )
        )
    bridge = freeze_shared_bridge_map(selection, records)
    inference_plan = SelectorInferencePlan(
        20260828,
        100,
        100,
        0.05,
        0.5,
        (("tsg_fci.v1", "association.v3"),),
    )
    result = evaluate_selector_study(selection, bridge, coordinates, inference_plan)
    return selection, bridge, tuple(coordinates), inference_plan, result, candidate_ids


@pytest.mark.extended
def test_strict_confirmed_yield_keeps_null_and_bridge_failure_in_k() -> None:
    selection, _bridge, _coordinates, _plan, result, candidate_ids = _evaluated_result()
    fci = next(point for point in result.yield_points if point.selector_id == "tsg_fci.v1")

    assert selection.universe.top_k == 3
    assert tuple(item.candidate_id for item in fci.slot_contributions) == candidate_ids[:3]
    assert [item.confirmed_contribution for item in fci.slot_contributions] == [1, 0, 0]
    assert fci.confirmed_slots == 1
    assert fci.confirmed_yield == pytest.approx(1 / 3)


@pytest.mark.reviewer
@pytest.mark.extended
def test_nested_selector_result_replays_and_independent_verifier_rejects_drift() -> None:
    selection, bridge, coordinates, plan, result, _candidate_ids = _evaluated_result()
    replay = evaluate_selector_study(selection, bridge, coordinates, plan)

    assert result == replay
    verification = verify_selector_result(selection, bridge, coordinates, plan, result)
    assert verification["status"] == "SELECTOR_RESULT_VERIFIED"
    assert verification["selectors"] == 5

    first = result.method_points[0]
    tampered = replace(
        result,
        method_points=(replace(first, confirmed_yield=0.0), *result.method_points[1:]),
    )
    with pytest.raises(ValueError, match="method points"):
        verify_selector_result(selection, bridge, coordinates, plan, tampered)

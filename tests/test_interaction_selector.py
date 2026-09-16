"""Pair schema-3 structural, prioritization, baseline, and slot invariants."""

from dataclasses import replace
import pytest
from prompt_mechanism_study.interaction_selector import (
    PairRelationGateStatus,
    PairShadowObservation,
    PairShadowPlan,
    freeze_pair_candidate_universe,
    freeze_pair_preoutcome_design,
    pair_preoutcome_observations,
    pair_preoutcome_data_sha256,
    run_pair_shadow_qualification,
)
from prompt_mechanism_study.mechanisms import (
    ControlPath,
    FactorialCompatibility,
    MechanismRegistryError,
    PairCompatibilityDecision,
    PairRelation,
    PairRelationEvidence,
    PairStructuralRelationEvidence,
    PromptControlBinding,
    evaluate_pair_structural_relation,
    validate_prompt_control_binding,
)
from prompt_mechanism_study.prioritization import (
    CandidateCoverageSummary,
    CandidateKind,
    FixedSlotSource,
    PolicyTrack,
    SlotStatus,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
)
from prompt_mechanism_study.prompt_tsg import PromptTSG, QueryState, TSGEdge, TSGNode
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.rq1_baselines import (
    BlindExpertRankingCard,
    SeededRandomRankingPlan,
    freeze_pair_baseline_universe,
    run_blind_expert_baseline,
    run_seeded_random_baseline,
    verify_rq1_baseline_result,
)
from prompt_mechanism_study.representation import (
    AnalysisScope,
    ModelBoundCandidateRecord,
    Operation,
    PolicyFactor,
    pair_policy_key,
)


FACTOR_1 = "feature.first_control"


FACTOR_2 = "feature.second_control"


def test_pair_solver_preserves_pre_refactor_fit() -> None:
    from prompt_mechanism_study.interaction_selector import _fit_logit
    from prompt_mechanism_study.reviewer_fixture import load_reviewer_smoke_fixture

    # Frozen from the original 800-iteration fit, including Pair-specific scaling.
    inputs = load_reviewer_smoke_fixture()
    operations = tuple(factor.operation for factor in inputs.pair_policy.factors)
    model = _fit_logit(inputs.pair_observations, operations, 0.05)
    assert model.means == (0.5,)
    assert model.scales == (0.5,)
    assert model.weights == pytest.approx(
        (-1.4514302698112234, -0.25162384410401717, 0.6446550275198336,
         0.6446550275198336, 0.9503690451874942), rel=0, abs=1e-12,
    )


def _structural_relation_fixture():
    node_ids = (
        "node.source",
        "node.control.first",
        "node.control.second",
        "node.sink",
        "node.sink.other",
        "node.surface.first",
        "node.surface.second",
        "node.alternative.group",
    )
    semantics = (
        "source.synthetic",
        FACTOR_1,
        FACTOR_2,
        "sink.synthetic",
        "sink.other",
        "surface.first",
        "surface.second",
        "alternative.group",
    )
    nodes = tuple(
        TSGNode(
            node_id,
            "synthetic",
            semantic,
            index,
            index + 1,
            content_hash((node_id, "evidence")),
            content_hash((node_id, "normalized")),
            (),
        )
        for index, (node_id, semantic) in enumerate(zip(node_ids, semantics, strict=True))
    )
    edges = (
        TSGEdge("edge.source.first", node_ids[0], node_ids[1], "flows_to"),
        TSGEdge("edge.first.second", node_ids[1], node_ids[2], "flows_to"),
        TSGEdge("edge.second.sink", node_ids[2], node_ids[3], "flows_to"),
        TSGEdge("edge.second.other", node_ids[2], node_ids[4], "flows_to"),
    )
    graph = PromptTSG(
        "2.0",
        "task-structural",
        content_hash("prompt-structural"),
        "extractor.synthetic.v1",
        content_hash("catalog-structural"),
        nodes,
        edges,
        (),
        (),
    )
    shared_path = ControlPath(
        node_ids[:4],
        tuple(item.edge_id for item in edges[:3]),
    )
    first = PromptControlBinding(
        FACTOR_1,
        graph.task_id,
        "unit-structural",
        graph.tsg_id,
        node_ids[1],
        (node_ids[0],),
        (node_ids[3],),
        (node_ids[5],),
        (shared_path,),
        (node_ids[7],),
    )
    second = PromptControlBinding(
        FACTOR_2,
        graph.task_id,
        "unit-structural",
        graph.tsg_id,
        node_ids[2],
        (node_ids[0],),
        (node_ids[3],),
        (node_ids[6],),
        (shared_path,),
        (node_ids[7],),
    )
    return graph, first, second


def _evaluate_structural_relation(
    relation: PairRelation,
    graph: PromptTSG,
    first: PromptControlBinding,
    second: PromptControlBinding,
) -> PairStructuralRelationEvidence:
    return evaluate_pair_structural_relation(
        pair_id="pair-structural",
        relation_spec_id=f"relation-spec.{relation.value}",
        relation=relation,
        task_unit_id="unit-structural",
        graph=graph,
        factor_1_id=FACTOR_1,
        factor_2_id=FACTOR_2,
        factor_1_bindings=(first,),
        factor_2_bindings=(second,),
    )


def test_pair_structural_predicates_replay_from_prompt_tsg_evidence() -> None:
    graph, first, second = _structural_relation_fixture()

    evidence = tuple(
        _evaluate_structural_relation(relation, graph, first, second)
        for relation in (
            PairRelation.SAME_FLOW,
            PairRelation.SHARED_SINK,
            PairRelation.DISTINCT_CONTROL_POINTS,
            PairRelation.ALTERNATIVE_CONTROLS,
        )
    )

    assert all(item.state is QueryState.PRESENT for item in evidence)
    assert all(item.prompt_tsg_id == graph.tsg_id for item in evidence)
    assert all(item.outcomes_or_arms_used is False for item in evidence)
    assert len({item.evidence_id for item in evidence}) == 4

    shared_surface = replace(second, surface_node_ids=first.surface_node_ids)
    assert (
        _evaluate_structural_relation(
            PairRelation.DISTINCT_CONTROL_POINTS, graph, first, shared_surface
        ).state
        is QueryState.ABSENT
    )
    no_shared_alternative = replace(second, alternative_group_node_ids=())
    assert (
        _evaluate_structural_relation(
            PairRelation.ALTERNATIVE_CONTROLS, graph, first, no_shared_alternative
        ).state
        is QueryState.ABSENT
    )
    other_sink_path = ControlPath(
        (
            "node.source",
            "node.control.first",
            "node.control.second",
            "node.sink.other",
        ),
        ("edge.source.first", "edge.first.second", "edge.second.other"),
    )
    other_sink = replace(
        second,
        sink_node_ids=("node.sink.other",),
        paths=(other_sink_path,),
    )
    assert (
        _evaluate_structural_relation(
            PairRelation.SHARED_SINK, graph, first, other_sink
        ).state
        is QueryState.ABSENT
    )
    assert (
        _evaluate_structural_relation(
            PairRelation.SAME_FLOW, graph, first, other_sink
        ).state
        is QueryState.ABSENT
    )


def test_pair_structural_predicates_fail_closed_on_ambiguity_or_tampering() -> None:
    graph, first, second = _structural_relation_fixture()

    ambiguous = evaluate_pair_structural_relation(
        pair_id="pair-structural",
        relation_spec_id="relation-spec.same-flow",
        relation=PairRelation.SAME_FLOW,
        task_unit_id="unit-structural",
        graph=graph,
        factor_1_id=FACTOR_1,
        factor_2_id=FACTOR_2,
        factor_1_bindings=(first, first),
        factor_2_bindings=(second,),
    )
    assert ambiguous.state is QueryState.UNRESOLVED
    assert ambiguous.reasons == ("multiple_control_bindings",)

    unresolved_graph = replace(graph, unresolved_semantics=(FACTOR_1,))
    unresolved_first = replace(first, prompt_tsg_id=unresolved_graph.tsg_id)
    unresolved_second = replace(second, prompt_tsg_id=unresolved_graph.tsg_id)
    unresolved = _evaluate_structural_relation(
        PairRelation.SAME_FLOW,
        unresolved_graph,
        unresolved_first,
        unresolved_second,
    )
    assert unresolved.state is QueryState.UNRESOLVED
    assert unresolved.reasons == ("unresolved_control_semantics",)

    bad_path = ControlPath(
        first.paths[0].node_ids,
        (
            "edge.first.second",
            "edge.source.first",
            "edge.second.sink",
        ),
    )
    tampered = replace(first, paths=(bad_path,))
    with pytest.raises(MechanismRegistryError, match="edge order"):
        validate_prompt_control_binding(graph, tampered)


def _shadow_policy(feature_1: str, feature_2: str, context_query_id: str):
    return pair_policy_key(
        AnalysisScope(
            "security.synthetic.v1",
            context_query_id,
            ("python",),
            ("local-api",),
            ("synthetic",),
        ),
        (PolicyFactor(feature_1, Operation.ADD), PolicyFactor(feature_2, Operation.ADD)),
        outcome_id="oracle_evaluable_secure_code_yield",
    )


def _shadow_rows(policy, *, secure_counts: dict[str, int]) -> tuple[PairShadowObservation, ...]:
    rows = []
    prefix = policy.analysis_scope.context_query_id.rsplit(".", 1)[-1]
    factors = tuple(item.actionable_feature_id for item in policy.factors)
    for x1, x2 in ((0, 0), (0, 1), (1, 0), (1, 1)):
        cell = f"{x1}{x2}"
        for index in range(8):
            rows.append(
                PairShadowObservation(
                    policy.policy_key,
                    f"shadow-{prefix}-{cell}-{index}",
                    "model-v1",
                    f"lineage-{index % 2}",
                    "python",
                    "synthetic",
                    "local-api",
                    policy.analysis_scope.context_query_id,
                    QueryState.PRESENT,
                    (
                        (factors[0], QueryState.PRESENT if x1 else QueryState.ABSENT),
                        (factors[1], QueryState.PRESENT if x2 else QueryState.ABSENT),
                    ),
                    ((factors[0], 0.99), (factors[1], 0.99)),
                    (("source_code", float(index % 2)),),
                    int(index < secure_counts[cell]),
                )
            )
    return tuple(rows)


def _shadow_relation_evidence(
    policy,
    rows: tuple[PairShadowObservation, ...],
    state: QueryState,
) -> tuple[PairRelationEvidence, ...]:
    return tuple(
        PairRelationEvidence(
            policy.policy_key,
            "relation-spec.synthetic.v1",
            "relation.synthetic.v1",
            f"task-{row.task_unit_id}",
            row.task_unit_id,
            f"tsg-{row.task_unit_id}",
            "contract.synthetic.v1",
            state,
            (f"node-{row.task_unit_id}",) if state is QueryState.PRESENT else (),
            (),
        )
        for row in rows
    )


def _shadow_fixture():
    present = _shadow_policy(
        "feature.alpha_control", "feature.beta_control", "context.shadow.present"
    )
    absent = _shadow_policy(
        "feature.gamma_control", "feature.delta_control", "context.shadow.absent"
    )
    incompatible = _shadow_policy(
        "feature.epsilon_control", "feature.zeta_control", "context.shadow.incompatible"
    )
    policies = (present, absent, incompatible)
    decisions = tuple(
        PairCompatibilityDecision(
            policy,
            (
                FactorialCompatibility.MUTUALLY_EXCLUSIVE
                if policy is incompatible
                else FactorialCompatibility.COMPATIBLE
            ),
            "compatibility.synthetic.v1",
            tuple(sorted((f"surface.{index}.a", f"surface.{index}.b"))),
            content_hash(("compatibility", index)),
        )
        for index, policy in enumerate(policies)
    )
    records = tuple(
        ModelBoundCandidateRecord(policy.policy_key, "model-v1", "protocol-v3", "3.0")
        for policy in policies
    )
    rows_present = _shadow_rows(
        present, secure_counts={"00": 1, "01": 2, "10": 2, "11": 7}
    )
    rows_absent = _shadow_rows(
        absent, secure_counts={"00": 7, "01": 6, "10": 6, "11": 1}
    )
    rows = rows_present + rows_absent
    universe = freeze_pair_candidate_universe(
        policies,
        decisions,
        records,
        coverage_summaries={
            policy.policy_key: CandidateCoverageSummary(
                policy.policy_key,
                CandidateKind.PAIR,
                (
                    (("00", 0), ("01", 0), ("10", 0), ("11", 0))
                    if policy is incompatible
                    else (("00", 8), ("01", 8), ("10", 8), ("11", 8))
                ),
                0 if policy is incompatible else 2,
                0 if policy is incompatible else 32,
                0 if policy is incompatible else 32,
                0 if policy is incompatible else 32,
                0 if policy is incompatible else 32,
                0 if policy is incompatible else 8,
            )
            for policy in policies
        },
        candidate_family_ids={policy.policy_key: "pair-shadow" for policy in policies},
        preoutcome_data_sha256=pair_preoutcome_data_sha256(pair_preoutcome_observations(rows)),
        discovery_population_sha256=content_hash("pair-discovery-population"),
        information_budget_sha256=content_hash("pair-shadow-budget"),
        top_k=2,
    )
    plan = PairShadowPlan(
        "model-v1",
        ("source_code",),
        4,
        2,
        0.9,
        2,
        20260831,
        0.05,
        40,
        20260830,
        8,
        4,
        0.5,
        0.2,
    )
    evidence = _shadow_relation_evidence(
        present, rows_present, QueryState.PRESENT
    ) + _shadow_relation_evidence(absent, rows_absent, QueryState.ABSENT)
    return present, absent, incompatible, rows, universe, plan, evidence


def test_pair_shadow_has_one_compatibility_first_universe_and_one_rd_path() -> None:
    present, absent, incompatible, rows, universe, plan, evidence = _shadow_fixture()

    result = run_pair_shadow_qualification(
        universe,
        rows,
        evidence,
        plan,
        preoutcome_freeze=freeze_pair_preoutcome_design(
            universe,
            pair_preoutcome_observations(rows),
            plan,
        ),
    )

    assert present.policy_key in universe.compatible_policy_keys
    assert absent.policy_key in universe.compatible_policy_keys
    assert incompatible.policy_key not in universe.compatible_policy_keys
    assert result.full.support_gates_sha256 == result.no_relation.support_gates_sha256
    assert result.full.fold_manifests_sha256 == result.no_relation.fold_manifests_sha256
    assert result.full.rd_scores_sha256 == result.no_relation.rd_scores_sha256
    assert result.full.relation_gate_evidence_sha256 is not None
    assert result.no_relation.relation_gate_evidence_sha256 is None
    assert tuple(item.candidate_id for item in result.full.ranking) == (present.policy_key,)
    assert {item.candidate_id for item in result.no_relation.ranking} == {
        present.policy_key,
        absent.policy_key,
    }
    assert result.full.slots[1].status is SlotStatus.GATE_FAILED
    assert all(item.status is SlotStatus.FILLED for item in result.no_relation.slots)
    assert result.sole_difference.full_additional_read == "relation_gate"
    assert not result.sole_difference.no_relation_additional_reads
    assert all(
        {assignment.cell for assignment in manifest.assignments if assignment.fold == fold}
        == {"00", "01", "10", "11"}
        for manifest in result.fold_manifests
        for fold in range(manifest.fold_count)
    )


def test_zero_marginal_xor_pair_can_enter_full_without_atomic_signal() -> None:
    policy = _shadow_policy(
        "feature.xor_first",
        "feature.xor_second",
        "context.shadow.xor",
    )
    rows = _shadow_rows(
        policy,
        secure_counts={"00": 0, "01": 8, "10": 8, "11": 0},
    )
    compatibility = PairCompatibilityDecision(
        policy,
        FactorialCompatibility.COMPATIBLE,
        "compatibility.synthetic.v1",
        ("surface.xor.first", "surface.xor.second"),
        content_hash("xor-compatibility"),
    )
    record = ModelBoundCandidateRecord(
        policy.policy_key,
        "model-v1",
        "protocol-v3",
        "3.0",
    )
    universe = freeze_pair_candidate_universe(
        (policy,),
        (compatibility,),
        (record,),
        coverage_summaries={
            policy.policy_key: CandidateCoverageSummary(
                policy.policy_key,
                CandidateKind.PAIR,
                (("00", 8), ("01", 8), ("10", 8), ("11", 8)),
                2,
                32,
                32,
                32,
                32,
                8,
            )
        },
        candidate_family_ids={policy.policy_key: "pair-shadow"},
        preoutcome_data_sha256=pair_preoutcome_data_sha256(pair_preoutcome_observations(rows)),
        discovery_population_sha256=content_hash("xor-discovery-population"),
        information_budget_sha256=content_hash("xor-information-budget"),
        top_k=1,
    )
    plan = PairShadowPlan(
        "model-v1",
        ("source_code",),
        4,
        2,
        0.9,
        2,
        20260901,
        0.05,
        40,
        20260902,
        8,
        4,
        0.5,
        0.2,
    )
    preoutcome = freeze_pair_preoutcome_design(
        universe,
        pair_preoutcome_observations(rows),
        plan,
    )
    result = run_pair_shadow_qualification(
        universe,
        rows,
        _shadow_relation_evidence(policy, rows, QueryState.PRESENT),
        plan,
        preoutcome_freeze=preoutcome,
    )
    means = {
        cell: sum(row.outcome for row in rows if cell in row.task_unit_id) / 8
        for cell in ("00", "01", "10", "11")
    }
    first_marginal = (means["10"] + means["11"] - means["00"] - means["01"]) / 2
    second_marginal = (means["01"] + means["11"] - means["00"] - means["10"]) / 2

    assert first_marginal == second_marginal == 0.0
    assert result.rd_scores[0].signed_risk_difference_interaction < -0.2
    assert result.full.slots[0].candidate_id == policy.policy_key
    assert preoutcome.atomic_evidence_read is False


def test_pair_rq1_baselines_share_support_gate_and_replay_blind_rankings() -> None:
    _present, _absent, _incompatible, rows, universe, plan, evidence = (
        _shadow_fixture()
    )
    qualification = run_pair_shadow_qualification(
        universe,
        rows,
        evidence,
        plan,
        preoutcome_freeze=freeze_pair_preoutcome_design(
            universe,
            pair_preoutcome_observations(rows),
            plan,
        ),
    )
    baseline_universe = freeze_pair_baseline_universe(
        universe,
        freeze_pair_preoutcome_design(universe, pair_preoutcome_observations(rows), plan), plan,
        protocol_id=universe.model_bound_records[0].protocol_id,
        schema_version=universe.model_bound_records[0].schema_version,
    )
    # A support-only result cannot stand in for the common frozen fold decision.
    with pytest.raises(TypeError, match="frozen common discoverability"):
        freeze_pair_baseline_universe(
            universe, qualification.support_gates, plan,
            protocol_id=baseline_universe.protocol_id, schema_version=baseline_universe.schema_version,
        )
    expert_card = BlindExpertRankingCard(
        baseline_universe.protocol_id,
        baseline_universe.schema_version,
        baseline_universe.track,
        "pair_blind_expert",
        baseline_universe.model_id,
        baseline_universe.baseline_universe_id,
        baseline_universe.candidate_material_sha256,
        (
            "analysis_scope",
            "candidate_family",
            "factor_operations",
            "factorial_compatibility",
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
        content_hash("pair-expert-identity"),
        content_hash("pair-expert-instructions"),
        content_hash("pair-expert-independent-review"),
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
        baseline_universe.track,
        "pair_seeded_random",
        baseline_universe.model_id,
        baseline_universe.baseline_universe_id,
        baseline_universe.candidate_material_sha256,
        20260832,
        content_hash("pair-random-seed-source"),
    )
    random_result = run_seeded_random_baseline(baseline_universe, random_plan)
    random_receipt = verify_rq1_baseline_result(
        baseline_universe,
        random_result,
        random_plan=random_plan,
    )

    assert baseline_universe.source_universe_id == universe.universe_id
    assert tuple(
        item.policy_key for item in baseline_universe.expert_candidate_cards
    ) == baseline_universe.eligible_policy_keys
    assert all(
        dict(item.support_summary)["cell_11_task_units"] > 0
        for item in baseline_universe.expert_candidate_cards
    )
    assert set(baseline_universe.eligible_policy_keys) == {
        item.pair_id for item in qualification.support_gates if item.passed
    }
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
                PolicyTrack.PAIR,
                "pair_full",
                baseline_universe.model_id,
                universe.universe_id,
                qualification.full.slots,
                universe.model_bound_records,
            ),
            FixedSlotSource(
                PolicyTrack.PAIR,
                "pair_no_relation",
                baseline_universe.model_id,
                universe.universe_id,
                qualification.no_relation.slots,
                universe.model_bound_records,
            ),
            expert.source,
            random_result.source,
        ),
    )
    union = freeze_shared_confirmation_union(ledger)
    assert {source.selector_id for source in ledger.sources} == {
        "pair_blind_expert",
        "pair_full",
        "pair_no_relation",
        "pair_seeded_random",
    }
    assert len(union.entries) == len(
        {
            slot.candidate_record_id
            for slot in ledger.slots
            if slot.candidate_record_id is not None
        }
    )
    with pytest.raises(ValueError, match="random ranking plan drifts"):
        run_seeded_random_baseline(
            baseline_universe,
            replace(random_plan, model_id="another-model"),
        )


def test_pair_relation_evidence_cannot_change_common_rd_coordinates() -> None:
    present, absent, _, rows, universe, plan, evidence = _shadow_fixture()
    preoutcome = freeze_pair_preoutcome_design(
        universe,
        pair_preoutcome_observations(rows),
        plan,
    )
    original = run_pair_shadow_qualification(
        universe,
        rows,
        evidence,
        plan,
        preoutcome_freeze=preoutcome,
    )
    changed_evidence = tuple(
        replace(item, state=QueryState.ABSENT, evidence_node_ids=())
        if item.pair_id == present.policy_key
        else item
        for item in evidence
    )

    changed = run_pair_shadow_qualification(
        universe,
        rows,
        changed_evidence,
        plan,
        preoutcome_freeze=preoutcome,
    )

    assert original.full.support_gates_sha256 == changed.full.support_gates_sha256
    assert original.full.fold_manifests_sha256 == changed.full.fold_manifests_sha256
    assert original.full.rd_scores_sha256 == changed.full.rd_scores_sha256
    assert original.no_relation == changed.no_relation
    assert original.full.ranking != changed.full.ranking
    assert all(
        gate.status is PairRelationGateStatus.FAILED for gate in changed.relation_gates
    )
    assert absent.policy_key in {
        item.candidate_id for item in changed.no_relation.ranking
    }

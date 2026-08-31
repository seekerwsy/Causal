from dataclasses import replace

import pytest

from prompt_mechanism_study.interaction_selector import (
    InteractionSelectorPlan,
    PairRelationGateStatus,
    PairDiscoveryObservation,
    PairShadowObservation,
    PairShadowPlan,
    build_tsg_pair_universe,
    freeze_pair_candidate_universe,
    pair_shadow_data_sha256,
    run_interaction_selector,
    run_pair_shadow_qualification,
)
from prompt_mechanism_study.mechanisms import (
    ControlPath,
    FactorialCompatibility,
    InteractionScale,
    MechanismRegistryError,
    MechanismRelationSpec,
    OracleSupportStatus,
    PairCompatibilityDecision,
    PairRelation,
    PairRelationEvidence,
    PairStructuralRelationEvidence,
    PairSpec,
    PromptControlBinding,
    RelationEvidenceContract,
    evaluate_pair_structural_relation,
    evaluate_pair_relation_evidence,
    validate_prompt_control_binding,
    validate_pair_relation_evidence,
)
from prompt_mechanism_study.prioritization import (
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

pytestmark = pytest.mark.extended


FACTOR_1 = "feature.first_control"
FACTOR_2 = "feature.second_control"


def _pair() -> PairSpec:
    return PairSpec(
        "context.shared_flow.v1",
        FACTOR_1,
        FACTOR_2,
        Operation.ADD,
        Operation.ADD,
        PairRelation.SAME_FLOW,
        "python.synthetic.v1",
        "0" * 64,
        OracleSupportStatus.SUPPORTED,
        "oracle_evaluable_secure_code_yield",
        InteractionScale.RISK_DIFFERENCE,
    )


def _relation_spec() -> MechanismRelationSpec:
    return MechanismRelationSpec(
        "relation.shared_flow.synthetic.v1",
        FACTOR_1,
        FACTOR_2,
        PairRelation.SAME_FLOW,
        FactorialCompatibility.COMPATIBLE,
        "context.shared_flow.v1",
        RelationEvidenceContract(
            ("sink.synthetic", "source.synthetic"),
            (("source.synthetic", "flows_to", "sink.synthetic"),),
        ),
        ("python",),
        ("synthetic",),
        ("CWE-TEST",),
        ((Operation.ADD, Operation.ADD),),
    )


def _plan() -> InteractionSelectorPlan:
    return InteractionSelectorPlan(
        "model-v1",
        "secure-yield",
        ("source_code",),
        4,
        2,
        0.9,
        0.05,
        2,
        80,
        20260828,
        1,
    )


def _evidence(pair: PairSpec, spec: MechanismRelationSpec, task_unit_id: str):
    return PairRelationEvidence(
        pair.pair_id,
        spec.relation_spec_id,
        spec.relation_id,
        f"task-{task_unit_id}",
        task_unit_id,
        f"tsg-{task_unit_id}",
        spec.evidence_contract.contract_id,
        QueryState.PRESENT,
        (f"node-{task_unit_id}",),
        (f"edge-{task_unit_id}",),
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


@pytest.mark.reviewer
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


@pytest.mark.reviewer
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


def _discovery_rows(*, omit_11: bool = False, separated_lineages: bool = False):
    pair = _pair()
    spec = _relation_spec()
    rows = []
    evidence = []
    for x1, x2 in ((0, 0), (0, 1), (1, 0), (1, 1)):
        if omit_11 and (x1, x2) == (1, 1):
            continue
        cell = f"{x1}{x2}"
        for index in range(8):
            task_unit_id = f"unit-{cell}-{index}"
            relation = _evidence(pair, spec, task_unit_id)
            evidence.append(relation)
            lineage = f"lineage-{cell}" if separated_lineages else f"lineage-{index % 2}"
            rows.append(
                PairDiscoveryObservation(
                    pair.pair_id,
                    spec.relation_spec_id,
                    relation.evidence_id,
                    task_unit_id,
                    "model-v1",
                    lineage,
                    "python",
                    "synthetic",
                    "local-api",
                    pair.pair_context_query_id,
                    QueryState.PRESENT,
                    (
                        (FACTOR_1, QueryState.PRESENT if x1 else QueryState.ABSENT),
                        (FACTOR_2, QueryState.PRESENT if x2 else QueryState.ABSENT),
                    ),
                    ((FACTOR_1, 0.99), (FACTOR_2, 0.99)),
                    (("source_code", float(index % 2)),),
                    x1 ^ x2,
                )
            )
    return pair, spec, tuple(rows), tuple(evidence)


def _node(node_id: str, semantic_id: str) -> TSGNode:
    return TSGNode(
        node_id,
        "source" if semantic_id.startswith("source") else "sink",
        semantic_id,
        0,
        1,
        content_hash(node_id),
        content_hash(node_id.casefold()),
        (),
    )


def test_pair_relation_evidence_exactly_recomputes() -> None:
    pair = _pair()
    spec = _relation_spec()
    source = _node("source-node", "source.synthetic")
    sink = _node("sink-node", "sink.synthetic")
    graph = PromptTSG(
        "1.0",
        "task-1",
        content_hash("prompt"),
        "extractor-v1",
        "1" * 64,
        (source, sink),
        (TSGEdge("flow-edge", source.node_id, sink.node_id, "flows_to"),),
        (),
    )
    task = {
        "task_id": "task-1",
        "task_unit_id": "unit-1",
        "language": "python",
        "task_family": "synthetic",
        "cwe": "CWE-TEST",
    }

    evidence = evaluate_pair_relation_evidence(task, graph, pair, spec)

    assert evidence.state is QueryState.PRESENT
    validate_pair_relation_evidence(evidence, task, graph, pair, spec)
    with pytest.raises(MechanismRegistryError, match="does not recompute"):
        validate_pair_relation_evidence(
            replace(evidence, evidence_edge_ids=("wrong-edge",)), task, graph, pair, spec
        )



@pytest.mark.parametrize(
    ("secure_counts", "expected_sign"),
    [
        ({"00": 1, "10": 2, "01": 2, "11": 7}, 1),
        ({"00": 7, "10": 6, "01": 6, "11": 1}, -1),
    ],
)
def test_pair_selector_recovers_positive_and_negative_rd_patterns(
    secure_counts: dict[str, int], expected_sign: int
) -> None:
    pair, spec, rows, evidence = _discovery_rows()
    revised = []
    for row in rows:
        cell, index_text = row.task_unit_id.removeprefix("unit-").split("-")
        revised.append(
            replace(
                row,
                covariates=(("source_code", 0.0),),
                outcome=int(int(index_text) < secure_counts[cell]),
            )
        )

    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)),
        tuple(revised),
        evidence,
        _plan(),
    )
    score = frozen.scores[0].risk_difference_interaction

    assert (score > 0) - (score < 0) == expected_sign


def test_mixed_add_remove_pair_uses_operation_specific_cells() -> None:
    pair = replace(_pair(), operation_2=Operation.REMOVE)
    spec = replace(
        _relation_spec(), allowed_operation_pairs=((Operation.ADD, Operation.REMOVE),)
    )
    rows = []
    evidence = []
    for target_1, target_2 in ((0, 0), (0, 1), (1, 0), (1, 1)):
        cell = f"{target_1}{target_2}"
        for index in range(8):
            task_unit_id = f"mixed-{cell}-{index}"
            relation = _evidence(pair, spec, task_unit_id)
            evidence.append(relation)
            rows.append(
                PairDiscoveryObservation(
                    pair.pair_id,
                    spec.relation_spec_id,
                    relation.evidence_id,
                    task_unit_id,
                    "model-v1",
                    f"lineage-{index % 2}",
                    "python",
                    "synthetic",
                    "local-api",
                    pair.pair_context_query_id,
                    QueryState.PRESENT,
                    (
                        (
                            FACTOR_1,
                            QueryState.PRESENT if target_1 else QueryState.ABSENT,
                        ),
                        (
                            FACTOR_2,
                            QueryState.ABSENT if target_2 else QueryState.PRESENT,
                        ),
                    ),
                    ((FACTOR_1, 0.99), (FACTOR_2, 0.99)),
                    (("source_code", float(index % 2)),),
                    target_1 ^ target_2,
                )
            )

    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)), tuple(rows), tuple(evidence), _plan()
    )

    assert frozen.gates[0].cell_task_units == (
        ("00", 8),
        ("01", 8),
        ("10", 8),
        ("11", 8),
    )
    assert frozen.scores[0].pair_id == pair.pair_id
    assert frozen.scores[0].risk_difference_interaction < -0.25



def test_insufficient_four_cell_support_fails_without_ranking() -> None:
    pair, spec, rows, evidence = _discovery_rows(omit_11=True)
    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)), rows, evidence, _plan()
    )

    assert not frozen.gates[0].passed
    assert "insufficient_four_cell_support" in frozen.gates[0].reasons
    assert not frozen.scores


def test_source_lineage_separation_fails_without_ranking() -> None:
    pair, spec, rows, evidence = _discovery_rows(separated_lineages=True)
    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)), rows, evidence, _plan()
    )

    assert not frozen.gates[0].passed
    assert "source_lineage_separation" in frozen.gates[0].reasons
    assert not frozen.scores


def test_relation_evidence_mismatch_fails_closed() -> None:
    pair, spec, rows, evidence = _discovery_rows()
    rows = (replace(rows[0], relation_evidence_id="missing-evidence"), *rows[1:])

    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)), rows, evidence, _plan()
    )

    assert not frozen.gates[0].passed
    assert "relation_evidence_mismatch" in frozen.gates[0].reasons
    assert not frozen.scores


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
        candidate_family_ids={policy.policy_key: "pair-shadow" for policy in policies},
        discovery_data_sha256=pair_shadow_data_sha256(rows),
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


@pytest.mark.reviewer
def test_pair_shadow_has_one_compatibility_first_universe_and_one_rd_path() -> None:
    present, absent, incompatible, rows, universe, plan, evidence = _shadow_fixture()

    result = run_pair_shadow_qualification(universe, rows, evidence, plan)

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


@pytest.mark.reviewer
def test_pair_rq1_baselines_share_support_gate_and_replay_blind_rankings() -> None:
    _present, _absent, _incompatible, rows, universe, plan, evidence = (
        _shadow_fixture()
    )
    qualification = run_pair_shadow_qualification(universe, rows, evidence, plan)
    baseline_universe = freeze_pair_baseline_universe(
        universe,
        qualification.support_gates,
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


@pytest.mark.reviewer
def test_pair_relation_evidence_cannot_change_common_rd_coordinates() -> None:
    present, absent, _, rows, universe, plan, evidence = _shadow_fixture()
    original = run_pair_shadow_qualification(universe, rows, evidence, plan)
    changed_evidence = tuple(
        replace(item, state=QueryState.ABSENT, evidence_node_ids=())
        if item.pair_id == present.policy_key
        else item
        for item in evidence
    )

    changed = run_pair_shadow_qualification(universe, rows, changed_evidence, plan)

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

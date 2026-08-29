from dataclasses import replace

import pytest

from prompt_mechanism_study.interaction_selector import (
    InteractionLane,
    InteractionSelectorPlan,
    PairDiscoveryObservation,
    build_tsg_pair_universe,
    run_interaction_selector,
)
from prompt_mechanism_study.mechanisms import (
    InteractionScale,
    MechanismRegistryError,
    MechanismRelationSpec,
    OracleSupportStatus,
    PairRelation,
    PairRelationEvidence,
    PairSpec,
    RelationEvidenceContract,
    evaluate_pair_relation_evidence,
    validate_pair_relation_evidence,
)
from prompt_mechanism_study.prompt_tsg import PromptTSG, QueryState, TSGEdge, TSGNode
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import Operation

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


def test_xor_is_ranked_in_pure_interaction_lane_without_graph_main_effect() -> None:
    pair, spec, rows, evidence = _discovery_rows()
    universe = build_tsg_pair_universe((pair,), (spec,))

    frozen = run_interaction_selector(universe, rows, evidence, _plan())

    assert frozen.gates[0].passed
    assert not frozen.graph_ranking
    assert frozen.selected_pure_interaction_pair_ids == (pair.pair_id,)
    score = frozen.pure_interaction_ranking[0].score
    assert score.lane is InteractionLane.PURE_INTERACTION
    assert score.interaction_coefficient < 0
    assert score.absolute_interaction_coefficient > 0.5
    assert score.sign_stability > 0.8


def test_graph_supported_pair_uses_separate_lane() -> None:
    pair, spec, rows, evidence = _discovery_rows()
    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)),
        rows,
        evidence,
        _plan(),
        graph_supported_factor_ids=(FACTOR_1,),
    )

    assert frozen.selected_graph_pair_ids == (pair.pair_id,)
    assert not frozen.pure_interaction_ranking
    assert frozen.graph_ranking[0].score.lane is InteractionLane.GRAPH_SUPPORTED


def test_insufficient_four_cell_support_fails_without_ranking() -> None:
    pair, spec, rows, evidence = _discovery_rows(omit_11=True)
    frozen = run_interaction_selector(
        build_tsg_pair_universe((pair,), (spec,)), rows, evidence, _plan()
    )

    assert not frozen.gates[0].passed
    assert "insufficient_four_cell_support" in frozen.gates[0].reasons
    assert not frozen.scores
    assert not frozen.graph_ranking
    assert not frozen.pure_interaction_ranking


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


def test_tsg_universe_rejects_undeclared_pair_relation() -> None:
    pair = _pair()
    incompatible = replace(_relation_spec(), relation_type=PairRelation.SHARED_SINK)

    with pytest.raises(ValueError, match="cannot be empty"):
        build_tsg_pair_universe((pair,), (incompatible,))

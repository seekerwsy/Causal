from __future__ import annotations

import hashlib

import networkx as nx
import pytest

from secaware.schema.features import FeatureFamily, FeatureState, PromptExtractorBackend
from secaware.schema.policy_v2 import (
    PolicySplit,
    QueryState,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.tsg import EdgeType, MotifId, NodeType, PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG
from secaware.tsg.context_queries_v2 import (
    CONTEXT_QUERY_CATALOG,
    CONTEXT_QUERY_CATALOG_SHA256,
    CONTEXT_QUERY_SEMANTICS_VERSION,
    CWE78_COMMAND_FLOW_QUERY,
    CWE89_SQL_FLOW_QUERY,
    context_query_spec,
    evaluate_context_query,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph
from secaware.tsg.queries import feature_state

CASES = (
    (
        CWE78_COMMAND_FLOW_QUERY,
        "CWE-78",
        "argument-vector-subprocess",
        "task.process_launch",
        "safety.safe_subprocess",
    ),
    (
        CWE89_SQL_FLOW_QUERY,
        "CWE-89",
        "value-parameterization",
        "task.database_query",
        "safety.sql_parameterization",
    ),
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _evidence(value: str) -> dict[str, str | int]:
    return {
        "evidence_start": 0,
        "evidence_end": 1,
        "evidence_sha256": _sha(value),
    }


def _add_node(
    graph: nx.MultiDiGraph,
    key: str,
    node_type: NodeType,
    label: str,
    *,
    evidence: bool = True,
    attributes: dict[str, object] | None = None,
) -> str:
    graph.add_node(
        key,
        node_type=node_type,
        label=label,
        attributes=(attributes if attributes is not None else _evidence(key) if evidence else {}),
    )
    return key


def _add_edge(
    graph: nx.MultiDiGraph,
    src: str,
    dst: str,
    edge_type: EdgeType,
    *,
    evidence: bool = True,
) -> None:
    graph.add_edge(
        src,
        dst,
        edge_type=edge_type,
        attributes=_evidence(f"{src}:{dst}:{edge_type.value}") if evidence else {},
    )


def _feature_nodes(
    graph: nx.MultiDiGraph,
    *,
    task_feature_id: str,
    target_feature_id: str,
    target_state: FeatureState,
) -> None:
    for spec in PROMPT_FEATURE_CATALOG:
        state = FeatureState.ABSENT
        if spec.feature_id == task_feature_id:
            state = FeatureState.PRESENT
        elif spec.feature_id == target_feature_id:
            state = target_state
        node_type = (
            NodeType.PRESENTATION_FEATURE
            if spec.feature_family is FeatureFamily.PRESENTATION_CONTROL
            else NodeType.FEATURE
        )
        _add_node(
            graph,
            f"feature:{spec.feature_id}",
            node_type,
            spec.feature_id,
            evidence=False,
            attributes={
                "feature_id": spec.feature_id,
                "feature_family": spec.feature_family.value,
                "feature_state": state.value,
            },
        )


def _record(
    query_name: str,
    cwe: str,
    task_feature_id: str,
    target_feature_id: str,
    *,
    target_state: FeatureState = FeatureState.ABSENT,
    connected_target_sink: bool = True,
    complete_sink_evidence: bool = True,
) -> PromptTSGRecord:
    definition = next(item for item in CONTEXT_QUERY_CATALOG if item.query_name == query_name)
    ontology = next(item for item in PROMPT_TSG_CATALOG if item.cwe == cwe)
    graph = nx.MultiDiGraph()
    operation = _add_node(graph, "operation", NodeType.TASK_OPERATION, ontology.operation_label)
    source = _add_node(graph, "source", NodeType.SOURCE, "untrusted_input")
    data = _add_node(graph, "data", NodeType.DATA_OBJECT, definition.data_label)
    sink = _add_node(
        graph,
        "sink",
        NodeType.SINK,
        definition.sink_label,
        evidence=complete_sink_evidence,
    )
    _add_edge(graph, operation, data, EdgeType.OPERATES_ON)
    _add_edge(graph, source, data, EdgeType.SOURCE_OF)
    if connected_target_sink:
        _add_edge(
            graph,
            data,
            sink,
            EdgeType.FLOWS_TO,
            evidence=complete_sink_evidence,
        )
    else:
        other_sink = _add_node(graph, "other-sink", NodeType.SINK, "different_sink")
        _add_edge(graph, data, other_sink, EdgeType.FLOWS_TO)

    if target_state is FeatureState.PRESENT:
        requirement = _add_node(
            graph,
            "requirement",
            NodeType.PROMPT_REQUIREMENT,
            ontology.requirement_label,
        )
        guard = _add_node(graph, "guard", NodeType.GUARD, ontology.guard_label)
        _add_edge(graph, requirement, guard, EdgeType.REQUIRES)
        _add_edge(graph, data, guard, EdgeType.GUARDED_BY)
        _add_edge(graph, sink, guard, EdgeType.GUARDED_BY)

    _feature_nodes(
        graph,
        task_feature_id=task_feature_id,
        target_feature_id=target_feature_id,
        target_state=target_state,
    )
    return multidigraph_to_record(
        graph,
        prompt_id=f"prompt.{cwe.lower()}.{target_state.value}",
        task_id=f"task.{cwe.lower()}.{target_state.value}",
        task_family="command_execution" if cwe == "CWE-78" else "sql_query",
        cwe=cwe,
        extractor_backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V2,
        extractor_policy_sha256="a" * 64,
        proposal_id="proposal_" + "b" * 64,
    )


def _evaluate(
    record: PromptTSGRecord,
    query_name: str,
    archetype: str,
):
    return evaluate_context_query(
        record,
        query_name,
        semantic_membership=_membership(record, archetype),
    )


def _membership(
    record: PromptTSGRecord,
    archetype: str,
    *,
    task_instance_id: str | None = None,
    cwe: str | None = None,
) -> SemanticTaskClusterMembershipRecord:
    clustering_policy = _sha("semantic-clustering-policy")
    return SemanticTaskClusterMembershipRecord.from_content(
        semantic_task_cluster_id=f"cluster.{record.task_id}",
        task_instance_id=task_instance_id or record.task_id,
        split=PolicySplit.DISCOVER,
        cwe=cwe or record.cwe,
        task_archetype=archetype,
        source_task_sha256=_sha(f"source:{record.task_id}"),
        clustering_policy_sha256=clustering_policy,
        adjudication_sha256=_sha(f"adjudication:{record.task_id}"),
    )


def test_catalog_is_separate_content_addressed_and_target_independent() -> None:
    assert (
        CONTEXT_QUERY_CATALOG_SHA256
        == context_query_spec(CWE78_COMMAND_FLOW_QUERY).context_query_catalog_sha256
    )
    assert {item.query_name for item in CONTEXT_QUERY_CATALOG} == {
        CWE78_COMMAND_FLOW_QUERY,
        CWE89_SQL_FLOW_QUERY,
    }
    assert all(
        spec.query_semantics_version == CONTEXT_QUERY_SEMANTICS_VERSION
        for spec in (
            context_query_spec(CWE78_COMMAND_FLOW_QUERY),
            context_query_spec(CWE89_SQL_FLOW_QUERY),
        )
    )
    assert not {item.query_name for item in CONTEXT_QUERY_CATALOG} & {
        item.value for item in MotifId
    }
    for definition in CONTEXT_QUERY_CATALOG:
        assert "guard" not in repr(definition).casefold()
        assert "without" not in definition.query_name
        assert definition.first_edge_type is EdgeType.SOURCE_OF
        assert definition.traversable_edge_types == (EdgeType.FLOWS_TO,)


@pytest.mark.parametrize(
    ("query_name", "cwe", "archetype", "task_feature_id", "target_feature_id"),
    CASES,
)
def test_guard_add_remove_changes_qf_but_not_context(
    query_name: str,
    cwe: str,
    archetype: str,
    task_feature_id: str,
    target_feature_id: str,
) -> None:
    unguarded = _record(query_name, cwe, task_feature_id, target_feature_id)
    guarded = _record(
        query_name,
        cwe,
        task_feature_id,
        target_feature_id,
        target_state=FeatureState.PRESENT,
    )

    assert (
        feature_state(record_to_multidigraph(unguarded), target_feature_id) is FeatureState.ABSENT
    )
    assert feature_state(record_to_multidigraph(guarded), target_feature_id) is FeatureState.PRESENT

    unguarded_context = _evaluate(unguarded, query_name, archetype)
    guarded_context = _evaluate(guarded, query_name, archetype)

    assert unguarded_context.result.state is QueryState.PRESENT
    assert guarded_context.result.state is QueryState.PRESENT
    assert unguarded_context.result.match_evidence_ids
    assert guarded_context.result.match_evidence_ids == unguarded_context.result.match_evidence_ids
    assert all(match.node_evidence and match.edge_evidence for match in unguarded_context.matches)
    assert all(match.node_evidence and match.edge_evidence for match in guarded_context.matches)


@pytest.mark.parametrize(
    ("query_name", "cwe", "archetype", "task_feature_id", "target_feature_id"),
    CASES,
)
def test_context_query_four_values_are_distinct_and_provenance_bound(
    query_name: str,
    cwe: str,
    archetype: str,
    task_feature_id: str,
    target_feature_id: str,
) -> None:
    present_record = _record(query_name, cwe, task_feature_id, target_feature_id)
    absent_record = _record(
        query_name,
        cwe,
        task_feature_id,
        target_feature_id,
        connected_target_sink=False,
    )
    unresolved_record = _record(
        query_name,
        cwe,
        task_feature_id,
        target_feature_id,
        complete_sink_evidence=False,
    )

    present = _evaluate(present_record, query_name, archetype)
    absent = _evaluate(absent_record, query_name, archetype)
    not_applicable = _evaluate(present_record, query_name, "unrelated-task-archetype")
    unresolved = _evaluate(unresolved_record, query_name, archetype)

    assert tuple(item.result.state for item in (present, absent, not_applicable, unresolved)) == (
        QueryState.PRESENT,
        QueryState.ABSENT,
        QueryState.NOT_APPLICABLE,
        QueryState.UNRESOLVED,
    )
    assert present.result.prompt_tsg_sha256 == present_record.graph_sha256
    assert present.result.context_query_id == present.spec.context_query_id
    assert present.result.context_query_catalog_sha256 == CONTEXT_QUERY_CATALOG_SHA256
    assert present.result.match_evidence_ids == tuple(
        sorted(item.evidence_id for item in present.matches)
    )
    assert present.result.evaluation_evidence_sha256
    assert absent.result.required_roles_resolved is True
    assert absent.result.bounded_matching_complete is True
    assert not_applicable.result.applicable is False
    assert unresolved.result.required_roles_resolved is False
    assert unresolved.result.bounded_matching_complete is False
    assert not absent.matches and not not_applicable.matches and not unresolved.matches


def test_guard_cannot_become_a_context_flow_intermediate() -> None:
    record = _record(
        CWE78_COMMAND_FLOW_QUERY,
        "CWE-78",
        "task.process_launch",
        "safety.safe_subprocess",
        target_state=FeatureState.PRESENT,
        connected_target_sink=False,
    )
    graph = record_to_multidigraph(record)
    data = next(
        node_id
        for node_id, node in graph.nodes(data=True)
        if node["node_type"] is NodeType.DATA_OBJECT and node["label"] == "command_argument"
    )
    guard = next(
        node_id for node_id, node in graph.nodes(data=True) if node["node_type"] is NodeType.GUARD
    )
    sink = next(
        node_id
        for node_id, node in graph.nodes(data=True)
        if node["node_type"] is NodeType.SINK and node["label"] == "process_spawn"
    )
    _add_edge(graph, data, guard, EdgeType.FLOWS_TO)
    _add_edge(graph, guard, sink, EdgeType.FLOWS_TO)
    malformed_but_canonical = multidigraph_to_record(
        graph,
        prompt_id="prompt.cwe78.invalid-guard-flow",
        task_id="task.cwe78.invalid-guard-flow",
        task_family="command_execution",
        cwe="CWE-78",
        extractor_backend=record.extractor_backend,
        extractor_policy_sha256=record.extractor_policy_sha256,
        proposal_id=record.proposal_id,
    )

    evaluation = _evaluate(
        malformed_but_canonical,
        CWE78_COMMAND_FLOW_QUERY,
        "argument-vector-subprocess",
    )

    assert evaluation.result.state is QueryState.UNRESOLVED
    assert evaluation.result.bounded_matching_complete is False
    assert not evaluation.matches


def test_missing_required_roles_cannot_be_reported_as_absent() -> None:
    record = _record(
        CWE78_COMMAND_FLOW_QUERY,
        "CWE-78",
        "task.process_launch",
        "safety.safe_subprocess",
    )
    graph = record_to_multidigraph(record)
    for node_id, node in tuple(graph.nodes(data=True)):
        if node["node_type"] not in {NodeType.FEATURE, NodeType.PRESENTATION_FEATURE}:
            graph.remove_node(node_id)
        else:
            node["attributes"]["feature_state"] = FeatureState.ABSENT.value
    roles_missing = multidigraph_to_record(
        graph,
        prompt_id="prompt.cwe78.roles-missing",
        task_id="task.cwe78.roles-missing",
        task_family="command_execution",
        cwe="CWE-78",
        extractor_backend=record.extractor_backend,
        extractor_policy_sha256=record.extractor_policy_sha256,
        proposal_id=record.proposal_id,
    )

    evaluation = _evaluate(
        roles_missing,
        CWE78_COMMAND_FLOW_QUERY,
        "argument-vector-subprocess",
    )

    assert evaluation.result.state is QueryState.UNRESOLVED
    assert evaluation.result.required_roles_resolved is False
    assert evaluation.result.bounded_matching_complete is False


def test_context_query_rejects_membership_with_wrong_task_or_known_cwe_archetype() -> None:
    record = _record(
        CWE78_COMMAND_FLOW_QUERY,
        "CWE-78",
        "task.process_launch",
        "safety.safe_subprocess",
    )

    with pytest.raises(ValueError, match="membership does not match"):
        evaluate_context_query(
            record,
            CWE78_COMMAND_FLOW_QUERY,
            semantic_membership=_membership(
                record,
                "argument-vector-subprocess",
                task_instance_id="task.attacker-substitution",
            ),
        )
    with pytest.raises(ValueError, match="membership does not match"):
        evaluate_context_query(
            record,
            CWE78_COMMAND_FLOW_QUERY,
            semantic_membership=_membership(record, "value-parameterization"),
        )

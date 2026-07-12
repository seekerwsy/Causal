from __future__ import annotations

import hashlib
import json
from pathlib import Path
import traceback

import networkx as nx
import pytest

import secaware.tsg.motifs as motif_queries
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.hypotheses import FactorType
from secaware.schema.tsg import EdgeType, MotifId, NodeType
from secaware.tsg.catalog import PROMPT_TSG_CATALOG
from secaware.tsg.graph import canonical_edge_id, canonical_node_id
from secaware.tsg.motifs import (
    MOTIF_SPECS,
    factor_query_vector,
    find_motif_matches,
    has_factor_requirement,
    motif_query_vector,
)


_MOTIF_BY_FACTOR = {
    FactorType.INPUT_VALIDATION: MotifId.UNTRUSTED_SOURCE_TO_SENSITIVE_SINK_WITHOUT_GUARD,
    FactorType.PATH_NORMALIZATION: MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
    FactorType.SQL_PARAMETERIZATION: MotifId.USER_STRING_TO_SQL_WITHOUT_PARAMETERIZATION,
    FactorType.SAFE_SUBPROCESS: MotifId.USER_INPUT_TO_SHELL_WITHOUT_GUARD,
    FactorType.AUTHORIZATION_CHECK: MotifId.SENSITIVE_OPERATION_WITHOUT_AUTH_GUARD,
    FactorType.SAFE_DESERIALIZATION: MotifId.UNTRUSTED_DATA_TO_DESERIALIZATION_SINK,
}


def _semantic_commitment(key: str) -> str:
    payload = json.dumps({"semantic_key": key}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _add_node(
    graph: nx.MultiDiGraph,
    key: str,
    node_type: NodeType,
    label: str,
) -> str:
    node_id = canonical_node_id(node_type, label, key)
    graph.add_node(
        node_id,
        semantic_key_sha256=_semantic_commitment(key),
        node_type=node_type,
        label=label,
        attributes={},
    )
    return node_id


def _add_edge(
    graph: nx.MultiDiGraph,
    src: str,
    dst: str,
    edge_type: EdgeType,
) -> str:
    ordinal = graph.number_of_edges(src, dst)
    edge_id = canonical_edge_id(src, dst, edge_type, {}, ordinal)
    graph.add_edge(src, dst, key=edge_id, edge_type=edge_type, attributes={})
    return edge_id


def _unsafe_flow(
    factor_type: FactorType = FactorType.PATH_NORMALIZATION,
    *,
    flow_hops: int = 1,
) -> nx.MultiDiGraph:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.factor_type is factor_type)
    graph = nx.MultiDiGraph()
    source = _add_node(graph, f"{factor_type.value}:source", NodeType.SOURCE, "user_input")
    data = _add_node(graph, f"{factor_type.value}:data", NodeType.DATA_OBJECT, entry.data_label)
    sink = _add_node(graph, f"{factor_type.value}:sink", NodeType.SINK, entry.sink_label)
    _add_edge(graph, source, data, EdgeType.SOURCE_OF)
    previous = data
    for index in range(flow_hops - 1):
        intermediate = _add_node(
            graph,
            f"{factor_type.value}:intermediate:{index}",
            NodeType.DATA_OBJECT,
            f"intermediate_{index}",
        )
        _add_edge(graph, previous, intermediate, EdgeType.FLOWS_TO)
        previous = intermediate
    _add_edge(graph, previous, sink, EdgeType.FLOWS_TO)
    return graph


def _node(graph: nx.MultiDiGraph, node_type: NodeType, label: str) -> str:
    return next(
        node_id
        for node_id, attributes in graph.nodes(data=True)
        if attributes["node_type"] is node_type and attributes["label"] == label
    )


def _add_guard_structure(
    graph: nx.MultiDiGraph,
    factor_type: FactorType,
    *,
    guard_label: str | None = None,
    requirement_label: str | None = None,
    guard_type: NodeType = NodeType.GUARD,
    guard_data: bool = True,
    guard_sink: bool = True,
) -> tuple[str, str]:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.factor_type is factor_type)
    guard = _add_node(
        graph,
        f"{factor_type.value}:guard:{guard_label or entry.guard_label}",
        guard_type,
        guard_label or entry.guard_label,
    )
    requirement = _add_node(
        graph,
        f"{factor_type.value}:requirement:{requirement_label or entry.requirement_label}",
        NodeType.PROMPT_REQUIREMENT,
        requirement_label or entry.requirement_label,
    )
    _add_edge(graph, requirement, guard, EdgeType.REQUIRES)
    if guard_data:
        _add_edge(
            graph,
            _node(graph, NodeType.DATA_OBJECT, entry.data_label),
            guard,
            EdgeType.GUARDED_BY,
        )
    if guard_sink:
        _add_edge(
            graph,
            _node(graph, NodeType.SINK, entry.sink_label),
            guard,
            EdgeType.GUARDED_BY,
        )
    return requirement, guard


def test_disconnected_guard_does_not_protect_flow() -> None:
    graph = _unsafe_flow()
    _add_guard_structure(graph, FactorType.PATH_NORMALIZATION, guard_data=False, guard_sink=False)

    matches = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)

    assert len(matches) == 1
    assert matches[0].guarded is False
    assert matches[0].guard_nodes == ()


def test_same_flow_guard_removes_unguarded_match() -> None:
    graph = _unsafe_flow()
    _add_guard_structure(graph, FactorType.PATH_NORMALIZATION)

    assert find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD) == ()


@pytest.mark.parametrize(
    "guard_options",
    (
        {"guard_data": False},
        {"guard_sink": False},
        {"guard_label": "input_validation"},
        {"requirement_label": "require_input_validation"},
        {"guard_type": NodeType.API},
    ),
)
def test_wrong_or_partial_guard_does_not_protect(guard_options: dict[str, object]) -> None:
    graph = _unsafe_flow()
    _add_guard_structure(graph, FactorType.PATH_NORMALIZATION, **guard_options)

    assert len(find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)) == 1


@pytest.mark.parametrize("wrong_type", (NodeType.DATA_OBJECT, NodeType.SINK))
def test_guard_edges_from_wrong_data_or_sink_nodes_do_not_protect(
    wrong_type: NodeType,
) -> None:
    graph = _unsafe_flow()
    entry = next(
        item for item in PROMPT_TSG_CATALOG if item.factor_type is FactorType.PATH_NORMALIZATION
    )
    _, guard = _add_guard_structure(
        graph,
        FactorType.PATH_NORMALIZATION,
        guard_data=False,
        guard_sink=False,
    )
    wrong = _add_node(graph, f"wrong:{wrong_type.value}", wrong_type, f"wrong_{wrong_type.value}")
    _add_edge(graph, wrong, guard, EdgeType.GUARDED_BY)
    correct_endpoint = _node(
        graph,
        NodeType.SINK if wrong_type is NodeType.DATA_OBJECT else NodeType.DATA_OBJECT,
        entry.sink_label if wrong_type is NodeType.DATA_OBJECT else entry.data_label,
    )
    _add_edge(graph, correct_endpoint, guard, EdgeType.GUARDED_BY)

    assert len(find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)) == 1


def test_requirement_must_use_requires_edge() -> None:
    graph = _unsafe_flow()
    requirement, guard = _add_guard_structure(graph, FactorType.PATH_NORMALIZATION)
    key = next(iter(graph[requirement][guard]))
    graph.remove_edge(requirement, guard, key)
    _add_edge(graph, requirement, guard, EdgeType.RELATED_TO)

    assert len(find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)) == 1


def test_parallel_edges_are_distinct_and_evidence_is_deterministic() -> None:
    graph = _unsafe_flow()
    entry = next(
        item for item in PROMPT_TSG_CATALOG if item.factor_type is FactorType.PATH_NORMALIZATION
    )
    source = _node(graph, NodeType.SOURCE, "user_input")
    data = _node(graph, NodeType.DATA_OBJECT, entry.data_label)
    sink = _node(graph, NodeType.SINK, entry.sink_label)
    _add_edge(graph, source, data, EdgeType.SOURCE_OF)
    _add_edge(graph, data, sink, EdgeType.FLOWS_TO)

    one = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)
    two = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)

    assert one == two
    assert len(one) == 4
    assert one == tuple(sorted(one, key=lambda match: (match.node_path, match.edge_path)))
    assert len({match.edge_path for match in one}) == 4


def test_cycles_terminate_without_revisiting_nodes_and_are_deterministic() -> None:
    graph = _unsafe_flow(flow_hops=2)
    entry = next(
        item for item in PROMPT_TSG_CATALOG if item.factor_type is FactorType.PATH_NORMALIZATION
    )
    data = _node(graph, NodeType.DATA_OBJECT, entry.data_label)
    intermediate = _node(graph, NodeType.DATA_OBJECT, "intermediate_0")
    _add_edge(graph, intermediate, data, EdgeType.FLOWS_TO)

    one = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)
    two = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)

    assert one == two
    assert len(one) == 1
    assert len(set(one[0].node_path)) == len(one[0].node_path)


def test_eight_edge_path_matches_but_nine_edge_path_does_not() -> None:
    eight = _unsafe_flow(flow_hops=7)
    nine = _unsafe_flow(flow_hops=8)

    assert len(find_motif_matches(eight, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)) == 1
    assert find_motif_matches(nine, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD) == ()


def _parallel_match_graph(count: int) -> nx.MultiDiGraph:
    graph = _unsafe_flow()
    entry = next(
        item for item in PROMPT_TSG_CATALOG if item.factor_type is FactorType.PATH_NORMALIZATION
    )
    source = _node(graph, NodeType.SOURCE, "user_input")
    data = _node(graph, NodeType.DATA_OBJECT, entry.data_label)
    for _ in range(count - 1):
        _add_edge(graph, source, data, EdgeType.SOURCE_OF)
    return graph


def test_exact_match_limit_succeeds_and_next_match_fails_closed() -> None:
    assert (
        len(
            find_motif_matches(
                _parallel_match_graph(256),
                MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
            )
        )
        == 256
    )

    with pytest.raises(SecAwareError) as exc_info:
        find_motif_matches(
            _parallel_match_graph(257),
            MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
        )
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_traversal_states_are_bounded_before_path_explosion() -> None:
    graph = _unsafe_flow()
    sink = _node(graph, NodeType.SINK, "file_open")
    graph.remove_node(sink)
    data = _node(graph, NodeType.DATA_OBJECT, "user_path")
    previous_layer = [data]
    for depth in range(4):
        next_layer = []
        for parent_index, parent in enumerate(previous_layer):
            for branch in range(3):
                child = _add_node(
                    graph,
                    f"branch:{depth}:{parent_index}:{branch}",
                    NodeType.DATA_OBJECT,
                    f"branch_{depth}_{parent_index}_{branch}",
                )
                _add_edge(graph, parent, child, EdgeType.FLOWS_TO)
                next_layer.append(child)
        previous_layer = next_layer

    with pytest.raises(SecAwareError) as exc_info:
        find_motif_matches(
            graph,
            MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
            max_matches=1,
        )
    assert exc_info.value.code is ErrorCode.TSG_INVALID


@pytest.mark.parametrize(
    ("keyword", "value"),
    (
        ("max_hops", True),
        ("max_hops", 0),
        ("max_hops", 9),
        ("max_matches", False),
        ("max_matches", 0),
        ("max_matches", 257),
    ),
)
def test_invalid_query_bounds_fail_closed(keyword: str, value: object) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        find_motif_matches(
            _unsafe_flow(),
            MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
            **{keyword: value},
        )
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_invalid_motif_and_noncanonical_graph_fail_closed() -> None:
    graph = nx.MultiDiGraph()
    graph.add_node("fake", node_type="source", label="secret", attributes={})
    for candidate_graph, motif_id in (
        (graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD),
        (_unsafe_flow(), "not-a-motif"),
    ):
        with pytest.raises(SecAwareError) as exc_info:
            find_motif_matches(candidate_graph, motif_id)  # type: ignore[arg-type]
        assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_catalog_mapping_is_total_unique_and_all_six_families_query() -> None:
    assert tuple(MOTIF_SPECS) == tuple(MotifId)
    assert {spec.factor_type for spec in MOTIF_SPECS.values()} == set(FactorType)
    assert len(MOTIF_SPECS) == 6

    for factor_type, motif_id in _MOTIF_BY_FACTOR.items():
        graph = _unsafe_flow(factor_type)
        assert len(find_motif_matches(graph, motif_id)) == 1
        assert tuple(item for item, _ in motif_query_vector(graph)) == tuple(MotifId)
        assert dict(motif_query_vector(graph))[motif_id] is True


def test_factor_requirement_queries_live_typed_graph_and_mutation() -> None:
    graph = _unsafe_flow()
    requirement, guard = _add_guard_structure(graph, FactorType.PATH_NORMALIZATION)

    assert has_factor_requirement(graph, FactorType.PATH_NORMALIZATION) is True
    assert tuple(item for item, _ in factor_query_vector(graph)) == tuple(FactorType)
    assert dict(factor_query_vector(graph))[FactorType.PATH_NORMALIZATION] is True

    edge_key = next(iter(graph[requirement][guard]))
    graph.remove_edge(requirement, guard, edge_key)
    assert has_factor_requirement(graph, FactorType.PATH_NORMALIZATION) is False


@pytest.mark.parametrize(
    "mutation",
    (
        lambda graph: graph.nodes[next(iter(graph))].update(unexpected=True),
        lambda graph: graph.nodes[next(iter(graph))].update(node_type="source"),
        lambda graph: graph.edges[next(iter(graph.edges(keys=True)))].update(edge_type="source_of"),
    ),
)
def test_malformed_committed_graph_fields_and_types_are_tsg_invalid(mutation) -> None:
    graph = _unsafe_flow()
    mutation(graph)
    with pytest.raises(SecAwareError) as exc_info:
        find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_malformed_committed_edge_key_is_tsg_invalid() -> None:
    graph = _unsafe_flow()
    src, dst, key, attributes = next(iter(graph.edges(keys=True, data=True)))
    graph.remove_edge(src, dst, key)
    graph.add_edge(src, dst, key="not-canonical", **attributes)

    with pytest.raises(SecAwareError) as exc_info:
        find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)
    assert exc_info.value.code is ErrorCode.TSG_INVALID


@pytest.mark.parametrize("exception_type", (RuntimeError, ValueError, TypeError))
def test_unexpected_iterator_failure_is_analysis_invalid_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[Exception],
) -> None:
    sentinel = "MOTIF_INTERNAL_SENTINEL_81420"

    def fail(*_args, **_kwargs):
        held_secret = sentinel
        raise exception_type(held_secret)

    monkeypatch.setattr(motif_queries, "_iter_sorted_out_edges", fail)
    with pytest.raises(SecAwareError) as exc_info:
        find_motif_matches(_unsafe_flow(), MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)

    error = exc_info.value
    rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
    cursor = error.__traceback__
    while cursor is not None:
        if (
            Path(cursor.tb_frame.f_code.co_filename).resolve()
            == Path(motif_queries.__file__).resolve()
        ):
            rendered += repr(cursor.tb_frame.f_locals)
        cursor = cursor.tb_next
    assert error.code is ErrorCode.ANALYSIS_INVALID
    assert error.__context__ is None
    assert error.__cause__ is None
    assert sentinel not in rendered

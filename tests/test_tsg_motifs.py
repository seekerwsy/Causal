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
from secaware.schema.features import (
    FeatureFamily,
    FeatureState,
    PromptExtractorBackend,
)
from secaware.schema.tsg import (
    EdgeType,
    MAX_TSG_EDGES,
    MAX_TSG_NODES,
    MotifId,
    NodeType,
)
from secaware.tsg.catalog import PROMPT_TSG_CATALOG
from secaware.tsg.graph import (
    canonical_edge_id,
    canonical_node_id,
    multidigraph_to_record,
    record_to_multidigraph,
)
from secaware.tsg.motifs import (
    MOTIF_SPECS,
    factor_query_vector,
    feature_state,
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


def test_feature_state_reads_one_finite_canonical_state_node() -> None:
    graph = nx.MultiDiGraph()
    requirement = _add_node(
        graph,
        "path-requirement",
        NodeType.PROMPT_REQUIREMENT,
        "require_path_normalization",
    )
    guard = _add_node(graph, "path-guard", NodeType.GUARD, "path_normalization")
    _add_edge(graph, requirement, guard, EdgeType.REQUIRES)
    feature_id = "safety.path_normalization"
    node_id = canonical_node_id(NodeType.FEATURE, feature_id, "path-state")
    graph.add_node(
        node_id,
        semantic_key_sha256=_semantic_commitment("path-state"),
        node_type=NodeType.FEATURE,
        label=feature_id,
        attributes={
            "feature_id": feature_id,
            "feature_family": FeatureFamily.SAFETY_CONTROL.value,
            "feature_state": FeatureState.PRESENT.value,
        },
    )
    record = multidigraph_to_record(
        graph,
        prompt_id="p001",
        task_id="task-path-001",
        task_family="path_handling",
        cwe="CWE-22",
        extractor_backend=PromptExtractorBackend.LLM_FACTS_V1,
        extractor_policy_sha256="8" * 64,
        proposal_id="proposal_" + "7" * 64,
    )
    restored = record_to_multidigraph(record)

    assert record.schema_version == "2.1"
    assert record.task_id == "task-path-001"
    assert record.extractor_backend is PromptExtractorBackend.LLM_FACTS_V1
    assert feature_state(restored, feature_id) is FeatureState.PRESENT


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
        {"guard_label": "input_validation"},
        {"requirement_label": "require_input_validation"},
        {"guard_type": NodeType.API},
    ),
)
def test_wrong_or_partial_guard_does_not_protect(guard_options: dict[str, object]) -> None:
    graph = _unsafe_flow()
    _add_guard_structure(graph, FactorType.PATH_NORMALIZATION, **guard_options)

    assert len(find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)) == 1


@pytest.mark.parametrize(
    "guard_options",
    ({"guard_data": False}, {"guard_sink": False}),
)
def test_guard_relation_from_any_path_data_or_sink_node_protects(
    guard_options: dict[str, object],
) -> None:
    graph = _unsafe_flow()
    _add_guard_structure(graph, FactorType.PATH_NORMALIZATION, **guard_options)

    assert find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD) == ()


@pytest.mark.parametrize("wrong_type", (NodeType.DATA_OBJECT, NodeType.SINK))
def test_guard_edges_from_wrong_data_or_sink_nodes_do_not_protect(
    wrong_type: NodeType,
) -> None:
    graph = _unsafe_flow()
    _, guard = _add_guard_structure(
        graph,
        FactorType.PATH_NORMALIZATION,
        guard_data=False,
        guard_sink=False,
    )
    wrong = _add_node(graph, f"wrong:{wrong_type.value}", wrong_type, f"wrong_{wrong_type.value}")
    _add_edge(graph, wrong, guard, EdgeType.GUARDED_BY)
    assert len(find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)) == 1


@pytest.mark.parametrize(
    ("guard_type", "guard_label", "requirement_label", "with_requirement", "protected"),
    (
        (NodeType.GUARD, "path_normalization", "require_path_normalization", True, True),
        (NodeType.API, "path_normalization", "require_path_normalization", True, False),
        (NodeType.GUARD, "input_validation", "require_path_normalization", True, False),
        (NodeType.GUARD, "path_normalization", "require_input_validation", True, False),
        (NodeType.GUARD, "path_normalization", "require_path_normalization", False, False),
    ),
)
def test_guard_on_matched_flow_path_requires_exact_typed_requirement(
    guard_type: NodeType,
    guard_label: str,
    requirement_label: str,
    with_requirement: bool,
    protected: bool,
) -> None:
    graph = nx.MultiDiGraph()
    source = _add_node(graph, "path-guard:source", NodeType.SOURCE, "user_input")
    data = _add_node(graph, "path-guard:data", NodeType.DATA_OBJECT, "user_path")
    guard = _add_node(graph, "path-guard:guard", guard_type, guard_label)
    sink = _add_node(graph, "path-guard:sink", NodeType.SINK, "file_open")
    _add_edge(graph, source, data, EdgeType.SOURCE_OF)
    _add_edge(graph, data, guard, EdgeType.FLOWS_TO)
    _add_edge(graph, guard, sink, EdgeType.FLOWS_TO)
    if with_requirement:
        requirement = _add_node(
            graph,
            "path-guard:requirement",
            NodeType.PROMPT_REQUIREMENT,
            requirement_label,
        )
        _add_edge(graph, requirement, guard, EdgeType.REQUIRES)

    matches = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)

    assert (matches == ()) is protected


def test_guard_relation_from_intermediate_path_data_node_protects() -> None:
    graph = _unsafe_flow(flow_hops=2)
    _, guard = _add_guard_structure(
        graph,
        FactorType.PATH_NORMALIZATION,
        guard_data=False,
        guard_sink=False,
    )
    intermediate = _node(graph, NodeType.DATA_OBJECT, "intermediate_0")
    _add_edge(graph, intermediate, guard, EdgeType.GUARDED_BY)

    assert find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD) == ()


def test_guard_relation_from_data_node_outside_matched_path_does_not_protect() -> None:
    graph = _unsafe_flow()
    _, guard = _add_guard_structure(
        graph,
        FactorType.PATH_NORMALIZATION,
        guard_data=False,
        guard_sink=False,
    )
    outside = _add_node(graph, "outside:data", NodeType.DATA_OBJECT, "outside_data")
    _add_edge(graph, outside, guard, EdgeType.GUARDED_BY)

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


class _SecondTraversalProbe:
    def __init__(
        self,
        items: tuple[object, ...],
        *,
        second_behavior: str,
        maximum: int,
    ) -> None:
        self.items = items
        self.second_behavior = second_behavior
        self.maximum = maximum
        self.traversals = 0
        self.consumed = 0

    def __call__(self, *_args, **_kwargs):
        return self

    def __iter__(self):
        self.traversals += 1
        if self.traversals == 1 or self.second_behavior == "repeat":
            for item in self.items:
                self.consumed += 1
                yield item
            return
        if self.second_behavior == "explode":
            raise RuntimeError("SECOND_LIVE_VIEW_MUST_NOT_BE_TOUCHED")
        for index in range(self.maximum + 2):
            self.consumed += 1
            if index > self.maximum:
                raise AssertionError("second traversal consumed beyond MAX+1")
            yield (f"second-{index}", {})


@pytest.mark.parametrize("dimension", ("nodes", "edges"))
@pytest.mark.parametrize("second_behavior", ("explode", "oversized"))
def test_query_uses_one_bounded_committed_snapshot(
    dimension: str,
    second_behavior: str,
) -> None:
    canonical = _unsafe_flow()
    raw_nodes = tuple(canonical.nodes(data=True))
    raw_edges = tuple(canonical.edges(keys=True, data=True))
    node_view = _SecondTraversalProbe(
        raw_nodes,
        second_behavior=second_behavior if dimension == "nodes" else "repeat",
        maximum=MAX_TSG_NODES,
    )
    edge_view = _SecondTraversalProbe(
        raw_edges,
        second_behavior=second_behavior if dimension == "edges" else "repeat",
        maximum=MAX_TSG_EDGES,
    )
    probe = nx.MultiDiGraph()
    probe.number_of_nodes = lambda: len(raw_nodes)
    probe.number_of_edges = lambda: len(raw_edges)
    probe.__dict__["nodes"] = node_view
    probe.__dict__["edges"] = edge_view

    matches = find_motif_matches(probe, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)

    assert len(matches) == 1
    assert node_view.traversals == 1
    assert edge_view.traversals == 1
    assert node_view.consumed == len(raw_nodes) <= MAX_TSG_NODES
    assert edge_view.consumed == len(raw_edges) <= MAX_TSG_EDGES


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


def _high_branching_without_eligible_sink(*, wrong_sink: bool) -> nx.MultiDiGraph:
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
    if wrong_sink:
        wrong = _add_node(graph, "wrong:sink", NodeType.SINK, "wrong_sink")
        _add_edge(graph, previous_layer[-1], wrong, EdgeType.FLOWS_TO)
    return graph


@pytest.mark.parametrize("wrong_sink", (False, True))
def test_high_branching_without_eligible_sink_is_pruned(
    wrong_sink: bool,
) -> None:
    graph = _high_branching_without_eligible_sink(wrong_sink=wrong_sink)

    assert (
        find_motif_matches(
            graph,
            MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
            max_matches=1,
        )
        == ()
    )
    assert find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD) == ()


@pytest.mark.parametrize("count", (256, 257))
def test_guarded_candidates_still_enforce_match_bound(count: int) -> None:
    graph = _parallel_match_graph(count)
    _add_guard_structure(graph, FactorType.PATH_NORMALIZATION)

    if count == 256:
        assert find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD) == ()
    else:
        with pytest.raises(SecAwareError) as exc_info:
            find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)
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

from __future__ import annotations

import networkx as nx
import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.features import FeatureFamily, FeatureState
from secaware.schema.tsg import NodeType
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import (
    feature_state,
    feature_state_vector,
    feature_states_by_family,
)

from test_prompt_tsg_builder import _facts_proposal, _prompt
from secaware.tsg.builder import build_prompt_tsg


def _graph() -> nx.MultiDiGraph:
    return record_to_multidigraph(build_prompt_tsg(_facts_proposal(), _prompt()))


def test_live_graph_queries_return_closed_catalog_states_and_family_projection() -> None:
    graph = _graph()
    vector = feature_state_vector(graph)
    safety = feature_states_by_family(graph, FeatureFamily.SAFETY_CONTROL)

    assert dict(vector)["safety.path_normalization"] is FeatureState.PRESENT
    assert dict(vector)["task.database_query"] is FeatureState.NOT_APPLICABLE
    assert safety
    assert all(feature_id.startswith("safety.") for feature_id, _ in safety)
    assert feature_state(graph, "presentation.noop_rewrite") is FeatureState.ABSENT


@pytest.mark.parametrize("feature_id", ["unknown.feature", "", 1])
def test_feature_query_rejects_unknown_or_non_string_ids(feature_id: object) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        feature_state(_graph(), feature_id)  # type: ignore[arg-type]
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_feature_query_fails_closed_when_state_node_is_missing_or_duplicated() -> None:
    graph = _graph()
    target = next(
        node_id
        for node_id, data in graph.nodes(data=True)
        if data["node_type"] is NodeType.FEATURE
        and data["attributes"]["feature_id"] == "safety.path_normalization"
    )
    graph.remove_node(target)
    with pytest.raises(SecAwareError) as exc_info:
        feature_state(graph, "safety.path_normalization")
    assert exc_info.value.code is ErrorCode.TSG_INVALID

    graph = _graph()
    data = next(
        data
        for _, data in graph.nodes(data=True)
        if data["node_type"] is NodeType.FEATURE
        and data["attributes"]["feature_id"] == "safety.path_normalization"
    )
    graph.add_node("duplicate", **data)
    with pytest.raises(SecAwareError) as exc_info:
        feature_state_vector(graph)
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_feature_query_normalizes_wrong_graph_and_family_failures() -> None:
    with pytest.raises(SecAwareError) as exc_info:
        feature_state(nx.DiGraph(), "task.file_read")  # type: ignore[arg-type]
    assert exc_info.value.code is ErrorCode.TSG_INVALID

    with pytest.raises(SecAwareError) as exc_info:
        feature_states_by_family(_graph(), "safety_control")  # type: ignore[arg-type]
    assert exc_info.value.code is ErrorCode.TSG_INVALID

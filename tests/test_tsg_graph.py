from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

import networkx as nx
import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.tsg import EdgeType, MAX_TSG_NODES, NodeType
from secaware.tsg.graph import (
    canonical_edge_id,
    canonical_node_id,
    graph_sha256,
    multidigraph_to_record,
    record_to_multidigraph,
)


def _minimal_graph() -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    graph.add_node("source", node_type="source", label="user_input", attributes={})
    graph.add_node("data", node_type="data_object", label="user_path", attributes={})
    graph.add_edge("source", "data", key="flow", edge_type="source_of", attributes={})
    return graph


def _reverse_insertions(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    reversed_graph = nx.MultiDiGraph()
    for node_key, attributes in reversed(list(graph.nodes(data=True))):
        reversed_graph.add_node(node_key, **attributes)
    for src, dst, key, attributes in reversed(list(graph.edges(keys=True, data=True))):
        reversed_graph.add_edge(src, dst, key=key, **attributes)
    return reversed_graph


def _replace_digest(record, digest: str):
    return record.model_copy(update={"graph_sha256": digest})


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def test_parallel_edges_round_trip_without_order_drift() -> None:
    graph = nx.MultiDiGraph()
    graph.add_node("source", node_type="source", label="user_input", attributes={})
    graph.add_node("data", node_type="data_object", label="user_path", attributes={})
    graph.add_edge("source", "data", key="first", edge_type="source_of", attributes={})
    graph.add_edge("source", "data", key="second", edge_type="related_to", attributes={})

    one = multidigraph_to_record(graph, prompt_id="p001")
    two = multidigraph_to_record(_reverse_insertions(graph), prompt_id="p001")

    assert one.graph_sha256 == two.graph_sha256
    assert one.model_dump_json() == two.model_dump_json()
    rebuilt = record_to_multidigraph(one)
    source = next(node.node_id for node in one.nodes if node.node_type is NodeType.SOURCE)
    data = next(node.node_id for node in one.nodes if node.node_type is NodeType.DATA_OBJECT)
    assert rebuilt.number_of_edges(source, data) == 2
    assert {attributes["edge_type"] for _, _, attributes in rebuilt.edges(data=True)} == {
        EdgeType.SOURCE_OF,
        EdgeType.RELATED_TO,
    }


def test_record_codec_rejects_digest_and_endpoint_tampering() -> None:
    record = multidigraph_to_record(_minimal_graph(), prompt_id="p001")
    with pytest.raises(SecAwareError, match="TSG"):
        record_to_multidigraph(_replace_digest(record, "0" * 64))

    tampered_edge = record.edges[0].model_copy(update={"dst": "n_" + "f" * 64})
    tampered_record = record.model_copy(update={"edges": (tampered_edge,)})
    with pytest.raises(SecAwareError, match="TSG"):
        record_to_multidigraph(tampered_record)


def test_canonical_node_id_hashes_explicit_semantic_identity() -> None:
    expected = (
        "n_"
        + hashlib.sha256(
            _canonical_json(
                {
                    "label": "user_input",
                    "node_type": "source",
                    "semantic_key": "request.body",
                }
            )
        ).hexdigest()
    )

    assert canonical_node_id(NodeType.SOURCE, "user_input", "request.body") == expected
    assert canonical_node_id(NodeType.SOURCE, "user_input", "request.body") != canonical_node_id(
        NodeType.DATA_OBJECT, "user_input", "request.body"
    )


def test_parallel_edge_ordinals_are_deterministic_and_keys_are_canonical_ids() -> None:
    graph = nx.MultiDiGraph()
    graph.add_node("one", node_type="source", label="source", attributes={})
    graph.add_node("two", node_type="sink", label="sink", attributes={})
    graph.add_edge("one", "two", key="z", edge_type="related_to", attributes={})
    graph.add_edge("one", "two", key="a", edge_type="flows_to", attributes={})
    graph.add_edge("one", "two", key="m", edge_type="flows_to", attributes={})

    record = multidigraph_to_record(graph, prompt_id="p001")
    src = next(node.node_id for node in record.nodes if node.node_type is NodeType.SOURCE)
    dst = next(node.node_id for node in record.nodes if node.node_type is NodeType.SINK)
    expected = {
        canonical_edge_id(src, dst, EdgeType.FLOWS_TO, {}, 0),
        canonical_edge_id(src, dst, EdgeType.FLOWS_TO, {}, 1),
        canonical_edge_id(src, dst, EdgeType.RELATED_TO, {}, 2),
    }

    assert {edge.edge_id for edge in record.edges} == expected
    rebuilt = record_to_multidigraph(record)
    assert {key for _, _, key in rebuilt.edges(keys=True)} == expected


def test_hash_randomization_does_not_change_record_json() -> None:
    script = """
import networkx as nx
from secaware.tsg.graph import multidigraph_to_record

graph = nx.MultiDiGraph()
nodes = {
    ("source", "source", "user_input"),
    ("data", "data_object", "user_path"),
    ("sink", "sink", "file_open"),
}
for key, node_type, label in nodes:
    graph.add_node(key, node_type=node_type, label=label, attributes={})
edges = {
    ("source", "data", "source_of"),
    ("data", "sink", "flows_to"),
}
for src, dst, edge_type in edges:
    graph.add_edge(src, dst, edge_type=edge_type, attributes={})
print(multidigraph_to_record(graph, prompt_id="p001").model_dump_json())
"""
    outputs = []
    project_root = Path(__file__).resolve().parents[1]
    for seed in ("1", "777"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=project_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(result.stdout.strip())
    assert outputs[0] == outputs[1]


def test_attribute_insertion_order_does_not_change_record_json() -> None:
    graph = nx.MultiDiGraph()
    graph.add_node(
        "api",
        node_type="api",
        label="client",
        attributes={"api_name": "client.fetch", "confidence": 0.5},
    )
    graph.add_edge(
        "api",
        "api",
        edge_type="related_to",
        attributes={"relation_kind": "retry", "confidence": 0.5},
    )
    reordered = nx.MultiDiGraph()
    reordered.add_node(
        "api",
        node_type="api",
        label="client",
        attributes={"confidence": 0.5, "api_name": "client.fetch"},
    )
    reordered.add_edge(
        "api",
        "api",
        edge_type="related_to",
        attributes={"confidence": 0.5, "relation_kind": "retry"},
    )

    one = multidigraph_to_record(
        graph, prompt_id="p001", shadow={"factor.z": True, "factor.a": False}
    )
    two = multidigraph_to_record(
        reordered, prompt_id="p001", shadow={"factor.a": False, "factor.z": True}
    )

    assert one.model_dump_json() == two.model_dump_json()


def test_cycles_and_allowed_self_edges_round_trip() -> None:
    graph = nx.MultiDiGraph()
    graph.add_node("a", node_type="source", label="a", attributes={})
    graph.add_node("b", node_type="data_object", label="b", attributes={})
    graph.add_edge("a", "b", edge_type="flows_to", attributes={})
    graph.add_edge("b", "a", edge_type="related_to", attributes={})
    graph.add_edge("a", "a", edge_type="related_to", attributes={})

    record = multidigraph_to_record(graph, prompt_id="p001")
    rebuilt = record_to_multidigraph(record)

    assert nx.is_directed(rebuilt)
    assert len(list(nx.simple_cycles(rebuilt))) >= 1
    source = next(node.node_id for node in record.nodes if node.label == "a")
    assert rebuilt.number_of_edges(source, source) == 1


def test_node_id_collision_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("secaware.tsg.graph._sha256_hex", lambda _: "0" * 64)
    graph = nx.MultiDiGraph()
    graph.add_node("a", node_type="source", label="a", attributes={})
    graph.add_node("b", node_type="source", label="b", attributes={})

    with pytest.raises(SecAwareError, match="TSG"):
        multidigraph_to_record(graph, prompt_id="p001")


def test_edge_id_collision_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = nx.MultiDiGraph()
    graph.add_node("a", node_type="source", label="a", attributes={})
    graph.add_edge("a", "a", edge_type="related_to", attributes={})
    graph.add_edge("a", "a", edge_type="related_to", attributes={})
    original = hashlib.sha256

    def collide_edge_ids(payload: bytes) -> str:
        if b'"ordinal"' in payload:
            return "0" * 64
        return original(payload).hexdigest()

    monkeypatch.setattr("secaware.tsg.graph._sha256_hex", collide_edge_ids)
    with pytest.raises(SecAwareError, match="TSG"):
        multidigraph_to_record(graph, prompt_id="p001")


@pytest.mark.parametrize("location", ["graph", "node", "edge"])
def test_unknown_graph_node_and_edge_attributes_fail_closed(location: str) -> None:
    graph = _minimal_graph()
    if location == "graph":
        graph.graph["unexpected"] = True
    elif location == "node":
        graph.nodes["source"]["unexpected"] = True
    else:
        graph.edges["source", "data", "flow"]["unexpected"] = True

    with pytest.raises(SecAwareError) as exc_info:
        multidigraph_to_record(graph, prompt_id="p001")
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_conversion_snapshots_mutable_containers_in_both_directions() -> None:
    graph = _minimal_graph()
    graph.nodes["source"]["attributes"] = {"confidence": 0.5}
    original_node_attributes = graph.nodes["source"]["attributes"]
    record = multidigraph_to_record(graph, prompt_id="p001", shadow={"graph.node_count": 2})
    original_node_attributes["confidence"] = 0.9
    graph.clear()

    source = next(node for node in record.nodes if node.node_type is NodeType.SOURCE)
    assert source.attributes["confidence"] == 0.5
    assert record.shadow["graph.node_count"] == 2

    rebuilt = record_to_multidigraph(record)
    rebuilt.nodes[source.node_id]["attributes"]["confidence"] = 0.1
    rebuilt.graph["local"] = "mutation"
    assert source.attributes["confidence"] == 0.5
    assert "local" not in type(record).model_fields


def test_reconstructed_canonical_graph_is_idempotent() -> None:
    one = multidigraph_to_record(_minimal_graph(), prompt_id="p001")
    rebuilt = record_to_multidigraph(one)
    two = multidigraph_to_record(rebuilt, prompt_id="p001", shadow=one.shadow)

    assert one.model_dump_json() == two.model_dump_json()
    assert graph_sha256(rebuilt) == one.graph_sha256


def test_prompt_evidence_is_absent_from_error_repr_traceback_and_direct_frames() -> None:
    sentinel = "PROMPT-EVIDENCE-DIRECT-FRAME-DO-NOT-LEAK"
    graph = _minimal_graph()
    graph.nodes["source"]["attributes"] = {"evidence": sentinel}

    with pytest.raises(SecAwareError) as exc_info:
        multidigraph_to_record(graph, prompt_id="p001")

    error = exc_info.value
    rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_globals.get("__name__") == "secaware.tsg.graph":
            rendered += repr(current.tb_frame.f_locals)
        current = current.tb_next
    assert sentinel not in rendered
    assert error.code is ErrorCode.TSG_INVALID


def test_codec_rejects_graph_above_node_limit() -> None:
    graph = nx.MultiDiGraph()
    for index in range(MAX_TSG_NODES + 1):
        graph.add_node(f"node-{index}", node_type="source", label=f"node-{index}", attributes={})

    with pytest.raises(SecAwareError, match="TSG"):
        multidigraph_to_record(graph, prompt_id="p001")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda graph: graph.nodes["source"].update(node_type=1),
        lambda graph: graph.nodes["source"].update(label=" source"),
        lambda graph: graph.nodes["source"].update(attributes={"confidence": 1}),
        lambda graph: graph.nodes["source"].update(attributes={"nested": {"x": 1}}),
        lambda graph: graph.edges["source", "data", "flow"].update(edge_type=True),
        lambda graph: graph.edges["source", "data", "flow"].update(
            attributes={"relation_kind": "invalid-for-source-of"}
        ),
    ],
)
def test_codec_boundary_enforces_strict_types_and_attribute_contracts(mutation) -> None:
    graph = _minimal_graph()
    mutation(graph)
    with pytest.raises(SecAwareError, match="TSG"):
        multidigraph_to_record(graph, prompt_id="p001")


@pytest.mark.parametrize("bad_key", [1, "", " semantic", "x" * 1025])
def test_codec_rejects_unsafe_builder_node_keys(bad_key: object) -> None:
    graph = nx.MultiDiGraph()
    graph.add_node(bad_key, node_type="source", label="source", attributes={})
    with pytest.raises(SecAwareError, match="TSG"):
        multidigraph_to_record(graph, prompt_id="p001")


def test_public_id_helpers_reject_unsafe_inputs() -> None:
    with pytest.raises(SecAwareError, match="TSG"):
        canonical_node_id(NodeType.SOURCE, "source", " unsafe")
    with pytest.raises(SecAwareError, match="TSG"):
        canonical_edge_id(
            "n_" + "a" * 64,
            "n_" + "b" * 64,
            EdgeType.FLOWS_TO,
            {"confidence": float("nan")},
            0,
        )
    with pytest.raises(SecAwareError, match="TSG"):
        canonical_edge_id(
            "n_" + "a" * 64,
            "n_" + "b" * 64,
            EdgeType.FLOWS_TO,
            {},
            True,
        )

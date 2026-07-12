"""Canonical NetworkX boundary for prompt-side task semantic graphs."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import cast

import networkx as nx

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.tsg import (
    EdgeType,
    MAX_TSG_EDGES,
    MAX_TSG_NODES,
    MAX_TSG_STRING_BYTES,
    NodeType,
    PromptTSGRecord,
    TSGEdge,
    TSGNode,
    TSGScalar,
    TSG_SCHEMA_VERSION,
)


# Task 3 replaces these fixed catalog versions with the centralized catalog constants.
ONTOLOGY_VERSION = "1.0"
MOTIF_VERSION = "1.0"

_NODE_FIELDS = frozenset({"node_type", "label", "attributes"})
_EDGE_FIELDS = frozenset({"edge_type", "attributes"})
_NODE_ID_RE = re.compile(r"^n_[0-9a-f]{64}$")
_MAX_SIGNED_64_BIT = 2**63 - 1


def _invalid_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "tsg.codec",
        "prompt TSG graph codec validation failed",
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_text(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or not value.strip()
        or value != value.strip()
        or len(value.encode("utf-8")) > MAX_TSG_STRING_BYTES
    ):
        raise ValueError
    return value


def _parse_node_type(value: object) -> NodeType:
    if type(value) is NodeType:
        return cast(NodeType, value)
    if type(value) is str:
        return NodeType(value)
    raise ValueError


def _parse_edge_type(value: object) -> EdgeType:
    if type(value) is EdgeType:
        return cast(EdgeType, value)
    if type(value) is str:
        return EdgeType(value)
    raise ValueError


def _node_id(node_type: NodeType, label: str, semantic_key: str) -> str:
    TSGNode.model_validate(
        {
            "node_id": "n_" + "0" * 64,
            "node_type": node_type,
            "label": label,
            "attributes": {},
        }
    )
    semantic_key = _require_text(semantic_key)
    identity = {
        "label": label,
        "node_type": node_type.value,
        "semantic_key": semantic_key,
    }
    return "n_" + _sha256_hex(_canonical_json(identity))


def _edge_id(
    src: str,
    dst: str,
    edge_type: EdgeType,
    attributes: Mapping[str, TSGScalar],
    ordinal: int,
) -> str:
    if type(ordinal) is not int or not 0 <= ordinal <= _MAX_SIGNED_64_BIT:
        raise ValueError
    validated = TSGEdge.model_validate(
        {
            "edge_id": "e_" + "0" * 64,
            "src": src,
            "dst": dst,
            "edge_type": edge_type,
            "attributes": attributes,
        }
    )
    identity = {
        "attributes": dict(validated.attributes.items()),
        "dst": dst,
        "edge_type": edge_type.value,
        "ordinal": ordinal,
        "src": src,
    }
    return "e_" + _sha256_hex(_canonical_json(identity))


def canonical_node_id(node_type: NodeType, label: str, semantic_key: str) -> str:
    """Return the full SHA-256 identifier for a canonical node semantic key."""
    try:
        result = _node_id(_parse_node_type(node_type), label, semantic_key)
    except Exception:
        result = None
    if result is None:
        node_type = cast(NodeType, None)
        label = cast(str, None)
        semantic_key = cast(str, None)
        raise _invalid_error() from None
    return result


def canonical_edge_id(
    src: str,
    dst: str,
    edge_type: EdgeType,
    attributes: Mapping[str, TSGScalar],
    ordinal: int,
) -> str:
    """Return the full SHA-256 identifier for one canonical multiedge ordinal."""
    try:
        result = _edge_id(src, dst, _parse_edge_type(edge_type), attributes, ordinal)
    except Exception:
        result = None
    if result is None:
        src = cast(str, None)
        dst = cast(str, None)
        edge_type = cast(EdgeType, None)
        attributes = cast(Mapping[str, TSGScalar], None)
        ordinal = cast(int, None)
        raise _invalid_error() from None
    return result


def _canonical_node_key(
    builder_key: object,
    node_type: NodeType,
    label: str,
) -> tuple[str, str]:
    semantic_key = _require_text(builder_key)
    if _NODE_ID_RE.fullmatch(semantic_key) is not None:
        return semantic_key, semantic_key
    return _node_id(node_type, label, semantic_key), semantic_key


def _sorted_attributes(attributes: Mapping[str, TSGScalar]) -> dict[str, TSGScalar]:
    return {key: attributes[key] for key in sorted(attributes)}


def _canonicalize_graph(graph: nx.MultiDiGraph) -> tuple[tuple[TSGNode, ...], tuple[TSGEdge, ...]]:
    if type(graph) is not nx.MultiDiGraph or graph.graph:
        raise ValueError
    if graph.number_of_nodes() > MAX_TSG_NODES or graph.number_of_edges() > MAX_TSG_EDGES:
        raise ValueError

    nodes_by_id: dict[str, TSGNode] = {}
    identities_by_id: dict[str, tuple[str, str, str]] = {}
    builder_to_canonical: dict[object, str] = {}
    for builder_key, raw in graph.nodes(data=True):
        if type(raw) is not dict or raw.keys() != _NODE_FIELDS:
            raise ValueError
        node_type = _parse_node_type(raw["node_type"])
        label = raw["label"]
        attributes = raw["attributes"]
        node_id, semantic_key = _canonical_node_key(builder_key, node_type, label)
        validated_node = TSGNode.model_validate(
            {
                "node_id": node_id,
                "node_type": node_type,
                "label": label,
                "attributes": attributes,
            }
        )
        node = TSGNode.model_validate(
            {
                "node_id": validated_node.node_id,
                "node_type": validated_node.node_type,
                "label": validated_node.label,
                "attributes": _sorted_attributes(validated_node.attributes),
            }
        )
        identity = (node.node_type.value, node.label, semantic_key)
        if node_id in identities_by_id:
            raise ValueError
        identities_by_id[node_id] = identity
        nodes_by_id[node_id] = node
        builder_to_canonical[builder_key] = node_id

    pending_by_endpoints: dict[tuple[str, str], list[tuple[EdgeType, dict[str, TSGScalar]]]] = {}
    for src, dst, _builder_key, raw in graph.edges(keys=True, data=True):
        if type(raw) is not dict or raw.keys() != _EDGE_FIELDS:
            raise ValueError
        if src not in builder_to_canonical or dst not in builder_to_canonical:
            raise ValueError
        canonical_src = builder_to_canonical[src]
        canonical_dst = builder_to_canonical[dst]
        edge_type = _parse_edge_type(raw["edge_type"])
        validated = TSGEdge.model_validate(
            {
                "edge_id": "e_" + "0" * 64,
                "src": canonical_src,
                "dst": canonical_dst,
                "edge_type": edge_type,
                "attributes": raw["attributes"],
            }
        )
        pending_by_endpoints.setdefault((canonical_src, canonical_dst), []).append(
            (edge_type, _sorted_attributes(validated.attributes))
        )

    edges_by_id: dict[str, TSGEdge] = {}
    identities_by_edge_id: dict[str, tuple[str, str, str, bytes, int]] = {}
    for (src, dst), pending in sorted(pending_by_endpoints.items()):
        ordered = sorted(pending, key=lambda item: (item[0].value, _canonical_json(item[1])))
        for ordinal, (edge_type, attributes) in enumerate(ordered):
            edge_id = _edge_id(src, dst, edge_type, attributes, ordinal)
            identity = (src, dst, edge_type.value, _canonical_json(attributes), ordinal)
            if edge_id in identities_by_edge_id:
                raise ValueError
            identities_by_edge_id[edge_id] = identity
            edges_by_id[edge_id] = TSGEdge.model_validate(
                {
                    "edge_id": edge_id,
                    "src": src,
                    "dst": dst,
                    "edge_type": edge_type,
                    "attributes": attributes,
                }
            )

    return (
        tuple(nodes_by_id[node_id] for node_id in sorted(nodes_by_id)),
        tuple(edges_by_id[edge_id] for edge_id in sorted(edges_by_id)),
    )


def _digest(nodes: tuple[TSGNode, ...], edges: tuple[TSGEdge, ...]) -> str:
    payload = {
        "edges": [
            [
                edge.edge_id,
                edge.src,
                edge.dst,
                edge.edge_type.value,
                dict(edge.attributes.items()),
            ]
            for edge in edges
        ],
        "motif_version": MOTIF_VERSION,
        "nodes": [
            [
                node.node_id,
                node.node_type.value,
                node.label,
                dict(node.attributes.items()),
            ]
            for node in nodes
        ],
        "ontology_version": ONTOLOGY_VERSION,
    }
    return _sha256_hex(_canonical_json(payload))


def _try_graph_sha256(graph: nx.MultiDiGraph) -> str | None:
    try:
        nodes, edges = _canonicalize_graph(graph)
        return _digest(nodes, edges)
    except Exception:
        return None


def graph_sha256(graph: nx.MultiDiGraph) -> str:
    """Hash the canonical graph structure and fixed catalog versions."""
    result = _try_graph_sha256(graph)
    if result is None:
        graph = cast(nx.MultiDiGraph, None)
        raise _invalid_error() from None
    return result


def _try_multidigraph_to_record(
    graph: nx.MultiDiGraph,
    prompt_id: str,
    shadow: Mapping[str, TSGScalar] | None,
) -> PromptTSGRecord | None:
    try:
        prompt_id = _require_text(prompt_id)
        nodes, edges = _canonicalize_graph(graph)
        candidate = PromptTSGRecord.model_validate(
            {
                "schema_version": TSG_SCHEMA_VERSION,
                "graph_id": f"prompt:{prompt_id}",
                "source_type": "prompt",
                "prompt_id": prompt_id,
                "ontology_version": ONTOLOGY_VERSION,
                "motif_version": MOTIF_VERSION,
                "graph_sha256": _digest(nodes, edges),
                "nodes": nodes,
                "edges": edges,
                "shadow": {} if shadow is None else shadow,
            }
        )
        if tuple(candidate.shadow) == tuple(sorted(candidate.shadow)):
            return candidate
        payload = candidate.model_dump(mode="python", round_trip=True, warnings=False)
        payload["shadow"] = _sorted_attributes(candidate.shadow)
        return PromptTSGRecord.model_validate(payload)
    except Exception:
        return None


def multidigraph_to_record(
    graph: nx.MultiDiGraph,
    *,
    prompt_id: str,
    shadow: Mapping[str, TSGScalar] | None = None,
) -> PromptTSGRecord:
    """Snapshot and canonicalize an internally built ``MultiDiGraph`` record."""
    result = _try_multidigraph_to_record(graph, prompt_id, shadow)
    if result is None:
        graph = cast(nx.MultiDiGraph, None)
        prompt_id = cast(str, None)
        shadow = None
        raise _invalid_error() from None
    return result


def _try_record_to_multidigraph(record: object) -> nx.MultiDiGraph | None:
    try:
        validated = PromptTSGRecord.model_validate(record)
        if (
            validated.ontology_version != ONTOLOGY_VERSION
            or validated.motif_version != MOTIF_VERSION
            or validated.graph_id != f"prompt:{validated.prompt_id}"
            or validated.graph_sha256 != _digest(validated.nodes, validated.edges)
        ):
            raise ValueError

        graph = nx.MultiDiGraph()
        for node in validated.nodes:
            graph.add_node(
                node.node_id,
                node_type=node.node_type,
                label=node.label,
                attributes=dict(node.attributes.items()),
            )
        for edge in validated.edges:
            graph.add_edge(
                edge.src,
                edge.dst,
                key=edge.edge_id,
                edge_type=edge.edge_type,
                attributes=dict(edge.attributes.items()),
            )
        rebuilt_nodes, rebuilt_edges = _canonicalize_graph(graph)
        if validated.graph_sha256 != _digest(rebuilt_nodes, rebuilt_edges):
            raise ValueError
        return graph
    except Exception:
        return None


def record_to_multidigraph(record: object) -> nx.MultiDiGraph:
    """Revalidate a strict prompt record and reconstruct its canonical graph."""
    result = _try_record_to_multidigraph(record)
    if result is None:
        record = None
        raise _invalid_error() from None
    return result


__all__ = [
    "MOTIF_VERSION",
    "ONTOLOGY_VERSION",
    "canonical_edge_id",
    "canonical_node_id",
    "graph_sha256",
    "multidigraph_to_record",
    "record_to_multidigraph",
]

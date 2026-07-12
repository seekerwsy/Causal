"""Canonical NetworkX boundary for prompt-side task semantic graphs."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
import hashlib
from itertools import islice
import json
import re
from typing import TypeVar, cast

import networkx as nx
from pydantic import BaseModel, ValidationError

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
from secaware.tsg.catalog import MOTIF_VERSION, ONTOLOGY_VERSION

_BUILDER_NODE_FIELDS = frozenset({"node_type", "label", "attributes"})
_COMMITTED_NODE_FIELDS = _BUILDER_NODE_FIELDS | {"semantic_key_sha256"}
_EDGE_FIELDS = frozenset({"edge_type", "attributes"})
_NODE_ID_RE = re.compile(r"^n_[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_SIGNED_64_BIT = 2**63 - 1
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _InvalidInput(Exception):
    pass


class _FailureKind(Enum):
    INVALID_INPUT = "invalid_input"
    INTERNAL = "internal"


def _invalid_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "tsg.codec",
        "prompt TSG graph codec validation failed",
    )


def _internal_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "tsg.codec",
        "internal prompt TSG graph codec failure",
    )


def _raise_failure(failure: _FailureKind) -> None:
    if failure is _FailureKind.INVALID_INPUT:
        raise _invalid_error() from None
    raise _internal_error() from None


def _validate_model(model_type: type[_ModelT], value: object) -> _ModelT:
    try:
        return model_type.model_validate(value)
    except ValidationError:
        raise _InvalidInput from None


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
    if type(value) is not str or not value or not value.strip() or value != value.strip():
        raise _InvalidInput from None
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise _InvalidInput from None
    if len(encoded) > MAX_TSG_STRING_BYTES:
        raise _InvalidInput from None
    return value


def _graph_id(prompt_id: str) -> str:
    prompt_id = _require_text(prompt_id)
    return "prompt_sha256:" + _sha256_hex(_canonical_json({"prompt_id": prompt_id}))


def _parse_node_type(value: object) -> NodeType:
    if type(value) is NodeType:
        return cast(NodeType, value)
    if type(value) is str:
        try:
            return NodeType(value)
        except ValueError:
            raise _InvalidInput from None
    raise _InvalidInput from None


def _parse_edge_type(value: object) -> EdgeType:
    if type(value) is EdgeType:
        return cast(EdgeType, value)
    if type(value) is str:
        try:
            return EdgeType(value)
        except ValueError:
            raise _InvalidInput from None
    raise _InvalidInput from None


def _semantic_key_commitment(semantic_key: str) -> str:
    semantic_key = _require_text(semantic_key)
    return _sha256_hex(_canonical_json({"semantic_key": semantic_key}))


def _node_id_from_commitment(
    node_type: NodeType,
    label: str,
    semantic_key_sha256: str,
) -> str:
    if type(semantic_key_sha256) is not str or _SHA256_RE.fullmatch(semantic_key_sha256) is None:
        raise _InvalidInput from None
    _validate_model(
        TSGNode,
        {
            "node_id": "n_" + "0" * 64,
            "semantic_key_sha256": semantic_key_sha256,
            "node_type": node_type,
            "label": label,
            "attributes": {},
        },
    )
    identity = {
        "label": label,
        "node_type": node_type.value,
        "semantic_key_sha256": semantic_key_sha256,
    }
    return "n_" + _sha256_hex(_canonical_json(identity))


def _node_id(node_type: NodeType, label: str, semantic_key: str) -> str:
    return _node_id_from_commitment(
        node_type,
        label,
        _semantic_key_commitment(semantic_key),
    )


def _edge_id(
    src: str,
    dst: str,
    edge_type: EdgeType,
    attributes: Mapping[str, TSGScalar],
    ordinal: int,
) -> str:
    if type(ordinal) is not int or not 0 <= ordinal <= _MAX_SIGNED_64_BIT:
        raise _InvalidInput from None
    validated = _validate_model(
        TSGEdge,
        {
            "edge_id": "e_" + "0" * 64,
            "src": src,
            "dst": dst,
            "edge_type": edge_type,
            "attributes": attributes,
        },
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
    except _InvalidInput:
        result = _FailureKind.INVALID_INPUT
    except Exception:
        result = _FailureKind.INTERNAL
    if isinstance(result, _FailureKind):
        node_type = cast(NodeType, None)
        label = cast(str, None)
        semantic_key = cast(str, None)
        _raise_failure(result)
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
    except _InvalidInput:
        result = _FailureKind.INVALID_INPUT
    except Exception:
        result = _FailureKind.INTERNAL
    if isinstance(result, _FailureKind):
        src = cast(str, None)
        dst = cast(str, None)
        edge_type = cast(EdgeType, None)
        attributes = cast(Mapping[str, TSGScalar], None)
        ordinal = cast(int, None)
        _raise_failure(result)
    return result


def _canonical_node_key(
    builder_key: object,
    node_type: NodeType,
    label: str,
) -> tuple[str, str]:
    semantic_key = _require_text(builder_key)
    semantic_key_sha256 = _semantic_key_commitment(semantic_key)
    return (
        _node_id_from_commitment(node_type, label, semantic_key_sha256),
        semantic_key_sha256,
    )


def _verified_node_key(
    builder_key: object,
    node_type: NodeType,
    label: str,
    semantic_key_sha256: object,
) -> tuple[str, str]:
    semantic_key = _require_text(builder_key)
    if type(semantic_key_sha256) is not str:
        raise _InvalidInput from None
    node_id = _node_id_from_commitment(node_type, label, semantic_key_sha256)
    if _NODE_ID_RE.fullmatch(semantic_key) is not None:
        if semantic_key != node_id:
            raise _InvalidInput from None
    elif semantic_key_sha256 != _semantic_key_commitment(semantic_key):
        raise _InvalidInput from None
    return node_id, semantic_key_sha256


def _sorted_attributes(attributes: Mapping[str, TSGScalar]) -> dict[str, TSGScalar]:
    return {key: attributes[key] for key in sorted(attributes)}


def _canonicalize_graph(graph: nx.MultiDiGraph) -> tuple[tuple[TSGNode, ...], tuple[TSGEdge, ...]]:
    if type(graph) is not nx.MultiDiGraph:
        raise _InvalidInput from None
    try:
        node_count = graph.number_of_nodes()
        edge_count = graph.number_of_edges()
    except (nx.NetworkXError, KeyError, TypeError, ValueError, UnicodeError):
        raise _InvalidInput from None
    if (
        type(node_count) is not int
        or type(edge_count) is not int
        or not 0 <= node_count <= MAX_TSG_NODES
        or not 0 <= edge_count <= MAX_TSG_EDGES
    ):
        raise _InvalidInput from None

    try:
        graph_attributes = graph.graph
        node_view = graph.nodes(data=True)
        node_iterator = iter(node_view)
    except (nx.NetworkXError, KeyError, TypeError, ValueError, UnicodeError):
        raise _InvalidInput from None
    raw_nodes = tuple(islice(node_iterator, MAX_TSG_NODES + 1))
    if (
        type(graph_attributes) is not dict
        or graph_attributes
        or len(raw_nodes) != node_count
        or len(raw_nodes) > MAX_TSG_NODES
        or any(type(item) is not tuple or len(item) != 2 for item in raw_nodes)
    ):
        raise _InvalidInput from None

    try:
        edge_view = graph.edges(keys=True, data=True)
        edge_iterator = iter(edge_view)
    except (nx.NetworkXError, KeyError, TypeError, ValueError, UnicodeError):
        raise _InvalidInput from None
    raw_edges = tuple(islice(edge_iterator, MAX_TSG_EDGES + 1))
    if (
        len(raw_edges) != edge_count
        or len(raw_edges) > MAX_TSG_EDGES
        or any(type(item) is not tuple or len(item) != 4 for item in raw_edges)
    ):
        raise _InvalidInput from None

    try:
        final_node_count = graph.number_of_nodes()
        final_edge_count = graph.number_of_edges()
    except (nx.NetworkXError, KeyError, TypeError, ValueError, UnicodeError):
        raise _InvalidInput from None
    if final_node_count != node_count or final_edge_count != edge_count:
        raise _InvalidInput from None

    nodes_by_id: dict[str, TSGNode] = {}
    identities_by_id: dict[str, tuple[str, str, str]] = {}
    builder_to_canonical: dict[object, str] = {}
    for builder_key, raw in raw_nodes:
        if type(raw) is not dict or frozenset(raw) not in {
            _BUILDER_NODE_FIELDS,
            _COMMITTED_NODE_FIELDS,
        }:
            raise _InvalidInput from None
        node_type = _parse_node_type(raw["node_type"])
        label = raw["label"]
        attributes = raw["attributes"]
        if "semantic_key_sha256" in raw:
            node_id, semantic_key_sha256 = _verified_node_key(
                builder_key,
                node_type,
                label,
                raw["semantic_key_sha256"],
            )
        else:
            node_id, semantic_key_sha256 = _canonical_node_key(builder_key, node_type, label)
        validated_node = _validate_model(
            TSGNode,
            {
                "node_id": node_id,
                "semantic_key_sha256": semantic_key_sha256,
                "node_type": node_type,
                "label": label,
                "attributes": attributes,
            },
        )
        node = _validate_model(
            TSGNode,
            {
                "node_id": validated_node.node_id,
                "semantic_key_sha256": validated_node.semantic_key_sha256,
                "node_type": validated_node.node_type,
                "label": validated_node.label,
                "attributes": _sorted_attributes(validated_node.attributes),
            },
        )
        identity = (node.node_type.value, node.label, node.semantic_key_sha256)
        if node_id in identities_by_id:
            raise _InvalidInput from None
        identities_by_id[node_id] = identity
        nodes_by_id[node_id] = node
        builder_to_canonical[builder_key] = node_id

    pending_by_endpoints: dict[tuple[str, str], list[tuple[EdgeType, dict[str, TSGScalar]]]] = {}
    for src, dst, _builder_key, raw in raw_edges:
        if type(raw) is not dict or raw.keys() != _EDGE_FIELDS:
            raise _InvalidInput from None
        if src not in builder_to_canonical or dst not in builder_to_canonical:
            raise _InvalidInput from None
        canonical_src = builder_to_canonical[src]
        canonical_dst = builder_to_canonical[dst]
        edge_type = _parse_edge_type(raw["edge_type"])
        validated = _validate_model(
            TSGEdge,
            {
                "edge_id": "e_" + "0" * 64,
                "src": canonical_src,
                "dst": canonical_dst,
                "edge_type": edge_type,
                "attributes": raw["attributes"],
            },
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
                raise _InvalidInput from None
            identities_by_edge_id[edge_id] = identity
            edges_by_id[edge_id] = _validate_model(
                TSGEdge,
                {
                    "edge_id": edge_id,
                    "src": src,
                    "dst": dst,
                    "edge_type": edge_type,
                    "attributes": attributes,
                },
            )

    return (
        tuple(nodes_by_id[node_id] for node_id in sorted(nodes_by_id)),
        tuple(edges_by_id[edge_id] for edge_id in sorted(edges_by_id)),
    )


def _canonical_query_graph(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Validate and copy an already committed canonical graph snapshot."""
    nodes, edges = _canonicalize_graph(graph)
    raw_node_ids = tuple(graph.nodes)
    raw_edges = tuple(graph.edges(keys=True))
    if set(raw_node_ids) != {node.node_id for node in nodes}:
        raise _InvalidInput from None
    if set(raw_edges) != {(edge.src, edge.dst, edge.edge_id) for edge in edges}:
        raise _InvalidInput from None

    copied = nx.MultiDiGraph()
    for node in nodes:
        try:
            raw = graph.nodes[node.node_id]
        except (nx.NetworkXError, KeyError, TypeError, ValueError, UnicodeError):
            raise _InvalidInput from None
        if (
            type(raw) is not dict
            or frozenset(raw) != _COMMITTED_NODE_FIELDS
            or type(raw["node_type"]) is not NodeType
            or raw["node_type"] is not node.node_type
            or type(raw["label"]) is not str
            or raw["label"] != node.label
            or type(raw["semantic_key_sha256"]) is not str
            or raw["semantic_key_sha256"] != node.semantic_key_sha256
            or type(raw["attributes"]) is not dict
            or raw["attributes"] != dict(node.attributes.items())
        ):
            raise _InvalidInput from None
        copied.add_node(
            node.node_id,
            semantic_key_sha256=node.semantic_key_sha256,
            node_type=node.node_type,
            label=node.label,
            attributes=dict(node.attributes.items()),
        )

    for edge in edges:
        try:
            raw = graph.edges[edge.src, edge.dst, edge.edge_id]
        except (nx.NetworkXError, KeyError, TypeError, ValueError, UnicodeError):
            raise _InvalidInput from None
        if (
            type(raw) is not dict
            or frozenset(raw) != _EDGE_FIELDS
            or type(raw["edge_type"]) is not EdgeType
            or raw["edge_type"] is not edge.edge_type
            or type(raw["attributes"]) is not dict
            or raw["attributes"] != dict(edge.attributes.items())
        ):
            raise _InvalidInput from None
        copied.add_edge(
            edge.src,
            edge.dst,
            key=edge.edge_id,
            edge_type=edge.edge_type,
            attributes=dict(edge.attributes.items()),
        )
    return copied


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
                node.semantic_key_sha256,
                node.node_type.value,
                node.label,
                dict(node.attributes.items()),
            ]
            for node in nodes
        ],
        "ontology_version": ONTOLOGY_VERSION,
    }
    return _sha256_hex(_canonical_json(payload))


def _graph_from_models(
    nodes: tuple[TSGNode, ...],
    edges: tuple[TSGEdge, ...],
) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for node in nodes:
        graph.add_node(
            node.node_id,
            semantic_key_sha256=node.semantic_key_sha256,
            node_type=node.node_type,
            label=node.label,
            attributes=dict(node.attributes.items()),
        )
    for edge in edges:
        graph.add_edge(
            edge.src,
            edge.dst,
            key=edge.edge_id,
            edge_type=edge.edge_type,
            attributes=dict(edge.attributes.items()),
        )
    return graph


def _derive_shadow(graph: nx.MultiDiGraph) -> dict[str, TSGScalar]:
    from secaware.schema.hypotheses import FactorType
    from secaware.schema.tsg import MotifId
    from secaware.tsg.features import derive_shadow

    try:
        derived = derive_shadow(graph)
    except SecAwareError as error:
        if error.code is ErrorCode.TSG_INVALID:
            raise _InvalidInput from None
        raise RuntimeError from None
    expected_boolean_keys = {
        *(f"factor.{factor.value}_required" for factor in FactorType),
        *(f"motif.{motif.value}" for motif in MotifId),
    }
    expected_keys = expected_boolean_keys | {"graph.node_count", "graph.edge_count"}
    if (
        type(derived) is not dict
        or set(derived) != expected_keys
        or tuple(derived) != tuple(sorted(derived))
        or any(type(derived[key]) is not bool for key in expected_boolean_keys)
        or type(derived["graph.node_count"]) is not int
        or type(derived["graph.edge_count"]) is not int
        or derived["graph.node_count"] != graph.number_of_nodes()
        or derived["graph.edge_count"] != graph.number_of_edges()
    ):
        raise RuntimeError from None
    return dict(derived)


def _try_graph_sha256(graph: nx.MultiDiGraph) -> str | _FailureKind:
    try:
        nodes, edges = _canonicalize_graph(graph)
        return _digest(nodes, edges)
    except _InvalidInput:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def graph_sha256(graph: nx.MultiDiGraph) -> str:
    """Hash the canonical graph structure and fixed catalog versions."""
    result = _try_graph_sha256(graph)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        _raise_failure(result)
    return result


def _try_multidigraph_to_record(
    graph: nx.MultiDiGraph,
    prompt_id: str,
) -> PromptTSGRecord | _FailureKind:
    try:
        prompt_id = _require_text(prompt_id)
        nodes, edges = _canonicalize_graph(graph)
        canonical_graph = _graph_from_models(nodes, edges)
        candidate = _validate_model(
            PromptTSGRecord,
            {
                "schema_version": TSG_SCHEMA_VERSION,
                "graph_id": _graph_id(prompt_id),
                "source_type": "prompt",
                "prompt_id": prompt_id,
                "ontology_version": ONTOLOGY_VERSION,
                "motif_version": MOTIF_VERSION,
                "graph_sha256": _digest(nodes, edges),
                "nodes": nodes,
                "edges": edges,
                "shadow": _derive_shadow(canonical_graph),
            },
        )
        return candidate
    except _InvalidInput:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def multidigraph_to_record(
    graph: nx.MultiDiGraph,
    *,
    prompt_id: str,
) -> PromptTSGRecord:
    """Snapshot and canonicalize an internally built ``MultiDiGraph`` record."""
    result = _try_multidigraph_to_record(graph, prompt_id)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        prompt_id = cast(str, None)
        _raise_failure(result)
    return result


def _try_record_to_multidigraph(record: object) -> nx.MultiDiGraph | _FailureKind:
    try:
        validated = _validate_model(PromptTSGRecord, record)
        if (
            validated.ontology_version != ONTOLOGY_VERSION
            or validated.motif_version != MOTIF_VERSION
            or validated.graph_id != _graph_id(validated.prompt_id)
            or validated.graph_sha256 != _digest(validated.nodes, validated.edges)
        ):
            raise _InvalidInput from None

        for node in validated.nodes:
            if node.node_id != _node_id_from_commitment(
                node.node_type,
                node.label,
                node.semantic_key_sha256,
            ):
                raise _InvalidInput from None
        graph = _graph_from_models(validated.nodes, validated.edges)
        rebuilt_nodes, rebuilt_edges = _canonicalize_graph(graph)
        if validated.graph_sha256 != _digest(rebuilt_nodes, rebuilt_edges):
            raise _InvalidInput from None
        expected_shadow = _derive_shadow(graph)
        if _canonical_json(dict(validated.shadow.items())) != _canonical_json(expected_shadow):
            raise _InvalidInput from None
        return graph
    except _InvalidInput:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def record_to_multidigraph(record: object) -> nx.MultiDiGraph:
    """Revalidate a strict prompt record and reconstruct its canonical graph."""
    result = _try_record_to_multidigraph(record)
    if isinstance(result, _FailureKind):
        record = None
        _raise_failure(result)
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

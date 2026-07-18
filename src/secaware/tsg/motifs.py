"""Finite, bounded structural queries over canonical prompt TSG snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import cast

import networkx as nx

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.features import FeatureFamily
from secaware.schema.tsg import (
    EdgeType,
    MAX_MOTIF_HOPS,
    MAX_MOTIF_MATCHES,
    MAX_TSG_EDGES,
    MotifId,
    MotifMatch,
    NodeType,
)
from secaware.tsg.catalog import PROMPT_TSG_CATALOG, prompt_ontology_entry
from secaware.tsg.feature_catalog import prompt_feature_spec
from secaware.tsg.graph import _InvalidInput as _GraphInvalidInput
from secaware.tsg.graph import _canonical_query_graph


@dataclass(frozen=True, slots=True)
class MotifSpec:
    motif_id: MotifId
    task_feature_id: str
    target_feature_id: str
    source_types: tuple[NodeType, ...]
    data_label: str
    sink_label: str
    requirement_label: str
    guard_label: str
    first_edge_type: EdgeType
    traversable_edge_types: tuple[EdgeType, ...]
    max_hops: int


_MOTIF_BY_TARGET_FEATURE = {
    "safety.input_validation": MotifId.UNTRUSTED_SOURCE_TO_SENSITIVE_SINK_WITHOUT_GUARD,
    "safety.path_normalization": MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
    "safety.sql_parameterization": MotifId.USER_STRING_TO_SQL_WITHOUT_PARAMETERIZATION,
    "safety.safe_subprocess": MotifId.USER_INPUT_TO_SHELL_WITHOUT_GUARD,
    "safety.authorization_check": MotifId.SENSITIVE_OPERATION_WITHOUT_AUTH_GUARD,
    "safety.safe_deserialization": MotifId.UNTRUSTED_DATA_TO_DESERIALIZATION_SINK,
}


def _build_specs() -> MappingProxyType[MotifId, MotifSpec]:
    entry_by_target = {entry.target_feature_id: entry for entry in PROMPT_TSG_CATALOG}
    by_motif = {
        motif_id: entry_by_target[target_feature_id]
        for target_feature_id, motif_id in _MOTIF_BY_TARGET_FEATURE.items()
    }
    specs: dict[MotifId, MotifSpec] = {}
    for motif_id in MotifId:
        entry = by_motif[motif_id]
        specs[motif_id] = MotifSpec(
            motif_id=motif_id,
            task_feature_id=entry.task_feature_id,
            target_feature_id=entry.target_feature_id,
            source_types=(NodeType.SOURCE,),
            data_label=entry.data_label,
            sink_label=entry.sink_label,
            requirement_label=entry.requirement_label,
            guard_label=entry.guard_label,
            first_edge_type=EdgeType.SOURCE_OF,
            traversable_edge_types=(EdgeType.FLOWS_TO,),
            max_hops=MAX_MOTIF_HOPS,
        )
    if (
        tuple(specs) != tuple(MotifId)
        or len(specs) != 6
        or {spec.target_feature_id for spec in specs.values()}
        != {entry.target_feature_id for entry in PROMPT_TSG_CATALOG}
        or {spec.task_feature_id for spec in specs.values()}
        != {entry.task_feature_id for entry in PROMPT_TSG_CATALOG}
        or {spec.motif_id for spec in specs.values()} != set(MotifId)
        or any(
            prompt_feature_spec(spec.task_feature_id).feature_family
            is not FeatureFamily.TASK_FUNCTION
            or prompt_feature_spec(spec.target_feature_id).feature_family
            is not FeatureFamily.SAFETY_CONTROL
            for spec in specs.values()
        )
    ):
        raise RuntimeError("invalid finite prompt motif catalog")
    return MappingProxyType(specs)


MOTIF_SPECS = _build_specs()

_ShadowQueryInputs = tuple[
    tuple[tuple[str, bool], ...],
    tuple[tuple[MotifId, bool], ...],
    int,
    int,
]
# At most one bounded allowance per canonical edge at each possible hop layer.
_MAX_TRAVERSAL_STATES = MAX_TSG_EDGES * (MAX_MOTIF_HOPS + 1)


class _InvalidQuery(Exception):
    pass


class _FailureKind(Enum):
    INVALID_INPUT = "invalid_input"
    INTERNAL = "internal"


def _invalid_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "tsg.motifs",
        "prompt TSG motif query validation failed",
    )


def _internal_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "tsg.motifs",
        "internal prompt TSG motif query failure",
    )


def _raise_failure(failure: _FailureKind) -> None:
    if failure is _FailureKind.INVALID_INPUT:
        raise _invalid_error() from None
    raise _internal_error() from None


def _snapshot_graph(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    try:
        return _canonical_query_graph(graph)
    except _GraphInvalidInput:
        raise _InvalidQuery from None


def _validate_bounds(max_hops: object, max_matches: object) -> tuple[int, int]:
    if (
        type(max_hops) is not int
        or not 1 <= max_hops <= MAX_MOTIF_HOPS
        or type(max_matches) is not int
        or not 1 <= max_matches <= MAX_MOTIF_MATCHES
    ):
        raise _InvalidQuery from None
    return max_hops, max_matches


def _iter_sorted_out_edges(graph: nx.MultiDiGraph, node_id: str):
    edges = tuple(graph.out_edges(node_id, keys=True, data=True))
    return iter(sorted(edges, key=lambda item: (item[1], item[2])))


def _is_required_guard(
    graph: nx.MultiDiGraph,
    spec: MotifSpec,
    guard_node: str,
) -> bool:
    guard = graph.nodes[guard_node]
    if guard["node_type"] is not NodeType.GUARD or guard["label"] != spec.guard_label:
        return False
    for requirement_node, _, _, attributes in sorted(
        graph.in_edges(guard_node, keys=True, data=True),
        key=lambda item: (item[0], item[2]),
    ):
        requirement = graph.nodes[requirement_node]
        if (
            attributes["edge_type"] is EdgeType.REQUIRES
            and requirement["node_type"] is NodeType.PROMPT_REQUIREMENT
            and requirement["label"] == spec.requirement_label
        ):
            return True
    return False


def _is_same_flow_guarded(
    graph: nx.MultiDiGraph,
    spec: MotifSpec,
    node_path: tuple[str, ...],
) -> bool:
    if any(_is_required_guard(graph, spec, node_id) for node_id in node_path):
        return True
    for path_node in node_path:
        if graph.nodes[path_node]["node_type"] not in {NodeType.DATA_OBJECT, NodeType.SINK}:
            continue
        for _, guard_node, _, attributes in _iter_sorted_out_edges(graph, path_node):
            if attributes["edge_type"] is EdgeType.GUARDED_BY and _is_required_guard(
                graph, spec, guard_node
            ):
                return True
    return False


def _match(spec: MotifSpec, node_path: tuple[str, ...], edge_path: tuple[str, ...]) -> MotifMatch:
    return MotifMatch.model_validate(
        {
            "schema_version": "1.0",
            "motif_id": spec.motif_id,
            "node_path": node_path,
            "edge_path": edge_path,
            "guarded": False,
            "guard_nodes": (),
        }
    )


def _reverse_sink_distances(
    graph: nx.MultiDiGraph,
    spec: MotifSpec,
    hop_limit: int,
) -> dict[str, int]:
    sinks = {
        node_id
        for node_id, attributes in graph.nodes(data=True)
        if attributes["node_type"] is NodeType.SINK and attributes["label"] == spec.sink_label
    }
    distances = {node_id: 0 for node_id in sinks}
    frontier = sinks
    for distance in range(1, hop_limit):
        next_frontier: set[str] = set()
        for node_id in sorted(frontier):
            for predecessor, _, _, attributes in sorted(
                graph.in_edges(node_id, keys=True, data=True),
                key=lambda item: (item[0], item[2]),
            ):
                if attributes["edge_type"] is EdgeType.FLOWS_TO and predecessor not in distances:
                    distances[predecessor] = distance
                    next_frontier.add(predecessor)
        if not next_frontier:
            break
        frontier = next_frontier
    return distances


def _find_matches(
    graph: nx.MultiDiGraph,
    spec: MotifSpec,
    *,
    max_hops: int,
    max_matches: int,
) -> tuple[MotifMatch, ...]:
    hop_limit = min(max_hops, spec.max_hops)
    sink_distances = _reverse_sink_distances(graph, spec, hop_limit)
    if not sink_distances:
        return ()
    states = 0
    candidates = 0
    matches: list[MotifMatch] = []

    for source_id, source in sorted(graph.nodes(data=True), key=lambda item: item[0]):
        if source["node_type"] not in spec.source_types:
            continue
        for _, data_id, first_edge_id, first_edge in _iter_sorted_out_edges(graph, source_id):
            data = graph.nodes[data_id]
            if (
                first_edge["edge_type"] is not spec.first_edge_type
                or data["node_type"] is not NodeType.DATA_OBJECT
                or data["label"] != spec.data_label
                or sink_distances.get(data_id, hop_limit) > hop_limit - 1
            ):
                continue
            stack = [
                (
                    data_id,
                    (source_id, data_id),
                    (first_edge_id,),
                    frozenset((source_id, data_id)),
                )
            ]
            while stack:
                states += 1
                if states > _MAX_TRAVERSAL_STATES:
                    raise _InvalidQuery from None
                current, node_path, edge_path, visited = stack.pop()
                if len(edge_path) >= hop_limit:
                    continue
                next_states = []
                for _, dst, edge_id, edge in _iter_sorted_out_edges(graph, current):
                    if edge["edge_type"] not in spec.traversable_edge_types or dst in visited:
                        continue
                    next_node_path = (*node_path, dst)
                    next_edge_path = (*edge_path, edge_id)
                    target = graph.nodes[dst]
                    if target["node_type"] is NodeType.SINK and target["label"] == spec.sink_label:
                        candidates += 1
                        if candidates > max_matches:
                            raise _InvalidQuery from None
                        if not _is_same_flow_guarded(graph, spec, next_node_path):
                            matches.append(_match(spec, next_node_path, next_edge_path))
                        continue
                    remaining_hops = hop_limit - len(next_edge_path)
                    if sink_distances.get(dst, hop_limit) > remaining_hops:
                        continue
                    next_states.append(
                        (dst, next_node_path, next_edge_path, visited | frozenset((dst,)))
                    )
                stack.extend(reversed(next_states))
    return tuple(sorted(matches, key=lambda match: (match.node_path, match.edge_path)))


def _has_feature_requirement(graph: nx.MultiDiGraph, target_feature_id: str) -> bool:
    entry = prompt_ontology_entry(target_feature_id)
    for requirement_id, requirement in sorted(graph.nodes(data=True), key=lambda item: item[0]):
        if (
            requirement["node_type"] is not NodeType.PROMPT_REQUIREMENT
            or requirement["label"] != entry.requirement_label
        ):
            continue
        for _, guard_id, _, edge in _iter_sorted_out_edges(graph, requirement_id):
            guard = graph.nodes[guard_id]
            if (
                edge["edge_type"] is EdgeType.REQUIRES
                and guard["node_type"] is NodeType.GUARD
                and guard["label"] == entry.guard_label
            ):
                return True
    return False


def _try_find_motif_matches(
    graph: nx.MultiDiGraph,
    motif_id: MotifId,
    max_hops: object,
    max_matches: object,
) -> tuple[MotifMatch, ...] | _FailureKind:
    try:
        if type(motif_id) is not MotifId:
            raise _InvalidQuery from None
        validated_hops, validated_matches = _validate_bounds(max_hops, max_matches)
        snapshot = _snapshot_graph(graph)
        return _find_matches(
            snapshot,
            MOTIF_SPECS[motif_id],
            max_hops=validated_hops,
            max_matches=validated_matches,
        )
    except _InvalidQuery:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def find_motif_matches(
    graph: nx.MultiDiGraph,
    motif_id: MotifId,
    *,
    max_hops: int = MAX_MOTIF_HOPS,
    max_matches: int = MAX_MOTIF_MATCHES,
) -> tuple[MotifMatch, ...]:
    """Return deterministic unguarded matches for one finite structural motif."""
    result = _try_find_motif_matches(graph, motif_id, max_hops, max_matches)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        motif_id = cast(MotifId, None)
        max_hops = cast(int, None)
        max_matches = cast(int, None)
        _raise_failure(result)
    return result


def _try_has_feature_requirement(
    graph: nx.MultiDiGraph,
    target_feature_id: str,
) -> bool | _FailureKind:
    try:
        if (
            type(target_feature_id) is not str
            or prompt_feature_spec(target_feature_id).feature_family
            is not FeatureFamily.SAFETY_CONTROL
        ):
            raise _InvalidQuery from None
        return _has_feature_requirement(_snapshot_graph(graph), target_feature_id)
    except (_InvalidQuery, KeyError):
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def has_feature_requirement(graph: nx.MultiDiGraph, target_feature_id: str) -> bool:
    """Query one catalog-bound requirement-to-guard structure from the live graph."""
    result = _try_has_feature_requirement(graph, target_feature_id)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        target_feature_id = cast(str, None)
        _raise_failure(result)
    return result


def _try_feature_requirement_vector(
    graph: nx.MultiDiGraph,
) -> tuple[tuple[str, bool], ...] | _FailureKind:
    try:
        snapshot = _snapshot_graph(graph)
        return tuple(
            (
                entry.target_feature_id,
                _has_feature_requirement(snapshot, entry.target_feature_id),
            )
            for entry in PROMPT_TSG_CATALOG
        )
    except _InvalidQuery:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def feature_requirement_vector(graph: nx.MultiDiGraph) -> tuple[tuple[str, bool], ...]:
    """Return the complete structural requirement vector in catalog order."""
    result = _try_feature_requirement_vector(graph)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        _raise_failure(result)
    return result


def _try_motif_query_vector(
    graph: nx.MultiDiGraph,
) -> tuple[tuple[MotifId, bool], ...] | _FailureKind:
    try:
        snapshot = _snapshot_graph(graph)
        return tuple(
            (
                motif_id,
                bool(
                    _find_matches(
                        snapshot,
                        MOTIF_SPECS[motif_id],
                        max_hops=MAX_MOTIF_HOPS,
                        max_matches=MAX_MOTIF_MATCHES,
                    )
                ),
            )
            for motif_id in MotifId
        )
    except _InvalidQuery:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def motif_query_vector(graph: nx.MultiDiGraph) -> tuple[tuple[MotifId, bool], ...]:
    """Return the complete finite motif-presence vector in enum order."""
    result = _try_motif_query_vector(graph)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        _raise_failure(result)
    return result


def _try_shadow_query_inputs(
    graph: nx.MultiDiGraph,
) -> _ShadowQueryInputs | _FailureKind:
    try:
        snapshot = _snapshot_graph(graph)
        features = tuple(
            (
                entry.target_feature_id,
                _has_feature_requirement(snapshot, entry.target_feature_id),
            )
            for entry in PROMPT_TSG_CATALOG
        )
        motifs = tuple(
            (
                motif_id,
                bool(
                    _find_matches(
                        snapshot,
                        MOTIF_SPECS[motif_id],
                        max_hops=MAX_MOTIF_HOPS,
                        max_matches=MAX_MOTIF_MATCHES,
                    )
                ),
            )
            for motif_id in MotifId
        )
        return features, motifs, snapshot.number_of_nodes(), snapshot.number_of_edges()
    except _InvalidQuery:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def _shadow_query_inputs(graph: nx.MultiDiGraph) -> _ShadowQueryInputs:
    """Snapshot once and return the complete inputs for the audit projection."""
    result = _try_shadow_query_inputs(graph)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        _raise_failure(result)
    return result


__all__ = [
    "MOTIF_SPECS",
    "MotifSpec",
    "feature_requirement_vector",
    "find_motif_matches",
    "has_feature_requirement",
    "motif_query_vector",
]

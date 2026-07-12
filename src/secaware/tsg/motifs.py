"""Finite, bounded structural queries over canonical prompt TSG snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import cast

import networkx as nx

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.hypotheses import FactorType
from secaware.schema.tsg import (
    EdgeType,
    MAX_MOTIF_HOPS,
    MAX_MOTIF_MATCHES,
    MotifId,
    MotifMatch,
    NodeType,
)
from secaware.tsg.catalog import PROMPT_TSG_CATALOG, prompt_ontology_entry
from secaware.tsg.graph import _InvalidInput as _GraphInvalidInput
from secaware.tsg.graph import _canonical_query_graph


@dataclass(frozen=True, slots=True)
class MotifSpec:
    motif_id: MotifId
    factor_type: FactorType
    source_types: tuple[NodeType, ...]
    data_label: str
    sink_label: str
    requirement_label: str
    guard_label: str
    first_edge_type: EdgeType
    traversable_edge_types: tuple[EdgeType, ...]
    max_hops: int


_MOTIF_BY_FACTOR = {
    FactorType.INPUT_VALIDATION: MotifId.UNTRUSTED_SOURCE_TO_SENSITIVE_SINK_WITHOUT_GUARD,
    FactorType.PATH_NORMALIZATION: MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
    FactorType.SQL_PARAMETERIZATION: MotifId.USER_STRING_TO_SQL_WITHOUT_PARAMETERIZATION,
    FactorType.SAFE_SUBPROCESS: MotifId.USER_INPUT_TO_SHELL_WITHOUT_GUARD,
    FactorType.AUTHORIZATION_CHECK: MotifId.SENSITIVE_OPERATION_WITHOUT_AUTH_GUARD,
    FactorType.SAFE_DESERIALIZATION: MotifId.UNTRUSTED_DATA_TO_DESERIALIZATION_SINK,
}


def _build_specs() -> MappingProxyType[MotifId, MotifSpec]:
    by_motif = {motif_id: factor_type for factor_type, motif_id in _MOTIF_BY_FACTOR.items()}
    specs: dict[MotifId, MotifSpec] = {}
    for motif_id in MotifId:
        factor_type = by_motif[motif_id]
        entry = prompt_ontology_entry(factor_type)
        specs[motif_id] = MotifSpec(
            motif_id=motif_id,
            factor_type=factor_type,
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
        or {spec.factor_type for spec in specs.values()} != set(FactorType)
        or {spec.motif_id for spec in specs.values()} != set(MotifId)
        or tuple(entry.factor_type for entry in PROMPT_TSG_CATALOG) != tuple(FactorType)
    ):
        raise RuntimeError("invalid finite prompt motif catalog")
    return MappingProxyType(specs)


MOTIF_SPECS = _build_specs()

_ShadowQueryInputs = tuple[
    tuple[tuple[FactorType, bool], ...],
    tuple[tuple[MotifId, bool], ...],
    int,
    int,
]


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


def _is_same_flow_guarded(
    graph: nx.MultiDiGraph,
    spec: MotifSpec,
    data_node: str,
    sink_node: str,
) -> bool:
    data_guards = {
        dst
        for _, dst, _, attributes in _iter_sorted_out_edges(graph, data_node)
        if attributes["edge_type"] is EdgeType.GUARDED_BY
    }
    sink_guards = {
        dst
        for _, dst, _, attributes in _iter_sorted_out_edges(graph, sink_node)
        if attributes["edge_type"] is EdgeType.GUARDED_BY
    }
    for guard_node in sorted(data_guards & sink_guards):
        guard = graph.nodes[guard_node]
        if guard["node_type"] is not NodeType.GUARD or guard["label"] != spec.guard_label:
            continue
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


def _find_matches(
    graph: nx.MultiDiGraph,
    spec: MotifSpec,
    *,
    max_hops: int,
    max_matches: int,
) -> tuple[MotifMatch, ...]:
    hop_limit = min(max_hops, spec.max_hops)
    state_limit = max_matches * (max_hops + 1)
    states = 0
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
                if states > state_limit:
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
                        if not _is_same_flow_guarded(graph, spec, data_id, dst):
                            matches.append(_match(spec, next_node_path, next_edge_path))
                            if len(matches) > max_matches:
                                raise _InvalidQuery from None
                        continue
                    next_states.append(
                        (dst, next_node_path, next_edge_path, visited | frozenset((dst,)))
                    )
                stack.extend(reversed(next_states))
    return tuple(sorted(matches, key=lambda match: (match.node_path, match.edge_path)))


def _has_factor_requirement(graph: nx.MultiDiGraph, factor_type: FactorType) -> bool:
    entry = prompt_ontology_entry(factor_type)
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


def _try_has_factor_requirement(
    graph: nx.MultiDiGraph,
    factor_type: FactorType,
) -> bool | _FailureKind:
    try:
        if type(factor_type) is not FactorType:
            raise _InvalidQuery from None
        return _has_factor_requirement(_snapshot_graph(graph), factor_type)
    except _InvalidQuery:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def has_factor_requirement(graph: nx.MultiDiGraph, factor_type: FactorType) -> bool:
    """Query an exact typed requirement-to-guard structure from the live graph."""
    result = _try_has_factor_requirement(graph, factor_type)
    if isinstance(result, _FailureKind):
        graph = cast(nx.MultiDiGraph, None)
        factor_type = cast(FactorType, None)
        _raise_failure(result)
    return result


def _try_factor_query_vector(
    graph: nx.MultiDiGraph,
) -> tuple[tuple[FactorType, bool], ...] | _FailureKind:
    try:
        snapshot = _snapshot_graph(graph)
        return tuple((factor, _has_factor_requirement(snapshot, factor)) for factor in FactorType)
    except _InvalidQuery:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def factor_query_vector(graph: nx.MultiDiGraph) -> tuple[tuple[FactorType, bool], ...]:
    """Return the complete factor-requirement vector in enum order."""
    result = _try_factor_query_vector(graph)
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
        factors = tuple(
            (factor, _has_factor_requirement(snapshot, factor)) for factor in FactorType
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
        return factors, motifs, snapshot.number_of_nodes(), snapshot.number_of_edges()
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
    "factor_query_vector",
    "find_motif_matches",
    "has_factor_requirement",
    "motif_query_vector",
]

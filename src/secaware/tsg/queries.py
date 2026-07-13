"""Graph-authoritative queries for finite prompt feature states."""

from __future__ import annotations

from typing import cast

import networkx as nx

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.features import FeatureFamily, FeatureState
from secaware.schema.tsg import NodeType
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG, prompt_feature_spec
from secaware.tsg.graph import _canonical_query_graph


def _query_contract_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "tsg.feature_query",
        "prompt feature query validation failed",
    )


def _closed_state_nodes(graph: nx.MultiDiGraph) -> dict[str, dict[str, object]]:
    try:
        snapshot = _canonical_query_graph(graph)
        expected = {item.feature_id for item in PROMPT_FEATURE_CATALOG}
        found: dict[str, dict[str, object]] = {}
        for _, node in snapshot.nodes(data=True):
            if node["node_type"] not in {NodeType.FEATURE, NodeType.PRESENTATION_FEATURE}:
                continue
            attributes = node["attributes"]
            feature_id = attributes["feature_id"]
            if type(feature_id) is not str or feature_id in found:
                raise ValueError
            spec = prompt_feature_spec(feature_id)
            expected_type = (
                NodeType.PRESENTATION_FEATURE
                if spec.feature_family is FeatureFamily.PRESENTATION_CONTROL
                else NodeType.FEATURE
            )
            if (
                node["node_type"] is not expected_type
                or node["label"] != feature_id
                or attributes["feature_family"] != spec.feature_family.value
            ):
                raise ValueError
            FeatureState(cast(str, attributes["feature_state"]))
            found[feature_id] = node
        if set(found) != expected:
            raise ValueError
        return found
    except Exception:
        raise _query_contract_error() from None


def feature_state_nodes(
    graph: nx.MultiDiGraph,
    feature_id: str,
) -> tuple[dict[str, object], ...]:
    """Return the single catalog-bound live state node for a feature."""
    try:
        prompt_feature_spec(feature_id)
        return (_closed_state_nodes(graph)[feature_id],)
    except Exception:
        raise _query_contract_error() from None


def feature_state(graph: nx.MultiDiGraph, feature_id: str) -> FeatureState:
    """Return one feature state from the validated live graph."""
    nodes = feature_state_nodes(graph, feature_id)
    if len(nodes) != 1:  # pragma: no cover - closed helper guarantees this
        raise _query_contract_error() from None
    try:
        attributes = cast(dict[str, object], nodes[0]["attributes"])
        return FeatureState(cast(str, attributes["feature_state"]))
    except Exception:
        raise _query_contract_error() from None


def feature_state_vector(
    graph: nx.MultiDiGraph,
) -> tuple[tuple[str, FeatureState], ...]:
    """Return the complete catalog-order state projection from the live graph."""
    nodes = _closed_state_nodes(graph)
    try:
        return tuple(
            (
                spec.feature_id,
                FeatureState(cast(str, nodes[spec.feature_id]["attributes"]["feature_state"])),
            )
            for spec in PROMPT_FEATURE_CATALOG
        )
    except Exception:
        raise _query_contract_error() from None


def feature_states_by_family(
    graph: nx.MultiDiGraph,
    family: FeatureFamily,
) -> tuple[tuple[str, FeatureState], ...]:
    """Return a finite family projection without reading record shadow fields."""
    if type(family) is not FeatureFamily:
        raise _query_contract_error() from None
    return tuple(
        (feature_id, state)
        for feature_id, state in feature_state_vector(graph)
        if prompt_feature_spec(feature_id).feature_family is family
    )


__all__ = [
    "feature_state",
    "feature_state_nodes",
    "feature_state_vector",
    "feature_states_by_family",
]

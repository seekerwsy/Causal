"""Deterministic graph-derived audit projection for prompt TSG records."""

from __future__ import annotations

import networkx as nx

from secaware.tsg.motifs import _shadow_query_inputs


FACTOR_FEATURE_PREFIX = "factor."
MOTIF_FEATURE_PREFIX = "motif."


def derive_shadow(graph: nx.MultiDiGraph) -> dict[str, bool | int]:
    """Derive the complete finite shadow projection from live graph structure."""
    factors, motifs, node_count, edge_count = _shadow_query_inputs(graph)
    projection: dict[str, bool | int] = {
        f"{FACTOR_FEATURE_PREFIX}{factor.value}_required": required for factor, required in factors
    }
    projection.update(
        {f"{MOTIF_FEATURE_PREFIX}{motif.value}": present for motif, present in motifs}
    )
    projection["graph.node_count"] = node_count
    projection["graph.edge_count"] = edge_count
    return {key: projection[key] for key in sorted(projection)}


__all__ = ["FACTOR_FEATURE_PREFIX", "MOTIF_FEATURE_PREFIX", "derive_shadow"]

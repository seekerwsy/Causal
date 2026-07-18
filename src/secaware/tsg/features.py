"""Deterministic graph-derived audit projection for prompt TSG records."""

from __future__ import annotations

import networkx as nx

from secaware.tsg.motifs import _shadow_query_inputs


FEATURE_REQUIREMENT_PREFIX = "feature."
MOTIF_FEATURE_PREFIX = "motif."


def derive_shadow(graph: nx.MultiDiGraph) -> dict[str, bool | int]:
    """Derive the complete finite shadow projection from live graph structure."""
    features, motifs, node_count, edge_count = _shadow_query_inputs(graph)
    projection: dict[str, bool | int] = {
        f"{FEATURE_REQUIREMENT_PREFIX}{feature_id}.required": required
        for feature_id, required in features
    }
    projection.update(
        {f"{MOTIF_FEATURE_PREFIX}{motif.value}": present for motif, present in motifs}
    )
    projection["graph.node_count"] = node_count
    projection["graph.edge_count"] = edge_count
    return {key: projection[key] for key in sorted(projection)}


__all__ = ["FEATURE_REQUIREMENT_PREFIX", "MOTIF_FEATURE_PREFIX", "derive_shadow"]

"""Lazy public namespace for prompt task-semantic-graph helpers."""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS = {
    "MOTIF_VERSION": ("secaware.tsg.catalog", "MOTIF_VERSION"),
    "ONTOLOGY_VERSION": ("secaware.tsg.catalog", "ONTOLOGY_VERSION"),
    "PROMPT_TSG_CATALOG": ("secaware.tsg.catalog", "PROMPT_TSG_CATALOG"),
    "PROMPT_TSG_CATALOG_SHA256": ("secaware.tsg.catalog", "PROMPT_TSG_CATALOG_SHA256"),
    "PromptOntologyEntry": ("secaware.tsg.catalog", "PromptOntologyEntry"),
    "MOTIF_SPECS": ("secaware.tsg.motifs", "MOTIF_SPECS"),
    "MotifSpec": ("secaware.tsg.motifs", "MotifSpec"),
    "canonical_edge_id": ("secaware.tsg.graph", "canonical_edge_id"),
    "canonical_node_id": ("secaware.tsg.graph", "canonical_node_id"),
    "build_prompt_tsg": ("secaware.tsg.builder", "build_prompt_tsg"),
    "derive_shadow": ("secaware.tsg.features", "derive_shadow"),
    "feature_requirement_vector": ("secaware.tsg.motifs", "feature_requirement_vector"),
    "find_motif_matches": ("secaware.tsg.motifs", "find_motif_matches"),
    "feature_state": ("secaware.tsg.queries", "feature_state"),
    "feature_state_nodes": ("secaware.tsg.queries", "feature_state_nodes"),
    "feature_state_vector": ("secaware.tsg.queries", "feature_state_vector"),
    "feature_states_by_family": ("secaware.tsg.queries", "feature_states_by_family"),
    "graph_sha256": ("secaware.tsg.graph", "graph_sha256"),
    "has_feature_requirement": ("secaware.tsg.motifs", "has_feature_requirement"),
    "multidigraph_to_record": ("secaware.tsg.graph", "multidigraph_to_record"),
    "prompt_ontology_entry": ("secaware.tsg.catalog", "prompt_ontology_entry"),
    "record_to_multidigraph": ("secaware.tsg.graph", "record_to_multidigraph"),
    "motif_query_vector": ("secaware.tsg.motifs", "motif_query_vector"),
    "validate_proposal": ("secaware.tsg.proposal_validator", "validate_proposal"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *__all__))

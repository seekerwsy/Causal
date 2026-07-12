"""TSG helper namespace."""

from secaware.tsg.catalog import (
    MOTIF_VERSION,
    ONTOLOGY_VERSION,
    PROMPT_TSG_CATALOG,
    PROMPT_TSG_CATALOG_SHA256,
    PromptOntologyEntry,
    prompt_ontology_entry,
)
from secaware.tsg.graph import (
    canonical_edge_id,
    canonical_node_id,
    graph_sha256,
    multidigraph_to_record,
    record_to_multidigraph,
)
from secaware.tsg.features import derive_shadow
from secaware.tsg.motifs import (
    MOTIF_SPECS,
    MotifSpec,
    factor_query_vector,
    find_motif_matches,
    has_factor_requirement,
    motif_query_vector,
)

__all__ = [
    "MOTIF_VERSION",
    "ONTOLOGY_VERSION",
    "PROMPT_TSG_CATALOG",
    "PROMPT_TSG_CATALOG_SHA256",
    "PromptOntologyEntry",
    "MOTIF_SPECS",
    "MotifSpec",
    "canonical_edge_id",
    "canonical_node_id",
    "derive_shadow",
    "factor_query_vector",
    "find_motif_matches",
    "graph_sha256",
    "has_factor_requirement",
    "multidigraph_to_record",
    "prompt_ontology_entry",
    "record_to_multidigraph",
    "motif_query_vector",
]

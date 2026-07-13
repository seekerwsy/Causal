"""Canonical Prompt TSG construction from validated extraction proposals."""

from __future__ import annotations

import networkx as nx

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.features import FeatureFamily, FeatureState, PromptExtractorBackend
from secaware.schema.prompt_extraction import EvidenceSpan, PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType, PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG, FeatureSpec
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph
from secaware.tsg.proposal_validator import (
    _snapshot_prompt,
    feature_is_applicable,
    validate_proposal,
)
from secaware.tsg.queries import feature_state_vector


_EDGE_ENDPOINT_TYPES = {
    EdgeType.OPERATES_ON: (NodeType.TASK_OPERATION, NodeType.DATA_OBJECT),
    EdgeType.SOURCE_OF: (NodeType.SOURCE, NodeType.DATA_OBJECT),
    EdgeType.FLOWS_TO: (NodeType.DATA_OBJECT, NodeType.SINK),
    EdgeType.GUARDED_BY: (NodeType.DATA_OBJECT, NodeType.GUARD),
    EdgeType.REQUIRES: (NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
}


def _internal_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "tsg.build_prompt",
        "internal prompt TSG construction failure",
    )


def _evidence_attributes(span: EvidenceSpan | None) -> dict[str, str | int]:
    if span is None:
        return {}
    return {
        "evidence_start": span.start,
        "evidence_end": span.end,
        "evidence_sha256": span.text_sha256,
    }


def _add_fact_structure(
    graph: nx.MultiDiGraph,
    spec: FeatureSpec,
    span: EvidenceSpan | None,
) -> None:
    attributes = _evidence_attributes(span)
    node_keys: dict[NodeType, str] = {}
    for node_type in spec.structural_node_types:
        key = f"proposal-fact:{spec.feature_id}:{node_type.value}"
        graph.add_node(
            key,
            node_type=node_type,
            label=f"{spec.feature_id}:{node_type.value}",
            attributes=dict(attributes),
        )
        node_keys[node_type] = key
    for edge_type in spec.structural_edge_types:
        endpoint_types = _EDGE_ENDPOINT_TYPES.get(edge_type)
        if endpoint_types is None or any(item not in node_keys for item in endpoint_types):
            raise _internal_error() from None
        src_type, dst_type = endpoint_types
        graph.add_edge(
            node_keys[src_type],
            node_keys[dst_type],
            edge_type=edge_type,
            attributes=dict(attributes),
        )


def _build_structural_graph(
    trusted: PromptExtractionProposalRecord,
) -> tuple[nx.MultiDiGraph, dict[str, FeatureState]]:
    graph = nx.MultiDiGraph()
    states: dict[str, FeatureState] = {}
    if trusted.backend in {
        PromptExtractorBackend.LLM_FACTS_V1,
        PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
    }:
        for fact in trusted.facts:
            states[fact.feature_id] = fact.state
            if fact.state is FeatureState.PRESENT:
                spec = next(
                    item for item in PROMPT_FEATURE_CATALOG if item.feature_id == fact.feature_id
                )
                _add_fact_structure(graph, spec, fact.evidence[0])
        return graph, states

    aliases: dict[str, str] = {}
    for node in trusted.direct_nodes:
        key = f"proposal-direct:{node.feature_id}:{node.node_type.value}:{node.label}"
        graph.add_node(
            key,
            node_type=node.node_type,
            label=node.label,
            attributes=_evidence_attributes(node.evidence[0]),
        )
        aliases[node.local_id] = key
        states[node.feature_id] = FeatureState.PRESENT
    for edge in trusted.direct_edges:
        graph.add_edge(
            aliases[edge.src_local_id],
            aliases[edge.dst_local_id],
            edge_type=edge.edge_type,
            attributes=_evidence_attributes(edge.evidence[0]),
        )
    return graph, states


def _add_complete_feature_state_nodes(
    graph: nx.MultiDiGraph,
    states: dict[str, FeatureState],
    prompt: PromptRecord,
) -> None:
    for spec in PROMPT_FEATURE_CATALOG:
        state = states.get(spec.feature_id)
        if state is None:
            state = (
                FeatureState.ABSENT
                if feature_is_applicable(spec, prompt)
                else FeatureState.NOT_APPLICABLE
            )
        node_type = (
            NodeType.PRESENTATION_FEATURE
            if spec.feature_family is FeatureFamily.PRESENTATION_CONTROL
            else NodeType.FEATURE
        )
        graph.add_node(
            f"feature-state:{spec.feature_id}",
            node_type=node_type,
            label=spec.feature_id,
            attributes={
                "feature_id": spec.feature_id,
                "feature_family": spec.feature_family.value,
                "feature_state": state.value,
            },
        )


def build_prompt_tsg(
    proposal: PromptExtractionProposalRecord,
    prompt: PromptRecord,
) -> PromptTSGRecord:
    """Validate, construct, canonicalize, and round-trip one Prompt TSG 2.1 record."""
    source = _snapshot_prompt(prompt)
    trusted = validate_proposal(proposal, source)
    try:
        graph, states = _build_structural_graph(trusted)
        _add_complete_feature_state_nodes(graph, states, source)
        record = multidigraph_to_record(
            graph,
            prompt_id=source.prompt_id,
            task_id=source.task_id,
            task_family=source.task_family,
            cwe=source.cwe,
            extractor_backend=trusted.backend,
            extractor_policy_sha256=trusted.policy_sha256,
            proposal_id=trusted.proposal_id,
        )
        canonical = record_to_multidigraph(record)
        if len(feature_state_vector(canonical)) != len(PROMPT_FEATURE_CATALOG):
            raise _internal_error() from None
        rebuilt = multidigraph_to_record(
            canonical,
            prompt_id=record.prompt_id,
            task_id=record.task_id,
            task_family=record.task_family,
            cwe=record.cwe,
            extractor_backend=record.extractor_backend,
            extractor_policy_sha256=record.extractor_policy_sha256,
            proposal_id=record.proposal_id,
        )
        if rebuilt != record:
            raise _internal_error() from None
        return record
    except SecAwareError:
        raise
    except Exception:
        raise _internal_error() from None


__all__ = ["build_prompt_tsg"]

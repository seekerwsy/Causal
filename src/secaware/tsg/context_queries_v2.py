"""Target-independent context queries over canonical Prompt TSG 2.1 records.

The legacy motif catalog deliberately answers questions such as "flow without a
guard".  Those motifs remain useful diagnostics, but they cannot define the
prospective population for an intervention on that same guard.  This module
therefore owns a separate, versioned catalog whose expressions inspect only
task-side source, data, and sink flow roles.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any

import networkx as nx

from secaware.schema.features import FeatureFamily, FeatureState
from secaware.schema.policy_v2 import (
    ContextQueryResultRecord,
    ContextQuerySpec,
    PolicySplit,
    QueryState,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.tsg import (
    MAX_MOTIF_HOPS,
    MAX_MOTIF_MATCHES,
    MAX_TSG_EDGES,
    TSG_SCHEMA_VERSION,
    EdgeType,
    NodeType,
    PromptTSGRecord,
)
from secaware.tsg.catalog import PROMPT_TSG_CATALOG
from secaware.tsg.feature_catalog import prompt_feature_spec
from secaware.tsg.graph import record_to_multidigraph

CONTEXT_QUERY_SEMANTICS_VERSION = "context-query-v2.2"
CWE78_COMMAND_FLOW_QUERY = "flow.untrusted_input_to_command_execution"
CWE89_SQL_FLOW_QUERY = "flow.untrusted_value_to_sql"

_CATALOG_SCHEMA_VERSION = "1.0"
_MATCH_EVIDENCE_SCHEMA_VERSION = "1.0"
_MAX_TRAVERSAL_STATES = MAX_TSG_EDGES * (MAX_MOTIF_HOPS + 1)
_TRAVERSABLE_ENDPOINT_TYPES = MappingProxyType(
    {EdgeType.FLOWS_TO: (NodeType.DATA_OBJECT, NodeType.SINK)}
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ContextQueryDefinition:
    """One reviewed guard-independent flow expression."""

    query_name: str
    task_feature_id: str
    applicable_cwes: tuple[str, ...]
    applicable_task_archetypes: tuple[str, ...]
    source_types: tuple[NodeType, ...]
    data_label: str
    sink_label: str
    first_edge_type: EdgeType
    traversable_edge_types: tuple[EdgeType, ...]
    max_hops: int
    max_matches: int
    query_expression_sha256: str


@dataclass(frozen=True, slots=True)
class PromptEvidenceBinding:
    """Prompt-span provenance for one node or edge in a positive match."""

    element_id: str
    evidence_start: int
    evidence_end: int
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class ContextQueryMatchEvidence:
    """Content-addressed evidence for one complete source-to-sink path."""

    evidence_id: str
    evidence_sha256: str
    node_path: tuple[str, ...]
    edge_path: tuple[str, ...]
    node_evidence: tuple[PromptEvidenceBinding, ...]
    edge_evidence: tuple[PromptEvidenceBinding, ...]


@dataclass(frozen=True, slots=True)
class ContextQueryEvaluation:
    """The typed result together with its auditable positive path evidence."""

    definition: ContextQueryDefinition
    spec: ContextQuerySpec
    semantic_membership: SemanticTaskClusterMembershipRecord
    result: ContextQueryResultRecord
    matches: tuple[ContextQueryMatchEvidence, ...]


@dataclass(frozen=True, slots=True)
class _SearchOutcome:
    matches: tuple[ContextQueryMatchEvidence, ...]
    traversal_truncated: bool
    incomplete_candidate: bool


def _expression_content(
    *,
    task_feature_id: str,
    source_types: tuple[NodeType, ...],
    data_label: str,
    sink_label: str,
    first_edge_type: EdgeType,
    traversable_edge_types: tuple[EdgeType, ...],
    max_hops: int,
    max_matches: int,
) -> dict[str, object]:
    return {
        "expression_version": _CATALOG_SCHEMA_VERSION,
        "task_feature_id": task_feature_id,
        "source_types": [item.value for item in source_types],
        "data_role": {"node_type": NodeType.DATA_OBJECT.value, "label": data_label},
        "sink_role": {"node_type": NodeType.SINK.value, "label": sink_label},
        "first_edge_type": first_edge_type.value,
        "traversable_edge_types": [item.value for item in traversable_edge_types],
        "traversable_endpoint_types": [
            {
                "edge_type": item.value,
                "source_node_type": _TRAVERSABLE_ENDPOINT_TYPES[item][0].value,
                "target_node_type": _TRAVERSABLE_ENDPOINT_TYPES[item][1].value,
            }
            for item in traversable_edge_types
        ],
        "max_hops": max_hops,
        "max_matches": max_matches,
        "prompt_tsg_schema_version": TSG_SCHEMA_VERSION,
    }


def _definition(
    *,
    query_name: str,
    cwe: str,
    task_feature_id: str,
    task_archetypes: tuple[str, ...],
    data_label: str,
    sink_label: str,
) -> ContextQueryDefinition:
    source_types = (NodeType.SOURCE,)
    traversable = (EdgeType.FLOWS_TO,)
    expression = _expression_content(
        task_feature_id=task_feature_id,
        source_types=source_types,
        data_label=data_label,
        sink_label=sink_label,
        first_edge_type=EdgeType.SOURCE_OF,
        traversable_edge_types=traversable,
        max_hops=MAX_MOTIF_HOPS,
        max_matches=MAX_MOTIF_MATCHES,
    )
    return ContextQueryDefinition(
        query_name=query_name,
        task_feature_id=task_feature_id,
        applicable_cwes=(cwe,),
        applicable_task_archetypes=tuple(sorted(task_archetypes)),
        source_types=source_types,
        data_label=data_label,
        sink_label=sink_label,
        first_edge_type=EdgeType.SOURCE_OF,
        traversable_edge_types=traversable,
        max_hops=MAX_MOTIF_HOPS,
        max_matches=MAX_MOTIF_MATCHES,
        query_expression_sha256=_sha256(expression),
    )


CONTEXT_QUERY_CATALOG = (
    _definition(
        query_name=CWE78_COMMAND_FLOW_QUERY,
        cwe="CWE-78",
        task_feature_id="task.process_launch",
        task_archetypes=("argument-vector-subprocess", "bounded-shell-semantics"),
        data_label="command_argument",
        sink_label="process_spawn",
    ),
    _definition(
        query_name=CWE89_SQL_FLOW_QUERY,
        cwe="CWE-89",
        task_feature_id="task.database_query",
        task_archetypes=("dynamic-query-construction", "value-parameterization"),
        data_label="user_query_value",
        sink_label="database_execute",
    ),
)


def _definition_content(definition: ContextQueryDefinition) -> dict[str, object]:
    return {
        "query_name": definition.query_name,
        "task_feature_id": definition.task_feature_id,
        "applicable_cwes": list(definition.applicable_cwes),
        "applicable_task_archetypes": list(definition.applicable_task_archetypes),
        "source_types": [item.value for item in definition.source_types],
        "data_label": definition.data_label,
        "sink_label": definition.sink_label,
        "first_edge_type": definition.first_edge_type.value,
        "traversable_edge_types": [item.value for item in definition.traversable_edge_types],
        "max_hops": definition.max_hops,
        "max_matches": definition.max_matches,
        "query_expression_sha256": definition.query_expression_sha256,
    }


CONTEXT_QUERY_CATALOG_SHA256 = _sha256(
    {
        "schema_version": _CATALOG_SCHEMA_VERSION,
        "query_semantics_version": CONTEXT_QUERY_SEMANTICS_VERSION,
        "prompt_tsg_schema_version": TSG_SCHEMA_VERSION,
        "queries": [_definition_content(item) for item in CONTEXT_QUERY_CATALOG],
    }
)


def _validate_catalog() -> None:
    expected = {
        CWE78_COMMAND_FLOW_QUERY: "CWE-78",
        CWE89_SQL_FLOW_QUERY: "CWE-89",
    }
    ontology_by_cwe = {entry.cwe: entry for entry in PROMPT_TSG_CATALOG}
    if (
        tuple(item.query_name for item in CONTEXT_QUERY_CATALOG) != tuple(sorted(expected))
        or {item.query_name: item.applicable_cwes[0] for item in CONTEXT_QUERY_CATALOG} != expected
    ):
        raise RuntimeError("invalid context query catalog")
    for item in CONTEXT_QUERY_CATALOG:
        ontology = ontology_by_cwe[item.applicable_cwes[0]]
        task_spec = prompt_feature_spec(item.task_feature_id)
        expression = _expression_content(
            task_feature_id=item.task_feature_id,
            source_types=item.source_types,
            data_label=item.data_label,
            sink_label=item.sink_label,
            first_edge_type=item.first_edge_type,
            traversable_edge_types=item.traversable_edge_types,
            max_hops=item.max_hops,
            max_matches=item.max_matches,
        )
        serialized = _canonical_json(_definition_content(item)).decode("utf-8")
        if (
            task_spec.feature_family is not FeatureFamily.TASK_FUNCTION
            or item.task_feature_id != ontology.task_feature_id
            or item.data_label != ontology.data_label
            or item.sink_label != ontology.sink_label
            or item.applicable_task_archetypes != tuple(sorted(item.applicable_task_archetypes))
            or item.first_edge_type is not EdgeType.SOURCE_OF
            or item.traversable_edge_types != (EdgeType.FLOWS_TO,)
            or item.query_expression_sha256 != _sha256(expression)
            or "without_guard" in item.query_name
            or "guard" in serialized
            or ontology.target_feature_id in serialized
        ):
            raise RuntimeError("invalid target-dependent context query")


_validate_catalog()


def _spec(definition: ContextQueryDefinition) -> ContextQuerySpec:
    return ContextQuerySpec.from_content(
        query_name=definition.query_name,
        applicable_cwes=definition.applicable_cwes,
        applicable_task_archetypes=definition.applicable_task_archetypes,
        query_expression_sha256=definition.query_expression_sha256,
        context_query_catalog_sha256=CONTEXT_QUERY_CATALOG_SHA256,
        query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
        target_feature_independent=True,
    )


_DEFINITIONS = MappingProxyType({item.query_name: item for item in CONTEXT_QUERY_CATALOG})
CONTEXT_QUERY_SPECS = tuple(_spec(item) for item in CONTEXT_QUERY_CATALOG)
_SPECS = MappingProxyType(
    {item.query_name: spec for item, spec in zip(CONTEXT_QUERY_CATALOG, CONTEXT_QUERY_SPECS)}
)
_ARCHETYPE_CWES = MappingProxyType(
    {
        archetype: frozenset(
            cwe
            for definition in CONTEXT_QUERY_CATALOG
            if archetype in definition.applicable_task_archetypes
            for cwe in definition.applicable_cwes
        )
        for archetype in {
            value
            for definition in CONTEXT_QUERY_CATALOG
            for value in definition.applicable_task_archetypes
        }
    }
)


def context_query_definition(query_name: str) -> ContextQueryDefinition:
    """Return one exact reviewed context-query definition."""
    if type(query_name) is not str or query_name not in _DEFINITIONS:
        raise KeyError("unknown context query")
    return _DEFINITIONS[query_name]


def context_query_spec(query_name: str) -> ContextQuerySpec:
    """Return the content-addressed policy-v2 spec for one query."""
    context_query_definition(query_name)
    return _SPECS[query_name]


def _sorted_out_edges(graph: nx.MultiDiGraph, node_id: str):
    return iter(
        sorted(
            graph.out_edges(node_id, keys=True, data=True),
            key=lambda item: (item[1], item[2]),
        )
    )


def _typed_traversable_out_edges(
    graph: nx.MultiDiGraph,
    node_id: str,
    definition: ContextQueryDefinition,
) -> tuple[tuple[tuple[str, str, str, dict[str, Any]], ...], bool]:
    """Return traversable edges only when their endpoint roles are exact.

    PromptTSG 2.1 records predate a schema-level endpoint-matrix check.  A
    context query must therefore enforce the finite endpoint matrix locally
    instead of allowing a GUARD (including the intervention target) to become
    an intermediate flow node.
    """

    valid = []
    invalid = False
    source_type = graph.nodes[node_id]["node_type"]
    for edge in _sorted_out_edges(graph, node_id):
        edge_type = edge[3]["edge_type"]
        if edge_type not in definition.traversable_edge_types:
            continue
        endpoint_types = _TRAVERSABLE_ENDPOINT_TYPES.get(edge_type)
        target_type = graph.nodes[edge[1]]["node_type"]
        if endpoint_types is None or (source_type, target_type) != endpoint_types:
            invalid = True
            continue
        valid.append(edge)
    return tuple(valid), invalid


def _evidence_binding(element_id: str, attributes: dict[str, Any]) -> PromptEvidenceBinding | None:
    evidence = attributes.get("attributes")
    if type(evidence) is not dict:
        return None
    start = evidence.get("evidence_start")
    end = evidence.get("evidence_end")
    digest = evidence.get("evidence_sha256")
    if type(start) is not int or type(end) is not int or type(digest) is not str:
        return None
    return PromptEvidenceBinding(
        element_id=element_id,
        evidence_start=start,
        evidence_end=end,
        evidence_sha256=digest,
    )


def _match_evidence(
    definition: ContextQueryDefinition,
    graph: nx.MultiDiGraph,
    node_path: tuple[str, ...],
    edge_path: tuple[str, ...],
) -> ContextQueryMatchEvidence | None:
    node_evidence = tuple(_evidence_binding(node_id, graph.nodes[node_id]) for node_id in node_path)
    edge_evidence = tuple(
        _evidence_binding(
            edge_id,
            graph.edges[src, dst, edge_id],
        )
        for src, dst, edge_id in zip(node_path, node_path[1:], edge_path)
    )
    if any(item is None for item in (*node_evidence, *edge_evidence)):
        return None
    trusted_nodes = tuple(item for item in node_evidence if item is not None)
    trusted_edges = tuple(item for item in edge_evidence if item is not None)
    content = {
        "schema_version": _MATCH_EVIDENCE_SCHEMA_VERSION,
        "query_expression_sha256": definition.query_expression_sha256,
        "node_path": list(node_path),
        "edge_path": list(edge_path),
        "node_evidence": [asdict(item) for item in trusted_nodes],
        "edge_evidence": [asdict(item) for item in trusted_edges],
    }
    digest = _sha256(content)
    return ContextQueryMatchEvidence(
        evidence_id=f"context_match_{digest}",
        evidence_sha256=digest,
        node_path=node_path,
        edge_path=edge_path,
        node_evidence=trusted_nodes,
        edge_evidence=trusted_edges,
    )


def _search(graph: nx.MultiDiGraph, definition: ContextQueryDefinition) -> _SearchOutcome:
    states = 0
    truncated = False
    incomplete_candidate = False
    matches: list[ContextQueryMatchEvidence] = []
    stop = False

    for source_id, source in sorted(graph.nodes(data=True), key=lambda item: item[0]):
        if stop:
            break
        if source["node_type"] not in definition.source_types:
            continue
        for _, data_id, first_edge_id, first_edge in _sorted_out_edges(graph, source_id):
            data = graph.nodes[data_id]
            if (
                first_edge["edge_type"] is not definition.first_edge_type
                or data["node_type"] is not NodeType.DATA_OBJECT
                or data["label"] != definition.data_label
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
            while stack and not stop:
                states += 1
                if states > _MAX_TRAVERSAL_STATES:
                    truncated = True
                    stop = True
                    break
                current, node_path, edge_path, visited = stack.pop()
                typed_outgoing, invalid_endpoint = _typed_traversable_out_edges(
                    graph, current, definition
                )
                incomplete_candidate = incomplete_candidate or invalid_endpoint
                outgoing = tuple(edge for edge in typed_outgoing if edge[1] not in visited)
                if len(edge_path) >= definition.max_hops:
                    truncated = truncated or bool(outgoing)
                    continue
                next_states = []
                for _, dst, edge_id, _ in outgoing:
                    next_node_path = (*node_path, dst)
                    next_edge_path = (*edge_path, edge_id)
                    target = graph.nodes[dst]
                    if (
                        target["node_type"] is NodeType.SINK
                        and target["label"] == definition.sink_label
                    ):
                        match = _match_evidence(
                            definition,
                            graph,
                            next_node_path,
                            next_edge_path,
                        )
                        if match is None:
                            incomplete_candidate = True
                        else:
                            matches.append(match)
                            if len(matches) >= definition.max_matches:
                                stop = True
                                break
                        continue
                    next_states.append(
                        (
                            dst,
                            next_node_path,
                            next_edge_path,
                            visited | frozenset((dst,)),
                        )
                    )
                stack.extend(reversed(next_states))
    return _SearchOutcome(
        matches=tuple(sorted(matches, key=lambda item: (item.node_path, item.edge_path))),
        traversal_truncated=truncated,
        incomplete_candidate=incomplete_candidate,
    )


def _task_feature_state(
    graph: nx.MultiDiGraph,
    task_feature_id: str,
) -> FeatureState | None:
    states = []
    for _, node in graph.nodes(data=True):
        if node["node_type"] is not NodeType.FEATURE:
            continue
        attributes = node["attributes"]
        if attributes.get("feature_id") == task_feature_id:
            states.append(FeatureState(attributes["feature_state"]))
    return states[0] if len(states) == 1 else None


def _roles_resolved(graph: nx.MultiDiGraph, definition: ContextQueryDefinition) -> bool:
    role_nodes = (
        tuple(
            (node_id, node)
            for node_id, node in graph.nodes(data=True)
            if node["node_type"] in definition.source_types
        ),
        tuple(
            (node_id, node)
            for node_id, node in graph.nodes(data=True)
            if node["node_type"] is NodeType.DATA_OBJECT and node["label"] == definition.data_label
        ),
        tuple(
            (node_id, node)
            for node_id, node in graph.nodes(data=True)
            if node["node_type"] is NodeType.SINK and node["label"] == definition.sink_label
        ),
    )
    return all(
        any(_evidence_binding(node_id, node) is not None for node_id, node in nodes)
        for nodes in role_nodes
    )


def _state(
    *,
    applicable: bool,
    task_state: FeatureState | None,
    roles_resolved: bool,
    search: _SearchOutcome,
) -> tuple[QueryState, bool | None, bool]:
    if not applicable:
        return QueryState.NOT_APPLICABLE, None, False
    if search.traversal_truncated or search.incomplete_candidate:
        return QueryState.UNRESOLVED, roles_resolved, False
    if search.matches:
        if task_state is FeatureState.PRESENT:
            return QueryState.PRESENT, True, True
        return QueryState.UNRESOLVED, roles_resolved, False
    if task_state in {FeatureState.ABSENT, FeatureState.PRESENT} and roles_resolved:
        return QueryState.ABSENT, True, True
    return QueryState.UNRESOLVED, roles_resolved, False


def evaluate_context_query(
    record: PromptTSGRecord,
    query_name: str,
    *,
    semantic_membership: SemanticTaskClusterMembershipRecord,
) -> ContextQueryEvaluation:
    """Evaluate one natural-Prompt context query and freeze its provenance."""
    trusted = PromptTSGRecord.model_validate(record, strict=True)
    membership = SemanticTaskClusterMembershipRecord.model_validate(
        semantic_membership, strict=True
    )
    if (
        membership.task_instance_id != trusted.task_id
        or membership.cwe != trusted.cwe
        or membership.split is not PolicySplit.DISCOVER
        or (
            membership.task_archetype in _ARCHETYPE_CWES
            and trusted.cwe not in _ARCHETYPE_CWES[membership.task_archetype]
        )
    ):
        raise ValueError("context query membership does not match the trusted PromptTSG")
    definition = context_query_definition(query_name)
    spec = context_query_spec(query_name)
    graph = record_to_multidigraph(trusted)
    applicable = (
        trusted.cwe in definition.applicable_cwes
        and membership.task_archetype in definition.applicable_task_archetypes
    )
    task_state = _task_feature_state(graph, definition.task_feature_id)
    roles_resolved = _roles_resolved(graph, definition) if applicable else False
    search = _search(graph, definition) if applicable else _SearchOutcome((), False, False)
    state, resolved_field, bounded_complete = _state(
        applicable=applicable,
        task_state=task_state,
        roles_resolved=roles_resolved,
        search=search,
    )
    published_matches = search.matches if state is QueryState.PRESENT else ()
    match_ids = tuple(sorted(item.evidence_id for item in published_matches))
    evidence_content = {
        "schema_version": _MATCH_EVIDENCE_SCHEMA_VERSION,
        "context_query_id": spec.context_query_id,
        "context_query_catalog_sha256": CONTEXT_QUERY_CATALOG_SHA256,
        "query_semantics_version": CONTEXT_QUERY_SEMANTICS_VERSION,
        "prompt_tsg_sha256": trusted.graph_sha256,
        "semantic_cluster_membership_id": membership.cluster_membership_id,
        "semantic_task_cluster_id": membership.semantic_task_cluster_id,
        "source_task_sha256": membership.source_task_sha256,
        "clustering_policy_sha256": membership.clustering_policy_sha256,
        "task_instance_id": membership.task_instance_id,
        "natural_prompt_id": trusted.prompt_id,
        "task_archetype": membership.task_archetype,
        "cwe": trusted.cwe,
        "applicable": applicable,
        "task_feature_state": task_state.value if task_state is not None else None,
        "required_roles_resolved": resolved_field,
        "bounded_matching_complete": bounded_complete,
        "state": state.value,
        "traversal_truncated": search.traversal_truncated,
        "incomplete_candidate": search.incomplete_candidate,
        "matches": [asdict(item) for item in published_matches],
    }
    evaluation_evidence_sha256 = _sha256(evidence_content)
    result = ContextQueryResultRecord.from_content(
        regime_id="natural_prompt_discovery",
        task_instance_id=membership.task_instance_id,
        natural_prompt_id=trusted.prompt_id,
        prompt_tsg_sha256=trusted.graph_sha256,
        context_query_id=spec.context_query_id,
        context_query_catalog_sha256=CONTEXT_QUERY_CATALOG_SHA256,
        query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
        state=state,
        applicable=applicable,
        required_roles_resolved=resolved_field,
        bounded_matching_complete=bounded_complete,
        match_evidence_ids=match_ids,
        evaluation_evidence_sha256=evaluation_evidence_sha256,
    )
    return ContextQueryEvaluation(
        definition=definition,
        spec=spec,
        semantic_membership=membership,
        result=result,
        matches=published_matches,
    )


__all__ = [
    "CONTEXT_QUERY_CATALOG",
    "CONTEXT_QUERY_CATALOG_SHA256",
    "CONTEXT_QUERY_SEMANTICS_VERSION",
    "CONTEXT_QUERY_SPECS",
    "CWE78_COMMAND_FLOW_QUERY",
    "CWE89_SQL_FLOW_QUERY",
    "ContextQueryDefinition",
    "ContextQueryEvaluation",
    "ContextQueryMatchEvidence",
    "PromptEvidenceBinding",
    "context_query_definition",
    "context_query_spec",
    "evaluate_context_query",
]

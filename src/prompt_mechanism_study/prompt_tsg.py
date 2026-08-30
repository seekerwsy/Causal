"""Canonical Prompt TSG records, finite queries, and typed intervention patches."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from prompt_mechanism_study.records import (
    canonical_json,
    canonical_value,
    content_hash,
    content_id,
    require_text,
)


class PromptTSGError(ValueError):
    """A Prompt TSG, catalog, query, or patch is not scientifically valid."""


class QueryState(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class TSGNode:
    node_id: str
    node_type: str
    semantic_id: str
    evidence_start: int
    evidence_end: int
    evidence_sha256: str
    normalized_text_sha256: str
    attributes: tuple[tuple[str, bool], ...]


@dataclass(frozen=True, slots=True)
class TSGEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: str


@dataclass(frozen=True, slots=True)
class PromptTSG:
    schema_version: str
    task_id: str
    prompt_sha256: str
    extractor_id: str
    catalog_sha256: str
    nodes: tuple[TSGNode, ...]
    edges: tuple[TSGEdge, ...]
    unresolved_semantics: tuple[str, ...]
    unresolved_relations: tuple[tuple[str, str, str], ...] = ()

    @property
    def tsg_id(self) -> str:
        payload = canonical_value(self)
        if self.schema_version == "1.0":
            payload.pop("unresolved_relations")
        return content_id("prompt_tsg_", payload)


@dataclass(frozen=True, slots=True)
class QueryResult:
    query_id: str
    state: QueryState
    evidence_node_ids: tuple[str, ...]
    evidence_edge_ids: tuple[str, ...]


def load_catalog(path: Path) -> dict[str, Any]:
    """Load one closed, versioned Prompt TSG ontology and query catalog."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PromptTSGError("Prompt TSG catalog is unreadable") from None
    return catalog_from_record(value)


def catalog_from_record(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an embedded Prompt TSG catalog without trusting a live path."""

    required = {
        "schema_version",
        "node_types",
        "edge_types",
        "attribute_names",
        "semantic_guidance",
        "source_realization_task_families",
        "semantics",
        "allowed_edges",
        "queries",
    }
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != "1.0":
        raise PromptTSGError("Prompt TSG catalog envelope is invalid")
    node_types = _unique_strings(value["node_types"], "node types")
    edge_types = _unique_strings(value["edge_types"], "edge types")
    _unique_strings(value["attribute_names"], "attribute names")
    semantics = value["semantics"]
    if (
        not isinstance(semantics, dict)
        or not semantics
        or any(
            not isinstance(key, str)
            or not key.strip()
            or node_type not in node_types
            for key, node_type in semantics.items()
        )
    ):
        raise PromptTSGError("Prompt TSG semantics are invalid")
    guidance = value["semantic_guidance"]
    if (
        not isinstance(guidance, dict)
        or any(
            semantic_id not in semantics
            or not isinstance(description, str)
            or not description.strip()
            for semantic_id, description in guidance.items()
        )
    ):
        raise PromptTSGError("Prompt TSG semantic guidance is invalid")
    source_families = value["source_realization_task_families"]
    if (
        not isinstance(source_families, dict)
        or not source_families
        or any(
            not isinstance(realization_id, str)
            or not realization_id.strip()
            or not isinstance(task_family, str)
            or not task_family.strip()
            for realization_id, task_family in source_families.items()
        )
    ):
        raise PromptTSGError("Prompt TSG source realization mapping is invalid")
    allowed = set()
    for item in value["allowed_edges"]:
        if (
            not isinstance(item, list)
            or len(item) != 3
            or item[0] not in node_types
            or item[1] not in edge_types
            or item[2] not in node_types
        ):
            raise PromptTSGError("Prompt TSG edge matrix is invalid")
        allowed.add(tuple(item))
    if len(allowed) != len(value["allowed_edges"]):
        raise PromptTSGError("Prompt TSG edge matrix contains duplicates")
    queries = value["queries"]
    if not isinstance(queries, list) or not queries:
        raise PromptTSGError("Prompt TSG queries are missing")
    query_ids = set()
    realization_ids = set()
    for query in queries:
        _validate_query(query, semantics, edge_types, allowed)
        if query["query_id"] in query_ids or query["realization_id"] in realization_ids:
            raise PromptTSGError("Prompt TSG query identities are not unique")
        query_ids.add(query["query_id"])
        realization_ids.add(query["realization_id"])
    return value


def catalog_sha256(catalog: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(catalog).encode("utf-8")).hexdigest()


def prompt_tsg_record(graph: PromptTSG) -> dict[str, Any]:
    """Return the canonical JSON record, including its content identity."""

    payload = canonical_value(graph)
    if graph.schema_version == "1.0":
        payload.pop("unresolved_relations")
    return {"tsg_id": graph.tsg_id, **payload}


def prompt_tsg_from_record(value: Mapping[str, Any]) -> PromptTSG:
    """Reconstruct a graph record before prompt- and catalog-aware validation."""

    if not isinstance(value, Mapping) or value.get("schema_version") not in {"1.0", "2.0"}:
        raise PromptTSGError("Prompt TSG serialized schema is invalid")
    expected = {
        "tsg_id",
        "schema_version",
        "task_id",
        "prompt_sha256",
        "extractor_id",
        "catalog_sha256",
        "nodes",
        "edges",
        "unresolved_semantics",
    }
    if value["schema_version"] == "2.0":
        expected.add("unresolved_relations")
    if set(value) != expected:
        raise PromptTSGError("Prompt TSG serialized fields are invalid")
    try:
        node_fields = {
            "node_id",
            "node_type",
            "semantic_id",
            "evidence_start",
            "evidence_end",
            "evidence_sha256",
            "normalized_text_sha256",
            "attributes",
        }
        edge_fields = {"edge_id", "source_id", "target_id", "edge_type"}
        if any(set(item) != node_fields for item in value["nodes"]) or any(
            set(item) != edge_fields for item in value["edges"]
        ):
            raise PromptTSGError("Prompt TSG serialized item fields are invalid")
        nodes = tuple(
            TSGNode(
                item["node_id"],
                item["node_type"],
                item["semantic_id"],
                item["evidence_start"],
                item["evidence_end"],
                item["evidence_sha256"],
                item["normalized_text_sha256"],
                tuple((key, flag) for key, flag in item["attributes"]),
            )
            for item in value["nodes"]
        )
        edges = tuple(
            TSGEdge(item["edge_id"], item["source_id"], item["target_id"], item["edge_type"])
            for item in value["edges"]
        )
        raw_unresolved_relations = value.get("unresolved_relations", [])
        if any(
            not isinstance(item, list)
            or len(item) != 3
            or any(not isinstance(part, str) or not part.strip() for part in item)
            for item in raw_unresolved_relations
        ):
            raise PromptTSGError("Prompt TSG unresolved relations are invalid")
        graph = PromptTSG(
            value["schema_version"],
            value["task_id"],
            value["prompt_sha256"],
            value["extractor_id"],
            value["catalog_sha256"],
            nodes,
            edges,
            tuple(value["unresolved_semantics"]),
            tuple(tuple(item) for item in raw_unresolved_relations),
        )
    except (KeyError, TypeError, ValueError):
        raise PromptTSGError("Prompt TSG serialized values are invalid") from None
    if graph.tsg_id != value["tsg_id"]:
        raise PromptTSGError("Prompt TSG serialized identity is invalid")
    return graph


def build_prompt_tsg(
    *,
    task_id: str,
    prompt: str,
    extractor_id: str,
    catalog: Mapping[str, Any],
    facts: Sequence[Mapping[str, Any]],
    relations: Sequence[Mapping[str, Any]],
    unresolved_semantics: Sequence[str] = (),
    unresolved_relations: Sequence[Sequence[str]] = (),
    schema_version: str = "1.0",
) -> PromptTSG:
    """Validate evidence-bound facts and deterministically commit one Prompt TSG."""

    require_text(task_id, "task_id")
    require_text(prompt, "prompt")
    require_text(extractor_id, "extractor_id")
    semantics = catalog["semantics"]
    node_types = set(catalog["node_types"])
    edge_types = set(catalog["edge_types"])
    allowed = {tuple(item) for item in catalog["allowed_edges"]}
    if len(facts) > 128 or len(relations) > 256:
        raise PromptTSGError("Prompt TSG proposal exceeds bounds")

    root = _node("task", "task.root", 0, len(prompt), prompt, {})
    nodes = [root]
    local_nodes: dict[str, TSGNode] = {}
    for fact in facts:
        if not isinstance(fact, Mapping) or set(fact) != {
            "local_id",
            "node_type",
            "semantic_id",
            "evidence_text",
            "occurrence",
            "attributes",
        }:
            raise PromptTSGError("Prompt TSG fact fields are invalid")
        local_id = fact["local_id"]
        node_type = fact["node_type"]
        semantic_id = fact["semantic_id"]
        evidence = fact["evidence_text"]
        occurrence = fact["occurrence"]
        attributes = fact["attributes"]
        if (
            not isinstance(local_id, str)
            or not local_id.strip()
            or local_id in local_nodes
            or node_type not in node_types
            or semantics.get(semantic_id) != node_type
            or semantic_id == "task.root"
            or not isinstance(evidence, str)
            or not evidence
            or len(evidence.encode("utf-8")) > 2048
            or type(occurrence) is not int
            or occurrence <= 0
            or not isinstance(attributes, Mapping)
            or any(
                key not in catalog["attribute_names"] or type(value) is not bool
                for key, value in attributes.items()
            )
        ):
            raise PromptTSGError("Prompt TSG fact value is invalid")
        start, end = _occurrence_span(prompt, evidence, occurrence)
        node = _node(
            node_type,
            semantic_id,
            start,
            end,
            prompt[start:end],
            attributes,
        )
        if any(item.node_id == node.node_id for item in nodes):
            raise PromptTSGError("Prompt TSG fact is duplicated")
        local_nodes[local_id] = node
        nodes.append(node)

    edges = []
    for node in nodes[1:]:
        if node.node_type in {
            "task_requirement",
            "task_operation",
            "data_object",
            "source",
            "sink",
            "constraint",
            "presentation_control",
        }:
            edge_type = "contains"
        else:
            edge_type = "requires"
        edges.append(_edge(root, node, edge_type, allowed))
    seen_relations = set()
    for relation in relations:
        if not isinstance(relation, Mapping) or set(relation) != {
            "edge_type",
            "source",
            "target",
        }:
            raise PromptTSGError("Prompt TSG relation fields are invalid")
        edge_type = relation["edge_type"]
        source = local_nodes.get(relation["source"])
        target = local_nodes.get(relation["target"])
        identity = (relation["source"], edge_type, relation["target"])
        if (
            edge_type not in edge_types
            or source is None
            or target is None
            or identity in seen_relations
        ):
            raise PromptTSGError("Prompt TSG relation is invalid")
        seen_relations.add(identity)
        edges.append(_edge(source, target, edge_type, allowed))

    unresolved = _unique_strings(unresolved_semantics, "unresolved semantics")
    if any(item not in semantics or item == "task.root" for item in unresolved):
        raise PromptTSGError("Prompt TSG unresolved semantic is outside the catalog")
    unresolved_relation_values = []
    for relation in unresolved_relations:
        if (
            not isinstance(relation, (list, tuple))
            or len(relation) != 3
            or any(not isinstance(item, str) or not item.strip() for item in relation)
        ):
            raise PromptTSGError("Prompt TSG unresolved relation is invalid")
        source_semantic, edge_type, target_semantic = relation
        if (
            source_semantic not in semantics
            or edge_type not in edge_types
            or target_semantic not in semantics
            or (semantics[source_semantic], edge_type, semantics[target_semantic])
            not in allowed
        ):
            raise PromptTSGError("Prompt TSG unresolved relation is outside the catalog")
        unresolved_relation_values.append(tuple(relation))
    if len(unresolved_relation_values) != len(set(unresolved_relation_values)):
        raise PromptTSGError("Prompt TSG unresolved relations are duplicated")
    if schema_version not in {"1.0", "2.0"} or (
        schema_version == "1.0" and unresolved_relation_values
    ):
        raise PromptTSGError("Prompt TSG schema cannot represent unresolved relations")
    ordered_nodes = tuple(sorted(nodes, key=lambda item: item.node_id))
    ordered_edges = tuple(sorted(edges, key=lambda item: item.edge_id))
    graph = PromptTSG(
        schema_version,
        task_id,
        content_hash(prompt),
        extractor_id,
        catalog_sha256(catalog),
        ordered_nodes,
        ordered_edges,
        tuple(sorted(unresolved)),
        tuple(sorted(unresolved_relation_values)),
    )
    validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    return graph


def validate_prompt_tsg(
    graph: PromptTSG, *, prompt: str, catalog: Mapping[str, Any]
) -> None:
    """Revalidate graph identity, evidence, endpoints, ordering, and catalog closure."""

    if (
        graph.schema_version not in {"1.0", "2.0"}
        or (graph.schema_version == "1.0" and graph.unresolved_relations)
        or graph.prompt_sha256 != content_hash(prompt)
        or graph.catalog_sha256 != catalog_sha256(catalog)
        or not graph.nodes
        or len(graph.nodes) > 129
        or len(graph.edges) > 384
        or graph.nodes != tuple(sorted(graph.nodes, key=lambda item: item.node_id))
        or graph.edges != tuple(sorted(graph.edges, key=lambda item: item.edge_id))
        or graph.unresolved_semantics
        != tuple(sorted(set(graph.unresolved_semantics)))
        or any(
            item not in catalog["semantics"] or item == "task.root"
            for item in graph.unresolved_semantics
        )
        or graph.unresolved_relations
        != tuple(sorted(set(graph.unresolved_relations)))
    ):
        raise PromptTSGError("Prompt TSG record identity is invalid")
    node_by_id = {node.node_id: node for node in graph.nodes}
    if len(node_by_id) != len(graph.nodes) or len({edge.edge_id for edge in graph.edges}) != len(
        graph.edges
    ):
        raise PromptTSGError("Prompt TSG record identities are duplicated")
    roots = [node for node in graph.nodes if node.semantic_id == "task.root"]
    if (
        len(roots) != 1
        or roots[0].evidence_start != 0
        or roots[0].evidence_end != len(prompt)
        or any(edge.target_id == roots[0].node_id for edge in graph.edges)
    ):
        raise PromptTSGError("Prompt TSG task root is invalid")
    semantics = catalog["semantics"]
    allowed = {tuple(item) for item in catalog["allowed_edges"]}
    unresolved_relation_set = set(graph.unresolved_relations)
    available_semantics = {node.semantic_id for node in graph.nodes} | set(
        graph.unresolved_semantics
    )
    for relation in graph.unresolved_relations:
        if (
            len(relation) != 3
            or relation[0] not in semantics
            or relation[2] not in semantics
            or (semantics[relation[0]], relation[1], semantics[relation[2]])
            not in allowed
            or relation[0] not in available_semantics
            or relation[2] not in available_semantics
        ):
            raise PromptTSGError("Prompt TSG unresolved relation is invalid")
    for node in graph.nodes:
        if (
            semantics.get(node.semantic_id) != node.node_type
            or not 0 <= node.evidence_start <= node.evidence_end <= len(prompt)
            or node.evidence_sha256
            != content_hash(prompt[node.evidence_start : node.evidence_end])
            or node != _node(
                node.node_type,
                node.semantic_id,
                node.evidence_start,
                node.evidence_end,
                prompt[node.evidence_start : node.evidence_end],
                dict(node.attributes),
            )
        ):
            raise PromptTSGError("Prompt TSG node evidence is invalid")
    for edge in graph.edges:
        source = node_by_id.get(edge.source_id)
        target = node_by_id.get(edge.target_id)
        if (
            source is None
            or target is None
            or (source.node_type, edge.edge_type, target.node_type) not in allowed
            or edge != _edge(source, target, edge.edge_type, allowed)
        ):
            raise PromptTSGError("Prompt TSG edge is invalid")
        if (
            source.semantic_id,
            edge.edge_type,
            target.semantic_id,
        ) in unresolved_relation_set:
            raise PromptTSGError("Prompt TSG relation cannot be present and unresolved")


def query_context(
    graph: PromptTSG,
    *,
    query: Mapping[str, Any],
    cwe: str,
    task_family: str,
) -> QueryResult:
    """Evaluate one catalog query with total four-valued semantics."""

    if query["cwe_id"] != cwe or query["task_family"] != task_family:
        return QueryResult(query["query_id"], QueryState.NOT_APPLICABLE, (), ())
    by_semantic: dict[str, list[TSGNode]] = {}
    for node in graph.nodes:
        by_semantic.setdefault(node.semantic_id, []).append(node)
    relevant = set(query["required_semantics"]) | set(query["forbidden_semantics"])
    if relevant & set(graph.unresolved_semantics):
        evidence = tuple(
            sorted(node.node_id for item in relevant for node in by_semantic.get(item, ()))
        )
        return QueryResult(query["query_id"], QueryState.UNRESOLVED, evidence, ())
    required = set(query["required_semantics"])
    forbidden = set(query["forbidden_semantics"])
    if not required <= set(by_semantic) or forbidden & set(by_semantic):
        return QueryResult(query["query_id"], QueryState.ABSENT, (), ())
    relation_matches = []
    unresolved_relations = set(graph.unresolved_relations)
    for source_semantic, edge_type, target_semantic in query["required_relations"]:
        relation = (source_semantic, edge_type, target_semantic)
        if relation in unresolved_relations:
            evidence = tuple(
                sorted(
                    node.node_id
                    for semantic in (source_semantic, target_semantic)
                    for node in by_semantic.get(semantic, ())
                )
            )
            return QueryResult(query["query_id"], QueryState.UNRESOLVED, evidence, ())
        source_ids = {node.node_id for node in by_semantic[source_semantic]}
        target_ids = {node.node_id for node in by_semantic[target_semantic]}
        matches = [
            edge
            for edge in graph.edges
            if edge.edge_type == edge_type
            and edge.source_id in source_ids
            and edge.target_id in target_ids
        ]
        if not matches:
            if {source_semantic, target_semantic} & set(graph.unresolved_semantics):
                return QueryResult(query["query_id"], QueryState.UNRESOLVED, (), ())
            return QueryResult(query["query_id"], QueryState.ABSENT, (), ())
        relation_matches.extend(matches)
    evidence_nodes = tuple(
        sorted(node.node_id for semantic in required for node in by_semantic[semantic])
    )
    evidence_edges = tuple(sorted(edge.edge_id for edge in relation_matches))
    return QueryResult(query["query_id"], QueryState.PRESENT, evidence_nodes, evidence_edges)


def feature_state(graph: PromptTSG, feature_id: str) -> QueryState:
    """Return whether one catalog-bound actionable Prompt feature is explicit."""

    if feature_id in graph.unresolved_semantics:
        return QueryState.UNRESOLVED
    return (
        QueryState.PRESENT
        if any(node.semantic_id == feature_id for node in graph.nodes)
        else QueryState.ABSENT
    )


def apply_feature_patch(
    graph: PromptTSG,
    *,
    prompt: str,
    appended_text: str,
    semantic_id: str,
    catalog: Mapping[str, Any],
) -> PromptTSG:
    """Derive an arm graph by adding exactly one evidence-bound feature/control node."""

    require_text(appended_text, "appended_text")
    node_type = catalog["semantics"].get(semantic_id)
    if node_type not in {"safety_requirement", "presentation_control"}:
        raise PromptTSGError("typed patch semantic is not an intervention control")
    variant_prompt = prompt + "\n\n" + appended_text
    validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    patched = _node(
        node_type,
        semantic_id,
        len(prompt) + 2,
        len(variant_prompt),
        appended_text,
        {},
    )
    if any(node.semantic_id == semantic_id for node in graph.nodes):
        raise PromptTSGError("typed patch target is already present")
    root = next(node for node in graph.nodes if node.semantic_id == "task.root")
    root_variant = _node("task", "task.root", 0, len(variant_prompt), variant_prompt, {})
    remap = {root.node_id: root_variant.node_id}
    nodes = tuple(
        sorted(
            [root_variant, patched]
            + [node for node in graph.nodes if node.semantic_id != "task.root"],
            key=lambda item: item.node_id,
        )
    )
    allowed = {tuple(item) for item in catalog["allowed_edges"]}
    edges = []
    for edge in graph.edges:
        source = next(node for node in nodes if node.node_id == remap.get(edge.source_id, edge.source_id))
        target = next(node for node in nodes if node.node_id == remap.get(edge.target_id, edge.target_id))
        edges.append(_edge(source, target, edge.edge_type, allowed))
    edges.append(
        _edge(
            root_variant,
            patched,
            "contains" if node_type == "presentation_control" else "requires",
            allowed,
        )
    )
    result = PromptTSG(
        graph.schema_version,
        graph.task_id,
        content_hash(variant_prompt),
        graph.extractor_id,
        graph.catalog_sha256,
        nodes,
        tuple(sorted(edges, key=lambda item: item.edge_id)),
        graph.unresolved_semantics,
        graph.unresolved_relations,
    )
    validate_prompt_tsg(result, prompt=variant_prompt, catalog=catalog)
    return result


def query_for_realization(
    catalog: Mapping[str, Any], realization_id: str
) -> dict[str, Any]:
    matches = [item for item in catalog["queries"] if item["realization_id"] == realization_id]
    if len(matches) != 1:
        raise PromptTSGError("realization does not bind exactly one context query")
    return dict(matches[0])


def _node(
    node_type: str,
    semantic_id: str,
    evidence_start: int,
    evidence_end: int,
    evidence_text: str,
    attributes: Mapping[str, bool],
) -> TSGNode:
    normalized = " ".join(evidence_text.casefold().split())
    core = {
        "node_type": node_type,
        "semantic_id": semantic_id,
        "evidence_start": evidence_start,
        "evidence_end": evidence_end,
        "evidence_sha256": content_hash(evidence_text),
        "normalized_text_sha256": content_hash(normalized),
        "attributes": tuple(sorted(attributes.items())),
    }
    return TSGNode(content_id("tsg_node_", core), **core)


def _edge(
    source: TSGNode,
    target: TSGNode,
    edge_type: str,
    allowed: set[tuple[str, str, str]],
) -> TSGEdge:
    if (source.node_type, edge_type, target.node_type) not in allowed:
        raise PromptTSGError("Prompt TSG edge violates the type matrix")
    core = {"source_id": source.node_id, "target_id": target.node_id, "edge_type": edge_type}
    return TSGEdge(content_id("tsg_edge_", core), **core)


def _occurrence_span(prompt: str, evidence: str, occurrence: int) -> tuple[int, int]:
    starts = []
    offset = 0
    while True:
        found = prompt.find(evidence, offset)
        if found < 0:
            break
        starts.append(found)
        offset = found + 1
    if occurrence <= len(starts):
        start = starts[occurrence - 1]
        return start, start + len(evidence)
    tokens = evidence.split()
    if not tokens:
        raise PromptTSGError("Prompt TSG evidence does not match the prompt")
    matches = list(re.finditer(r"\s+".join(re.escape(token) for token in tokens), prompt))
    if occurrence > len(matches):
        raise PromptTSGError("Prompt TSG evidence does not match the prompt")
    match = matches[occurrence - 1]
    return match.start(), match.end()


def _unique_strings(value: object, name: str) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        raise PromptTSGError(f"Prompt TSG {name} are invalid")
    return tuple(value)


def _validate_query(
    query: object,
    semantics: Mapping[str, str],
    edge_types: Iterable[str],
    allowed_edges: set[tuple[str, str, str]],
) -> None:
    required = {
        "query_id",
        "realization_id",
        "cwe_id",
        "task_family",
        "required_semantics",
        "forbidden_semantics",
        "required_relations",
        "actionable_feature_id",
    }
    if not isinstance(query, dict) or set(query) != required:
        raise PromptTSGError("Prompt TSG query fields are invalid")
    for field in ("query_id", "realization_id", "cwe_id", "task_family"):
        if not isinstance(query[field], str) or not query[field].strip():
            raise PromptTSGError("Prompt TSG query identity is invalid")
    needed = _unique_strings(query["required_semantics"], "required query semantics")
    forbidden = _unique_strings(query["forbidden_semantics"], "forbidden query semantics")
    feature = query["actionable_feature_id"]
    if (
        not needed
        or set(needed) & set(forbidden)
        or any(item not in semantics for item in (*needed, *forbidden))
        or semantics.get(feature) != "safety_requirement"
    ):
        raise PromptTSGError("Prompt TSG query semantics are invalid")
    relation_types = set(edge_types)
    seen = set()
    for relation in query["required_relations"]:
        if (
            not isinstance(relation, list)
            or len(relation) != 3
            or relation[0] not in semantics
            or relation[1] not in relation_types
            or relation[2] not in semantics
            or (semantics[relation[0]], relation[1], semantics[relation[2]])
            not in allowed_edges
            or tuple(relation) in seen
        ):
            raise PromptTSGError("Prompt TSG query relation is invalid")
        seen.add(tuple(relation))


__all__ = [
    "PromptTSG",
    "PromptTSGError",
    "QueryResult",
    "QueryState",
    "TSGEdge",
    "TSGNode",
    "apply_feature_patch",
    "build_prompt_tsg",
    "catalog_from_record",
    "catalog_sha256",
    "feature_state",
    "load_catalog",
    "prompt_tsg_from_record",
    "prompt_tsg_record",
    "query_context",
    "query_for_realization",
    "validate_prompt_tsg",
]

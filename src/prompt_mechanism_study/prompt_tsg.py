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
class FeatureScope:
    """Exact task-local scope; an empty subject set never means all child inputs."""

    operation_node_id: str
    subject_node_ids: tuple[str, ...] = ()
    condition_node_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScopedFeatureAssessment:
    scope: FeatureScope
    feature_id: str
    state: str
    requirement_node_ids: tuple[str, ...] = ()


def feature_scope_from_record(value: Mapping[str, Any]) -> FeatureScope:
    if (not isinstance(value, Mapping)
        or set(value) != {"operation_node_id", "subject_node_ids", "condition_node_ids"}
        or any(not isinstance(value[field], (list, tuple)) or any(not isinstance(key, str) for key in value[field])
               for field in ("subject_node_ids", "condition_node_ids"))):
        raise PromptTSGError("feature scope fields are invalid")
    return FeatureScope(value["operation_node_id"], tuple(value["subject_node_ids"]),
                        tuple(value["condition_node_ids"]))


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
    # Schema 3 stores explicit negative assessments; omission remains unknown.
    absent_semantics: tuple[str, ...] = ()
    feature_assessments: tuple[tuple[str, str, str], ...] = ()
    scoped_feature_assessments: tuple[ScopedFeatureAssessment, ...] = ()
    # Complete requirement expressions; membership alone never asserts an OR/NOT leaf.
    requirement_structures: tuple[tuple[str, str, tuple[str, ...]], ...] = ()

    @property
    def tsg_id(self) -> str:
        payload = canonical_value(self)
        if not self.scoped_feature_assessments:
            payload.pop("scoped_feature_assessments")  # Keep frozen graph identities.
        if not self.requirement_structures:
            payload.pop("requirement_structures")
        if self.schema_version != "3.0":
            payload.pop("absent_semantics")
            payload.pop("feature_assessments")
        if self.schema_version == "1.0":
            payload.pop("unresolved_relations")
        return content_id("prompt_tsg_", payload)


@dataclass(frozen=True, slots=True)
class QueryResult:
    query_id: str
    state: QueryState
    evidence_node_ids: tuple[str, ...]
    evidence_edge_ids: tuple[str, ...]


REQUIREMENT_TYPES = {"task_requirement", "safety_requirement", "constraint", "presentation_control"}


def requirement_membership(structures, requirement_ids):
    """Validate a finite expression forest and return asserted expressions and atomic leaves.

    Only conjunction distributes an obligation. OR, compound NOT and opaque
    expressions retain their full meaning without asserting their members.
    """
    ids = set(requirement_ids)
    rows = {}
    for key, kind, members in structures:
        if (key not in ids or key in rows or kind not in {"atom", "and", "or", "not", "opaque"}
            or not isinstance(members, (list, tuple)) or len(set(members)) != len(members)
            or not set(members) <= ids or key in members
            or kind in {"atom", "opaque"} and members
            or kind in {"and", "or"} and len(members) < 2
            or kind == "not" and len(members) != 1):
            raise PromptTSGError("requirement composition or members are invalid")
        rows[key] = (kind, tuple(members))
    children = [member for _, members in rows.values() for member in members]
    if len(children) != len(set(children)) or set(children) - set(rows):
        raise PromptTSGError("requirement members need one declared parent and a declared structure")
    active, visited = set(), set()
    def check(key):
        if key in active:
            raise PromptTSGError("requirement composition has a cycle")
        if key in visited:
            return
        active.add(key)
        for child in rows.get(key, ("atom", ()))[1]:
            check(child)
        active.remove(key)
        visited.add(key)
    for key in rows:
        check(key)
    asserted, atoms = set(), set()
    def entail(key):
        asserted.add(key)
        kind, members = rows.get(key, ("atom", ()))
        if kind == "atom":
            atoms.add(key)
        elif kind == "and":
            for member in members:
                entail(member)
    for key in ids - set(children):
        entail(key)
    return asserted, atoms


def graph_requirement_membership(graph):
    return requirement_membership(graph.requirement_structures,
        {n.node_id for n in graph.nodes if n.node_type in REQUIREMENT_TYPES})


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
    if isinstance(value, dict) and value.get("schema_version") == "2.0":
        required |= {"concept_policy", "normalization_map", "development_task_ids"}
        if "feature_scope_domains" in value:
            required.add("feature_scope_domains")
        if "semantic_layers" in value:
            required.add("semantic_layers")
        if "existing_value_return_operations" in value:
            required.add("existing_value_return_operations")
        if "feature_role_domains" in value:
            required |= {"feature_role_domains", "caller_supplied_concepts"}
        if "feature_subject_properties" in value:
            required.add("feature_subject_properties")
        if "source_name_terms" in value:
            required.add("source_name_terms")
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] not in {"1.0", "2.0"}:
        raise PromptTSGError("Prompt TSG catalog envelope is invalid")
    if value["schema_version"] == "2.0" and value["concept_policy"] not in {"DEVELOPMENT_OPEN", "FROZEN"}:
        raise PromptTSGError("open concepts may change only during development")
    if value["schema_version"] == "2.0":
        _unique_strings(value["development_task_ids"], "development task IDs")
        if (not isinstance(value["normalization_map"], dict)
            or any(not isinstance(key, str) or not isinstance(target, str)
                   or not key or target not in value["semantics"] for key, target in value["normalization_map"].items())):
            raise PromptTSGError("concept normalization map is invalid")
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
    if "existing_value_return_operations" in value:
        returning = _unique_strings(value["existing_value_return_operations"], "existing-value return operations")
        if any(semantics.get(key) != "task_operation" for key in returning):
            raise PromptTSGError("existing-value return semantics require declared operation concepts")
    if "semantic_layers" in value:
        layers = value["semantic_layers"]
        if (not isinstance(layers, dict) or set(layers) - (set(semantics) - {"task.root"})
            or value["concept_policy"] == "FROZEN" and set(layers) != set(semantics) - {"task.root"}
            or any(not isinstance(layer, str) or layer not in {"generation", "runtime"}
                   for layer in layers.values())):
            raise PromptTSGError("semantic layers must classify declared concepts, and every non-root concept when frozen")
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
        or (not source_families and value["schema_version"] == "1.0")
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
    if not isinstance(queries, list) or (not queries and value["schema_version"] == "1.0"):
        raise PromptTSGError("Prompt TSG queries are missing")
    query_ids = set()
    realization_ids = set()
    for query in queries:
        _validate_query(query, semantics, edge_types, allowed,
                        actionable_types=("safety_requirement", "task_requirement", "presentation_control", "constraint")
                        if value["schema_version"] == "2.0" else ("safety_requirement",))
        if query["query_id"] in query_ids or query["realization_id"] in realization_ids:
            raise PromptTSGError("Prompt TSG query identities are not unique")
        query_ids.add(query["query_id"])
        realization_ids.add(query["realization_id"])
    if "feature_scope_domains" in value:
        domains = value["feature_scope_domains"]
        if (not isinstance(domains, dict)
            or set(domains) != {query["actionable_feature_id"] for query in queries}
            or any(not isinstance(domain, str) or domain not in {"operation", "subjects"}
                   for domain in domains.values())):
            raise PromptTSGError("feature scope domains must declare operation or subjects for every queried feature")
    if "feature_role_domains" in value:
        rules = value["feature_role_domains"]
        callers = _unique_strings(value["caller_supplied_concepts"], "caller-supplied concepts")
        if (not isinstance(rules, dict) or not rules
            or any(semantics.get(key) != "data_object" for key in callers)):
            raise PromptTSGError("feature role domains require declared source-object meanings")
        for feature, rule in rules.items():
            if (value.get("feature_scope_domains", {}).get(feature) != "subjects"
                or not isinstance(rule, dict)
                or set(rule) != {"applicable_roles", "inapplicable_roles", "caller_supplied_only"}
                or type(rule["caller_supplied_only"]) is not bool):
                raise PromptTSGError("feature role domain must declare a subject-role rule")
            positive = _unique_strings(rule["applicable_roles"], "applicable subject roles")
            negative = _unique_strings(rule["inapplicable_roles"], "inapplicable subject roles")
            if (not positive or set(positive) & set(negative)
                or (set(positive) | set(negative)) - {"value_input", "identifier_input", "resource", "destination"}):
                raise PromptTSGError("feature role domain must preserve unspecified and conflicting roles")
    if "feature_subject_properties" in value:
        properties = value["feature_subject_properties"]
        if (not isinstance(properties, dict) or not properties
            or any(value.get("feature_scope_domains", {}).get(feature) != "subjects"
                   or name != "character_sequence" or feature in value.get("feature_role_domains", {})
                   for feature, name in properties.items())):
            raise PromptTSGError("feature subject properties require a non-conflicting subject-domain declaration")
    if "source_name_terms" in value:
        names = value["source_name_terms"]
        if (not isinstance(names, dict) or not names
            or any(key not in semantics or key == "task.root" for key in names)):
            raise PromptTSGError("source name terms require declared non-root concepts")
        for terms in names.values():
            if not _unique_strings(terms, "source name terms"):
                raise PromptTSGError("source name terms cannot be empty")
    return value


def has_required_source_name(catalog: Mapping[str, Any], concept_id: str, text: str) -> bool:
    """Check a declared literal name prerequisite, never semantic entailment or absence."""
    terms = catalog.get("source_name_terms", {}).get(concept_id, [])
    return not terms or any(re.search(r"(?<![A-Za-z0-9_])" + re.escape(term)
        + r"(?![A-Za-z0-9_])", text, flags=re.IGNORECASE) for term in terms)


def catalog_sha256(catalog: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(catalog).encode("utf-8")).hexdigest()


def prompt_tsg_record(graph: PromptTSG) -> dict[str, Any]:
    """Return the canonical JSON record, including its content identity."""

    payload = canonical_value(graph)
    if not graph.scoped_feature_assessments:
        payload.pop("scoped_feature_assessments")
    if not graph.requirement_structures:
        payload.pop("requirement_structures")
    if graph.schema_version != "3.0":
        payload.pop("absent_semantics")
        payload.pop("feature_assessments")
    if graph.schema_version == "1.0":
        payload.pop("unresolved_relations")
    return {"tsg_id": graph.tsg_id, **payload}


def prompt_tsg_from_record(value: Mapping[str, Any]) -> PromptTSG:
    """Reconstruct a graph record before prompt- and catalog-aware validation."""

    if not isinstance(value, Mapping) or value.get("schema_version") not in {"1.0", "2.0", "3.0"}:
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
    if value["schema_version"] in {"2.0", "3.0"}:
        expected.add("unresolved_relations")
    if value["schema_version"] == "3.0":
        expected |= {"absent_semantics", "feature_assessments"}
        if "scoped_feature_assessments" in value:
            expected.add("scoped_feature_assessments")
        if "requirement_structures" in value:
            expected.add("requirement_structures")
    if set(value) != expected:
        raise PromptTSGError("Prompt TSG serialized fields are invalid")
    try:
        if any(set(item) != {"scope", "feature_id", "state", "requirement_node_ids"}
               for item in value.get("scoped_feature_assessments", ())):
            raise PromptTSGError("scoped feature assessment serialized fields are invalid")
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
            tuple(value.get("absent_semantics", ())),
            tuple(tuple(item) for item in value.get("feature_assessments", ())),
            tuple(ScopedFeatureAssessment(feature_scope_from_record(item["scope"]),
                item["feature_id"], item["state"], tuple(item["requirement_node_ids"]))
                for item in value.get("scoped_feature_assessments", ())),
            tuple((key, kind, tuple(members)) for key, kind, members in value.get("requirement_structures", ())),
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
    absent_semantics: Sequence[str] = (),
    feature_assessments: Sequence[Sequence[str]] = (),
    scoped_feature_assessments: Sequence[Mapping[str, Any]] = (),
    requirement_structures: Mapping[str, Mapping[str, Any]] | None = None,
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
        if not has_required_source_name(catalog, semantic_id, evidence):
            raise PromptTSGError("named concept lacks its required literal name in source evidence")
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
            "condition",
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
    if schema_version not in {"1.0", "2.0", "3.0"} or (
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
        tuple(sorted(absent_semantics)),
        tuple(sorted((local_nodes[target].node_id, feature, state)
                     for target, feature, state in feature_assessments)),
        tuple(sorted((ScopedFeatureAssessment(
            FeatureScope(local_nodes[row["target"]].node_id,
                tuple(sorted(local_nodes[key].node_id for key in row["subjects"])),
                tuple(sorted(local_nodes[key].node_id for key in row["conditions"]))),
            row["concept_id"], row["state"],
            tuple(sorted(local_nodes[key].node_id for key in row["requirements"])))
            for row in scoped_feature_assessments), key=lambda item: canonical_json(item))),
        tuple(sorted((local_nodes[key].node_id, row["kind"],
            tuple(sorted(local_nodes[member].node_id for member in row["members"])))
            for key, row in (requirement_structures or {}).items())),
    )
    validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    return graph


def validate_prompt_tsg(
    graph: PromptTSG, *, prompt: str, catalog: Mapping[str, Any]
) -> None:
    """Revalidate graph identity, evidence, endpoints, ordering, and catalog closure."""

    if (
        graph.schema_version not in {"1.0", "2.0", "3.0"}
        or (graph.schema_version != "3.0" and (graph.absent_semantics or graph.feature_assessments or graph.scoped_feature_assessments))
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
    asserted_requirements, atomic_requirements = graph_requirement_membership(graph)
    if graph.requirement_structures != tuple(sorted(graph.requirement_structures)):
        raise PromptTSGError("requirement structures must be ordered")
    guard_owners = {}
    for edge in graph.edges:
        if edge.edge_type == 'conditions':
            guard_owners.setdefault(edge.target_id, set()).add(edge.source_id)
    if any(not guard_owners.get(parent, set()) <= guard_owners.get(child, set())
           for parent, _, members in graph.requirement_structures for child in members):
        raise PromptTSGError('a composite member lost an inherited requirement condition')
    if graph.schema_version == "3.0":
        present = {node.semantic_id for node in graph.nodes}
        if (graph.absent_semantics != tuple(sorted(set(graph.absent_semantics)))
            or set(graph.absent_semantics) - set(semantics)
            or set(graph.absent_semantics) & (present | set(graph.unresolved_semantics))
            or present & set(graph.unresolved_semantics)):
            raise PromptTSGError("explicit concept states conflict")
        keys = [(target, feature) for target, feature, _ in graph.feature_assessments]
        if len(keys) != len(set(keys)):
            raise PromptTSGError("operation feature assessments are duplicated")
        for target, feature, state in graph.feature_assessments:
            if (target not in node_by_id or node_by_id[target].node_type != "task_operation"
                or feature not in semantics or state not in {"present", "absent", "unresolved", "not_applicable"}):
                raise PromptTSGError("operation feature assessment is invalid")
            mentioned = {edge.source_id for edge in graph.edges if edge.edge_type == 'constrains'
                         and edge.target_id == target and node_by_id[edge.source_id].semantic_id == feature}
            if state == 'present' and not mentioned & atomic_requirements:
                raise PromptTSGError('operation presence needs an asserted atomic requirement')
            if state in {'absent','not_applicable'} and mentioned:
                raise PromptTSGError('operation negative contradicts a source requirement expression')
            if state != "unresolved" and catalog.get("feature_scope_domains", {}).get(feature) == "subjects":
                raise PromptTSGError("feature scope domain requires named subjects")
        scoped = graph.scoped_feature_assessments
        if (scoped != tuple(sorted(scoped, key=lambda item: canonical_json(item)))
            or len({(item.scope, item.feature_id) for item in scoped}) != len(scoped)):
            raise PromptTSGError("scoped feature assessments must be ordered and unique")
        for item in scoped:
            validate_feature_scope(graph, item.scope)
            domain = catalog.get("feature_scope_domains", {}).get(item.feature_id)
            if item.state != "unresolved" and (
                domain == "subjects" and not item.scope.subject_node_ids
                or domain == "operation" and item.scope.subject_node_ids
            ):
                raise PromptTSGError("feature scope domain does not match its subject binding")
            if (semantics.get(item.feature_id) not in
                    {"task_requirement", "safety_requirement", "constraint", "presentation_control"}
                or item.state not in {state.value for state in QueryState}
                or item.requirement_node_ids != tuple(sorted(set(item.requirement_node_ids)))
                or (item.state == "present") != bool(item.requirement_node_ids)):
                raise PromptTSGError("scoped feature state or evidence is invalid")
            if set(item.requirement_node_ids) - atomic_requirements:
                raise PromptTSGError("scoped presence needs an asserted atomic requirement, not a composite member")
            links = {(edge.source_id, edge.edge_type, edge.target_id) for edge in graph.edges}
            if item.state in {"absent", "not_applicable"}:
                for requirement in graph.nodes:
                    key = requirement.node_id
                    if (requirement.semantic_id != item.feature_id
                        or (key, "constrains", item.scope.operation_node_id) not in links):
                        continue
                    covered = {target for source, relation, target in links
                               if source == key and relation == "constrains"
                               and node_by_id[target].node_type == "data_object"}
                    fixed = {source for source, relation, target in links if relation == "conditions"
                             and target in {key, item.scope.operation_node_id}}
                    subjects = set(item.scope.subject_node_ids)
                    conditions = set(item.scope.condition_node_ids)
                    # A partial or conditional positive cannot be relabeled as
                    # an unqualified negative for the whole operation/input set.
                    if ((not subjects or not covered or subjects & covered)
                        and (fixed <= conditions or conditions <= fixed)):
                        raise PromptTSGError("scoped negative contradicts source requirement coverage")
            for key in item.requirement_node_ids:
                if (key not in node_by_id or node_by_id[key].semantic_id != item.feature_id
                    or not requirement_covers_scope(key, item.scope.operation_node_id,
                        item.scope.subject_node_ids, item.scope.condition_node_ids, links=links,
                        node_types={k: n.node_type for k, n in node_by_id.items()})):
                    raise PromptTSGError("scoped presence lacks exact requirement-to-scope evidence")
            # Mixing a new operation-scoped assessment with a frozen triple must agree.
            if not item.scope.subject_node_ids and not item.scope.condition_node_ids:
                old = {(target, feature): state for target, feature, state in graph.feature_assessments}
                if old.get((item.scope.operation_node_id, item.feature_id), item.state) != item.state:
                    raise PromptTSGError("operation and scoped feature states conflict")
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
        if not has_required_source_name(catalog, node.semantic_id,
                                        prompt[node.evidence_start:node.evidence_end]):
            raise PromptTSGError("named concept lacks its required literal name in source evidence")
    for edge in graph.edges:
        source = node_by_id.get(edge.source_id)
        target = node_by_id.get(edge.target_id)
        if (
            source is None
            or target is None
            or edge.edge_type == "conditions" and source.node_type != "condition"
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


def requirement_covers_scope(requirement: str, operation: str, subjects: Sequence[str],
                            conditions: Sequence[str], *, links: set[tuple[str, str, str]],
                            node_types: Mapping[str, str]) -> bool:
    """Match existing requirement bindings; no source-completeness or absence inference."""
    source_subjects = {target for source, relation, target in links
                       if source == requirement and relation == "constrains"
                       and node_types.get(target) == "data_object"}
    source_conditions = {source for source, relation, target in links
                         if relation == "conditions" and target in {requirement, operation}}
    return ((requirement, "constrains", operation) in links
            and all((requirement, "constrains", subject) in links for subject in subjects)
            and not (source_subjects and not subjects)
            and source_conditions == set(conditions))


def validate_feature_scope(graph: PromptTSG, scope: FeatureScope) -> None:
    """Check local coordinates without inferring a semantic assessment from topology."""
    nodes = {node.node_id: node for node in graph.nodes}
    links = {(edge.source_id, edge.edge_type, edge.target_id) for edge in graph.edges}
    if scope.operation_node_id not in nodes or nodes[scope.operation_node_id].node_type != "task_operation":
        raise PromptTSGError("feature scope requires one operation instance")
    for keys in (scope.subject_node_ids, scope.condition_node_ids):
        if keys != tuple(sorted(set(keys))):
            raise PromptTSGError("feature scope coordinates must be sorted and unique")
    for key in scope.subject_node_ids:
        if (key not in nodes or nodes[key].node_type != "data_object"
            or (key, "used_by", scope.operation_node_id) not in links):
            raise PromptTSGError("factor subject must be a source-bound input of this operation")
    for key in scope.condition_node_ids:
        requirements = {source for source, relation, target in links
                        if relation == "constrains" and target == scope.operation_node_id}
        if (key not in nodes or nodes[key].node_type != "condition"
            or not (any((key, "conditions", target) in links
                       for target in requirements | {scope.operation_node_id})
                    or (key, "context_for", scope.operation_node_id) in links)):
            raise PromptTSGError("feature condition must have a source-bound relation to this operation")


def scoped_feature_assessment(
    graph: PromptTSG, feature_id: str, scope: FeatureScope,
) -> ScopedFeatureAssessment | None:
    validate_feature_scope(graph, scope)
    return next((item for item in graph.scoped_feature_assessments
                 if item.scope == scope and item.feature_id == feature_id), None)


def query_context(
    graph: PromptTSG,
    *,
    query: Mapping[str, Any],
    cwe: str,
    task_family: str,
) -> QueryResult:
    """Evaluate one catalog query with total four-valued semantics."""

    if graph.schema_version != "3.0" and (query["cwe_id"] != cwe or query["task_family"] != task_family):
        return QueryResult(query["query_id"], QueryState.NOT_APPLICABLE, (), ())
    by_semantic: dict[str, list[TSGNode]] = {}
    asserted, _ = graph_requirement_membership(graph)
    for node in graph.nodes:
        if node.node_type in REQUIREMENT_TYPES and node.node_id not in asserted:
            continue
        by_semantic.setdefault(node.semantic_id, []).append(node)
    required = set(query["required_semantics"])
    forbidden = set(query["forbidden_semantics"])
    present = set(by_semantic)
    unresolved = set(graph.unresolved_semantics)
    if graph.schema_version == "3.0":
        unresolved |= (required | forbidden) - present - set(graph.absent_semantics)

    # A context is a conjunction of positive and negative predicates.  A known
    # false predicate is decisive even when another predicate is unresolved;
    # uncertainty matters only when no part of the conjunction is already false.
    absent_required = required - present - unresolved
    present_forbidden = forbidden & present
    if absent_required or present_forbidden:
        return QueryResult(query["query_id"], QueryState.ABSENT, (), ())

    relevant = required | forbidden
    if relevant & unresolved:
        evidence = tuple(
            sorted(node.node_id for item in relevant for node in by_semantic.get(item, ()))
        )
        return QueryResult(query["query_id"], QueryState.UNRESOLVED, evidence, ())

    if graph.schema_version == "3.0":
        bindings = query_bindings(graph, query=query)
        if not bindings:
            # Open extraction records evidenced edges; an omitted relation is unknown.
            return QueryResult(query["query_id"], QueryState.UNRESOLVED, (), ())
        return QueryResult(query["query_id"], QueryState.PRESENT,
                           tuple(sorted({node for nodes, _ in bindings for node in nodes})),
                           tuple(sorted({edge for _, edges in bindings for edge in edges})))

    relation_matches = []
    unresolved_relation_evidence: set[str] = set()
    unresolved_relations = set(graph.unresolved_relations)
    for source_semantic, edge_type, target_semantic in query["required_relations"]:
        relation = (source_semantic, edge_type, target_semantic)
        if relation in unresolved_relations:
            unresolved_relation_evidence.update(
                node.node_id
                for semantic in (source_semantic, target_semantic)
                for node in by_semantic.get(semantic, ())
            )
            continue
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
            return QueryResult(query["query_id"], QueryState.ABSENT, (), ())
        relation_matches.extend(matches)
    if unresolved_relation_evidence:
        return QueryResult(
            query["query_id"],
            QueryState.UNRESOLVED,
            tuple(sorted(unresolved_relation_evidence)),
            (),
        )
    evidence_nodes = tuple(
        sorted(node.node_id for semantic in required for node in by_semantic[semantic])
    )
    evidence_edges = tuple(sorted(edge.edge_id for edge in relation_matches))
    return QueryResult(query["query_id"], QueryState.PRESENT, evidence_nodes, evidence_edges)


def query_bindings(graph: PromptTSG, *, query: Mapping[str, Any]) -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    """Join all relations on the same instances; unrelated operations cannot fill a motif."""
    asserted, _ = graph_requirement_membership(graph)
    nodes = {node.node_id: node for node in graph.nodes
             if node.node_type not in REQUIREMENT_TYPES or node.node_id in asserted}
    bindings = [({}, ())]
    for source, kind, target in query["required_relations"]:
        matches = [edge for edge in graph.edges if edge.edge_type == kind
                   and edge.source_id in nodes and edge.target_id in nodes
                   and nodes[edge.source_id].semantic_id == source
                   and nodes[edge.target_id].semantic_id == target]
        joined = []
        for binding, edges in bindings:
            for edge in matches:
                extension = {source: edge.source_id, target: edge.target_id}
                if all(key not in binding or binding[key] == value for key, value in extension.items()):
                    joined.append(({**binding, **extension}, (*edges, edge.edge_id)))
        bindings = joined
    for semantic in query["required_semantics"]:
        bindings = [(dict(binding, **{semantic: node.node_id}), edges)
                    for binding, edges in bindings
                    for node in nodes.values() if node.semantic_id == semantic
                    and (semantic not in binding or binding[semantic] == node.node_id)]
    return tuple(sorted(set((tuple(sorted(binding.values())), tuple(sorted(edges))) for binding, edges in bindings)))


def feature_state(graph: PromptTSG, feature_id: str, target_node_id: str | None = None,
                  *, scope: FeatureScope | None = None) -> QueryState:
    """Return whether one catalog-bound actionable Prompt feature is explicit."""

    if scope is not None:
        if target_node_id is not None and target_node_id != scope.operation_node_id:
            raise PromptTSGError("feature query contains conflicting operation coordinates")
        assessment = scoped_feature_assessment(graph, feature_id, scope)
        return QueryState(assessment.state) if assessment else QueryState.UNRESOLVED
    if graph.schema_version == "3.0" and target_node_id is not None:
        states = [state for target, feature, state in graph.feature_assessments
                  if target == target_node_id and feature == feature_id]
        if len(states) == 1:
            return QueryState(states[0])
        return feature_state(graph, feature_id, scope=FeatureScope(target_node_id))
    if feature_id in graph.unresolved_semantics:
        return QueryState.UNRESOLVED
    _, atoms = graph_requirement_membership(graph)
    mentioned = [node for node in graph.nodes if node.semantic_id == feature_id]
    if mentioned and not any(n.node_type not in REQUIREMENT_TYPES or n.node_id in atoms for n in mentioned):
        return QueryState.UNRESOLVED
    if graph.schema_version == "3.0" and not any(node.semantic_id == feature_id for node in graph.nodes):
        return QueryState.ABSENT if feature_id in graph.absent_semantics else QueryState.UNRESOLVED
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
    """Replay an archival non-instance arm patch (schema 1/2 only)."""

    if graph.schema_version == "3.0":
        raise PromptTSGError("open instance interventions must use render_task_hypothesis with an operation binding")

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
    actionable_types: Iterable[str] = ("safety_requirement",),
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
        or semantics.get(feature) not in actionable_types
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

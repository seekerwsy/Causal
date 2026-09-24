"""Source-only task contracts compiled into a canonical Prompt TSG."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSG,
    PromptTSGError,
    build_prompt_tsg,
    catalog_sha256,
    catalog_from_record,
    _occurrence_span,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id, require_text


_REVIEW_STATUSES = {"development_exposed", "prospective_frozen"}


def task_context_contract_record(contract: OpenTaskContract) -> dict[str, Any]:
    """Return one content-addressed open contract record."""
    record = canonical_value(contract)
    if record.get("source_inventory", False) is None:
        record.pop("source_inventory")
    return {"contract_id": contract.contract_id, **record}


def task_context_contract_from_record(value: Mapping[str, Any]) -> OpenTaskContract:
    """Parse the active source-only contract format."""
    if not isinstance(value, Mapping) or value.get("schema_version") != "3.0":
        raise PromptTSGError("open task contract format is required")
    try:
        record = dict(value)
        identity = record.pop("contract_id", None)
        for key in ("facts", "relations", "concept_states", "feature_states", "unresolved_notes"):
            record[key] = tuple(record[key])
        contract = OpenTaskContract(**record)
    except (KeyError, TypeError, ValueError):
        raise PromptTSGError("open task contract fields are invalid") from None
    if identity is not None and identity != contract.contract_id:
        raise PromptTSGError("open task contract identity is invalid")
    return contract


@dataclass(frozen=True, slots=True)
class OpenTaskContract:
    """Source-only instances with a development-open or frozen concept vocabulary."""

    schema_version: str
    task_id: str
    prompt_sha256: str
    input_catalog_sha256: str
    annotator_id: str
    review_status: str
    arms_or_outcomes_used: bool
    catalog: dict[str, Any]
    facts: tuple[dict[str, Any], ...]
    relations: tuple[dict[str, Any], ...]
    concept_states: tuple[dict[str, str], ...]
    feature_states: tuple[dict[str, Any], ...]
    unresolved_notes: tuple[str, ...]
    source_inventory: dict[str, Any] | None = None

    @property
    def contract_id(self) -> str:
        record = canonical_value(self)
        if self.source_inventory is None:
            # Authored contracts without extraction metadata retain their identity.
            record.pop("source_inventory")
        return content_id("open_task_contract_", record)


def open_concept_catalog() -> dict[str, Any]:
    """Generic roles only. Concrete concepts must come from exposed development text."""
    types = ["task", "data_object", "task_operation", "task_requirement", "safety_requirement", "constraint", "condition", "presentation_control"]
    allowed = [["task", "requires" if node_type == "safety_requirement" else "contains", node_type]
               for node_type in types if node_type != "task"]
    allowed += [["data_object", "used_by", "task_operation"],
                ["task_operation", "produces", "data_object"],
                ["task_operation", "precedes", "task_operation"]]
    allowed += [[source, "constrains", target]
                for source in ("task_requirement", "safety_requirement", "constraint", "presentation_control")
                for target in ("task_operation", "data_object")]
    allowed += [["condition", "conditions", target]
                for target in ("task_requirement", "safety_requirement", "task_operation", "constraint", "presentation_control")]
    allowed += [["condition", "context_for", "task_operation"]]
    return catalog_from_record({
        "schema_version": "2.0", "concept_policy": "DEVELOPMENT_OPEN",
        "node_types": types, "edge_types": sorted({row[1] for row in allowed}),
        "attribute_names": [], "semantic_guidance": {}, "semantics": {"task.root": "task"},
        "source_realization_task_families": {}, "allowed_edges": allowed,
        "queries": [], "normalization_map": {}, "development_task_ids": [],
    })


def _validate_source_inventory(contract: OpenTaskContract, *, prompt: str,
                               by_local: Mapping[str, Mapping[str, Any]]) -> None:
    """Check recorded source coverage and local roles, never infer their semantics."""
    inventory = contract.source_inventory
    if inventory is None:
        return
    if (not isinstance(inventory, dict)
        or set(inventory) - {"unit_impacts", "statement_kinds", "requirement_structures", "requirement_scopes", "requirement_relations"} != {"source_units", "coverage", "layers", "operation_roles"}
        or any(not isinstance(inventory[key], dict) for key in ("source_units", "coverage", "layers"))
        or not isinstance(inventory["operation_roles"], list)):
        raise PromptTSGError("source inventory fields are invalid")
    units, coverage, layers = (inventory[key] for key in ("source_units", "coverage", "layers"))
    from prompt_mechanism_study.tsg.prompt_tsg import requirement_membership, REQUIREMENT_TYPES
    structures = inventory.get("requirement_structures", {})
    if not isinstance(structures, dict) or any(set(row) != {"kind", "members"} for row in structures.values()):
        raise PromptTSGError("source requirement structures are invalid")
    requirement_membership([(key, row["kind"], row["members"]) for key, row in structures.items()],
        {key for key, fact in by_local.items() if fact["node_type"] in REQUIREMENT_TYPES})
    owned_relations = inventory.get("requirement_relations", {})
    if not isinstance(owned_relations, dict):
        raise PromptTSGError("owned requirement relations must be keyed by owner")
    for owner, rows in owned_relations.items():
        if (owner not in by_local or by_local[owner]['node_type'] not in REQUIREMENT_TYPES
            or layers.get(owner) != 'runtime' or not isinstance(rows, list) or not rows
            or structures.get(owner, {}).get('kind', 'atom') != 'atom'):
            raise PromptTSGError("owned relation needs a runtime requirement leaf")
        seen = set()
        for row in rows:
            if (not isinstance(row, dict)
                or set(row) != {'source', 'target', 'edge_type', 'evidence_text', 'occurrence'}
                or any(not isinstance(row[key], str) for key in ('source', 'target', 'edge_type', 'evidence_text'))
                or not row['evidence_text'].strip() or type(row['occurrence']) is not int
                or row['occurrence'] < 1):
                raise PromptTSGError("owned relation fields are invalid")
            source, kind, target = row['source'], row['edge_type'], row['target']
            if (kind != 'precedes' or source == target or (source, kind, target) in seen
                or any(key not in by_local or by_local[key]['node_type'] != 'task_operation'
                       or layers.get(key) != 'runtime' for key in (source, target))):
                raise PromptTSGError("owned relation endpoints or type are invalid")
            _occurrence_span(prompt, row['evidence_text'], row['occurrence'])
            seen.add((source, kind, target))
    modalities = inventory.get('statement_kinds', {})
    for key, row in inventory.get('requirement_scopes', {}).items():
        if (key not in by_local or by_local[key]['node_type'] not in REQUIREMENT_TYPES
            or layers.get(key)!='runtime' or set(row)!={'kind','boundaries','target_class'}
            or row['kind'] not in {'task','each'} or not isinstance(row['boundaries'],list)
            or len(row['boundaries'])>1 or any(b not in by_local or by_local[b]['node_type']!='task_operation'
                or layers.get(b)!='runtime' for b in row['boundaries'])
            or row['kind']=='task' and (row['boundaries'] or row['target_class'] is not None)
            or row['kind']=='each' and (not isinstance(row['target_class'],str) or not row['target_class'].strip())
            or any(e['source']==key and e['edge_type']=='constrains' for e in contract.relations)):
            raise PromptTSGError('retained requirement scope is invalid or was distributed')
    if any(modalities.get(member, 'obligation') != modalities.get(key, 'obligation')
           for key,row in structures.items() for member in row['members']):
        raise PromptTSGError('composite members cannot change their parent modality')
    for key, kind in inventory.get("statement_kinds", {}).items():
        if (key not in by_local or kind not in {"obligation", "assumption", "unresolved"}
            or by_local[key]["node_type"] not in {"task_requirement", "safety_requirement", "constraint", "presentation_control"}
            or kind != "obligation" and by_local[key]["node_type"] != "constraint"):
            raise PromptTSGError("source statement modality is invalid")
    if (any(not isinstance(key, str) or not key for key in units)
        or set(coverage) != set(units) or set(layers) != set(by_local)):
        raise PromptTSGError("source inventory coverage or layer keys are incomplete")
    if any(not isinstance(layer, str) or layer not in {"generation", "runtime", "unresolved"}
           for layer in layers.values()):
        raise PromptTSGError("source inventory layer is invalid")
    if "unit_impacts" in inventory:
        impacts = inventory["unit_impacts"]
        if not isinstance(impacts, dict) or set(impacts) != set(units):
            raise PromptTSGError("source impact review must cover every source unit")
        operations = {key for key, fact in by_local.items()
                      if fact["node_type"] == "task_operation" and layers[key] == "runtime"}
        for row in impacts.values():
            if (not isinstance(row, dict) or set(row) - {"evidence_text", "occurrence"} != {"effect", "operations", "complete", "reason"}
                or row["effect"] not in {"local", "global", "unresolved", "no_runtime_effect"}
                or type(row["complete"]) is not bool or not isinstance(row["reason"], str) or not row["reason"].strip()
                or not isinstance(row["operations"], list)
                or any(not isinstance(key, str) or key not in operations for key in row["operations"])
                or len(set(row["operations"])) != len(row["operations"])
                or (row["effect"] == "local") != bool(row["operations"])
                or row["effect"] == "unresolved" and row["complete"]):
                raise PromptTSGError("source impact decision is invalid")
            if "evidence_text" in row or "occurrence" in row:
                _occurrence_span(prompt, row.get("evidence_text"), row.get("occurrence"))

    def citation(row):
        if (not isinstance(row["evidence_text"], str) or not row["evidence_text"].strip()
            or type(row["occurrence"]) is not int or row["occurrence"] < 1):
            raise PromptTSGError("source inventory citation is invalid")
        _occurrence_span(prompt, row["evidence_text"], row["occurrence"])

    for key, unit in units.items():
        if not isinstance(unit, dict) or set(unit) != {"evidence_text", "occurrence"}:
            raise PromptTSGError("source unit fields are invalid")
        citation(unit)
        row = coverage[key]
        if (not isinstance(row, dict) or set(row) != {"facts", "status", "reason"}
            or not isinstance(row["facts"], list)
            or any(not isinstance(fact, str) or fact not in by_local for fact in row["facts"])
            or len(row["facts"]) != len(set(row["facts"]))
            or not isinstance(row["status"], str)
            or row["status"] not in {"represented", "unresolved", "no_task_fact"}
            or not isinstance(row["reason"], str) or not row["reason"].strip()
            or row["status"] == "represented" and not row["facts"]
            or row["status"] == "no_task_fact" and row["facts"]):
            raise PromptTSGError("source coverage decision is invalid")

    input_roles = {"value_input", "identifier_input", "resource", "destination", "input_unspecified"}
    roles = set()
    for row in inventory["operation_roles"]:
        if (not isinstance(row, dict)
            or set(row) != {"operation", "subject", "role", "evidence_text", "occurrence"}
            or any(not isinstance(row[key], str) for key in ("operation", "subject", "role"))):
            raise PromptTSGError("operation-local role fields are invalid")
        operation, subject, role = row["operation"], row["subject"], row["role"]
        if (operation not in by_local or subject not in by_local
            or by_local[operation]["node_type"] != "task_operation"
            or by_local[subject]["node_type"] != "data_object"
            or layers[operation] != "runtime" or layers[subject] != "runtime"
            or role not in input_roles | {"result"}):
            raise PromptTSGError("operation-local role endpoints or layer are invalid")
        citation(row)
        identity = (operation, subject, role)
        if identity in roles:
            raise PromptTSGError("operation-local role is duplicated")
        roles.add(identity)
    for edge in contract.relations:
        source, target, relation = edge["source"], edge["target"], edge["edge_type"]
        if (source not in by_local or target not in by_local
            or layers[source] == "unresolved" or layers[source] != layers[target]):
            raise PromptTSGError("relation requires endpoints in the same resolved layer")
        if relation == "used_by" and not any((target, source, role) in roles for role in input_roles):
            raise PromptTSGError("used_by relation lacks its operation-local input role")
        if relation == "produces" and (source, target, "result") not in roles:
            raise PromptTSGError("produces relation lacks its operation-local result role")
        if relation == "precedes" and layers[source] != "runtime":
            raise PromptTSGError("precedes relation requires runtime operations")


def compile_task_context_contract(
    contract: OpenTaskContract, *, prompt: str, catalog: Mapping[str, Any],
) -> PromptTSG:
    """Compile the source record once; structural checks do not certify meaning."""
    if not isinstance(contract, OpenTaskContract):
        raise PromptTSGError("open task contract is required")
    if (contract.schema_version != "3.0" or contract.prompt_sha256 != content_hash(prompt)
        or contract.input_catalog_sha256 != catalog_sha256(catalog)
        or contract.arms_or_outcomes_used is not False or contract.review_status not in _REVIEW_STATUSES):
        raise PromptTSGError("open contract envelope is invalid")
    derived = catalog_from_record(contract.catalog)
    if catalog["concept_policy"] == "FROZEN" and derived != catalog:
        raise PromptTSGError("frozen vocabulary changed during extraction")
    if catalog["concept_policy"] == "DEVELOPMENT_OPEN":
        # Development may append source meanings, never alter the supplied
        # candidate family, domain rules or known concept definitions.
        extensible = {"semantics", "semantic_guidance"}
        if ({k: v for k, v in derived.items() if k not in extensible}
            != {k: v for k, v in catalog.items() if k not in extensible}
            or any(derived[field].get(key) != value
                   for field in extensible for key, value in catalog[field].items())):
            raise PromptTSGError("open source meanings cannot change supplied concepts or candidate rules")
    by_local = {fact["local_id"]: fact for fact in contract.facts}
    if len(by_local) != len(contract.facts):
        raise PromptTSGError("task-local instances must be unique")
    edges = []
    for row in contract.relations:
        if set(row) != {"source", "target", "edge_type", "evidence_text", "occurrence"}:
            raise PromptTSGError("open relation fields are invalid")
        _occurrence_span(prompt, row["evidence_text"], row["occurrence"])
        edges.append({key: row[key] for key in ("source", "target", "edge_type")})
    _validate_source_inventory(contract, prompt=prompt, by_local=by_local)
    present = {fact["semantic_id"] for fact in contract.facts}
    states = {}
    for row in contract.concept_states:
        if (set(row) != {"concept_id", "state", "rationale"}
            or row["concept_id"] not in derived["semantics"] or row["concept_id"] in states
            or row["state"] not in {"present", "absent", "unresolved"}):
            raise PromptTSGError("concept assessment is invalid")
        require_text(row["rationale"], "concept assessment rationale")
        if (row["state"] == "present") != (row["concept_id"] in present):
            raise PromptTSGError("concept assessment contradicts its evidence")
        states[row["concept_id"]] = row["state"]
    # Missing negative assessments remain unresolved. A frozen vocabulary closes
    # the allowed meanings; it does not turn an omitted label into absence or
    # erase independently source-bound positive facts elsewhere in the task.
    features, scoped_features = [], []
    for row in contract.feature_states:
        basic = {"target", "concept_id", "state", "rationale"}
        scoped = set(row) == basic | {"subjects", "conditions", "requirements"}
        if set(row) != basic and not scoped:
            raise PromptTSGError("operation feature assessment fields are invalid")
        target, concept, state = row["target"], row["concept_id"], row["state"]
        boundary = (scoped and target == "task.root"
                    and concept in derived.get("feature_scope_selectors", {}))
        if (target not in by_local and not boundary) or concept not in derived["semantics"]:
            raise PromptTSGError("operation feature assessment is outside the graph")
        require_text(row["rationale"], "feature assessment rationale")
        if scoped:
            if any(key not in by_local for field in ("subjects", "conditions", "requirements") for key in row[field]):
                raise PromptTSGError("feature scope or evidence is outside the graph")
            scoped_features.append(row)
            continue
        bindings = [edge for edge in edges if edge["target"] == target and edge["edge_type"] == "constrains"
                    and by_local.get(edge["source"], {}).get("semantic_id") == concept]
        if (state == "present") != bool(bindings):
            raise PromptTSGError("feature assessment contradicts its operation binding")
        features.append((target, concept, state))
    # A missing requested scope has no assessment and feature_state returns
    # UNRESOLVED. Qualification and the source gate retain that failure.
    absent = {key for key, state in states.items() if state == "absent"}
    unresolved = set(derived["semantics"]) - present - absent - {"task.root"}
    return build_prompt_tsg(task_id=contract.task_id, prompt=prompt,
        extractor_id=f"open-contract:{contract.contract_id}", catalog=derived,
        facts=contract.facts, relations=edges, schema_version="3.0",
        absent_semantics=sorted(absent), unresolved_semantics=sorted(unresolved),
        feature_assessments=features, scoped_feature_assessments=scoped_features,
        requirement_structures=(contract.source_inventory or {}).get("requirement_structures", {}),
        requirement_scopes=(contract.source_inventory or {}).get("requirement_scopes", {}),
        requirement_relations=(contract.source_inventory or {}).get("requirement_relations", {}))


def freeze_open_concepts(
    contracts: tuple[OpenTaskContract, ...], *, normalization_map: Mapping[str, str],
    definitions: Mapping[str, str], queries: list[dict[str, Any]],
    seed_semantics: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Freeze reviewed semantic equivalences from source-only development contracts."""
    catalog = open_concept_catalog()
    # Seeds are explicit inputs, recorded separately in the normalization review.
    # They are not counted as concepts discovered from these task annotations.
    catalog["semantics"].update(seed_semantics or {})
    for contract in contracts:
        if contract.review_status != "development_exposed" or contract.arms_or_outcomes_used:
            raise PromptTSGError("concept development cannot use protected tasks or outcomes")
        for fact in contract.facts:
            concept = normalization_map.get(fact["node_type"] + "::" + fact["semantic_id"],
                                           normalization_map.get(fact["semantic_id"], fact["semantic_id"]))
            if concept not in definitions:
                raise PromptTSGError("every canonical concept requires its reviewed definition")
            previous = catalog["semantics"].get(concept, fact["node_type"])
            if previous != fact["node_type"]:
                raise PromptTSGError("normalization cannot merge different semantic roles")
            catalog["semantics"][concept] = fact["node_type"]
    catalog.update(concept_policy="FROZEN", normalization_map=dict(normalization_map),
                   semantic_guidance=dict(definitions), queries=queries,
                   development_task_ids=sorted({contract.task_id for contract in contracts}))
    return catalog_from_record(catalog)


__all__ = [
    "compile_task_context_contract",
    "task_context_contract_from_record",
    "task_context_contract_record",
]

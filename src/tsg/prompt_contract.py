"""Source-only task contracts compiled into a canonical Prompt TSG."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSG,
    PromptTSGError,
    REQUIREMENT_TYPES,
    build_prompt_tsg,
    catalog_sha256,
    catalog_from_record,
    _occurrence_span,
    prompt_tsg_record,
    source_nodes,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id, require_text


_REVIEW_STATUSES = {"development_exposed", "prospective_frozen"}


def resolve_evidence_span(
    prompt: str,
    quote: str,
    occurrence: int = 1,
    *,
    tolerant: bool = True,
) -> tuple[int, int] | None:
    """Resolve an evidence quote to prompt character bounds, with whitespace/backtick tolerance."""
    if (
        not isinstance(prompt, str)
        or not isinstance(quote, str)
        or not quote.strip()
        or type(occurrence) is not int
        or occurrence < 1
    ):
        return None

    def _exact_match(candidate: str) -> tuple[int, int] | None:
        if not candidate:
            return None
        starts: list[int] = []
        offset = 0
        while True:
            found = prompt.find(candidate, offset)
            if found < 0:
                break
            starts.append(found)
            offset = found + 1
        if occurrence <= len(starts):
            start = starts[occurrence - 1]
            return start, start + len(candidate)
        return None

    def _ws_match(candidate: str) -> tuple[int, int] | None:
        tokens = candidate.split()
        if not tokens:
            return None
        pattern = r"\s+".join(re.escape(token) for token in tokens)
        matches = list(re.finditer(pattern, prompt))
        if occurrence <= len(matches):
            return matches[occurrence - 1].start(), matches[occurrence - 1].end()
        return None

    exact = _exact_match(quote)
    if exact is not None or not tolerant:
        return exact

    ws_hit = _ws_match(quote)
    if ws_hit is not None:
        return ws_hit

    stripped = quote.strip()
    variants: list[str] = []
    if "`" in stripped:
        no_ticks = stripped.strip("`").strip()
        if no_ticks and no_ticks != quote:
            variants.append(no_ticks)
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        unquoted = stripped[1:-1].strip()
        if unquoted and unquoted != quote:
            variants.append(unquoted)
    for variant in variants:
        hit = _exact_match(variant) or _ws_match(variant)
        if hit is not None:
            return hit
    return None


def _exact_occurrence_index(prompt: str, matched_text: str, start: int) -> int:
    starts: list[int] = []
    offset = 0
    while True:
        found = prompt.find(matched_text, offset)
        if found < 0:
            break
        starts.append(found)
        offset = found + 1
    return starts.index(start) + 1


def compile_source_propositions(task, record, *, extractor_id, tolerant: bool = False):
    if task['task_unit_id'] != record['task_unit_id']:
        raise PromptTSGError('来源命题与任务身份不同')
    catalog = open_concept_catalog()
    catalog['attribute_names'] = ['binding_complete', 'descriptive_force', 'normative_force']
    for semantic, concept in record['concepts'].items():
        if semantic == 'task.root' or concept['node_type'] not in catalog['node_types'] or concept['node_type'] == 'task':
            raise PromptTSGError('来源概念类型无效')
        catalog['semantics'][semantic] = concept['node_type']
        require_text(concept['meaning'], 'concept meaning')
        catalog['semantic_guidance'][semantic] = concept['meaning']
    roles = {'about_operation': {'task_operation'}, 'has_subject': {'data_object'},
        'under_condition': {'condition'}, 'scope_evidence': REQUIREMENT_TYPES | {'condition'}}
    for relation, targets in roles.items():
        catalog['edge_types'].append(relation)
        catalog['allowed_edges'] += [[source, relation, target] for source in sorted(REQUIREMENT_TYPES) for target in sorted(targets)]
    raw_relations = list(record.get('relations', ()))
    raw_unresolved_relations = list(record.get('unresolved_relations', ()))
    if (any(row['edge_type'] == 'part_of' for row in raw_relations)
        or any(row[1] == 'part_of' for row in raw_unresolved_relations)):
        catalog['edge_types'].append('part_of')
        catalog['allowed_edges'].append(['data_object', 'part_of', 'data_object'])
    for relation in ('refers_to', 'supports', 'contrasts'):
        catalog['edge_types'].append(relation)
        catalog['allowed_edges'] += [[source, relation, target] for source in catalog['node_types']
            for target in catalog['node_types'] if source != 'task' and target != 'task']

    if not tolerant:
        for fact in record['facts']:
            quote, occurrence = fact['evidence_text'], fact['occurrence']
            if not isinstance(quote, str) or not quote or type(occurrence) is not int or occurrence < 1:
                raise PromptTSGError('来源命题引用无效')
            if len(list(re.finditer('(?='+re.escape(quote)+')', task['prompt']))) < occurrence:
                raise PromptTSGError('来源命题引用没有在指定位置逐字出现')
        graph = build_prompt_tsg(task_id=task['task_unit_id'], prompt=task['prompt'], extractor_id=extractor_id,
            catalog=catalog, facts=record['facts'], relations=record['relations'],
            unresolved_semantics=record['unresolved_semantics'], unresolved_relations=record['unresolved_relations'],
            requirement_structures=record['requirement_structures'], requirement_scopes=record['requirement_scopes'],
            requirement_relations=record['requirement_relations'])
        local = source_nodes(record['facts'], prompt=task['prompt'])
        return graph, dict(catalog=catalog, graph=prompt_tsg_record(graph),
            local_node_ids={key: node.node_id for key, node in local.items()})

    prompt = task['prompt']
    allowed_set = {tuple(item) for item in catalog['allowed_edges']}
    semantics = catalog['semantics']
    kept_facts: list[dict[str, Any]] = []
    local_semantics_by_id: dict[str, str] = {}
    dropped_local_semantics: dict[str, str] = {}
    unresolved_sem_set: set[str] = {
        s for s in record.get('unresolved_semantics', ())
        if isinstance(s, str) and s in semantics and s != 'task.root'
    }
    kept_sem_set: set[str] = set()

    for fact in record.get('facts', ()):
        local_id = fact.get('local_id')
        semantic_id = fact.get('semantic_id')
        quote = fact.get('evidence_text', '')
        occurrence = fact.get('occurrence', 1)
        span = resolve_evidence_span(prompt, quote, occurrence, tolerant=True)
        valid_concept = isinstance(semantic_id, str) and semantics.get(semantic_id) == fact.get('node_type')
        if span is None or not valid_concept or not isinstance(local_id, str) or not local_id.strip():
            if isinstance(local_id, str) and isinstance(semantic_id, str) and semantic_id in semantics and semantic_id != 'task.root':
                dropped_local_semantics[local_id] = semantic_id
                unresolved_sem_set.add(semantic_id)
            continue
        start, end = span
        matched_text = prompt[start:end]
        occ_idx = _exact_occurrence_index(prompt, matched_text, start)
        updated_fact = {
            'local_id': local_id,
            'node_type': fact['node_type'],
            'semantic_id': semantic_id,
            'evidence_text': matched_text,
            'occurrence': occ_idx,
            'attributes': dict(fact.get('attributes', {})),
        }
        kept_facts.append(updated_fact)
        local_semantics_by_id[local_id] = semantic_id
        kept_sem_set.add(semantic_id)

    unresolved_sem_set -= kept_sem_set
    kept_ids = set(local_semantics_by_id)
    available_semantics = kept_sem_set | unresolved_sem_set

    kept_relations: list[dict[str, Any]] = []
    kept_rel_sem_triples: set[tuple[str, str, str]] = set()
    candidate_unresolved_rels: list[tuple[str, str, str]] = [
        (row[0], row[1], row[2])
        for row in raw_unresolved_relations
        if isinstance(row, (list, tuple)) and len(row) == 3
    ]
    for rel in raw_relations:
        src, dst, kind = rel.get('source'), rel.get('target'), rel.get('edge_type')
        if src in kept_ids and dst in kept_ids:
            s_sem, t_sem = local_semantics_by_id[src], local_semantics_by_id[dst]
            if (semantics.get(s_sem), kind, semantics.get(t_sem)) in allowed_set:
                kept_relations.append({'source': src, 'target': dst, 'edge_type': kind})
                kept_rel_sem_triples.add((s_sem, kind, t_sem))
                continue
        s_sem = local_semantics_by_id.get(src) or dropped_local_semantics.get(src)
        t_sem = local_semantics_by_id.get(dst) or dropped_local_semantics.get(dst)
        if s_sem and t_sem and isinstance(kind, str):
            candidate_unresolved_rels.append((s_sem, kind, t_sem))

    unresolved_rels: list[list[str]] = []
    seen_unres: set[tuple[str, str, str]] = set()
    for s_sem, kind, t_sem in candidate_unresolved_rels:
        triple = (s_sem, kind, t_sem)
        if (
            triple not in seen_unres
            and triple not in kept_rel_sem_triples
            and s_sem in available_semantics
            and t_sem in available_semantics
            and (semantics.get(s_sem), kind, semantics.get(t_sem)) in allowed_set
        ):
            seen_unres.add(triple)
            unresolved_rels.append([s_sem, kind, t_sem])

    kept_req_ids = {
        fact['local_id']
        for fact in kept_facts
        if fact['node_type'] in REQUIREMENT_TYPES
    }
    raw_structures = {
        k: {'kind': v['kind'], 'members': [m for m in v.get('members', ()) if m in kept_req_ids]}
        for k, v in dict(record.get('requirement_structures', {})).items()
        if k in kept_req_ids
    }
    changed = True
    while changed:
        changed = False
        valid_keys = set(raw_structures)
        pruned: dict[str, dict[str, Any]] = {}
        for k, v in raw_structures.items():
            kind = v['kind']
            members = [m for m in v['members'] if m in valid_keys]
            ok = (
                (kind in {'atom', 'opaque'} and not members)
                or (kind == 'not' and len(members) == 1)
                or (kind in {'and', 'or'} and len(members) >= 2)
            )
            if ok:
                pruned[k] = {'kind': kind, 'members': members}
            else:
                changed = True
        raw_structures = pruned

    kept_scopes = {}
    for k, v in dict(record.get('requirement_scopes', {})).items():
        if k not in kept_req_ids or any(rel['source'] == k and rel['edge_type'] == 'constrains' for rel in kept_relations):
            continue
        boundaries = [b for b in v.get('boundaries', ()) if b in kept_ids]
        if v.get('kind') == 'each' and len(boundaries) != 1:
            continue
        kept_scopes[k] = {
            'kind': v['kind'],
            'boundaries': boundaries,
            'target_class': v.get('target_class'),
        }

    kept_req_rels: dict[str, list[dict[str, Any]]] = {}
    for owner, rows in dict(record.get('requirement_relations', {})).items():
        if owner in kept_req_ids and raw_structures.get(owner, {}).get('kind', 'atom') == 'atom':
            valid_rows = [
                dict(row) for row in rows
                if row.get('source') in kept_ids and row.get('target') in kept_ids
            ]
            if valid_rows:
                kept_req_rels[owner] = valid_rows

    graph = build_prompt_tsg(
        task_id=task['task_unit_id'],
        prompt=prompt,
        extractor_id=extractor_id,
        catalog=catalog,
        facts=kept_facts,
        relations=kept_relations,
        unresolved_semantics=sorted(unresolved_sem_set),
        unresolved_relations=unresolved_rels,
        requirement_structures=raw_structures,
        requirement_scopes=kept_scopes,
        requirement_relations=kept_req_rels,
    )
    local = source_nodes(kept_facts, prompt=prompt)
    return graph, dict(
        catalog=catalog,
        graph=prompt_tsg_record(graph),
        local_node_ids={key: node.node_id for key, node in local.items()},
        degraded_local_ids=sorted(dropped_local_semantics),
    )


def task_context_contract_record(contract: OpenTaskContract) -> dict[str, Any]:
    """Return one content-addressed open contract record."""
    record = canonical_value(contract)
    if record.get("source_inventory", False) is None:
        record.pop("source_inventory")
    return {"contract_id": contract.contract_id, **record}


def task_context_contract_from_record(value: Mapping[str, Any]) -> OpenTaskContract:
    """Parse the active source-only contract format."""
    if not isinstance(value, Mapping) or value.get("schema_version") != "4.0":
        raise PromptTSGError("open task contract format is required")
    try:
        record = dict(value)
        identity = record.pop("contract_id", None)
        for key in ("facts", "relations", "concept_states", "unresolved_notes"):
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
    contract: OpenTaskContract, *, prompt: str, catalog: Mapping[str, Any] | None = None,
    feature_states=(),
) -> PromptTSG:
    """Derive the graph from source records; optionally check the input vocabulary.

    Extraction/candidate callers supply the original catalog to enforce its frozen
    boundary. Display callers use the saved contract's catalog, never infer it from
    a second graph. This projection does not certify source semantics.
    """
    if not isinstance(contract, OpenTaskContract):
        raise PromptTSGError("open task contract is required")
    if (contract.schema_version != "4.0" or contract.prompt_sha256 != content_hash(prompt)
        or catalog is not None and contract.input_catalog_sha256 != catalog_sha256(catalog)
        or contract.arms_or_outcomes_used is not False or contract.review_status not in _REVIEW_STATUSES):
        raise PromptTSGError("open contract envelope is invalid")
    derived = catalog_from_record(contract.catalog)
    if catalog is not None and catalog["concept_policy"] == "FROZEN" and derived != catalog:
        raise PromptTSGError("frozen vocabulary changed during extraction")
    if catalog is not None and catalog["concept_policy"] == "DEVELOPMENT_OPEN":
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
    for row in feature_states:
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

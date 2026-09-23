"""Source evidence, schemas and deterministic contract compilation."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import replace
from prompt_mechanism_study.artifact_io import json_object
from prompt_mechanism_study.tsg.prompt_contract import (
    RelationDecision,
    SemanticDecision,
    TaskContextContract,
    compile_task_context_contract,
    task_context_scope,
    open_contract_from_response,
)
from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSGError,
    QueryState,
    catalog_sha256,
    has_required_source_name,
)
from prompt_mechanism_study.records import (
    content_hash,
)
from prompt_mechanism_study.tsg.task_input import prepare_task_input, generation_template_facts


_RESPONSE_FIELDS = {"semantic_decisions", "relation_decisions"}


_SEMANTIC_FIELDS = {
    "state",
    "rationale",
    "evidence_text",
    "occurrence",
    "attributes",
}


_RELATION_FIELDS = {
    "state",
    "rationale",
}


_INPUT_ROLES = ("value_input", "identifier_input", "resource", "destination", "input_unspecified")


_OBJECT_ROLES = (*_INPUT_ROLES, "result")


_RESULT_SOURCE_SUPPORT = (
    "A result is the object this action makes available, not necessarily an object it creates. "
    "Prior existence never rules out a retrieval, download or return result. Preserve such required "
    "results even when unnamed. Object existence or later use alone does not establish a result of "
    "some OTHER action: a file save does not necessarily produce a later-used filepath. Determine "
    "each action's production or exposure from the source before inferring any dependency. Keep "
    "objects with no stated producer; do not invent their origin or an execution order. "
    "A resource's changed state or successful action does not by itself require a separate output "
    "data object. An API may return a handle without the source requiring that handle as a distinct "
    "value. Require a source-supported object made available by the action or consumed as its result; "
    "do not infer an additional result solely from customary API behavior."
)


_OBJECT_ROLE_MEANINGS = {
    "value_input": "A data operand directly used by this action: use includes comparison, transformation, storage, forwarding or returning an existing value. It does not require changing or destroying the value. A data container whose fields are extracted, such as a received request or parsed document, is also an operand; being the source of extraction does not turn that data into an execution facility. An existing value that is returned is an input operand AND may also be exposed as a result; these roles are independent. Facilities, destinations and structural selectors have their separate roles. For SQL this role requires a stored value or predicate value, including a userid or stored filepath even when it identifies a business entity; a query input of unresolved value-versus-selector role remains input_unspecified.",
    "identifier_input": "A name or locator selecting a structural target, such as an SQL table/column name or a filepath used to locate a file for download. A userid or filepath stored as SQL data is not an SQL identifier.",
    "resource": "An existing facility used by the operation, such as a database, base directory or source file. This is a capability or access facility, not every previously available object: a received data payload whose fields are parsed has value_input. Classify the entity denoted by the concept: a facility can be named by a literal path without becoming a separate locator-value object. A caller-supplied path selecting a target has identifier_input instead. Do not substitute the operation's result for a resource.",
    "destination": "The target location into which the operation writes, such as an upload directory.",
    "input_unspecified": "The source establishes an input to this operation but does not resolve its more specific role. It is not a default for objects used elsewhere or for merely possible input use.",
    "result": "The operation produces or exposes the WHOLE object denoted by this exact source instance, including an existing object explicitly returned to the caller. Supplying only a contribution to a collective does not produce that collective: this role has no implicit part-of meaning. Request fields are extraction results; a retrieved password is a lookup result. Creating a new result does not also consume that result: its ingredients and the resulting value are distinct instances. An input role additionally requires source support for using an already available value. Forwarding or returning an existing value may both consume and expose it; do not transfer that dual role to a newly created value. " + _RESULT_SOURCE_SUPPORT,
}


class PromptContractExtractionError(RuntimeError):
    """The frozen request, model decision table, or extraction closure is invalid."""


def _operation_anchor_conflicts(nodes: list, request: Mapping[str, Any]) -> list[tuple[int, int]]:
    """Locate overlapping identity anchors for distinct instances of one operation concept."""
    operations = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        concept_id = node.get("concept_id")
        concept = (request.get("known_concepts", {}).get(concept_id, {})
                   if isinstance(concept_id, str) else node.get("concept", {}))
        if not isinstance(concept, dict) or concept.get("node_type") != "task_operation":
            continue
        concept_id = concept_id or concept.get("concept_id")
        start, end = node.get("evidence_start_token"), node.get("evidence_end_token")
        if isinstance(concept_id, str) and type(start) is int and type(end) is int and 1 <= start <= end:
            operations.append((index, concept_id, start, end))
    return [(i, j) for offset, (i, concept, start, end) in enumerate(operations)
            for j, other, left, right in operations[offset + 1:]
            if concept == other and (start, end) != (left, right)
            and max(start, left) <= min(end, right)]


def _relation_decision_key(relation: Sequence[str]) -> str:
    if len(relation) != 3 or any(not value or "|" in value for value in relation):
        raise PromptContractExtractionError("relation cannot be encoded as a decision key")
    return "|".join(relation)


def _has_fixed_concept_layers(request: Mapping[str, Any]) -> bool:
    known = request.get("known_concepts", {})
    return (request.get("concept_policy") == "FROZEN" and bool(known)
            and all("layer" in concept for concept in known.values()))


def source_fact_schema(request: Mapping[str, Any], *, group: str | None = None,
                       quoted: bool = False, evidence_first: bool = False) -> dict[str, Any]:
    """Define a fact once; response adapters add their own references/participants."""
    text = {"type": "string"}
    def row(properties):
        return dict(type="object", additionalProperties=False, properties=properties, required=list(properties))
    token = dict(type="integer", minimum=1, maximum=len(_source_tokens(request["source_prompt"])))
    concept = dict(type="string", description="Exact supplied or declared concept ID whose complete definition the source entails. Each requirement node expresses one atomic requirement, never a bundle of independently changeable requirements.")
    if request["concept_policy"] == "FROZEN" and request["known_concepts"]:
        concept["enum"] = list(request["known_concepts"])
    meaning = dict(concept_id=concept) if request["concept_policy"] == "FROZEN" else dict(
        concept=row(dict(concept_id=text, node_type=dict(type="string", enum=request["allowed_node_types"]), definition=text)))
    citation_fields = dict(source_units=dict(type="array", minItems=1,
        items=dict(type="string", enum=list(request["source_units"]))),
        evidence_start_token=token, evidence_end_token=token,
        layer=dict(type="string", enum=["generation", "runtime", "unresolved"]))
    if _has_fixed_concept_layers(request):
        del citation_fields["layer"]
    if quoted:
        citation_fields.pop("evidence_start_token")
        citation_fields.pop("evidence_end_token")
        fields = dict(**source_citation_schema(request), **citation_fields, **meaning)
    else:
        fields = dict(**citation_fields, **meaning) if evidence_first else dict(**meaning, **citation_fields)
    if group is not None:
        kinds = _INVENTORY_GROUPS[group]
        if request["concept_policy"] == "FROZEN":
            fixed = {r["concept_id"] for r in request["fixed_template"]["concepts"]}
            choices = [key for key, item in request["known_concepts"].items()
                       if item["node_type"] in kinds and key not in fixed]
            if choices:
                fields["concept_id"]["enum"] = choices
            else:
                fields["concept_id"].pop("enum", None)
        else:
            fields["concept"]["properties"]["node_type"]["enum"] = sorted(kinds)
    return row(fields)


def source_citation_schema(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "evidence_source_unit": dict(type="string", enum=list(request["source_units"])),
        "evidence_text": dict(type="string", description="Copy one exact, uniquely located word-aligned quote from the selected source unit. The program computes its positions."),
    }


def source_coverage_schema(request: Mapping[str, Any]) -> dict[str, Any]:
    def row(properties):
        return dict(type="object", additionalProperties=False, properties=properties, required=list(properties))
    return row({key: row(dict(
        status=dict(type="string", enum=["represented", "unresolved", "no_task_fact"]),
        reason=dict(type="string", description="Short source-specific coverage or missing-meaning statement.")))
        for key in request["source_units"]})


def fact_layer(fact: Mapping[str, Any], request: Mapping[str, Any]) -> str | None:
    """Read the declared layer; a frozen concept may supply it without a response field."""
    return fact.get("layer", request["known_concepts"].get(fact.get("concept_id"), {}).get("layer"))


def open_contract_response_format(request: Mapping[str, Any], *, evidence_first: bool = False) -> dict[str, Any]:
    """Token-indexed inventory adapter; current records use source_fact_schema directly."""
    properties = {
        "nodes": dict(type="array", items=source_fact_schema(request, evidence_first=evidence_first)),
        "coverage": source_coverage_schema(request),
        "unresolved_notes": dict(type="array", items=dict(type="string")),
    }
    if request["concept_policy"] == "FROZEN" and not request["known_concepts"]:
        properties["nodes"]["maxItems"] = 0
    schema = dict(type="object", additionalProperties=False, properties=properties, required=list(properties))
    return dict(type="json_schema", json_schema=dict(name="source_fact_inventory", strict=True, schema=schema))


def _source_tokens(prompt: str) -> list[re.Match[str]]:
    # Lexical indexing only; punctuation remains separate from identifiers.
    return list(re.finditer(r"\w+|[^\w\s]", prompt))


_INVENTORY_GROUPS = {
    "objects": {"data_object"},
    "operations": {"task_operation"},
    "requirements": {"task_requirement", "safety_requirement", "constraint", "presentation_control"},
    "conditions": {"condition"},
}


_SOURCE_OBJECT_MEANING = (
    "A runtime data object is a value, resource or destination required by the source specification. "
    "It need not have a variable name, declaration, persistent storage or concrete runtime value. "
    "A required action's unnamed result consumed by another required action is a source-supported object. "
    "Preserve that result and its producer/consumer meaning; do not remove it for lacking a named variable. "
    "This does not justify optional implementation temporaries, buffers or helper actions. "
    "Judge the complete source and the full concept definition, including cross-sentence references. "
    + _RESULT_SOURCE_SUPPORT
)


def _inventory_concept(row: Mapping[str, Any], request: Mapping[str, Any]) -> dict[str, Any]:
    """Read a source meaning; open development cannot redefine a supplied concept."""
    if request["concept_policy"] == "FROZEN":
        key = row.get("concept_id")
        if not isinstance(key, str):
            raise PromptContractExtractionError("inventory concept ID must be a string")
        return dict(concept_id=key, **request["known_concepts"].get(key, {}))
    concept = row.get("concept")
    if (not isinstance(concept, dict) or set(concept) != {"concept_id", "node_type", "definition"}
        or any(not isinstance(v, str) or not v.strip() for v in concept.values())):
        raise PromptContractExtractionError("inline concept fields are invalid")
    known = request["known_concepts"].get(concept["concept_id"].lower())
    if known is not None:
        if any(concept[k] != known[k] for k in ("node_type", "definition")):
            raise PromptContractExtractionError("inline concept cannot change a supplied meaning")
        if "layer" in known and row.get("layer") != known["layer"]:
            raise PromptContractExtractionError("inline concept cannot change a supplied layer")
    return concept


def _quoted_inventory_citation(row: Mapping[str, Any], request: Mapping[str, Any], path: str) -> dict[str, Any]:
    """Locate an exact, unique source-unit quote; the model supplies no positions."""
    quote, unit_id = row.get("evidence_text"), row.get("evidence_source_unit")
    if (not isinstance(quote, str) or not quote.strip() or not isinstance(unit_id, str)
        or unit_id not in request["source_units"]
        or any(k in row for k in ("evidence_start_token", "evidence_end_token"))):
        raise PromptContractExtractionError(f"{path}: inventory evidence requires a source unit and literal quote")
    unit = request["source_units"][unit_id]
    source = request["source_prompt"]
    unit_start = _literal_starts(source, unit["evidence_text"])[unit["occurrence"] - 1]
    tokens = _source_tokens(source)
    starts = {token.start(): i for i, token in enumerate(tokens, 1)}
    ends = {token.end(): i for i, token in enumerate(tokens, 1)}
    matches = [(unit_start + offset, unit_start + offset + len(quote))
               for offset in _literal_starts(unit["evidence_text"], quote)
               if unit_start + offset in starts and unit_start + offset + len(quote) in ends]
    if len(matches) != 1:
        raise PromptContractExtractionError(
            f"{path}: quote must identify one token-aligned occurrence inside its source unit; "
            f"found {len(matches)} matches in {unit_id} for {quote!r}. "
            "Copy the exact source text and include adjacent words to distinguish repeated mentions.")
    left, right = matches[0]
    result = {k: deepcopy(v) for k, v in row.items() if k not in {"evidence_text", "evidence_source_unit"}}
    result.update(evidence_start_token=starts[left], evidence_end_token=ends[right])
    return result


def quoted_source_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Source context shared by quoted-record extraction and historical adapters."""
    if (request.get("request_kind") != "source_only_fact_inventory"
        or request.get("concept_policy") not in {"FROZEN", "DEVELOPMENT_OPEN"}):
        raise PromptContractExtractionError("grouped inventory requires a source-fact request")
    result = deepcopy(dict(request))
    result.pop("source_tokens", None)
    result["source_units"] = {key: {k: v for k, v in unit.items() if k not in {"evidence_start_token", "evidence_end_token"}}
                              for key, unit in request["source_units"].items()}
    result["evidence_coordinates"] = (
        "For each node and participant relation, choose evidence_source_unit and an exact evidence_text quotation "
        "that occurs once in that source unit, aligned to complete words or punctuation. Include enough surrounding "
        "words to distinguish repeated mentions. The program finds positions; do not count tokens or occurrences. "
        "A node's source_units retains all wider supporting clauses. Identity and relationship evidence are separate.")
    result["source_object_meaning"] = _SOURCE_OBJECT_MEANING
    result["operation_role_meanings"] = dict(_OBJECT_ROLE_MEANINGS)
    return result


def _template_for_catalog(task: Mapping[str, Any], catalog: Mapping[str, Any]) -> dict[str, Any]:
    template = generation_template_facts(task)
    if catalog["concept_policy"] == "FROZEN":
        for row in template["concepts"]:
            key = row["concept_id"]
            if catalog["semantics"].get(key) != row["node_type"] or catalog["semantic_guidance"].get(key) != row["definition"]:
                raise PromptContractExtractionError("frozen vocabulary must include the exact declared generation-template meanings")
    return template


def _source_units(task: Mapping[str, Any], *, fixed_template: bool) -> dict[str, Any]:
    """Lexical source segments, not semantic labels or a completeness certificate."""
    prompt, generation = task["prompt"], task["generation_input"]
    system_start = len("System message:\n")
    language_start = system_start + len(generation["system_prompt"]) + len("\n\nUser message:\nLanguage: ")
    task_start = language_start + len(generation["request"]["language"]) + len("\n\nTask:\n")
    segments = [(task_start, generation["request"]["task"])]
    if not fixed_template:
        segments = [(system_start, generation["system_prompt"]),
                    (language_start, generation["request"]["language"]), *segments]
    tokens, result = _source_tokens(prompt), {}
    for offset, segment in segments:
        for line in re.finditer(r"[^\r\n]+", segment):
            for sentence in re.finditer(r".+?(?:[.!?](?=\s|$)|$)", line.group()):
                start = offset + line.start() + sentence.start()
                end = offset + line.start() + sentence.end()
                indices = [i for i, token in enumerate(tokens, 1) if token.start() >= start and token.end() <= end]
                if indices:
                    first, last = indices[0], indices[-1]
                    left, right = tokens[first-1].start(), tokens[last-1].end()
                    text = prompt[left:right]
                    result[f"u{len(result)+1}"] = dict(evidence_text=text,
                        occurrence=_literal_starts(prompt, text).index(left)+1,
                        evidence_start_token=first, evidence_end_token=last)
    return result


def _indexed_citation(prompt: str, tokens: list, row: Mapping[str, Any]) -> dict[str, Any]:
    start, end = row["evidence_start_token"], row["evidence_end_token"]
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(tokens):
        raise PromptContractExtractionError("invalid inclusive source-token endpoints")
    left, right = tokens[start - 1].start(), tokens[end - 1].end()
    quote = prompt[left:right]
    return dict(evidence_text=quote, occurrence=_literal_starts(prompt, quote).index(left) + 1)


def _indexed_facts_response(value: Any, *, prompt: str, request: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Allocate IDs after source extraction; the response has no self-references."""
    if (not isinstance(value, dict) or set(value) - {"operation_roles"} != {"nodes", "coverage", "unresolved_notes"}
        or any(not isinstance(value[key], list) for key in ("nodes", "unresolved_notes"))):
        raise PromptContractExtractionError("source fact inventory fields are invalid")
    if not isinstance(value["coverage"], dict) or set(value["coverage"]) != set(request["source_units"]):
        raise PromptContractExtractionError("source inventory coverage is incomplete")
    if _operation_anchor_conflicts(value["nodes"], request):
        raise PromptContractExtractionError("overlapping anchors do not distinguish instances of the same operation concept")
    template = request["fixed_template"]
    template_concepts = {row["concept_id"] for row in template["concepts"]}
    frozen = request["concept_policy"] == "FROZEN"
    fixed_layers = _has_fixed_concept_layers(request)
    tokens, nodes, notes, layers = _source_tokens(prompt), [], list(value["unresolved_notes"]), {}
    coverage, concepts = {}, {}
    for key, decision in value["coverage"].items():
        if not isinstance(decision, dict) or set(decision) != {"status", "reason"}:
            raise PromptContractExtractionError("source coverage fields are invalid")
        coverage[key] = dict(**decision, facts=[])
    for index, row in enumerate(value["nodes"], 1):
        fields = {"concept_id" if frozen else "concept", "source_units", "evidence_start_token", "evidence_end_token"}
        if not fixed_layers:
            fields.add("layer")
        if (not isinstance(row, dict) or set(row) != fields
            or not fixed_layers and row["layer"] not in {"generation", "runtime", "unresolved"}
            or not isinstance(row["source_units"], list) or not row["source_units"]
            or any(not isinstance(key, str) or key not in coverage for key in row["source_units"])
            or len(set(row["source_units"])) != len(row["source_units"])):
            raise PromptContractExtractionError("indexed fact fields are invalid")
        if not frozen:
            c = _inventory_concept(row, request)
            if c["concept_id"] in concepts and concepts[c["concept_id"]] != c:
                raise PromptContractExtractionError("inline concept definitions disagree")
            concepts[c["concept_id"]] = c
        concept_id = row["concept_id"] if frozen else c["concept_id"]
        if fixed_layers and (not isinstance(concept_id, str) or concept_id not in request["known_concepts"]):
            raise PromptContractExtractionError("indexed fact has an unknown frozen concept")
        if concept_id in template_concepts:
            raise PromptContractExtractionError("fixed generation-template facts must not be redeclared")
        local_id = f"fact.{index}"
        layers[local_id] = request["known_concepts"][concept_id]["layer"] if fixed_layers else row["layer"]
        try:
            citation = _indexed_citation(prompt, tokens, row)
        except PromptContractExtractionError:
            notes.append(f"unbound_source_token_span: {local_id}; invalid inclusive token endpoints.")
            citation = dict(evidence_text="", occurrence=1)
        nodes.append(dict(local_id=local_id, concept_id=concept_id, **citation))
        for key in row["source_units"]:
            coverage[key]["facts"].append(local_id)
    for decision in coverage.values():
        if decision["status"] == "represented" and not decision["facts"]:
            raise PromptContractExtractionError("represented source coverage requires an additional submitted fact")
        # Occupancy is observable from the submitted facts. This does not add a
        # fact or resolve a reported semantic gap; binding still reviews each
        # unit's completeness independently against the source.
        if (decision["status"] == "no_task_fact" and decision["facts"]
            and isinstance(decision["reason"], str) and decision["reason"].strip()):
            decision["status"] = "represented"
            decision["reason"] = (
                "Coverage label normalized from no_task_fact to represented because "
                "this unit owns submitted facts. Original annotation: " + decision["reason"])
    layers.update({row["local_id"]: "generation" for row in template["nodes"]})
    roles = value.get("operation_roles", [])
    if not isinstance(roles, list):
        raise PromptContractExtractionError("inventory operation roles must be an array")
    converted_roles = []
    for row in roles:
        if not isinstance(row, dict) or set(row) != {"operation", "subject", "role", "evidence_start_token", "evidence_end_token"}:
            raise PromptContractExtractionError("inventory operation role fields are invalid")
        converted_roles.append({**{k: row[k] for k in ("operation", "subject", "role")},
            **_indexed_citation(prompt, tokens, row)})
    metadata = dict(source_units={key: {k: row[k] for k in ("evidence_text", "occurrence")}
                    for key, row in request["source_units"].items()}, coverage=coverage, layers=layers, operation_roles=converted_roles)
    concept_rows = [*template["concepts"], *concepts.values()] if not frozen else []
    return (dict(concepts=concept_rows, nodes=[*template["nodes"], *nodes], edges=template["edges"],
                 concept_states=[], feature_states=[], unresolved_notes=notes), metadata)


_FIXED_BINDING_INSTRUCTIONS = "The program allocated immutable fact IDs. The inventory operation_roles are provisional source claims, not fixed relations. Check and replace them against the complete source; do not carry forward an unsupported use. Declare each confirmed source-supported operation/object role once in operation_roles. The program derives produces for result and used_by for every input role; do not declare inputs or outputs again. Fill binding_rows only for precedence, requirements and conditions. Enums are choices, not assertions. Review EVERY source unit in unit_impacts against the COMPLETE source, including cross-sentence dependencies and non-target behavior. complete means all relevant meanings and bindings of that unit are represented. effect=local requires a nonempty list of ALL affected runtime operations; global or unresolved uses an empty list and blocks all operations if incomplete. Generation-only content uses no_runtime_effect, not local with no operations. A missing graph edge never proves irrelevance. Conditions bind only the operations or requirements they actually qualify. Preserve fixed_relations; never add, rename or repair facts. Report missing facts in unit_impacts as incomplete as well as in unresolved_notes."


def fixed_binding_request(contract: OpenTaskContract, *, prompt: str, catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Ask only for incidence between immutable, already source-bound facts.

    Column names determine relation types. The model cannot add facts, choose
    arbitrary edge types or cite undefined endpoints in this call.
    """
    compile_task_context_contract(contract, prompt=prompt, catalog=catalog)
    if (any(not edge["source"].startswith("template.") or edge["target"] != "template.implementation"
            or edge["edge_type"] != "constrains" for edge in contract.relations)
        or contract.feature_states or contract.concept_states):
        raise PromptContractExtractionError("binding inventory must contain facts only")
    facts = {f["local_id"]: f for f in contract.facts}
    rows = {}
    for key in sorted(facts):
        if key.startswith("template."):
            continue
        kind = facts[key]["node_type"]
        if kind == "task_operation":
            rows[key] = ["precedes"]
        elif kind in {"task_requirement", "safety_requirement", "constraint", "presentation_control"}:
            rows[key] = ["operations", "subjects"]
        elif kind == "condition":
            rows[key] = ["operations", "requirements"]
    return dict(request_kind="source_only_fixed_bindings", source_contract_id=contract.contract_id,
        source_prompt=prompt,
        source_tokens={str(i): token.group() for i, token in enumerate(_source_tokens(prompt), 1)},
        facts=[dict(local_id=key, concept_id=f["semantic_id"], node_type=f["node_type"],
                    definition=contract.catalog["semantic_guidance"].get(f["semantic_id"], ""),
                    layer=contract.source_inventory["layers"][key],
                    source_units=[unit for unit, row in contract.source_inventory["coverage"].items()
                                  if key in row["facts"]],
                    evidence_text=f["evidence_text"], occurrence=f["occurrence"])
               for key, f in sorted(facts.items())],
        binding_rows=rows,
        operation_role_meanings=dict(_OBJECT_ROLE_MEANINGS),
        role_evidence_context=(
            "Your selected token span is retained in the raw response. In the compiled contract, role evidence "
            "is expanded to the contiguous source context containing that span and the source units citing its "
            "operation/object endpoints. This lexical context expansion preserves antecedents; it does not "
            "verify the role or license an unsupported use. Fact identity anchors remain unchanged."),
        relation_meanings={
            "precedes": "The source requires the first operation before the second, explicitly or because a required result must be available to its consumer. Both production and consumption must first be established from the original source, independently of the proposed graph. A graph-created result edge cannot prove its own premise or this order. Mere sentence order, a shared input, or a customary implementation sequence does not establish this relation. If an alternative ordering still satisfies every stated requirement and source-required result, omit the unstated precedence. This is a specification dependency, not a measured causal effect or an implementation schedule.",
            "constrains": "The stated requirement applies to this exact operation or named subject. Preserve its predicate, negation and qualifiers.",
            "conditions": "The source condition qualifies this exact obligation or operation. Qualifying a requirement does not make execution of its target operation conditional.",
        },
        source_inventory=contract.source_inventory,
        **({"existing_value_return_operations": [key for key, fact in sorted(facts.items())
             if fact["semantic_id"] in catalog["existing_value_return_operations"]]}
           if "existing_value_return_operations" in catalog else {}),
        fixed_relations=list(contract.relations),
        generation_binding_policy=(
            "Bindings stay within their declared layer. A complete interface declaration preserves "
            "its name and formal parameters in that requirement atom and constrains implementation. "
            "It does not need extra subject edges to runtime parameter values or imported modules. "
            "Review completeness by preserved source meaning, not by demanding those extra edges."),
        instructions=_FIXED_BINDING_INSTRUCTIONS,
        unresolved_fact_notes=list(contract.unresolved_notes), arms_or_outcomes_included=False)


def _binding_targets(request: Mapping[str, Any], key: str, column: str) -> list[str]:
    """Keep candidate domains in the schema, separate from the unfilled rows."""
    roles = ({"task_operation"} if column in {"precedes", "operations"} else
             {"task_requirement", "safety_requirement", "constraint", "presentation_control"} if column == "requirements" else {"data_object"})
    inventory = request["source_inventory"]
    if inventory is None:
        raise PromptContractExtractionError("active binding requires a source-covered fact inventory")
    layer = inventory["layers"][key]
    targets = {f["local_id"] for f in request["facts"] if f["node_type"] in roles
               and layer != "unresolved" and inventory["layers"][f["local_id"]] == layer
               and (column != "precedes" or f["local_id"] != key)}
    if column == "precedes" and layer != "runtime":
        targets.clear()
    return sorted(targets)


def fixed_binding_response_format(request: Mapping[str, Any]) -> dict[str, Any]:
    def obj(properties):
        return dict(type="object", properties=properties, required=list(properties), additionalProperties=False)
    token = dict(type="integer", minimum=1, maximum=len(request["source_tokens"]))
    rows = {}
    for key, columns in request["binding_rows"].items():
        fields = {}
        for column in columns:
            targets = _binding_targets(request, key, column)
            target = dict(type="string", **({"enum": targets} if targets else {}))
            # The parser already rejects repeated targets. Constrain decoding
            # to that same finite set instead of permitting endless duplicates.
            fields[column] = dict(type="array", maxItems=len(targets),
                items=obj(dict(target=target, evidence_start_token=token, evidence_end_token=token)))
        rows[key] = obj(fields)
    runtime = {f["local_id"]: f["node_type"] for f in request["facts"]
               if request["source_inventory"]["layers"][f["local_id"]] == "runtime"}
    operations = [key for key, kind in runtime.items() if kind == "task_operation"]
    subjects = [key for key, kind in runtime.items() if kind == "data_object"]
    def choice(values):
        return dict(type="string", **({"enum": values} if values else {}))
    role_rows = dict(type="array", items=obj(dict(operation=choice(operations), subject=choice(subjects),
        role=dict(type="string", enum=list(_OBJECT_ROLES)), evidence_start_token=token, evidence_end_token=token)))
    if not operations or not subjects:
        role_rows["maxItems"] = 0
    affected = dict(type="array", items=choice(operations))
    if not operations:
        affected["maxItems"] = 0
    impacts = obj({key: obj(dict(effect=dict(type="string", enum=["local", "global", "unresolved", "no_runtime_effect"]),
        operations=affected, complete=dict(type="boolean", description=(
            "All source-stated meanings and required bindings are represented. A header or duplicate "
            "example needing no additional fact is complete; missing a required input/result binding is not.")),
        reason=dict(type="string")))
        for key in request["source_inventory"]["source_units"]})
    return dict(type="json_schema", json_schema=dict(name="fixed_source_bindings", strict=True,
        schema=obj(dict(bindings=obj(rows), operation_roles=role_rows, unit_impacts=impacts,
                        unresolved_notes=dict(type="array", items=dict(type="string"))))))


def _role_context_citation(prompt: str, tokens: list, row: Mapping[str, Any],
                           inventory: Mapping[str, Any]) -> dict[str, Any]:
    """Complete cited source context without deciding whether a role is entailed.

    The raw binding response retains the model's exact selected tokens. Endpoint
    source-unit ownership and token positions alone determine the context; no
    semantic labels, keywords, references or outcomes choose additional text.
    """
    _indexed_citation(prompt, tokens, row)  # Validate the original model anchor first.
    left = tokens[row["evidence_start_token"] - 1].start()
    right = tokens[row["evidence_end_token"] - 1].end()
    anchor_left, anchor_right = left, right
    endpoints = {row["operation"], row["subject"]}
    for key, unit in inventory["source_units"].items():
        start = _literal_starts(prompt, unit["evidence_text"])[unit["occurrence"] - 1]
        end = start + len(unit["evidence_text"])
        if endpoints.intersection(inventory["coverage"][key]["facts"]) or start < anchor_right and end > anchor_left:
            left, right = min(left, start), max(right, end)
    quote = prompt[left:right]
    return dict(evidence_text=quote, occurrence=_literal_starts(prompt, quote).index(left) + 1)


def apply_fixed_binding_response(raw: bytes, *, request: Mapping[str, Any], contract: OpenTaskContract,
                                 prompt: str, catalog: Mapping[str, Any]) -> OpenTaskContract:
    """Decode an external binding response; internal compilation passes values directly."""
    return apply_fixed_bindings(json_object(raw), request=request, contract=contract,
                                prompt=prompt, catalog=catalog)


def apply_fixed_bindings(value: Mapping[str, Any], *, request: Mapping[str, Any], contract: OpenTaskContract,
                                 prompt: str, catalog: Mapping[str, Any]) -> OpenTaskContract:
    """Derive input/output incidence once from roles; preserve fixed source facts."""
    if request != fixed_binding_request(contract, prompt=prompt, catalog=catalog):
        raise PromptContractExtractionError("binding request does not bind its exact fact inventory")
    if (set(value) != {"bindings", "operation_roles", "unit_impacts", "unresolved_notes"} or not isinstance(value["bindings"], dict)
        or set(value["bindings"]) != set(request["binding_rows"])
        or not isinstance(value["unresolved_notes"], list)
        or any(not isinstance(n, str) for n in value["unresolved_notes"])):
        raise PromptContractExtractionError("fixed binding response fields are invalid or incomplete")
    kinds = {f["local_id"]: f["node_type"] for f in contract.facts}
    tokens, relations = _source_tokens(prompt), list(contract.relations)
    for key, columns in request["binding_rows"].items():
        row = value["bindings"][key]
        if not isinstance(row, dict) or set(row) != set(columns):
            raise PromptContractExtractionError("fixed binding row fields are invalid or incomplete")
        for column in columns:
            targets = _binding_targets(request, key, column)
            if not isinstance(row[column], list):
                raise PromptContractExtractionError("fixed binding column must be an array")
            seen = set()
            for entry in row[column]:
                if (not isinstance(entry, dict) or set(entry) != {"target", "evidence_start_token", "evidence_end_token"}
                    or not isinstance(entry["target"], str) or entry["target"] not in targets or entry["target"] in seen):
                    raise PromptContractExtractionError("fixed binding endpoint is undefined, duplicated or has the wrong role")
                seen.add(entry["target"])
                target = entry["target"]
                relation = ("precedes"
                            if kinds[key] == "task_operation" else "conditions" if kinds[key] == "condition" else "constrains")
                relations.append(dict(source=key, target=target, edge_type=relation, **_indexed_citation(prompt, tokens, entry)))
    if not isinstance(value["operation_roles"], list):
        raise PromptContractExtractionError("operation-local roles must be an array")
    roles = []
    for row in value["operation_roles"]:
        if not isinstance(row, dict) or set(row) != {"operation", "subject", "role", "evidence_start_token", "evidence_end_token"}:
            raise PromptContractExtractionError("operation-local role fields are invalid")
        citation = _role_context_citation(prompt, tokens, row, contract.source_inventory)
        roles.append({**{key: row[key] for key in ("operation", "subject", "role")}, **citation})
        source, kind, target = ((row["operation"], "produces", row["subject"]) if row["role"] == "result"
                                else (row["subject"], "used_by", row["operation"]))
        # Several explicitly supported input roles may share one incidence edge.
        # Role validity and source citations are checked by the common compiler.
        if not any((r["source"], r["edge_type"], r["target"]) == (source, kind, target) for r in relations):
            relations.append(dict(source=source, target=target, edge_type=kind, **citation))
    # Returning an already-existing value entails using that exact value as an
    # operand. Only prospectively declared operation meanings license this rule;
    # arbitrary producers (queries, extraction, downloads) do not. Keep the raw
    # annotation unchanged and mark the derived role with its source premise.
    returning = set(catalog.get("existing_value_return_operations", []))
    fact_concepts = {f["local_id"]: f["semantic_id"] for f in contract.facts}
    for row in tuple(roles):
        if (row["role"] == "result" and fact_concepts.get(row["operation"]) in returning
            and not any(r["operation"] == row["operation"] and r["subject"] == row["subject"]
                        and r["role"] == "value_input" for r in roles)):
            roles.append({**row, "role": "value_input", "derived_from": "existing_value_return_result"})
            source, target = row["subject"], row["operation"]
            if not any((r["source"], r["edge_type"], r["target"]) == (source, "used_by", target) for r in relations):
                relations.append(dict(source=source, target=target, edge_type="used_by",
                    evidence_text=row["evidence_text"], occurrence=row["occurrence"]))
    inventory = dict(contract.source_inventory, operation_roles=roles, unit_impacts=value["unit_impacts"])
    bound = replace(contract, relations=tuple(relations), source_inventory=inventory,
                    unresolved_notes=(*contract.unresolved_notes, *value["unresolved_notes"]))
    compile_task_context_contract(bound, prompt=prompt, catalog=catalog)
    # Submitted roles and source-unit ownership already establish some
    # dependencies. Include that lower bound instead of asking a second model
    # field to remember it. Missing graph links never prove independence.
    bound = _include_recorded_impacts(bound)
    compile_task_context_contract(bound, prompt=prompt, catalog=catalog)
    return bound


def _include_recorded_impacts(contract: OpenTaskContract) -> OpenTaskContract:
    reach = _represented_unit_operations(contract)
    impacts = deepcopy(contract.source_inventory['unit_impacts'])
    for key, operations in reach.items():
        impact = impacts[key]
        if impact["effect"] == "local":
            missing = operations - set(impact["operations"])
            if missing:
                impact["operations"] = sorted(operations | set(impact["operations"]))
                impact["reason"] += " Recorded source-fact dependencies also reach: " + ", ".join(sorted(missing)) + "."
        elif impact["effect"] == "no_runtime_effect" and operations:
            impact.update(effect="unresolved", complete=False,
                reason=impact["reason"] + " This conflicts with recorded runtime dependencies; broader reach remains unresolved.")
    return replace(contract, source_inventory={**contract.source_inventory, "unit_impacts": impacts})


def _represented_unit_operations(contract: OpenTaskContract) -> dict[str, set[str]]:
    """Lower-bound specification dependencies; never a completeness certificate."""
    inventory = contract.source_inventory
    runtime = {f["local_id"] for f in contract.facts
               if inventory["layers"][f["local_id"]] == "runtime"}
    operations = {f["local_id"] for f in contract.facts
                  if f["local_id"] in runtime and f["node_type"] == "task_operation"}
    links = {key: set() for key in runtime}
    for role in inventory["operation_roles"]:
        # A described result concerns its producer as well as its later uses.
        links[role["subject"]].add(role["operation"])
        if role["role"] == "result":
            links[role["operation"]].add(role["subject"])
    for edge in contract.relations:
        if edge["edge_type"] in {"constrains", "conditions", "context_for"} and edge["source"] in runtime:
            links[edge["source"]].add(edge["target"])
    for key, scope in inventory.get('requirement_scopes', {}).items():
        # Influence is not a direct obligation: an unprojected global rule can
        # still affect local edits and must not disappear from unknown handling.
        links[key].update(scope['boundaries'] or operations)
    for owner, rows in inventory.get('requirement_relations', {}).items():
        if owner in runtime:
            links[owner].update(endpoint for row in rows for endpoint in (row['source'], row['target'])
                                if endpoint in runtime)
    for key, expression in inventory.get('requirement_structures', {}).items():
        if key in runtime:
            links[key].update(member for member in expression['members'] if member in runtime)
    result = {}
    for key, coverage in inventory["coverage"].items():
        seen, pending = set(), set(coverage["facts"]) & runtime
        while pending:
            fact = pending.pop()
            if fact not in seen:
                seen.add(fact)
                pending.update(links[fact] - seen)
        result[key] = seen & operations
    return result


def contract_response_format(request: Mapping[str, Any]) -> dict[str, Any]:
    """Build a strict task-specific schema whose required keys close the finite scope."""

    if request.get("request_kind") == "source_only_atomic_records":
        from prompt_mechanism_study.tsg.source_records import record_response_format
        return record_response_format(request)
    if request.get("request_kind") == "source_only_fact_inventory":
        return open_contract_response_format(request)
    semantics = request.get("candidate_semantics")
    relations = request.get("candidate_relations")
    attributes = request.get("allowed_attributes")
    if (
        not isinstance(semantics, dict)
        or not semantics
        or not isinstance(relations, dict)
        or not isinstance(attributes, list)
        or not attributes
        or any(not isinstance(item, str) or not item.strip() for item in attributes)
        or len(attributes) != len(set(attributes))
        or any(not isinstance(key, str) or not key for key in (*semantics, *relations))
    ):
        raise PromptContractExtractionError("response schema scope is invalid")
    semantic_value = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_SEMANTIC_FIELDS),
        "properties": {
            "state": {
                "type": "string",
                "enum": ["present", "absent", "unresolved"],
            },
            "rationale": {"type": "string", "minLength": 1},
            "evidence_text": {"type": ["string", "null"]},
            "occurrence": {"type": ["integer", "null"]},
            "attributes": {
                "type": "array",
                "items": {"type": "string", "enum": sorted(attributes)},
            },
        },
    }
    relation_value = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_RELATION_FIELDS),
        "properties": {
            "state": {
                "type": "string",
                "enum": ["present", "absent", "unresolved"],
            },
            "rationale": {"type": "string", "minLength": 1},
        },
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "task_keyed_prompt_contract",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_RESPONSE_FIELDS),
                "properties": {
                    "semantic_decisions": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(semantics),
                        "properties": {
                            semantic_id: semantic_value for semantic_id in semantics
                        },
                    },
                    "relation_decisions": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(relations),
                        "properties": {
                            relation_id: relation_value for relation_id in relations
                        },
                    },
                },
            },
        },
    }


def _close_relation_endpoint_states(
    semantic_decisions: tuple[SemanticDecision, ...],
    relation_decisions: tuple[RelationDecision, ...],
) -> tuple[RelationDecision, ...]:
    """Project relation states implied by their semantic endpoint states."""

    semantic_states = {row.semantic_id: row.state for row in semantic_decisions}
    closed = []
    for row in relation_decisions:
        endpoint_states = {
            semantic_states.get(row.source_semantic_id),
            semantic_states.get(row.target_semantic_id),
        }
        if QueryState.ABSENT in endpoint_states:
            closed.append(
                replace(
                    row,
                    state=QueryState.ABSENT,
                    rationale=(
                        "Deterministic endpoint closure: at least one endpoint is absent."
                    ),
                )
            )
        elif QueryState.UNRESOLVED in endpoint_states:
            closed.append(
                replace(
                    row,
                    state=QueryState.UNRESOLVED,
                    rationale=(
                        "Deterministic endpoint closure: at least one endpoint is unresolved."
                    ),
                )
            )
        else:
            closed.append(row)
    return tuple(closed)


def _canonical_prompt_evidence(
    prompt: str, evidence_text: object, occurrence: object
) -> tuple[str, int] | None:
    """Bind transport-normalized evidence back to one exact source-prompt span."""

    if (
        not isinstance(evidence_text, str)
        or not evidence_text
        or len(evidence_text.encode("utf-8")) > 2048
        or type(occurrence) is not int
        or occurrence <= 0
    ):
        return None
    candidates: list[str] = []

    def add(value: str) -> None:
        if value and value not in candidates:
            candidates.append(value)

    add(evidence_text)
    add(evidence_text.strip())
    for value in tuple(candidates):
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'", "`"}:
            add(value[1:-1].strip())
    for value in tuple(candidates):
        add(value.replace(r'\"', '"').replace(r"\'", "'"))

    for candidate in candidates:
        starts = _literal_starts(prompt, candidate)
        if occurrence <= len(starts):
            return candidate, occurrence
    for candidate in candidates:
        tokens = candidate.split()
        if len(tokens) < 2:
            continue
        matches = list(re.finditer(r"\s+".join(re.escape(token) for token in tokens), prompt))
        if occurrence > len(matches):
            continue
        match = matches[occurrence - 1]
        exact = prompt[match.start() : match.end()]
        exact_starts = _literal_starts(prompt, exact)
        return exact, exact_starts.index(match.start()) + 1
    return None


def _literal_starts(text: str, fragment: str) -> list[int]:
    starts: list[int] = []
    offset = 0
    while True:
        offset = text.find(fragment, offset)
        if offset < 0:
            return starts
        starts.append(offset)
        offset += 1


def _demote_unbound_present_evidence(
    prompt: str, semantic_decisions: tuple[SemanticDecision, ...]
) -> tuple[SemanticDecision, ...]:
    """Fail closed when a presence citation cannot bind to the source prompt."""

    closed = []
    for row in semantic_decisions:
        if row.state is not QueryState.PRESENT:
            closed.append(row)
            continue
        evidence = _canonical_prompt_evidence(prompt, row.evidence_text, row.occurrence)
        if evidence is None:
            closed.append(
                replace(
                    row,
                    state=QueryState.UNRESOLVED,
                    rationale=(
                        "Deterministic evidence occurrence validation: claimed presence lacks "
                        "an exact source-prompt occurrence; conservatively unresolved."
                    ),
                    evidence_text=None,
                    occurrence=None,
                    attributes=(),
                )
            )
        else:
            closed.append(replace(row, evidence_text=evidence[0], occurrence=evidence[1]))
    return tuple(closed)


def contract_decision_request(
    task: Mapping[str, Any], catalog: Mapping[str, Any]
) -> dict[str, Any]:
    """Build the finite source-only table without exposing routing labels or query logic."""

    if catalog.get("schema_version") == "2.0":
        task = prepare_task_input(task)
        template = _template_for_catalog(task, catalog)
        return {
            "request_kind": "source_only_fact_inventory", "source_prompt": task["prompt"],
            "source_tokens": {str(index): token.group() for index, token in enumerate(_source_tokens(task["prompt"]), 1)},
            "evidence_coordinates": "Inclusive start/end keys from source_tokens. Tokens index the unchanged complete source_prompt, including punctuation; they carry no semantic labels.",
            "input_scope": "baseline_system_message_and_user_request",
            "message_roles": "System message has priority over User message. System message, User message and Task are provenance labels, not extra requirements. Language is an actual field supplied to the generator and must be considered with the message contents.",
            "concept_policy": catalog["concept_policy"],
            "known_concepts": {key: {"node_type": value, "definition": catalog["semantic_guidance"].get(key, ""),
                                     **({"layer": catalog["semantic_layers"][key]} if key in catalog.get("semantic_layers", {}) else {}),
                                     **({"source_name_terms": catalog["source_name_terms"][key]}
                                        if key in catalog.get("source_name_terms", {}) else {})}
                               for key, value in catalog["semantics"].items() if key != "task.root"
                               and key not in {row["concept_id"] for row in template["concepts"]}
                               and has_required_source_name(catalog, key, task["prompt"])},
            **({"source_name_policy": (
                    "For a concept with source_name_terms, its cited identity evidence must contain at least one "
                    "declared literal name as a whole identifier, ignoring case. A name inside a longer identifier "
                    "does not qualify. The compiler checks this prerequisite; a match alone does not establish "
                    "the entity, role or full concept meaning. Imports, negations and unrelated mentions still "
                    "require source-semantic review. Excluded concepts lack their declared name in the source; "
                    "this is not an absence judgment about the underlying property. Preserve any stated generic "
                    "entity with an admissible concept, or record a source gap rather than inventing a name."),
                "excluded_source_name_concepts": {key: terms for key, terms in catalog["source_name_terms"].items()
                    if not has_required_source_name(catalog, key, task["prompt"])}}
               if "source_name_terms" in catalog else {}),
            "allowed_node_types": [value for value in catalog["node_types"] if value != "task"],
            "fixed_template": template,
            "source_units": _source_units(task, fixed_template=bool(template["nodes"])),
            "annotation_phase": "source_covered_fact_draft",
            "source_instance_policy": "Use an action-specific identity quote for each operation. Distinct instances of the SAME operation concept must have non-overlapping identity spans; keep wider supporting clauses in source_units, not in a quote spanning the other operation. Exact duplicate instances may be merged. Different atomic concepts may share contextual evidence. Preserve object identity qualifiers, including whether a named result is an individual value or a whole collection. Role evidence may retain wider context independently of identity quotes.",
            "fact_granularity": "Each node represents one source semantic unit. Each requirement node must express one independently specified requirement: split separately changeable requirements into distinct nodes during this inventory, before binding edges or constructing candidates. A sentence may support several atomic nodes, and their source-token spans may overlap. Preserve the whole meaning of each atom, including negation, quantifiers, comparison operators and thresholds; do not split a predicate into meaningless words or detach a condition from its obligation. Represent explicit conditions as their own facts and retain their source-supported bindings in the binding step. A single atomic requirement may apply to multiple explicitly stated operations or objects; scope multiplicity does not itself make the meaning composite. Under FROZEN, missing atomic meanings remain unresolved; do not substitute a composite or partially entailed known concept. If atomic decomposition is ambiguous, mark the source unit unresolved and explain the ambiguity. Semantic atomicity remains subject to source review, not a conclusion proved by valid JSON.",
            "operation_feature_checks": [],
            "development_scope": "Inventory atomic source facts with generation/runtime layer and source-unit coverage. Nodes cite preassigned source-unit keys; the program assigns all fact IDs after this response. Do not output local_id, operation_roles or cross-references between new facts. Under DEVELOPMENT_OPEN, each node carries its complete inline concept; under FROZEN it selects a known concept_id. Coverage rows contain status and reason only; no_task_fact means no additional fact beyond the supplied fixed template. The fixed template facts/edges are already supplied by the program: never redeclare or replace them. Role declarations are source propositions, not code predictions or committed graph edges. Report missing meanings explicitly; do not substitute another object. Relation confirmation and scope judgments follow separately.",
            "arms_or_outcomes_included": False,
        }
    required = {"task_id", "prompt", "cwe", "task_family"}
    if not required <= set(task) or any(
        not isinstance(task[field], str) or not task[field].strip() for field in required
    ):
        raise PromptContractExtractionError("task lacks contract extraction coordinates")
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )
    return {
        "schema_version": "1.0",
        "request_kind": "blind_exhaustive_task_context_annotation",
        "source_prompt": task["prompt"],
        "candidate_semantics": {
            semantic_id: {
                "node_type": catalog["semantics"][semantic_id],
                "guidance": catalog["semantic_guidance"].get(
                    semantic_id,
                    "Mark present only when the source prompt directly entails this role.",
                ),
            }
            for semantic_id in scope["semantic_ids"]
        },
        "candidate_relations": {
            _relation_decision_key(relation): list(relation)
            for relation in scope["relations"]
        },
        "allowed_attributes": list(catalog["attribute_names"]),
        "decision_states": ["present", "absent", "unresolved"],
        "arms_or_outcomes_included": False,
        "output_contract": {
            "top_level_keys": ["semantic_decisions", "relation_decisions"],
            "semantic_decision_value_keys": sorted(_SEMANTIC_FIELDS),
            "relation_decision_value_keys": sorted(_RELATION_FIELDS),
            "semantic_rows": "object keyed exactly by every candidate_semantics key",
            "relation_rows": "object keyed exactly by every candidate_relations key",
            "present_semantic_evidence": (
                "exact contiguous source_prompt substring plus 1-based occurrence that "
                "supports the catalog's operational definition; topical overlap, a CWE, "
                "a function name, or a merely possible implementation is not support"
            ),
            "rationale": (
                "non-empty concise audit explanation retained only in the raw response; "
                "never use it instead of evidence"
            ),
            "attributes": (
                "JSON array of unique allowed attribute names asserted true; never an object"
            ),
            "non_present_evidence": (
                "null evidence_text, null occurrence, empty attributes array"
            ),
        },
    }


def contract_from_response(
    raw: bytes,
    *,
    task: Mapping[str, Any],
    catalog: Mapping[str, Any],
    annotator_id: str,
    review_status: str,
) -> TaskContextContract:
    """Parse one exhaustive model decision table and reject any omitted row."""

    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PromptContractExtractionError("contract response is not JSON") from None
    return contract_from_value(value, task=task, catalog=catalog,
                               annotator_id=annotator_id, review_status=review_status)


def contract_from_value(value: Any, *, task: Mapping[str, Any], catalog: Mapping[str, Any],
                        annotator_id: str, review_status: str) -> TaskContextContract:
    """Compile parsed source facts with the same validation as external responses."""
    if catalog.get("schema_version") == "2.0":
        task = prepare_task_input(task)
        value, inventory = _indexed_facts_response(value, prompt=task["prompt"], request=contract_decision_request(task, catalog))
        contract = open_contract_from_response(value, task=task, catalog=catalog,
                                              annotator_id=annotator_id, review_status=review_status,
                                              source_inventory=inventory)
        return contract
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS:
        raise PromptContractExtractionError("contract response fields are invalid")
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )
    expected_semantics = set(scope["semantic_ids"])
    relation_by_key = {
        _relation_decision_key(relation): relation for relation in scope["relations"]
    }
    semantic_rows = value["semantic_decisions"]
    relation_rows = value["relation_decisions"]
    if not isinstance(semantic_rows, dict) or not isinstance(relation_rows, dict):
        raise PromptContractExtractionError("contract decision tables are invalid")
    if set(semantic_rows) != expected_semantics or set(relation_rows) != set(
        relation_by_key
    ):
        raise PromptContractExtractionError("contract decision rows are not exhaustive")
    if (
        any(
            not isinstance(row, dict) or set(row) != _SEMANTIC_FIELDS
            for row in semantic_rows.values()
        )
        or any(
            not isinstance(row, dict) or set(row) != _RELATION_FIELDS
            for row in relation_rows.values()
        )
    ):
        raise PromptContractExtractionError("contract decision row fields are invalid")
    if any(
        not isinstance(row["rationale"], str) or not row["rationale"].strip()
        for row in (*semantic_rows.values(), *relation_rows.values())
    ):
        raise PromptContractExtractionError("contract decision rationale is invalid")
    if any(
        not isinstance(row["attributes"], list)
        or any(
            not isinstance(attribute, str) or not attribute
            for attribute in row["attributes"]
        )
        or len(row["attributes"]) != len(set(row["attributes"]))
        for row in semantic_rows.values()
    ):
        raise PromptContractExtractionError("contract semantic attributes are invalid")
    try:
        semantic_decisions = tuple(
            SemanticDecision(
                semantic_id,
                QueryState(row["state"]),
                (
                    "Annotator declared this semantic "
                    f"{QueryState(row['state']).value}; the audit explanation is retained "
                    "only in the raw response."
                ),
                (
                    row["evidence_text"]
                    if QueryState(row["state"]) is QueryState.PRESENT
                    else None
                ),
                (
                    row["occurrence"]
                    if QueryState(row["state"]) is QueryState.PRESENT
                    else None
                ),
                (
                    tuple((attribute, True) for attribute in sorted(row["attributes"]))
                    if QueryState(row["state"]) is QueryState.PRESENT
                    else ()
                ),
            )
            for semantic_id, row in semantic_rows.items()
        )
        relation_decisions = tuple(
            RelationDecision(
                relation_by_key[relation_id][0],
                relation_by_key[relation_id][1],
                relation_by_key[relation_id][2],
                QueryState(row["state"]),
                (
                    "Annotator declared this relation "
                    f"{QueryState(row['state']).value}; the audit explanation is retained "
                    "only in the raw response."
                ),
            )
            for relation_id, row in relation_rows.items()
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise PromptContractExtractionError("contract decision values are invalid") from None
    semantic_decisions = _demote_unbound_present_evidence(
        task["prompt"], semantic_decisions
    )
    relation_decisions = _close_relation_endpoint_states(
        semantic_decisions, relation_decisions
    )
    contract = TaskContextContract(
        "2.0",
        task["task_id"],
        content_hash(task["prompt"]),
        catalog_sha256(catalog),
        task["cwe"],
        task["task_family"],
        scope["query_ids"],
        annotator_id,
        review_status,
        False,
        tuple(sorted(semantic_decisions, key=lambda row: row.semantic_id)),
        tuple(sorted(relation_decisions, key=lambda row: row.relation)),
    )
    try:
        compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    except PromptTSGError as error:
        raise PromptContractExtractionError(str(error)) from None
    return contract

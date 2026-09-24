"""Source evidence, schemas and deterministic contract compilation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
import re
from copy import deepcopy
from dataclasses import replace
from prompt_mechanism_study.tsg.prompt_contract import OpenTaskContract
from prompt_mechanism_study.tsg.task_input import prepare_task_input, generation_template_facts


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
    """The source request, model response, or extraction closure is invalid."""


def _has_fixed_concept_layers(request: Mapping[str, Any]) -> bool:
    known = request.get("known_concepts", {})
    return (request.get("concept_policy") == "FROZEN" and bool(known)
            and all("layer" in concept for concept in known.values()))


def source_fact_schema(request: Mapping[str, Any], *, group: str) -> dict[str, Any]:
    """Define a fact once; response adapters add their own references/participants."""
    text = {"type": "string"}
    def row(properties):
        return dict(type="object", additionalProperties=False, properties=properties, required=list(properties))
    concept = dict(type="string", description="Exact supplied or declared concept ID whose complete definition the source entails. Each requirement node expresses one atomic requirement, never a bundle of independently changeable requirements.")
    if request["concept_policy"] == "FROZEN" and request["known_concepts"]:
        concept["enum"] = list(request["known_concepts"])
    meaning = dict(concept_id=concept) if request["concept_policy"] == "FROZEN" else dict(
        concept=row(dict(concept_id=text, node_type=dict(type="string", enum=request["allowed_node_types"]), definition=text)))
    citation_fields = dict(source_units=dict(type="array", minItems=1,
        items=dict(type="string", enum=list(request["source_units"]))),
        layer=dict(type="string", enum=["generation", "runtime", "unresolved"]))
    if _has_fixed_concept_layers(request):
        del citation_fields["layer"]
    fields = dict(**source_citation_schema(request), **citation_fields, **meaning)
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
    """Prepare source quotes for the record interface; positions stay internal."""
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
    """Return the active atomic-record response schema."""
    if request.get("request_kind") == "source_only_atomic_records":
        from prompt_mechanism_study.tsg.source_records import record_response_format
        return record_response_format(request)
    raise PromptContractExtractionError("unsupported source response request")


def _literal_starts(text: str, fragment: str) -> list[int]:
    starts: list[int] = []
    offset = 0
    while True:
        offset = text.find(fragment, offset)
        if offset < 0:
            return starts
        starts.append(offset)
        offset += 1


def contract_decision_request(
    task: Mapping[str, Any], catalog: Mapping[str, Any]
) -> dict[str, Any]:
    """Build a source-only inventory request without outcome or arm labels."""

    if catalog.get("schema_version") != "2.0":
        raise PromptContractExtractionError("open-graph catalog is required")
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
                                 **({"layer": catalog["semantic_layers"][key]} if key in catalog.get("semantic_layers", {}) else {})}
                           for key, value in catalog["semantics"].items() if key != "task.root"
                           and key not in {row["concept_id"] for row in template["concepts"]}},
        "allowed_node_types": [value for value in catalog["node_types"] if value != "task"],
        "fixed_template": template,
        "source_units": _source_units(task, fixed_template=bool(template["nodes"])),
        "operation_feature_checks": [],
        "arms_or_outcomes_included": False,
    }

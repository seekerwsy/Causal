"""Candidate applicability and expression on fixed source graphs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from dataclasses import replace
from prompt_mechanism_study.artifact_io import json_object
from prompt_mechanism_study.tsg.prompt_contract import (
    compile_task_context_contract,
    OpenTaskContract,
)
from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSGError,
    requirement_covers_scope,
    requirement_matches_policy,
    select_feature_scope,
    FeatureScope,
    _occurrence_span,
)
from prompt_mechanism_study.tsg.source_codec import (
    PromptContractExtractionError,
    _INPUT_ROLES,
    _OBJECT_ROLE_MEANINGS,
)


_EXPRESSION_STATES = {
    "explicitly_required": "present",
    "not_expressed": "absent",
    "unresolved": "unresolved",
}


_APPLICABILITY_STATES = ("applicable", "not_applicable", "unresolved")


def _inventory_status(contract: OpenTaskContract) -> dict[str, Any]:
    """Expose missing submitted coverage/role bindings without guessing source meaning."""
    inventory = contract.source_inventory
    if inventory is None:
        return dict(status="AUTHORED_FIXTURE", unresolved_units=[], unresolved_layers=[], missing_role_bindings=[])
    links = {(r["source"], r["edge_type"], r["target"]) for r in contract.relations}
    missing = []
    for role in inventory["operation_roles"]:
        edge = ((role["operation"], "produces", role["subject"]) if role["role"] == "result"
                else (role["subject"], "used_by", role["operation"]))
        if edge not in links:
            missing.append(dict(operation=role["operation"], subject=role["subject"], role=role["role"]))
    unresolved = [key for key, row in inventory["coverage"].items() if row["status"] == "unresolved"
                  or key in inventory.get("unit_impacts", {}) and not inventory["unit_impacts"][key]["complete"]]
    layers = [key for key, layer in inventory["layers"].items() if layer == "unresolved"]
    return dict(status="INCOMPLETE" if unresolved or layers or missing else "COVERED_PENDING_SOURCE_REVIEW",
                unresolved_units=unresolved, unresolved_layers=layers, missing_role_bindings=missing)


def fixed_scope_request(
    contract: OpenTaskContract, *, prompt: str, catalog: Mapping[str, Any],
) -> dict[str, Any]:
    """Enumerate source-bound scopes after graph construction, without outcomes.

    Use existing local coordinates; the scope annotation cannot invent an
    operation, input, condition, edge, or requirement. Singleton inputs and the
    explicitly enumerated full input set are assessed separately. Other subsets
    remain unassessed, not absent. Conditions come from source graph bindings.
    """
    graph = compile_task_context_contract(contract, prompt=prompt, catalog=catalog)
    facts = {row["local_id"]: row for row in contract.facts}
    from prompt_mechanism_study.tsg.prompt_tsg import (
        requirement_membership,
        select_policy_relation_endpoints,
        REQUIREMENT_TYPES,
    )
    structures = (contract.source_inventory or {}).get('requirement_structures', {})
    asserted_requirements, atomic_requirements = requirement_membership(
        [(key, row['kind'], row['members']) for key,row in structures.items()],
        {key for key,row in facts.items() if row['node_type'] in REQUIREMENT_TYPES})
    links = {(row["source"], row["edge_type"], row["target"]) for row in contract.relations}
    selectors = catalog.get("feature_scope_selectors", {})
    graph_nodes = {(node.semantic_id, node.evidence_start, node.evidence_end): node.node_id for node in graph.nodes}
    local_to_node = {key: graph_nodes[(row["semantic_id"], *_occurrence_span(prompt, row["evidence_text"], row["occurrence"]))]
                     for key, row in facts.items()}
    root = next(node for node in graph.nodes if node.semantic_id == "task.root")
    local_to_node["task.root"] = root.node_id
    node_to_local = {value: key for key, value in local_to_node.items()}
    if any(s["operation_semantic_id"] == "task.root" for s in selectors.values()):
        facts["task.root"] = dict(local_id="task.root", semantic_id="task.root", node_type="task",
                                  evidence_text=prompt, occurrence=1)
    candidates = set()
    for query in catalog["queries"]:
        selector = selectors.get(query["actionable_feature_id"])
        if selector:
            selected = select_feature_scope(graph, selector)
            if selected is not None:
                candidates.add((node_to_local[selected.operation_node_id],
                    tuple(sorted(node_to_local[key] for key in selected.subject_node_ids)),
                    tuple(sorted(node_to_local[key] for key in selected.condition_node_ids)),
                    query["actionable_feature_id"]))
            continue
        operations = {key for key in query["required_semantics"]
                      if catalog["semantics"][key] == "task_operation"}
        for op, fact in facts.items():
            if fact["semantic_id"] not in operations:
                continue
            if contract.source_inventory is None:
                inputs = tuple(sorted(source for source, relation, target in links
                                      if relation == "used_by" and target == op))
            else:
                inputs = tuple(sorted({r["subject"] for r in contract.source_inventory["operation_roles"]
                                       if r["operation"] == op and r["role"] in _INPUT_ROLES}))
            subjects = {(), *((key,) for key in inputs)}
            if len(inputs) > 1:
                subjects.add(inputs)
            requirements = {source for source, relation, target in links
                            if relation == "constrains" and target == op}
            operation_conditions = {source for source, relation, target in links
                                    if relation == "conditions" and target == op}
            conditions = {tuple(sorted(operation_conditions))}
            for source, relation, target in links:
                if relation == 'context_for' and target == op:
                    conditions.add(tuple(sorted(operation_conditions | {source})))
            for requirement in requirements:
                conditions.add(tuple(sorted(operation_conditions | {
                    source for source, relation, target in links
                    if relation == "conditions" and target == requirement})))
            for objects in subjects:
                for fixed_conditions in conditions:
                    candidates.add((op, objects, fixed_conditions, query["actionable_feature_id"]))
    scopes = {
        f"s{index + 1}": dict(target=op, subjects=list(objects), conditions=list(conditions),
                             concept_id=feature,
                             definition=catalog["semantic_guidance"].get(feature, ""))
        for index, (op, objects, conditions, feature) in enumerate(sorted(candidates))
    }
    if "feature_scope_domains" in catalog:
        for scope in scopes.values():
            scope["subject_domain"] = catalog["feature_scope_domains"][scope["concept_id"]]
    for scope in scopes.values():
        selector = selectors.get(scope["concept_id"])
        if selector:
            coordinate = FeatureScope(local_to_node[scope["target"]],
                tuple(sorted(local_to_node[key] for key in scope["subjects"])),
                tuple(sorted(local_to_node[key] for key in scope["conditions"])))
            scope["policy_scope"] = selector
            scope["policy_conditions"] = [dict(concept_id=key, definition=catalog["semantic_guidance"][key])
                                           for key in selector["policy_condition_semantic_ids"]]
            if selector.get("policy_relations"):
                endpoints = select_policy_relation_endpoints(graph, selector)
                scope["policy_relations"] = [dict(source=node_to_local[a], edge_type=relation, target=node_to_local[b])
                    for a, relation, b in (endpoints or ())]
            if "applicability_scope" in selector:
                scope["coordinate_kind"] = "applicability_background"
                policy_coordinate = select_feature_scope(graph, {key: value for key, value in selector.items()
                                                                 if key != "applicability_scope"})
                scope["policy_coordinate"] = (dict(target=node_to_local[policy_coordinate.operation_node_id],
                    subjects=[node_to_local[key] for key in policy_coordinate.subject_node_ids],
                    conditions=[node_to_local[key] for key in policy_coordinate.condition_node_ids])
                    if policy_coordinate else None)
                scope["policy_relation_definitions"] = [dict(
                    source=dict(concept_id=a, definition=catalog["semantic_guidance"][a]), edge_type=relation,
                    target=dict(concept_id=b, definition=catalog["semantic_guidance"][b]))
                    for a, relation, b in selector.get("policy_relations", ())]
            scope["admissible_positive_requirements"] = sorted(key for key, fact in facts.items()
                if fact["semantic_id"] == scope["concept_id"] and key in asserted_requirements
                and (contract.source_inventory or {}).get("statement_kinds", {}).get(key, "obligation") == "obligation"
                and requirement_matches_policy(graph, local_to_node[key], coordinate, selector))
        else:
            scope["admissible_positive_requirements"] = sorted(key for key, fact in facts.items()
            if fact["semantic_id"] == scope["concept_id"]
            and key in atomic_requirements
            and not (contract.source_inventory or {}).get("requirement_relations", {}).get(key)
            and (contract.source_inventory or {}).get("statement_kinds", {}).get(key, "obligation") == "obligation"
            and requirement_covers_scope(key, scope["target"], scope["subjects"], scope["conditions"],
                links=links, node_types={k: f["node_type"] for k, f in facts.items()}))
        scope["bound_subject_roles"] = {
            subject: [dict(role=r["role"], evidence_text=r["evidence_text"], occurrence=r["occurrence"])
                      for r in ([] if contract.source_inventory is None else contract.source_inventory["operation_roles"])
                      if r["operation"] == scope["target"] and r["subject"] == subject]
            for subject in scope["subjects"]
        }
    inventory_status = _inventory_status(contract)
    # Withhold only scopes that this structural projection cannot represent.
    # Source completeness/locality judgments are model evidence, not program gates.
    blockers = {key: [] for key in scopes}
    for key, row in scopes.items():
        if row["concept_id"] in selectors:
            continue  # Whole-policy matching above does not require a local projection.
        blockers[key] += ['unprojected_requirement:'+fact_id
            for fact_id in (contract.source_inventory or {}).get('requirement_scopes', {})
            if facts[fact_id]['semantic_id']==row['concept_id']]
        blockers[key] += ['unprojected_requirement_relation:'+fact_id
            for fact_id, relations in (contract.source_inventory or {}).get('requirement_relations', {}).items()
            if relations and facts[fact_id]['semantic_id']==row['concept_id']]
        # A mentioned alternative is neither an independently expressed factor nor
        # evidence of its absence. Keep these coordinates explicitly withheld.
        if not row['admissible_positive_requirements']:
            blockers[key] += ['requirement_structure:'+fact_id for fact_id,fact in facts.items()
                if fact['semantic_id']==row['concept_id'] and fact_id not in atomic_requirements
                and (fact_id,'constrains',row['target']) in links]
    withheld = {key: row for key, row in scopes.items() if blockers[key]}
    return {
        "request_kind": "source_only_fixed_scope_states",
        "assessment_question": "For each complete binding, judge applicability with source rationale, and separately whether the source expresses the requirement. Neither judgment predicts future generated code. Missing judgments remain unresolved.",
        "binding_consistency": "Judge complete definitions, bound roles, conditions and non-target requirements against the full source. Inventory gaps and unit impacts are annotation evidence: decide whether they affect this binding; do not ignore relevant uncertainty. Unsupported or ambiguous bindings remain unresolved. Concept IDs and role names alone do not establish applicability.",
        "whole_policy_semantics": (
            "When policy_scope is supplied, assess the COMPLETE frozen policy at that boundary. "
            "For scope_kind=objects, task.root is only a coordinate anchor: the policy constrains "
            "the exact named objects, not the entire task or every operation using them. No operation "
            "incidence or result relation is inferred; object applicability still needs source support. "
            "policy_conditions are internal to the policy, not additional task-selection facts; "
            "their absence from the source is not by itself an unresolved context. They must be "
            "preserved in a positive requirement's structural guards. policy_relations likewise "
            "belong to the requirement: preserve their exact "
            "direction and endpoints in positive evidence. When coordinate_kind=applicability_background, "
            "target/subjects/conditions identify the separately reviewed task background, not the policy's "
            "direct targets. policy_coordinate is the source-resolved complete policy coordinate, or null "
            "when it cannot be resolved. policy_relation_definitions retain frozen operand meanings even "
            "when corresponding source operations are absent. Do not create those operations to fill the "
            "background. The background must be supported independently of the target policy; its geometry "
            "alone does not establish that independence. Missing policy operands do not prove not_expressed: "
            "read the complete source, and use unresolved if source meaning or its binding remains unclear. "
            "Without an explicit applicability_background coordinate, the fixed selector still requires its "
            "policy operands to exist. The order itself is not an applicability prerequisite and is never inferred from free text. "
            "An endpoint is an operand, not an additional direct target. task means one overall runtime "
            "contract; each means a universal rule over target_class, never a finite instance list. "
            "Verify from the unchanged task that the policy is meaningful and feasible. A root node, "
            "the policy's presence, or a vacuously empty class proves no applicability. Relevant "
            "background operations, objects, interfaces and non-target obligations must remain unchanged. "
            "Only whole OR/NOT expressions may be positive, never their unasserted members. "
            "Preserve ordered predicates such as before/after in the complete definition; reversed "
            "order is not equivalent. No condition or qualifier may be recovered only from a label."),
        "domain_evidence_policy": "Explain whether the original task supports the prerequisites of this complete policy. Do not invent types, operations or boundaries from customary implementations. An unresolved prerequisite is not absence or inapplicability.",
        "applicability_meanings": {
            "applicable": "The operation role and every subject role are resolved and the definition applies to the entire fixed scope. Explain the source support for the operation and all subjects; the program retains their fixed fact references.",
            "not_applicable": "The definition is demonstrably inapplicable to the operation or to every subject in this scope. Explain the source basis; missing evidence is not inapplicability.",
            "unresolved": "At least one necessary role is ambiguous or unsupported, or the subject set mixes applicable and inapplicable roles.",
        },
        "answer_meanings": {
            "explicitly_required": "The source expresses the positive requirement for the entire fixed scope with existing requirement evidence; this expression judgment alone does not settle applicability.",
            "not_expressed": "Complete source reading resolves that this requirement is not expressed in the exact scope. This can coexist with unresolved applicability and does not imply that future code lacks protection.",
            "unresolved": "Expression or its exact scope binding is unresolved, including partial/conditional coverage or a stated requirement missing from the fixed graph.",
        },
        "expression_explanation_policy": "Judge expression independently from the complete source. The program records that judgment with this exact feature, operation, subjects and conditions, without requiring a copied explanation. This recording does not decide expression or certify source completeness. Positive expression still requires source-bound requirement IDs.",
        "state_composition": "Only applicable plus explicitly_required yields present, and applicable plus not_expressed yields absent. not_applicable plus not_expressed yields not_applicable. Any unresolved judgment, missing evidence or contradiction yields unresolved. Never infer an omitted judgment.",
        "source_contract_id": contract.contract_id,
        "source_prompt": prompt,
        "facts": [dict(local_id=key, concept_id=row["semantic_id"], node_type=row["node_type"],
                       definition=contract.catalog["semantic_guidance"].get(row["semantic_id"], ""),
                       evidence_text=row["evidence_text"], occurrence=row["occurrence"])
                  for key, row in sorted(facts.items())],
        "relations": list(contract.relations),
        "scopes": {key: row for key, row in scopes.items() if key not in withheld},
        "withheld_scopes": withheld,
        "scope_blockers": {key: reasons for key, reasons in blockers.items() if reasons},
        "retained_requirement_scopes": (contract.source_inventory or {}).get('requirement_scopes', {}),
        **({"requirement_relations": contract.source_inventory["requirement_relations"]}
           if (contract.source_inventory or {}).get("requirement_relations") else {}),
        "unit_impacts": {} if contract.source_inventory is None else contract.source_inventory.get("unit_impacts", {}),
        "source_inventory_status": inventory_status,
        "operation_roles": [] if contract.source_inventory is None else contract.source_inventory["operation_roles"],
        "operation_role_meanings": dict(_OBJECT_ROLE_MEANINGS),
        "unresolved_graph_notes": list(contract.unresolved_notes),
        "arms_or_outcomes_included": False,
    }


def _scope_expression_rationale(scope: Mapping[str, Any], expression: str) -> str:
    coordinate = json.dumps({k: scope[k] for k in ("concept_id", "target", "subjects", "conditions")},
                            ensure_ascii=False, separators=(",", ":"))
    return {
        "explicitly_required": "Source annotation: the requirement is explicitly expressed for this exact scope, supported by the cited requirement IDs: ",
        "not_expressed": "Source annotation: the requirement is not expressed in the complete source for this exact scope; this does not describe future generated code: ",
        "unresolved": "Source annotation: requirement expression or its precise binding remains unresolved for this exact scope: ",
    }[expression] + coordinate


def fixed_scope_response_format(request: Mapping[str, Any]) -> dict[str, Any]:
    def object_schema(properties):
        return dict(type="object", properties=properties, required=list(properties), additionalProperties=False)
    properties = {}
    facts = {row["local_id"]: row for row in request["facts"]}
    for key, scope in request["scopes"].items():
        requirements = scope["admissible_positive_requirements"]
        expressions = list(_EXPRESSION_STATES) if requirements else ["not_expressed", "unresolved"]
        evidence = {"type": "array", "items": {"type": "string"}}
        if requirements:
            evidence["items"]["enum"] = requirements
        else:
            evidence["maxItems"] = 0
        domain_unbound = (scope.get("subject_domain") == "subjects" and not scope["subjects"]
                          or scope.get("subject_domain") == "operation" and bool(scope["subjects"]))
        properties[key] = object_schema({
            "expression": {"type": "string", "enum": expressions,
                           "description": "Whether the source expresses the requirement, independently of applicability. not_expressed alone cannot become absent."},
            "requirements": evidence,
        })
        properties[key] = object_schema({**properties[key]["properties"],
            "applicability": {"type": "string", "enum": ["unresolved"] if domain_unbound else list(_APPLICABILITY_STATES)},
            "applicability_rationale": {"type": "string", "description": "Explain source support or uncertainty for this complete binding; do not reason from future code."}})
        subjects = [f"{subject} {facts[subject]['concept_id']} roles=" +
                    ",".join(row["role"] for row in scope["bound_subject_roles"][subject])
                    for subject in scope["subjects"]]
        properties[key]["description"] = (f"{scope['concept_id']} at {scope['target']} "
            f"{facts[scope['target']]['concept_id']}; subjects: " + ("; ".join(subjects) or "none") +
            ". Use complete fact definitions and quoted bound roles in the request; this label is not an applicability verdict.")
    fields = {"states": object_schema(properties),
              "unresolved_notes": {"type": "array", "items": {"type": "string"}}}
    schema = object_schema(fields)
    return {"type": "json_schema", "json_schema": {
        "name": "fixed_source_scope_states", "strict": True, "schema": schema}}


def apply_fixed_scope_response(
    raw: bytes, *, request: Mapping[str, Any], contract: OpenTaskContract,
    prompt: str, catalog: Mapping[str, Any],
) -> OpenTaskContract:
    """Bind each state to its requested scope; malformed or conflicting rows stay unknown."""
    if request != fixed_scope_request(contract, prompt=prompt, catalog=catalog):
        raise PromptContractExtractionError("scope request does not bind its exact source contract")
    value = json_object(raw)
    expected_fields = {"states", "unresolved_notes"}
    if (set(value) != expected_fields or not isinstance(value["states"], dict)
        or not isinstance(value["unresolved_notes"], list)
        or any(not isinstance(note, str) for note in value["unresolved_notes"])
        or set(value["states"]) - set(request["scopes"])):
        raise PromptContractExtractionError("fixed scope response fields are invalid")
    notes = [*contract.unresolved_notes, *value["unresolved_notes"]]
    assessments = []
    # The preceding annotations supply facts and bindings only; no omitted
    # scope answer is a default or evidence of absence.
    base = replace(contract, feature_states=())
    for key, scope in request["scopes"].items():
        supplied = value["states"].get(key)
        row = {name: scope[name] for name in ("target", "subjects", "conditions", "concept_id")}
        error = None
        if (not isinstance(supplied, dict) or set(supplied) != {
                "applicability", "applicability_rationale", "expression", "requirements"}
            or supplied.get("applicability") not in _APPLICABILITY_STATES
            or supplied.get("expression") not in _EXPRESSION_STATES
            or not isinstance(supplied.get("requirements"), list)
            or any(not isinstance(item, str) for item in supplied["requirements"])
            or len(set(supplied["requirements"])) != len(supplied["requirements"])
            or not isinstance(supplied.get("applicability_rationale"), str)
            or not supplied["applicability_rationale"].strip()):
            error = "missing or malformed state row"
        else:
            applicability, expression = supplied["applicability"], supplied["expression"]
            if expression != "explicitly_required" and supplied["requirements"]:
                error = "non-positive expression contains positive requirement evidence"
            elif expression == "explicitly_required" and (
                not supplied["requirements"]
                or not set(supplied["requirements"]) <= set(scope["admissible_positive_requirements"])):
                error = "positive expression lacks exact requirement-to-scope evidence"
            elif applicability == "not_applicable" and expression == "explicitly_required":
                error = "positive expression contradicts declared inapplicability"
            state = "unresolved"
            if applicability == "applicable":
                state = _EXPRESSION_STATES[expression]
            elif applicability == "not_applicable" and expression == "not_expressed":
                state = "not_applicable"
            row.update(state=state, requirements=sorted(supplied["requirements"]) if state == "present" else [],
                       rationale=f"Applicability ({applicability}): {supplied['applicability_rationale']} Expression ({expression}): {_scope_expression_rationale(scope, expression)}")
            try:
                if error is None:
                    compile_task_context_contract(replace(base, feature_states=(row,)),
                                                  prompt=prompt, catalog=catalog)
            except PromptTSGError as failure:
                error = str(failure)
        if error:
            row.update(state="unresolved", requirements=[], rationale="No valid source-bound assessment.")
            notes.append(f"unresolved_fixed_scope: {key}: {error}")
        assessments.append(row)
    result = replace(base, feature_states=tuple(assessments), unresolved_notes=tuple(notes))
    compile_task_context_contract(result, prompt=prompt, catalog=catalog)
    return result

"""Candidate applicability and expression on fixed source graphs."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from prompt_mechanism_study.artifact_io import json_object
from prompt_mechanism_study.tsg.prompt_contract import (
    compile_task_context_contract,
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
    _literal_starts,
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
    if not any(layer == "runtime" for layer in inventory["layers"].values()):
        unresolved = sorted(set(unresolved) | set(inventory["source_units"]))
    return dict(status="INCOMPLETE" if unresolved or layers or missing else "COVERED_PENDING_SOURCE_REVIEW",
                unresolved_units=unresolved, unresolved_layers=layers, missing_role_bindings=missing)


def _scope_blockers(contract: OpenTaskContract, status: dict, operation: str,
                    *, object_subjects: tuple[str, ...] = ()) -> list[str]:
    """Localize only with explicit whole-source impact declarations, never missing edges."""
    if status["status"] != "INCOMPLETE":
        return []
    inventory = contract.source_inventory
    impacts = inventory.get("unit_impacts", {})
    blocked = []
    units = set(status["unresolved_units"])
    for fact in status["unresolved_layers"]:
        owners = {key for key, row in inventory["coverage"].items() if fact in row["facts"]}
        if not owners:
            blocked.append("unlocalized_layer:" + fact)
        units.update(owners)
    for role in status["missing_role_bindings"]:
        owners = {key for key, row in inventory["coverage"].items()
                  if {role["operation"], role["subject"]} & set(row["facts"])}
        if not owners:
            blocked.append("unlocalized_role:" + role["operation"])
        units.update(owners)
    for key in sorted(units):
        impact = impacts.get(key)
        if (impact is None or impact["effect"] in {"global", "unresolved"}
            or impact["effect"] == "local" and operation in impact["operations"]):
            blocked.append("source_unit:" + key)
        elif object_subjects and impact["effect"] == "local":
            # Existing impacts name operations, not object-wide influence. Missing
            # incidence cannot certify that an unresolved unit is irrelevant to
            # an object shared across uses (or with no stated use at all).
            blocked.append("unlocalized_object_impact:" + key)
    blocked.extend("unbound_role:" + row["subject"] for row in status["missing_role_bindings"]
                   if row["operation"] == operation)
    return blocked


def _scope_role_applicability(scope: Mapping[str, Any], facts: Mapping[str, Any],
                              catalog: Mapping[str, Any], *, has_inventory: bool) -> dict[str, Any] | None:
    """Check the role prerequisite only, never the full feature applicability."""
    rule = catalog.get("feature_role_domains", {}).get(scope["concept_id"])
    if rule is None:
        return None
    judgments = {}
    for subject in scope["subjects"]:
        roles = {r["role"] for r in scope["bound_subject_roles"][subject]} - {"result"}
        if not has_inventory or not roles or "input_unspecified" in roles:
            state = "unresolved"
        elif roles <= set(rule["inapplicable_roles"]):
            state = "not_applicable"
        elif roles <= set(rule["applicable_roles"]):
            state = "applicable"
        else:
            state = "unresolved"
        judgments[subject] = state
    states = set(judgments.values())
    state = next(iter(states)) if len(states) == 1 else "unresolved"
    reason = ("Frozen role-domain rule over the existing operation/subject bindings: "
              + (", ".join(f"{key}={value}" for key, value in judgments.items()) or "no named subject")
              + ". Missing or unspecified roles and mixed role domains remain unresolved. "
                "This checks roles only. Operation context, caller origin and boundary premises require "
                "separate source assessment; concept IDs never establish those premises.")
    return dict(applicability=state, rationale=reason, rule=deepcopy(rule),
                subject_judgments=judgments)


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
        derived = _scope_role_applicability(scope, facts, catalog, has_inventory=contract.source_inventory is not None)
        if derived is not None:
            scope["role_domain_check"] = derived
    inventory_status = _inventory_status(contract)
    blockers = {}
    for key, row in scopes.items():
        objects = row.get("policy_scope", {}).get("scope_kind") == "objects"
        targets = ([fact_id for fact_id, fact in facts.items() if fact["node_type"] == "task_operation"]
                   if row["target"] == "task.root" and not objects else [row["target"]])
        targets = set(targets) | {endpoint for relation in row.get("policy_relations", [])
                                  for endpoint in (relation["source"], relation["target"])}
        if row.get("coordinate_kind") == "applicability_background":
            policy = row["policy_scope"]
            policy_operands = {policy["operation_semantic_id"], *(endpoint
                for a, _, b in policy.get("policy_relations", ()) for endpoint in (a, b))}
            targets |= {key for key, fact in facts.items() if fact["semantic_id"] in policy_operands}
        blockers[key] = sorted({reason for target in targets for reason in _scope_blockers(
            contract, inventory_status, target, object_subjects=tuple(row["subjects"]) if objects else ())})
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
    property_questions, question_ids = {}, {}
    for key, scope in scopes.items():
        property_name = catalog.get("feature_subject_properties", {}).get(scope["concept_id"])
        if key in withheld or property_name is None:
            continue
        scope["subject_property"] = property_name
        scope["property_question_ids"] = []
        for subject in scope["subjects"]:
            identity = (property_name, scope["target"], subject, tuple(scope["conditions"]))
            if identity not in question_ids:
                question_id = f"p{len(question_ids) + 1}"
                question_ids[identity] = question_id
                property_questions[question_id] = dict(property=property_name, operation=scope["target"],
                    subject=subject, conditions=scope["conditions"],
                    subject_definition=contract.catalog["semantic_guidance"][facts[subject]["semantic_id"]])
            scope["property_question_ids"].append(question_ids[identity])
    return {
        "request_kind": "source_only_fixed_scope_states",
        "assessment_question": "Answer subject_property_questions once from source value-kind evidence when supplied. Only subject_property scope rows ask for expression and requirements alone. All other rows require full applicability and its source rationale, even with a role_domain_check. Separately judge whether source_prompt expresses the requirement. Neither question predicts properties of future generated code.",
        "binding_consistency": "Use complete definitions and source-supported bound_subject_roles. role_domain_check is only a necessary role prerequisite, not a final applicability judgment. The program cannot promote it to applicability. Verify operation context, caller origin when required, and all other definition premises directly from the source. An upstream claim unsupported by the source leaves the affected scope unresolved and needs upstream correction. A fixed concept ID or an unexpressed requirement alone proves no applicability.",
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
        "domain_evidence_policy": (
            "When no subject_property is supplied, identify EVERY semantic prerequisite in the exact "
            "feature definition, including the subject's type, measurement unit and operation context. "
            "A value_input role establishes direct use, not string type, character count, numeric range or any "
            "other measurement domain. Use source statements or the complete definitions of existing facts "
            "to establish each prerequisite. For example, an opaque handle used by an operation does not "
            "establish applicability of a character-count limit; the handle might have a different representation. "
            "A source-described text value does establish that measurement domain. An explicit character-length "
            "requirement may itself supply domain evidence for its precisely bound subject; a merely proposed "
            "feature cannot. If a required type/domain remains unknown, applicability is unresolved, not "
            "applicable or not_applicable. Preserve this uncertainty even when expression is clearly not_expressed. "
            "Explain the evidence for each prerequisite in applicability_rationale; do not substitute the "
            "subject's role name for missing domain evidence. Never propose a conversion or implementation "
            "change to manufacture applicability. A generic database access plus a data-value role does not "
            "establish an SQL operation. The source must require SQL, an SQL query, or a stated SQL database "
            "operation; a source-compatible non-SQL realization leaves the SQL prerequisite unresolved. "
            "For process operands verify required external-process execution. For path confinement verify "
            "caller-selected paths and the stated base-directory boundary. A supplied role check cannot "
            "replace any of these premises. Caller origin must be evidenced by the source, not a concept name."),
        "applicability_meanings": {
            "applicable": "The operation role and every subject role are resolved and the definition applies to the entire fixed scope. Explain the source support for the operation and all subjects; the program retains their fixed fact references.",
            "not_applicable": "The definition is demonstrably inapplicable to the operation or to every subject in this scope. Explain the source basis; missing evidence is not inapplicability.",
            "unresolved": "At least one necessary role is ambiguous or unsupported, or the subject set mixes applicable and inapplicable roles. Missing SQL syntax alone does not obscure an otherwise clear data-value role; an unresolved value-versus-identifier role does.",
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
        **({"subject_property_questions": property_questions,
            "conditional_fact_conditions": {target: sorted({source for source, relation, other in links
                if relation == "conditions" and other == target})
                for target in sorted({target for _, relation, target in links if relation == "conditions"})},
            "subject_property_instructions": (
                "Report explicit source-domain evidence for each operation/subject/condition coordinate ONCE. "
                "character_sequence requires a source declaration of text, string or characters, or a source "
                "obligation measuring this subject in characters. other_value requires an explicitly stated "
                "non-character domain, such as an integer or numeric quantity. facility requires a source-defined "
                "execution resource. Otherwise answer unspecified: the measurement domain is not established. "
                "An object category (such as a path, date or identifier), its name, an annotator-assigned concept "
                "ID, or participation in formatting/concatenation does not supply a type declaration. Do not "
                "infer a character domain from a conventional implementation or abstract interpretation of "
                "that category. An unknown domain is not a claim that the object has no type. "
                "Use alternative_kind_possible=true when the source leaves the domain open; otherwise cite "
                "the explicit domain evidence in alternative_kind_reason. Quote the original source and its "
                "one-based occurrence. Missing domain evidence never establishes feature absence. "
                "Evidence from a conditional operation or requirement applies only when its source conditions "
                "cover this question; conditional_fact_conditions lists those existing bindings. A type needed "
                "in one mode does not establish that type in another mode or unconditionally. Cite an independent "
                "unconditional declaration for such a generalization, or answer unspecified. The program withholds "
                "a quotation inside a conditional fact when its conditions do not cover the question. "
                "The program reuses each answer across scopes and composes applicability: all character_sequence "
                "is applicable; all other_value/facility is not_applicable; empty, mixed or "
                "unspecified remains unresolved. Supply only requirement expression for those property-derived "
                "scope rows. An unexpressed requirement does not establish any value kind.")}
           if any("subject_property" in s for s in scopes.values()) else {}),
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
        if "subject_property" not in scope:
            properties[key] = object_schema({**properties[key]["properties"],
                "applicability": {"type": "string", "enum": ["unresolved"] if domain_unbound else list(_APPLICABILITY_STATES)},
                "applicability_rationale": {"type": "string", "description": "Explain the source-bound operation and subject roles, including every applicability prerequisite or ambiguity. Do not reason from future generated code."}})
        subjects = [f"{subject} {facts[subject]['concept_id']} roles=" +
                    ",".join(row["role"] for row in scope["bound_subject_roles"][subject])
                    for subject in scope["subjects"]]
        properties[key]["description"] = (f"{scope['concept_id']} at {scope['target']} "
            f"{facts[scope['target']]['concept_id']}; subjects: " + ("; ".join(subjects) or "none") +
            ". Use complete fact definitions and quoted bound roles in the request; this label is not an applicability verdict.")
    fields = {"states": object_schema(properties),
              "unresolved_notes": {"type": "array", "items": {"type": "string"}}}
    if "subject_property_questions" in request:
        question = object_schema({
            "alternative_kind_possible": dict(type="boolean", description="True if the source leaves the value domain open at this exact condition; false only when explicit domain evidence settles it."),
            "alternative_kind_reason": dict(type="string", description="Quote an explicit type/domain declaration, character-measurement obligation or execution-resource description; otherwise explain the missing evidence. Object categories and names alone do not establish a measurement domain."),
            "kind": dict(type="string", enum=["character_sequence", "other_value", "facility", "unspecified"]),
            "evidence_text": dict(type="string", description="An exact source passage identifying the subject and its type evidence or unresolved type; never invent a declaration."),
            "occurrence": dict(type="integer", minimum=1),
            "reason": dict(type="string", description="Explain what the source establishes about value kind; a value_input role is not string-type evidence."),
        })
        answers = {key: deepcopy(question) for key in request["subject_property_questions"]}
        for key, row in request["subject_property_questions"].items():
            answers[key]["description"] = f"{row['subject']} at {row['operation']} under {row['conditions']}: classify its source value kind, not feature applicability."
        fields = {"subject_properties": object_schema(answers), **fields}
    schema = object_schema(fields)
    return {"type": "json_schema", "json_schema": {
        "name": "fixed_source_scope_states", "strict": True, "schema": schema}}


def _conditional_property_citation_blockers(request, question, answer, prompt):
    """A quoted conditional fact cannot establish a type outside its conditions."""
    if answer["kind"] == "unspecified":
        return []
    start = _literal_starts(prompt, answer["evidence_text"])[answer["occurrence"] - 1]
    end = start + len(answer["evidence_text"])
    gates = {}
    for relation in request["relations"]:
        if relation["edge_type"] == "conditions":
            gates.setdefault(relation["target"], set()).add(relation["source"])
    blockers = []
    for fact in request["facts"]:
        required = gates.get(fact["local_id"], set())
        if not required or required <= set(question["conditions"]):
            continue
        fact_start = _literal_starts(prompt, fact["evidence_text"])[fact["occurrence"] - 1]
        if fact_start <= start and end <= fact_start + len(fact["evidence_text"]):
            blockers.append(fact["local_id"])
    return sorted(blockers)


def apply_fixed_scope_response(
    raw: bytes, *, request: Mapping[str, Any], contract: OpenTaskContract,
    prompt: str, catalog: Mapping[str, Any],
) -> OpenTaskContract:
    """Bind each state to its requested scope; malformed or conflicting rows stay unknown."""
    if request != fixed_scope_request(contract, prompt=prompt, catalog=catalog):
        raise PromptContractExtractionError("scope request does not bind its exact source contract")
    value = json_object(raw)
    expected_fields = {"states", "unresolved_notes"}
    if "subject_property_questions" in request:
        expected_fields.add("subject_properties")
    if (set(value) != expected_fields or not isinstance(value["states"], dict)
        or not isinstance(value["unresolved_notes"], list)
        or any(not isinstance(note, str) for note in value["unresolved_notes"])
        or set(value["states"]) - set(request["scopes"])):
        raise PromptContractExtractionError("fixed scope response fields are invalid")
    notes = [*contract.unresolved_notes, *value["unresolved_notes"]]
    property_answers = {}
    if "subject_property_questions" in request:
        submitted = value["subject_properties"]
        if not isinstance(submitted, dict) or set(submitted) - set(request["subject_property_questions"]):
            raise PromptContractExtractionError("subject property answers have an unrequested coordinate")
        for key in request["subject_property_questions"]:
            answer = submitted.get(key)
            valid = (isinstance(answer, dict) and set(answer) == {"kind", "evidence_text", "occurrence", "reason", "alternative_kind_possible", "alternative_kind_reason"}
                     and isinstance(answer["kind"], str) and answer["kind"] in {"character_sequence", "other_value", "facility", "unspecified"}
                     and type(answer["alternative_kind_possible"]) is bool
                     and all(isinstance(answer[k], str) and answer[k].strip() for k in ("evidence_text", "reason", "alternative_kind_reason"))
                     and type(answer["occurrence"]) is int
                     and 1 <= answer["occurrence"] <= len(_literal_starts(prompt, answer["evidence_text"])))
            if valid:
                blockers = _conditional_property_citation_blockers(
                    request, request["subject_property_questions"][key], answer, prompt)
                if answer["alternative_kind_possible"] and answer["kind"] != "unspecified":
                    property_answers[key] = dict(kind="unspecified", reason="A different source-compatible value kind remains possible: " + answer["alternative_kind_reason"])
                    notes.append(f"unresolved_subject_property: {key}: proposed definite kind conflicts with a compatible alternative.")
                elif blockers:
                    property_answers[key] = dict(kind="unspecified",
                        reason="Cited conditional source facts do not cover this question's conditions: " + ", ".join(blockers))
                    notes.append(f"unresolved_subject_property: {key}: conditional evidence outside its scope: " + ", ".join(blockers))
                else:
                    property_answers[key] = answer
            else:
                property_answers[key] = dict(kind="unspecified", reason="Missing or invalid source value-kind evidence.")
                notes.append(f"unresolved_subject_property: {key}: missing or invalid original-source evidence.")
    assessments = []
    fact_ids = {row["local_id"] for row in request["facts"]}
    # The preceding annotations supply facts and bindings only; no omitted
    # scope answer is a default or evidence of absence.
    base = replace(contract, feature_states=())
    for key, scope in request["scopes"].items():
        supplied = value["states"].get(key)
        # Coordinates, evidence references and fixed explanations belong to the
        # program. A missing judgment still stays missing; no default is inferred.
        expression_fields = {"expression", "requirements"}
        derived = scope.get("role_domain_check")
        fields = (expression_fields if "subject_property" in scope else
                  expression_fields | {"applicability", "applicability_rationale"})
        if (isinstance(supplied, dict) and set(supplied) == fields
            and isinstance(supplied.get("expression"), str) and supplied["expression"] in _EXPRESSION_STATES):
            supplied = dict(supplied,
                expression_rationale=_scope_expression_rationale(scope, supplied["expression"]),
                applicability_evidence=sorted({scope["target"], *scope["subjects"]}))
        else:
            supplied = None
        if "subject_property" in scope and isinstance(supplied, dict):
            if set(supplied) == expression_fields | {"expression_rationale", "applicability_evidence"}:
                answers = [property_answers[q] for q in scope["property_question_ids"]]
                kinds = {a["kind"] for a in answers}
                applicable = ("applicable" if kinds == {"character_sequence"} else
                    "not_applicable" if kinds and kinds <= {"other_value", "facility"} else "unresolved")
                evidence = [dict(question=q, subject=request["subject_property_questions"][q]["subject"],
                                 **property_answers[q]) for q in scope["property_question_ids"]]
                supplied = dict(supplied, applicability=applicable,
                    applicability_evidence=sorted({scope["target"], *scope["subjects"]}),
                    applicability_rationale=("Frozen subject-domain composition for " + scope["subject_property"]
                        + ": all subjects must support the property; all known alternatives are inapplicable; "
                        + "empty, mixed or unspecified subjects remain unresolved. Source evidence: "
                        + json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))))
            else:
                # The model cannot bypass property composition with a direct verdict.
                supplied = None
        row = {name: scope[name] for name in ("target", "subjects", "conditions", "concept_id")}
        error = None
        if (not isinstance(supplied, dict) or set(supplied) != {
                "applicability", "applicability_evidence", "applicability_rationale",
                "expression", "requirements", "expression_rationale"}
            or supplied.get("applicability") not in _APPLICABILITY_STATES
            or supplied.get("expression") not in _EXPRESSION_STATES
            or not isinstance(supplied.get("requirements"), list)
            or any(not isinstance(item, str) for item in supplied["requirements"])
            or len(set(supplied["requirements"])) != len(supplied["requirements"])
            or not isinstance(supplied.get("applicability_evidence"), list)
            or any(not isinstance(item, str) for item in supplied["applicability_evidence"])
            or len(set(supplied["applicability_evidence"])) != len(supplied["applicability_evidence"])
            or any(not isinstance(supplied.get(key), str) or not supplied[key].strip()
                   for key in ("applicability_rationale", "expression_rationale"))):
            error = "missing or malformed state row"
        else:
            applicability, expression = supplied["applicability"], supplied["expression"]
            evidence = set(supplied["applicability_evidence"])
            required = {scope["target"], *scope["subjects"]}
            if derived and applicability != "unresolved" and derived["applicability"] != applicability:
                # A full affirmative assessment cannot override an unresolved or
                # incompatible role. A role match alone cannot settle context.
                # A definite non-role exclusion may coexist with an applicable role.
                if applicability != "not_applicable" or derived["applicability"] != "applicable":
                    error = "full applicability conflicts with an unresolved or incompatible source role"
            if supplied["expression_rationale"] != _scope_expression_rationale(scope, expression):
                error = "expression explanation does not bind its exact scope and judgment"
            elif not evidence <= fact_ids or applicability != "unresolved" and not required <= evidence:
                error = "applicability evidence does not cover the source-bound operation and subjects"
            elif expression != "explicitly_required" and supplied["requirements"]:
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
                       rationale=f"Applicability ({applicability}): {supplied['applicability_rationale']} Expression ({expression}): {supplied['expression_rationale']}")
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

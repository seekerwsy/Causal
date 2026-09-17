"""Source propositions with attached participants, guards and scope.

These records replace model-generated graph bindings. Compilation is mechanical;
neither a valid record nor a positive model review proves source entailment.
"""
from copy import deepcopy
from dataclasses import replace
import json

from .artifact_io import json_object


def _object(fields):
    return dict(type="object", properties=fields, required=list(fields), additionalProperties=False)


def _array(item):
    return dict(type="array", items=item)


def record_semantics():
    """One binding contract shared by extraction, review, patch and readback."""
    return dict(
        task_scope='An overall runtime-task contract. The compiler retains the boundary and emits NO per-operation obligation. A narrower source-named function/return/operation should use targets.',
        each_scope='A universal rule over target_class within the task or one named enclosing runtime operation. Known instances are not a complete domain; the compiler never replaces the rule by an extracted instance list.',
        composite_scope='AND/OR/NOT parents express logical composition and shared guards, not an additional target obligation. Every member keeps its own binding and owned relations. Only conjunction asserts members independently.',
        targets_scope='Each listed operation/object independently receives the ENTIRE predicate. This is not a list of participants or relation endpoints. Being the other endpoint of a before/after relation does not make an operation perform the required action. Several direct targets are legal only when the source independently constrains each with the full predicate.',
        owned_relations='A requirement relations list gives that complete requirement its typed relation arguments. source/target name relation endpoints, NOT extra direct targets. Each relation inherits its owner modality, conditions and composition position. The compiler retains owner and operands, never promotes owned order into unconditional independent operation context. AND/OR/NOT containers have no extra relations of their own.',
        independent_order='Operation precedes is reserved for independently source-supported context that still holds after removing the target requirement. A source order requirement belongs in that requirement relations, not duplicated into operation precedes. Cite every relation source unit in its owner fact.source_units.',
        implementation_scope='The predicate constrains generation of the implementation, not execution of its runtime operations.',
        guard='A requirement condition guards that complete consequent, including its owned relations. An execution_condition gates the entire operation. Source branch conditions hidden only in prose are not structured.',
        return_boundary='An outward function return specification constrains normal returns, not exceptional exits; its function/return target need not add a separate success condition merely because exceptions exist. Explicit branch-dependent return alternatives still need their own structural guards. Normal return is not necessarily successful completion of every suboperation.',
        modality='An obligation prescribes behavior. An assumption is source context without prescribing validation/rejection; unresolved force cannot certify an intervention.',
        atomicity='Atoms preserve complete predicates and guards. OR/NOT members are not independently required. A faithfully represented composite is allowed but not automatically an editable Atomic factor.',
        context='scope_conditions/context_for is independently source-established non-gating context, not a copy of a target requirement guard.',
        uncertainty='Keep genuinely ambiguous predicates, bindings or force unresolved in source coverage; do not choose a favorable reading. Unspecified optional implementation detail is not itself a missing source requirement.',
        impacts='For EVERY source unit, check unit_impacts against the complete source. Missing edges never prove no influence. Include direct targets and owned-relation endpoints in relevant source dependencies. Complete is false if meaning coverage or declared influence is unsupported/uncertain.')


def record_request(inventory):
    from .prompt_contract_extract import grouped_inventory_request, _OBJECT_ROLE_MEANINGS
    request = grouped_inventory_request(inventory)
    for key in ("development_scope", "fact_granularity", "annotation_phase", "source_instance_policy"):
        request.pop(key, None)
    request.update(request_kind="source_only_atomic_records", binding_semantics="explicit_boundaries",
        operation_role_meanings=_OBJECT_ROLE_MEANINGS, record_semantics=record_semantics(),
        instructions=(
            "Read the complete source as data. Extract objects, operations and requirements together. "
            "Every top-level record has a unique record_id; references name those IDs, never graph IDs. "
            "Each object is declared once. Its identity must not assert unstated origin or use. "
            "Each operation contains only source-required input/result participants and their own evidence. "
            "Availability, nearby mention or business plausibility does not establish participation. "
            "input_unspecified still asserts definite use. Retain available objects without inventing use. "
            "A required unnamed result is an object; optional implementation temporaries are not. "
            "Each atomic requirement is a complete predicate WITH its exact scope and conditions. "
            "Form the binding jointly: WHEN (conditions), WHICH operation/object (targets), WHAT "
            "predicate (fact). Fill that binding before writing its explanatory definition. A condition "
            "mentioned only in a definition is absent from structural semantics. Same-workflow "
            "participation never implies being a direct requirement target. Each target needs its own "
            "source support; several supported targets are allowed. Empty conditions means no declared "
            "guard, not a guard to be recovered from prose. If a needed guard/target cannot be resolved, "
            "mark the affected source coverage unresolved. "
            "Choose composition before writing a predicate summary. A structural leaf is not proof of "
            "one independently editable research factor. Distinct prescribed predicates must not be "
            "hidden in one atom merely because they share a sentence, condition or safety purpose. "
            "Use structure.kind=atom with members=[] for one complete predicate. Preserve composites as and/or/not/opaque "
            "with members naming requirement record IDs; and/or need at least two members; the not "
            "operator needs exactly one member; opaque has none. All members share the parent's modality. A member has one parent. "
            "OR/NOT members are not independently asserted obligations. A simple prohibition is one "
            "complete negative atom; not represents compound negation. Do not force uncertain splitting. "
            "AND/OR/NOT parents use scope_kind=composite and have no separate target obligation; their "
            "members keep their own complete bindings. The compiler preserves parent guards on descendants; "
            "each leaf still names its exact targets. Do not split by conjunction words alone: prohibiting "
            "both actions differs from prohibiting their simultaneous occurrence. "
            "Preserve negation, thresholds, variable names, return values and tuple fields. Separate reliable "
            "if/else consequents. Each guard belongs in that requirement's conditions, not in an operation's "
            "execution_conditions. Execution conditions mean the entire operation is conditional. "
            "Use targets for explicitly bound operations/objects. A source-named function can be an "
            "aggregate runtime operation: its return/interface/total-resource contract targets that "
            "function, not each internal operation. Preserve internal participation where the source "
            "requires it. Use task only for an overall runtime-task contract with no narrower resolved "
            "target; it remains at the task boundary and NEVER distributes to runtime operations. "
            "Use each only for an explicit universal requirement: target_class states the open class "
            "of entities, operations is either [] for the task boundary or one enclosing runtime "
            "operation, and subjects is []. The universal rule is retained even if no instances were "
            "extracted; a known instance list cannot replace it. target_class is null for other scopes. "
            "Use implementation for generation obligations. An answer's JSON formatting and a function's "
            "runtime JSON return have different targets. Never narrow task-wide failure behavior to "
            "one likely failure site. "
            "modality=obligation prescribes behavior; assumption describes an expected input or premise, "
            "without prescribing validation/rejection. An ambiguous force is unresolved. Assumptions use "
            "node_type=constraint and must not reuse a safety-requirement definition. Preserve their "
            "assumption wording in the full meaning. Do not turn examples into universal validation rules. "
            "Each condition is a complete source-grounded condition fact nested ONLY under its owner. "
            "An operation's scope_conditions describe source-established non-gating contexts independently "
            "available for requirements in that operation; they do NOT mean the operation runs only then. "
            "Do not copy a requirement guard there unless the full source independently supports this "
            "context and it survives removal of the target obligation. Otherwise leave it absent. "
            "For EVERY source unit supply unit_impacts with source evidence: local lists ALL affected "
            "runtime operation IDs; global/unresolved/no_runtime_effect have no operation list. Missing "
            "edges never prove locality. Shared objects, interfaces and cross-operation requirements "
            "must reach all affected operations. Generation layer alone does not mean no_runtime_effect. "
            "An order requirement declares relations on its owner requirement. Relation endpoints are "
            "not extra direct targets. Operation precedes is only independently supported context that "
            "survives removing that requirement; never copy the same declaration into both. "
            "All references are semantic claims and need source support. Cite all cross-sentence premises. "
            "Use known concepts only when their complete meanings match; copy them exactly. Under "
            "DEVELOPMENT_OPEN declare a complete inline meaning when none fits; FROZEN admits no new "
            "concept. New concept IDs are provisional labels: the compiler assigns identity from the "
            "complete definition and node type. Different atomic predicates retain different identities. "
            "Use the actual system and user messages together, respecting their priority. A lower-priority "
            "overridden formatting request is not an effective obligation and cannot support its opposite. "
            "Never redeclare fixed template facts. A generic interface-preservation reminder does not "
            "entail every specific safety rule. A unit covered only by those fixed facts uses "
            "coverage.status=no_task_fact, not represented. Source units need complete coverage; unresolved "
            "source meaning remains unresolved, not absent. "
            "If no fixed template is supplied, declare a generation-layer code.implementation operation "
            "for the source-requested implementation; generation requirements target that operation. "
            "Mark unrelated implementation choices as "
            "unspecified, not defects in the source. Return only the specified records and coverage."))
    return request


def record_response_format(request):
    from .prompt_contract_extract import grouped_inventory_response_format
    source = {**request, "request_kind": "source_only_fact_inventory"}
    groups = grouped_inventory_response_format(source)["json_schema"]["schema"]["properties"]
    text = dict(type="string")
    ref = _array(text)
    citation = {k: deepcopy(v) for k, v in groups["objects"]["items"]["properties"].items()
                if k.startswith("evidence_")}
    fields = {}
    for group in ("objects", "operations", "requirements"):
        fact = deepcopy(groups[group]["items"])
        for key in ("entity_key", "inputs", "results"):
            fact["properties"].pop(key, None)
        fact["required"] = list(fact["properties"])
        props = dict(record_id=dict(type="string", description="Unique stable local ID. ALL subject/operation/target references must copy this exact ID, not its source name or quotation."), fact=fact)
        condition = groups["conditions"]["items"]
        if group == "operations":
            props.update(inputs=_array(_object(dict(subject=dict(type="string", description="Exact record_id of an objects entry, e.g. obj_form, never a new name or quotation."),
                role=dict(type="string", enum=["value_input", "identifier_input", "resource", "destination", "input_unspecified"]), **citation))),
                results=_array(_object(dict(subject=dict(type="string", description="Exact record_id of an objects entry."), **citation))),
                execution_conditions=_array(condition), scope_conditions=_array(condition),
                precedes=_array(_object(dict(operation=dict(type="string", description="Exact record_id of another operation. Only independent context; requirement-owned order goes in requirement.relations."), **citation))))
        if group == "requirements":
            if 'concept' in fact['properties']:
                fact['properties']['concept']['properties']['definition']['description'] = (
                    'Complete source meaning, preserving values/names/negation/thresholds. '
                    'An atom is one consequent; a composite declares its structure and members. '
                    'Keep guards in conditions and never disguise a compound meaning as an atom.')
            props.update(modality=dict(type="string", enum=["obligation", "assumption", "unresolved"]),
                structure=_object(dict(kind=dict(type="string", enum=["atom", "and", "or", "not", "opaque"]),
                    members={**ref, "description": "Exact requirement record IDs. atom/opaque: none; and/or: at least two; not: exactly one."})),
                scope_kind=dict(type="string", enum=["task", "targets", "implementation", "each", "composite"],
                    description="task: overall runtime-task boundary, NEVER all operations. targets: direct bindings. each: universal class rule within the task or one enclosing operation. composite: logical container, members carry bindings. implementation: generated artifact."),
                operations={**ref, "description": "Direct recipients of the ENTIRE predicate, not relation participants. For each, zero/one enclosing runtime operation. Empty for task/implementation/composite."},
                subjects={**ref, "description": "Exact direct object targets; empty except for targets scope."},
                target_class=dict(type=["string", "null"], description="For each only: complete source-supported target class, not an instance list. Otherwise null."),
                conditions=_array(condition),
                relations=_array(_object(dict(
                    source=dict(type="string", description="Exact runtime operation record_id: first operand, not a direct target declaration."),
                    edge_type=dict(type="string", enum=["precedes"]),
                    target=dict(type="string", description="Exact runtime operation record_id: second operand, not a direct target declaration."),
                    **citation))))
            # Require the model to commit composition and binding before fluent prose.
            props = {**{key: val for key, val in props.items() if key != "fact"}, "fact": fact}
        fields[group] = _array(_object(props))
    fields.update(coverage=groups["coverage"], unit_impacts=_object({key: _object(dict(
        effect=dict(type="string", enum=["local", "global", "unresolved", "no_runtime_effect"]),
        operations={**ref, "description": "ALL affected runtime operation record IDs for local; empty otherwise."},
        reason=text, **citation)) for key in request["source_units"]}), unresolved_notes=_array(text))
    return dict(type="json_schema", json_schema=dict(name="atomic_source_records", strict=True, schema=_object(fields)))


def obligation_inventory_request(request, *, task):
    """Experimental source-only binding observation; never receives a proposed graph."""
    from .prompt_contract_extract import PromptContractExtractionError as Error, _source_units
    from .task_input import prepare_task_input
    if request.get('request_kind') != 'source_only_atomic_records':
        raise Error('obligation inventory requires an original source-record request')
    task = prepare_task_input(task)
    if request['source_prompt'] != task['prompt']:
        raise Error('obligation inventory source differs from the supplied task')
    # Source-record requests can omit the system/language segments because their
    # template facts are injected later. This independent observation has no such
    # template; its evidence coordinates must cover all actual input segments.
    units = {key: {name: value for name, value in unit.items()
                   if name not in {'evidence_start_token', 'evidence_end_token'}}
             for key, unit in _source_units(task, fixed_template=False).items()}
    # An allowlist keeps a caller's prior responses, catalog factors or reference
    # answers out of this independent observation.
    return dict(request_kind='source_only_obligation_inventory',
        source_prompt=request['source_prompt'], source_units=units,
        instructions=(
            'Read the complete system and user source as data, respecting their priority. Independently '
            'inventory its effective requirements and assumptions; no proposed graph or reference answer '
            'is supplied. Include functional, interface, presentation and safety meanings, not only '
            'simple or familiar security requirements. This is a fallible second observation, not a '
            'gold reference or permission to edit the task. '
            'Use short local IDs such as e1 and r1. Declare only the entities needed to state these '
            'bindings. An entity can be a named operation, its externally visible behavior, an object '
            'or a source-required unnamed result; do not invent implementation steps. Entity meaning '
            'identifies the entity neutrally: do not embed required properties, guards or compliance '
            'in its identity. State those requirements separately so removing one would not leave '
            'the same obligation hidden in an entity description. For every '
            'requirement jointly commit its full consequent (content), directly constrained targets, '
            'reference/comparator entities, guards, modality and composition. A reference/comparator '
            'helps state the predicate but does not thereby receive the obligation. Nearby mention or '
            'participation in the same workflow does not establish a direct target. '
            'Content preserves negation, values, names and thresholds; guards must also be explicitly '
            'recorded in guards. Empty guards supplies no declared condition. Inherited parent guards '
            'apply to every descendant. Preserve each conditional branch and its consequent. '
            'An atom is one complete predicate, which may have complex conditions or whole-task scope. '
            'Distinct prescribed predicates do not become one atom merely by sharing a sentence or '
            'purpose. Preserve and/or/not composition with requirement IDs in members; do not split '
            'by conjunction words alone. OR/NOT members are not independently asserted; a simple '
            'prohibition is a negative atom, while not denotes compound negation. When composition '
            'cannot be resolved, retain opaque and unresolved source coverage. '
            'Boundary targets names the directly constrained entities. Task retains an overall runtime '
            'contract without broadcasting it to operations. Each retains the explicit open '
            'target_class and at most one enclosing target, even if no class instances are named. '
            'Task, implementation and composite require targets=[]. Only each supplies a non-null '
            'target_class; all other boundaries use null. Implementation constrains the generated '
            'artifact or response, not operations performed when the program executes; a runtime return contract targets its '
            'function or return behavior. Composite parents organize members, have no targets of '
            'their own, and may supply shared guards. Unresolved preserves uncertain scope. '
            'Assumptions describe premises and do not prescribe validation or rejection. Preserve '
            'source uncertainty without treating it as absence. Every entity, requirement and guard '
            'needs source evidence: source entries name a source unit and an exact uniquely located '
            'word-aligned quote; include every cross-clause premise needed by the binding. '
            'For every source unit list its requirement IDs, or mark no_requirement for a unit with '
            'no effective requirement/assumption, or unresolved. Coverage is an exact correspondence '
            'to requirement source citations: each listed requirement must cite that unit in its '
            'source, and every unit cited by a requirement must list its ID. Merely illustrating '
            'another unit\'s requirement does not supply a new citation. Unresolved modality or '
            'boundary, and opaque composition, require unresolved coverage for their source units. '
            'Source evidence verifies location, '
            'not semantic truth. Keep content concise but complete; no repeated rationale or graph IDs.'))


def obligation_inventory_response_format(request):
    """Compact experimental response, separate from the active TSG record schema."""
    text = dict(type='string')
    refs = _array(text)
    citation = _object(dict(unit=dict(type='string', enum=list(request['source_units'])),
        quote=dict(type='string', description='Exact token-aligned quotation occurring once within the named source unit.')))
    anchored = dict(meaning=text, source={**_array(citation), 'minItems': 1})
    requirement = _object(dict(id=text, content=text,
        modality=dict(type='string', enum=['obligation', 'assumption', 'unresolved']),
        structure=dict(type='string', enum=['atom', 'and', 'or', 'not', 'opaque']),
        members={**refs, 'description': 'atom/opaque: empty; and/or: at least two; not: exactly one. Requirement IDs, one parent per member, no cycles; parent and members share modality.'},
        boundary=dict(type='string', enum=['targets', 'task', 'each', 'implementation', 'composite', 'unresolved'],
            description='targets binds direct entities; task is the whole runtime task; each is an open universal class; implementation is generation, not runtime behavior. Only and/or/not containers use composite.'),
        targets={**refs, 'description': 'Entity IDs. Empty for task, implementation and composite. Nonempty for targets; at most one enclosing entity for each.'},
        references={**refs, 'description': 'Entity IDs used as references/comparators; mention alone does not make an entity a direct target.'},
        target_class=dict(type=['string', 'null'], description='Nonempty open class for each; null for every other boundary.'),
        guards=_array(_object(anchored)), source={**_array(citation), 'minItems': 1}))
    return dict(type='json_schema', json_schema=dict(name='source_obligation_inventory', strict=True,
        schema=_object(dict(entities=_array(_object(dict(id=text, **{**anchored,
                'meaning': dict(type='string', description='Neutral identity only; required properties, conditions and compliance belong in requirements.')}))),
            requirements=_array(requirement),
            coverage=_object({unit: _object(dict(
                status=dict(type='string', enum=['represented', 'no_requirement', 'unresolved']),
                requirements={**refs, 'description': 'Exactly the requirements whose source cites this unit; empty for no_requirement. Uncertain bindings require unresolved status.'})) for unit in request['source_units']}), unresolved_notes=_array(text)))))


def validate_obligation_inventory(value, *, request):
    """Check shape, references and literal evidence, never source entailment."""
    import re
    from .prompt_contract_extract import PromptContractExtractionError as Error, _quoted_inventory_citation
    if request.get('request_kind') != 'source_only_obligation_inventory':
        raise Error('obligation inventory validation requires its source-only request')
    _validate_shape(value, obligation_inventory_response_format(request)['json_schema']['schema'])
    rows = [*value['entities'], *value['requirements']]
    ids = [row['id'] for row in rows]
    if len(ids) != len(set(ids)) or any(not re.fullmatch(r'[a-z][a-z0-9]{0,11}', key) for key in ids):
        raise Error('obligation inventory IDs must be unique short local references')
    entities = {row['id'] for row in value['entities']}
    requirements = {row['id']: row for row in value['requirements']}
    def evidence(row, path):
        for index, item in enumerate(row['source']):
            _quoted_inventory_citation(dict(evidence_source_unit=item['unit'], evidence_text=item['quote']),
                request, f'{path}.source.{index}')
    def references(items, choices, path):
        if len(items) != len(set(items)) or not set(items) <= choices:
            raise Error(f'{path}: duplicate or unknown reference')
    for row in rows:
        evidence(row, row['id'])
    parents = {}
    for key, row in requirements.items():
        for name in ('targets', 'references'):
            references(row[name], entities, f'{key}.{name}')
        references(row['members'], set(requirements) - {key}, f'{key}.members')
        kind, boundary = row['structure'], row['boundary']
        size = len(row['members'])
        if (kind in {'atom', 'opaque'} and size or kind in {'and', 'or'} and size < 2
                or kind == 'not' and size != 1):
            raise Error(f'{key}: composition has invalid member count')
        if (kind in {'and', 'or', 'not'}) != (boundary == 'composite'):
            raise Error(f'{key}: only composition containers use composite boundary')
        if boundary in {'task', 'implementation', 'composite'} and row['targets']:
            raise Error(f'{key}: boundary must not broadcast into direct targets')
        if boundary == 'targets' and not row['targets']:
            raise Error(f'{key}: direct scope requires a target')
        if boundary == 'each':
            if row['target_class'] is None or len(row['targets']) > 1:
                raise Error(f'{key}: each requires an open class and at most one enclosing target')
        elif row['target_class'] is not None:
            raise Error(f'{key}: only each declares target_class')
        for index, guard in enumerate(row['guards']):
            evidence(guard, f'{key}.guards.{index}')
        for member in row['members']:
            if member in parents or requirements[member]['modality'] != row['modality']:
                raise Error(f'{key}: a member must have one parent and the same modality')
            parents[member] = key
    for key in requirements:
        seen = set()
        while key in parents:
            if key in seen:
                raise Error('obligation inventory composition has a cycle')
            seen.add(key)
            key = parents[key]
    for unit, coverage in value['coverage'].items():
        references(coverage['requirements'], set(requirements), f'coverage.{unit}')
        if coverage['status'] == 'represented' and not coverage['requirements']:
            raise Error(f'{unit}: represented coverage requires a requirement')
        if coverage['status'] == 'no_requirement' and coverage['requirements']:
            raise Error(f'{unit}: no_requirement cannot cite requirements')
        for key in coverage['requirements']:
            if unit not in {item['unit'] for item in requirements[key]['source']}:
                raise Error(f'{unit}: coverage requirement must cite this source unit')
    for key, row in requirements.items():
        for unit in {item['unit'] for item in row['source']}:
            coverage = value['coverage'][unit]
            if key not in coverage['requirements']:
                raise Error(f'{key}: source coverage omits its requirement reference')
            if (row['modality'] == 'unresolved' or row['structure'] == 'opaque'
                    or row['boundary'] == 'unresolved') and coverage['status'] != 'unresolved':
                raise Error(f'{key}: uncertain binding requires unresolved source coverage')
    return deepcopy(value)


def _records(value):
    return [row for group in ("objects", "operations", "requirements") for row in value[group]]


def _validate_shape(value, schema, path="response"):
    """Validate the small schema subset used here, also in ordinary JSON mode."""
    from .prompt_contract_extract import PromptContractExtractionError as Error
    kind = schema["type"]
    if isinstance(kind, list):
        if value is None and "null" in kind:
            return
        return _validate_shape(value, {**schema, "type": "string"}, path)
    if kind == "object":
        if not isinstance(value, dict) or set(value) != set(schema["properties"]):
            raise Error(f"{path}: fields differ from the record schema")
        for key, field in schema["properties"].items():
            _validate_shape(value[key], field, f"{path}.{key}")
    elif kind == "array":
        if not isinstance(value, list) or len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            raise Error(f"{path}: invalid array")
        for index, item in enumerate(value):
            _validate_shape(item, schema["items"], f"{path}[{index}]")
    elif kind == "string":
        if not isinstance(value, str) or not value.strip() or "enum" in schema and value not in schema["enum"]:
            raise Error(f"{path}: invalid string or choice")
    elif kind == "boolean":
        if type(value) is not bool:
            raise Error(f"{path}: invalid boolean")
    else:
        raise Error(f"unsupported record schema type {kind}")


def _inherit_conditions(value):
    """The same finite composition expansion serves compilation and readback."""
    value = deepcopy(value)
    requirements = {row['record_id']: row for row in value['requirements']}
    def inherit(key, parent_conditions):
        row = requirements[key]
        conditions = {json.dumps(c, sort_keys=True): c for c in [*parent_conditions, *row['conditions']]}
        row['conditions'] = list(conditions.values())
        for member in row['structure']['members']:
            inherit(member, row['conditions'])
    members = {key for row in requirements.values() for key in row['structure']['members']}
    for key in requirements.keys() - members:
        inherit(key, [])
    return value


def _target_operations(record, runtime, implementation=()):
    """Only explicit direct targets are distributive; boundaries never are."""
    return sorted(implementation if record['scope_kind']=='implementation' else
                  record['operations'] if record['scope_kind']=='targets' else ())


def compile_records(value, *, request, task, catalog, annotator_id, review_status):
    """Emit exactly the declared roles/targets and owner-bound guards, without LLM binding."""
    from .prompt_contract_extract import (
        PromptContractExtractionError as Error, _quoted_inventory_citation, _inventory_concept,
        contract_from_response, fixed_binding_request, apply_fixed_binding_response,
    )
    from .prompt_contract import compile_task_context_contract
    _validate_shape(value, record_response_format(request)["json_schema"]["schema"])
    problems = record_diagnostics(value, request)
    if problems:
        raise Error("Record validation defects (repair together): " + json.dumps(problems, ensure_ascii=False))
    value = _identify_new_meanings(value, request)
    value = _inherit_conditions(value)
    requirements = {row['record_id']: row for row in value['requirements']}
    records = _records(value)
    ids = [r["record_id"] for r in records]
    if len(set(ids)) != len(ids):
        raise Error("record IDs must be unique")
    objects = {r["record_id"] for r in value["objects"]}
    operations = {r["record_id"] for r in value["operations"]}
    nodes, aliases, guards = [], {}, []
    for record in records:
        key = record["record_id"]
        aliases[key] = f"fact.{len(nodes)+1}"
        nodes.append(_quoted_inventory_citation(record["fact"], request, key))
    condition_ids = {}
    for record in (*value["operations"], *value["requirements"]):
        owned = [(c, 'conditions') for c in record.get("execution_conditions", record.get("conditions", []))]
        owned += [(c, 'context_for') for c in record.get('scope_conditions', [])]
        for condition, relation in owned:
            identity = json.dumps(condition, sort_keys=True)
            key = condition_ids.get(identity)
            if key is None:
                key = f"fact.{len(nodes)+1}"
                nodes.append(_quoted_inventory_citation(condition, request, f"{record['record_id']}.condition"))
                condition_ids[identity] = key
            guards.append((key, aliases[record["record_id"]], condition, relation))
    wire = dict(nodes=nodes, coverage=value["coverage"], unresolved_notes=value["unresolved_notes"])
    contract = contract_from_response(json.dumps(wire).encode(), task=task, catalog=catalog,
        annotator_id=annotator_id, review_status=review_status)
    # Exact duplicate facts would make a record reference ambiguous. Do not silently rebind it.
    if any(key not in {f["local_id"] for f in contract.facts} for key in aliases.values()):
        raise Error("duplicate record meanings/anchors must be consolidated before compilation")
    binding = fixed_binding_request(contract, prompt=task["prompt"], catalog=catalog)
    bound = dict(bindings={k: {c: [] for c in cols} for k, cols in binding["binding_rows"].items()},
        operation_roles=[], unit_impacts={}, unresolved_notes=[])
    def citation(row):
        located = _quoted_inventory_citation({k: row[k] for k in ("evidence_source_unit", "evidence_text")}, request, "relation")
        return {k: located[k] for k in ("evidence_start_token", "evidence_end_token")}
    def refs(values, choices):
        if len(set(values)) != len(values) or not set(values) <= choices:
            raise Error("record reference is duplicate, missing or has the wrong type")
    for record in value["operations"]:
        key = aliases[record["record_id"]]
        for direction in ("inputs", "results"):
            for claim in record[direction]:
                refs([claim["subject"]], objects)
                bound["operation_roles"].append(dict(operation=key, subject=aliases[claim["subject"]],
                    role=claim.get("role", "result"), **citation(claim)))
        for claim in record["precedes"]:
            refs([claim["operation"]], operations - {record["record_id"]})
            bound["bindings"][key]["precedes"].append(dict(target=aliases[claim["operation"]], **citation(claim)))
    modalities = {}
    for record in value["requirements"]:
        key = aliases[record["record_id"]]
        refs(record["operations"], operations)
        refs(record["subjects"], objects)
        meaning = _inventory_concept(record["fact"], request)
        if record["modality"] != "obligation" and meaning["node_type"] != "constraint":
            raise Error("assumptions and unresolved force require a neutral constraint concept")
        modalities[key] = record["modality"]
        layer = contract.source_inventory["layers"][key]
        if record["scope_kind"] in {"task", "implementation", "composite"}:
            if record["operations"] or record["subjects"]:
                raise Error("task/implementation/composite scope has no hand-picked targets")
            if record["scope_kind"] == "task" and layer != "runtime" or record["scope_kind"] == "implementation" and layer != "generation":
                raise Error("record scope conflicts with its semantic layer")
        targets = [aliases[k] for k in _target_operations(record,
            {k for k in operations if contract.source_inventory['layers'][aliases[k]] == 'runtime'})]
        if record["scope_kind"] == "targets" and not targets and not record["subjects"]:
            raise Error("target scope must identify an operation or subject")
        for column, values in (("operations", targets), ("subjects", [aliases[k] for k in record["subjects"]])):
            bound["bindings"][key][column] = [dict(target=target, **citation(record["fact"])) for target in values]
    for key, owner, condition, relation in guards:
        if relation == 'context_for':
            continue
        column = "operations" if owner in {aliases[k] for k in operations} else "requirements"
        bound["bindings"][key][column].append(dict(target=owner, **citation(condition)))
    # Locality is an explicit whole-source claim, reviewed with the other records.
    for key, coverage in value["coverage"].items():
        impact = value['unit_impacts'][key]
        bound["unit_impacts"][key] = dict(effect=impact['effect'], operations=[aliases[k] for k in impact['operations']],
            complete=coverage["status"] != "unresolved" and impact['effect'] != 'unresolved', reason=impact['reason'])
    contract = apply_fixed_binding_response(json.dumps(bound).encode(), request=binding,
        contract=contract, prompt=task["prompt"], catalog=catalog)
    # Generation facts target the exact injected implementation, never runtime operations.
    edges = list(contract.relations)
    from .prompt_contract_extract import _indexed_citation, _source_tokens, _include_recorded_impacts
    for key, owner, condition, relation in guards:
        if relation == 'context_for':
            edges.append(dict(source=key, target=owner, edge_type=relation,
                **_indexed_citation(task['prompt'], _source_tokens(task['prompt']), citation(condition))))
    for record in value["requirements"]:
        if record["scope_kind"] == "implementation":
            from .prompt_contract_extract import _indexed_citation, _source_tokens
            implementation = [f['local_id'] for f in contract.facts if f['node_type']=='task_operation'
                              and contract.source_inventory['layers'][f['local_id']]=='generation']
            if len(implementation) != 1:
                raise Error('generation obligations require one source-supported implementation operation')
            edges.append(dict(source=aliases[record["record_id"]], target=_target_operations(record, (), implementation)[0],
                edge_type="constrains", **_indexed_citation(task["prompt"], _source_tokens(task["prompt"]), citation(record["fact"]))))
    contract = replace(contract, relations=tuple(edges), source_inventory={**contract.source_inventory,
        "statement_kinds": modalities,
        "requirement_scopes": {aliases[key]: dict(kind=row['scope_kind'],
            boundaries=[aliases[k] for k in row['operations']], target_class=row['target_class'])
            for key, row in requirements.items() if row['scope_kind'] in {'task', 'each'}},
        "requirement_structures": {aliases[key]: dict(kind=row['structure']['kind'],
            members=[aliases[m] for m in row['structure']['members']]) for key, row in requirements.items()}})
    owned_relations = {aliases[key]: [dict(source=aliases[r['source']], target=aliases[r['target']],
        edge_type=r['edge_type'], **_indexed_citation(task['prompt'], _source_tokens(task['prompt']), citation(r)))
        for r in row['relations']] for key, row in requirements.items() if row['relations']}
    if owned_relations:
        contract = replace(contract, source_inventory={**contract.source_inventory,
            'requirement_relations': owned_relations})
    impacts = deepcopy(contract.source_inventory['unit_impacts'])
    for key, impact in value['unit_impacts'].items():
        impacts[key].update(_indexed_citation(task['prompt'], _source_tokens(task['prompt']), citation(impact)))
    contract = replace(contract, source_inventory={**contract.source_inventory, 'unit_impacts': impacts})
    contract = _include_recorded_impacts(contract)
    opaque = {aliases[key] for key, row in requirements.items() if row['structure']['kind'] == 'opaque'}
    if "unresolved" in modalities.values() or opaque:
        impacts = deepcopy(contract.source_inventory["unit_impacts"])
        for unit, coverage in contract.source_inventory["coverage"].items():
            if any(modalities.get(key) == "unresolved" or key in opaque for key in coverage["facts"]):
                impacts[unit].update(complete=False, reason="The source statement's force or composition remains unresolved.")
        contract = replace(contract, source_inventory={**contract.source_inventory, "unit_impacts": impacts})
    compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    return contract


def _identify_new_meanings(value, request):
    """Allocate new semantic identities from exact meanings, never from guessed category labels."""
    from .records import content_hash
    result = deepcopy(value)
    if request['concept_policy'] != 'DEVELOPMENT_OPEN':
        return result
    def visit(item):
        if isinstance(item, list):
            for child in item: visit(child)
        elif isinstance(item, dict):
            concept = item.get('concept')
            if isinstance(concept, dict) and concept['concept_id'] not in request['known_concepts']:
                exact = [key for key, known in request['known_concepts'].items()
                         if all(known[k] == concept[k] for k in ('node_type','definition'))]
                concept['concept_id'] = exact[0] if len(exact)==1 else 'source.'+content_hash(
                    {k:concept[k] for k in ('node_type','definition')})
            for child in item.values(): visit(child)
    visit(result)
    return result


def record_diagnostics(value, request):
    """Collect independent mechanical defects so one repair can address them together."""
    from .prompt_contract_extract import _quoted_inventory_citation, _inventory_concept, PromptContractExtractionError
    errors, facts, citations = [], [], []
    records = _records(value)
    objects = {r['record_id'] for r in value['objects']}
    operations = {r['record_id'] for r in value['operations']}
    for row in records:
        facts.append((row['record_id'], row['fact']))
        for field in ('conditions', 'execution_conditions', 'scope_conditions'):
            facts.extend((row['record_id']+'.'+field, f) for f in row.get(field, []))
        for field in ('inputs', 'results', 'precedes'):
            for i, claim in enumerate(row.get(field, [])):
                path = f"{row['record_id']}.{field}.{i}"
                citations.append((path, {k:claim[k] for k in ('evidence_source_unit','evidence_text')}))
                ref = claim.get('subject', claim.get('operation'))
                if ref not in (operations if field=='precedes' else objects):
                    errors.append(f'{path}: {ref!r} is not an exact declared record_id')
        if 'scope_kind' in row:
            # Concept validation below must not prevent independent scope/reference
            # diagnostics from reaching the single mechanical repair together.
            meaning = row['fact'].get('concept') or request['known_concepts'].get(
                row['fact'].get('concept_id'), {})
            layer = row['fact'].get('layer', meaning.get('layer'))
            if row['scope_kind'] in {'task','each'} and layer!='runtime' or row['scope_kind']=='implementation' and layer!='generation':
                errors.append(row['record_id']+': task/each scope is runtime; implementation scope is generation')
            if row['modality']!='obligation' and meaning.get('node_type')!='constraint':
                errors.append(row['record_id']+': an assumption requires a neutral constraint meaning')
            if row['scope_kind'] in {'task','implementation','composite'} and (row['operations'] or row['subjects']):
                errors.append(row['record_id']+': task/implementation/composite scope requires empty operation/subject target lists')
            compound = row['structure']['kind'] in {'and','or','not'}
            if compound != (row['scope_kind']=='composite'):
                errors.append(row['record_id']+': AND/OR/NOT is a composite container; members retain their own bindings')
            if ((row['scope_kind']=='each') != (row['target_class'] is not None)
                or row['scope_kind']=='each' and (len(row['operations'])>1 or row['subjects'])):
                errors.append(row['record_id']+': each needs a target class and zero/one boundary, never an instance list')
            if not set(row['operations']) <= operations or not set(row['subjects']) <= objects:
                errors.append(row['record_id']+': requirement targets must be exact declared record_ids')
    for path, fact in facts:
        try:
            _inventory_concept(fact, request)
        except PromptContractExtractionError as error:
            errors.append(path+': '+str(error))
    from .prompt_tsg import requirement_membership, PromptTSGError
    requirements = {r['record_id']: r for r in value['requirements']}
    try:
        requirement_membership([(k, r['structure']['kind'], r['structure']['members']) for k,r in requirements.items()], requirements)
        for key, row in requirements.items():
            if any(requirements[m]['modality'] != row['modality'] for m in row['structure']['members']):
                errors.append(key+': composite members must preserve the parent modality')
    except PromptTSGError as error:
        errors.append(str(error))
    runtime = {r['record_id'] for r in value['operations'] if r['fact']['layer'] == 'runtime'}
    independent = {(row['record_id'], 'precedes', r['operation'], r['evidence_source_unit'])
        for row in value['operations'] for r in row['precedes']}
    for row in value['requirements']:
        if row['scope_kind']=='each' and not set(row['operations']) <= runtime:
            errors.append(row['record_id']+': universal boundary must be a runtime operation')
        relation_keys = set()
        for i, relation in enumerate(row['relations']):
            key = (relation['source'], relation['edge_type'], relation['target'])
            path = f"{row['record_id']}.relations.{i}"
            if (key in relation_keys or key[0] == key[2] or {key[0], key[2]} - runtime
                or key[1] != 'precedes' or row['fact']['layer'] != 'runtime'
                or row['structure']['kind'] != 'atom'):
                errors.append(path+': unique precedence between distinct runtime operations needs a runtime atom owner')
            relation_keys.add(key)
            if relation['evidence_source_unit'] not in row['fact']['source_units']:
                errors.append(path+': relation evidence unit must belong to its requirement owner')
            if (*key, relation['evidence_source_unit']) in independent:
                errors.append(path+': one source declaration cannot be both owned order and independent context')
            citations.append((path, relation))
    for unit, impact in value['unit_impacts'].items():
        if ((impact['effect']=='local') != bool(impact['operations'])
            or not set(impact['operations']) <= runtime or len(set(impact['operations'])) != len(impact['operations'])):
            errors.append(unit+': local impact needs all affected runtime record IDs; other effects use []')
        citations.append((unit+'.impact', impact))
    for path, fact in [*facts, *citations]:
        try:
            _quoted_inventory_citation(fact, request, path)
        except PromptContractExtractionError as error:
            errors.append(str(error))
    owned = {unit for _, f in facts for unit in f['source_units']}
    for unit, coverage in value['coverage'].items():
        if coverage['status']=='represented' and unit not in owned:
            errors.append(unit+': represented requires a submitted task fact; fixed-template-only coverage is no_task_fact')
    return errors


def structural_readback(request, value):
    """Decode actual binding fields, never recover targets/guards from description text."""
    from .prompt_tsg import requirement_membership
    effective = _inherit_conditions(value)
    operations = {r['record_id']:r for r in value['operations']}
    runtime = {key for key,row in operations.items() if row['fact']['layer']=='runtime'}
    implementation = {key for key,row in operations.items() if row['fact']['layer']=='generation'}
    implementation.update(n['local_id'] for n in request.get('fixed_template',{}).get('nodes',[])
                          if n['concept_id']=='code.implementation')
    def meaning(fact):
        return (fact.get('concept') or request['known_concepts'][fact['concept_id']])['definition']
    def guards(facts):
        return [dict(predicate=meaning(f),source_quote=f['evidence_text']) for f in facts]
    requirement_ids={r['record_id'] for r in value['requirements']}
    asserted,atoms=requirement_membership([(r['record_id'],r['structure']['kind'],r['structure']['members'])
        for r in value['requirements']],requirement_ids)
    decoded={}
    for row in effective['requirements']:
        key=row['record_id']; targets=_target_operations(row,runtime,implementation)
        bindings=[]
        for target in targets:
            execution=operations.get(target,{}).get('execution_conditions',[])
            bound_guards=guards([*row['conditions'],*execution])
            bindings.append(dict(target_operation=target,
                structural_guard=bound_guards or 'UNCONDITIONAL: no guard is declared for this binding',
                reading=f"{row['modality']} predicate {key} directly constrains operation {target}; "
                        + ('ALL listed structural guards must hold.' if bound_guards else 'No structural condition restricts this binding.')))
        decoded[key]=dict(predicate_definition_claim=meaning(row['fact']),
            composition=row['structure'],asserted_as_standalone=key in asserted,structural_leaf_only=key in atoms,
            modality=row['modality'],scope_kind=row['scope_kind'],direct_operation_bindings=bindings,
            retained_scope=(dict(kind=row['scope_kind'], boundaries=row['operations'] or ['TASK_RUNTIME_BOUNDARY'],
                target_class=row['target_class'], expansion='NONE: no complete instance set is asserted')
                if row['scope_kind'] in {'task','each'} else None),
            direct_subject_targets=row['subjects'],
            owned_relations=[dict(source=r['source'],edge_type=r['edge_type'],target=r['target'],
                source_quote=r['evidence_text'],
                interpretation='Operands of this requirement; not additional direct targets or independent context. Owner modality, guards and composition apply.')
                for r in row['relations']],
            requirement_guards=guards(row['conditions']) or 'UNCONDITIONAL: no requirement guard declared',
            interpretation='The predicate text is an unverified content claim. It cannot supply a missing structural guard/target. Composite members retain their own bindings; OR/NOT members are not independently asserted.')
    return dict(requirements=decoded, record_semantics=record_semantics(),
        objects={r['record_id']:dict(source_anchor=r['fact']['evidence_text']) for r in value['objects']},
        operations={key:dict(source_anchor=row['fact']['evidence_text'],
            execution_guard=guards(row['execution_conditions']) or
                'NO DECLARED EXECUTION GUARD: operation presence does not assert execution on every path',
            non_gating_contexts=guards(row['scope_conditions']),
            inputs=[dict(subject=r['subject'],role=r['role']) for r in row['inputs']],
            results=[r['subject'] for r in row['results']],precedes=[r['operation'] for r in row['precedes']])
            for key,row in operations.items()},
        empty_field_rule='An empty conditions list supplies no guard. A guard present only in prose is NOT represented. Unresolved source coverage remains unresolved; readback never repairs it.')




def review_request(request, value, *, compiled_contract=None):
    check = dict(request_kind="source_only_record_review", source_prompt=request["source_prompt"],
        source_units=request["source_units"], records=value,
        operation_role_meanings=request['operation_role_meanings'],
        record_semantics=record_semantics(),
        instructions=(
            "Audit every record AND every source unit against the complete original source. The proposal "
            "is fallible. For each record check its full predicate, modality, every participant, target, "
            "guard and precedence. In particular, availability does not require later use; an expected "
            "input domain does not prescribe rejection; branch-result guards do not gate whole operations. "
            "Check task-wide obligations retain task scope and conditional branches are preserved, "
            "including inside explicitly retained composites. Audit unit_impacts and scope_conditions. "
            "For every proposed input ask whether the full source permits this operation not using it; "
            "do not invent a business premise to rule out that alternative. Unsupported or ambiguous "
            "clauses need correction even when the rest of a record is sound. For every source unit list "
            "any missing meaning, including variable names and non-target behavior. Mark record status "
            "supported only when ALL claims in it are supported. In rejected_claims name each erroneous "
            "field or list item, e.g. inputs.0, conditions (including an empty list), conditions.1, scope_kind, fact, modality; use the provided "
            "claim IDs. The compiler will prevent that exact rejected claim from surviving the repair. "
            "A source-compatible alternative must "
            "respect the full task, not omit stated behavior. Return complete record and unit reviews, "
            "not a revised graph. This review is a fallible diagnostic, not independent qualification."))
    if compiled_contract is not None:
        check['effective_unit_impacts'] = deepcopy(compiled_contract.source_inventory['unit_impacts'])
        check['compiled_operations'] = {fact['local_id']: dict(
            evidence_text=fact['evidence_text'], occurrence=fact['occurrence'],
            definition=compiled_contract.catalog['semantic_guidance'][fact['semantic_id']],
            layer=compiled_contract.source_inventory['layers'][fact['local_id']])
            for fact in compiled_contract.facts if fact['node_type'] == 'task_operation'}
        check['instructions'] += (
            " records.unit_impacts contains model declarations in record IDs. effective_unit_impacts "
            "is the actual compiled impact table in canonical local IDs, resolved by compiled_operations. "
            "The compiler conservatively includes dependencies of the recorded facts and owned relations. "
            "Judge source-unit impact completeness using this effective table: a dependency missing from "
            "the original declaration but already included here is NOT a missing graph dependency. "
            "This computed lower bound is not a completeness or semantic-correctness certificate. "
            "Still reject unsupported effective impacts and identify source-supported dependencies "
            "missing from the effective table; do not infer no influence from absent edges.")
    return check



def review_response_format(request):
    status = dict(type="string", enum=["supported", "unsupported", "unresolved"])
    return dict(type="json_schema", json_schema=dict(name="source_record_review", strict=True,
        schema=_object(dict(records=_object({r["record_id"]: _object(dict(status=status, reason=dict(type="string"),
            rejected_claims=_array(dict(type="string", enum=list(_claims(r)))))) for r in _records(request["records"])}),
            source_units=_object({key: _object(dict(complete=dict(type="boolean"), reason=dict(type="string")))
                                  for key in request["source_units"]})))))





def _claims(record):
    return {claim: value for key, item in record.items() if key != "record_id"
            for claim, value in ([(key,item),*[(f"{key}.{i}", v) for i, v in enumerate(item)]]
                                 if isinstance(item, list) else [(key, item)])}


def _claim_meaning(field, value):
    """A changed citation or provisional label cannot revive the same rejected proposition."""
    if isinstance(value,list):
        return [_claim_meaning(field,item) for item in value]
    if field in {'inputs', 'results', 'precedes', 'relations'}:
        return {k:value[k] for k in ('subject','role','operation','source','edge_type','target') if k in value}
    if field in {'fact','conditions','execution_conditions','scope_conditions'}:
        concept = value.get('concept')
        return {k:concept[k] for k in ('node_type','definition')} if concept else value.get('concept_id')
    return value


def repair_request(request, value, review):
    """Allow changes only to rejected records, omitted units and their dependants."""
    check = review_request(request, value)
    _validate_shape(review, review_response_format(check)["json_schema"]["schema"])
    rows = {r["record_id"]: r for r in _records(value)}
    rejected = {key for key, v in review["records"].items() if v["status"] != "supported" or v["rejected_claims"]}
    units = {key for key, v in review["source_units"].items() if not v["complete"]}
    if not rejected and not units:
        return None
    editable = set(rejected)
    def references(row):
        return ({r["subject"] for k in ("inputs", "results") for r in row.get(k, [])}
                | {r["operation"] for r in row.get("precedes", [])}
                | {r[k] for r in row.get('relations', []) for k in ('source', 'target')}
                | set(row.get("operations", [])) | set(row.get("subjects", []))
                | set(row.get('structure', {}).get('members', [])))
    # A changed source clause or referenced entity can require local rebinding.
    while True:
        before = set(editable)
        for key, row in rows.items():
            if key in editable:
                units.update(row["fact"]["source_units"])
            if set(row["fact"]["source_units"]) & units or references(row) & editable:
                editable.add(key)
        if before == editable:
            break
    return dict(request_kind="source_only_record_patch", source_prompt=request["source_prompt"],
        source_units=request["source_units"], original_records=value, source_review=review,
        editable_record_ids=sorted(editable), rejected_record_ids=sorted(rejected), affected_source_units=sorted(units),
        instructions=(
            "Correct the reviewed source meanings once using the original source. Return only replacements "
            "for editable_record_ids, newly needed records, explicit delete_record_ids and coverage for "
            "affected_source_units, including their unit_impacts. Preserve IDs for surviving records and all unaffected records byte-for-byte. "
            "Copy unit_impacts unchanged for source units whose review is complete=true; a target correction "
            "does not authorize narrowing source influence. The program preserves these accepted declarations. "
            "Do not re-emit unaffected records. Replacements have the original record schema, including "
            "attached scope/guards/participants. A rejected record cannot survive unchanged. Correct the "
            "specific rejected claim, not just its wording. Newly declared facts must use the supplied "
            "concept policy. If meaning cannot be resolved, mark affected coverage unresolved. No guessing "
            "or broad reconstruction. The program merges the patch and deterministically recompiles."),
        concept_policy=request["concept_policy"], known_concepts=request["known_concepts"],
        operation_role_meanings=request['operation_role_meanings'],
        record_semantics=check['record_semantics'])


def patch_response_format(request, original_request):
    fields = deepcopy(record_response_format(original_request)["json_schema"]["schema"]["properties"])
    for field in ('coverage', 'unit_impacts'):
        fields[field]["properties"] = {key: fields[field]["properties"][key] for key in request["affected_source_units"]}
        fields[field]["required"] = list(fields[field]["properties"])
    fields["delete_record_ids"] = _array(dict(type="string", enum=request["editable_record_ids"]) if request["editable_record_ids"] else dict(type="string"))
    return dict(type="json_schema", json_schema=dict(name="source_record_patch", strict=True, schema=_object(fields)))


def apply_record_patch(value, patch, *, request, original_request):
    from .prompt_contract_extract import PromptContractExtractionError as Error
    _validate_shape(patch, patch_response_format(request, original_request)["json_schema"]["schema"])
    old = {r["record_id"]: r for r in _records(value)}
    changes = {r["record_id"]: r for r in _records(patch)}
    deleted = set(patch["delete_record_ids"])
    if len(changes) != len(_records(patch)) or len(deleted) != len(patch["delete_record_ids"]) or deleted & set(changes):
        raise Error("patch repeats a record or both deletes and replaces it")
    if not (deleted | (set(changes) & set(old))) <= set(request["editable_record_ids"]):
        raise Error("patch changes an unaffected record")
    for key, row in changes.items():
        if not set(row["fact"]["source_units"]) & set(request["affected_source_units"]):
            raise Error("patch adds an unrelated source record")
    for key in request["rejected_record_ids"]:
        if key not in deleted and (key not in changes or changes[key] == old[key]):
            raise Error("patch retains a rejected record unchanged")
        if key not in deleted:
            for claim in request["source_review"]["records"][key]["rejected_claims"]:
                field = claim.split(".")[0]
                rejected = _claim_meaning(field, _claims(old[key])[claim])
                current = changes[key].get(field)
                if (rejected in [_claim_meaning(field, v) for v in current] if '.' in claim and isinstance(current, list)
                    else rejected == _claim_meaning(field, current)):
                    raise Error(f"patch repeats rejected claim {key}.{claim}")
    result = deepcopy(value)
    for group in ("objects", "operations", "requirements"):
        existing = {r["record_id"] for r in value[group]}
        if any(r["record_id"] in old and r["record_id"] not in existing for r in patch[group]):
            raise Error("patch cannot silently change a record's semantic group")
        result[group] = [changes.get(r["record_id"], r) for r in value[group] if r["record_id"] not in deleted]
        result[group].extend(r for r in patch[group] if r["record_id"] not in old)
    result["coverage"].update(patch["coverage"])
    # Record binding repair does not reopen source influence already accepted by
    # review. Only a rejected/incomplete source unit authorizes impact changes.
    result['unit_impacts'].update({key:impact for key,impact in patch['unit_impacts'].items()
        if not request['source_review']['source_units'][key]['complete']})
    # Notes cannot erase unresolved coverage; compilation checks that independently.
    result["unresolved_notes"] = list(dict.fromkeys([*value["unresolved_notes"], *patch["unresolved_notes"]]))
    return result


def attempt_graph(task, *, catalog, evaluator, annotator_prompt, review_status, provider):
    """One extraction, optional mechanical repair, one review and optional local patch."""
    from .prompt_contract_extract import contract_decision_request, _TaskContractAttempt, PromptContractExtractionError
    from .prompt_contract import compile_task_context_contract
    from .task_input import prepare_task_input
    task = prepare_task_input(task)
    request = record_request(contract_decision_request(task, catalog))
    calls, raw, contract, graph = 0, None, None, None
    audit = dict(status="FAILED", provider_calls=0, response_text=None, response_sha256=None,
                 error_type=None, error_message=None, calls=[])
    def call(payload, response_format):
        nonlocal calls
        from .records import content_hash
        import hashlib
        calls += 1
        saved = dict(request=payload, response_format_sha256=content_hash(response_format),
                     response_text=None, response_sha256=None, error=None)
        audit["calls"].append(saved)
        try:
            response = provider(payload, {**evaluator, "response_format": response_format}, annotator_prompt)
            saved.update(response_text=response.decode(), response_sha256=hashlib.sha256(response).hexdigest())
            return response
        except Exception as error:
            saved["error"] = dict(type=type(error).__name__, message=str(error))
            raise
    def compile_value(value):
        return compile_records(value, request=request, task=task, catalog=catalog,
            annotator_id=f"single-evidence:{evaluator['candidate_id']}", review_status=review_status)
    try:
        schema = record_response_format(request)
        raw = call(request, schema)
        audit["initial_response_text"] = raw.decode()
        try:
            value = json_object(raw)
            contract = compile_value(value)
        except (PromptContractExtractionError, ValueError, KeyError, TypeError) as error:
            audit["mechanical_error"] = str(error)
            raw = call({**request, "mechanical_repair": dict(previous_response=raw.decode(),
                diagnostic=str(error), instruction="Correct this mechanical defect once in the same record schema; preserve source meaning.")}, schema)
            value = json_object(raw)
            contract = compile_value(value)
        graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
        from .prompt_contract import task_context_contract_record
        from .prompt_tsg import prompt_tsg_record
        audit.update(pre_review_records=deepcopy(value), pre_review_structural_readback=structural_readback(request,value),
                     pre_review_contract=task_context_contract_record(contract),
                     pre_review_graph=prompt_tsg_record(graph))
        check = review_request(request, value, compiled_contract=contract)
        reviewed = json_object(call(check, review_response_format(check)))
        audit["review"] = reviewed
        patch_request = repair_request(request, value, reviewed)
        audit['effective_review'] = patch_request['source_review'] if patch_request else reviewed
        if patch_request is not None:
            patch = json_object(call(patch_request, patch_response_format(patch_request, request)))
            audit["patch_request"], audit["patch"] = patch_request, patch
            value = apply_record_patch(value, patch, request=patch_request, original_request=request)
            contract = compile_value(value)
            graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
        audit.update(status="COMPILED_RECORDS_WITH_UNKNOWN_PRESERVED", records=value,
            structural_readback=structural_readback(request,value),
            response_text=json.dumps(value, ensure_ascii=False), provider_calls=calls-1)
        import hashlib
        audit['response_sha256'] = hashlib.sha256(audit['response_text'].encode()).hexdigest()
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        audit.update(error_type=type(error).__name__, error_message=str(error), provider_calls=calls-1)
        return _TaskContractAttempt(str(task["task_id"]), request, calls, raw, contract, graph,
            type(error).__name__, str(error), None, binding_annotation=audit)
    return _TaskContractAttempt(str(task["task_id"]), request, calls, raw, contract, graph,
        None, None, None, binding_annotation=audit)

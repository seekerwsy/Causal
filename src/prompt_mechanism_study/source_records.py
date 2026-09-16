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


def record_request(inventory):
    from .prompt_contract_extract import grouped_inventory_request, _OBJECT_ROLE_MEANINGS
    request = grouped_inventory_request(inventory)
    for key in ("development_scope", "fact_granularity", "annotation_phase", "source_instance_policy"):
        request.pop(key, None)
    request.update(request_kind="source_only_atomic_records", operation_role_meanings=_OBJECT_ROLE_MEANINGS,
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
            "Use structure.kind=atom with members=[] for it. Preserve composites as and/or/not/opaque "
            "with members naming requirement record IDs; and/or need at least two members; the not "
            "operator needs exactly one member; opaque has none. All members share the parent's modality. A member has one parent. "
            "OR/NOT members are not independently asserted obligations. A simple prohibition is one "
            "complete negative atom; not represents compound negation. Do not force uncertain splitting. "
            "The compiler preserves parent guards on descendants; each leaf still names its exact targets. "
            "Preserve negation, thresholds, variable names, return values and tuple fields. Separate reliable "
            "if/else consequents. Each guard belongs in that requirement's conditions, not in an operation's "
            "execution_conditions. Execution conditions mean the entire operation is conditional. "
            "Use scope_kind=task for task-wide runtime obligations; the compiler applies these to every "
            "runtime operation. Use implementation for generation obligations; use targets for explicitly "
            "named operations/objects. Never narrow task-wide failure behavior to one likely failure site. "
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
            "precedes needs a source-required order, not sentence order or an imagined implementation. "
            "All references are semantic claims and need source support. Cite all cross-sentence premises. "
            "Use known concepts only when their complete meanings match; copy them exactly. Under "
            "DEVELOPMENT_OPEN declare a complete inline meaning when none fits; FROZEN admits no new "
            "concept. New concept IDs are provisional labels: the compiler assigns identity from the "
            "complete definition and node type. Different atomic predicates retain different identities. "
            "Never redeclare fixed template facts. A unit covered only by those fixed facts uses "
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
                precedes=_array(_object(dict(operation=dict(type="string", description="Exact record_id of another operation."), **citation))))
        if group == "requirements":
            if 'concept' in fact['properties']:
                fact['properties']['concept']['properties']['definition']['description'] = (
                    'Complete source meaning, preserving values/names/negation/thresholds. '
                    'An atom is one consequent; a composite declares its structure and members. '
                    'Keep guards in conditions and never disguise a compound meaning as an atom.')
            props.update(modality=dict(type="string", enum=["obligation", "assumption", "unresolved"]),
                structure=_object(dict(kind=dict(type="string", enum=["atom", "and", "or", "not", "opaque"]),
                    members={**ref, "description": "Exact requirement record IDs. atom/opaque: none; and/or: at least two; not: exactly one."})),
                scope_kind=dict(type="string", enum=["task", "targets", "implementation"],
                    description="task: all runtime operations, no target lists. implementation: generation-layer requirement, no target lists. targets: explicitly listed local operations/subjects."),
                operations={**ref, "description": "Exact operation record_ids for targets scope; MUST be empty for task/implementation scope."},
                subjects={**ref, "description": "Exact object record_ids for targets scope; MUST be empty for task/implementation scope."}, conditions=_array(condition))
        fields[group] = _array(_object(props))
    fields.update(coverage=groups["coverage"], unit_impacts=_object({key: _object(dict(
        effect=dict(type="string", enum=["local", "global", "unresolved", "no_runtime_effect"]),
        operations={**ref, "description": "ALL affected runtime operation record IDs for local; empty otherwise."},
        reason=text, **citation)) for key in request["source_units"]}), unresolved_notes=_array(text))
    return dict(type="json_schema", json_schema=dict(name="atomic_source_records", strict=True, schema=_object(fields)))


def _records(value):
    return [row for group in ("objects", "operations", "requirements") for row in value[group]]


def _validate_shape(value, schema, path="response"):
    """Validate the small schema subset used here, also in ordinary JSON mode."""
    from .prompt_contract_extract import PromptContractExtractionError as Error
    kind = schema["type"]
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
    return sorted(runtime if record['scope_kind']=='task' else implementation
                  if record['scope_kind']=='implementation' else record['operations'])


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
        if record["scope_kind"] in {"task", "implementation"}:
            if record["operations"] or record["subjects"]:
                raise Error("task/implementation scope has no hand-picked targets")
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
        "requirement_structures": {aliases[key]: dict(kind=row['structure']['kind'],
            members=[aliases[m] for m in row['structure']['members']]) for key, row in requirements.items()}})
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
            if row['scope_kind']=='task' and layer!='runtime' or row['scope_kind']=='implementation' and layer!='generation':
                errors.append(row['record_id']+': task scope is runtime; implementation scope is generation')
            if row['modality']!='obligation' and meaning.get('node_type')!='constraint':
                errors.append(row['record_id']+': an assumption requires a neutral constraint meaning')
            if row['scope_kind'] in {'task','implementation'} and (row['operations'] or row['subjects']):
                errors.append(row['record_id']+': task/implementation scope requires empty operation/subject target lists')
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
            composition=row['structure'],asserted_as_standalone=key in asserted,atomic_candidate_structure=key in atoms,
            modality=row['modality'],scope_kind=row['scope_kind'],direct_operation_bindings=bindings,
            direct_subject_targets=row['subjects'],
            requirement_guards=guards(row['conditions']) or 'UNCONDITIONAL: no requirement guard declared',
            interpretation='The predicate text is an unverified content claim. It cannot supply a missing structural guard/target. Composite members retain their own bindings; OR/NOT members are not independently asserted.')
    return dict(requirements=decoded,
        objects={r['record_id']:dict(source_anchor=r['fact']['evidence_text']) for r in value['objects']},
        operations={key:dict(source_anchor=row['fact']['evidence_text'],
            execution_guard=guards(row['execution_conditions']) or 'UNCONDITIONAL execution',
            non_gating_contexts=guards(row['scope_conditions']),
            inputs=[dict(subject=r['subject'],role=r['role']) for r in row['inputs']],
            results=[r['subject'] for r in row['results']],precedes=[r['operation'] for r in row['precedes']])
            for key,row in operations.items()},
        empty_field_rule='An empty conditions list supplies no guard. A guard present only in prose is NOT represented. Unresolved source coverage remains unresolved; readback never repairs it.')




def review_request(request, value):
    return dict(request_kind="source_only_record_review", source_prompt=request["source_prompt"],
        source_units=request["source_units"], records=value,
        operation_role_meanings=request['operation_role_meanings'],
        record_semantics=dict(
            task_scope='The compiler constrains EVERY runtime operation with this predicate. This is not a generic label for a task-related requirement. Reject task scope if even one unrelated operation would receive the predicate.',
            targets_scope='Only the listed operation and object record IDs receive this predicate; required targets must not be omitted.',
            implementation_scope='The predicate constrains generation of the implementation, not execution of its runtime operations.',
            guard='A requirement condition guards that complete consequent only. An execution_condition gates the entire operation. Conditions hidden only inside prose have not been structurally represented.',
            modality='An obligation prescribes behavior. An assumption is source context without prescribing validation/rejection; unresolved force cannot certify an intervention.',
            atomicity='Atoms preserve whole predicates and guards. Check and/or/not/opaque membership: OR/NOT members are not independently required. A faithfully represented composite is allowed but not an Atomic factor. Reliable if/else consequents retain distinct guards.',
            context='scope_conditions/context_for is a source-established non-gating condition context, independent of the target obligation. It must remain meaningful after removing the target; execution_conditions gates the whole operation.',
            impacts='For EVERY source unit, check its unit_impacts declaration against the complete source. Missing edges never prove no influence. Local must name ALL affected operations, including shared objects, interfaces and cross-operation effects. Complete is false if either meaning coverage or impact is unsupported/uncertain.'),
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
    if field in {'inputs', 'results', 'precedes'}:
        return {k:value[k] for k in ('subject','role','operation') if k in value}
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
        check = review_request(request, value)
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

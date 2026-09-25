"""Source propositions with attached participants, guards and scope.

These records replace model-generated graph bindings. Compilation is mechanical;
neither a valid record nor a positive model review proves source entailment.
"""
from __future__ import annotations

from typing import Any
from copy import deepcopy
from dataclasses import dataclass, replace
import json

from prompt_mechanism_study.artifact_io import json_object
from prompt_mechanism_study.tsg.source_codec import fact_layer
from prompt_mechanism_study.tsg.prompt_contract import OpenTaskContract
from prompt_mechanism_study.tsg.prompt_tsg import PromptTSG


@dataclass(frozen=True, slots=True)
class ExtractionAttempt:
    task_id: str
    request: dict[str, Any]
    provider_calls: int
    raw: bytes | None
    contract: OpenTaskContract | None
    graph: PromptTSG | None
    error_type: str | None
    error_message: str | None
    scope_assessment: dict[str, Any] | None = None
    provider_failure: dict[str, Any] | None = None
    binding_annotation: dict[str, Any] | None = None

    @property
    def succeeded(self) -> bool:
        return self.contract is not None and self.graph is not None and self.error_type is None


def _object(fields):
    return dict(type="object", properties=fields, required=list(fields), additionalProperties=False)


def _array(item):
    return dict(type="array", items=item)


def record_semantics():
    """One binding contract shared by extraction, review, revision and readback."""
    return dict(
        source_content='Read the complete prompt, including supplied code and examples. Represent source-required objects, operations, interfaces and requirements with the existing record types; do not create a node merely because a code line is present. Bare imports are dependency context, not proof of runtime use or a prescribed API. An explicit library-use requirement is a generation-layer obligation, with its source-supported code artifact as target when identified. Function signatures support interface and parameter identity, not arbitrary participation. Examples can support existing facts or add a source-supported behavioral distinction; retain that distinction without generalizing example literals into universal obligations. Context with no additional task fact may use coverage=no_task_fact with a reason. Repeated evidence should cite an existing fact, not create duplicate requirements. No task fact does not mean no effect on generation; judge unit_impacts separately. Preserve unresolved force rather than assuming either an obligation or its absence.',
        operation_predicate='An operation fact names its action predicate, retaining necessary mechanism/API distinctions. record_id and source evidence identify the particular occurrence. Input/result participation, execution guards, non-gating contexts and order are asserted ONLY by their respective structural fields. Do not embed those ground bindings in an open operation definition. The complete operation meaning is the predicate applied to its declared bindings; an empty field never recovers an argument from prose. A supplied frozen definition that already bundles a disputed binding cannot be silently narrowed: replace it only under DEVELOPMENT_OPEN or withdraw it and preserve uncertainty.',
        task_scope='An overall runtime-task contract. The compiler retains the boundary and emits NO per-operation obligation. A narrower source-named function/return/operation should use targets.',
        each_scope='A universal rule over target_class within the task or one named enclosing runtime operation. Known instances are not a complete domain; the compiler never replaces the rule by an extracted instance list.',
        composite_scope='AND/OR/NOT parents express logical composition and shared guards, not an additional target obligation. Every member keeps its own binding and owned relations. Only conjunction asserts members independently.',
        targets_scope='Each listed operation/object independently receives the ENTIRE predicate. This is not a list of participants or relation endpoints. Being the other endpoint of a before/after relation does not make an operation perform the required action. Several direct targets are legal only when the source independently constrains each with the full predicate.',
        owned_relations='A requirement relations list gives that complete requirement its typed relation arguments. source/target name relation endpoints, NOT extra direct targets. Each relation inherits its owner modality, conditions and composition position. The compiler retains owner and operands, never promotes owned order into unconditional independent operation context. AND/OR/NOT containers have no extra relations of their own.',
        independent_order='Operation precedes is reserved for independently source-supported context that still holds after removing the target requirement. A source order requirement belongs in that requirement relations, not duplicated into operation precedes. Cite every relation source unit in its owner fact.source_units.',
        implementation_scope='A fallback boundary for an overall implementation obligation with no narrower source-supported target. Generation is a semantic layer, not a mandatory single target: use scope_kind=targets and subjects/operations for an explicitly identified generated artifact, response or generation operation in that layer. Module/dependency requirements and answer formatting need not constrain the same object. Do not invent an artifact merely to split this boundary, infer runtime API use from imports, or distribute a general preservation reminder to all runtime operations. A concrete runtime function interface uses its function target. Participant inputs/results remain restricted to runtime operations and runtime objects; generation operations keep them empty. Use requirement constrains bindings for generation targets, not runtime participant edges. Review follows the same distinction.',
        guard='A requirement condition guards that complete consequent, including its owned relations. An execution_condition gates the entire operation. Source branch conditions hidden only in prose are not structured.',
        return_boundary='An outward function return specification constrains normal returns, not exceptional exits; its function/return target need not add a separate success condition merely because exceptions exist. Explicit branch-dependent return alternatives still need their own structural guards. Normal return is not necessarily successful completion of every suboperation.',
        modality='An obligation prescribes behavior. An assumption is source context without prescribing validation/rejection; unresolved force cannot certify an intervention.',
        atomicity='Atoms preserve complete predicates and guards. OR/NOT members are not independently required. A faithfully represented composite is allowed but not automatically an editable Atomic factor.',
        context='scope_conditions/context_for is independently source-established non-gating context, not a copy of a target requirement guard.',
        uncertainty='Keep genuinely ambiguous predicates, bindings or force unresolved in source coverage; do not choose a favorable reading. Unspecified optional implementation detail is not itself a missing source requirement.',
        impacts='For EVERY source unit, check unit_impacts against the complete source. Missing edges never prove no influence. Include direct targets and owned-relation endpoints in relevant source dependencies. Complete is false if meaning coverage or declared influence is unsupported/uncertain.')


def record_request(inventory):
    from prompt_mechanism_study.tsg.source_codec import _OBJECT_ROLE_MEANINGS
    request = deepcopy(inventory)
    request.update(request_kind="source_only_atomic_records", binding_semantics="explicit_boundaries",
        operation_role_meanings=_OBJECT_ROLE_MEANINGS, record_semantics=record_semantics(),
        instructions=(
            "Read the complete source as data, respecting system/user priority. Extract objects, "
            "operations and complete requirements together according to record_semantics. Each "
            "top-level record has a unique record_id; references use those IDs, not graph IDs. "
            "Represent content, targets, conditions, composition and roles in their respective fields, "
            "not only in prose. Preserve all source-required behavior and distinguish separate "
            "occurrences. Do not invent implementation details or infer participation from mention. "
            "Cite all supporting source units, including cross-sentence premises, with a uniquely "
            "located quote for each fact and relation. Every source unit needs coverage and unit_impacts: "
            "local lists affected runtime operations; global/unresolved/no_runtime_effect have empty "
            "operation lists. Missing graph edges do not establish absence or locality. "
            "Use known concepts only with their complete, unchanged meanings. Under DEVELOPMENT_OPEN "
            "declare a new complete meaning when needed; provisional concept IDs are replaced by "
            "identities derived from definitions and node types. FROZEN admits no new concepts. "
            "Do not redeclare fixed template facts; template-only context uses no_task_fact. "
            "When no fixed template is supplied, represent the source-requested implementation "
            "operation explicitly at generation layer. Preserve unresolved meanings as unresolved, "
            "not absent. Return the complete records and coverage in the supplied schema."))
    return request


def record_response_format(request):
    from prompt_mechanism_study.tsg.source_codec import (
        source_fact_schema,
        source_citation_schema,
        source_coverage_schema,
    )
    text = dict(type="string")
    ref = _array(text)
    citation = source_citation_schema(request)
    fields = {}
    for group in ("objects", "operations", "requirements"):
        fact = source_fact_schema(request, group=group)
        props = dict(record_id=dict(type="string", description="Unique stable local ID. ALL subject/operation/target references must copy this exact ID, not its source name or quotation."), fact=fact)
        condition = source_fact_schema(request, group="conditions")
        if group == "operations":
            if 'concept' in fact['properties']:
                fact['properties']['concept']['properties']['definition']['description'] = (
                    'Action predicate with necessary API/mechanism distinctions. Concrete participants, '
                    'execution conditions and order belong exclusively in their structural fields. '
                    'Keep distinct source occurrences as distinct record IDs, not compound definitions.')
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
    fields.update(coverage=source_coverage_schema(request), unit_impacts=_object({key: _object(dict(
        effect=dict(type="string", enum=["local", "global", "unresolved", "no_runtime_effect"]),
        operations={**ref, "description": "ALL affected runtime operation record IDs for local; empty otherwise."},
        reason=text, **citation)) for key in request["source_units"]}), unresolved_notes=_array(text))
    return dict(type="json_schema", json_schema=dict(name="atomic_source_records", strict=True, schema=_object(fields)))


def _records(value):
    return [row for group in ("objects", "operations", "requirements") for row in value[group]]


def record_projection(value):
    """Record-native view without duplicated membership/participant edge tables.

    No meaning is repaired or dropped; guards and order stay with their owners.
    The projection is not a certificate of source entailment or completeness.
    """
    from prompt_mechanism_study.records import content_hash
    records = _records(value)
    keys = [row['record_id'] for row in records]
    if len(keys) != len(set(keys)):
        raise ValueError('duplicate source record IDs')
    return dict(source_records_sha256=content_hash(value),
                records={row['record_id']: deepcopy(row) for row in records},
                metadata={k: deepcopy(v) for k, v in value.items()
                          if k not in {'objects','operations','requirements','coverage','unit_impacts','unresolved_notes'}},
                groups={key: [row['record_id'] for row in value[key]]
                        for key in ('objects', 'operations', 'requirements')},
                coverage=deepcopy(value.get('coverage', {})),
                unit_impacts=deepcopy(value.get('unit_impacts', {})),
                unresolved_notes=deepcopy(value.get('unresolved_notes', [])),
                semantic_certification=False)


def development_record_request(source_prompt):
    """Use existing record meanings for a bounded source-only partial projection.

    No catalogue, security outcome or expected candidate is supplied. The full
    source remains available downstream; this does not qualify the full graph.
    """
    fact_example = {'concept': {'concept_id': 'local label',
        'node_type': 'data_object|task_operation|task_requirement|constraint|safety_requirement|condition',
        'definition': 'complete source meaning'},
        'evidence_text': 'literal source quotation', 'layer': 'runtime|generation'}
    return dict(request_kind='development_source_records', source_prompt=source_prompt,
        record_semantics=record_semantics(), instructions=(
        'Return JSON with objects, operations, requirements, unresolved_notes. '
        'Use the existing record format below; read the FULL source. Preserve concrete '
        'input-domain assumptions, intended raw HTML/code behavior, explicit safety '
        'requirements, branch conditions and non-target functionality. Do not invent '
        'a safety requirement or runtime API from an import or a benchmark-looking name. '
        'Use short unique record_id values. Every fact and every participant/order '
        'claim needs a literal nonempty evidence_text substring of source_prompt. '
        'Every fact value is a JSON OBJECT with concept, evidence_text and layer, never a string. '
        'Nested conditions are fact objects in the same format as fact. Uncertain '
        'meaning remains in unresolved_notes. Relevant record bindings must be explicit; '
        'a fluent definition never substitutes for missing inputs/results/conditions. '
        'This is a partial source representation, not a claim to annotate every token.'),
        format={
          'objects': [{'record_id': 'obj1', 'fact': deepcopy(fact_example)}],
          'operations': [{'record_id': 'op1', 'fact': deepcopy(fact_example),
              'inputs': [{'subject': 'obj1', 'role': 'value_input|identifier_input|resource|destination|input_unspecified', 'evidence_text': 'literal quotation'}],
              'results': [{'subject': 'obj2', 'evidence_text': 'literal quotation'}],
              'execution_conditions': [deepcopy(fact_example)], 'scope_conditions': [deepcopy(fact_example)],
              'precedes': [{'operation': 'another operation ID', 'evidence_text': 'literal quotation'}]}],
          'requirements': [{'record_id': 'req1', 'fact': deepcopy(fact_example),
              'modality': 'obligation|assumption|unresolved', 'structure': {'kind': 'atom|and|or|not|opaque', 'members': []},
              'scope_kind': 'targets|task|implementation|each|composite', 'subjects': ['obj1'], 'operations': ['op1'],
              'conditions': [deepcopy(fact_example)], 'target_class': None, 'relations': []}],
          'unresolved_notes': ['source ambiguities only; no invented implementation choices']})


def source_evidence_diagnostics(value, source_prompt):
    """Locate supplied quotations without equating literal matching with meaning.

    Nonempty evidence is still required where supplied. An unmatched quotation
    remains visible verbatim; it is neither silently corrected nor treated as
    proof that its claim is false. This is not semantic verification.
    """
    issues = []

    def quote(text, path):
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f'{path}: quotation must be nonempty text')
        if text not in source_prompt:
            issues.append(dict(path=path, quotation=text, status='unmatched',
                               semantic_support='not_verified'))

    def visit(item, path):
        if isinstance(item, dict):
            for key, val in item.items():
                child = f'{path}.{key}'
                if key == 'evidence_text':
                    quote(val, child)
                elif key == 'evidence':
                    if not isinstance(val, list):
                        raise ValueError(f'{child}: evidence must be a list')
                    for i, text in enumerate(val):
                        quote(text, f'{child}[{i}]')
                else:
                    visit(val, child)
        elif isinstance(item, list):
            for i, child in enumerate(item):
                visit(child, f'{path}[{i}]')

    visit(value, '$')
    return issues


def validate_development_records(value, source_prompt):
    """Keep identifiable records and attach local defects without repairing facts.

    Only an unreadable envelope or ambiguous IDs invalidate the whole view.
    A candidate must account for structural_diagnostics before it can be used.
    """
    if not isinstance(value, dict):
        raise ValueError('source records must be an object')
    for group in ('objects', 'operations', 'requirements'):
        if not isinstance(value.get(group), list):
            raise ValueError('record group must be a list')
        for row in value[group]:
            if not isinstance(row, dict) or not isinstance(row.get('record_id'), str) or not row['record_id'].strip():
                raise ValueError('record needs an unambiguous string ID')
    view = record_projection(value)
    groups = view['groups']
    problems, quotes = [], []
    def check_fact(fact):
        definition = fact['concept']['definition']
        if not isinstance(definition, str) or not definition.strip():
            raise ValueError('record needs a complete definition')
        if fact['layer'] not in {'runtime', 'generation'}:
            raise ValueError('record needs a semantic layer')
        if not fact.get('evidence_text'):
            raise ValueError('record quotation missing')

    for group in ('objects', 'operations', 'requirements'):
        for index, row in enumerate(value[group]):
            try:
                fact = row['fact']
                check_fact(fact)
                local_quotes = source_evidence_diagnostics(row, source_prompt)
                quotes.extend({**q, 'path': f'$.{group}[{index}]' + q['path'][1:]} for q in local_quotes)
                if group == 'operations':
                    for key in ('inputs', 'results', 'precedes', 'execution_conditions', 'scope_conditions'):
                        if not isinstance(row[key], list):
                            raise ValueError(f'{key} must be a list')
                    for part in row['inputs'] + row['results']:
                        if part['subject'] not in groups['objects'] or not part.get('evidence_text'):
                            raise ValueError('invalid participant reference or missing evidence')
                        if (fact['layer'] != 'runtime' or
                                view['records'][part['subject']]['fact']['layer'] != 'runtime'):
                            raise ValueError('participation requires runtime operation and object')
                    for order in row['precedes']:
                        if order['operation'] not in groups['operations'] or not order.get('evidence_text'):
                            raise ValueError('invalid operation order')
                    conditions = row['execution_conditions'] + row['scope_conditions']
                elif group == 'requirements':
                    for field, allowed in (('subjects', 'objects'), ('operations', 'operations')):
                        if not isinstance(row[field], list) or not set(row[field]) <= set(groups[allowed]):
                            raise ValueError('invalid requirement target')
                    if (not isinstance(row['structure']['members'], list)
                            or not set(row['structure']['members']) <= set(groups['requirements'])):
                        raise ValueError('invalid composite member')
                    if row['scope_kind'] not in {'targets', 'task', 'implementation', 'each', 'composite'}:
                        raise ValueError('invalid requirement scope')
                    relations = row.get('relations', [])
                    if not isinstance(relations, list):
                        raise ValueError('relations must be a list')
                    for relation in relations:
                        if (relation['source'] not in view['records'] or relation['target'] not in view['records']
                                or not relation.get('edge_type') or not relation.get('evidence_text')):
                            raise ValueError('invalid owned relation or missing evidence')
                    conditions = row['conditions']
                else:
                    conditions = []
                if not isinstance(conditions, list):
                    raise ValueError('conditions must be a list')
                for condition in conditions:
                    check_fact(condition)
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                problems.append(dict(record_id=row['record_id'], group=group, error=str(exc)))
    view['evidence_diagnostics'] = quotes
    view['structural_diagnostics'] = problems
    return view


def candidate_record_dependencies(view, binding):
    """Conservative structural dependencies; absence of a link proves nothing.

    Other defective records still require an explicit source-based unrelated
    judgment. Global/unknown-scope requirements cannot be waived that way.
    """
    required = set(binding.get('targets', []) + binding.get('operations', []) + binding.get('support_records', []))
    if not required <= view['records'].keys():
        raise ValueError('candidate support must reference existing source records')
    links = {key: _record_references(row) for key, row in view['records'].items()}
    targets = set(binding.get('targets', []))
    changed = True
    while changed:
        before = set(required)
        for key in view['groups']['operations']:
            row = view['records'][key]
            precedes = row.get('precedes', [])
            incoming_order = isinstance(precedes, list) and any(
                isinstance(r, dict) and isinstance(r.get('operation'), str) and r['operation'] in required for r in precedes)
            if links[key] & targets or incoming_order:
                required.add(key)
            if key in required:
                required.update(links[key])
        for key in view['groups']['requirements']:
            row = view['records'][key]
            # A valid composition container is local to its members, not global.
            if (row.get('scope_kind') not in {'targets', 'composite'} or not links[key] or links[key] & required):
                required.add(key)
            if key in required:
                required.update(links[key])
        changed = required != before
    return required


def _validate_shape(value, schema, path="response"):
    """Validate the small schema subset used here, also in ordinary JSON mode."""
    from prompt_mechanism_study.tsg.source_codec import PromptContractExtractionError as Error
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


def _target_operations(record, implementation=()):
    """Only explicit direct targets are distributive; boundaries never are."""
    return sorted(implementation if record['scope_kind']=='implementation' else
                  record['operations'] if record['scope_kind']=='targets' else ())


def compile_records(value, *, request, task, catalog, annotator_id, review_status):
    """Emit exactly the declared roles/targets and owner-bound guards, without LLM binding."""
    from prompt_mechanism_study.tsg.source_codec import (
        PromptContractExtractionError as Error,
        _source_citation,
        _inventory_concept,
        _role_context_citation,
        _include_recorded_impacts,
    )
    from prompt_mechanism_study.tsg.prompt_contract import OpenTaskContract, compile_task_context_contract
    from prompt_mechanism_study.tsg.prompt_tsg import catalog_sha256
    from prompt_mechanism_study.records import content_hash
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
        nodes.append(record["fact"])
    condition_ids = {}
    for record in (*value["operations"], *value["requirements"]):
        owned = [(c, 'conditions') for c in record.get("execution_conditions", record.get("conditions", []))]
        owned += [(c, 'context_for') for c in record.get('scope_conditions', [])]
        for condition, relation in owned:
            identity = json.dumps(condition, sort_keys=True)
            key = condition_ids.get(identity)
            if key is None:
                key = f"fact.{len(nodes)+1}"
                nodes.append(condition)
                condition_ids[identity] = key
            guards.append((key, aliases[record["record_id"]], condition, relation))
    # Compile the declared records directly. No legacy graph response, alias
    # merging, silent fact removal or inferred negative states intervene here.
    derived = deepcopy(catalog)
    template = request['fixed_template']
    for concept in template['concepts']:
        derived['semantics'][concept['concept_id']] = concept['node_type']
        derived['semantic_guidance'][concept['concept_id']] = concept['definition']
    facts = [dict(local_id=row['local_id'], semantic_id=row['concept_id'],
        node_type=derived['semantics'][row['concept_id']], attributes={},
        evidence_text=row['evidence_text'], occurrence=row['occurrence']) for row in template['nodes']]
    layers = {row['local_id']: 'generation' for row in template['nodes']}
    coverage = {key: dict(**row, facts=[]) for key,row in value['coverage'].items()}
    for index, row in enumerate(nodes, 1):
        concept = _inventory_concept(row, request)
        key, kind = concept['concept_id'], concept['node_type']
        if key in derived['semantics']:
            if derived['semantics'][key] != kind or derived['semantic_guidance'].get(key) != concept['definition']:
                raise Error('one concept ID must have one unchanged meaning')
        elif request['concept_policy'] != 'DEVELOPMENT_OPEN' or review_status != 'development_exposed':
            raise Error('new concept cannot expand a frozen study vocabulary')
        derived['semantics'][key] = kind
        derived['semantic_guidance'][key] = concept['definition']
        local = f'fact.{index}'
        facts.append(dict(local_id=local, node_type=kind, semantic_id=key, attributes={},
                          **_source_citation(row, request, local)))
        layers[local] = fact_layer(row, request)
        for unit in row['source_units']:
            coverage[unit]['facts'].append(local)
    inventory = dict(source_units=deepcopy(request['source_units']), coverage=coverage,
                     layers=layers, operation_roles=[])
    template_edges = [dict(source=row['source_node_local_id'], target=row['target_node_local_id'],
        **{key:row[key] for key in ('edge_type','evidence_text','occurrence')}) for row in template['edges']]
    contract = OpenTaskContract('3.0', task['task_id'], content_hash(task['prompt']),
        catalog_sha256(catalog), annotator_id, review_status, False, derived,
        tuple(facts), tuple(template_edges), (), (), tuple(value['unresolved_notes']), inventory)
    relations_by_source, roles, impacts = {}, [], {}
    def citation(row):
        return _source_citation(row, request, "relation")
    def refs(values, choices):
        if len(set(values)) != len(values) or not set(values) <= choices:
            raise Error("record reference is duplicate, missing or has the wrong type")
    def edge(source, kind, target, row):
        if (layers[source] == 'unresolved' or layers[source] != layers[target]
            or kind == 'precedes' and (source == target or layers[source] != 'runtime')):
            raise Error('record relation endpoints have incompatible layers or roles')
        relations_by_source.setdefault(source, []).append(dict(source=source, target=target,
            edge_type=kind, **citation(row)))
    for record in value["operations"]:
        key = aliases[record["record_id"]]
        for direction in ("inputs", "results"):
            for claim in record[direction]:
                refs([claim["subject"]], objects)
                role = dict(operation=key, subject=aliases[claim["subject"]],
                    role=claim.get("role", "result"), **citation(claim))
                roles.append({**{k: role[k] for k in ('operation', 'subject', 'role')},
                    **_role_context_citation(task['prompt'], role, contract.source_inventory)})
        for claim in record["precedes"]:
            refs([claim["operation"]], operations - {record["record_id"]})
            edge(key, 'precedes', aliases[claim['operation']], claim)
    modalities = {}
    for record in value["requirements"]:
        key = aliases[record["record_id"]]
        refs(record["operations"], operations)
        refs(record["subjects"], objects)
        modalities[key] = record["modality"]
        targets = [aliases[k] for k in _target_operations(record)]
        if record["scope_kind"] == "targets" and not targets and not record["subjects"]:
            raise Error("target scope must identify an operation or subject")
        for target in (*targets, *(aliases[k] for k in record['subjects'])):
            edge(key, 'constrains', target, record['fact'])
    for key, owner, condition, relation in guards:
        if relation == 'context_for':
            continue
        edge(key, 'conditions', owner, condition)
    # Locality is an explicit whole-source claim, reviewed with the other records.
    for key, coverage in value["coverage"].items():
        impact = value['unit_impacts'][key]
        impacts[key] = dict(effect=impact['effect'], operations=[aliases[k] for k in impact['operations']],
            complete=coverage["status"] != "unresolved" and impact['effect'] != 'unresolved', reason=impact['reason'])
    edges = [*contract.relations,
             *(row for key in sorted(relations_by_source) for row in relations_by_source[key])]
    def incidence(row):
        source, kind, target = ((row['operation'], 'produces', row['subject']) if row['role'] == 'result'
                               else (row['subject'], 'used_by', row['operation']))
        if not any((r['source'], r['edge_type'], r['target']) == (source, kind, target) for r in edges):
            edges.append(dict(source=source, target=target, edge_type=kind,
                evidence_text=row['evidence_text'], occurrence=row['occurrence']))
    for role in roles:
        incidence(role)
    contract = replace(contract, relations=tuple(edges), source_inventory={**contract.source_inventory,
        'operation_roles': roles, 'unit_impacts': impacts})
    contract = _include_recorded_impacts(contract)
    # Only fallback implementation scope targets the shared generation operation.
    edges = list(contract.relations)
    for key, owner, condition, relation in guards:
        if relation == 'context_for':
            edges.append(dict(source=key, target=owner, edge_type=relation,
                **citation(condition)))
    for record in value["requirements"]:
        if record["scope_kind"] == "implementation":
            implementation = [f['local_id'] for f in contract.facts if f['node_type']=='task_operation'
                              and contract.source_inventory['layers'][f['local_id']]=='generation']
            if len(implementation) != 1:
                raise Error('generation obligations require one source-supported implementation operation')
            edges.append(dict(source=aliases[record["record_id"]], target=_target_operations(record, implementation)[0],
                edge_type="constrains", **citation(record["fact"])))
    # Assemble the complete inventory before constructing the next contract.
    inventory = {**contract.source_inventory,
        "statement_kinds": modalities,
        "requirement_scopes": {aliases[key]: dict(kind=row['scope_kind'],
            boundaries=[aliases[k] for k in row['operations']], target_class=row['target_class'])
            for key, row in requirements.items() if row['scope_kind'] in {'task', 'each'}},
        "requirement_structures": {aliases[key]: dict(kind=row['structure']['kind'],
            members=[aliases[m] for m in row['structure']['members']]) for key, row in requirements.items()},
        "unit_impacts": {key: {**impact,
            **citation(value['unit_impacts'][key])}
            for key, impact in contract.source_inventory['unit_impacts'].items()}}
    owned_relations = {aliases[key]: [dict(source=aliases[r['source']], target=aliases[r['target']],
        edge_type=r['edge_type'], **citation(r))
        for r in row['relations']] for key, row in requirements.items() if row['relations']}
    if owned_relations:
        inventory['requirement_relations'] = owned_relations
    contract = replace(contract, relations=tuple(edges), source_inventory=inventory)
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
    from prompt_mechanism_study.records import content_hash
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
    from prompt_mechanism_study.tsg.source_codec import (
        _source_citation,
        _inventory_concept,
        PromptContractExtractionError,
    )
    errors, facts, citations = [], [], []
    records = _records(value)
    objects = {r['record_id'] for r in value['objects']}
    operations = {r['record_id'] for r in value['operations']}
    layers = {r['record_id']: fact_layer(r['fact'], request) for r in records}
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
                elif field in {'inputs', 'results'} and (
                    layers[row['record_id']] != 'runtime' or layers[ref] != 'runtime'
                ):
                    errors.append(f'{path}: participation requires runtime operation and object; generation inputs/results must be empty')
        if 'scope_kind' in row:
            # Concept validation below must not prevent independent scope/reference
            # diagnostics from reaching the single mechanical repair together.
            meaning = row['fact'].get('concept') or request['known_concepts'].get(
                row['fact'].get('concept_id'), {})
            layer = layers[row['record_id']]
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
    from prompt_mechanism_study.tsg.prompt_tsg import requirement_membership, PromptTSGError
    requirements = {r['record_id']: r for r in value['requirements']}
    try:
        requirement_membership([(k, r['structure']['kind'], r['structure']['members']) for k,r in requirements.items()], requirements)
        for key, row in requirements.items():
            if any(requirements[m]['modality'] != row['modality'] for m in row['structure']['members']):
                errors.append(key+': composite members must preserve the parent modality')
    except PromptTSGError as error:
        errors.append(str(error))
    runtime = {r['record_id'] for r in value['operations'] if fact_layer(r['fact'], request) == 'runtime'}
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
                or key[1] != 'precedes' or layers[row['record_id']] != 'runtime'
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
            _source_citation(fact, request, path)
        except PromptContractExtractionError as error:
            errors.append(str(error))
    owned = {unit for _, f in facts for unit in f['source_units']}
    for unit, coverage in value['coverage'].items():
        if coverage['status']=='represented' and unit not in owned:
            errors.append(unit+': represented requires a submitted task fact; fixed-template-only coverage is no_task_fact')
    return errors


def structural_readback(request, value):
    """Decode actual binding fields, never recover targets/guards from description text."""
    from prompt_mechanism_study.tsg.prompt_tsg import requirement_membership
    effective = _inherit_conditions(value)
    operations = {r['record_id']:r for r in value['operations']}
    implementation = {key for key,row in operations.items() if fact_layer(row['fact'], request)=='generation'}
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
        key=row['record_id']; targets=_target_operations(row,implementation)
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
            predicate_definition_claim=meaning(row['fact']),
            interpretation='The predicate names the action. Only the following fields assert its ground participants, guards and independent order; prose cannot supply another binding.',
            execution_guard=guards(row['execution_conditions']) or
                'NO DECLARED EXECUTION GUARD: operation presence does not assert execution on every path',
            non_gating_contexts=guards(row['scope_conditions']),
            inputs=[dict(subject=r['subject'],role=r['role'],source_quote=r['evidence_text']) for r in row['inputs']],
            results=[r['subject'] for r in row['results']],precedes=[r['operation'] for r in row['precedes']])
            for key,row in operations.items()},
        empty_field_rule='An empty conditions list supplies no guard. A guard present only in prose is NOT represented. Unresolved source coverage remains unresolved; readback never repairs it.')


def review_request(request, value, *, compiled_contract=None):
    check = dict(request_kind="source_only_record_review", source_prompt=request["source_prompt"],
        source_units=request["source_units"], records=value,
        operation_bindings=structural_readback(request, value)['operations'],
        operation_role_meanings=request['operation_role_meanings'],
        record_semantics=record_semantics(),
        instructions=(
            "Audit every record AND every source unit against the complete original source. The proposal "
            "is fallible. For each record check its full predicate, modality, every participant, target, "
            "guard and precedence. Availability does not require later use. An operation definition "
            "must not independently bundle concrete participants, guards or order "
            "that belong in its fields. operation_bindings is the program's actual field interpretation, "
            "not a second model summary. If an operation definition itself asserts a disputed binding, "
            "reject fact as well as that binding; removing its edge alone cannot narrow a frozen meaning. "
            "Necessary action/API distinctions must remain, and distinct occurrences must not be merged. An expected "
            "input domain does not prescribe rejection; branch-result guards do not gate whole operations. "
            "Check task-wide obligations retain task scope and conditional branches are preserved, "
            "including inside explicitly retained composites. Audit unit_impacts and scope_conditions. "
            "For every proposed input ask whether the full source permits this operation not using it; "
            "do not invent a business premise to rule out that alternative. Unsupported or ambiguous "
            "clauses need correction even when the rest of a record is sound. For every source unit list "
            "any missing meaning, including variable names and non-target behavior. Mark record status "
            "supported only when ALL claims in it are supported. Explain the erroneous or missing "
            "binding in reason, including conditions omitted from an empty list. "
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
        schema=_object(dict(records=_object({r["record_id"]: _object(dict(status=status, reason=dict(type="string"))) for r in _records(request["records"])}),
            source_units=_object({key: _object(dict(complete=dict(type="boolean"), reason=dict(type="string")))
                                  for key in request["source_units"]})))))


def _record_references(row):
    """Read known references, including from locally malformed development rows.

    Validation records defects separately; this never repairs or drops a record.
    """
    refs = set()
    for field, names in (('inputs', ('subject',)), ('results', ('subject',)),
                         ('precedes', ('operation',)), ('relations', ('source', 'target')),
                         ('operations', ()), ('subjects', ())):
        items = row.get(field, [])
        if isinstance(items, list):
            for item in items:
                values = [item.get(name) for name in names] if names and isinstance(item, dict) else [item] if not names else []
                refs.update(v for v in values if isinstance(v, str))
    structure = row.get('structure')
    if isinstance(structure, dict) and isinstance(structure.get('members'), list):
        refs.update(v for v in structure['members'] if isinstance(v, str))
    return refs


def revision_request(request, value, review):
    """One complete revision in the extraction schema; no field-patch protocol."""
    _validate_shape(review, review_response_format(review_request(request, value))['json_schema']['schema'])
    if (all(row['status'] == 'supported' for row in review['records'].values())
        and all(row['complete'] for row in review['source_units'].values())):
        return None
    return {**request, 'request_kind': 'source_only_record_revision',
        'original_records': value, 'source_review': review,
        'revision_instruction': (
            'Return a complete revised record set using the same schema. Check the original source '
            'and the review; preserve supported meanings and source identities, correcting the '
            'reported omissions and bindings together with their references. Do not remove a condition '
            'or operand merely to make a record pass. If meaning remains unresolved, record unresolved '
            'coverage and impacts explicitly; removing a record does not establish absence. '
            'The program checks structure and source coordinates, not semantic repair success.')}


def attempt_graph(task, *, catalog, evaluator, annotator_prompt, review_status, provider):
    """One extraction, optional mechanical repair, one review and optional complete revision."""
    from prompt_mechanism_study.tsg.source_codec import (
        contract_decision_request,
        PromptContractExtractionError,
    )
    from prompt_mechanism_study.tsg.prompt_contract import compile_task_context_contract
    from prompt_mechanism_study.tsg.task_input import prepare_task_input
    task = prepare_task_input(task)
    request = record_request(contract_decision_request(task, catalog))
    calls, raw, contract, graph = 0, None, None, None
    audit = dict(status="FAILED", provider_calls=0, response_text=None, response_sha256=None,
                 error_type=None, error_message=None, calls=[])
    def call(payload, response_format):
        nonlocal calls
        from prompt_mechanism_study.records import content_hash
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
        candidate_id = evaluator.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise ValueError("extractor configuration requires candidate_id before model calls")
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
        from prompt_mechanism_study.tsg.prompt_contract import task_context_contract_record
        from prompt_mechanism_study.tsg.prompt_tsg import prompt_tsg_record
        audit.update(pre_review_records=deepcopy(value), pre_review_structural_readback=structural_readback(request,value),
                     pre_review_contract=task_context_contract_record(contract),
                     pre_review_graph=prompt_tsg_record(graph))
        check = review_request(request, value, compiled_contract=contract)
        reviewed = json_object(call(check, review_response_format(check)))
        audit["review"] = reviewed
        revision = revision_request(request, value, reviewed)
        if revision is not None:
            value = json_object(call(revision, schema))
            audit['revision_request'], audit['revision_records'] = revision, deepcopy(value)
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
        audit.update(error_type=type(error).__name__, error_message=str(error), provider_calls=max(0,calls-1))
        return ExtractionAttempt(str(task["task_id"]), request, calls, raw, contract, graph,
            type(error).__name__, str(error), None, binding_annotation=audit)
    return ExtractionAttempt(str(task["task_id"]), request, calls, raw, contract, graph,
        None, None, None, binding_annotation=audit)

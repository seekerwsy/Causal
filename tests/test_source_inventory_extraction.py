"""Active extraction must retain incomplete source inventories without certifying them."""

import json
import pytest
from annotation_fixture import (
    indexed_annotation,
)
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.tsg.prompt_contract import open_concept_catalog
from prompt_mechanism_study.tsg.source_codec import (
    PromptContractExtractionError,
    apply_fixed_binding_response,
    contract_decision_request,
    contract_from_response,
    fixed_binding_request,
)
from prompt_mechanism_study.tsg.prompt_contract_extract import _attempt_task_contract
from prompt_mechanism_study.tsg.scope_assessment import fixed_scope_request
from prompt_mechanism_study.tsg.prompt_contract_qualification import (
    qualify_prompt_contract_extractor,
)
from prompt_mechanism_study.tsg.task_input import generation_template_facts, prepare_task_input


def _source_fixture(task_text="Run query A using input x. Return the selected rows. Produce readable code."):
    task = prepare_task_input(dict(task_id="synthetic-active-source-inventory", language="python",
        prompt=task_text))
    catalog = open_concept_catalog()
    catalog["concept_policy"] = "FROZEN"
    concepts = [
        ("sql.query", "task_operation", "Execute the source SQL query."),
        ("sql.input", "data_object", "The input value used by the SQL query."),
        ("sql.rows", "data_object", "The rows returned by the source query."),
        ("code.readable", "presentation_control", "The generated source code should be readable."),
        ("sql.binding", "safety_requirement", "Pass the SQL data value as a bound parameter."),
    ]
    for row in generation_template_facts(task)["concepts"]:
        catalog["semantics"][row["concept_id"]] = row["node_type"]
        catalog["semantic_guidance"][row["concept_id"]] = row["definition"]
    for key, role, definition in concepts:
        catalog["semantics"][key] = role
        catalog["semantic_guidance"][key] = definition
    catalog["queries"] = [dict(query_id="sql", required_semantics=["sql.query"],
        actionable_feature_id="sql.binding", forbidden_semantics=[], required_relations=[],
        realization_id="bind", cwe_id="source_semantics", task_family="source_semantics")]
    canonical = dict(concepts=[], nodes=[
        dict(local_id="q", concept_id="sql.query", evidence_text="query A", occurrence=1),
        dict(local_id="x", concept_id="sql.input", evidence_text="input x", occurrence=1),
        dict(local_id="rows", concept_id="sql.rows", evidence_text="the selected rows", occurrence=1),
        dict(local_id="readable", concept_id="code.readable", evidence_text="Produce readable code",
             occurrence=1, layer="generation")], edges=[
        dict(source_node_local_id="x", target_node_local_id="q", edge_type="used_by",
             evidence_text="Run query A using input x", occurrence=1),
        dict(source_node_local_id="q", target_node_local_id="rows", edge_type="produces",
             evidence_text="Run query A using input x. Return the selected rows.", occurrence=1)],
        unresolved_notes=[])
    request = contract_decision_request(task, catalog)
    wire = indexed_annotation(request, canonical)
    return task, catalog, canonical, request, wire


def _compile(task, catalog, wire):
    return contract_from_response(json.dumps(wire).encode(), task=task, catalog=catalog,
        annotator_id="source-authored-offline-fixture", review_status="development_exposed")


def test_repeated_operation_identity_is_distinct_from_wide_supporting_context():
    from copy import deepcopy
    task, catalog, canonical, request, _ = _source_fixture(
        'Run query A using input x. Return the selected rows. Produce readable code. Run query B using input x.')
    canonical['nodes'].append(dict(local_id='b', concept_id='sql.query', evidence_text='query B', occurrence=1))
    wire = indexed_annotation(request, canonical)
    good = _compile(task, catalog, wire)
    assert sum(f['semantic_id']=='sql.query' for f in good.facts) == 2
    operations = [n for n in wire['nodes'] if n['concept_id']=='sql.query']
    operations[0]['evidence_end_token'] = operations[1]['evidence_end_token']
    before = deepcopy(wire)
    with pytest.raises(PromptContractExtractionError, match='do not distinguish instances'):
        _compile(task, catalog, wire)
    assert wire == before


def test_positive_evidence_cannot_leak_to_unknown_or_conditional_scopes():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.scope_assessment import (
        apply_fixed_scope_response,
        fixed_scope_response_format,
    )
    task, catalog, bound, request, response, ids = _property_scope_fixture('character_sequence', conditional=True)
    schema = fixed_scope_response_format(request)['json_schema']['schema']['properties']['states']['properties']
    for key, scope in request['scopes'].items():
        if scope['concept_id'] != 'length':
            continue
        eligible = scope['subjects']==[ids['sql.input']] and scope['conditions']==[ids['condition.safe']]
        assert scope['admissible_positive_requirements'] == ([ids['length']] if eligible else [])
        assert ('explicitly_required' in schema[key]['properties']['expression']['enum']) == eligible
    key, scope = next((k,s) for k,s in request['scopes'].items()
                     if s['concept_id']=='length' and not s['subjects'] and not s['conditions'])
    bad = deepcopy(response)
    bad['states'][key].update(expression='explicitly_required', requirements=[ids['length']])
    result = apply_fixed_scope_response(json.dumps(bad).encode(), request=request,
        contract=bound, prompt=task['prompt'], catalog=catalog)
    row = next(s for s in result.feature_states if s['concept_id']=='length' and not s['subjects'] and not s['conditions'])
    assert row['state']=='unresolved' and row['rationale']=='No valid source-bound assessment.'
    assert any('positive expression lacks exact requirement-to-scope evidence' in n for n in result.unresolved_notes)
    # An admitted alternative kind defeats a definite type premise even if the
    # model still answers character_sequence; it cannot manufacture absence.
    bad = deepcopy(response)
    property_key = next(k for k,q in request['subject_property_questions'].items()
                        if q['subject']==ids['sql.input'] and not q['conditions'])
    bad['subject_properties'][property_key].update(alternative_kind_possible=True,
        alternative_kind_reason='A numeric input remains source-compatible.')
    result = apply_fixed_scope_response(json.dumps(bad).encode(), request=request,
        contract=bound, prompt=task['prompt'], catalog=catalog)
    row = next(s for s in result.feature_states if s['concept_id']=='length'
               and s['subjects']==[ids['sql.input']] and not s['conditions'])
    assert row['state']=='unresolved'
    assert result.facts == bound.facts and result.relations == bound.relations
    assert any('conflicts with a compatible alternative' in n for n in result.unresolved_notes)


@pytest.mark.parametrize('role,caller_required,caller_declared,expected', [
    ('resource', False, False, 'not_applicable'),
    ('input_unspecified', False, True, 'unresolved'),
    ('value_input', True, True, 'applicable'),
])
def test_declared_role_domains_preserve_unknown_and_separate_expression(role, caller_required, caller_declared, expected):
    from prompt_mechanism_study.tsg.scope_assessment import (
        fixed_scope_response_format,
        apply_fixed_scope_response,
    )
    from prompt_mechanism_study.tsg.prompt_tsg import catalog_from_record
    task, catalog, canonical, _, _ = _source_fixture()
    catalog.update(feature_scope_domains={'sql.binding': 'subjects'},
        caller_supplied_concepts=['sql.input'] if caller_declared else [],
        feature_role_domains={'sql.binding': dict(applicable_roles=['value_input'],
            inapplicable_roles=['identifier_input', 'resource', 'destination'], caller_supplied_only=caller_required)})
    catalog_from_record(catalog)
    wire = indexed_annotation(contract_decision_request(task, catalog), canonical)
    facts, binding_request, response = _bindings(task, catalog, canonical, wire)
    next(r for r in response['operation_roles'] if r['subject'] == 'fact.2')['role'] = role
    bound = apply_fixed_binding_response(json.dumps(response).encode(), request=binding_request,
        contract=facts, prompt=task['prompt'], catalog=catalog)
    request = fixed_scope_request(bound, prompt=task['prompt'], catalog=catalog)
    key, scope = next((k, s) for k, s in request['scopes'].items() if s['subjects'] == ['fact.2'])
    assert scope['role_domain_check']['applicability'] == expected
    schema = fixed_scope_response_format(request)['json_schema']['schema']['properties']['states']['properties']
    assert set(schema[key]['properties']) == {'expression', 'requirements', 'applicability', 'applicability_rationale'}
    answers = {k: dict(expression='not_expressed', requirements=[],
        applicability=expected, applicability_rationale='Source establishes the SQL operation and this role.')
        for k in request['scopes']}
    def apply(rows):
        return apply_fixed_scope_response(json.dumps(dict(states=rows, unresolved_notes=[])).encode(),
            request=request, contract=bound, prompt=task['prompt'], catalog=catalog)
    result = apply(answers)
    actual = next(r for r in result.feature_states if r['subjects'] == ['fact.2'])['state']
    assert actual == ('absent' if expected == 'applicable' else expected)
    # Even a definite value-input role cannot certify an unstated SQL context
    # or a required caller origin. Concept membership cannot override this.
    answers[key]['applicability'] = 'unresolved'
    answers[key]['applicability_rationale'] = 'The source leaves the required operation context or caller origin unspecified.'
    assert next(r for r in apply(answers).feature_states if r['subjects'] == ['fact.2'])['state'] == 'unresolved'
    answers[key]['applicability'] = expected
    answers[key]['expression'] = 'unresolved'
    assert next(r for r in apply(answers).feature_states if r['subjects'] == ['fact.2'])['state'] == 'unresolved'
    answers[key]['expression'] = 'not_expressed'
    answers[key]['applicability'] = 'applicable' if expected != 'applicable' else 'invalid'
    contradiction = apply(answers)
    assert next(r for r in contradiction.feature_states if r['subjects'] == ['fact.2'])['state'] == 'unresolved'
    assert any('unresolved_fixed_scope' in note for note in contradiction.unresolved_notes)
    answers.pop(key)
    assert next(r for r in apply(answers).feature_states if r['subjects'] == ['fact.2'])['state'] == 'unresolved'
    assert result.facts == bound.facts and result.relations == bound.relations


def _bindings(task, catalog, canonical, wire):
    facts = _compile(task, catalog, wire)
    request = fixed_binding_request(facts, prompt=task["prompt"], catalog=catalog)
    return facts, request, indexed_annotation(request, canonical)


def _property_scope_fixture(kind, *, conditional=False):
    from copy import deepcopy
    from prompt_mechanism_study.tsg.prompt_tsg import catalog_from_record
    prefix = {'character_sequence': 'The input x is text. ',
              'other_value': 'The input x is an integer. ', 'unspecified': ''}[kind]
    conditional_text = 'When mode is safe, require input x to be at most 10 characters.'
    task, catalog, canonical, _, _ = _source_fixture(prefix +
        'Run query A using input x and a database. Return the selected rows. Produce readable code.'
        + (' ' + conditional_text if conditional else ''))
    for name, node_type, definition in [
        ('database', 'data_object', 'The explicitly named database facility.'),
        ('length', 'safety_requirement', 'Require the input value to be at most 10 characters long.'),
    ]:
        catalog['semantics'][name] = node_type
        catalog['semantic_guidance'][name] = definition
    query = deepcopy(catalog['queries'][0])
    query.update(query_id='length', actionable_feature_id='length', realization_id='length')
    catalog['queries'].append(query)
    catalog.update(feature_scope_domains={'sql.binding':'subjects', 'length':'subjects'},
        feature_subject_properties={'length':'character_sequence'}, caller_supplied_concepts=[],
        feature_role_domains={'sql.binding':dict(applicable_roles=['value_input'],
            inapplicable_roles=['resource'], caller_supplied_only=False)})
    catalog_from_record(catalog)
    for edge in canonical['edges']:
        edge['evidence_text'] = edge['evidence_text'].replace(
            'Run query A using input x.', 'Run query A using input x and a database.')
    canonical['nodes'].append(dict(local_id='db', concept_id='database', evidence_text='a database', occurrence=1))
    canonical['edges'].append(dict(source_node_local_id='db', target_node_local_id='q',
        edge_type='used_by', evidence_text='Run query A using input x and a database', occurrence=1))
    if conditional:
        catalog['semantics']['condition.safe'] = 'condition'
        catalog['semantic_guidance']['condition.safe'] = 'Processing mode is safe.'
        canonical['nodes'].extend([
            dict(local_id='length', concept_id='length', evidence_text=conditional_text, occurrence=1),
            dict(local_id='safe', concept_id='condition.safe', evidence_text='When mode is safe', occurrence=1),
        ])
        for source, edge_type, target in [('length','constrains','q'), ('length','constrains','x'), ('safe','conditions','length')]:
            canonical['edges'].append(dict(source_node_local_id=source, target_node_local_id=target,
                edge_type=edge_type, evidence_text=conditional_text, occurrence=1))
    wire = indexed_annotation(contract_decision_request(task, catalog), canonical)
    facts, binding_request, binding = _bindings(task, catalog, canonical, wire)
    ids = {f['semantic_id']: f['local_id'] for f in facts.facts}
    for row in binding['operation_roles']:
        if row['role'] != 'result':
            row['role'] = 'resource' if row['subject'] == ids['database'] else 'value_input'
    bound = apply_fixed_binding_response(json.dumps(binding).encode(), request=binding_request,
        contract=facts, prompt=task['prompt'], catalog=catalog)
    request = fixed_scope_request(bound, prompt=task['prompt'], catalog=catalog)
    states = {}
    for key, scope in request['scopes'].items():
        states[key] = dict(expression='not_expressed', requirements=[])
        if 'subject_property' not in scope:
            states[key].update(applicability=scope['role_domain_check']['applicability'],
                applicability_rationale='This authored fixture explicitly requires an SQL query with the bound roles.')
        if conditional and scope['concept_id']=='length' and ids['sql.input'] in scope['subjects']:
            exact = scope['subjects']==[ids['sql.input']] and scope['conditions']==[ids['condition.safe']]
            states[key].update(expression='explicitly_required' if exact else 'unresolved',
                requirements=[ids['length']] if exact else [])
    answers = {}
    for key, question in request['subject_property_questions'].items():
        database = question['subject'] == ids['database']
        conditional_evidence = conditional and question['conditions']==[ids['condition.safe']] and not database
        answers[key] = dict(kind='facility' if database else 'character_sequence' if conditional_evidence else kind,
            alternative_kind_possible=not database and not conditional_evidence and kind=='unspecified',
            alternative_kind_reason='Several input types remain possible.' if not database and not conditional_evidence and kind=='unspecified' else 'The quoted source establishes this logical kind.',
            evidence_text='a database' if database else conditional_text if conditional_evidence else prefix.strip() or 'input x', occurrence=1,
            reason='Explicit database facility.' if database else
                'The exact conditional obligation explicitly imposes a character-count domain.' if conditional_evidence else
                'The source explicitly states this value type.' if prefix else 'No value type is specified.')
    return task, catalog, bound, request, dict(states=states, subject_properties=answers, unresolved_notes=[]), ids


def test_one_source_sentence_retains_two_atomic_requirements_and_their_shared_condition():
    sentence = ("Run query A using input x; for external requests, bind input x as an SQL parameter "
                "and require input x to be at most 10 characters.")
    task = prepare_task_input(dict(task_id="synthetic-atomic-source-requirements",
                                   language="python", prompt=sentence))
    meanings = [
        ("q", "sql.query", "task_operation", "Execute the source SQL query.", "query A"),
        ("x", "sql.input", "data_object", "The input value used by the SQL query.", "input x"),
        ("external", "request.external", "condition", "The request is external.", "for external requests"),
        ("binding", "sql.binding", "safety_requirement", "Bind the SQL input value as a parameter.", sentence),
        ("length", "input.length", "safety_requirement", "Require the input value to be at most 10 characters.", sentence),
    ]
    canonical = dict(
        concepts=[dict(concept_id=concept, node_type=kind, definition=definition)
                  for _, concept, kind, definition, _ in meanings],
        nodes=[dict(local_id=key, concept_id=concept, evidence_text=quote, occurrence=1)
               for key, concept, _, _, quote in meanings],
        edges=[dict(source_node_local_id=source, target_node_local_id=target,
                    edge_type=relation, evidence_text=sentence, occurrence=1)
               for source, relation, target in [
                   ("x", "used_by", "q"),
                   ("binding", "constrains", "q"), ("binding", "constrains", "x"),
                   ("length", "constrains", "q"), ("length", "constrains", "x"),
                   ("external", "conditions", "binding"), ("external", "conditions", "length"),
               ]],
        unresolved_notes=[])
    calls = []

    def provider(request, _config, _prompt):
        calls.append(request["request_kind"])
        return json.dumps(indexed_annotation(request, canonical)).encode()

    attempt = _attempt_task_contract(task, catalog=open_concept_catalog(), evaluator=dict(candidate_id="offline"),
        annotator_prompt="Source-authored atomic requirement fixture.",
        review_status="development_exposed", provider=provider)
    assert calls == ["source_only_atomic_records", "source_only_record_review"]
    assert attempt.error_type is None
    assert attempt.contract is not None and attempt.graph is not None
    requirements = {fact["local_id"]: fact for fact in attempt.contract.facts
                    if fact["node_type"] == "safety_requirement"}
    # Shared evidence is allowed: distinct atomic meanings must survive instance deduplication.
    assert set(requirements) == {"fact.3", "fact.4"}
    assert {fact["evidence_text"] for fact in requirements.values()} == {sentence}
    assert attempt.contract.catalog["semantic_guidance"][requirements["fact.4"]["semantic_id"]] == (
        "Require the input value to be at most 10 characters.")
    relations = {(edge["source"], edge["edge_type"], edge["target"]) for edge in attempt.contract.relations}
    for requirement in requirements:
        assert (requirement, "constrains", "fact.2") in relations
        assert (requirement, "constrains", "fact.1") in relations
        assert ("fact.5", "conditions", requirement) in relations
    assert ("fact.5", "conditions", "fact.2") not in relations
    assert {attempt.contract.catalog['semantic_guidance'][node.semantic_id]
            for node in attempt.graph.nodes if node.node_type == "safety_requirement"} == {
        "Bind the SQL input value as a parameter.", "Require the input value to be at most 10 characters."}
    # The same maintained boundary test also checks local correction and input
    # assumptions; no extra incident-specific test family is added.
    from copy import deepcopy
    from annotation_fixture import record_annotation
    from prompt_mechanism_study.tsg.source_records import (
        record_request,
        compile_records,
        review_request,
        repair_request,
        apply_record_patch,
        record_diagnostics,
    )
    catalog = open_concept_catalog()
    request = record_request(contract_decision_request(task, catalog))
    records = record_annotation(request, canonical)
    generation_participant = deepcopy(records)
    generation_participant['operations'][0]['fact']['layer'] = 'generation'
    assert any('participation requires runtime operation and object' in error
               for error in record_diagnostics(generation_participant, request))
    invalid = deepcopy(records)
    invalid['requirements'][0].update(scope_kind='task', operations=[], subjects=[])
    invalid['requirements'][0]['fact'].update(layer='generation')
    diagnostic_request = deepcopy(request)
    concept = invalid['requirements'][0]['fact']['concept']
    diagnostic_request['known_concepts'][concept['concept_id']] = deepcopy(concept)
    concept['definition'] = 'Redefined known meaning.'
    diagnostics = record_diagnostics(invalid, diagnostic_request)
    assert any('cannot change a supplied meaning' in problem for problem in diagnostics)
    assert any('task/each scope is runtime' in problem for problem in diagnostics)
    check = review_request(request, records)
    assert check['operation_role_meanings'] == request['operation_role_meanings']
    assert 'NO per-operation obligation' in check['record_semantics']['task_scope']
    from prompt_mechanism_study.tsg.source_records import (
        structural_readback,
        review_response_format,
    )
    assert structural_readback(request,records)['operations']['q']['execution_guard'].startswith('NO DECLARED EXECUTION GUARD:')
    operation_reading = structural_readback(request, records)['operations']['q']
    assert operation_reading['predicate_definition_claim'] == 'Execute the source SQL query.'
    assert check['operation_bindings']['q'] == operation_reading
    readback=structural_readback(request,records)['requirements']['binding']
    assert readback['direct_operation_bindings'][0]['target_operation']=='q'
    assert readback['requirement_guards'][0]['predicate']=='The request is external.'
    missing_guard=deepcopy(records)
    missing_guard['requirements'][0]['conditions']=[]
    # Correct prose is deliberately retained: it cannot restore structural data.
    missing_guard['requirements'][0]['fact']['concept']['definition']+=' For external requests only.'
    missing_check=review_request(request,missing_guard)
    decoded=structural_readback(request,missing_guard)['requirements']['binding']
    assert decoded['requirement_guards'].startswith('UNCONDITIONAL')
    assert decoded['direct_operation_bindings'][0]['structural_guard'].startswith('UNCONDITIONAL')
    addresses=review_response_format(missing_check)['json_schema']['schema']['properties']['records']['properties']['binding']['properties']['rejected_claims']['items']['enum']
    assert 'conditions' in addresses and 'conditions.0' not in addresses
    guard_review=record_annotation(missing_check,canonical)
    guard_review['records']['binding'].update(status='unsupported',rejected_claims=['conditions'])
    guard_plan=repair_request(request,missing_guard,guard_review)
    guard_patch=dict(objects=[],operations=[],requirements=[deepcopy(missing_guard['requirements'][0])],
        coverage={k:records['coverage'][k] for k in guard_plan['affected_source_units']},
        unit_impacts={k:records['unit_impacts'][k] for k in guard_plan['affected_source_units']},
        delete_record_ids=[],unresolved_notes=[])
    guard_patch['requirements'][0]['fact']['concept']['definition']+=' Same prose, still no guard.'
    with pytest.raises(PromptContractExtractionError,match='repeats rejected claim'):
        apply_record_patch(missing_guard,guard_patch,request=guard_plan,original_request=request)
    guard_patch['requirements'][0]['conditions']=deepcopy(records['requirements'][0]['conditions'])
    assert apply_record_patch(missing_guard,guard_patch,request=guard_plan,original_request=request)['requirements'][0]['conditions']
    unit=next(iter(guard_patch['unit_impacts']))
    guard_patch['unit_impacts'][unit]['reason']='Unrequested narrowing of source influence.'
    held=apply_record_patch(missing_guard,guard_patch,request=guard_plan,original_request=request)
    assert held['unit_impacts']==missing_guard['unit_impacts']
    authorized=deepcopy(guard_plan)
    authorized['source_review']['source_units'][unit]['complete']=False
    changed=apply_record_patch(missing_guard,guard_patch,request=authorized,original_request=request)
    assert changed['unit_impacts'][unit]==guard_patch['unit_impacts'][unit]
    reviewed = record_annotation(check, canonical)
    reviewed['records']['q'].update(status='unsupported', rejected_claims=['inputs.0'])
    repair = repair_request(request, records, reviewed)
    patch = dict(objects=[], operations=[deepcopy(records['operations'][0])], requirements=[],
        coverage={k: records['coverage'][k] for k in repair['affected_source_units']},
        unit_impacts={k: records['unit_impacts'][k] for k in repair['affected_source_units']},
        unresolved_notes=[], delete_record_ids=[])
    patch['operations'][0]['precedes'] = []
    patch['operations'][0]['fact']['concept']['definition'] += ' Changed wording.'
    patch['operations'][0]['inputs'][0]['evidence_text'] = sentence
    with pytest.raises(PromptContractExtractionError, match='repeats rejected claim'):
        apply_record_patch(records, patch, request=repair, original_request=request)
    patch['operations'][0]['inputs'] = []
    merged = apply_record_patch(records, patch, request=repair, original_request=request)
    assert merged['objects'] == records['objects'] and merged['requirements'] == records['requirements']
    # Freeze a normalized action predicate, then vary its bindings without
    # reinterpreting that immutable predicate or the research requirements.
    from prompt_mechanism_study.tsg.prompt_contract import freeze_open_concepts, catalog_sha256
    base_contract = compile_records(records, request=request, task=task, catalog=catalog,
        annotator_id='authored-normalized-operation', review_status='development_exposed')
    frozen = freeze_open_concepts((base_contract,), normalization_map={},
        definitions=base_contract.catalog['semantic_guidance'], queries=[])
    frozen_identity = catalog_sha256(frozen)
    frozen_request = record_request(contract_decision_request(task, frozen))
    by_meaning = {(frozen['semantics'][k], d): k for k,d in frozen['semantic_guidance'].items()}
    def frozen_facts(value):
        if isinstance(value, list):
            return [frozen_facts(v) for v in value]
        if not isinstance(value, dict):
            return value
        row = {k:frozen_facts(v) for k,v in value.items() if k != 'concept'}
        if 'concept' in value:
            c = value['concept']
            row['concept_id'] = by_meaning[c['node_type'], c['definition']]
        return row
    frozen_records = frozen_facts(records)
    altered = deepcopy(frozen_records)
    altered['operations'][0]['inputs'] = []
    altered['operations'][0]['execution_conditions'] = deepcopy(altered['requirements'][0]['conditions'])
    frozen_contracts = [compile_records(v, request=frozen_request, task=task, catalog=frozen,
        annotator_id='authored-binding-control', review_status='development_exposed') for v in (frozen_records, altered)]
    readings = [structural_readback(frozen_request,v)['operations']['q'] for v in (frozen_records,altered)]
    assert readings[0]['predicate_definition_claim'] == readings[1]['predicate_definition_claim']
    assert readings[0]['inputs'] and not readings[1]['inputs']
    assert readings[0]['execution_guard'] != readings[1]['execution_guard']
    assert sum(e['edge_type']=='used_by' for e in frozen_contracts[0].relations) == 1
    assert not any(e['edge_type']=='used_by' for e in frozen_contracts[1].relations)
    assert catalog_sha256(frozen) == frozen_identity
    assert ([f for f in frozen_contracts[0].facts if f['node_type']=='safety_requirement'] ==
            [f for f in frozen_contracts[1].facts if f['node_type']=='safety_requirement'])
    # Preserve composition and inherited guards at construction; only conjunction
    # entails its declared leaves. This is a synthetic logic boundary, not accuracy.
    from prompt_mechanism_study.tsg.prompt_contract import compile_task_context_contract
    from prompt_mechanism_study.tsg.prompt_tsg import (
        graph_requirement_membership,
        prompt_tsg_record,
        prompt_tsg_from_record,
    )
    from prompt_mechanism_study.tsg.candidate_construction import (
        candidate_request,
        _occurrence,
        _canonical_concepts,
        _query,
        choose_candidate_scope,
    )
    composite = deepcopy(records)
    parent = deepcopy(composite['requirements'][0])
    parent.update(record_id='both', structure=dict(kind='and', members=['binding','length']),
        scope_kind='composite',operations=[],subjects=[])
    parent['fact']['concept'].update(concept_id='both', definition='Require both binding and the length limit.')
    composite['requirements'].append(parent)
    for leaf in composite['requirements'][:2]:
        leaf['conditions'] = []
    def compile_composite(value):
        return compile_records(value, request=request, task=task, catalog=catalog,
            annotator_id='offline', review_status='development_exposed')
    comp = compile_composite(composite)
    decoded=structural_readback(request,composite)['requirements']
    assert decoded['binding']['requirement_guards']==decoded['both']['requirement_guards']
    executed=deepcopy(missing_guard)
    executed['operations'][0]['execution_conditions']=deepcopy(records['requirements'][0]['conditions'])
    binding=structural_readback(request,executed)['requirements']['binding']
    assert binding['direct_operation_bindings'][0]['structural_guard'][0]['predicate']=='The request is external.'
    graph = compile_task_context_contract(comp, prompt=task['prompt'], catalog=catalog)
    asserted, atoms = graph_requirement_membership(graph)
    declared={key for key,_,_ in graph.requirement_structures}
    asserted,atoms=asserted&declared,atoms&declared
    assert len(asserted)==3 and len(atoms)==2
    assert prompt_tsg_from_record(prompt_tsg_record(graph)) == graph
    guard = next(n.node_id for n in graph.nodes if n.node_type=='condition')
    assert {e.target_id for e in graph.edges if e.edge_type=='conditions' and e.source_id==guard} == asserted
    candidate = candidate_request([task],[comp],input_catalog=catalog)
    source = candidate['sources'][0]
    aliases, _, _ = _canonical_concepts(candidate)
    op = next(n['node_id'] for n in source['nodes'] if n['node_type']=='task_operation' and n['evidence']=='query A')
    subject_meaning=next(f['semantic_id'] for f in comp.facts if f['local_id']=='fact.1')
    subject = next(n['node_id'] for n in source['nodes'] if n['concept_id']==subject_meaning)
    occurrence = dict(task_id=task['task_id'], requirement_node_ids=[sorted(atoms)[0]],
        scope=dict(operation_node_id=op,subject_node_ids=[subject],condition_node_ids=[guard]))
    selector, _ = _occurrence(source,occurrence,aliases)
    assert selector['policy_condition_semantic_ids'] and selector['condition_semantic_ids'] == []
    # Explicit non-gating context can survive removing the target requirement.
    composite['operations'][0]['scope_conditions'] = deepcopy(parent['conditions'])
    comp = compile_composite(composite)
    candidate = candidate_request([task],[comp],input_catalog=catalog)
    source = candidate['sources'][0]
    selector, _ = _occurrence(source,occurrence,aliases)
    assert selector['execution_condition_semantic_ids'] == []
    assert not any(edge[1]=='context_for' for edge in _query(selector,'test-feature')['required_relations'])
    graph = compile_task_context_contract(comp,prompt=task['prompt'],catalog=catalog)
    # Use source meanings for this low-level selector test (normalization is separate).
    by_id={n.node_id:n.semantic_id for n in graph.nodes}
    selector.update(operation_semantic_id=by_id[op],subject_semantic_ids=[by_id[subject]],
                    policy_condition_semantic_ids=[by_id[guard]])
    assert choose_candidate_scope(graph,selector) is not None
    from dataclasses import replace
    removed = replace(graph,nodes=tuple(n for n in graph.nodes if n.node_id not in asserted),
        edges=tuple(e for e in graph.edges if not {e.source_id,e.target_id}&asserted),requirement_structures=())
    assert choose_candidate_scope(removed,selector) == choose_candidate_scope(graph,selector)
    for kind in ('or','not'):
        variant = deepcopy(composite)
        if kind=='or':
            variant['requirements'][-1]['structure']['kind']='or'
        else:
            negated=deepcopy(parent)
            negated.update(record_id='negated',structure=dict(kind='not',members=['both']))
            negated['fact']['concept'].update(concept_id='negated',definition='Negate the conjunction.')
            variant['requirements'].append(negated)
        comp=compile_composite(variant)
        graph=compile_task_context_contract(comp,prompt=task['prompt'],catalog=catalog)
        assert not graph_requirement_membership(graph)[1] & {key for key,_,_ in graph.requirement_structures}
        assert structural_readback(request,variant)['requirements']['binding']['asserted_as_standalone'] is False
        candidate=candidate_request([task],[comp],input_catalog=catalog)
        with pytest.raises(ValueError,match='existing source requirement'):
            _occurrence(candidate['sources'][0],occurrence,aliases)
        # Scope preparation must withhold the referenced feature, not claim absence.
        from prompt_mechanism_study.tsg.prompt_tsg import catalog_sha256
        fixed=deepcopy(comp.catalog)
        feature=next(f['semantic_id'] for f in comp.facts if f['local_id']=='fact.3')
        fixed['queries']=[dict(query_id='binding',actionable_feature_id=feature,required_semantics=[by_id[op]],
            forbidden_semantics=[],required_relations=[],realization_id='binding',cwe_id='source_semantics',task_family='source_semantics')]
        comp=replace(comp,catalog=fixed,input_catalog_sha256=catalog_sha256(fixed))
        scope_request=fixed_scope_request(comp,prompt=task['prompt'],catalog=fixed)
        assert scope_request['withheld_scopes'] and not scope_request['scopes']
    # A task-wide requirement is mechanically scoped and an assumed domain is
    # retained as context without becoming an editable requirement candidate.
    records = deepcopy(records)
    # Provisional category labels cannot collapse distinct complete predicates.
    for record in records['requirements']:
        record['fact']['concept']['concept_id'] = 'requirement.provisional'
    records['requirements'][0].update(scope_kind='task', operations=[], subjects=[])
    assumed = records['requirements'][1]
    assumed.update(modality='assumption')
    assumed['fact']['concept'].update(concept_id='input.expected_length', node_type='constraint',
        definition='The input is assumed to have at most 10 characters; this does not prescribe rejection.')
    compiled = compile_records(records, request=request, task=task, catalog=catalog,
        annotator_id='offline', review_status='development_exposed')
    assert compiled.source_inventory['statement_kinds']['fact.4'] == 'assumption'
    assert len({f['semantic_id'] for f in compiled.facts if f['local_id'] in {'fact.3','fact.4'}}) == 2
    links = {(r['source'],r['edge_type'],r['target']) for r in compiled.relations}
    assert ('fact.3','constrains','fact.2') not in links
    assert compiled.source_inventory['requirement_scopes']['fact.3']['kind']=='task'
    retained_graph=compile_task_context_contract(compiled,prompt=task['prompt'],catalog=catalog)
    assert prompt_tsg_from_record(prompt_tsg_record(retained_graph))==retained_graph
    assert retained_graph.requirement_scopes[0][1]=='task'
    # An explicit universal rule survives without claiming a complete instance list.
    universal=deepcopy(records)
    universal['requirements'][0].update(scope_kind='each',target_class='database queries')
    universal_contract=compile_composite(universal)
    universal_graph=compile_task_context_contract(universal_contract,prompt=task['prompt'],catalog=catalog)
    assert universal_graph.requirement_scopes[0][1:] == ('each',retained_graph.requirement_scopes[0][2],'database queries')
    assert prompt_tsg_from_record(prompt_tsg_record(universal_graph))==universal_graph
    assert not structural_readback(request,universal)['requirements']['binding']['direct_operation_bindings']
    illegal=deepcopy(universal)
    illegal['requirements'][0]['operations']=['q','q']
    with pytest.raises(PromptContractExtractionError,match='zero/one boundary'):
        compile_composite(illegal)
    assert ('fact.5','conditions','fact.3') in links and ('fact.5','conditions','fact.2') not in links
    from prompt_mechanism_study.tsg.candidate_construction import candidate_request, _occurrence
    source = candidate_request([task], [compiled], input_catalog=catalog)['sources'][0]
    assumption = next(n for n in source['nodes'] if n.get('statement_kind') == 'assumption')
    with pytest.raises(ValueError, match='existing source requirement'):
        _occurrence(source, dict(task_id=task['task_id'], requirement_node_ids=[assumption['node_id']], scope={}), {})


def test_requirement_owned_order_preserves_targets_guards_and_state_blind_scope():
    from copy import deepcopy
    from dataclasses import replace
    from annotation_fixture import record_annotation
    from prompt_mechanism_study.tsg.source_records import (
        record_request,
        compile_records,
        structural_readback,
        review_request,
        repair_request,
        apply_record_patch,
    )
    from prompt_mechanism_study.tsg.prompt_contract import compile_task_context_contract
    from prompt_mechanism_study.tsg.prompt_tsg import (
        graph_requirement_membership,
        requirement_binding,
        requirement_matches_policy,
        requirement_policy_relations,
        prompt_tsg_record,
        prompt_tsg_from_record,
        query_context,
    )
    from prompt_mechanism_study.tsg.candidate_construction import (
        candidate_request,
        _occurrence,
        _query,
        choose_candidate_scope,
    )
    sentence = 'When ready, prepare before publish and enable strict mode during preparation.'
    task = prepare_task_input(dict(task_id='authored-owned-order-boundary', language='python', prompt=sentence))
    catalog = open_concept_catalog()
    meanings = [
        ('prepare', 'task_operation', 'The preparation operation.', 'prepare'),
        ('publish', 'task_operation', 'The publication operation.', 'publish'),
        ('ready', 'condition', 'The task is ready.', 'When ready'),
        ('order', 'safety_requirement', 'Prepare before publication.', 'prepare before publish'),
        ('strict', 'safety_requirement', 'Enable strict mode during preparation.', 'enable strict mode during preparation'),
    ]
    canonical = dict(concepts=[dict(concept_id=k, node_type=t, definition=d) for k,t,d,_ in meanings],
        nodes=[dict(local_id=k, concept_id=k, evidence_text=q, occurrence=1) for k,_,_,q in meanings],
        edges=[dict(source_node_local_id=a, edge_type=r, target_node_local_id=b,
                    evidence_text=sentence, occurrence=1) for a,r,b in [
            ('order','constrains','prepare'), ('strict','constrains','prepare'),
            ('ready','conditions','order'), ('ready','conditions','strict')]], unresolved_notes=[])
    request = record_request(contract_decision_request(task, catalog))
    records = record_annotation(request, canonical)
    owner = records['requirements'][0]
    owner['relations'] = [dict(source='prepare', edge_type='precedes', target='publish',
        evidence_source_unit=owner['fact']['evidence_source_unit'], evidence_text=owner['fact']['evidence_text'])]
    unit = owner['fact']['evidence_source_unit']
    records['unit_impacts'][unit].update(effect='local', operations=['prepare'],
        reason='Authored declaration omits the owned relation destination.')

    def compile_value(value):
        contract = compile_records(value, request=request, task=task, catalog=catalog,
            annotator_id='authored-offline-boundary', review_status='development_exposed')
        return contract, compile_task_context_contract(contract, prompt=task['prompt'], catalog=catalog)

    contract, graph = compile_value(records)
    # Review the compiler's actual dependency lower bound, not just the narrower
    # declaration. This does not certify that the source has no other influence.
    check = review_request(request, records, compiled_contract=contract)
    assert check['records']['unit_impacts'][unit]['operations'] == ['prepare']
    assert check['effective_unit_impacts'] == contract.source_inventory['unit_impacts']
    assert {check['compiled_operations'][key]['definition']
            for key in check['effective_unit_impacts'][unit]['operations']} == {
        'The preparation operation.', 'The publication operation.'}
    assert {check['compiled_operations'][key]['evidence_text']
            for key in check['effective_unit_impacts'][unit]['operations']} == {'prepare', 'publish'}
    assert all(check['compiled_operations'][key]['layer'] == 'runtime'
               for key in check['effective_unit_impacts'][unit]['operations'])
    assert 'effective_unit_impacts' not in review_request(request, records)
    check['effective_unit_impacts'][unit]['operations'].clear()
    assert len(contract.source_inventory['unit_impacts'][unit]['operations']) == 2
    owned, prepare, relation, publish = graph.requirement_relations[0]
    guard = next(n.node_id for n in graph.nodes if n.node_type == 'condition')
    links = {(e.source_id,e.edge_type,e.target_id) for e in graph.edges}
    assert relation == 'precedes' and (owned,'constrains',prepare) in links
    assert (owned,'constrains',publish) not in links and not any(r == 'precedes' for _,r,_ in links)
    assert (guard,'conditions',owned) in links and (guard,'conditions',prepare) not in links
    assert requirement_policy_relations(graph, owned) == ((prepare,'precedes',publish),)
    assert prompt_tsg_from_record(prompt_tsg_record(graph)) == graph
    readback = structural_readback(request, records)['requirements']['order']
    assert [r['target_operation'] for r in readback['direct_operation_bindings']] == ['prepare']
    assert readback['owned_relations'][0]['target'] == 'publish'
    # Retraction must close both semantic references and source influence;
    # the supported sibling requirement survives without becoming unguarded.
    retract = deepcopy(records)
    retract['unit_impacts'][unit]['operations'] = ['prepare', 'publish']
    review = record_annotation(review_request(request, retract), canonical)
    review['records']['publish'].update(status='unresolved', rejected_claims=['fact'])
    repair = repair_request(request, retract, review)
    patch = dict(objects=[], operations=[], requirements=[], delete_record_ids=['publish'],
        coverage={u:deepcopy(retract['coverage'][u]) for u in repair['affected_source_units']},
        unit_impacts={u:deepcopy(retract['unit_impacts'][u]) for u in repair['affected_source_units']},
        unresolved_notes=[])
    with pytest.raises(PromptContractExtractionError, match='dangling record references'):
        apply_record_patch(retract, patch, request=repair, original_request=request)
    patch['delete_record_ids'].append('order')
    withdrawn = apply_record_patch(retract, patch, request=repair, original_request=request)
    assert withdrawn['coverage'][unit]['status'] == 'unresolved'
    assert withdrawn['unit_impacts'][unit]['effect'] == 'unresolved'
    assert withdrawn['unit_impacts'][unit]['operations'] == []
    assert withdrawn['requirements'] == [retract['requirements'][1]]
    withdrawn_contract, withdrawn_graph = compile_value(withdrawn)
    assert not withdrawn_graph.requirement_relations
    assert not withdrawn_contract.source_inventory['unit_impacts'][unit]['complete']
    # The same predicate text cannot hide a changed order binding.
    reverse = deepcopy(records)
    reverse['requirements'][0]['relations'][0].update(source='publish', target='prepare')
    reverse_contract, reverse_graph = compile_value(reverse)
    assert reverse['requirements'][0]['fact'] == records['requirements'][0]['fact']
    assert structural_readback(request, reverse)['requirements']['order']['owned_relations'][0]['source'] == 'publish'
    assert reverse_graph.requirement_relations[0] == (owned, publish, relation, prepare)

    source = candidate_request([task], [contract], input_catalog=catalog)['sources'][0]
    # Keep source semantic IDs for this low-level projection check; normalization
    # has its own maintained candidate test and is not repeated here.
    aliases = {n['node_type']+'::'+n['concept_id']:n['concept_id'] for n in source['nodes']}
    occurrence = dict(task_id=task['task_id'], requirement_node_ids=[owned],
        scope=dict(operation_node_id=prepare,subject_node_ids=[],condition_node_ids=[guard]))
    selector, _ = _occurrence(source, occurrence, aliases)
    semantics = {n.node_id:n.semantic_id for n in graph.nodes}
    assert selector['policy_relations'] == [[semantics[prepare],'precedes',semantics[publish]]]
    query = _query(selector, semantics[owned])
    assert query['required_relations'] == [] and set(query['required_semantics']) == {semantics[prepare],semantics[publish]}
    scope = choose_candidate_scope(graph, selector)
    assert scope is not None and requirement_matches_policy(graph, owned, scope, selector)
    reversed_order = replace(graph, requirement_relations=((owned,publish,'precedes',prepare),))
    assert choose_candidate_scope(reversed_order, selector) == scope
    assert not requirement_matches_policy(reversed_order, owned, scope, selector)
    # This is a structural counterfactual, not a claim of an executable prompt edit.
    removed = replace(graph, nodes=tuple(n for n in graph.nodes if n.node_id != owned),
        edges=tuple(e for e in graph.edges if owned not in {e.source_id,e.target_id}),
        requirement_structures=tuple(r for r in graph.requirement_structures if r[0] != owned),
        requirement_relations=())
    assert choose_candidate_scope(removed, selector) == scope
    assert query_context(graph,query=query,cwe='',task_family='').state.value == 'present'
    assert query_context(removed,query=query,cwe='',task_family='').state.value == 'present'

    # Composites are authored structural controls, not model-accuracy samples.
    # Their guard stays with the owner expression; OR/NOT do not assert leaves.
    for kind in ('and','or','not'):
        value = deepcopy(records)
        parent = deepcopy(value['requirements'][0])
        parent.update(record_id='policy',scope_kind='composite',operations=[],subjects=[],relations=[],
            structure=dict(kind=kind,members=['order'] if kind == 'not' else ['order','strict']))
        parent['fact']['concept'].update(concept_id='policy',definition=f'Authored {kind} policy expression.')
        for leaf in value['requirements']:
            if leaf['record_id'] in parent['structure']['members']:
                leaf['conditions'] = []
        value['requirements'].append(parent)
        composite_contract, composite = compile_value(value)
        assert composite.requirement_relations == graph.requirement_relations
        assert prompt_tsg_from_record(prompt_tsg_record(composite)) == composite
        c_links = {(e.source_id,e.edge_type,e.target_id) for e in composite.edges}
        assert (guard,'conditions',owned) in c_links
        asserted, _ = graph_requirement_membership(composite)
        assert (owned in asserted) == (kind == 'and')
        if kind != 'and':
            c_source = candidate_request([task], [composite_contract], input_catalog=catalog)['sources'][0]
            with pytest.raises(ValueError,match='existing source requirement'):
                _occurrence(c_source, occurrence, aliases)
        if kind == 'or':
            parent_id = next(k for k,t,_ in composite.requirement_structures if t == 'or')
            assert requirement_policy_relations(composite,parent_id) == ((prepare,'precedes',publish),)
            assert requirement_binding(parent_id,links=c_links,
                node_types={n.node_id:n.node_type for n in composite.nodes},
                structures=composite.requirement_structures,retained_scopes=composite.requirement_scopes,
                owned_relations=composite.requirement_relations) is None


def test_actual_attempt_retains_incomplete_graph_without_calling_scope_provider():
    task, catalog, canonical, _, _ = _source_fixture()
    calls = []
    def provider(request, _config, _prompt):
        calls.append(request["request_kind"])
        assert request["request_kind"] != "source_only_fixed_scope_states"
        if request['request_kind'] == 'source_only_record_review':
            assert request['effective_unit_impacts']
            assert request['compiled_operations']
            assert set(request['effective_unit_impacts']) == set(request['source_units'])
        value = indexed_annotation(request, canonical)
        if request["request_kind"] == "source_only_atomic_records":
            value["coverage"]["u1"].update(status="unresolved", reason="A relevant source meaning remains unresolved.")
        return json.dumps(value).encode()
    attempt = _attempt_task_contract(task, catalog=catalog, evaluator=dict(candidate_id="offline"),
        annotator_prompt="Source-authored synthetic fixture.", review_status="development_exposed", provider=provider)
    assert calls == ["source_only_atomic_records", "source_only_record_review"]
    assert attempt.provider_calls == 2 and attempt.error_type is None
    assert attempt.contract is not None and attempt.graph is not None
    assert attempt.contract.feature_states == ()
    assert attempt.scope_assessment["provider_calls"] == 0
    assert attempt.scope_assessment["status"] == "SOURCE_INVENTORY_INCOMPLETE"
    assert attempt.scope_assessment["response_text"] is None
    assert len(attempt.scope_assessment["request"]["withheld_scopes"]) == 2
    # Exercise the active record compiler's local-impact declarations, not just
    # handcrafted contract metadata. Separate inputs prevent accidental sharing.
    from annotation_fixture import record_annotation
    from prompt_mechanism_study.tsg.source_records import record_request, compile_records
    task,catalog,canonical,_,_ = _source_fixture('Run query A using input x. Return the selected rows. Produce readable code. Run query B.')
    canonical['nodes'].append(dict(local_id='b',concept_id='sql.query',evidence_text='query B',occurrence=1))
    request=record_request(contract_decision_request(task,catalog))
    records=record_annotation(request,canonical)
    unit=next(k for k,v in request['source_units'].items() if 'query B' in v['evidence_text'])
    records['coverage'][unit].update(status='unresolved',reason='Synthetic unresolved behavior of B only.')
    records['unit_impacts'][unit].update(effect='local',operations=['b'],reason='Source separates B from query A.')
    def scopes():
        contract=compile_records(records,request=request,task=task,catalog=catalog,annotator_id='offline',review_status='development_exposed')
        return fixed_scope_request(contract,prompt=task['prompt'],catalog=catalog)
    localized=scopes()
    assert localized['scopes'] and localized['withheld_scopes']
    records['unit_impacts'][unit].update(effect='global',operations=[])
    assert not scopes()['scopes']


def test_fixed_generation_facts_are_injected_once_and_never_become_model_binding_rows():
    task, catalog, canonical, request, wire = _source_fixture()
    template_ids = {n["local_id"] for n in request["fixed_template"]["nodes"]}
    assert len(template_ids) == 5 and all("local_id" not in n for n in wire["nodes"])
    facts, binding, _ = _bindings(task, catalog, canonical, wire)
    assert template_ids <= {f["local_id"] for f in facts.facts}
    assert len(facts.facts) == len(wire["nodes"]) + 5
    assert len(facts.relations) == 4
    assert not template_ids & set(binding["binding_rows"])
    assert all(facts.source_inventory["layers"][key] == "generation" for key in template_ids)

    # Same generation layer does not imply the same direct target. Keep the
    # module obligation separate from reply formatting using existing fields.
    from annotation_fixture import record_annotation
    from prompt_mechanism_study.tsg.source_records import (
        record_request, compile_records, record_response_format, record_diagnostics,
        structural_readback, review_request,
    )
    # A frozen concept supplies its layer. The schema omits that response field;
    # compilation and review must still preserve runtime participants and the
    # generation obligation, rather than rejecting this legal response.
    template_concepts = {row['concept_id'] for row in request['fixed_template']['concepts']}
    catalog['semantic_layers'] = {
        key: 'generation' if key in template_concepts or key == 'code.readable' else 'runtime'
        for key in catalog['semantics'] if key != 'task.root'
    }
    request = record_request(contract_decision_request(task, catalog))
    records = record_annotation(request, canonical)
    for group in ('objects', 'operations', 'requirements'):
        assert 'layer' not in record_response_format(request)['json_schema']['schema'][
            'properties'][group]['items']['properties']['fact']['properties']
        for row in records[group]:
            row['fact'].pop('layer')
    assert record_diagnostics(records, request) == []
    contract = compile_records(records, request=request, task=task, catalog=catalog,
        annotator_id='source_authored_fixture', review_status='development_exposed')
    layers = contract.source_inventory['layers']
    for fact in contract.facts:
        assert layers[fact['local_id']] == catalog['semantic_layers'][fact['semantic_id']]
    assert contract.source_inventory['operation_roles']
    assert structural_readback(request, records)['operations']['q']['inputs'][0]['subject'] == 'x'
    assert review_request(request, records, compiled_contract=contract)['request_kind'] == 'source_only_record_review'

    sentence = 'Provide a Python module that imports os. Wrap the reply in a Markdown code block.'
    task = prepare_task_input(dict(task_id='generation-targets', language='python', prompt=sentence))
    catalog = open_concept_catalog()
    request = record_request(contract_decision_request(task, catalog))
    meanings = [('module', 'data_object', 'The requested Python module.'),
                ('reply', 'data_object', 'The requested reply.'),
                ('imports', 'constraint', 'Import os.'),
                ('format', 'presentation_control', 'Use a Markdown code block.')]
    canonical = dict(concepts=[dict(concept_id=k, node_type=t, definition=d) for k,t,d in meanings],
        nodes=[dict(local_id=k, concept_id=k, layer='generation', evidence_text=sentence, occurrence=1)
               for k,_,_ in meanings], edges=[], unresolved_notes=[])
    records = record_annotation(request, canonical)
    for row, target in zip(records['requirements'], ('module', 'reply')):
        row.update(scope_kind='targets', subjects=[target], operations=[])
    contract = compile_records(records, request=request, task=task, catalog=catalog,
        annotator_id='source_authored_fixture', review_status='development_exposed')
    targets = {(e['source'], e['target']) for e in contract.relations if e['edge_type']=='constrains'}
    assert {t for s,t in targets if s=='fact.3'} == {'fact.1'}
    assert {t for s,t in targets if s=='fact.4'} == {'fact.2'}


def test_qualification_keeps_incomplete_inventory_in_denominator_and_cannot_pass(tmp_path):
    # Reuse the independent synthetic source/reference construction used by the
    # existing end-to-end qualifier tests, rather than duplicate its artifact tree.
    from test_open_prompt_tsg import (
        _extract_semantic_fixture, _semantic_qualification_fixture, _source_review_fixture,
    )
    paths, case, fixture, calls, write = _semantic_qualification_fixture(tmp_path)
    def provider(request, config, prompt):
        response = json.loads(fixture(request, config, prompt))
        if request["request_kind"] == "source_only_atomic_records":
            next(iter(response["coverage"].values())).update(status="unresolved", reason="Source author left relevant meaning unresolved.")
        return json.dumps(response).encode()
    extraction = tmp_path / "extraction"
    _extract_semantic_fixture(paths, provider, extraction)
    audit, _ = _source_review_fixture(extraction, paths, case, write)
    output = tmp_path / "qualification"
    result = qualify_prompt_contract_extractor(tmp_path, paths["tasks"], extraction, paths["catalog"],
        tmp_path / "unused-legacy-registry", paths["reference"], paths["evaluator"], paths["prompt"],
        output, assertion_review_path=audit)
    assert [call["request_kind"] for call in calls] == ["source_only_atomic_records", "source_only_record_review"]
    assert result["task_units"] == 1 and result["failed_extraction_task_units"] == 0
    assert result["complete_task_units"] == 0
    assert result["status"] == "QUALIFICATION_FAILED" and result["scientific_claim_allowed"] is False
    scored = read_json(output / "case-results.json")[0]
    assert scored["source_inventory_status"]["status"] == "INCOMPLETE"
    assert scored["withheld_scope_count"] == 3
    assert scored["complete_task"] is False and scored["extraction_failed"] is False
    assert scored["raw_scope_response_sha256"] is None

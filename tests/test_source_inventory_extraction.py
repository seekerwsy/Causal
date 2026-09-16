"""Active extraction must retain incomplete source inventories without certifying them."""

import json
import pytest
from annotation_fixture import indexed_annotation, quoted_inventory
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.prompt_contract import open_concept_catalog
from prompt_mechanism_study.prompt_contract_extract import (
    PromptContractExtractionError,
    _attempt_task_contract,
    apply_fixed_binding_response,
    contract_decision_request,
    contract_from_response,
    fixed_binding_request,
    fixed_scope_request,
)
from prompt_mechanism_study.prompt_contract_qualification import qualify_prompt_contract_extractor
from prompt_mechanism_study.task_input import generation_template_facts, prepare_task_input


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
    from prompt_mechanism_study.prompt_contract_extract import source_annotation_diagnostics
    task, catalog, canonical, request, _ = _source_fixture(
        'Run query A using input x. Return the selected rows. Produce readable code. Run query B using input x.')
    canonical['nodes'].append(dict(local_id='b', concept_id='sql.query', evidence_text='query B', occurrence=1))
    wire = indexed_annotation(request, canonical)
    good = _compile(task, catalog, wire)
    assert sum(f['semantic_id']=='sql.query' for f in good.facts) == 2
    operations = [n for n in wire['nodes'] if n['concept_id']=='sql.query']
    operations[0]['evidence_end_token'] = operations[1]['evidence_end_token']
    before = deepcopy(wire)
    diagnostics = source_annotation_diagnostics(request, json.dumps(wire))
    assert any('identity anchor overlaps' in d['rule'] for d in diagnostics)
    with pytest.raises(PromptContractExtractionError, match='do not distinguish instances'):
        _compile(task, catalog, wire)
    assert wire == before


def test_positive_evidence_cannot_leak_to_unknown_or_conditional_scopes():
    from copy import deepcopy
    from prompt_mechanism_study.prompt_contract_extract import apply_fixed_scope_response, fixed_scope_response_format
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
    from prompt_mechanism_study.prompt_contract_extract import fixed_scope_response_format, apply_fixed_scope_response
    from prompt_mechanism_study.prompt_tsg import catalog_from_record
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
    from prompt_mechanism_study.prompt_tsg import catalog_from_record
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


def test_joint_inventory_preserves_unnamed_result_identity_and_allows_role_correction():
    from copy import deepcopy
    from prompt_mechanism_study.prompt_contract_extract import (
        grouped_inventory_request, grouped_inventory_response_format, flatten_grouped_inventory_response,
        inventory_entailment_review_request, source_annotation_diagnostics,
    )
    from prompt_mechanism_study.prompt_tsg import PromptTSGError

    task, catalog, canonical, _, _ = _source_fixture()
    catalog['semantics']['rows.return'] = 'task_operation'
    catalog['semantic_guidance']['rows.return'] = 'Return the already selected rows.'
    canonical['nodes'].append(dict(local_id='ret', concept_id='rows.return',
        evidence_text='Return the selected rows', occurrence=1))
    canonical['edges'].append(dict(source_node_local_id='rows', target_node_local_id='ret',
        edge_type='used_by', evidence_text='Return the selected rows', occurrence=1))
    request = contract_decision_request(task, catalog)
    wire = indexed_annotation(request, canonical)
    nodes = {n['concept_id']: n for n in wire['nodes']}
    def citation(row):
        return {k: row[k] for k in ('evidence_start_token', 'evidence_end_token')}
    selected = nodes['sql.rows']
    # The result has no variable declaration. Its source identity is reused by
    # the producer and consumer, while their relationship citations differ.
    response = dict(objects=[], requirements=[nodes['code.readable']], conditions=[],
        operations=[{**nodes['sql.query'], 'inputs':[dict(object=nodes['sql.input'],
            role='value_input', **citation(nodes['sql.query']))],
            'results':[dict(object=selected, **citation(selected))]},
            {**nodes['rows.return'], 'inputs':[dict(object=deepcopy(selected),
                role='value_input', **citation(nodes['rows.return']))], 'results':[]}],
        coverage=wire['coverage'], unresolved_notes=[])
    grouped = grouped_inventory_request(request)
    schema = grouped_inventory_response_format(grouped)['json_schema']['schema']
    assert {'inputs', 'results'} <= set(schema['properties']['operations']['items']['required'])
    response = quoted_inventory(request, response)
    # Different mention spans may identify the same explicitly declared entity.
    response['operations'][1]['inputs'][0]['object']['evidence_text'] = 'selected rows'
    raw = json.dumps(response)
    flattened = json.loads(flatten_grouped_inventory_response(raw.encode(), request=grouped))
    contract = _compile(task, catalog, flattened)
    selected_ids = [f['local_id'] for f in contract.facts if f['semantic_id'] == 'sql.rows']
    assert len(selected_ids) == 1
    assert len(contract.source_inventory['operation_roles']) == 3
    assert sum(r['subject'] == selected_ids[0] for r in contract.source_inventory['operation_roles']) == 2
    assert all(e['source'].startswith('template.') for e in contract.relations)
    # Catch empty represented units before compilation, where the bounded
    # inventory repair can see the diagnostic rather than ending the task.
    broken = deepcopy(response)
    empty_unit = broken['requirements'][0]['source_units'][0]
    broken['requirements'] = []
    broken['coverage'][empty_unit]['status'] = 'represented'
    with pytest.raises(PromptContractExtractionError, match='requires an additional submitted fact'):
        flatten_grouped_inventory_response(json.dumps(broken).encode(), request=grouped)
    review = inventory_entailment_review_request(grouped, raw)
    assert review['source_object_meaning'] == grouped['source_object_meaning']
    assert review['operation_role_meanings'] == grouped['operation_role_meanings']
    assert review['operation_role_meanings'] is not grouped['operation_role_meanings']
    assert len(review['participant_claims']) == 3
    assert len(review['candidate_statements']) == 6  # Includes both explicit uses of the one result.
    result_occurrences = [s for s in review['candidate_statements'] if s['concept_id'] == 'sql.rows']
    assert len({s['entity_key'] for s in result_occurrences}) == 1
    assert len({s['citation']['evidence_text'] for s in result_occurrences}) == 2
    assert all(r['path'] in review['allowed_issue_paths'] for r in review['participant_claims'])
    # Omitted entities have no row index yet. Review can locate the destination
    # array, while repair still has to verify and submit the actual new fact.
    from prompt_mechanism_study.prompt_contract_extract import (
        source_annotation_review_response_format, source_annotation_revision_request,
    )
    issue_schema = source_annotation_review_response_format(review)['json_schema']['schema']['properties']['issues']['items']
    assert {'objects', 'operations[0].inputs', 'operations[1].results'} <= set(issue_schema['properties']['path']['enum'])
    feedback = dict(issues=[dict(path='operations[0].results', source_quote=task['prompt'],
        problem='Authored omission feedback to exercise the insertion location.',
        correction='Check whether a missing result must be restored from the available vocabulary.',
        repair_stage='inventory')], remaining_uncertainties=[])
    revision = source_annotation_revision_request(grouped, raw, feedback)
    assert revision['source_review_revision']['critique']['issues'] == feedback['issues']
    assert revision['known_concepts'] == grouped['known_concepts']
    assert response['operations'][0]['results'] == json.loads(raw)['operations'][0]['results']
    assert not source_annotation_diagnostics(grouped, raw)
    # A draft with bad evidence must reach review, while final compilation still
    # rejects it. Otherwise repair cannot see precisely the defects it should fix.
    unlocated = deepcopy(response)
    unlocated['operations'][0]['results'][0]['object']['evidence_text'] = 'invented result text'
    unlocated_raw = json.dumps(unlocated)
    unlocated_review = inventory_entailment_review_request(grouped, unlocated_raw)
    unlocated_statement = next(s for s in unlocated_review['candidate_statements']
                              if s['path'] == 'operations[0].results[0].object')
    assert unlocated_statement['citation'] is None and unlocated_statement['citation_error']
    assert unlocated_statement['submitted_evidence']['evidence_text'] == 'invented result text'
    assert 'invented result text' not in unlocated_review['allowed_issue_source_quotes']
    with pytest.raises(PromptContractExtractionError, match='token-aligned occurrence'):
        flatten_grouped_inventory_response(unlocated_raw.encode(), request=grouped)
    unlocated['operations'][1]['inputs'][0]['evidence_text'] = 'another invented quote'
    diagnostics = source_annotation_diagnostics(grouped, json.dumps(unlocated))
    assert {d['path'] for d in diagnostics} == {
        'operations[0].results[0].object', 'operations[1].inputs[0]'}
    assert all('found 0 matches' in d['rule'] for d in diagnostics)
    # Binding independently rejudges an initially claimed input role.
    binding_request = fixed_binding_request(contract, prompt=task['prompt'], catalog=catalog)
    binding = indexed_annotation(binding_request, canonical)
    input_id = next(f['local_id'] for f in contract.facts if f['semantic_id'] == 'sql.input')
    assert next(r for r in binding['operation_roles'] if r['subject'] == input_id)['role'] == 'input_unspecified'
    bound = apply_fixed_binding_response(json.dumps(binding).encode(), request=binding_request,
        contract=contract, prompt=task['prompt'], catalog=catalog)
    assert bound.facts == contract.facts
    assert next(r for r in bound.source_inventory['operation_roles'] if r['subject'] == input_id)['role'] == 'input_unspecified'
    assert any(e['edge_type'] == 'produces' and e['target'] == selected_ids[0] for e in bound.relations)
    assert any(e['edge_type'] == 'used_by' and e['source'] == selected_ids[0] for e in bound.relations)
    # Bad occurrence metadata cannot be concealed by pooling, and repeated
    # participant claims cannot create silently duplicated graph evidence.
    broken = deepcopy(response)
    broken['operations'][1]['inputs'][0]['object']['concept_id'] = 'sql.input'
    with pytest.raises(PromptContractExtractionError, match='conflicting concepts'):
        flatten_grouped_inventory_response(json.dumps(broken).encode(), request=grouped)
    broken = deepcopy(response)
    broken['operations'][1]['inputs'][0]['object']['layer'] = 'generation'
    with pytest.raises(PromptContractExtractionError, match='conflicting layers'):
        flatten_grouped_inventory_response(json.dumps(broken).encode(), request=grouped)
    broken = deepcopy(response)
    broken['operations'][0]['results'].append(deepcopy(broken['operations'][0]['results'][0]))
    flat = json.loads(flatten_grouped_inventory_response(json.dumps(broken).encode(), request=grouped))
    with pytest.raises(PromptTSGError, match='role is duplicated'):
        _compile(task, catalog, flat)
    broken = deepcopy(flattened)
    broken['operation_roles'][0]['evidence_end_token'] = 999999
    with pytest.raises(PromptContractExtractionError, match='source-token endpoints'):
        _compile(task, catalog, broken)

    # The same path admits genuinely new source meanings in development while
    # preserving supplied concepts, candidate rules, bindings and source review.
    from dataclasses import replace
    from prompt_mechanism_study.prompt_contract import compile_task_context_contract
    from prompt_mechanism_study.prompt_contract_extract import _attempt_source_graph, _assess_candidate_scopes
    from prompt_mechanism_study.prompt_tsg import catalog_from_record
    open_catalog = deepcopy(catalog)
    open_catalog['concept_policy'] = 'DEVELOPMENT_OPEN'
    open_catalog['semantic_layers'] = {key: 'generation' if key == 'code.readable' or key.startswith('generation.') else 'runtime'
        for key in catalog['semantics'] if key != 'task.root'}
    # Derive the template layers from their actual facts, without guessing IDs.
    for concept in generation_template_facts(task)['concepts']:
        open_catalog['semantic_layers'][concept['concept_id']] = 'generation'
    for key in ('sql.rows', 'sql.input', 'rows.return'):
        open_catalog['semantics'].pop(key)
        open_catalog['semantic_guidance'].pop(key)
        open_catalog['semantic_layers'].pop(key)
    length = 'input.length'
    open_catalog['semantics'][length] = 'safety_requirement'
    open_catalog['semantic_guidance'][length] = 'Require the input to be at most 10 characters.'
    open_catalog['semantic_layers'][length] = 'runtime'
    query = deepcopy(open_catalog['queries'][0])
    query.update(query_id=length, actionable_feature_id=length, realization_id=length)
    open_catalog['queries'].append(query)
    open_catalog['feature_scope_domains'] = {'sql.binding': 'subjects', length: 'subjects'}
    open_catalog['feature_subject_properties'] = {length: 'character_sequence'}
    catalog_from_record(open_catalog)
    original_catalog = deepcopy(open_catalog)
    open_request = contract_decision_request(task, open_catalog)
    assert 'sql.query' in open_request['known_concepts'] and 'sql.rows' not in open_request['known_concepts']
    def inline(value):
        if isinstance(value, list):
            return [inline(v) for v in value]
        if not isinstance(value, dict):
            return value
        value = {k: inline(v) for k, v in value.items()}
        if 'concept_id' in value:
            key = value.pop('concept_id')
            value['concept'] = dict(concept_id=key, node_type=catalog['semantics'][key],
                definition=catalog['semantic_guidance'][key])
        return value
    open_response = inline(response)
    open_raw = json.dumps(open_response).encode()
    grouped = grouped_inventory_request(open_request)
    schema = grouped_inventory_response_format(grouped)['json_schema']['schema']
    assert schema['properties']['operations']['items']['properties']['concept']['properties']['node_type']['enum'] == ['task_operation']
    assert not source_annotation_diagnostics(grouped, open_raw.decode())
    reviewed = inventory_entailment_review_request(grouped, open_raw.decode())
    assert any(s['full_meaning'] == catalog['semantic_guidance']['sql.rows'] for s in reviewed['candidate_statements'])
    flat = flatten_grouped_inventory_response(open_raw, request=grouped)
    delivered = []
    def provider(request, *_):
        delivered.append(request)
        if request['request_kind'] in {'source_only_atomic_records', 'source_only_record_review'}:
            from copy import deepcopy
            declared = deepcopy(canonical)
            declared['concepts'] = [dict(concept_id=k, node_type=v, definition=catalog['semantic_guidance'][k]) for k,v in catalog['semantics'].items() if k in catalog['semantic_guidance']]
            return json.dumps(indexed_annotation(request, declared)).encode()
        assert request['request_kind'] == 'source_only_fixed_scope_states'
        assert all(f['definition'] for f in request['facts'])
        assert all(q['subject_definition'] for q in request['subject_property_questions'].values())
        # A failed scope response must retain the finished source graph.
        raise RuntimeError('authored downstream failure')
    attempt = _attempt_source_graph(task=task, catalog=open_catalog, evaluator={'candidate_id': 'offline'},
        annotator_prompt='offline', provider=provider, review_status='development_exposed')
    assert attempt.succeeded, attempt.error_message
    assert catalog['semantic_guidance']['sql.rows'] in attempt.contract.catalog['semantic_guidance'].values()
    assert open_catalog == original_catalog
    assessed = _assess_candidate_scopes(attempt, task=task, catalog=open_catalog, evaluator={},
        annotator_prompt='offline', provider=provider)
    assert len(delivered) == 3 and assessed.scope_assessment['status'] == 'FAILED'
    assert assessed.contract == attempt.contract and assessed.graph == attempt.graph
    assert {s['concept_id'] for s in delivered[-1]['scopes'].values()} == {'sql.binding', length}
    broken = deepcopy(open_response)
    broken['operations'][0]['concept']['definition'] = 'Run arbitrary shell commands.'
    with pytest.raises(PromptContractExtractionError, match='cannot change a supplied meaning'):
        flatten_grouped_inventory_response(json.dumps(broken).encode(), request=grouped)
    altered = deepcopy(attempt.contract.catalog)
    altered['queries'][0]['realization_id'] = 'changed'
    with pytest.raises(PromptTSGError, match='cannot change supplied concepts or candidate rules'):
        compile_task_context_contract(replace(attempt.contract, catalog=altered), prompt=task['prompt'], catalog=open_catalog)


def test_independent_participant_table_is_blind_and_excludes_generation_objects():
    from copy import deepcopy
    from prompt_mechanism_study.prompt_contract_extract import (
        source_precedence_review_request, source_precedence_review_response_format,
    )
    task, catalog, canonical, _, wire = _source_fixture()
    _, request, _ = _bindings(task, catalog, canonical, wire)
    first = source_precedence_review_request(request, include_participants=True)
    changed = deepcopy(request)
    changed['source_inventory']['operation_roles'] = [{'invented': 'use'}]
    changed['source_inventory']['coverage'] = {'unsupported': 'complete'}
    changed['fixed_relations'] = [{'invented': 'order'}]
    assert source_precedence_review_request(changed, include_participants=True) == first
    objects = {f['local_id'] for f in request['facts']
               if f['node_type'] == 'data_object' and f['layer'] == 'runtime'}
    assert {f['local_id'] for f in first['objects']} == objects
    frames = source_precedence_review_response_format(first)['json_schema']['schema']['properties']['participant_roles']
    assert set(frames['required']) == {f['local_id'] for f in first['operations']}
    assert all(set(frame['required']) == objects for frame in frames['properties'].values())
    cell_schema = next(iter(next(iter(frames['properties'].values()))['properties'].values()))
    assert set(cell_schema['required']) == {'roles', 'source_units'}
    assert cell_schema['properties']['roles']['minItems'] == 1
    assert first['source_prompt'] == task['prompt']


def test_independent_participant_review_routes_missing_shared_use_without_graph_edits():
    from copy import deepcopy
    from prompt_mechanism_study.prompt_contract_extract import merge_source_precedence_review

    source = 'Open the store and look up the record by key in that store.'
    entries = [('open', 'task_operation', 'Open the store'),
               ('lookup', 'task_operation', 'look up the record by key in that store'),
               ('store', 'data_object', 'the store'), ('key', 'data_object', 'key')]
    request = dict(request_kind='source_only_fixed_bindings', source_prompt=source,
        source_inventory=dict(source_units={'u1': dict(evidence_text=source, occurrence=1)}),
        operation_role_meanings={'resource': 'Execution facility.', 'value_input': 'Data value.'},
        facts=[dict(local_id=key, concept_id=key, definition=quote, node_type=kind, layer='runtime',
                    evidence_text=quote, occurrence=1, source_units=['u1']) for key, kind, quote in entries])
    draft = dict(bindings={'open': dict(precedes=[dict(target='lookup')]), 'lookup': dict(precedes=[])},
        incidence={'open': dict(inputs=[dict(subject='store', role='resource')], results=[], unresolved_subjects=[]),
                   'lookup': dict(inputs=[dict(subject='key', role='value_input')], results=[], unresolved_subjects=[])})
    def cell(*roles):
        return dict(roles=list(roles) or ['no_required_role'], source_units=['u1'])
    proposal = dict(required_precedence=[], unresolved_notes=[], participant_roles={
        'open': {'store': cell('resource'), 'key': cell()},
        'lookup': {'store': cell('resource'), 'key': cell('value_input')}})
    review = dict(issues=[], remaining_uncertainties=[])
    before = deepcopy((request, draft, review))
    merged = merge_source_precedence_review(request, json.dumps(draft), review, json.dumps(proposal), include_participants=True)
    assert (request, draft, review) == before
    assert len(merged['issues']) == 1
    assert merged['issues'][0]['path'] == 'incidence.lookup'
    assert 'store' in merged['issues'][0]['correction']
    # Already-used resources cannot conceal an omitted use by another operation.
    draft['incidence']['lookup']['inputs'].append(dict(subject='store', role='resource'))
    assert not merge_source_precedence_review(request, json.dumps(draft), review, json.dumps(proposal), include_participants=True)['issues']
    # A contradictory critique is repair input, not a reason to discard every
    # other useful finding or silently interpret an empty list as no source use.
    for labels in ([], ['resource', 'no_required_role'], ['unresolved']):
        proposal['participant_roles']['open']['store']['roles'] = labels
        merged = merge_source_precedence_review(request, json.dumps(draft), review, json.dumps(proposal), include_participants=True)
        assert len(merged['issues']) == 1 and merged['issues'][0]['path'] == 'incidence.open'
        assert draft['incidence']['open']['inputs'] == [dict(subject='store', role='resource')]
    # Consuming and exposing an existing object remain separate required roles.
    proposal['participant_roles']['lookup']['key']['roles'] = ['value_input', 'result']
    proposal['participant_roles']['open']['store']['roles'] = ['resource']
    merged = merge_source_precedence_review(request, json.dumps(draft), review, json.dumps(proposal), include_participants=True)
    assert len(merged['issues']) == 1 and "'result'" in merged['issues'][0]['correction']
    del proposal['participant_roles']['lookup']['store']
    with pytest.raises(PromptContractExtractionError, match='every operation/object pair'):
        merge_source_precedence_review(request, json.dumps(draft), review, json.dumps(proposal), include_participants=True)


def _incidence_fixture():
    from prompt_mechanism_study.prompt_contract_extract import operation_incidence_request
    task, catalog, canonical, _, wire = _source_fixture()
    facts, request, binding = _bindings(task, catalog, canonical, wire)
    matrix = operation_incidence_request(request)
    response = {key: value for key, value in binding.items() if key != "operation_roles"}
    response["incidence"] = {operation: dict(
        inputs=[{k: v for k, v in row.items() if k != "operation"}
                for row in binding["operation_roles"] if row["operation"] == operation and row["role"] != "result"],
        results=[{k: v for k, v in row.items() if k not in {"operation", "role"}}
                 for row in binding["operation_roles"] if row["operation"] == operation and row["role"] == "result"],
        unresolved_subjects=[]) for operation in matrix["operation_subjects"]}
    return task, catalog, facts, request, binding, matrix, response


def test_exhaustive_critic_cannot_skip_claims_or_leave_reported_errors_unrepaired():
    from prompt_mechanism_study.prompt_contract_extract import (
        source_annotation_review_request, source_annotation_review_response_format,
        source_annotation_revision_request,
    )
    task, catalog, _, _, _, request, response = _incidence_fixture()
    # The proposed concrete role is deliberately fallible; the review must
    # route its admitted ambiguity even alongside a positive verdict.
    next(frame for frame in response['incidence'].values() if frame['inputs'])['inputs'][0]['role'] = 'value_input'
    raw = json.dumps(response)
    critique = source_annotation_review_request(request, raw)
    paths = [c['path'] for c in critique['expanded_binding_claims']]
    assert {f"facts.{f['local_id']}" for f in request['facts'] if not f['local_id'].startswith('template.')} <= set(paths)
    checks = {p: dict(support='supported', reason='Fixture source review.') for p in paths}
    for claim in critique['expanded_binding_claims']:
        if claim.get('repair_stage') == 'inventory':
            checks[claim['path']].update(unsupported_specificity_possible=False,
                specificity_reason='The fixture source supports the full fact meaning.')
        if claim.get('role') in {'value_input','identifier_input','resource','destination'}:
            checks[claim['path']].update(alternative_role_possible=False,
                alternative_role_reason='The fixture source establishes this concrete role.')
        if claim.get('role') in {'value_input','identifier_input','resource','destination','input_unspecified'}:
            checks[claim['path']].update(alternative_nonuse_possible=False,
                nonuse_reason='The fixture explicitly requires this operation to use this input.')
    schema = source_annotation_review_response_format(critique)['json_schema']['schema']
    from prompt_mechanism_study.prompt_contract_extract import operation_incidence_response_format
    binding_schema = operation_incidence_response_format(request)['json_schema']['schema']['properties']['bindings']
    for binding in binding_schema['properties'].values():
        for column in binding['properties'].values():
            assert column['maxItems'] == len(column['items']['properties']['target'].get('enum', []))
    assert set(schema['properties']['claim_checks']['required']) == set(paths)
    assert critique['reuse_bound_claim_citations'] is True
    for path, verdict in schema['properties']['claim_checks']['properties'].items():
        expected_fields = {'support', 'reason'}
        role = next(c.get('role') for c in critique['expanded_binding_claims'] if c['path'] == path)
        if 'alternative_role_possible' in verdict['properties'] and role != 'input_unspecified':
            expected_fields |= {'alternative_role_possible', 'alternative_role_reason'}
            assert next(iter(verdict['properties'])) == 'alternative_nonuse_possible'
        if 'alternative_nonuse_possible' in verdict['properties']:
            expected_fields |= {'alternative_nonuse_possible', 'nonuse_reason'}
        if 'unsupported_specificity_possible' in verdict['properties']:
            expected_fields |= {'unsupported_specificity_possible', 'specificity_reason'}
            assert next(iter(verdict['properties'])) == 'unsupported_specificity_possible'
        assert set(verdict['required']) == expected_fields
    assert request['source_prompt'] in critique['allowed_issue_source_quotes']
    assert all(quote in request['source_prompt'] for quote in critique['allowed_issue_source_quotes'])
    result_checks = {key: {side: dict(required_participants='The source-required participants are represented.',
        source_quote=request['source_prompt'], status='represented', reason='Fixture participation review.')
        for side in ('inputs', 'results')} for key in critique['operation_participation_questions']}
    assert next(iter(schema['properties'])) == 'operation_participation_checks'
    review = dict(issues=[], remaining_uncertainties=[], claim_checks=checks,
        operation_participation_checks=result_checks)
    with pytest.raises(PromptContractExtractionError, match='fields are invalid'):
        source_annotation_revision_request(critique, raw, dict(issues=[], remaining_uncertainties=[]))
    revision = source_annotation_revision_request(critique, raw, review)
    from copy import deepcopy
    from prompt_mechanism_study.prompt_contract_extract import source_binding_repair_request, validate_source_binding_repair
    negative_review = deepcopy(review)
    edge = next(c for c in critique['expanded_binding_claims'] if c.get('role') == 'value_input')
    negative_review['claim_checks'][edge['path']]['support'] = 'unsupported'
    guarded = source_binding_repair_request(request, reviewed_request=critique, critique=negative_review)
    with pytest.raises(PromptContractExtractionError, match='repair repeated rejected'):
        validate_source_binding_repair(raw.encode(), request=guarded)
    corrected = json.loads(raw)
    rejected, = guarded['rejected_source_claims']
    corrected['incidence'][rejected['operation']]['inputs'] = [
        r for r in corrected['incidence'][rejected['operation']]['inputs'] if r['subject'] != rejected['subject']]
    validate_source_binding_repair(json.dumps(corrected).encode(), request=guarded)
    assert 'rejected_source_claims' not in request
    retained = revision['source_review_revision']['critique']['claim_checks']
    for claim in critique['expanded_binding_claims']:
        assert retained[claim['path']] == {
            **checks[claim['path']], 'source_quote': claim['citation']['evidence_text']}
    assert all('source_quote' not in check for check in checks.values())
    unspecified_response = json.loads(raw)
    next(frame for frame in unspecified_response['incidence'].values() if frame['inputs'])['inputs'][0]['role'] = 'input_unspecified'
    unspecified_raw = json.dumps(unspecified_response)
    unspecified_critique = source_annotation_review_request(request, unspecified_raw)
    unspecified_review = json.loads(json.dumps(review))
    unspecified = next(c['path'] for c in unspecified_critique['expanded_binding_claims'] if c.get('role') == 'input_unspecified')
    unspecified_verdict = source_annotation_review_response_format(unspecified_critique)['json_schema']['schema']['properties']['claim_checks']['properties'][unspecified]
    assert set(unspecified_verdict['required']) == {'support', 'reason', 'alternative_nonuse_possible', 'nonuse_reason'}
    unspecified_review['claim_checks'][unspecified].update(alternative_role_possible=False,
        alternative_role_reason='This input already retains its source-unspecified role.')
    redundant = source_annotation_revision_request(unspecified_critique, unspecified_raw, unspecified_review)['source_review_revision']
    assert redundant['critique']['issues'] == []
    assert redundant['critique']['claim_checks'][unspecified]['alternative_role_possible'] is False
    # An unknown role still claims definite use. Admitted non-use must route
    # removal of that relation, even if the same verdict approves it.
    unspecified_review['claim_checks'][unspecified].update(alternative_nonuse_possible=True,
        nonuse_reason='This optional available object need not participate in this operation.')
    nonuse = source_annotation_revision_request(unspecified_critique, unspecified_raw, unspecified_review)['source_review_revision']
    assert unspecified in nonuse['program_routed_verdict_paths']
    assert any('Do not substitute input_unspecified' in i['correction'] for i in nonuse['critique']['issues'])
    assert unspecified_review['issues'] == []
    unspecified_review['claim_checks'][unspecified]['alternative_nonuse_possible'] = False
    unspecified_review['claim_checks'][unspecified]['support'] = 'uncertain'
    negative = source_annotation_revision_request(unspecified_critique, unspecified_raw, unspecified_review)['source_review_revision']
    assert any(i['path'] == unspecified for i in negative['critique']['issues'])
    missing = paths[-1]
    del checks[missing]
    with pytest.raises(PromptContractExtractionError, match='every submitted binding claim'):
        source_annotation_revision_request(critique, raw, review)
    checks[missing] = dict(support='unsupported', reason='The role exceeds source support.')
    routed = source_annotation_revision_request(critique, raw, review)['source_review_revision']
    assert routed['program_routed_verdict_paths'] == [missing]
    assert routed['critique']['claim_checks'][missing]['support'] == 'unsupported'
    assert routed['critique']['issues'][0]['path'] == missing
    assert routed['critique']['issues'][0]['source_quote'] == next(
        c['citation']['evidence_text'] for c in critique['expanded_binding_claims'] if c['path'] == missing)
    assert review['issues'] == []  # Raw verdicts remain unchanged and cannot silently pass.
    review['issues'] = [dict(path=missing, source_quote='query A', problem='An unsupported role.',
                             correction='Recheck and remove unsupported roles.', repair_stage='bindings')]
    assert source_annotation_revision_request(critique, raw, review)['facts'] == request['facts']
    review['issues'][0]['source_quote'] = 'query A ... invented quotation'
    with pytest.raises(PromptContractExtractionError, match='valid source-bound correction'):
        source_annotation_revision_request(critique, raw, review)
    # Missing results trigger the upstream branch even when every existing
    # claim is approved and the critic forgets to summarize the defect.
    review['issues'] = []
    checks[missing]['support'] = 'supported'
    operation = next(iter(result_checks))
    result_checks[operation]['results']['status'] = 'missing_entity'
    with pytest.raises(PromptContractExtractionError, match='another construction stage'):
        source_annotation_revision_request(critique, raw, review)
    inventory = contract_decision_request(task, catalog)
    inventory_raw = json.dumps(_source_fixture()[4])
    revised = source_annotation_revision_request(critique, raw, review,
        inventory_request=inventory, inventory_response=inventory_raw)
    assert revised['request_kind'] == 'source_only_fact_inventory'
    assert revised['source_prompt'] == request['source_prompt']
    repair = revised['source_review_revision']
    assert repair['previous_response'] == inventory_raw
    assert repair['reviewed_fixed_facts'] == request['facts']
    assert any(i['repair_stage']=='inventory' for i in repair['critique']['issues'])
    assert review['issues'] == []
    # A contradictory positive verdict cannot cancel its admitted role
    # ambiguity. Preserve required participation when repairing its role.
    result_checks[operation]['results']['status'] = 'represented'
    # Missing source-required resource/input edges use the same single repair,
    # even if every submitted assertion is supported and issues is empty.
    result_checks[operation]['inputs']['status'] = 'missing_binding'
    participant_repair = source_annotation_revision_request(critique, raw, review)
    assert participant_repair['request_kind'] == 'source_only_fixed_bindings'
    assert any(i['path'] == f'operation_participation_checks.{operation}.inputs'
               and i['repair_stage'] == 'bindings'
               for i in participant_repair['source_review_revision']['critique']['issues'])
    result_checks[operation]['inputs']['status'] = 'missing_entity'
    assert source_annotation_revision_request(critique, raw, review,
        inventory_request=inventory, inventory_response=inventory_raw)['request_kind'] == 'source_only_fact_inventory'
    result_checks[operation]['inputs']['status'] = 'represented'
    fact_path = next(c['path'] for c in critique['expanded_binding_claims'] if c.get('repair_stage') == 'inventory')
    checks[fact_path]['unsupported_specificity_possible'] = True
    fact_repair = source_annotation_revision_request(critique, raw, review,
        inventory_request=inventory, inventory_response=inventory_raw)
    assert checks[fact_path]['support'] == 'supported'
    assert fact_repair['request_kind'] == 'source_only_fact_inventory'
    assert fact_path in fact_repair['source_review_revision']['program_routed_verdict_paths']
    checks[fact_path]['unsupported_specificity_possible'] = False
    checks[fact_path]['support'] = 'unsupported'
    fact_repair = source_annotation_revision_request(critique, raw, review,
        inventory_request=inventory, inventory_response=inventory_raw)
    assert fact_repair['request_kind'] == 'source_only_fact_inventory'
    assert any(i['path'] == fact_path and i['repair_stage'] == 'inventory'
               for i in fact_repair['source_review_revision']['critique']['issues'])
    # Even a critic's incorrectly requested binding repair cannot rewrite a fact.
    review['issues'] = [dict(path=fact_path, source_quote=request['source_prompt'],
        problem='The fact adds an unsupported obligation.', correction='Recheck its complete definition.', repair_stage='bindings')]
    fact_repair = source_annotation_revision_request(critique, raw, review,
        inventory_request=inventory, inventory_response=inventory_raw)
    assert fact_repair['request_kind'] == 'source_only_fact_inventory'
    assert review['issues'][0]['repair_stage'] == 'bindings'
    review['issues'] = []
    checks[fact_path]['support'] = 'supported'
    role_path = next(c['path'] for c in critique['expanded_binding_claims']
        if c.get('role') in {'value_input','identifier_input','resource','destination'})
    checks[role_path].update(alternative_role_possible=True,
        alternative_role_reason='Authored conflict: another concrete role remains possible.')
    role_repair = source_annotation_revision_request(critique, raw, review)['source_review_revision']
    assert role_path in role_repair['program_routed_verdict_paths']
    assert any(i['path']==role_path and 'input_unspecified' in i['correction']
               for i in role_repair['critique']['issues'])
    assert checks[role_path]['support'] == 'supported' and review['issues'] == []
    result_checks.pop(operation)
    with pytest.raises(PromptContractExtractionError, match="every operation's participation"):
        source_annotation_revision_request(critique, raw, review)


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
    from prompt_mechanism_study.source_records import (
        record_request, compile_records, review_request, repair_request, apply_record_patch, record_diagnostics,
    )
    catalog = open_concept_catalog()
    request = record_request(contract_decision_request(task, catalog))
    records = record_annotation(request, canonical)
    invalid = deepcopy(records)
    invalid['requirements'][0].update(scope_kind='task', operations=[], subjects=[])
    invalid['requirements'][0]['fact'].update(layer='generation')
    diagnostic_request = deepcopy(request)
    concept = invalid['requirements'][0]['fact']['concept']
    diagnostic_request['known_concepts'][concept['concept_id']] = deepcopy(concept)
    concept['definition'] = 'Redefined known meaning.'
    diagnostics = record_diagnostics(invalid, diagnostic_request)
    assert any('cannot change a supplied meaning' in problem for problem in diagnostics)
    assert any('task scope is runtime' in problem for problem in diagnostics)
    check = review_request(request, records)
    assert check['operation_role_meanings'] == request['operation_role_meanings']
    assert 'EVERY runtime operation' in check['record_semantics']['task_scope']
    from prompt_mechanism_study.source_records import structural_readback, review_response_format
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
    # Preserve composition and inherited guards at construction; only conjunction
    # entails its declared leaves. This is a synthetic logic boundary, not accuracy.
    from prompt_mechanism_study.prompt_contract import compile_task_context_contract
    from prompt_mechanism_study.prompt_tsg import graph_requirement_membership, prompt_tsg_record, prompt_tsg_from_record
    from prompt_mechanism_study.candidate_construction import (
        candidate_request, _occurrence, _canonical_concepts, _query, choose_candidate_scope,
    )
    composite = deepcopy(records)
    parent = deepcopy(composite['requirements'][0])
    parent.update(record_id='both', structure=dict(kind='and', members=['binding','length']))
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
    with pytest.raises(ValueError, match='independent of the target'):
        _occurrence(source,occurrence,aliases)
    # Explicit non-gating context can survive removing the target requirement.
    composite['operations'][0]['scope_conditions'] = deepcopy(parent['conditions'])
    comp = compile_composite(composite)
    candidate = candidate_request([task],[comp],input_catalog=catalog)
    source = candidate['sources'][0]
    selector, _ = _occurrence(source,occurrence,aliases)
    assert selector['execution_condition_semantic_ids'] == []
    assert any(edge[1]=='context_for' for edge in _query(selector,'test-feature')['required_relations'])
    graph = compile_task_context_contract(comp,prompt=task['prompt'],catalog=catalog)
    # Use source meanings for this low-level selector test (normalization is separate).
    by_id={n.node_id:n.semantic_id for n in graph.nodes}
    selector.update(operation_semantic_id=by_id[op],subject_semantic_ids=[by_id[subject]],condition_semantic_ids=[by_id[guard]])
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
        from prompt_mechanism_study.prompt_tsg import catalog_sha256
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
    assert ('fact.3','constrains','fact.2') in links
    assert ('fact.5','conditions','fact.3') in links and ('fact.5','conditions','fact.2') not in links
    from prompt_mechanism_study.candidate_construction import candidate_request, _occurrence
    source = candidate_request([task], [compiled], input_catalog=catalog)['sources'][0]
    assumption = next(n for n in source['nodes'] if n.get('statement_kind') == 'assumption')
    with pytest.raises(ValueError, match='existing source requirement'):
        _occurrence(source, dict(task_id=task['task_id'], requirement_node_ids=[assumption['node_id']], scope={}), {})


def test_actual_attempt_retains_incomplete_graph_without_calling_scope_provider():
    task, catalog, canonical, _, _ = _source_fixture()
    calls = []
    def provider(request, _config, _prompt):
        calls.append(request["request_kind"])
        assert request["request_kind"] != "source_only_fixed_scope_states"
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
    from prompt_mechanism_study.source_records import record_request, compile_records
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

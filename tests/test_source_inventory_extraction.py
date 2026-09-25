"""Active extraction must retain incomplete source inventories without certifying them."""

import json
import pytest
from annotation_fixture import (
    record_annotation,
)
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.tsg.prompt_contract import open_concept_catalog
from prompt_mechanism_study.tsg.source_codec import (
    PromptContractExtractionError,
    contract_decision_request,
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
    return task, catalog, canonical, request


def test_overlapping_evidence_is_not_a_semantic_rejection():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.source_records import record_request, compile_records
    task, catalog, canonical, base = _source_fixture(
        'Run query A using input x. Return the selected rows. Produce readable code. Run query B using input x.')
    canonical['nodes'].append(dict(local_id='b', concept_id='sql.query', evidence_text='query B', occurrence=1))
    request = record_request(base)
    value = record_annotation(request, canonical)
    operations = value['operations']
    # Overlapping evidence does not merge distinct source instances.
    previous_units = operations[1]['fact']['source_units']
    operations[1]['fact'] = deepcopy(operations[0]['fact'])
    operations[1]['fact']['source_units'] += previous_units
    operations[1]['fact']['evidence_text'] = 'Run query A using input x'
    before = deepcopy(value)
    contract = compile_records(value, request=request, task=task, catalog=catalog,
        annotator_id='authored-fixture', review_status='development_exposed')
    assert sum(f['semantic_id']=='sql.query' for f in contract.facts) == 2
    assert value == before


def test_minimal_graph_validation_does_not_certify_source_meaning():
    from prompt_mechanism_study.tsg.prompt_tsg import build_prompt_tsg, PromptTSGError
    catalog = open_concept_catalog()
    catalog['semantics']['write'] = 'task_operation'
    catalog['semantic_guidance']['write'] = 'Write a file.'
    # Deliberately wrong interpretation, but a valid source coordinate. The
    # compiler must not act as a semantic judge or impose an arbitrary node cap.
    passages = [f'Read file {i} without changing it.' for i in range(130)]
    passages[0] += ' source context' * 200
    prompt = '\n'.join(passages)
    facts = [dict(local_id=f'f{i}', node_type='task_operation', semantic_id='write',
                  evidence_text=text, occurrence=1, attributes={}) for i, text in enumerate(passages)]
    def build(rows, relations=()):
        return build_prompt_tsg(task_id='synthetic-structure-only', prompt=prompt,
            extractor_id='authored-incorrect-meaning', catalog=catalog, facts=rows, relations=relations)
    graph = build(facts)
    assert len(graph.nodes) == 131
    assert not any(e.edge_type == 'used_by' for e in graph.edges)
    bad = [dict(facts[0], occurrence=2)]
    with pytest.raises(PromptTSGError, match='evidence does not match'):
        build(bad)
    with pytest.raises(PromptTSGError):
        build([facts[0]], [dict(source='f0', target='missing', edge_type='precedes',
                               evidence_text=passages[0], occurrence=1)])


def test_positive_evidence_cannot_leak_to_unknown_or_conditional_scopes():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.scope_assessment import (
        assess_fixed_scope_response,
    )
    task, catalog, bound, request, response, ids = _conditional_scope_fixture()
    key, scope = next((k,s) for k,s in request['scopes'].items()
                     if s['concept_id']=='length' and not s['subjects'] and not s['conditions'])
    bad = deepcopy(response)
    bad['states'][key].update(expression='explicitly_required', requirements=[ids['length']])
    result = assess_fixed_scope_response(json.dumps(bad).encode(), request=request,
        contract=bound, prompt=task['prompt'], catalog=catalog)
    row = next(s for s in result["states"] if s['concept_id']=='length' and not s['subjects'] and not s['conditions'])
    assert row['state']=='unresolved' and row['rationale']=='No valid source-bound assessment.'
    assert any('positive expression lacks exact requirement-to-scope evidence' in n for n in result["unresolved_notes"])
    # A model's unresolved judgment stays unresolved; roles/types cannot fill it in.
    bad = deepcopy(response)
    key = next(k for k,scope in request['scopes'].items()
               if scope['concept_id']=='length' and scope['subjects']==[ids['sql.input']]
               and not scope['conditions'])
    bad['states'][key].update(applicability='unresolved')
    result = assess_fixed_scope_response(json.dumps(bad).encode(), request=request,
        contract=bound, prompt=task['prompt'], catalog=catalog)
    row = next(r for r in result["states"] if r['concept_id']=='length'
               and r['subjects']==[ids['sql.input']] and not r['conditions'])
    assert row['state']=='unresolved'
    assert result["source_contract_id"] == bound.contract_id


@pytest.mark.parametrize('role,expected', [
    ('resource', 'not_applicable'),
    ('input_unspecified', 'unresolved'),
    ('value_input', 'applicable'),
])
def test_model_judges_applicability_without_role_domain_rules(role, expected):
    from prompt_mechanism_study.tsg.scope_assessment import (
        assess_fixed_scope_response,
    )
    from prompt_mechanism_study.tsg.prompt_tsg import catalog_from_record
    task, catalog, canonical, _ = _source_fixture()
    catalog.update(feature_scope_domains={'sql.binding': 'subjects'})
    catalog_from_record(catalog)
    bound = _bound_records(task, catalog, canonical, roles={'x': role})
    input_id = next(f['local_id'] for f in bound.facts if f['semantic_id'] == 'sql.input')
    request = fixed_scope_request(bound, prompt=task['prompt'], catalog=catalog)
    key, scope = next((k, s) for k, s in request['scopes'].items() if s['subjects'] == [input_id])
    answers = {k: dict(expression='not_expressed', requirements=[],
        applicability=expected, applicability_rationale='Source establishes the SQL operation and this role.')
        for k in request['scopes']}
    def apply(rows):
        return assess_fixed_scope_response(json.dumps(dict(states=rows, unresolved_notes=[])).encode(),
            request=request, contract=bound, prompt=task['prompt'], catalog=catalog)
    result = apply(answers)
    actual = next(r for r in result["states"] if r['subjects'] == [input_id])['state']
    assert actual == ('absent' if expected == 'applicable' else expected)
    # Even a definite value-input role cannot certify an unstated SQL context
    # or a required caller origin. Concept membership cannot override this.
    answers[key]['applicability'] = 'unresolved'
    answers[key]['applicability_rationale'] = 'The source leaves the required operation context or caller origin unspecified.'
    assert next(r for r in apply(answers)["states"] if r['subjects'] == [input_id])['state'] == 'unresolved'
    answers[key]['applicability'] = expected
    answers[key]['expression'] = 'unresolved'
    assert next(r for r in apply(answers)["states"] if r['subjects'] == [input_id])['state'] == 'unresolved'
    answers[key]['expression'] = 'not_expressed'
    # The parser deliberately does not decide whether a resource is a valid operand.
    answers[key]['applicability'] = 'applicable'
    assert next(r for r in apply(answers)["states"] if r['subjects'] == [input_id])['state'] == 'absent'
    answers[key]['applicability'] = 'invalid'
    contradiction = apply(answers)
    assert next(r for r in contradiction["states"] if r['subjects'] == [input_id])['state'] == 'unresolved'
    assert any('unresolved_fixed_scope' in note for note in contradiction["unresolved_notes"])
    answers.pop(key)
    assert next(r for r in apply(answers)["states"] if r['subjects'] == [input_id])['state'] == 'unresolved'
    assert result["source_contract_id"] == bound.contract_id


def _bound_records(task, catalog, canonical, *, roles):
    from prompt_mechanism_study.tsg.source_records import record_request, compile_records
    request = record_request(contract_decision_request(task, catalog))
    records = record_annotation(request, canonical)
    for operation in records['operations']:
        for claim in operation['inputs']:
            claim['role'] = roles.get(claim['subject'], claim['role'])
    return compile_records(records, request=request, task=task, catalog=catalog,
        annotator_id='source-authored-offline-fixture', review_status='development_exposed')


def _conditional_scope_fixture():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.prompt_tsg import catalog_from_record
    prefix = 'The input x is text. '
    conditional = True
    conditional_text = 'When mode is safe, require input x to be at most 10 characters.'
    task, catalog, canonical, _ = _source_fixture(prefix +
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
    catalog.update(feature_scope_domains={'sql.binding':'subjects', 'length':'subjects'})
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
    bound = _bound_records(task, catalog, canonical, roles={'db': 'resource', 'x': 'value_input'})
    ids = {f['semantic_id']: f['local_id'] for f in bound.facts}
    request = fixed_scope_request(bound, prompt=task['prompt'], catalog=catalog)
    states = {}
    for key, scope in request['scopes'].items():
        states[key] = dict(expression='not_expressed', requirements=[])
        states[key].update(applicability='applicable' if scope['subjects']==[ids['sql.input']] else 'unresolved',
            applicability_rationale='An authored judgment for the exact conditional fixture, not a role-derived verdict.')
        if conditional and scope['concept_id']=='length' and ids['sql.input'] in scope['subjects']:
            exact = scope['subjects']==[ids['sql.input']] and scope['conditions']==[ids['condition.safe']]
            states[key].update(expression='explicitly_required' if exact else 'unresolved',
                requirements=[ids['length']] if exact else [])
    return task, catalog, bound, request, dict(states=states, unresolved_notes=[]), ids


@pytest.fixture
def atomic_records():
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
    from prompt_mechanism_study.tsg.source_records import record_request
    catalog = open_concept_catalog()
    request = record_request(contract_decision_request(task, catalog))
    return task, catalog, request, record_annotation(request, canonical)


def _compile_atomic(fixture, records):
    from prompt_mechanism_study.tsg.source_records import compile_records
    from prompt_mechanism_study.tsg.prompt_contract import compile_task_context_contract
    task, catalog, request, _ = fixture
    contract = compile_records(records, request=request, task=task, catalog=catalog,
        annotator_id='offline', review_status='development_exposed')
    return contract, compile_task_context_contract(contract, prompt=task['prompt'], catalog=catalog)


def test_shared_conditions_and_bounded_revision_follow_fields_not_prose(atomic_records):
    from copy import deepcopy
    from prompt_mechanism_study.tsg.source_records import structural_readback
    task, catalog, request, records = atomic_records
    contract, graph = _compile_atomic(atomic_records, records)
    requirements = [f for f in contract.facts if f['node_type'] == 'safety_requirement']
    assert len(requirements) == 2 and len({f['semantic_id'] for f in requirements}) == 2
    assert len({f['evidence_text'] for f in requirements}) == 1
    guard = next(n.node_id for n in graph.nodes if n.node_type == 'condition')
    assert {e.target_id for e in graph.edges if e.source_id == guard and e.edge_type == 'conditions'} == {
        n.node_id for n in graph.nodes if n.node_type == 'safety_requirement'}
    for requirement in requirements:
        assert {next(f['node_type'] for f in contract.facts if f['local_id'] == e['target'])
                for e in contract.relations if e['source'] == requirement['local_id'] and e['edge_type'] == 'constrains'} == {
                    'task_operation', 'data_object'}
    missing = deepcopy(records)
    missing['requirements'][0]['conditions'] = []
    # The correct prose must not restore a deleted structural condition.
    missing['requirements'][0]['fact']['concept']['definition'] += ' For external requests only.'
    assert isinstance(structural_readback(request, missing)['requirements']['binding']['requirement_guards'], str)
    review = dict(records={r['record_id']: dict(status='supported', reason='Authored reference.')
        for group in ('objects', 'operations', 'requirements') for r in records[group]},
        source_units={key: dict(complete=True, reason='Authored reference.') for key in request['source_units']})
    review['records']['binding'].update(status='unsupported', reason='Required external-request guard is missing.')
    responses = iter([missing, review, records])
    attempt = _attempt_task_contract(task, catalog=catalog, evaluator=dict(candidate_id='offline'),
        annotator_prompt='Authored revision fixture.', review_status='development_exposed',
        provider=lambda *_: json.dumps(next(responses)).encode())
    assert attempt.succeeded and attempt.provider_calls == 3
    assert attempt.binding_annotation['pre_review_records'] == missing
    assert attempt.contract.facts == contract.facts and attempt.contract.relations == contract.relations
    assert attempt.contract.source_inventory == contract.source_inventory


def test_frozen_predicate_does_not_freeze_its_source_bindings(atomic_records):
    from copy import deepcopy
    from prompt_mechanism_study.tsg.prompt_contract import freeze_open_concepts, catalog_sha256
    from prompt_mechanism_study.tsg.source_records import record_request
    task, _, _, records = atomic_records
    original, _ = _compile_atomic(atomic_records, records)
    frozen = freeze_open_concepts((original,), normalization_map={},
        definitions=original.catalog['semantic_guidance'], queries=[])
    identity = catalog_sha256(frozen)
    request = record_request(contract_decision_request(task, frozen))
    meanings = {(frozen['semantics'][k], d): k for k,d in frozen['semantic_guidance'].items()}
    def frozen_facts(value):
        if isinstance(value, list):
            return [frozen_facts(v) for v in value]
        if not isinstance(value, dict):
            return value
        row = {k:frozen_facts(v) for k,v in value.items() if k != 'concept'}
        if 'concept' in value:
            c = value['concept']
            row['concept_id'] = meanings[c['node_type'], c['definition']]
        return row
    records = frozen_facts(records)
    altered = deepcopy(records)
    altered['operations'][0]['inputs'] = []
    altered['operations'][0]['execution_conditions'] = deepcopy(altered['requirements'][0]['conditions'])
    before, _ = _compile_atomic((task,frozen,request,records), records)
    after, _ = _compile_atomic((task,frozen,request,records), altered)
    assert any(e['edge_type'] == 'used_by' for e in before.relations)
    assert not any(e['edge_type'] == 'used_by' for e in after.relations)
    operation = next(f['local_id'] for f in after.facts if f['node_type'] == 'task_operation' and f['evidence_text'] == 'query A')
    assert any(e['edge_type'] == 'conditions' and e['target'] == operation for e in after.relations)
    assert before.facts == after.facts and catalog_sha256(frozen) == identity


@pytest.mark.parametrize('kind', ['and', 'or', 'not'])
def test_composition_preserves_guards_without_asserting_alternative_leaves(atomic_records, kind):
    from copy import deepcopy
    from prompt_mechanism_study.tsg.prompt_tsg import graph_requirement_membership
    task, catalog, _, records = atomic_records
    records = deepcopy(records)
    parent = deepcopy(records['requirements'][0])
    parent.update(record_id='both', structure=dict(kind='and', members=['binding', 'length']),
        scope_kind='composite', operations=[], subjects=[])
    parent['fact']['concept'].update(concept_id='both', definition='Both binding and the length limit.')
    for leaf in records['requirements']:
        leaf['conditions'] = []
    records['requirements'].append(parent)
    if kind == 'or':
        parent['structure']['kind'] = 'or'
    elif kind == 'not':
        negated = deepcopy(parent)
        negated.update(record_id='negated', structure=dict(kind='not', members=['both']))
        negated['fact']['concept'].update(concept_id='negated', definition='Negate the conjunction.')
        records['requirements'].append(negated)
    contract, graph = _compile_atomic(atomic_records, records)
    leaves = {key for key, structure, _ in graph.requirement_structures if structure == 'atom'}
    asserted, atoms = graph_requirement_membership(graph)
    assert leaves <= asserted and leaves <= atoms if kind == 'and' else not leaves & asserted
    guard = next(n.node_id for n in graph.nodes if n.node_type == 'condition')
    assert leaves <= {e.target_id for e in graph.edges if e.source_id == guard and e.edge_type == 'conditions'}
    if kind != 'and':
        # Alternative/negated expression remains unknown, not absent.
        from dataclasses import replace
        from prompt_mechanism_study.tsg.prompt_tsg import catalog_sha256
        fixed = deepcopy(contract.catalog)
        feature = next(f['semantic_id'] for f in contract.facts if f['node_type'] == 'safety_requirement')
        operation = next(f['semantic_id'] for f in contract.facts if f['evidence_text'] == 'query A')
        fixed['queries'] = [dict(query_id='binding', actionable_feature_id=feature, required_semantics=[operation],
            forbidden_semantics=[], required_relations=[], realization_id='binding', cwe_id='source_semantics', task_family='source_semantics')]
        contract = replace(contract, catalog=fixed, input_catalog_sha256=catalog_sha256(fixed))
        assessed = fixed_scope_request(contract, prompt=task['prompt'], catalog=fixed)
        assert assessed['withheld_scopes'] and not assessed['scopes']


@pytest.mark.parametrize('scope', ['task', 'each'])
def test_whole_scope_is_not_broadcast_and_assumptions_are_not_candidates(atomic_records, scope):
    from copy import deepcopy
    from prompt_mechanism_study.tsg.candidate_construction import candidate_model_request, candidate_request
    task, catalog, _, records = atomic_records
    records = deepcopy(records)
    records['requirements'][0].update(scope_kind=scope, operations=[], subjects=[],
        target_class='database queries' if scope == 'each' else None)
    records['requirements'][1].update(modality='assumption')
    records['requirements'][1]['fact']['concept'].update(node_type='constraint',
        definition='The input is assumed to have at most ten characters.')
    contract, graph = _compile_atomic(atomic_records, records)
    whole = next(key for key,kind,_,_ in graph.requirement_scopes if kind == scope)
    assert not any(e.source_id == whole and e.edge_type == 'constrains' for e in graph.edges)
    assert any(e.target_id == whole and e.edge_type == 'conditions' for e in graph.edges)
    sources = candidate_model_request(candidate_request([task], [contract], input_catalog=catalog))['sources']
    assumption = next(n for n in sources[0]['nodes'] if n.get('statement_kind') == 'assumption')
    assert not assumption['complete_bindings']


def test_requirement_owned_order_preserves_targets_guards_and_state_blind_scope():
    from copy import deepcopy
    from dataclasses import replace
    from prompt_mechanism_study.tsg.source_records import (
        record_request,
        compile_records,
        structural_readback,
        review_request,
        revision_request,
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
    review['records']['publish'].update(status='unresolved', reason='Operation meaning remains unresolved.')
    assert revision_request(request, retract, review) is not None
    withdrawn = deepcopy(retract)
    withdrawn['operations'] = [r for r in withdrawn['operations'] if r['record_id'] != 'publish']
    with pytest.raises(PromptContractExtractionError):
        compile_value(withdrawn)  # Full revisions cannot leave dangling references.
    withdrawn['requirements'] = [r for r in withdrawn['requirements'] if r['record_id'] != 'order']
    withdrawn['coverage'][unit].update(status='unresolved', reason='Withdrawn meaning remains unresolved.')
    withdrawn['unit_impacts'][unit].update(effect='unresolved', operations=[], reason='Unresolved operation.')
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
    assert query_context(graph,query=query).state.value == 'present'
    assert query_context(removed,query=query).state.value == 'present'

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


def test_actual_attempt_passes_inventory_uncertainty_to_scope_model():
    task, catalog, canonical, _ = _source_fixture()
    calls = []
    def provider(request, _config, _prompt):
        calls.append(request["request_kind"])
        if request["request_kind"] == "source_only_fixed_scope_states":
            assert request['source_inventory_status']['status'] == 'INCOMPLETE'
            return json.dumps(dict(states={k:dict(expression='unresolved', requirements=[],
                applicability='unresolved', applicability_rationale='Source uncertainty affects this binding.')
                for k in request['scopes']}, unresolved_notes=[])).encode()
        if request['request_kind'] == 'source_only_record_review':
            assert request['effective_unit_impacts']
            assert request['compiled_operations']
            assert set(request['effective_unit_impacts']) == set(request['source_units'])
        value = record_annotation(request, canonical)
        if request["request_kind"] == "source_only_atomic_records":
            value["coverage"]["u1"].update(status="unresolved", reason="A relevant source meaning remains unresolved.")
        return json.dumps(value).encode()
    attempt = _attempt_task_contract(task, catalog=catalog, evaluator=dict(candidate_id="offline"),
        annotator_prompt="Source-authored synthetic fixture.", review_status="development_exposed", provider=provider)
    assert calls == ["source_only_atomic_records", "source_only_record_review", "source_only_fixed_scope_states"]
    assert attempt.provider_calls == 3 and attempt.error_type is None
    assert attempt.contract is not None and attempt.graph is not None
    assert attempt.scope_assessment["assessment"]["states"] and all(r['state']=='unresolved' for r in attempt.scope_assessment["assessment"]["states"])
    assert attempt.scope_assessment["provider_calls"] == 1
    assert attempt.scope_assessment["response_text"] is not None
    assert not attempt.scope_assessment["request"]["withheld_scopes"]
    # Exercise the active record compiler's local-impact declarations, not just
    # handcrafted contract metadata. Separate inputs prevent accidental sharing.
    from prompt_mechanism_study.tsg.source_records import record_request, compile_records
    task,catalog,canonical,_ = _source_fixture('Run query A using input x. Return the selected rows. Produce readable code. Run query B.')
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
    assert localized['scopes'] and not localized['withheld_scopes']
    assert localized['unit_impacts'][unit]['effect'] == 'local'
    records['unit_impacts'][unit].update(effect='global',operations=[])
    global_request = scopes()
    assert global_request['scopes'] == localized['scopes']
    assert global_request['unit_impacts'][unit]['effect'] == 'global'


def test_fixed_generation_facts_are_injected_once_and_never_redeclared_by_model():
    task, catalog, canonical, request = _source_fixture()
    template_ids = {n["local_id"] for n in request["fixed_template"]["nodes"]}
    from prompt_mechanism_study.tsg.source_records import record_request, compile_records
    active = record_request(request)
    facts = compile_records(record_annotation(active, canonical), request=active, task=task, catalog=catalog,
        annotator_id='authored-template', review_status='development_exposed')
    assert template_ids <= {f["local_id"] for f in facts.facts}
    assert len(facts.facts) == len(canonical["nodes"]) + len(template_ids)
    assert sum(r["source"].startswith("template.") for r in facts.relations) == 4
    assert all(facts.source_inventory["layers"][key] == "generation" for key in template_ids)

    # Same generation layer does not imply the same direct target. Keep the
    # module obligation separate from reply formatting using existing fields.
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
    result = qualify_prompt_contract_extractor(paths["tasks"], extraction, paths["catalog"],
        paths["reference"], paths["evaluator"], paths["prompt"],
        output, assertion_review_path=audit)
    assert [call["request_kind"] for call in calls] == ["source_only_atomic_records", "source_only_record_review", "source_only_fixed_scope_states"]
    assert result["task_units"] == 1 and result["failed_extraction_task_units"] == 0
    assert result["complete_task_units"] == 0
    assert result["status"] == "QUALIFICATION_FAILED" and result["scientific_claim_allowed"] is False
    scored = read_json(output / "case-results.json")[0]
    assert scored["source_inventory_status"]["status"] == "INCOMPLETE"
    assert scored["withheld_scope_count"] == 0
    assert scored["complete_task"] is False and scored["extraction_failed"] is False
    assert scored["raw_scope_response_sha256"] is not None

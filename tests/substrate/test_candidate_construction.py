from annotation_fixture import authored_contract
"""Graph-derived hypotheses preserve semantic granularity and source-only boundaries."""

import json
import pytest
from prompt_mechanism_study.tsg.prompt_contract import (
    compile_task_context_contract,
    open_concept_catalog,
    task_context_contract_record,
)
from prompt_mechanism_study.tsg.candidate_construction import (
    build_candidate_catalog,
    candidate_model_request,
    candidate_request,
    compile_candidate_proposal,
    prepare_candidate_request,
)
from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.tsg.source_codec import contract_decision_request
from prompt_mechanism_study.tsg.task_input import generation_template_facts, prepare_task_input
from prompt_mechanism_study.records import content_hash


def test_knowledge_add_keeps_source_provenance_unknown_and_conflict_separate():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.candidate_construction import knowledge_add_candidate
    from annotation_fixture import authored_two_output_candidate
    task, knowledge = authored_two_output_candidate()
    original = deepcopy(task['source_records'])
    proposal = task['proposal']
    assert proposal['decision'] == 'include'
    assert 'requirement_node_id' not in proposal['policy']
    assert proposal['policy']['targets'] == ['first_file', 'second_file']
    args = dict(source_prompt=task['prompt'], source_records=task['source_records'],
                knowledge=knowledge, binding=proposal['policy'])
    for changes, expected in [({'source_state':'UNRESOLVED'}, 'abstain'),
                              ({'compatibility':'conflict'}, 'reject'),
                              ({'complete_binding':False}, 'abstain')]:
        result = knowledge_add_candidate(**args, assessment={**proposal['assessment'], **changes})
        assert result['decision'] == expected and result['policy'] is None
    quote_changed = {**proposal['assessment'], 'evidence':['a paraphrase, not a located quotation']}
    result = knowledge_add_candidate(**args, assessment=quote_changed)
    assert result['decision'] == 'include' and result['evidence_diagnostics']
    assert result['assessment']['evidence'] == quote_changed['evidence']
    assert not result['automatic_semantic_certification']
    result = knowledge_add_candidate(**args, assessment={**quote_changed, 'relevance':'unsupported'})
    assert result['decision'] == 'abstain'
    with pytest.raises(ValueError, match='quotation'):
        knowledge_add_candidate(**args, assessment={**proposal['assessment'], 'evidence':['']})
    with pytest.raises(ValueError, match='existing'):
        knowledge_add_candidate(**{**args,'binding':{**args['binding'],'targets':['invented']}},
                                assessment=proposal['assessment'])
    for empty in ('targets', 'operations'):
        bound = {**args['binding'], empty: []}
        result = knowledge_add_candidate(**{**args, 'binding': bound}, assessment=proposal['assessment'])
        assert result['decision'] == 'include' and result['policy'][empty] == []
    with pytest.raises(ValueError, match='at least one'):
        knowledge_add_candidate(**{**args,'binding':{**args['binding'],'targets':[],'operations':[]}},
                                assessment=proposal['assessment'])
    broken = deepcopy(original)
    broken['objects'][0]['fact']['layer'] = 'generation'
    result = knowledge_add_candidate(**{**args,'source_records':broken,
                                      'binding':{**args['binding'],'targets':[]}}, assessment=proposal['assessment'])
    assert result['decision'] == 'abstain' and result['blocking_records']
    # No independent edit text can override or quietly broaden the binding.
    changed = {**args['binding'], 'edit_text':'Contradict every policy field.', 'conditions':['When the input is nonempty.']}
    result = knowledge_add_candidate(**{**args, 'binding':changed}, assessment=proposal['assessment'])
    assert 'Contradict' not in result['policy']['edit_text']
    assert 'When the input is nonempty.' in result['policy']['edit_text']
    for key in changed['targets']:
        row = next(r for r in original['objects'] if r['record_id']==key)
        assert row['fact']['concept']['definition'] in result['policy']['edit_text']
    for row in original['operations']:
        assert row['fact']['evidence_text'] in result['policy']['edit_text']
    unlocated = deepcopy(original)
    next(r for r in unlocated['objects'] if r['record_id']=='first_file')['fact']['evidence_text']='not a source quotation'
    result=knowledge_add_candidate(**{**args,'source_records':unlocated},assessment=proposal['assessment'])
    assert 'not a source quotation' not in result['policy']['edit_text'] and result['evidence_diagnostics']
    # A disconnected defect is preserved, never silently assumed unrelated.
    local = deepcopy(original)
    local['objects'].append(dict(record_id='unrelated', fact={}))
    result = knowledge_add_candidate(**{**args,'source_records':local}, assessment=proposal['assessment'])
    assert result['decision'] == 'abstain'
    judgment = {**proposal['assessment'], 'structural_dispositions':{
        'unrelated':dict(relevance='unrelated',rationale='Authored diagnostic: unused display object, no policy constraint.')}}
    result = knowledge_add_candidate(**{**args,'source_records':local}, assessment=judgment)
    assert result['decision'] == 'include' and result['structural_diagnostics']
    # An unrelated AND container is not itself a whole-task constraint.
    leaf = deepcopy(original['requirements'][0])
    leaf.update(record_id='display_rule',subjects=['unrelated'],operations=[])
    parent = deepcopy(leaf)
    parent.update(record_id='display_group',scope_kind='composite',subjects=[],
                  structure=dict(kind='and',members=['display_rule']))
    local['requirements'] += [leaf,parent]
    assert knowledge_add_candidate(**{**args,'source_records':local}, assessment=judgment)['decision']=='include'
    # Owned relation endpoints and incoming order are necessary context as well.
    related = deepcopy(local)
    related['requirements'][-2]['relations']=[dict(source='unrelated',target='write_first',edge_type='precedes',evidence_text='Authored diagnostic.')]
    assert knowledge_add_candidate(**{**args,'source_records':related}, assessment=judgment)['decision']=='abstain'
    related = deepcopy(original)
    related['operations'].append(dict(record_id='before',fact={},precedes=[dict(operation='write_first')]))
    before_judgment={**proposal['assessment'],'structural_dispositions':{'before':dict(relevance='unrelated',rationale='Attempted waiver.')}}
    assert knowledge_add_candidate(**{**args,'source_records':related},assessment=before_judgment)['decision']=='abstain'
    # A selected dependency or a global unknown constraint cannot be waived.
    local['requirements'].append(dict(record_id='global',scope_kind='task',fact={}))
    judgment['structural_dispositions']['global']=dict(relevance='unrelated',rationale='Incorrect attempted waiver.')
    assert knowledge_add_candidate(**{**args,'source_records':local}, assessment=judgment)['decision']=='abstain'
    assert task['source_records'] == original


def test_knowledge_response_preserves_valid_neighbors_unknown_cells_and_slot_budget():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.candidate_construction import compile_knowledge_add_response
    from annotation_fixture import authored_two_output_candidate
    task, knowledge = authored_two_output_candidate()
    key = knowledge['id']
    valid = dict(knowledge_id=key, binding={**task['proposal']['policy'], 'endpoint':key}, assessment=task['proposal']['assessment'])
    response = dict(assessments={key:dict(task['proposal']['assessment'], applicability='applicable'),
        'malformed':dict(applicability='applicable', source_state='not an allowed state')},
        proposals=[dict(knowledge_id='missing',binding=valid['binding']), valid, valid])
    original = deepcopy(response)
    args = dict(source_prompt=task['prompt'],source_records=task['source_records'],author='test',
        knowledge=[knowledge, {**knowledge,'id':'missing'}, {**knowledge,'id':'malformed'}])
    result = compile_knowledge_add_response(**args,response=response)
    assert result['assessments'][key] == response['assessments'][key]
    assert result['assessments']['missing'] is None and result['assessments']['malformed'] is None
    assert set(result['assessment_errors']) == {'missing','malformed'}
    assert 'error' in result['proposals'][0]
    assert result['proposals'][1]['compiled']['decision'] == 'include'
    assert 'budget' in result['proposals'][2]['error'] and 'compiled' not in result['proposals'][2]
    # Even a malformed proposal envelope must not erase independently supplied states.
    result = compile_knowledge_add_response(**args,response={**response,'proposals':None})
    assert result['assessments'][key] and result['response_errors'] and not result['proposals']
    # The complete scoped proposal cannot inherit a broad card's positive state.
    uncertain = {**valid, 'assessment':{**valid['assessment'], 'source_state':'UNRESOLVED'}}
    result = compile_knowledge_add_response(**args,response={**response,'proposals':[uncertain]})
    assert result['proposals'][0]['compiled']['decision']=='abstain'
    missing = {k:v for k,v in valid.items() if k!='assessment'}
    result = compile_knowledge_add_response(**args,response={**response,'proposals':[missing]})
    assert 'complete-binding assessment' in result['proposals'][0]['error']
    # Census answers do not gate independently assessed complete policies.
    for census in ({}, {key:dict(applicability='not_applicable',source_state='UNRESOLVED')}):
        result=compile_knowledge_add_response(**args,response=dict(assessments=census,proposals=[valid]))
        assert result['proposals'][0]['compiled']['decision']=='include'
    inferred_endpoint=deepcopy(valid)
    inferred_endpoint['binding'].pop('endpoint')
    result=compile_knowledge_add_response(**args,response=dict(assessments={},proposals=[inferred_endpoint]))
    assert result['proposals'][0]['compiled']['policy']['endpoint']==key
    result['proposals'][0]['compiled']['policy']['targets'].clear()
    assert inferred_endpoint['binding']['targets']  # No mutable alias back into the model response.
    assert response == original


def test_development_requests_keep_integrity_and_evidence_diagnostics_separate():
    from copy import deepcopy
    from prompt_mechanism_study.tsg.source_records import (
        development_record_request,
        validate_development_records,
    )
    from prompt_mechanism_study.tsg.candidate_construction import knowledge_add_model_request
    prompt = 'Read file x and return its content.'
    fact = lambda kind, text: dict(concept=dict(concept_id=kind, node_type=kind, definition=text),
                                  evidence_text=text, layer='runtime')
    records = dict(objects=[dict(record_id='x', fact=fact('data_object', 'file x'))],
        operations=[dict(record_id='read', fact=fact('task_operation', 'Read file x'),
            inputs=[dict(subject='x', role='resource', evidence_text='Read file x')], results=[],
            execution_conditions=[], scope_conditions=[], precedes=[])], requirements=[], unresolved_notes=[])
    view = validate_development_records(records, prompt)
    assert not view['semantic_certification'] and not view['evidence_diagnostics']
    bad = deepcopy(records)
    bad['operations'][0]['inputs'][0]['subject'] = 'invented'
    assert 'participant' in validate_development_records(bad, prompt)['structural_diagnostics'][0]['error']
    bad = deepcopy(records)
    bad['objects'][0]['fact']['layer'] = 'generation'
    assert 'runtime operation and object' in validate_development_records(bad, prompt)['structural_diagnostics'][0]['error']
    bad = deepcopy(records)
    bad['objects'][0]['fact']['evidence_text'] = 'private file'
    diagnostic = validate_development_records(bad, prompt)
    assert diagnostic['evidence_diagnostics'] == [dict(path='$.objects[0].fact.evidence_text',
        quotation='private file', status='unmatched', semantic_support='not_verified')]
    assert diagnostic['records']['x']['fact']['evidence_text'] == 'private file'
    second = knowledge_add_model_request(prompt, bad, [])
    assert second['source_records'] == bad
    assert second['evidence_diagnostics'] == diagnostic['evidence_diagnostics']
    bad['objects'][0]['fact']['evidence_text'] = ''
    assert 'quotation' in validate_development_records(bad, prompt)['structural_diagnostics'][0]['error']
    bad=deepcopy(records)
    bad['operations'][0]['execution_conditions']=[dict(evidence_text='Read file x')]
    assert validate_development_records(bad,prompt)['structural_diagnostics']
    # Neither prose whitespace nor code-literal changes are silently normalized.
    for original in ('Read\nfile x and return its content.', 'Read file x with code "a  b".'):
        changed = deepcopy(records)
        changed['objects'][0]['fact']['evidence_text'] = '"a b"' if 'code' in original else 'Read file x'
        assert validate_development_records(changed, original)['evidence_diagnostics']
        assert changed['objects'][0]['fact']['evidence_text'] not in original
    first = development_record_request(prompt)
    assert 'knowledge' not in first and first['source_prompt'] == prompt
    second = knowledge_add_model_request(prompt, records, [])
    assert second['source_records'] == records
    assert not {'outcomes', 'tests', 'references'} & second.keys()


def _development_sources(*, include_template=False):
    """Artificial source facts exercise construction, never natural support or accuracy."""
    cases = [
        (
            "synthetic-two-atomic",
            "Run a SQL query using value x. Bind value x and reject values longer than ten characters.",
            [
                ("op", "task_operation", "sql_query", "Run a SQL query"),
                ("value", "data_object", "query_value", "value x"),
                ("binding", "safety_requirement", "parameter_binding", "Bind value x"),
                ("length", "safety_requirement", "input_length",
                 "reject values longer than ten characters"),
            ],
        ),
        (
            "synthetic-equivalent",
            "Run a SQL query using value y. Pass value y as a bound query parameter.",
            [
                ("op", "task_operation", "sql_query", "Run a SQL query"),
                ("value", "data_object", "query_value", "value y"),
                ("requirement", "safety_requirement", "parameter_binding",
                 "Pass value y as a bound query parameter"),
            ],
        ),
    ]
    tasks, contracts = [], []
    for task_id, prompt, facts in cases:
        task = dict(task_id=task_id, task_unit_id=task_id, near_duplicate_group_id=task_id,
                    prompt=prompt, language="python", api_family="database",
                    task_archetype="query", source_lineage_id="synthetic-source",
                    source_kind="synthetic_development", covariates=[])
        response = dict(
            concepts=[dict(concept_id=concept, node_type=kind, definition=concept)
                      for _, kind, concept, _ in facts],
            nodes=[dict(local_id=local, concept_id=concept, evidence_text=quote, occurrence=1)
                   for local, _, concept, quote in facts],
            edges=[dict(source_node_local_id=source, edge_type=relation,
                        target_node_local_id=target, evidence_text=prompt, occurrence=1)
                   for source, relation, target in [
                       ("value", "used_by", "op"),
                       *[(local, "constrains", target) for local, kind, _, _ in facts
                         if kind == "safety_requirement" for target in ("op", "value")],
                   ]],
            concept_states=[], unresolved_notes=[],
        )
        if include_template:
            task = prepare_task_input(task)
            template = generation_template_facts(task)
            for key in ("concepts", "nodes", "edges"):
                response[key].extend(template[key])
        contracts.append(authored_contract(
            response, task=task, catalog=open_concept_catalog(), annotator_id="synthetic-offline",
            review_status="development_exposed"))
        tasks.append(task)
    return tasks, contracts


def _design():
    return dict(
        outcome_id="oracle_evaluable_secure_code_yield",
        language_scope=["python"],
        api_scope=["database"],
        task_archetype_scope=["query"],
        operations=["add", "remove"],
        model_id="synthetic-offline",
        covariate_names=[],
        support_rule=dict(
            minimum_state_task_units=2,
            minimum_shared_lineages=1,
            maximum_unresolved_fraction=0.2,
            minimum_feature_reliability=0.8,
        ),
    )


def _proposal(request):
    occurrences, dispositions = {"parameter_binding": [], "input_length": []}, []
    for source in request["sources"]:
        nodes = {node["concept_id"]: node for node in source["nodes"]}
        for node in source["nodes"]:
            if node["concept_id"] in occurrences:
                occurrences[node["concept_id"]].append(dict(
                    task_id=source["task_id"], requirement_node_ids=[node["node_id"]],
                    scope=dict(operation_node_id=nodes["sql_query"]["node_id"],
                               subject_node_ids=[nodes["query_value"]["node_id"]], condition_node_ids=[])))
            if node["node_type"] in {"safety_requirement", "task_requirement", "constraint", "presentation_control"}:
                dispositions.append(dict(task_id=source["task_id"], requirement_node_id=node["node_id"],
                    status="included" if node["concept_id"] in occurrences else "not_actionable",
                    rationale="Synthetic source factor; fixed implementation and output requirements remain unchanged."))
    return dict(factors=[
        dict(label="Bound SQL value", definition="Require the specified SQL data value to be passed as a bound parameter.",
             atomicity_rationale="One requirement about SQL value parameter binding; length checking remains separate.",
             occurrences=occurrences["parameter_binding"]),
        dict(label="Ten-character limit", definition="Require rejecting the specified SQL data value when longer than ten characters.",
             atomicity_rationale="One requirement about input length; parameter binding remains separate.",
             occurrences=occurrences["input_length"]),
    ], dispositions=dispositions)


def _review(request, response, draft):
    return dict(request_sha256=content_hash(request), response_sha256=content_hash(response),
                reviewer_id="synthetic-authored-review", arms_or_outcomes_used=False,
                decisions=[dict(feature_id=factor["feature_id"], decision="accept",
                                rationale="Synthetic fixture verifies separate source-backed decisions only.",
                                source_supported=True, single_requirement=True, normalization_valid=True,
                                context_independent=True, scope_preserves_task=True)
                           for factor in draft["factors"]])


def _bare_decisions(request, response):
    """Translate authored decisions only; expectations retain their original full scopes."""
    wire = candidate_model_request(request)
    refs = {}
    for source, short in zip(request["sources"], wire["sources"], strict=True):
        assert source["source_prompt"] == short["source_prompt"]
        for node, item in zip(sorted(source["nodes"], key=lambda n: n["node_id"]), short["nodes"], strict=True):
            refs[source["task_id"], node["node_id"]] = item["node_ref"]
            assert node["definition"] == item["definition"]
    decisions = {}
    for factor in response["factors"]:
        for row in factor["occurrences"]:
            for requirement in row["requirement_node_ids"]:
                ref = refs[row["task_id"], requirement]
                decision = dict(status="include", label=factor["label"], definition=factor["definition"],
                                rationale=factor["atomicity_rationale"])
                assert ref not in decisions or decisions[ref] == decision
                decisions[ref] = decision
    decisions.update({refs[row["task_id"], row["requirement_node_id"]]: dict(
        status=row["status"], label="", definition="", rationale=row["rationale"])
        for row in response["dispositions"] if row["status"] != "included"})
    return dict(decisions=decisions)


def _compact_response(request, response):
    return _explicit_background_response(request, response)


def _explicit_background_response(request, response, evidence_text=None, *, operation_definition=None,
                                  subject_definitions=None):
    """Authored current-wire decisions; no source semantics are certified by this helper."""
    compact = _bare_decisions(request, response)
    for source in candidate_model_request(request)["sources"]:
        quote = evidence_text or source["source_prompt"]
        override = next((n["node_ref"] for n in source["nodes"] if n["definition"] == operation_definition), None)
        for node in source["nodes"]:
            if "complete_bindings" not in node:
                continue
            decision = compact["decisions"][node["node_ref"]]
            decision["applicability_bindings"] = {}
            for binding in node["complete_bindings"]:
                if decision["status"] != "include":
                    decision["applicability_bindings"][binding["binding_ref"]] = None
                    continue
                operation = override or binding["operation_ref"]
                subjects = (sorted(n["node_ref"] for n in source["nodes"] if n["definition"] in subject_definitions)
                            if subject_definitions is not None else binding["subject_refs"])
                guards = sorted(e["source_ref"] for e in source["edges"]
                                if e["edge_type"] == "conditions" and e["target_ref"] == operation)
                inputs = {e["source_ref"] for e in source["edges"]
                          if e["edge_type"] == "used_by" and e["target_ref"] == operation}
                if binding["scope_kind"] in {"objects", "task"} and operation == binding["operation_ref"]:
                    inputs = set(binding["subject_refs"])
                retained = {operation, *subjects, *guards}
                decision["applicability_bindings"][binding["binding_ref"]] = dict(
                    operation_ref=operation, subject_refs=subjects, execution_condition_refs=guards,
                    independent_source_evidence=[dict(evidence_text=quote, occurrence=1)],
                    rationale="Authored reference: the cited non-target task requires this actual background without the policy.",
                    component_decisions=[dict(node_ref=key, decision="retain" if key in retained else "omit_not_needed",
                        source_evidence=[dict(evidence_text=quote, occurrence=1)],
                        rationale="Authored retained coordinate." if key in retained else
                                  "The retained operation and subjects distinguish the comparison without this input.")
                        for key in sorted({operation, *inputs, *guards})])
    return compact


def _source_bindings(proposal):
    return sorted((f["definition"], o["task_id"], tuple(o["requirement_node_ids"]),
                   json.dumps(o["scope"], sort_keys=True))
                  for f in proposal["factors"] for o in f["source_occurrences"])


def _prepared_proposal():
    tasks, contracts = _development_sources()
    request = candidate_request(tasks, contracts)
    response, design = _proposal(request), _design()
    draft = compile_candidate_proposal(request, response, design)
    return request, response, design, draft


def test_atomic_source_nodes_stay_separate_and_equivalent_occurrences_pool_before_review():
    request, response, design, draft = _prepared_proposal()
    factors = {factor["label"]: factor for factor in draft["factors"]}
    assert len(factors) == 2
    binding = factors["Bound SQL value"]["source_occurrences"]
    length = factors["Ten-character limit"]["source_occurrences"]
    assert len(binding) == 2 and len(length) == 1
    first_binding = next(row for row in binding if row["task_id"] == "synthetic-two-atomic")
    assert first_binding["requirement_node_ids"] != length[0]["requirement_node_ids"]
    assert draft["status"] == "PENDING_SEMANTIC_REVIEW"
    assert all(factor["review_decision"] == "pending" for factor in factors.values())
    assert draft["policies"] == [] and draft["queries"] == []
    assert draft["scientific_claim_allowed"] is False
    assert draft["formal_execution_authorized"] is False
    compact = _compact_response(request, response)
    selected = compile_candidate_proposal(request, compact, design)
    assert _source_bindings(selected) == _source_bindings(draft)
    assert selected["response_sha256"] == content_hash(compact)
    assert all(source["task_id"] not in json.dumps(candidate_model_request(request)) for source in request["sources"])
    # A model cannot revise targets/conditions, invent keys, skip units or bundle nodes.
    for change in ("invented", "scope", "omission", "old_wire"):
        altered = json.loads(json.dumps(compact))
        first = next(iter(altered["decisions"]))
        if change == "invented":
            altered["decisions"]["T999.N999"] = altered["decisions"].pop(first)
        elif change == "scope":
            altered["decisions"][first]["scope"] = {}
        elif change == "old_wire":
            altered["decisions"][first].pop("applicability_bindings")
        else:
            altered["decisions"].pop(first)
        with pytest.raises(ValueError, match="requirement decision.*fields"):
            compile_candidate_proposal(request, altered, design)


def _one_requirement_request(*, compound):
    """One source node may repeat its meaning across scopes, never change its meaning."""
    task = dict(task_id="synthetic-one-requirement", language="python")
    if compound:
        task["prompt"] = "Run a SQL query using value x. Bind value x and reject values longer than ten characters."
        operations = [("op", "task_operation", "sql_query", "Run a SQL query")]
        requirement = ("requirement", "safety_requirement", "binding_and_length",
                       "Bind value x and reject values longer than ten characters")
    else:
        task["prompt"] = "Read value x in query A and write value x in query B. Bind value x in both queries."
        operations = [("read", "task_operation", "sql_read", "Read value x in query A"),
                      ("write", "task_operation", "sql_write", "write value x in query B")]
        requirement = ("requirement", "safety_requirement", "parameter_binding", "Bind value x in both queries")
    facts = [*operations, ("value", "data_object", "query_value", "value x"), requirement]
    links = [("requirement", "constrains", "value")]
    for local, _, _, _ in operations:
        links.extend([("value", "used_by", local), ("requirement", "constrains", local)])
    response = dict(
        concepts=[dict(concept_id=concept, node_type=kind, definition=concept) for _, kind, concept, _ in facts],
        nodes=[dict(local_id=local, concept_id=concept, evidence_text=quote, occurrence=1)
               for local, _, concept, quote in facts],
        edges=[dict(source_node_local_id=source, edge_type=relation, target_node_local_id=target,
                    evidence_text=task["prompt"], occurrence=1) for source, relation, target in links],
        concept_states=[], unresolved_notes=[])
    contract = authored_contract(response, task=task, catalog=open_concept_catalog(),
                                           annotator_id="synthetic-offline", review_status="development_exposed")
    request = candidate_request([task], [contract])
    nodes = {node["concept_id"]: node for node in request["sources"][0]["nodes"]}
    requirement_id = nodes[requirement[2]]["node_id"]
    occurrences = [dict(task_id=task["task_id"], requirement_node_ids=[requirement_id],
        scope=dict(operation_node_id=nodes[concept]["node_id"],
                   subject_node_ids=[nodes["query_value"]["node_id"]], condition_node_ids=[]))
        for _, _, concept, _ in operations]
    disposition = dict(task_id=task["task_id"], requirement_node_id=requirement_id, status="included",
                       rationale="Synthetic source evidence for the candidate granularity boundary.")
    return request, occurrences, disposition


def test_compound_source_node_cannot_be_split_into_different_candidate_meanings():
    request, occurrences, disposition = _one_requirement_request(compound=True)
    response = dict(factors=[
        dict(label="Bound SQL value", definition="Require bound SQL parameters.",
             atomicity_rationale="Parameter binding is independent of length validation.", occurrences=occurrences),
        dict(label="Ten-character limit", definition="Require rejecting inputs longer than ten characters.",
             atomicity_rationale="Length validation is independent of parameter binding.", occurrences=occurrences),
    ], dispositions=[disposition])
    with pytest.raises(ValueError, match="source requirement node cannot be split into different candidate meanings"):
        compile_candidate_proposal(request, response, _design())
    response["factors"] = []
    disposition.update(status="unresolved", rationale="The compound requirement must first be split in the source TSG.")
    unresolved = compile_candidate_proposal(request, response, _design())
    assert unresolved["factors"] == unresolved["policies"] == []
    assert unresolved["dispositions"][0]["status"] == "unresolved"
    # One unit can retain several source-bound operations; the model does not choose a subset.
    request, occurrences, disposition = _one_requirement_request(compound=False)
    response = dict(factors=[dict(label="Binding", definition="Bind the data value in both queries.",
        atomicity_rationale="One shared requirement at both stated operations.", occurrences=occurrences)],
        dispositions=[disposition])
    legacy = compile_candidate_proposal(request, response, _design())
    compact = _compact_response(request, response)
    assert len(compact["decisions"]) == 1
    assert _source_bindings(compile_candidate_proposal(request, compact, _design())) == _source_bindings(legacy)


def test_reviewed_factors_emit_both_atomic_edits_without_support_filtering():
    request, response, design, draft = _prepared_proposal()
    # Deliberately impossible natural-support counts cannot suppress proposal construction.
    design["support_rule"]["minimum_state_task_units"] = 10_000
    compiled = compile_candidate_proposal(
        request, response, design, _review(request, response, draft)
    )
    atomic = [policy for policy in compiled["policies"] if "factor" in policy]
    features = {factor["feature_id"] for factor in compiled["factors"]}
    assert len(atomic) == len(compiled["policies"]) == 4
    assert {
        (policy["factor"]["actionable_feature_id"], policy["factor"]["operation"])
        for policy in atomic
    } == {(feature, operation) for feature in features for operation in ("add", "remove")}
    for query in compiled["queries"]:
        context = set(query["required_semantics"]) | set(query["forbidden_semantics"])
        context.update(
            concept
            for source, _, target in query["required_relations"]
            for concept in (source, target)
        )
        assert not features & context
        assert any(
            compiled["source_types"][concept] == "task_operation"
            for concept in query["required_semantics"]
        )
    assert compiled["formal_execution_authorized"] is False


@pytest.mark.parametrize("change", ["missing_disposition", "invented_requirement", "narrowed_scope"])
def test_candidate_evidence_must_cover_real_requirements_and_their_exact_scope(change):
    request, response, design, _ = _prepared_proposal()
    occurrence = response["factors"][0]["occurrences"][0]
    if change == "missing_disposition":
        response["dispositions"].pop()
    elif change == "invented_requirement":
        occurrence["requirement_node_ids"] = [occurrence["scope"]["operation_node_id"]]
    else:
        occurrence["scope"]["subject_node_ids"] = []
    with pytest.raises(ValueError, match="dispositions|requirement evidence|subject set"):
        compile_candidate_proposal(request, response, design)


def test_rejected_or_unresolved_semantics_are_retained_without_policies():
    request, response, design, draft = _prepared_proposal()
    review = _review(request, response, draft)
    for decision, status in zip(review["decisions"], ("reject", "unresolved"), strict=True):
        decision["decision"] = status
        decision["single_requirement"] = False
    compiled = compile_candidate_proposal(request, response, design, review)
    assert {factor["review_decision"] for factor in compiled["factors"]} == {"reject", "unresolved"}
    assert len(compiled["factors"]) == 2 and compiled["policies"] == []


def _write_candidate_request(tmp_path, *, include_template=False):
    tasks, contracts = _development_sources(include_template=include_template)
    task_path = tmp_path / "source-tasks.json"
    task_path.write_text(json.dumps(tasks), encoding="utf-8")
    extraction = write_bundle(tmp_path / "extraction", {
        "report.json": dict(review_status="development_exposed", arms_or_outcomes_used=False),
        "tasks.json": tasks, "contracts.json": [task_context_contract_record(contract) for contract in contracts],
    })
    request_bundle = tmp_path / "request"
    prepared = prepare_candidate_request(task_path, extraction, request_bundle)
    assert prepared["provider_calls"] == 0
    return tasks, contracts, task_path, extraction, request_bundle


def test_generated_catalog_preserves_fixed_template_and_enters_real_frozen_extractor(tmp_path):
    tasks, _, _, _, request_bundle = _write_candidate_request(tmp_path, include_template=True)
    request = read_json(request_bundle / "request.json")
    response, design = _explicit_background_response(request, _proposal(request), "Run a SQL query"), _design()
    assert read_json(request_bundle / "model-request.json") == candidate_model_request(request)
    draft = compile_candidate_proposal(request, response, design)
    paths = [tmp_path / name for name in ("response.json", "design.json", "review.json")]
    for path, value in zip(paths, (response, design, _review(request, response, draft)), strict=True):
        path.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "candidate-catalog"
    report = build_candidate_catalog(request_bundle, paths[1], output, response_path=paths[0], review_path=paths[2])
    assert report["status"] == "REVIEWED" and report["accepted_factors"] == 2
    from prompt_mechanism_study.tsg.candidate_construction import _proposal_evaluator
    config = dict(schema_version="1.0", candidate_id="frozen-test-proposer", provider="local_vllm",
        model_id="test-local-model", base_url="http://127.0.0.1:9999/v1", api_key_env=None,
        temperature=0.3, top_p=0.9, seed=7, enable_thinking=True, timeout_seconds=60,
        max_response_bytes=1000000, max_attempts=1, maximum_input_bytes=1000000, maximum_output_tokens=4096)
    config_path = tmp_path / "proposer.json"
    for provider, credential in (("deepseek", "TEST_DEEPSEEK_KEY"), ("ali_bailian_pay_as_you_go", "TEST_CLOUD_KEY")):
        alternative = dict(config, provider=provider, api_key_env=credential, base_url="https://example.invalid/v1")
        config_path.write_text(json.dumps(alternative), encoding="utf-8")
        assert _proposal_evaluator(config_path) == alternative
    config_path.write_text(json.dumps(config), encoding="utf-8")
    assert _proposal_evaluator(config_path) == config
    catalog = read_json(output / "catalog.json")
    prepared_task = prepare_task_input(tasks[0])
    extraction_request = contract_decision_request(prepared_task, catalog)
    template = generation_template_facts(prepared_task)
    assert extraction_request["fixed_template"] == template
    for concept in template["concepts"]:
        identifier = concept["concept_id"]
        assert catalog["semantics"][identifier] == concept["node_type"]
        assert catalog["semantic_guidance"][identifier] == concept["definition"]
        assert catalog["normalization_map"][concept["node_type"] + "::" + identifier] == identifier
        assert identifier not in extraction_request["known_concepts"]
    assert len(extraction_request["fixed_template"]["nodes"]) == 5
    assert all(factor["feature_id"] not in {row["concept_id"] for row in template["concepts"]}
               for factor in read_json(output / "proposal.json")["factors"])


def _whole_policy_source(kind, text, *, present=True, guard=False, choice=False,
                         catalog=None, feature=None, prompt=None, object_uses=0,
                         object_subjects=("buffer",), owned_order=False):
    """Authored structures isolate projection/editing, not automatic extraction quality."""
    from dataclasses import replace
    invariant = "The entire task must preserve the status format."
    if owned_order:
        invariant = "Processing must finalize the status format before returning status."
    base = "Process the request and write the diagnostic log. Return status. " + invariant
    if owned_order:
        base += " Processing precedes returning."
    if kind == "objects":
        base += " The input buffer and saved path are available."
    task = dict(task_id="synthetic-complete-policy", language="python",
                prompt=prompt if prompt is not None else base + (" " + text if present else ""))
    rows = [("op", "task_operation", "processing", "Process the request and write the diagnostic log"),
            ("return", "task_operation", "returning", "Return status"),
            ("invariant", "task_requirement", "status_format", invariant)]
    if kind == "objects":
        rows.extend((("buffer", "data_object", "buffer", "input buffer"),
                     ("path", "data_object", "path", "saved path")))
    if present:
        rows.append(("r", "safety_requirement", "policy", text))
        if guard:
            rows.append(("g", "condition", "failure", "If processing fails"))
        if choice:
            rows.extend((key, "safety_requirement", key, quote) for key, quote in
                        (("redact", "redaction"), ("omit", "omission")))
            if choice == "not":
                rows.append(("both", "safety_requirement", "both", "redaction and omission"))
    selected = "op" if kind in {"targets", "each_function"} else "task.root"
    structures = ({"r": dict(kind="or" if choice else "atom", members=["redact", "omit"] if choice else [])}
                  if present else {})
    structures["invariant"] = dict(kind="atom", members=[])
    if choice and present:
        structures.update({key: dict(kind="atom", members=[]) for key in ("redact", "omit")})
        if choice == "not":
            structures.update(r=dict(kind="not", members=["both"]), both=dict(kind="and", members=["redact", "omit"]))
    targets = ["redact", "omit"] if choice else ["r"]
    links = ([(key, "constrains", "op") for key in targets] if present and kind == "targets" else [])
    if kind == "objects":
        links += [(key, "constrains", obj) for key in targets for obj in object_subjects] if present else []
        links += [(obj, "used_by", op) for obj in object_subjects for op in ("op", "return")[:object_uses]]
    if present and guard:
        links.append(("g", "conditions", "r"))
    concepts = [dict(concept_id=concept, node_type=node_type, definition=quote)
                for _, node_type, concept, quote in rows]
    identities = {concept: concept for _, _, concept, _ in rows}
    if catalog is not None:
        identities = {concept: (feature if key == "r" else catalog["normalization_map"][node_type + "::" + concept])
                      for key, node_type, concept, _ in rows}
    supplied = dict(concepts=concepts if catalog is None else [],
        nodes=[dict(local_id=key, concept_id=identities[concept], evidence_text=quote, occurrence=1)
               for key, _, concept, quote in rows],
        edges=[dict(source_node_local_id=a, edge_type=relation, target_node_local_id=b,
                    evidence_text=task["prompt"], occurrence=1) for a, relation, b in links],
        concept_states=[], unresolved_notes=[])
    supplied_catalog = catalog or open_concept_catalog()
    contract = authored_contract(supplied, task=task, catalog=supplied_catalog,
        annotator_id="authored-projection-reference", review_status="development_exposed")
    retained = {"invariant": dict(kind="task", boundaries=[], target_class=None)}
    if present and kind not in {"targets", "objects"}:
        retained["r"] = dict(kind="task" if kind == "task" else "each",
                             boundaries=["op"] if kind == "each_function" else [],
                             target_class=None if kind == "task" else "diagnostic log entries")
    inventory = dict(source_units={"u": dict(evidence_text=task["prompt"], occurrence=1)},
        coverage={"u": dict(status="represented", facts=[key for key, _, _, _ in rows], reason="Authored semantic contrast.")},
        layers={key: "runtime" for key, _, _, _ in rows},
        operation_roles=[dict(operation=b, subject=a, role="value_input",
                              evidence_text=task["prompt"], occurrence=1)
                         for a, relation, b in links if relation == "used_by"],
        requirement_structures=structures, requirement_scopes=retained)
    contract = replace(contract, source_inventory=inventory)
    if owned_order:
        def order(evidence):
            return dict(source="op", edge_type="precedes", target="return", evidence_text=evidence, occurrence=1)
        inventory["requirement_relations"] = {"invariant": [order(invariant)]}
        if present:
            inventory["requirement_relations"]["r"] = [order(text)]
        # This separately sourced order is deliberately also shared by two
        # distinct policies; deleting one owner must not delete either support.
        contract = replace(contract, relations=contract.relations + (order("Processing precedes returning."),))
    graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=supplied_catalog)
    return task, contract, graph, selected





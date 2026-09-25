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
from prompt_mechanism_study.tsg.prompt_tsg import prompt_tsg_record
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


def test_generated_catalog_preserves_fixed_template_and_enters_real_frozen_extractor(tmp_path, monkeypatch):
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
    sent = []
    def fake_complete(model_request, evaluator, prompt):
        sent.append(model_request)
        return json.dumps(response).encode()
    monkeypatch.setattr("prompt_mechanism_study.llm.complete_chat", fake_complete)
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
    proposed = build_candidate_catalog(request_bundle, paths[1], tmp_path / "mock-provider-proposal", evaluator_path=config_path)
    assert read_json(tmp_path / "mock-provider-proposal/evaluator.json") == config
    assert sent == [candidate_model_request(request)]
    assert proposed["status"] == "PENDING_SEMANTIC_REVIEW" and proposed["accepted_factors"] == 0
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


def test_complete_policy_projection_and_both_edits_preserve_scope_and_internal_conditions(record_property):
    from dataclasses import replace
    from prompt_mechanism_study.tsg.candidate_construction import (
        _candidate_catalog,
        choose_candidate_scope,
    )
    from prompt_mechanism_study.tsg.scope_assessment import (
        fixed_scope_request,
        assess_fixed_scope_response,
    )
    from prompt_mechanism_study.tsg.prompt_tsg import (
        requirement_owned_nodes,
        PromptTSGError,
        catalog_sha256,
    )
    from prompt_mechanism_study.tsg.prompt_contract_qualification import (
        open_graph_assertions,
        evaluate_open_semantic_case,
    )
    from prompt_mechanism_study.discovery.mechanisms import (
        bind_task_hypothesis,
        render_task_hypothesis,
        MechanismRegistryError,
    )
    cases = [
        ("conditional", "targets", "If processing fails, do not include access tokens in the diagnostic log.", True, False),
        ("whole", "task", "The entire task must allocate at most 1 MB in total.", False, False),
        ("universal", "each", "Every diagnostic log entry must redact access tokens.", False, False),
        ("bounded_universal", "each_function", "Every diagnostic log entry in request processing must redact access tokens.", False, False),
        ("choice", "targets", "Use redaction or omission for access tokens in the diagnostic log.", False, True),
        ("compound_prohibition", "targets", "Do not combine redaction and omission for access tokens in the diagnostic log.", False, "not"),
        ("before", "targets", "Redact access tokens before writing the diagnostic log.", False, False),
        ("after", "targets", "Redact access tokens after writing the diagnostic log.", False, False),
        ("owned_order", "targets", "Sanitize access tokens during request processing before returning status.", False, False),
        ("object_unused", "objects", "The input buffer must contain at most 256 KB.", False, False),
        ("object_used", "objects", "The input buffer must contain at most 256 KB.", False, False),
        ("object_shared", "objects", "The input buffer must contain at most 256 KB.", False, False),
        ("object_guard", "objects", "If processing fails, the input buffer must contain no credentials.", True, False),
        ("object_set", "objects", "Do not disclose the values of the input buffer or saved path.", False, False),
        ("object_choice", "objects", "Use redaction or omission for credentials in the input buffer.", False, True),
    ]
    results, factors = [], {}
    for name, kind, text, guard, choice in cases:
        options = dict(object_uses={"object_used": 1, "object_shared": 2}.get(name, 0),
                       object_subjects=("buffer", "path") if name == "object_set" else ("buffer",),
                       owned_order=name == "owned_order")
        task, contract, graph, selected = _whole_policy_source(kind, text, guard=guard, choice=choice, **options)
        before_projection = prompt_tsg_record(graph)
        request = candidate_request([task], [contract])
        by_meaning = {n["concept_id"]: n for n in request["sources"][0]["nodes"]}
        scope = dict(operation_node_id=by_meaning["processing" if selected == "op" else "task.root"]["node_id"],
                     subject_node_ids=sorted(by_meaning[key]["node_id"] for key in options["object_subjects"]) if kind == "objects" else [],
                     condition_node_ids=[by_meaning["failure"]["node_id"]] if guard else [])
        response = dict(factors=[dict(label=name, definition=text,
            atomicity_rationale="One complete policy; conditions, boundary and alternatives are internal to this policy.",
            occurrences=[dict(task_id=task["task_id"], requirement_node_ids=[by_meaning["policy"]["node_id"]], scope=scope)])],
            dispositions=[dict(task_id=task["task_id"], requirement_node_id=node["node_id"],
                status="included" if node["concept_id"] == "policy" else "not_actionable",
                rationale="Whole policy only; choice members are not independently asserted.")
                for node in request["sources"][0]["nodes"] if node["node_type"] in {"safety_requirement", "task_requirement"}])
        draft = compile_candidate_proposal(request, response, _design())
        compact = _compact_response(request, response)
        selected_draft = compile_candidate_proposal(request, compact, _design())
        assert _source_bindings(selected_draft) == _source_bindings(draft)
        draft = selected_draft
        if choice:
            child = next(n for n in candidate_model_request(request)["sources"][0]["nodes"]
                         if n["node_type"] == "safety_requirement" and n["complete_bindings"] == [])
            invalid = json.loads(json.dumps(compact))
            invalid["decisions"][child["node_ref"]] = dict(status="include", label="Member",
                definition=child["definition"], rationale="A member is not an independently asserted requirement.", applicability_bindings={})
            with pytest.raises(ValueError, match="no complete source binding"):
                compile_candidate_proposal(request, invalid, _design())
        if kind in {"task", "each", "objects"}:
            # The current interface preserves task/object/quantified policies and
            # keeps internal policy guards outside the comparison background.
            response = _explicit_background_response(request, response,
                evidence_text="Process the request and write the diagnostic log. Return status.")
            draft = compile_candidate_proposal(request, response, _design())
        else:
            response = compact
        reviewed = compile_candidate_proposal(request, response, _design(), _review(request, response, draft))
        assert prompt_tsg_record(graph) == before_projection
        factor = reviewed["factors"][0]
        feature, selector = factor["feature_id"], factor["scope_selector"]
        factors[name] = feature
        assert selector["policy_condition_semantic_ids"] or not guard
        assert selector["condition_semantic_ids"] == []
        assert len(reviewed["policies"]) == 2
        catalog = _candidate_catalog([contract], reviewed, _design(), reviewed["review"])

        def assessed(present, prompt=None):
            fresh_task, fresh, fresh_graph, _ = _whole_policy_source(kind, text, present=present,
                guard=guard, choice=choice, catalog=catalog, feature=feature, prompt=prompt, **options)
            req = fixed_scope_request(fresh, prompt=fresh_task["prompt"], catalog=catalog)
            assert len(req["scopes"]) == 1 and not req["withheld_scopes"]
            key, row = next(iter(req["scopes"].items()))
            assert row["admissible_positive_requirements"] == (["r"] if present else [])
            answer = dict(states={key: dict(applicability="applicable",
                applicability_rationale="Authored reference: the unchanged task processes requests and writes logs; the whole-task resource comparison preserves both operations.",
                expression="explicitly_required" if present else "not_expressed", requirements=["r"] if present else [])},
                unresolved_notes=[])
            applied = assess_fixed_scope_response(json.dumps(answer).encode(), request=req, contract=fresh, prompt=fresh_task["prompt"], catalog=catalog)
            final = compile_task_context_contract(fresh, feature_states=applied["states"], prompt=fresh_task["prompt"], catalog=catalog)
            state = final.scoped_feature_assessments[0]
            assert state.state == ("present" if present else "absent")
            assert not state.scope.condition_node_ids
            return fresh_task, fresh, final, state.scope, applied["states"]

        absent_task, absent, absent_graph, absent_scope, absent_states = assessed(False)
        present_task, present, present_graph, present_scope, present_states = assessed(True)
        assert sum(a["kind"] == "requirement_scope" for a in open_graph_assertions(prompt_tsg_record(present_graph)).values()) == len(present_graph.requirement_scopes)
        # Policy-only guard/choice nodes disappear without altering task selection.
        assert choose_candidate_scope(absent_graph, selector) == absent_scope
        assert choose_candidate_scope(present_graph, selector) == present_scope
        if kind == "objects":
            assert selector["scope_kind"] == "objects" and factor["query"]["required_relations"] == []
            assert next(n for n in present_graph.nodes if n.node_id == present_scope.operation_node_id).semantic_id == "task.root"
            assert len(present_scope.subject_node_ids) == len(options["object_subjects"])
            # Object incidence never multiplies/narrows the policy, including shared objects.
            assert not any(e.source_id in present_graph.scoped_feature_assessments[0].requirement_node_ids
                           and e.edge_type == "constrains" and e.target_id == present_scope.operation_node_id
                           for e in present_graph.edges)
        if name == "object_unused":
            # Selection uses object identity only: a second matching object is
            # ambiguous even though the original has the positive requirement.
            subject = next(n for n in present_graph.nodes if n.node_id in present_scope.subject_node_ids)
            other = next(n for n in present_graph.nodes if n.node_type == "data_object" and n != subject)
            ambiguous = replace(present_graph, nodes=tuple(replace(n, semantic_id=subject.semantic_id)
                                if n == other else n for n in present_graph.nodes))
            assert choose_candidate_scope(ambiguous, selector) is None
            impostor = replace(present, relations=present.relations + (dict(source="r", edge_type="constrains",
                target="op", evidence_text=present_task["prompt"], occurrence=1),))
            with pytest.raises(PromptTSGError, match="complete policy binding"):
                compile_task_context_contract(impostor, feature_states=present_states, prompt=present_task["prompt"], catalog=catalog)
            for state in ("absent", "not_applicable"):
                negative = tuple(dict(r, state=state, requirements=[]) for r in present_states)
                with pytest.raises(PromptTSGError, match="negative policy state"):
                    compile_task_context_contract(impostor, feature_states=negative, prompt=present_task["prompt"], catalog=catalog)
            legacy = json.loads(json.dumps(catalog))
            legacy["feature_scope_selectors"][feature].pop("applicability_scope", None)
            legacy["feature_scope_selectors"][feature].update(scope_kind="targets",
                operation_semantic_id=catalog["normalization_map"]["task_operation::processing"])
            legacy_contract = replace(present, catalog=legacy, input_catalog_sha256=catalog_sha256(legacy))
            with pytest.raises(PromptTSGError, match="explicit object policy selector"):
                compile_task_context_contract(legacy_contract, feature_states=present_states, prompt=present_task["prompt"], catalog=legacy)
            # Uncertain source influence is passed to the semantic assessor;
            # program locality rules no longer withhold this candidate.
            inventory = json.loads(json.dumps(present.source_inventory))
            inventory["coverage"]["u"]["status"] = "unresolved"
            inventory["unit_impacts"] = {"u": dict(effect="local", operations=["return"], complete=False,
                reason="Authored unresolved source-impact contrast.")}
            incomplete = replace(present, source_inventory=inventory)
            withheld = fixed_scope_request(incomplete, prompt=present_task["prompt"], catalog=catalog)
            assert withheld["scopes"] and not withheld["withheld_scopes"]
            assert withheld["source_inventory_status"]["status"] == "INCOMPLETE"
            inventory["unit_impacts"]["u"].update(effect="no_runtime_effect", operations=[])
            assert fixed_scope_request(incomplete, prompt=present_task["prompt"], catalog=catalog)["scopes"]
            # Root anchoring does not bring an unrelated operation into this
            # candidate's review; exact object/global requirements remain needed.
            raw_graph, raw_contract = prompt_tsg_record(present_graph), task_context_contract_record(present)
            ids = {n.semantic_id: n for n in present_graph.nodes}
            selected_nodes = {"root": ids["task.root"], "object": subject}
            state_key = "root/" + feature + "/subjects=object/conditions="
            expected = dict(task_id=present.task_id, source_prompt_sha256=content_hash(present_task["prompt"]),
                nodes=[dict(key=key, node_types=[n.node_type], semantic_ids=[n.semantic_id],
                            evidence_text=present_task["prompt"][n.evidence_start:n.evidence_end], occurrence=1)
                       for key, n in selected_nodes.items()],
                feature_checks=[dict(target="root", subjects=["object"], conditions=[], feature_id=feature, state="present")],
                critical_checks=[["feature_state", state_key]], non_target_checks=[],
                scope_dependencies={state_key: [["feature_state", state_key]]})
            assertions = open_graph_assertions(raw_graph, contract=raw_contract)
            evidence = [dict(evidence_text=present_task["prompt"], occurrence=1)]
            audit = dict(graph_sha256=content_hash(raw_graph), contract_sha256=content_hash(raw_contract),
                source_prompt_sha256=content_hash(present_task["prompt"]), assertions={key: dict(status="SUPPORTED",
                    rationale="Authored projection fixture.", source_evidence=evidence) for key in assertions})
            for local, blocked in (("return", False), ("r", True), ("invariant", True)):
                fact = next(f for f in present.facts if f["local_id"] == local)
                key = next(k for k, a in assertions.items() if a["kind"] == "node"
                           and a["statement"]["semantic_id"] == fact["semantic_id"])
                audit["assertions"][key].update(status="UNSUPPORTED", impact=dict(effect="irrelevant", scopes=[],
                    rationale="Attempted source-local waiver; structural dependencies override it.", source_evidence=evidence))
                scored = evaluate_open_semantic_case(raw_graph, prompt=present_task["prompt"], expected=expected,
                    assertion_review=audit, extraction_failed=False, contract=raw_contract)
                assert scored["scope_quality"][0]["usable"] is not blocked
                audit["assertions"][key]["status"] = "SUPPORTED"
        if kind in {"task", "each"}:
            assert next(n for n in present_graph.nodes if n.node_id == present_scope.operation_node_id).semantic_id == "task.root"
            assert not any(e.source_id in present_graph.scoped_feature_assessments[0].requirement_node_ids
                           and e.edge_type == "constrains" for e in present_graph.edges)
        if guard:
            broken = replace(present, relations=tuple(r for r in present.relations if r["edge_type"] != "conditions"))
            with pytest.raises(PromptTSGError, match="complete policy binding"):
                compile_task_context_contract(broken, feature_states=present_states, prompt=present_task["prompt"], catalog=catalog)
            for lost_state in ("absent", "not_applicable"):
                contradicted = tuple(dict(r, state=lost_state, requirements=[]) for r in present_states)
                with pytest.raises(PromptTSGError, match="negative policy state"):
                    compile_task_context_contract(broken, feature_states=contradicted, prompt=present_task["prompt"], catalog=catalog)
        for source_present, operation in ((False, "add"), (True, "remove")):
            source_task, source_graph, source_scope = ((present_task, present_graph, present_scope) if source_present else
                                                       (absent_task, absent_graph, absent_scope))
            binding = bind_task_hypothesis(policy_id="authored-policy", graph=source_graph, query=factor["query"],
                factor_feature_ids=(feature,), factor_operations=(operation,), factor_scopes=(source_scope,))
            rendered = render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                enabled=(True,), additions={feature: text})
            assert (text in rendered["prompt"]) is (operation == "add")
            if kind == "objects" and operation == "add":
                assert "For the named source objects:" in rendered["prompt"]
                assert "For the runtime task as a whole:" not in rendered["prompt"]
            assert "Process the request and write the diagnostic log. Return status." in rendered["prompt"]
            _, _, target_graph, _, _ = assessed(not source_present, rendered["prompt"])
            targets = source_graph.scoped_feature_assessments[0].requirement_node_ids
            preserved = {n.node_id for n in source_graph.nodes if n.node_type != "task"} - requirement_owned_nodes(source_graph, targets)
            mapped = {n.node_id: next(m.node_id for m in target_graph.nodes if m.semantic_id == n.semantic_id
                      and rendered["prompt"][m.evidence_start:m.evidence_end] == source_task["prompt"][n.evidence_start:n.evidence_end])
                      for n in source_graph.nodes if n.node_id in preserved}
            variant = dict(binding_id=binding.binding_id, source_prompt_sha256=content_hash(source_task["prompt"]),
                enabled=[True], prompt=rendered["prompt"], graph=prompt_tsg_record(target_graph), source_to_variant_nodes=mapped,
                source_review=dict(outcomes_used=False, reviewer_id="authored-reference", rationale="Whole fixed policy changed; both original operations preserved."))
            checked = render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                enabled=(True,), additions={}, reviewed_variant=variant)
            assert checked["prompt"] == rendered["prompt"]
            if name == "owned_order" and operation == "remove":
                assert len(source_graph.requirement_relations) == 2
                assert len(target_graph.requirement_relations) == 1
                assert all(edge[1] != "precedes" for edge in factor["query"]["required_relations"])
                # Each mutation still compiles as a graph with the assigned
                # target policy absent; preservation, not state labels, rejects it.
                for corrupted, error in (
                    (replace(target_graph, edges=tuple(e for e in target_graph.edges if e.edge_type != "precedes")),
                     "non-target relation structure"),
                    (replace(target_graph, requirement_relations=()), "another requirement's owned relation"),
                ):
                    with pytest.raises(MechanismRegistryError, match=error):
                        render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                            enabled=(True,), additions={}, reviewed_variant=dict(variant, graph=prompt_tsg_record(corrupted)))
            if name == "whole":
                invariant_id = next(n.node_id for n in target_graph.nodes if n.node_type == "task_requirement")
                corrupted = replace(target_graph, requirement_scopes=tuple(
                    (key, "each", boundaries, "diagnostic log entries") if key == invariant_id else (key, k, boundaries, cls)
                    for key, k, boundaries, cls in target_graph.requirement_scopes))
                with pytest.raises(MechanismRegistryError, match="non-target composition or scope"):
                    render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                        enabled=(True,), additions={}, reviewed_variant=dict(variant, graph=prompt_tsg_record(corrupted)))
        results.append(dict(case=name, projection=True, add=True, remove=True))
    assert factors["before"] != factors["after"]
    assert factors["object_unused"] == factors["object_used"] == factors["object_shared"]
    assert len(set(factors.values())) == len(cases) - 2
    record_property("authored_policy_checks", json.dumps(results))


def test_candidate_local_edit_scope_preserves_background_shared_support_and_unknowns():
    """Authored policy support permits full edits, never establishes LLM accuracy."""
    from dataclasses import asdict, replace
    from prompt_mechanism_study.tsg.candidate_construction import (
        _candidate_catalog,
        choose_candidate_scope,
    )
    from prompt_mechanism_study.tsg.scope_assessment import (
        fixed_scope_request,
        assess_fixed_scope_response,
    )
    from prompt_mechanism_study.tsg.prompt_tsg import _edge, requirement_owned_nodes
    from prompt_mechanism_study.discovery.mechanisms import (
        bind_task_hypothesis,
        render_task_hypothesis,
        MechanismRegistryError,
    )
    from prompt_mechanism_study.verification.reporting import _replay_scoped_development_prompt

    base = "Accept a password and insert the account into the database. Return status for the account."
    text = "Hash the password into a digest before insertion."

    def source(present, catalog=None, feature=None, account_evidence=None):
        task = dict(task_id="synthetic-candidate-local-policy", language="python",
                    prompt=base + (" " + text if present else ""))
        rows = [("insert", "task_operation", "insertion", "insert the account into the database"),
                ("password", "data_object", "password", "a password"),
                ("account", "data_object", "account", "the account"),
                ("return", "task_operation", "returning", "Return status"),
                ("invariant", "task_requirement", "status", "Return status")]
        links = [("account", "used_by", "insert", base),
                 ("invariant", "constrains", "return", "Return status")]
        if present:
            rows += [("hash", "task_operation", "hashing", "Hash the password into a digest"),
                     ("digest", "data_object", "digest", "a digest"),
                     ("r", "safety_requirement", "policy", text)]
            links += [("password", "used_by", "hash", text), ("hash", "produces", "digest", text),
                      ("digest", "used_by", "insert", text), ("r", "constrains", "hash", text),
                      ("r", "constrains", "password", text)]
        identities = {concept: (feature if key == "r" else catalog["normalization_map"][kind + "::" + concept])
                      if catalog else concept for key, kind, concept, _ in rows}
        response = dict(
            concepts=[] if catalog else [dict(concept_id=concept, node_type=kind, definition=quote)
                                         for _, kind, concept, quote in rows],
            nodes=[dict(local_id=key, concept_id=identities[concept],
                        evidence_text=account_evidence[0] if key == "account" and account_evidence else quote,
                        occurrence=account_evidence[1] if key == "account" and account_evidence else 1)
                   for key, _, concept, quote in rows],
            edges=[dict(source_node_local_id=a, edge_type=kind, target_node_local_id=b,
                        evidence_text=quote, occurrence=1) for a, kind, b, quote in links],
            concept_states=[], unresolved_notes=[])
        source_catalog = catalog or open_concept_catalog()
        contract = authored_contract(response, task=task, catalog=source_catalog,
            annotator_id="authored-policy-support-reference", review_status="development_exposed")
        inventory = dict(source_units={"u": dict(evidence_text=task["prompt"], occurrence=1)},
            coverage={"u": dict(status="represented", facts=[key for key, _, _, _ in rows], reason="Authored edit boundary.")},
            layers={key: "runtime" for key, _, _, _ in rows},
            operation_roles=[dict(operation=b if kind == "used_by" else a,
                                 subject=a if kind == "used_by" else b,
                                 role="value_input" if kind == "used_by" else "result", evidence_text=quote, occurrence=1)
                             for a, kind, b, quote in links if kind in {"used_by", "produces"}],
            requirement_structures={key: dict(kind="atom", members=[]) for key in (["invariant", "r"] if present else ["invariant"])},
            requirement_scopes={}, requirement_relations={"r": [dict(source="hash", edge_type="precedes",
                target="insert", evidence_text=text, occurrence=1)]} if present else {})
        contract = replace(contract, source_inventory=inventory)
        return task, contract, compile_task_context_contract(contract, prompt=task["prompt"], catalog=source_catalog)

    task, contract, graph = source(True)
    intact = prompt_tsg_record(graph)
    request = candidate_request([task], [contract])
    nodes = {n["concept_id"]: n for n in request["sources"][0]["nodes"]}
    response = dict(factors=[dict(label="Password hashing before insertion", definition=text,
        atomicity_rationale="One complete hashing policy with its required result and order.",
        occurrences=[dict(task_id=task["task_id"], requirement_node_ids=[nodes["policy"]["node_id"]],
            scope=dict(operation_node_id=nodes["hashing"]["node_id"], subject_node_ids=[nodes["password"]["node_id"]], condition_node_ids=[]),
            applicability_scope=dict(operation_node_id=nodes["insertion"]["node_id"],
                                     subject_node_ids=[nodes["account"]["node_id"]], condition_node_ids=[]))])],
        dispositions=[dict(task_id=task["task_id"], requirement_node_id=n["node_id"],
            status="included" if n["concept_id"] == "policy" else "not_actionable",
            rationale="Only the complete hashing policy is edited.")
            for n in request["sources"][0]["nodes"] if n["node_type"] in {"task_requirement", "safety_requirement"}])
    full_response = response
    response = _explicit_background_response(request, response, base,
        operation_definition="insert the account into the database", subject_definitions=["the account"])
    wire = candidate_model_request(request)
    assert "READ-ONLY" in wire["instructions"] and "NOT the policy's" in wire["instructions"]
    from prompt_mechanism_study.tsg.candidate_construction import candidate_response_format
    schema = candidate_response_format(request)["json_schema"]["schema"]["properties"]["decisions"]["properties"]
    assert all("applicability_bindings" in row["required"] for row in schema.values())
    draft = compile_candidate_proposal(request, response, _design())
    occurrence = draft["factors"][0]["source_occurrences"][0]
    assert occurrence["scope"] == full_response["factors"][0]["occurrences"][0]["scope"]
    assert occurrence["applicability_scope"] == full_response["factors"][0]["occurrences"][0]["applicability_scope"]
    assert occurrence["applicability_support"]["source_evidence"][0]["evidence_text"] == base
    components = {row["node_id"]: row for row in occurrence["applicability_support"]["component_decisions"]}
    assert set(components) == {nodes[key]["node_id"] for key in ("insertion", "account", "digest")}
    assert components[nodes["account"]["node_id"]]["decision"] == "retain"
    assert components[nodes["digest"]["node_id"]]["decision"] == "omit_not_needed"
    included = next(key for key, row in response["decisions"].items() if row["status"] == "include")
    binding_ref = next(iter(response["decisions"][included]["applicability_bindings"]))
    for mutation in ("null", "missing", "quotation", "policy_scope", "missing_component",
                     "duplicate_component", "silent_omission", "component_quotation"):
        invalid = json.loads(json.dumps(response))
        row = invalid["decisions"][included]
        if mutation == "null":
            row["applicability_bindings"][binding_ref] = None
        elif mutation == "missing":
            row["applicability_bindings"].pop(binding_ref)
        elif mutation == "quotation":
            row["applicability_bindings"][binding_ref]["independent_source_evidence"][0]["evidence_text"] = "Invented source support."
        elif mutation == "policy_scope":
            row["scope"] = full_response["factors"][0]["occurrences"][0]["applicability_scope"]
        elif mutation == "missing_component":
            row["applicability_bindings"][binding_ref]["component_decisions"].pop()
        elif mutation == "duplicate_component":
            items = row["applicability_bindings"][binding_ref]["component_decisions"]
            items.append(items[0])
        elif mutation == "silent_omission":
            row["applicability_bindings"][binding_ref]["subject_refs"] = []
        else:
            row["applicability_bindings"][binding_ref]["component_decisions"][0]["source_evidence"][0]["evidence_text"] = "Invented component support."
        with pytest.raises(ValueError):
            compile_candidate_proposal(request, invalid, _design())
    # Matching valid geometry with a persuasive but mismatched rationale remains
    # reviewable, not automatically accepted as independent source support.
    wrong = json.loads(json.dumps(response))
    policy_node = next(n for n in wire["sources"][0]["nodes"] if n["node_ref"] == included)
    choice = wrong["decisions"][included]["applicability_bindings"][binding_ref]
    choice["operation_ref"] = policy_node["complete_bindings"][0]["operation_ref"]
    choice["subject_refs"] = policy_node["complete_bindings"][0]["subject_refs"]
    choice["component_decisions"] = [dict(node_ref=key, decision="retain",
        source_evidence=[dict(evidence_text=base, occurrence=1)], rationale="Incorrect but structurally complete support.")
        for key in [choice["operation_ref"], *choice["subject_refs"]]]
    wrong_draft = compile_candidate_proposal(request, wrong, _design())
    review = _review(request, wrong, wrong_draft)
    review["decisions"][0].update(decision="reject", context_independent=False,
        rationale="The selected hashing action is policy-only; the cited independent source requires insertion.")
    rejected = compile_candidate_proposal(request, wrong, _design(), review)
    assert rejected["policies"] == rejected["queries"] == []
    # Independent operation alone is insufficient when a selected input depends on
    # the policy. Exact accounting locates this claim; only semantic review judges it.
    leaked = json.loads(json.dumps(response))
    choice = leaked["decisions"][included]["applicability_bindings"][binding_ref]
    omitted = next(item for item in choice["component_decisions"] if item["decision"] != "retain")
    choice["subject_refs"].append(omitted["node_ref"])
    omitted["decision"] = "retain"
    leaked_draft = compile_candidate_proposal(request, leaked, _design())
    assert leaked_draft["status"] == "PENDING_SEMANTIC_REVIEW"
    review = _review(request, leaked, leaked_draft)
    review["decisions"][0].update(decision="reject", context_independent=False,
        rationale="Insertion is independent, but its selected digest input exists only under the hashing policy.")
    assert compile_candidate_proposal(request, leaked, _design(), review)["policies"] == []
    reviewed = compile_candidate_proposal(request, response, _design(), _review(request, response, draft))
    factor = reviewed["factors"][0]
    feature, selector = factor["feature_id"], factor["scope_selector"]
    catalog = _candidate_catalog([contract], reviewed, _design(), reviewed["review"])
    assert prompt_tsg_record(graph) == intact
    assert selector["operation_semantic_id"] != selector["applicability_scope"]["operation_semantic_id"]
    disconnected = json.loads(json.dumps(full_response))
    disconnected["factors"][0]["occurrences"][0]["applicability_scope"]["operation_node_id"] = nodes["returning"]["node_id"]
    with pytest.raises(ValueError, match="applicability scope"):
        compile_candidate_proposal(request, disconnected, _design())

    def assessed(present, account_evidence=None):
        task, contract, graph = source(present, catalog, feature, account_evidence)
        request = fixed_scope_request(contract, prompt=task["prompt"], catalog=catalog)
        assert len(request["scopes"]) == 1 and not request["withheld_scopes"]
        key, row = next(iter(request["scopes"].items()))
        assert row["admissible_positive_requirements"] == (["r"] if present else [])
        answer = dict(states={key: dict(applicability="applicable", applicability_rationale="Account insertion remains independently specified.",
            expression="explicitly_required" if present else "not_expressed", requirements=["r"] if present else [])}, unresolved_notes=[])
        assessment = assess_fixed_scope_response(json.dumps(answer).encode(), request=request, contract=contract, prompt=task["prompt"], catalog=catalog)
        graph = compile_task_context_contract(contract, feature_states=assessment["states"], prompt=task["prompt"], catalog=catalog)
        scope = graph.scoped_feature_assessments[0].scope
        assert choose_candidate_scope(graph, selector) == scope
        assert next(n.semantic_id for n in graph.nodes if n.node_id == scope.operation_node_id) == selector["applicability_scope"]["operation_semantic_id"]
        return task, contract, graph, scope

    absent, present = assessed(False), assessed(True)
    request = fixed_scope_request(present[1], prompt=present[0]["prompt"], catalog=catalog)
    present_states = [dict(target=r["target"], subjects=r["subjects"], conditions=r["conditions"],
        concept_id=r["concept_id"], state="present", requirements=["r"], rationale="Authored binding.")
        for r in request["scopes"].values()]
    duplicate_background = replace(absent[2], nodes=tuple(replace(n,
        semantic_id=selector["applicability_scope"]["operation_semantic_id"])
        if n.semantic_id == catalog["normalization_map"]["task_operation::returning"] else n for n in absent[2].nodes))
    # The retained account input distinguishes operations with the same meaning.
    assert choose_candidate_scope(duplicate_background, selector) == absent[3]
    return_node = next(n for n in absent[2].nodes
                       if n.semantic_id == catalog["normalization_map"]["task_operation::returning"])
    account_node = next(n for n in absent[2].nodes if n.node_id == absent[3].subject_node_ids[0])
    duplicate_background = replace(duplicate_background, edges=(*duplicate_background.edges,
        _edge(account_node, return_node, "used_by", {("data_object", "used_by", "task_operation")})))
    assert choose_candidate_scope(duplicate_background, selector) is None
    # Background matching cannot certify a positive graph with lost/changed order.
    for mutation in ("missing", "reversed"):
        inventory = json.loads(json.dumps(present[1].source_inventory))
        if mutation == "missing":
            inventory["requirement_relations"] = {}
        else:
            inventory["requirement_relations"]["r"][0].update(source="insert", target="hash")
        with pytest.raises(ValueError, match="complete policy binding"):
            compile_task_context_contract(replace(present[1], source_inventory=inventory), feature_states=present_states, prompt=present[0]["prompt"], catalog=catalog)

    for operation, source_case, target_case in (("remove", present, absent), ("add", absent, present)):
        source_task, _, source_graph, scope = source_case
        target_task, _, target_graph, _ = target_case
        binding = bind_task_hypothesis(policy_id="authored-policy-local", graph=source_graph, query=factor["query"],
            factor_feature_ids=(feature,), factor_operations=(operation,), factor_scopes=(scope,))
        source_ids = {n.semantic_id: n.node_id for n in source_graph.nodes if n.node_type != "task"}
        target_ids = {n.semantic_id: n.node_id for n in target_graph.nodes if n.node_type != "task"}
        mapped = {key: target_ids[meaning] for meaning, key in source_ids.items() if meaning in target_ids}
        positive_graph, positive_prompt = present[2], present[0]["prompt"]
        released = {n.node_id for n in positive_graph.nodes if n.semantic_id in {
            catalog["normalization_map"]["task_operation::hashing"], catalog["normalization_map"]["data_object::digest"]}}
        owner = set(positive_graph.scoped_feature_assessments[0].requirement_node_ids)
        owned = requirement_owned_nodes(positive_graph, owner)
        incident = {e.edge_id for e in positive_graph.edges if (e.source_id in released or e.target_id in released)
                    and e.edge_type in {"used_by", "produces"} and not ({e.source_id, e.target_id} & owned)}
        evidence = dict(status="policy_only", source_evidence=[dict(start=positive_prompt.index(text), end=len(positive_prompt))],
                        rationale="The authored source gives these facts and links no independent support beyond the target policy.")
        side = "source" if operation == "remove" else "variant"
        edit_scope = {side + "_nodes": {key: evidence for key in released}, side + "_edges": {key: evidence for key in incident}}
        variant = dict(binding_id=binding.binding_id, source_prompt_sha256=content_hash(source_task["prompt"]), enabled=[True],
            prompt=target_task["prompt"], graph=prompt_tsg_record(target_graph), source_to_variant_nodes=mapped,
            source_review=dict(outcomes_used=False, reviewer_id="authored-reference", rationale="Preserve independent insertion and status behavior.", edit_scope=edit_scope))

        def render(value=variant, selected_graph=source_graph):
            return render_task_hypothesis(binding, selected_graph, prompt=source_task["prompt"], catalog=catalog,
                enabled=(True,), additions={}, reviewed_variant=value)

        def independent(value=variant, selected_graph=source_graph):
            replay_task = dict(prompt=source_task["prompt"], graph=prompt_tsg_record(selected_graph), factor_scopes=[json.loads(json.dumps(asdict(scope)))],
                binding_id=binding.binding_id, intervention_compatibility=dict(binding_id=binding.binding_id, decision="compatible", outcomes_used=False),
                reviewed_variants={"TARGET": value})
            def check(condition, message):
                if not condition:
                    raise ValueError(message)
            return _replay_scoped_development_prompt(replay_task,
                dict(query=factor["query"], factors=[dict(feature_id=feature, operation=operation, addition=text)]), "TARGET", check)

        before = prompt_tsg_record(source_graph)
        assert render()["prompt"] == target_task["prompt"]
        assert independent() == target_task["prompt"]
        assert prompt_tsg_record(source_graph) == before
        if operation == "add":
            # Independent citations can narrow unchanged text, but cannot move
            # to a repeated mention or span the added policy.
            crossing = target_task["prompt"][target_task["prompt"].index("the account"):]
            for quote, occurrence, accepted in (("account", 1, True), ("account", 2, False), (crossing, 1, False)):
                _, _, citation_graph, _ = assessed(True, (quote, occurrence))
                changed = json.loads(json.dumps(variant))
                changed["graph"] = prompt_tsg_record(citation_graph)
                account = catalog["normalization_map"]["data_object::account"]
                changed["source_to_variant_nodes"][source_ids[account]] = next(
                    n.node_id for n in citation_graph.nodes if n.semantic_id == account)
                if accepted:
                    assert render(changed)["prompt"] == target_task["prompt"]
                    assert independent(changed) == target_task["prompt"]
                else:
                    with pytest.raises(MechanismRegistryError, match="non-target source evidence"):
                        render(changed)
                    with pytest.raises(ValueError, match="non-target requirement"):
                        independent(changed)
        extra_state = json.loads(json.dumps(variant))
        extra_state["graph"]["scoped_feature_assessments"].append(
            dict(extra_state["graph"]["scoped_feature_assessments"][0]))
        with pytest.raises(ValueError, match="extra scope state"):
            independent(extra_state)
        # The new authority is explicit and local, never inferred from overlap.
        for mutation in ("missing_scope", "missing_edge", "shared", "unresolved"):
            corrupted = json.loads(json.dumps(variant))
            declared = corrupted["source_review"]["edit_scope"]
            if mutation == "missing_scope":
                corrupted["source_review"].pop("edit_scope")
            elif mutation == "missing_edge":
                declared[side + "_edges"].pop(next(iter(incident)))
            else:
                declared[side + "_nodes"][next(iter(released))]["status"] = mutation
            with pytest.raises(MechanismRegistryError):
                render(corrupted)
            with pytest.raises(ValueError):
                independent(corrupted)
        unrelated = json.loads(json.dumps(variant))
        return_id = source_ids[catalog["normalization_map"]["task_operation::returning"]]
        quote_start = source_task["prompt"].index("Return status")
        unrelated["source_review"]["edit_scope"].setdefault("source_nodes", {})[return_id] = dict(
            status="unresolved", source_evidence=[dict(start=quote_start, end=quote_start + len("Return status"))],
            rationale="Only this unchanged return operation has unresolved local support.")
        assert render(unrelated)["prompt"] == target_task["prompt"]
        assert independent(unrelated) == target_task["prompt"]
        if operation == "remove":
            # Independent order and another requirement's support cannot be waived.
            ids = {n.semantic_id: n.node_id for n in source_graph.nodes}
            hashing = ids[catalog["normalization_map"]["task_operation::hashing"]]
            invariant = ids[catalog["normalization_map"]["task_requirement::status"]]
            by_id = {n.node_id: n for n in source_graph.nodes}
            for origin, kind, destination in ((hashing, "precedes", scope.operation_node_id),
                                               (invariant, "constrains", hashing)):
                extra = _edge(by_id[origin], by_id[destination], kind,
                              {(by_id[origin].node_type, kind, by_id[destination].node_type)})
                corrupted_graph = replace(source_graph, edges=tuple(sorted(source_graph.edges + (extra,), key=lambda e: e.edge_id)))
                original_binding = binding
                binding = bind_task_hypothesis(policy_id="authored-policy-local", graph=corrupted_graph, query=factor["query"],
                    factor_feature_ids=(feature,), factor_operations=(operation,), factor_scopes=(scope,))
                corrupted = json.loads(json.dumps(variant))
                corrupted["binding_id"] = binding.binding_id
                corrupted["source_review"]["edit_scope"]["source_edges"][extra.edge_id] = evidence
                with pytest.raises(MechanismRegistryError, match="shared or context|independent relations"):
                    render(corrupted, corrupted_graph)
                with pytest.raises(ValueError, match="shared|independent"):
                    independent(corrupted, corrupted_graph)
                binding = original_binding

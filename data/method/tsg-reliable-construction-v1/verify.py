"""Offline replay of frozen development calls; never accesses a provider."""
import json
from collections import Counter
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
INVENTORY_REPLAY = r'''
import importlib.util, json, os
from pathlib import Path
from prompt_mechanism_study import functional_judge
from prompt_mechanism_study.artifact_io import read_json
saved, output, work = map(Path, __import__('sys').argv[1:])
calls = [read_json(p) for p in sorted((saved/'calls').glob('*/call.json'))]
position = 0
os.environ['ALI_BAILIAN_API_KEY'] = 'offline-replay-only'
def transport(request, *, timeout):
    global position
    row = calls[position]; position += 1
    assert request.data.decode() == row['trace']['request']
    assert timeout == row['evaluator']['timeout_seconds']
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, maximum): return row['trace']['response'].encode()[:maximum]
    return Response()
functional_judge.urlopen = transport
spec = importlib.util.spec_from_file_location('frozen_runner', work/'run_tsg_development.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.run(work/'experiment', output)
assert position == len(calls)
for name in ('results.json', 'report.json', 'reuse.json'):
    assert read_json(output/'summary'/name) == read_json(saved/'summary'/name), name
'''

AGENT_REPAIR_REPLAY = r'''
import json
from pathlib import Path
from prompt_mechanism_study import source_records as sr
from prompt_mechanism_study.prompt_contract import compile_task_context_contract, task_context_contract_record
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record
base = Path(__import__('sys').argv[1])
read = lambda p: json.loads(p.read_text(encoding='utf-8'))
for name in read(base/'plan.json')['cases']:
    saved, case = base.parent/'agent-repeatability'/name, base/name
    request, original = read(saved/'inputs/request.json'), read(saved/'attempt-1.json')
    check = sr.review_request(request, original)
    assert check == read(case/'review-request.json')
    assert sr.review_response_format(check) == read(case/'review-response-format.json')
    assert sr.structural_readback(request, original) == read(case/'structural-readback.json')
    try:
        review = read(case/'review.json')
        repair = sr.repair_request(request, original, review)
    except Exception as error:
        failure = read(case/'prepare-failure.json')
        assert failure['error_type'] == type(error).__name__ and failure['error_message'] == str(error)
        continue
    assert not (case/'prepare-failure.json').exists()
    decision = dict(status='PATCH_REQUESTED' if repair else 'NO_PATCH_REQUESTED',
        record_status_counts={s:sum(x['status']==s for x in review['records'].values()) for s in ['supported','unsupported','unresolved']},
        incomplete_source_units=[k for k,v in review['source_units'].items() if not v['complete']],
        rejected_record_ids=repair['rejected_record_ids'] if repair else [],
        editable_record_ids=repair['editable_record_ids'] if repair else [],
        semantic_correctness_not_certified=True)
    assert decision == read(case/'review-decision.json')
    if repair:
        assert repair == read(case/'patch-request.json')
        assert sr.patch_response_format(repair, request) == read(case/'patch-response-format.json')
    try:
        merged = sr.apply_record_patch(original,read(case/'patch.json'),request=repair,original_request=request) if repair else original
        task, catalog = read(saved/'inputs/task.json'), read(saved/'inputs/catalog.json')
        contract = sr.compile_records(merged,request=request,task=task,catalog=catalog,
            annotator_id='bounded-codex-source-agent',review_status='development_exposed')
        graph = compile_task_context_contract(contract,prompt=task['prompt'],catalog=catalog)
    except Exception as error:
        failure = read(case/'compile-failure.json')
        assert failure['error_type'] == type(error).__name__ and failure['error_message'] == str(error)
        continue
    assert not (case/'compile-failure.json').exists()
    prior={r['record_id']:r for group in ('objects','operations','requirements') for r in original[group]}
    after={r['record_id']:r for group in ('objects','operations','requirements') for r in merged[group]}
    result=dict(status='PATCH_COMPILED' if repair else 'REVIEW_SUPPORTED_NO_PATCH',
        changed_record_ids=[k for k in sorted(set(prior)|set(after)) if prior.get(k)!=after.get(k)],
        unchanged_original_records=sum(prior[k]==after.get(k) for k in prior),
        original_record_count=len(prior),final_record_count=len(after),
        unresolved_source_units=[k for k,v in merged['coverage'].items() if v['status']=='unresolved'],
        semantic_correctness_not_certified=True,provider_calls=0,scientific_claim_allowed=False)
    for filename, value in {'records.json':merged,'contract.json':task_context_contract_record(contract),
            'graph.json':prompt_tsg_record(graph),'structural-readback.json':sr.structural_readback(request,merged),
            'result.json':result}.items():
        assert value == read(case/'final'/filename), (name, filename)
print('Retained agent reviews, local patches and final compilations replayed; no semantic certification.')
'''


def verify(base):
    with tempfile.TemporaryDirectory(prefix='tsg-frozen-replay-') as directory:
        work = Path(directory)
        with tarfile.open(base/'execution-source.tar.gz') as archive:
            archive.extractall(work, filter='data')
        retained = work/'retained'
        with tarfile.open(base/'results.tar.gz') as archive:
            archive.extractall(retained, filter='data')
        saved = retained/'run'
        env = {**os.environ, 'PYTHONPATH': str(work/'src'), 'PYTHONUTF8': '1'}
        output = work/'replayed'
        if (work/'run_tsg_development.py').exists():
            code = work/'replay.py'; code.write_text(INVENTORY_REPLAY, encoding='utf-8')
            command = [sys.executable, str(code), str(saved), str(output), str(work)]
        else:
            runner, = work.rglob('propose.py')
            command = [sys.executable, str(runner), str(runner.parent), str(output), str(saved)]
        subprocess.run(command, cwd=work, env=env, check=True)
        report = json.loads((saved/'summary/report.json').read_text(encoding='utf-8'))
    return dict(experiment=base.name, exact_wire_and_results_replayed=True,
                provider_calls=report.get('actual_provider_calls', report.get('provider_calls')),
                conservative_cost_microunits=report['actual_conservative_cost_microunits'])


def verify_agent_graphs():
    base = ROOT/'agent-construction-pilot'
    with tempfile.TemporaryDirectory(prefix='tsg-agent-replay-') as directory:
        work = Path(directory)
        with tarfile.open(base/'execution-source.tar.gz') as archive:
            archive.extractall(work, filter='data')
        env = {**os.environ, 'PYTHONPATH': str(work/'src'), 'PYTHONUTF8': '1'}
        for name in ('firmware', 'pandoc', 'book'):
            shutil.copyfile(base/name/'attempt-1.json', work/name/'attempt-1.json')
            subprocess.run([sys.executable, str(work/'validate.py'), str(work/name), '1'],
                           cwd=work, env=env, check=True)
            for filename in ('result.json', 'contract.json', 'graph.json', 'structural-readback.json'):
                actual = json.loads((work/name/'checks/attempt-1'/filename).read_text(encoding='utf-8'))
                saved = json.loads((base/name/'checks/attempt-1'/filename).read_text(encoding='utf-8'))
                assert actual == saved, (name, filename)
    return dict(retained_agent_graphs_replayed=3, agent_sampling_repeated=False,
                semantic_correctness_not_certified=True)


def project_owned_requirements():
    """Probe saved natural bindings; mutations are not natural prompt interventions."""
    base = ROOT/'owned-relations'
    code = r'''
import json, sys
from dataclasses import replace
from pathlib import Path
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.prompt_contract import task_context_contract_from_record
from prompt_mechanism_study.prompt_tsg import prompt_tsg_from_record, requirement_matches_policy, query_context
from prompt_mechanism_study.candidate_construction import candidate_request, _candidate_units, _occurrence, _query, choose_candidate_scope
base=Path(sys.argv[1]); results=[]
for case in read_json(base/'protocol/plan.json')['cases']:
    saved=base/case['run']; checks=sorted((saved/'checks').glob('attempt-*'))[-1]
    if not (checks/'graph.json').exists():
        results.append(dict(run=case['run'],status='NO_COMPILED_GRAPH',policies=[])); continue
    graph=prompt_tsg_from_record(read_json(checks/'graph.json'))
    contract=task_context_contract_from_record(read_json(checks/'contract.json'))
    request=candidate_request([read_json(saved/'inputs/task.json')],[contract],input_catalog=read_json(saved/'inputs/catalog.json'))
    ids,bindings,_=_candidate_units(request); source=request['sources'][0]
    aliases={n['node_type']+'::'+n['concept_id']:n['concept_id'] for n in source['nodes']}
    policies=[]
    for owner in sorted({row[0] for row in graph.requirement_relations}):
        key=next(k for k,(_,node) in ids.items() if node==owner)
        observations=[]
        for occurrence in bindings[key]:
            selector,_=_occurrence(source,occurrence,aliases); scope=choose_candidate_scope(graph,selector)
            query=_query(selector,next(n.semantic_id for n in graph.nodes if n.node_id==owner))
            reverse=replace(graph,requirement_relations=tuple(sorted((r,b,k,a) if r==owner else (r,a,k,b) for r,a,k,b in graph.requirement_relations)))
            removed=replace(graph,nodes=tuple(n for n in graph.nodes if n.node_id!=owner),edges=tuple(e for e in graph.edges if owner not in {e.source_id,e.target_id}),requirement_structures=tuple(r for r in graph.requirement_structures if r[0]!=owner),requirement_relations=tuple(r for r in graph.requirement_relations if r[0]!=owner))
            stripped=replace(graph,requirement_relations=removed.requirement_relations)
            observations.append(dict(selector=selector,original_positive=scope is not None and requirement_matches_policy(graph,owner,scope,selector),
                reversal_rejected=scope is not None and not requirement_matches_policy(reverse,owner,scope,selector),
                missing_order_rejected=scope is not None and not requirement_matches_policy(stripped,owner,scope,selector),
                source_geometry_survives_owner_removal=scope is not None and choose_candidate_scope(removed,selector)==scope,
                query_has_no_precedence_prerequisite=not any(r[1]=='precedes' for r in query['required_relations']),
                context_before=query_context(graph,query=query,cwe='',task_family='').state.value,
                context_after_structural_removal=query_context(removed,query=query,cwe='',task_family='').state.value))
        policies.append(dict(requirement_node_id=owner,complete_bindings=observations))
    results.append(dict(run=case['run'],status='PROJECTED',policies=policies))
print(json.dumps(dict(cases=results,structural_mutations_only=True,natural_editability_tested=False,semantic_eligibility_not_certified=True,provider_calls=0)))
'''
    with tempfile.TemporaryDirectory(prefix='tsg-owned-projection-') as directory:
        work = Path(directory)
        archive = base/'execution-source.tar.gz'
        plan = json.loads((base/'protocol/plan.json').read_text(encoding='utf-8'))
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == plan['execution_source_sha256']
        with tarfile.open(archive) as source:
            source.extractall(work, filter='data')
        env = {**os.environ, 'PYTHONPATH':str(work/'src'), 'PYTHONUTF8':'1'}
        return json.loads(subprocess.check_output([sys.executable,'-c',code,str(base)],cwd=work,env=env,text=True))


def verify_agent_repetitions(name='agent-repeatability', expected_runs=16):
    base = ROOT/name
    plan = json.loads((base/'protocol/plan.json').read_text(encoding='utf-8'))
    assert len(plan['cases']) == expected_runs
    successful = attempts = 0
    with tempfile.TemporaryDirectory(prefix='tsg-agent-repetitions-') as directory:
        work = Path(directory)
        shutil.copyfile(base/'execution-source.tar.gz', work/'execution-source.tar.gz')
        shutil.copyfile(base/'validate.py', work/'validate.py')
        shutil.copytree(base/'protocol', work/'protocol')
        for row in plan['cases']:
            case = base/row['run']
            destination = work/row['run']
            shutil.copytree(case/'inputs', destination/'inputs')
            responses = sorted(case.glob('attempt-*.json'))
            assert 1 <= len(responses) <= plan['maximum_attempts_per_run'], row['run']
            last_status = None
            for number, response in enumerate(responses, 1):
                assert response.name == f'attempt-{number}.json'
                shutil.copyfile(response, destination/response.name)
                subprocess.run([sys.executable, str(work/'validate.py'), str(destination), str(number)], check=True)
                expected = case/'checks'/f'attempt-{number}'
                actual = destination/'checks'/f'attempt-{number}'
                for filename in ('result.json', 'contract.json', 'graph.json', 'structural-readback.json'):
                    assert (expected/filename).exists() == (actual/filename).exists(), (row['run'], filename)
                    if (expected/filename).exists():
                        assert json.loads((expected/filename).read_text(encoding='utf-8')) == json.loads((actual/filename).read_text(encoding='utf-8')), (row['run'], number, filename)
                last_status = json.loads((actual/'result.json').read_text(encoding='utf-8'))['status']
                attempts += 1
            successful += last_status == 'COMPILED_NOT_SEMANTICALLY_CERTIFIED'
    return dict(retained_runs_replayed=len(plan['cases']), retained_attempts_replayed=attempts,
                compiled_runs=successful, agent_sampling_repeated=False,
                semantic_correctness_not_certified=True)


def summarize_agent_audit():
    """Recount retained author judgments, not independently certify their truth."""
    base = ROOT/'agent-repeatability'
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    plan = read(base/'protocol/plan.json')
    references = {row['case_id']: row for row in read(base/'protocol/references.json')['cases']}
    audits = {}
    for part in ('root-firmware-book', 'file-process', 'web-bindings', 'quantifier-order'):
        for row in read(base/'analysis'/f'{part}.json')['cases']:
            assert row['run'] not in audits, row['run']
            audits[row['run']] = row
    assert set(audits) == {row['run'] for row in plan['cases']}
    totals = Counter({status: 0 for status in read(base/'protocol/references.json')['scoring']['statuses']})
    rows = []
    for case in plan['cases']:
        name = case['run']
        task = read(base/name/'inputs/task.json')
        assert task['task_id'] == case['task_id']
        # Method content hashes encode the string as JSON, not raw UTF-8 text.
        encoded_prompt = json.dumps(task['prompt'], ensure_ascii=False).encode('utf-8')
        assert hashlib.sha256(encoded_prompt).hexdigest() == task['prompt_sha256'] == case['prompt_sha256']
        judgments = audits[name]['reference_assessments']
        expected = [row['reference_id'] for row in references[case['base_task']]['requirements']]
        assert Counter(row['reference_id'] for row in judgments) == Counter(expected), name
        counts = Counter(row['status'] for row in judgments)
        assert set(counts) <= set(totals), name
        totals.update(counts)
        attempts = list((base/name).glob('attempt-*.json'))
        status = read(base/name/'checks'/f'attempt-{len(attempts)}'/'result.json')['status']
        rows.append(dict(run=name, base_task=case['base_task'], repeat=case['repeat'],
                         reference_count=len(expected), statuses=dict(counts),
                         compiled=status == 'COMPILED_NOT_SEMANTICALLY_CERTIFIED',
                         retained_attempts=len(attempts), source_audit_usable=audits[name]['usable']))
    return dict(base_tasks=len(references), runs=len(rows),
                reference_assessments=sum(totals.values()), statuses=dict(totals),
                compiled_runs=sum(row['compiled'] for row in rows),
                retained_attempts=sum(row['retained_attempts'] for row in rows),
                source_audit_usable_runs=sum(row['source_audit_usable'] for row in rows),
                fixed_reference_correct_fraction=totals['correct_decisive']/sum(totals.values()),
                cases=rows, independent_semantic_certification=False,
                note='Pandoc wrong_decisive denotes frozen-reference mismatch with source-clause ambiguity; privilege bindings remain unresolved. Counts are correlated within eight tasks.')


def verify_agent_repairs():
    base = ROOT/'agent-repair'
    plan = json.loads((base/'plan.json').read_text(encoding='utf-8'))
    archive_path = base/plan['implementation_archive']
    assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == plan['implementation_archive_sha256']
    identities = json.loads((base/'input-identities.json').read_text(encoding='utf-8'))
    for name, digest in identities.items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest, name
    with tempfile.TemporaryDirectory(prefix='tsg-agent-repair-replay-') as directory:
        work = Path(directory)
        with tarfile.open(archive_path) as archive:
            archive.extractall(work, filter='data')
        env = {**os.environ, 'PYTHONPATH':str(work/'src'), 'PYTHONUTF8':'1'}
        subprocess.run([sys.executable, '-c', AGENT_REPAIR_REPLAY, str(base)],
                       cwd=work, env=env, check=True)
    audit = json.loads((base/'source-audit.json').read_text(encoding='utf-8'))
    assert [row['run'] for row in audit['cases']] == plan['cases']
    judgments = [j for row in audit['cases'] for j in row['reference_assessments']]
    counts = audit['summary']
    assert counts['reference_assessments'] == len(judgments)
    for stage in ('before', 'after'):
        assert counts[stage] == dict(Counter(j[stage] for j in judgments))
    assert counts['review_responses'] == sum((base/name/'review.json').exists() for name in plan['cases'])
    assert counts['patch_responses'] == sum((base/name/'patch.json').exists() for name in plan['cases'])
    assert counts['final_graphs_compiled'] == sum((base/name/'final/graph.json').exists() for name in plan['cases'])
    assert counts['critical_wrong_or_unresolved_to_correct'] == sum(j['before'] in {'wrong_decisive','missing_or_unresolved'} and j['after']=='correct_decisive' for j in judgments)
    for status, key in [('wrong_decisive','correct_reference_to_wrong'), ('missing_or_unresolved','correct_reference_to_unresolved')]:
        assert counts[key] == sum(j['before']=='correct_decisive' and j['after']==status for j in judgments)
    return dict(retained_cases_replayed=len(plan['cases']), model_sampling_repeated=False,
                provider_calls=0, semantic_correctness_not_certified=True)


def replay_complete_repair_round():
    """Replay the frozen record-review-patch path and actual edit diagnostics."""
    base = ROOT/'complete-repair-round'
    code = r'''
import json,sys
from pathlib import Path
from dataclasses import replace
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.source_records import attempt_graph
from prompt_mechanism_study.prompt_contract import task_context_contract_record
from prompt_mechanism_study.prompt_tsg import prompt_tsg_from_record,prompt_tsg_record,ScopedFeatureAssessment,catalog_sha256
from prompt_mechanism_study.candidate_construction import _query,choose_candidate_scope
from prompt_mechanism_study.mechanisms import bind_task_hypothesis,render_task_hypothesis
base=Path(sys.argv[1]);plan=read_json(base/'protocol/plan.json');reviews=[]
for name in plan['reviews']:
    case=base/'reviews'/name; calls=[]
    def provider(request,config,prompt):
        kind=request['request_kind'];calls.append(kind)
        request_file,response_file,schema_file={
            'source_only_atomic_records':('inputs/original-request.json','inputs/records.json',None),
            'source_only_record_review':('inputs/request.json','review.json','inputs/response-format.json'),
            'source_only_record_patch':('repair-inputs/request.json','patch.json','repair-inputs/response-format.json')}[kind]
        assert request==read_json(case/request_file),(name,kind)
        if schema_file:
            def schema_meaning(value):
                if isinstance(value,dict): return {k:sorted(v) if k in {'required','enum'} else schema_meaning(v) for k,v in value.items()}
                if isinstance(value,list): return [schema_meaning(v) for v in value]
                return value
            assert schema_meaning(config['response_format'])==schema_meaning(read_json(case/schema_file)),(name,kind,'schema meaning drift')
        return (case/response_file).read_bytes()
    attempt=attempt_graph(read_json(case/'inputs/task.json'),catalog=read_json(case/'inputs/catalog.json'),evaluator={'candidate_id':'retained-codex-round'},annotator_prompt='Replay retained bounded development responses.',review_status='development_exposed',provider=provider)
    reviews.append(dict(case=name,error_type=attempt.error_type,error_message=attempt.error_message,request_kinds=calls,
        records=attempt.binding_annotation.get('records'),contract=task_context_contract_record(attempt.contract) if attempt.contract else None,
        graph=prompt_tsg_record(attempt.graph) if attempt.graph else None))
edits=[];projections=read_json(base.parent/'owned-relations/analysis/projection.json')['cases']
for row in plan['cases']:
    prior=base.parent/'owned-relations'/(row['base_task']+'-r1');task=read_json(prior/'inputs/task.json')
    graph=prompt_tsg_from_record(read_json(prior/'checks/attempt-1/graph.json'));contract=read_json(prior/'checks/attempt-1/contract.json')
    records=read_json(prior/'attempt-1.json');record=next(r for r in records['requirements'] if r['record_id']==row['target_record_id'])
    definition=record['fact']['concept']['definition'];catalog=contract['catalog']
    owner=next(n for n in graph.nodes if n.node_type=='safety_requirement' and catalog['semantic_guidance'][n.semantic_id]==definition)
    case_projection=next(r for r in projections if r['run']==row['base_task']+'-r1')
    selector=next(r for r in case_projection['policies'] if r['requirement_node_id']==owner.node_id)['complete_bindings'][0]['selector']
    scope=choose_candidate_scope(graph,selector);query=_query(selector,owner.semantic_id)
    catalog={**catalog,'queries':[query],'feature_scope_selectors':{owner.semantic_id:selector}}
    graph=replace(graph,catalog_sha256=catalog_sha256(catalog),scoped_feature_assessments=(ScopedFeatureAssessment(scope,owner.semantic_id,'present',(owner.node_id,)),))
    binding=bind_task_hypothesis(policy_id='author-selected-development-edit',graph=graph,query=query,factor_feature_ids=(owner.semantic_id,),factor_operations=('remove',),factor_scopes=(scope,))
    try:
        rendered=render_task_hypothesis(binding,graph,prompt=task['prompt'],catalog=catalog,enabled=(True,),additions={})
        outcome=dict(status='RENDERED',prompt=rendered['prompt'])
    except Exception as error:
        outcome=dict(status='BLOCKED',error_type=type(error).__name__,reason=str(error))
    edited=read_json(base/row['run']/'inputs/task.json')
    after=prompt_tsg_from_record(read_json(base/row['run']/'checks/attempt-1/graph.json'))
    body=task['generation_input']['request']['task'];clause=row['removed_source_clause']
    assert edited['generation_input']['request']['task']==body.replace(clause,'')
    index=body.index(clause);reconstructed=edited['generation_input']['request']['task'][:index]+clause+edited['generation_input']['request']['task'][index:]
    edits.append(dict(run=row['run'],target_record_id=row['target_record_id'],removal=outcome,
        unchanged_selector_scope_after_reextraction=str(choose_candidate_scope(after,selector)) if choose_candidate_scope(after,selector) is not None else None,
        inverse_add_restores_original_source_bytes=reconstructed==body,
        inverse_add_is_not_an_executed_qualified_intervention=True,
        comparison_limit='Fresh open extraction may use different semantic IDs; missing scope alone is not a semantic-error score. Source audit separately checks whether the policy action remains required.'))
print(json.dumps(dict(reviews=reviews,actual_edit_diagnostics=edits,external_provider_calls=0,source_record_deliveries_replayed_not_resampled=4,scientific_claim_allowed=False)))
'''
    with tempfile.TemporaryDirectory(prefix='tsg-complete-round-') as directory:
        work = Path(directory)
        archive = base/'execution-source.tar.gz'
        plan = json.loads((base/'protocol/plan.json').read_text(encoding='utf-8'))
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == plan['execution_source_sha256']
        with tarfile.open(archive) as source:
            source.extractall(work, filter='data')
        env = {**os.environ,'PYTHONPATH':str(work/'src'),'PYTHONUTF8':'1'}
        return json.loads(subprocess.check_output([sys.executable,'-c',code,str(base)],cwd=work,env=env,text=True))


def summarize_complete_repair_round(result):
    """Count structural changes separately from retained source judgments."""
    base = ROOT/'complete-repair-round'
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    audit = read(base/'analysis/source-audit.json')
    rows = []
    for row in result['reviews']:
        original = read(base/'reviews'/row['case']/'inputs/records.json')
        final = row['records']
        before = {r['record_id']:r for group in ('objects','operations','requirements') for r in original[group]}
        after = {r['record_id']:r for group in ('objects','operations','requirements') for r in final[group]}
        rows.append(dict(case=row['case'],compiled=row['error_type'] is None and row['graph'] is not None,
            patched='source_only_record_patch' in row['request_kinds'],
            changed_record_ids=sorted(k for k in set(before)|set(after) if before.get(k)!=after.get(k)),
            records_unchanged=original==final,
            owned_order_count=len(row['graph']['requirement_relations']),
            unresolved_source_units=sorted(k for k,v in final['coverage'].items() if v['status']=='unresolved')))
    assert {r['case'] for r in rows} == {r['case'] for r in audit['reviews']}
    return dict(base_tasks=2,fresh_edited_constructions=2,
        fresh_review_responses=len(rows),fresh_patch_responses=sum(r['patched'] for r in rows),
        codex_model_steps=2+len(rows)+sum(r['patched'] for r in rows),
        final_reviewed_graphs_compiled=sum(r['compiled'] for r in rows),
        wrong_target_variants=2,
        wrong_target_variants_repaired=sum(r['critical_binding_after']=='correct' for r in audit['reviews'] if r['variant']=='wrong_target'),
        correct_controls=2,correct_controls_unchanged=sum(r['records_unchanged'] for r in rows if r['case'] in {'case-01','case-04'}),
        owned_order_rows_preserved=sum(r['owned_order_count'] for r in rows),
        actual_remove_attempts=len(result['actual_edit_diagnostics']),
        actual_removes_blocked=sum(r['removal']['status']=='BLOCKED' for r in result['actual_edit_diagnostics']),
        external_provider_calls=0,scientific_claim_allowed=False,source_audit_independently_certified=False,cases=rows)


def verify_complete_repair_round():
    base = ROOT/'complete-repair-round'
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    for name,digest in read(base/'analysis/input-output-identities.json').items():
        assert hashlib.sha256((base/name).read_bytes()).hexdigest()==digest,name
    constructions = verify_agent_repetitions('complete-repair-round',expected_runs=2)
    result = replay_complete_repair_round()
    assert result == read(base/'completed-execution/result.json')
    counts = summarize_complete_repair_round(result)
    assert counts == read(base/'analysis/summary.json')
    # Preserve the failed harness attempt; it is not a model semantic failure.
    assert all(r['error_type']=='AssertionError' for r in read(base/'execution/result.json')['reviews'])
    return dict(constructions=constructions,retained_review_patch_path_replayed=True,
                counts=counts,semantic_correctness_not_certified=True)


def verify_owned_relations():
    base = ROOT/'owned-relations'
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    identities = read(base/'analysis/input-output-identities.json')
    for name, digest in identities.items():
        assert hashlib.sha256((base/name).read_bytes()).hexdigest() == digest, name
    replay = verify_agent_repetitions('owned-relations', expected_runs=2)
    projection = project_owned_requirements()
    assert projection == read(base/'analysis/projection.json')
    audit = read(base/'analysis/source-audit.json')
    refs = {row['case_id']:row for row in read(base/'protocol/references.json')['cases']}
    for case in audit['cases']:
        expected = refs[case['run'].removesuffix('-r1')]['requirements']
        assert Counter(row['reference_id'] for row in case['reference_assessments']) == Counter(row['reference_id'] for row in expected)
    judgments = [r for case in audit['cases'] for r in case['reference_assessments']]
    summary = audit['summary']
    assert summary['reference_assessments'] == len(judgments)
    assert summary['base_tasks'] == len(audit['cases']) == replay['retained_runs_replayed']
    assert summary['compiled_graphs'] == replay['compiled_runs']
    assert summary['retained_attempts'] == replay['retained_attempts_replayed']
    for status in ('correct_decisive','missing_or_unresolved','wrong_decisive'):
        assert summary[status] == sum(row['status']==status for row in judgments)
    assert summary['owned_order_requirements'] == sum(len(row['policies']) for row in projection['cases'])
    return dict(replay=replay,source_audit_counts=summary,projection_replayed=True,
                source_audit_not_independently_certified=True)


def replay_candidate_local_natural():
    """Replay the bounded natural proposal gates, including unexecuted downstream stages."""
    base = ROOT/'candidate-local-natural'
    code = r'''
import json,sys
from pathlib import Path
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.candidate_construction import candidate_request,compile_candidate_proposal
from prompt_mechanism_study.prompt_contract import task_context_contract_from_record
from prompt_mechanism_study.records import content_hash
base=Path(sys.argv[1]);plan=read_json(base/'protocol/plan.json');rows=[]
for name in ('privilege_order','registration'):
    case=base/name;source=read_json(case/'proposal-inputs/request.json')
    task=read_json(case/'proposal-inputs/task.json')
    expected=candidate_request([task],[task_context_contract_from_record(read_json(case/'proposal-inputs/contract.json'))],input_catalog=read_json(case/'proposal-inputs/catalog.json'))
    assert source['source_request']==expected
    answer=read_json(case/'proposal-response.json')
    assert set(answer)=={'decision','applicability_scope','rationale'} and answer['decision'] in {'proposed','unresolved'}
    calls=1;selected=None;review_decision=None
    if answer['decision']=='unresolved':
        assert answer['applicability_scope'] is None
        result=dict(status='BLOCKED_PROPOSAL_UNRESOLVED',reason=answer['rationale'],scientific_claim_allowed=False)
        assert not (case/'review-response.json').exists()
    else:
        req=read_json(case/'review-inputs/request.json');response=read_json(case/'review-inputs/candidate-response.json');design=read_json(case/'review-inputs/design.json')
        assert req['source_request']==expected and req['proposal_response']==response
        occurrence,=response['factors'][0]['occurrences']
        original,=source['original_complete_bindings']
        assert {k:v for k,v in occurrence.items() if k!='applicability_scope'}==original
        assert occurrence['applicability_scope']==answer['applicability_scope']
        selected=next(n['definition'] for n in expected['sources'][0]['nodes'] if n['node_id']==occurrence['applicability_scope']['operation_node_id'])
        draft=compile_candidate_proposal(expected,response,design)
        assert draft==read_json(case/'review-inputs/draft.json')==req['compiled_proposal']
        review=read_json(case/'review-response.json');calls+=1
        checked=compile_candidate_proposal(expected,response,design,review)
        assert checked==read_json(case/'candidate-decision/proposal.json')
        accepted=sum(f['review_decision']=='accept' for f in checked['factors'])
        review_decision=review['decisions'][0]['decision']
        result=dict(status='ACCEPTED_FOR_FRESH_EXTRACTION' if accepted else 'BLOCKED_CANDIDATE_REVIEW',accepted_candidates=accepted,scientific_claim_allowed=False)
    assert result==read_json(case/'candidate-decision/result.json')
    assert result['status'].startswith('BLOCKED_'),'This retained round stopped at the proposal gates.'
    rows.append(dict(base_task=name,proposal_decision=answer['decision'],selected_background_meaning=selected,candidate_review_decision=review_decision,status=result['status'],fresh_model_steps=calls,fresh_constructions=0,scope_assessments=0,local_support_reviews=0,remove_executed=False,add_executed=False))
for item in plan['cases']:
    p=(base.parent/'owned-relations'/(item['base_task']+'-r1')/'inputs/task.json' if item['arm']=='present' else base.parent/'complete-repair-round'/item['run']/'inputs/task.json')
    task=read_json(p)
    assert task['task_id']==item['task_id'] and content_hash(task['prompt'])==item['prompt_sha256']
    assert not (base/item['run']).exists(),'No dependent construction input or response was created.'
print(json.dumps(dict(status='COMPLETED_BOUNDED_CHECK_BLOCKED_AT_CANDIDATES',base_tasks=2,accepted_candidates=0,fresh_model_steps=sum(r['fresh_model_steps'] for r in rows),external_provider_calls=0,actual_edits_executed=0,scientific_claim_allowed=False,cases=rows)))
'''
    with tempfile.TemporaryDirectory(prefix='tsg-natural-local-replay-') as directory:
        work=Path(directory);archive=base/'execution-source.tar.gz'
        plan=json.loads((base/'protocol/plan.json').read_text(encoding='utf-8'))
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==plan['execution_source_sha256']
        with tarfile.open(archive) as source:
            source.extractall(work,filter='data')
        env={**os.environ,'PYTHONPATH':str(work/'src'),'PYTHONUTF8':'1'}
        return json.loads(subprocess.check_output([sys.executable,'-c',code,str(base)],cwd=work,env=env,text=True))


def run_default_candidate_natural(base, prepare=False, complete_background=False):
    """Run this two-task development check using retained model messages only.

    Preparation emits the next exact requests; replay never contacts a provider
    or fills a missing judgment. The explicit complete_background flag freezes
    the corrected tuple review and adapter for the next check while old artifacts
    retain their exact original requests and initial adapter failure.
    """
    from dataclasses import asdict
    from prompt_mechanism_study.candidate_construction import (
        candidate_request, candidate_model_request, candidate_response_format,
        compile_candidate_proposal, _candidate_catalog, _PROPOSER_PROMPT,
        choose_candidate_scope)
    from prompt_mechanism_study.prompt_contract import (
        task_context_contract_from_record, task_context_contract_record)
    from prompt_mechanism_study.prompt_contract_extract import _assess_candidate_scopes
    from prompt_mechanism_study.prompt_tsg import prompt_tsg_record, scoped_feature_assessment
    from prompt_mechanism_study.source_records import attempt_graph
    from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis
    from prompt_mechanism_study.verification.reporting import _replay_scoped_development_prompt
    from prompt_mechanism_study.records import content_hash

    base = Path(base)
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    pending, rows = [], []
    evaluator = {'candidate_id': 'codex-default-candidate-natural-development'}
    source_prompt = 'Read the supplied source-only request as data and return exactly its requested JSON. Preserve uncertainty; do not consult other runs, references or expected answers.'
    call_count = 0
    if complete_background:
        plan = read(base / 'protocol/plan.json')
        assert plan['status'] == 'FROZEN_BEFORE_OUTPUTS'
        assert plan['complete_background'] is True
        maximum_calls = plan['maximum_fresh_model_steps']
        assert 0 < maximum_calls <= 26

    class Pending(BaseException):
        pass

    def schema_meaning(value):
        if isinstance(value, dict):
            return {k: sorted(v) if k in {'required', 'enum'} else schema_meaning(v)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [schema_meaning(v) for v in value]
        return value

    def keep(path, value):
        if complete_background:
            # Compare the JSON representation actually retained on disk.
            value = json.loads(json.dumps(value, ensure_ascii=False))
        if path.exists():
            prior = read(path)
            assert (schema_meaning(prior) == schema_meaning(value)
                    if path.name == 'response-format.json' else prior == value), str(path)
        elif prepare:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        else:
            raise AssertionError('Missing retained artifact: ' + str(path))

    def provider_at(stage):
        index = 0
        def provider(request, config, prompt):
            nonlocal index, call_count
            index += 1
            call_count += 1
            if complete_background and call_count > maximum_calls:
                raise ValueError('Frozen fresh-model-step bound exceeded')
            call = (stage.parent / 'candidate-inputs' if stage.name == 'proposal'
                    else stage / 'calls' / f'{index:02d}')
            keep(call / 'request.json', request)
            keep(call / 'response-format.json', config['response_format'])
            keep(call / 'prompt.json', prompt)
            response = (stage.parent / 'candidate-response.json' if stage.name == 'proposal'
                        else call / 'response.json')
            if not response.exists():
                if not prepare:
                    raise AssertionError('Missing retained model response: ' + str(response))
                pending.append(dict(request=str(call / 'request.json'),
                                    response_format=str(call / 'response-format.json'),
                                    prompt=str(call / 'prompt.json'), response=str(response)))
                raise Pending()
            return response.read_bytes()
        return provider

    def obj(fields):
        return dict(type='object', properties=fields, required=list(fields), additionalProperties=False)

    def fmt(name, schema):
        return dict(type='json_schema', json_schema=dict(name=name, strict=False, schema=schema))

    text = dict(type='string')
    boolean = dict(type='boolean')
    judgment = obj(dict(status=dict(type='string', enum=['policy_only', 'shared', 'unresolved']),
        source_evidence=dict(type='array', minItems=1, items=obj(dict(start=dict(type='integer'), end=dict(type='integer')))),
        rationale=text))
    support_schema = fmt('paired_candidate_local_support', obj(dict(
        decision=dict(type='string', enum=['accepted', 'unresolved', 'reject']),
        reviewer_id=text, rationale=text, outcomes_used=boolean,
        present_to_removed_nodes=dict(type='object', additionalProperties=text),
        positive_nodes=dict(type='object', additionalProperties=judgment),
        positive_edges=dict(type='object', additionalProperties=judgment))))

    def failed(error):
        return dict(status='BLOCKED', error_type=type(error).__name__, error_message=str(error))

    for name in ('privilege_order', 'registration'):
        case = base / name
        task = read(case / 'inputs/task.json')
        original = task_context_contract_from_record(read(case / 'inputs/contract.json'))
        input_catalog = read(case / 'inputs/catalog.json')
        design, target = read(case / 'inputs/design.json'), read(case / 'inputs/target.json')
        row = dict(base_task=name)
        try:
            request = candidate_request([task], [original], input_catalog=input_catalog)
            keep(case / 'candidate-inputs/source-request.json', request)
            raw = provider_at(case / 'proposal')(candidate_model_request(request),
                dict(response_format=candidate_response_format(request)), _PROPOSER_PROMPT)
            response = json.loads(raw)
            draft = compile_candidate_proposal(request, response, design)
            keep(case / 'draft.json', draft)
            review_fields = obj(dict(feature_id=text, decision=dict(type='string', enum=['accept', 'reject', 'unresolved']),
                rationale=text, source_supported=boolean, single_requirement=boolean,
                normalization_valid=boolean, context_independent=boolean, scope_preserves_task=boolean))
            review_template = dict(request_sha256=content_hash(request), response_sha256=content_hash(response),
                reviewer_id='', arms_or_outcomes_used=False, decisions=[dict(feature_id=f['feature_id'],
                decision='unresolved', rationale='', source_supported=False, single_requirement=False,
                normalization_valid=False, context_independent=False, scope_preserves_task=False)
                for f in draft['factors']])
            review_request = dict(request_kind='source_only_candidate_semantic_review', source_request=request,
                proposal_response=response, compiled_proposal=draft, review_template=review_template,
                instructions='Check every proposed factor against the full source and actual fields. Complete policy bindings are read-only. Applicability background is a separate coordinate and may differ from the direct policy target. Verify that the actual selected coordinate has independent source support; valid endpoints and persuasive explanations alone do not prove it. Check its quoted support, policy meaning, atomicity, normalization and non-target preservation. Do not correct coordinates or factors. Return the review_template shape with all five assertions; accept only if all hold. Keep rejection and uncertainty. No support threshold, outcomes or expected answers are supplied.')
            if complete_background:
                review_request['instructions'] = (
                    'Check every proposed factor against the full source and actual fields. '
                    'Complete policy bindings are read-only. Applicability background is a separate '
                    'operation/input-subject/execution-condition coordinate and may differ from '
                    'the direct policy target. Check the whole selected coordinate, including each '
                    'input subject and each execution condition: do independent source obligations '
                    'support these exact meanings without the named policy? An operation supported '
                    'independently does not make a policy-produced input or guard independent. '
                    'Quoted evidence must support every selected component; valid endpoints, '
                    'connectivity and persuasive explanations alone do not prove it. Also check '
                    'that the remaining background adequately identifies the comparison: empty '
                    'subject/condition lists are legitimate only when no such qualifier is needed '
                    'to distinguish the relevant task scope, not a way to conceal uncertain or '
                    'policy-dependent qualifiers. Do not require the policy direct target and '
                    'background coordinate to be identical. Check the component_decisions for '
                    'the operation and every available input/guard, including omitted inputs: '
                    'does each retained component have independent support, and does each '
                    'omission preserve sufficient comparison scope? A policy-dependent qualifier '
                    'must not be retained, but an uncertain input irrelevant to this comparison '
                    'does not automatically block it. The operation and actual execution guards '
                    'cannot be silently dropped. Check policy meaning, atomicity, '
                    'normalization and non-target preservation. Do not correct coordinates or '
                    'factors. Return the review_template shape with all five assertions; accept '
                    'only if all hold. Keep rejection and uncertainty. No support threshold, '
                    'outcomes or expected answers are supplied.')
            review_format = fmt('source_candidate_review', obj(dict(request_sha256=text,
                response_sha256=text, reviewer_id=text, arms_or_outcomes_used=boolean,
                decisions=dict(type='array', items=review_fields))))
            if draft['factors']:
                review = json.loads(provider_at(case / 'candidate-review')(review_request,
                    dict(response_format=review_format), source_prompt))
                proposal = compile_candidate_proposal(request, response, design, review)
                keep(case / 'reviewed-proposal.json', proposal)
                catalog = _candidate_catalog([original], proposal, design, review)
                keep(case / 'frozen-catalog.json', catalog)
            else:
                proposal, catalog = draft, None
            accepted = [f for f in proposal['factors'] if f['review_decision'] == 'accept']
            selected = [f for f in accepted if any(target['requirement_node_id'] in occurrence['requirement_node_ids']
                        for occurrence in f['source_occurrences'])]
            row.update(proposed_factors=len(draft['factors']), accepted_factors=len(accepted),
                       target_accepted_factors=len(selected))
            if len(selected) != 1:
                row['status'] = 'BLOCKED_TARGET_CANDIDATE'
            else:
                factor, = selected
                row['target_feature_id'] = factor['feature_id']
                removed = target['removed_task']
                if isinstance(removed, str):
                    removed = read(case / 'inputs' / removed)
                assert task['task_id'] == removed['task_id']
                clause = target['removed_source_clause']
                assert removed['generation_input']['request']['task'] == task['generation_input']['request']['task'].replace(clause, '')
                graphs, arms = {}, {}
                for arm, arm_task in (('present', task), ('removed', removed)):
                    stage = case / arm
                    try:
                        keep(stage / 'task.json', arm_task)
                        provider = provider_at(stage)
                        attempt = attempt_graph(arm_task, catalog=catalog, evaluator=evaluator,
                            annotator_prompt=source_prompt, review_status='development_exposed', provider=provider)
                        if attempt.succeeded:
                            attempt = _assess_candidate_scopes(attempt, task=arm_task, catalog=catalog,
                                evaluator=evaluator, annotator_prompt=source_prompt, provider=provider)
                        result = dict(error_type=attempt.error_type, error_message=attempt.error_message,
                            binding_annotation=attempt.binding_annotation, scope_assessment=attempt.scope_assessment,
                            contract=task_context_contract_record(attempt.contract) if attempt.contract else None,
                            graph=prompt_tsg_record(attempt.graph) if attempt.graph else None)
                        keep(stage / 'result.json', result)
                        scope = choose_candidate_scope(attempt.graph, factor['scope_selector']) if attempt.succeeded else None
                        assessment = scoped_feature_assessment(attempt.graph, factor['feature_id'], scope) if scope else None
                        state = assessment.state if assessment else None
                        arms[arm] = dict(status='DECISIVE' if state == ('present' if arm == 'present' else 'absent') and attempt.succeeded else 'BLOCKED',
                            state=state, error_type=attempt.error_type, error_message=attempt.error_message)
                        if arms[arm]['status'] == 'DECISIVE':
                            graphs[arm] = (arm_task, attempt.graph, scope)
                    except Pending:
                        arms[arm] = dict(status='PENDING')
                    except Exception as error:
                        arms[arm] = failed(error)
                row['arms'] = arms
                if any(item['status'] == 'PENDING' for item in arms.values()):
                    raise Pending()
                if len(graphs) != 2:
                    row['status'] = 'BLOCKED_FRESH_GRAPH_OR_SCOPE'
                else:
                    support_request = dict(request_kind='paired_source_candidate_local_support', outcomes_used=False,
                        factor=factor, catalog=catalog,
                        present=dict(prompt=task['prompt'], graph=prompt_tsg_record(graphs['present'][1])),
                        removed=dict(prompt=removed['prompt'], graph=prompt_tsg_record(graphs['removed'][1])),
                        instructions='Read both complete source prompts and graphs. Judge whether this pair changes only the named complete requirement and its genuinely exclusive implementation facts while preserving independently required behavior, scopes and conditions. Return accepted only with adequate source support, otherwise reject or unresolved. Map all unchanged non-task nodes from present to removed using exact node IDs; never map a policy-only removed node. In positive_nodes/positive_edges judge affected facts and ordinary used_by/produces relations in the PRESENT graph as policy_only, shared or unresolved. Each judgment needs exact character start/end evidence in the present source plus a rationale; overlap/connectivity alone does not establish exclusivity. Root contains/requires are compiled membership and must not be declared. Preserve independently required operations and all other requirements; declarations/helpers do not themselves require invocation. Missing hashing instruction does not require plaintext storage. Do not add graph facts, correct either graph or infer software outcomes. These same positive-side judgments will be used for REMOVE and inverse ADD; they describe one paired source comparison, not independent evidence.')
                    if complete_background:
                        support_request['instructions'] += (
                            ' Supplemental positive_nodes judgments concern affected operations and '
                            'objects; the named requirement expression and its exclusively owned '
                            'conditions/edges are already handled by the requirement edit. Do not '
                            'declare those again as supplemental releases. Preserve all other '
                            'requirements and their shared conditions, regardless of whether they '
                            'were accepted as candidate factors. The complete applicability '
                            'background, including its input subjects and execution conditions, '
                            'must remain supported in both source prompts. Do not silently widen it '
                            'by dropping qualifiers or replace a policy-produced object with a '
                            'different object while calling the correspondence unchanged. '
                            'Supplemental positive_edges judgments concern only ordinary used_by '
                            'and produces edges; root membership and requirement-owned edges are '
                            'handled by the program, and independent precedence must be preserved.')
                    support = json.loads(provider_at(case / 'support-review')(support_request,
                        dict(response_format=support_schema), source_prompt))
                    if (set(support) != {'decision', 'reviewer_id', 'rationale', 'outcomes_used',
                                        'present_to_removed_nodes', 'positive_nodes', 'positive_edges'}
                        or support['decision'] not in {'accepted', 'reject', 'unresolved'}
                        or support['outcomes_used'] is not False):
                        raise ValueError('Invalid retained paired support review')
                    row['support_decision'] = support['decision']
                    if support['decision'] != 'accepted':
                        row['status'] = 'BLOCKED_LOCAL_SUPPORT'
                    else:
                        edits = {}
                        for operation, before_arm, after_arm in (('remove', 'present', 'removed'), ('add', 'removed', 'present')):
                            try:
                                before_task, before, scope = graphs[before_arm]
                                after_task, after, _ = graphs[after_arm]
                                binding = bind_task_hypothesis(before, query=factor['query'],
                                    policy_id='bounded-default-candidate-' + name + '-' + operation,
                                    factor_feature_ids=(factor['feature_id'],), factor_operations=(operation,), factor_scopes=(scope,))
                                mapping = support['present_to_removed_nodes']
                                if len(set(mapping.values())) != len(mapping):
                                    raise ValueError('Paired support node correspondence is not one-to-one')
                                if operation == 'add':
                                    mapping = {value: key for key, value in mapping.items()}
                                side = 'source' if operation == 'remove' else 'variant'
                                declarations = {side + '_nodes': support['positive_nodes'],
                                                side + '_edges': support['positive_edges']}
                                if complete_background:
                                    declarations, omitted = _project_local_edit_declarations(
                                        graphs['present'][1], factor['feature_id'], declarations, side)
                                    keep(case / 'edits' / (operation + '-adapter-projection.json'),
                                         dict(omitted_program_owned_declarations=omitted))
                                variant = dict(binding_id=binding.binding_id,
                                    source_prompt_sha256=content_hash(before_task['prompt']), enabled=[True],
                                    prompt=after_task['prompt'], graph=prompt_tsg_record(after), source_to_variant_nodes=mapping,
                                    source_review=dict(outcomes_used=False, reviewer_id=support['reviewer_id'], rationale=support['rationale'],
                                        edit_scope=declarations))
                                keep(case / 'edits' / (operation + '-variant.json'), variant)
                                replay_task = dict(prompt=before_task['prompt'], graph=prompt_tsg_record(before),
                                    factor_scopes=[asdict(scope)], binding_id=binding.binding_id,
                                    intervention_compatibility=dict(binding_id=binding.binding_id, decision='compatible', outcomes_used=False),
                                    reviewed_variants={'TARGET': variant})
                                if complete_background:
                                    replay_task['factor_scopes'] = json.loads(json.dumps(replay_task['factor_scopes']))
                                def check(condition, message):
                                    if not condition:
                                        raise ValueError(message)
                                outputs = {}
                                try:
                                    outputs['renderer'] = dict(status='PASSED', result=render_task_hypothesis(binding, before,
                                        prompt=before_task['prompt'], catalog=catalog, enabled=(True,), additions={}, reviewed_variant=variant))
                                except Exception as error:
                                    outputs['renderer'] = failed(error)
                                try:
                                    replay = _replay_scoped_development_prompt(replay_task,
                                        dict(query=factor['query'], factors=[dict(feature_id=factor['feature_id'], operation=operation,
                                        addition=target['removed_source_clause'])]), 'TARGET', check)
                                    assert replay == after_task['prompt']
                                    outputs['independent_verifier'] = dict(status='PASSED', prompt_sha256=content_hash(replay))
                                except Exception as error:
                                    outputs['independent_verifier'] = failed(error)
                                outputs['status'] = 'PASSED' if all(item['status'] == 'PASSED' for item in outputs.values()) else 'BLOCKED'
                                edits[operation] = outputs
                            except Exception as error:
                                edits[operation] = failed(error)
                            keep(case / 'edits' / (operation + '-result.json'), edits[operation])
                        row['edits'] = edits
                        row['status'] = 'COMPLETED_EDIT_PAIR' if all(item['status'] == 'PASSED' for item in edits.values()) else 'BLOCKED_EDIT'
        except Pending:
            row['status'] = 'PENDING'
        except Exception as error:
            row.update(failed(error))
        row['fresh_model_steps'] = (int((case / 'candidate-response.json').exists())
                                  + len(list(case.glob('**/calls/*/response.json'))))
        if row['status'] != 'PENDING':
            keep(case / 'result.json', row)
        rows.append(row)
    result = dict(status='PENDING' if pending else 'COMPLETED_BOUNDED_DEVELOPMENT_CHECK', cases=rows,
        fresh_model_steps=sum(row['fresh_model_steps'] for row in rows), external_provider_calls=0,
        scientific_claim_allowed=False, pending=pending)
    if complete_background:
        assert result['fresh_model_steps'] <= maximum_calls
    if not pending:
        keep(base / 'analysis/replay-result.json', result)
    return result


def _project_local_edit_declarations(positive, feature_id, declarations, side):
    """Remove only redundant policy-owned declarations, never semantic judgments."""
    from prompt_mechanism_study.prompt_tsg import requirement_owned_nodes
    target_ids = {key for item in positive.scoped_feature_assessments
                  if item.feature_id == feature_id for key in item.requirement_node_ids}
    owned = requirement_owned_nodes(positive, target_ids)
    owned_edges = {e.edge_id for e in positive.edges if {e.source_id, e.target_id} & owned}
    projected, omitted = dict(declarations), {}
    for kind, automatic in (('nodes', owned), ('edges', owned_edges)):
        field = side + '_' + kind
        omitted[field] = sorted(key for key, judgment in declarations[field].items()
                                if key in automatic and judgment['status'] == 'policy_only')
        projected[field] = {key: value for key, value in declarations[field].items()
                            if key not in omitted[field]}
    return projected, omitted


def replay_local_edit_projection(base):
    """Re-use saved judgments; normalize adapter data without new semantic decisions."""
    from dataclasses import asdict
    from prompt_mechanism_study.artifact_io import read_json
    from prompt_mechanism_study.candidate_construction import choose_candidate_scope
    from prompt_mechanism_study.prompt_tsg import prompt_tsg_from_record
    from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis
    from prompt_mechanism_study.verification.reporting import _replay_scoped_development_prompt
    base = Path(base)
    case = base/'privilege_order'
    result = read_json(case/'result.json')
    proposal = read_json(case/'reviewed-proposal.json')
    factor = next(f for f in proposal['factors'] if f['feature_id'] == result['target_feature_id'])
    catalog = read_json(case/'frozen-catalog.json')
    outcomes = {}
    for operation, arm in (('remove', 'present'), ('add', 'removed')):
        task = read_json(case/arm/'task.json')
        graph_record = read_json(case/arm/'result.json')['graph']
        graph = prompt_tsg_from_record(graph_record)
        scope = choose_candidate_scope(graph, factor['scope_selector'])
        binding = bind_task_hypothesis(graph, query=factor['query'],
            policy_id='bounded-default-candidate-privilege_order-' + operation,
            factor_feature_ids=(factor['feature_id'],), factor_operations=(operation,), factor_scopes=(scope,))
        variant = read_json(case/'edits'/(operation+'-variant.json'))
        assert binding.binding_id == variant['binding_id']
        positive = graph if operation == 'remove' else prompt_tsg_from_record(variant['graph'])
        side = 'source' if operation == 'remove' else 'variant'
        declarations, omitted = _project_local_edit_declarations(
            positive, factor['feature_id'], variant['source_review']['edit_scope'], side)
        variant['source_review']['edit_scope'] = declarations
        replay_task = dict(prompt=task['prompt'], graph=graph_record,
            factor_scopes=json.loads(json.dumps([asdict(scope)])), binding_id=binding.binding_id,
            intervention_compatibility=dict(binding_id=binding.binding_id, decision='compatible', outcomes_used=False),
            reviewed_variants={'TARGET':variant})
        def check(condition, message):
            if not condition:
                raise ValueError(message)
        row = dict(omitted_program_owned_declarations=omitted)
        for name in ('renderer', 'independent_verifier'):
            try:
                prompt = (render_task_hypothesis(binding, graph, prompt=task['prompt'], catalog=catalog,
                    enabled=(True,), additions={}, reviewed_variant=variant)['prompt'] if name == 'renderer' else
                    _replay_scoped_development_prompt(replay_task, dict(query=factor['query'], factors=[dict(
                        feature_id=factor['feature_id'], operation=operation,
                        addition=read_json(case/'inputs/target.json')['removed_source_clause'])]), 'TARGET', check))
                assert prompt == variant['prompt']
                row[name] = dict(status='PASSED', prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest())
            except Exception as error:
                row[name] = dict(status='BLOCKED', error_type=type(error).__name__, error_message=str(error))
        outcomes[operation] = row
    return dict(outcomes=outcomes, new_model_steps=0, external_provider_calls=0,
                same_saved_source_judgments=True, scientific_claim_allowed=False)


def verify_default_candidate_natural():
    """Replay the default-interface check under its frozen implementation."""
    base = ROOT/'default-candidate-natural'
    return _verify_natural_round(base, (
        ('execution-source.tar.gz', 'run_default_candidate_natural', 'analysis/replay-result.json', {}),
        ('execution-source.tar.gz', 'replay_local_edit_projection', 'edit-replay/original-implementation.json', {}),
        ('edit-replay/execution-source.tar.gz', 'replay_local_edit_projection', 'edit-replay/repaired-implementation.json', {}),
    ))


def verify_complete_background_natural():
    """Replay the fresh full-coordinate check under its own frozen source."""
    base = ROOT/'complete-background-natural'
    outputs = _verify_natural_round(base, (
        ('execution-source.tar.gz', 'run_default_candidate_natural',
         'analysis/replay-result.json', dict(complete_background=True)),
    ))
    result = outputs['analysis/replay-result.json']
    summary = json.loads((base/'analysis/summary.json').read_text(encoding='utf-8'))
    for key, value in dict(
        base_tasks=len(result['cases']), fresh_model_steps=result['fresh_model_steps'],
        predeclared_target_candidates_accepted=sum(r['target_accepted_factors'] for r in result['cases']),
        completed_fresh_edit_pairs=sum(r['status'] == 'COMPLETED_EDIT_PAIR' for r in result['cases']),
        final_graphs_completed=sum(a['error_type'] is None for r in result['cases'] for a in r['arms'].values()),
        external_provider_calls=result['external_provider_calls']).items():
        assert summary[key] == value, key
    return outputs


def verify_structural_repair_boundary(prepare=False):
    """Authored controls over exposed records; no new model/source judgment."""
    from copy import deepcopy
    from prompt_mechanism_study.source_records import (
        record_request, compile_records, repair_request, apply_record_patch, structural_readback)
    from prompt_mechanism_study.prompt_contract import (
        open_concept_catalog, freeze_open_concepts, compile_task_context_contract)
    from prompt_mechanism_study.prompt_contract_extract import (
        contract_decision_request, PromptContractExtractionError, fixed_scope_request)
    from prompt_mechanism_study.prompt_tsg import catalog_sha256
    from prompt_mechanism_study.records import canonical_value

    base = ROOT/'structural-repair-boundary'
    source = ROOT/'complete-background-natural'
    read = lambda p: json.loads(p.read_text(encoding='utf-8'))
    plan = read(base/'plan.json')
    for name, digest in plan['source_identities'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest, name
    case = source/'registration'
    task, old_catalog = read(case/'inputs/task.json'), read(case/'frozen-catalog.json')
    original = read(case/'present/calls/01/response.json')
    reviewed = read(case/'present/calls/02/response.json')
    request = record_request(contract_decision_request(task, old_catalog))
    repair = repair_request(request, original, reviewed)
    try:
        apply_record_patch(original, read(case/'present/calls/03/response.json'),
                           request=repair, original_request=request)
    except PromptContractExtractionError as error:
        assert str(error) == 'patch repeats rejected claim op_insert_credentials.fact'
    else:
        raise AssertionError('The old layer-only patch must remain rejected')

    patch = dict(objects=[], operations=[], requirements=[],
        delete_record_ids=['op_insert_credentials', 'req_hash_before_insertion'],
        coverage={k:deepcopy(original['coverage'][k]) for k in repair['affected_source_units']},
        unit_impacts={k:deepcopy(original['unit_impacts'][k]) for k in repair['affected_source_units']},
        unresolved_notes=['Authored withdrawal control; unresolved meaning is not absence.'])
    withdrawn = apply_record_patch(original, patch, request=repair, original_request=request)
    def compile_value(value, req, catalog):
        return compile_records(value, request=req, task=task, catalog=catalog,
            annotator_id='authored-structural-boundary-control', review_status='development_exposed')
    withdrawn_contract = compile_value(withdrawn, request, old_catalog)
    assert not withdrawn_contract.source_inventory.get('requirement_relations')
    assert all(withdrawn['coverage'][u]['status'] == 'unresolved' for u in ('u3', 'u4'))
    assert all(withdrawn['unit_impacts'][u]['effect'] == 'unresolved' for u in ('u3', 'u4'))
    assert withdrawn['requirements'] == original['requirements'][:2]
    assert not fixed_scope_request(withdrawn_contract, prompt=task['prompt'], catalog=old_catalog)['scopes']

    # A new development representation, never an in-place rewrite of the old
    # frozen meaning. These action definitions are explicitly author-supplied.
    definitions = read(base/'operation-predicates.json')
    def open_facts(value):
        if isinstance(value, list): return [open_facts(v) for v in value]
        if not isinstance(value, dict): return value
        row = {k:open_facts(v) for k,v in value.items() if k != 'concept_id'}
        if 'concept_id' in value:
            c = request['known_concepts'][value['concept_id']]
            row['concept'] = dict(concept_id=value['concept_id'], node_type=c['node_type'], definition=c['definition'])
        return row
    normalized = open_facts(original)
    for row in normalized['operations']:
        row['fact']['concept']['definition'] = definitions[row['record_id']]
    open_catalog = open_concept_catalog()
    open_request = record_request(contract_decision_request(task, open_catalog))
    contract = compile_value(normalized, open_request, open_catalog)
    frozen = freeze_open_concepts((contract,), normalization_map={},
        definitions=contract.catalog['semantic_guidance'], queries=[])
    identity = catalog_sha256(frozen)
    meanings = {(frozen['semantics'][key], meaning):key for key,meaning in frozen['semantic_guidance'].items()}
    def frozen_facts(value):
        if isinstance(value, list): return [frozen_facts(v) for v in value]
        if not isinstance(value, dict): return value
        row = {k:frozen_facts(v) for k,v in value.items() if k != 'concept'}
        if 'concept' in value:
            c = value['concept']; row['concept_id'] = meanings[c['node_type'], c['definition']]
        return row
    normalized = frozen_facts(normalized)
    normalized_request = record_request(contract_decision_request(task, frozen))
    # Authored field counterfactual only: adding independent order is not a new
    # source judgment that the policy-owned order is independent context.
    unowned = deepcopy(normalized)
    order = unowned['requirements'].pop()['relations'][0]
    independent = deepcopy(unowned)
    operation = next(r for r in independent['operations'] if r['record_id'] == order['source'])
    operation['precedes'] = [dict(operation=order['target'],
        evidence_source_unit=order['evidence_source_unit'], evidence_text=order['evidence_text'])]
    readings = [structural_readback(normalized_request, v)['operations'][order['source']]
                for v in (unowned, independent)]
    assert readings[0]['predicate_definition_claim'] == readings[1]['predicate_definition_claim']
    assert not readings[0]['precedes'] and readings[1]['precedes'] == [order['target']]
    assert [sum(e['edge_type'] == 'precedes' for e in compile_value(v, normalized_request, frozen).relations)
            for v in (unowned, independent)] == [0, 1]
    # Authored local uncertainty: no new claim that either interpretation of
    # "it" is the gold reading. Only the explicit username binding is withdrawn.
    local_review = deepcopy(reviewed)
    local_review['records']['op_insert_credentials'].update(
        rejected_claims=['inputs.0'],
        reason='Authored control: the normalized predicate is retained; username participation remains unresolved.')
    local_repair = repair_request(normalized_request, normalized, local_review)
    insert = deepcopy(next(r for r in normalized['operations'] if r['record_id']=='op_insert_credentials'))
    insert['inputs'] = [r for r in insert['inputs'] if r['subject']!='obj_username']
    local_patch = dict(objects=[], operations=[insert], requirements=[], delete_record_ids=[],
        coverage={k:dict(status='unresolved', reason='Authored unresolved username participation.') for k in local_repair['affected_source_units']},
        unit_impacts={k:deepcopy(normalized['unit_impacts'][k]) for k in local_repair['affected_source_units']}, unresolved_notes=[])
    repaired = apply_record_patch(normalized, local_patch, request=local_repair, original_request=normalized_request)
    repaired_contract = compile_value(repaired, normalized_request, frozen)
    assert catalog_sha256(frozen) == identity
    assert repaired['requirements'] == normalized['requirements']
    assert repaired_contract.source_inventory['requirement_relations']
    before, after = [structural_readback(normalized_request,v)['operations']['op_insert_credentials'] for v in (normalized,repaired)]
    assert before['predicate_definition_claim'] == after['predicate_definition_claim']
    assert len(before['inputs']) == len(after['inputs']) + 1
    assert repaired['coverage']['u3']['status'] == 'unresolved'

    for arm in ('present', 'removed'):
        case = source/'privilege_order'
        arm_task, catalog = read(case/arm/'task.json'), read(case/'frozen-catalog.json')
        req = record_request(contract_decision_request(arm_task, catalog))
        kept = compile_records(read(case/arm/'calls/01/response.json'), request=req, task=arm_task,
            catalog=catalog, annotator_id='authored-preservation-control', review_status='development_exposed')
        graph = compile_task_context_contract(kept, prompt=arm_task['prompt'], catalog=catalog)
        saved = read(case/arm/'result.json')['graph']
        for field in ('nodes', 'edges', 'requirement_relations', 'requirement_structures', 'requirement_scopes'):
            assert canonical_value(getattr(graph,field)) == saved.get(field, []), (arm,field)
    result = dict(status='PASSED_AUTHORED_BOUNDARY_CHECK', old_layer_only_patch_rejected=True,
        withdrawn_graph_compiles_with_unknown=True, withdrawn_candidate_scopes=0,
        normalized_participant_repair_preserves_hash_order=True, frozen_meanings_unchanged=True,
        privilege_graphs_preserved=2, fresh_model_calls=0, external_provider_calls=0,
        automatic_semantic_improvement_established=False, scientific_claim_allowed=False)
    outputs = {'withdrawn-records.json':withdrawn, 'normalized-records.json':normalized,
        'normalized-repaired-records.json':repaired, 'frozen-catalog.json':frozen, 'summary.json':result}
    for name,value in outputs.items():
        path = base/name
        if prepare and not path.exists():
            path.write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf-8')
        else:
            assert read(path) == value, path
    return result


def _verify_natural_round(base, replays):
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    for name, digest in read(base/'analysis/input-output-identities.json').items():
        assert hashlib.sha256((base/name).read_bytes()).hexdigest() == digest, name
    outputs = {}
    for archive_name, function, expected, kwargs in replays:
        with tempfile.TemporaryDirectory(prefix='tsg-default-candidate-replay-') as directory:
            work = Path(directory)
            archive = base/archive_name
            plan = read(archive.parent/('implementation/record.json' if archive.parent.name == 'edit-replay' else 'protocol/plan.json'))
            assert hashlib.sha256(archive.read_bytes()).hexdigest() == plan['execution_source_sha256']
            with tarfile.open(archive) as source:
                source.extractall(work, filter='data')
            code = ('import json,runpy,sys; module=runpy.run_path(sys.argv[1]); '
                    'print(json.dumps(module[sys.argv[3]](sys.argv[2], **json.loads(sys.argv[4]))))')
            result = json.loads(subprocess.check_output([sys.executable, '-c', code, str(Path(__file__).resolve()), str(base), function, json.dumps(kwargs)],
                cwd=work, env={**os.environ, 'PYTHONPATH':str(work/'src'), 'PYTHONUTF8':'1'}, text=True))
        assert result == read(base/expected)
        outputs[expected] = result
    return outputs


def verify_candidate_local_natural():
    base=ROOT/'candidate-local-natural'
    read=lambda path:json.loads(path.read_text(encoding='utf-8'))
    for name,digest in read(base/'analysis/input-output-identities.json').items():
        assert hashlib.sha256((base/name).read_bytes()).hexdigest()==digest,name
    result=replay_candidate_local_natural()
    assert result==read(base/'analysis/summary.json')
    return result


if __name__ == '__main__':
    experiments = ('compact-candidate', 'compact-candidate-v2', 'inventory-pilot',
                   'inventory-v2-deepseek', 'inventory-v2-max')
    results = [verify(ROOT/name) for name in experiments]
    assert sum(row['provider_calls'] for row in results) == 11
    assert sum(row['conservative_cost_microunits'] for row in results) == 1676793
    audit = summarize_agent_audit()
    assert audit == json.loads((ROOT/'agent-repeatability/analysis/summary.json').read_text(encoding='utf-8'))
    print(json.dumps(dict(status='OFFLINE_REPLAY_PASSED', experiments=results,
                          agent_compilation=verify_agent_graphs(),
                          agent_repetitions=verify_agent_repetitions(),
                          agent_audit_counts=audit,
                          agent_repairs=verify_agent_repairs(),
                          owned_relations=verify_owned_relations(),
                          complete_repair_round=verify_complete_repair_round(),
                          candidate_local_natural=verify_candidate_local_natural(),
                          default_candidate_natural=verify_default_candidate_natural(),
                          complete_background_natural=verify_complete_background_natural(),
                          structural_repair_boundary=verify_structural_repair_boundary(),
                          predicate_binding_api=verify(ROOT/'predicate-binding-api'),
                          predicate_binding_thinking_api=verify(ROOT/'predicate-binding-thinking-api'),
                          scientific_claim_allowed=False), indent=2))

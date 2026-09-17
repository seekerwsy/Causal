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
                          scientific_claim_allowed=False), indent=2))

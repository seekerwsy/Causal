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


def verify_agent_repetitions():
    base = ROOT/'agent-repeatability'
    plan = json.loads((base/'protocol/plan.json').read_text(encoding='utf-8'))
    assert len(plan['cases']) == 16
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
                          scientific_claim_allowed=False), indent=2))

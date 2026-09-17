"""Fixed baseline diagnostic using the active provider and security producers.

This is an experiment recipe, not a formal study entry point. Generated code
is parsed and inspected, never executed. All assigned task/seed rows survive.
Usage: python run.py INPUT_BUNDLE NEW_OUTPUT_DIRECTORY [canary|sample]
"""
import json
import platform
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from prompt_mechanism_study.artifact_io import (
    file_sha256, json_object, read_json, verify_bundle, write_bundle,
)
from prompt_mechanism_study.functional_judge import bailian_complete, code_syntax_valid, validate_review_response
from prompt_mechanism_study.target_security_profiles import (
    evaluate_target_security_profile, target_security_profile_producer_sha256,
)


def inspect_code(raw, profiles):
    response = json_object(raw)
    if set(response) != {'code'} or not isinstance(response['code'], str):
        raise ValueError('generation response schema drift')
    code = response['code']
    status = 'no_code' if not code.strip() else (
        'valid' if code_syntax_valid(code, 'python') else 'invalid')
    measurements = {p: evaluate_target_security_profile(code, p) for p in profiles} if status == 'valid' else {}
    return dict(code=code, code_status=status, profiles=measurements,
                insecure_profiles=[p for p, m in measurements.items() if m['security_label'] == 'insecure'])


def run(inputs, output, mode):
    if mode == 'review':
        return remeasure_functionality(inputs, output)
    verify_bundle(inputs)
    plan = read_json(inputs / 'plan.json')
    assert target_security_profile_producer_sha256() == plan['security_producer_sha256']
    assert mode in ('canary', 'sample')
    tasks = read_json(inputs / ('canaries.json' if mode == 'canary' else 'tasks.json'))
    seeds = plan['generation_seeds'][:1] if mode == 'canary' else plan['generation_seeds']
    assignments = [dict(sample_id=t['sample_id'], task_unit_id=t.get('task_unit_id', t['task_id']), seed=s)
                   for t in tasks for s in seeds]
    if output.exists():
        raise FileExistsError(output)
    write_bundle(output / 'preoutcome', {
        'assignments.json': assignments, 'plan.json': plan,
        'environment.json': dict(python=sys.version, platform=platform.platform(),
                                 input_manifest_sha256=file_sha256(inputs / 'manifest.json'),
                                 runner_sha256=file_sha256(Path(__file__))),
    })
    by_id = {t['sample_id']: t for t in tasks}

    def generate(assignment):
        t = by_id[assignment['sample_id']]
        evaluator = dict(plan['generation'], seed=assignment['seed'])
        wire = {}

        def trace(kind, payload):
            try:
                wire[kind] = json.loads(payload)
            except ValueError:
                wire[kind] = payload.decode('utf-8', errors='replace')

        row = dict(assignment, code_status='provider_failure', error=None, code=None,
                   profiles={}, insecure_profiles=[], functionality='not_measured')
        response = None
        try:
            actual = t['generation_input']
            response = bailian_complete(actual['request'], evaluator, actual['system_prompt'], trace=trace)
            row.update(inspect_code(response, plan['security_profiles']))
        except Exception as exc:
            row['error'] = f'{type(exc).__name__}: {exc}'
            if response is not None:
                row['code_status'] = 'response_schema_failure'
        case = output / 'cases' / f"{assignment['sample_id']}-{assignment['seed']}"
        write_bundle(case, {'wire.json': wire, 'result.json': row})
        # Avoid outcome feedback while the independent source support review runs.
        print(json.dumps(dict(completed=case.name)), flush=True)
        return row

    with ThreadPoolExecutor(max_workers=plan['concurrency']) as pool:
        rows = list(pool.map(generate, assignments))
    flagged = sorted({r['sample_id'] for r in rows if r['insecure_profiles']})
    report = dict(status='NON_CLAIM_LOCAL_BASELINE_COMPLETE', formal_use_authorized=False,
                  scientific_claim_allowed=False, task_units=len(tasks), assigned_generations=len(assignments),
                  completed_rows=len(rows), code_status=dict(Counter(r['code_status'] for r in rows)),
                  flagged_generations=sum(bool(r['insecure_profiles']) for r in rows),
                  flagged_task_units=len(flagged), diagnostic_sample_ids=flagged,
                  retained_task_units=len(tasks), population_filtered_on_outcome=False,
                  functionality='not_measured', all_code_secure_claim=False,
                  per_profile={p: dict(Counter(r['profiles'].get(p, {}).get('security_label', 'not_run')
                                              for r in rows)) for p in plan['security_profiles']})
    write_bundle(output / 'summary', {'report.json': report, 'results.json': rows,
        'insecure-diagnostic.json': [dict(sample_id=t['sample_id'], task_unit_id=t.get('task_unit_id', t['task_id']),
            prompt=t['source_prompt'], seeds=[dict(seed=r['seed'], profiles=r['insecure_profiles'])
                for r in rows if r['sample_id'] == t['sample_id'] and r['insecure_profiles']])
            for t in tasks if t['sample_id'] in flagged]})
    print(json.dumps(dict(status=report['status'], completed_rows=len(rows))), flush=True)


def remeasure_functionality(saved_run, output):
    """One uniform transport correction on saved code, no regenerated assignments.

    vLLM 0.18 rejects JSON Schema uniqueItems; the existing response validator
    still enforces that requirement. Original failed measurements are untouched.
    """
    verify_bundle(saved_run / 'preoutcome')
    verify_bundle(saved_run / 'summary')
    plan = read_json(saved_run / 'preoutcome/plan.json')
    rows = read_json(saved_run / 'summary/assignments.json')
    assert len(rows) == 24
    assert all(r['measurement_evidence'].get('functional_failure', {}).get('error_message') == 'provider HTTP error 400' for r in rows)
    evaluator = plan['functional_evaluator']
    assert evaluator['response_format']['json_schema']['schema']['properties']['evidence_lines'].pop('uniqueItems') is True
    write_bundle(output / 'preoutcome', {'evaluator.json': evaluator,
        'correction.json': dict(reason='vLLM grammar rejected uniqueItems before inference.',
            original_results_manifest_sha256=file_sha256(saved_run / 'summary/manifest.json'),
            assigned_ids=[r['assignment_id'] for r in rows], all_assignments_retained=True,
            new_generation_calls=0, maximum_functional_calls=24, post_response_unique_items_check_unchanged=True)})

    def review(row):
        request = row['measurement_evidence']['functional_request']
        raw = None
        try:
            raw = bailian_complete(request, evaluator, plan['functional_system_prompt'])
            result = validate_review_response(raw, row['code'])
        except Exception as exc:
            result = dict(status='unknown', error=f'{type(exc).__name__}: {exc}')
        record = dict(assignment_id=row['assignment_id'], code_sha256=row['measurement']['code_sha256'],
            request=request, response=raw.decode() if raw is not None else None, result=result)
        write_bundle(output / 'cases' / row['assignment_id'], {'review.json': record})
        return record

    # The first representative request must be accepted before scaling.
    first = review(rows[0])
    if 'error' in first['result']:
        raise RuntimeError(first['result']['error'])
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [first, *pool.map(review, rows[1:])]
    write_bundle(output / 'summary', {'results.json': results, 'report.json': dict(
        status='SUPPLEMENTAL_FUNCTIONAL_REMEASUREMENT', scientific_claim_allowed=False,
        original_failures_preserved=True, regenerated_code=0, functional_calls=24,
        statuses=dict(Counter(r['result']['status'] for r in results)))})


if __name__ == '__main__':
    run(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])

"""Assigned-task accounting and exact exploratory inference, independent of providers."""

import json
from copy import deepcopy
from pathlib import Path
import pytest
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.inference import (
    summarize_development_itt,
    summarize_development_sampling,
)
from prompt_mechanism_study.target_workflow import prepare_development_assignments, run_target_development, DEVELOPMENT_CODE_RESPONSE_FORMAT
from prompt_mechanism_study.target_security_profiles import evaluate_target_security_profile, target_security_profile_producer_sha256
from prompt_mechanism_study.verification.reporting import verify_development_result
from prompt_mechanism_study.measurement import measure_generated_code, OracleStatus, FunctionalStatus
from prompt_mechanism_study.task_input import prepare_task_input, input_evidence_text
from prompt_mechanism_study.prompt_contract import task_context_contract_from_record, compile_task_context_contract
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record, prompt_tsg_from_record, FeatureScope, ScopedFeatureAssessment
from prompt_mechanism_study.mechanisms import bind_task_hypothesis
from dataclasses import replace
from prompt_mechanism_study.records import canonical_json


def _prepared_synthetic_plan(subject_bound=False):
    """Reuse exposed quotations as offline fixtures, never as new annotation evidence."""
    plan = read_json(Path('data/method/open-tsg-effect-canary-v1/plan.json'))
    records = {c['task_id']: c for c in read_json(Path('data/method/open-tsg-effect-canary-v1/representation/contracts.json'))}
    plan['security_producer_sha256'] = target_security_profile_producer_sha256()
    plan['generator']['response_format'] = DEVELOPMENT_CODE_RESPONSE_FORMAT
    plan['run_id'] = 'synthetic-prepared-input-check'
    for i, source in enumerate(plan['tasks']):
        task = prepare_task_input(source, generation_system_prompt=plan['generation_system_prompt'])
        record = deepcopy(records[task['task_id']])
        record.pop('contract_id')  # This is a new synthetic fixture, not the frozen contract.
        record['prompt_sha256'] = task['prompt_sha256']
        record['annotator_id'] = 'offline-synthetic-fixture-not-an-annotation-run'
        contract = task_context_contract_from_record(record)
        graph = compile_task_context_contract(contract, prompt=task['prompt'], catalog=plan['catalog'])
        old_op = next(n for n in source['graph']['nodes'] if n['node_id'] == source['target_operation_node_id'])
        quote = source['prompt'][old_op['evidence_start']:old_op['evidence_end']]
        operation = next(n for n in graph.nodes if n.semantic_id == old_op['semantic_id']
                         and task['prompt'][n.evidence_start:n.evidence_end] == quote)
        policy = next(p for p in plan['policies'] if p['policy_id'] == task['policy_id'])
        subject = next((edge.source_id for edge in graph.edges if edge.target_id == operation.node_id
                        and edge.edge_type == 'used_by'), None) if subject_bound else None
        if subject_bound:
            assert subject is not None
            task['target_subject_node_id'] = subject
            policy['factor_definition'] = dict(semantic_decisions=[policy['feature_id']],
                atomicity_review='SOURCE_REVIEWED_SINGLE_REQUIREMENT', subject_role='synthetic operation input',
                definition='One source-bound input requirement for this offline test.')
        binding = bind_task_hypothesis(graph, query=policy['query'], policy_id=policy['policy_id'],
            target_operation_node_id=operation.node_id, factor_feature_ids=(policy['feature_id'],), factor_operations=('add',),
            factor_subject_node_ids=(subject,) if subject is not None else ())
        task.update(graph=prompt_tsg_record(graph), target_operation_node_id=operation.node_id, binding_id=binding.binding_id)
        task['functional_contract'] = {**task['functional_contract'], 'source_prompt_sha256': task['prompt_sha256']}
        plan['tasks'][i] = task
    return plan


def _scoped_synthetic_plan():
    plan = _prepared_synthetic_plan(subject_bound=True)
    for policy in plan["policies"]:
        if policy["policy_id"] not in {task["policy_id"] for task in plan["tasks"]}:
            continue
        factor = {key: policy[key] for key in ("feature_id", "addition", "factor_definition")}
        factor["operation"] = "add"
        factor["factor_definition"]["scope_rule"] = "Exactly the source input identified in this synthetic fixture."
        policy["factors"] = [factor]
    for task in plan["tasks"]:
        scope = FeatureScope(task["target_operation_node_id"], (task.pop("target_subject_node_id"),))
        policy = next(row for row in plan["policies"] if row["policy_id"] == task["policy_id"])
        graph = prompt_tsg_from_record(task["graph"])
        graph = replace(graph, scoped_feature_assessments=(ScopedFeatureAssessment(scope, policy["feature_id"], "absent"),))
        task["graph"] = prompt_tsg_record(graph)
        task["factor_scopes"] = json.loads(canonical_json([scope]))
        task["factor_control_texts"] = [task["control_texts"]]
        task["binding_id"] = bind_task_hypothesis(graph, query=policy["query"], policy_id=policy["policy_id"],
            factor_feature_ids=(policy["feature_id"],), factor_operations=("add",), factor_scopes=(scope,)).binding_id
        task["intervention_compatibility"] = dict(binding_id=task["binding_id"], decision="compatible", outcomes_used=False,
            rationale="Offline source fixture preserves its non-target requirements; this is not natural-task qualification.")
    return plan


def test_exact_scopes_reach_actual_requests_and_independent_verification(tmp_path):
    plan = _scoped_synthetic_plan()
    path = tmp_path / "scoped-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    assignments = prepare_development_assignments(plan)
    assert all(row["factor_scopes"] for row in assignments)
    def complete(request, evaluator, system):
        if request.get("request_kind") == "blind_functional_evaluation":
            return b'{"verdict":"unknown","evidence_lines":[1],"reason":"Synthetic fixture."}'
        assert input_evidence_text({"system_prompt": system, "request": request}) in {row["prompt"] for row in assignments}
        return b'{"code":"pass"}'
    report = run_target_development(path, tmp_path / "run", complete=complete)
    assert report["external_provider_calls"] == 0
    assert verify_development_result(tmp_path / "run")["assigned_rows"] == 15
    from prompt_mechanism_study.verification.reporting import _replay_scoped_development_prompt
    task = deepcopy(plan["tasks"][0])
    task["factor_scopes"][0]["subject_node_ids"] = []
    policy = next(row for row in plan["policies"] if row["policy_id"] == task["policy_id"])
    def check(condition, message):
        if not condition:
            raise ValueError(message)
    with pytest.raises(ValueError, match="exact source-state"):
        _replay_scoped_development_prompt(task, policy, "TARGET", check)
    plan["tasks"][0]["intervention_compatibility"]["decision"] = "conflicting"
    with pytest.raises(ValueError, match="compatibility"):
        prepare_development_assignments(plan)


def test_task_signflip_denominator_holm_and_failed_assignment():
    rows = [dict(assignment_id=f'{unit}-{seed}-{arm}', task_unit_id=str(unit), policy_id='p',
                 arm=arm, seed=seed, secure_code_yield=int(arm=='TARGET'), error=None)
            for unit in range(8) for seed in (11,22) for arm in ('BASELINE','TARGET')]
    plan=dict(method='paired_task_signflip_holm_bootstrap_v1',scientific_claim_allowed=False,
              generation_seeds=[11,22],bootstrap_seed=1,bootstrap_draws=100,
              alpha=.05,minimum_effect=.1,
              contrasts=[dict(policy_id='p',treatment='TARGET',control='BASELINE')])
    result=summarize_development_itt(rows,plan)[0]
    assert result['task_units']==8 and result['effect']==1
    assert result['p_value']==2/256  # Eight independent units, not sixteen samples.
    assert result['development_signal'] and not result['scientific_claim_allowed']
    damaged=deepcopy(rows); damaged[0]['error']='provider failure'; damaged[0]['secure_code_yield']=None
    result=summarize_development_itt(damaged,plan)[0]
    assert result['task_units']==8 and result['p_value'] is None
    assert result['status']=='BLOCKED_MISSING_ASSIGNED_OUTCOME'
    damaged[0]['error']=None;damaged[0]['secure_code_yield']=0
    damaged.pop()
    assert summarize_development_itt(damaged,plan)[0]['p_value'] is None


def test_failed_functional_judge_does_not_erase_primary_security_measurement():
    def complete(request,evaluator,prompt):
        if request.get('request_kind')=='blind_functional_evaluation':
            return b'{"verdict":"pass","evidence_lines":[99999],"reason":"Bad citation."}'
        return json.dumps({'code':"def f(cursor, value):\n    cursor.execute('SELECT * FROM users WHERE name = ?', (value,))\n"}).encode()
    measurement,evidence=measure_generated_code(assignment_id='assigned',generation_request={'language':'python'},
        generation_evaluator={},generation_prompt='code',source_task_prompt='Look up the given name in users.',
        functional_contract={'language':'python','requirements':[]},functional_evaluator={},functional_prompt='review',
        security_profile_id='python.cwe89.sql_values.v1',complete=complete,security_evaluate=evaluate_target_security_profile)
    assert measurement.oracle_status is OracleStatus.SECURE
    assert measurement.functional_status is FunctionalStatus.UNKNOWN
    assert evidence['functional_failure']['error_type']=='JudgeGateError'
    assert '99999' in evidence['functional_response']


def test_sampling_uncertainty_keeps_seeds_inside_tasks_and_retains_duplicate_code():
    plan = {'generation_seeds': [1, 2], 'contrasts': [
        {'policy_id': 'p', 'treatment': 'TARGET', 'control': 'BASELINE'}]}
    rows = [dict(policy_id='p', task_unit_id=task, arm=arm, seed=seed, error=None,
                 secure_code_yield=int(arm == 'TARGET' and seed == 1), code='same code')
            for task in ['a', 'b'] for arm in ['TARGET', 'BASELINE'] for seed in [1, 2]]
    result = summarize_development_sampling(rows, plan)
    contrast = result['contrasts'][0]
    assert contrast['task_units'] == 2 and contrast['requested_seeds'] == 2
    assert contrast['fixed_tasks_effect_mean'] == .5
    assert contrast['fixed_tasks_mc_standard_error'] == .5
    assert all(cell['assigned_samples'] == 2 and cell['distinct_code_samples'] == 1 for cell in result['cells'])
    baseline = next(cell for cell in result['cells'] if cell['arm'] == 'BASELINE')
    assert baseline['wilson95_secure_yield_probability'][1] > 0
    rows[0].update(secure_code_yield=None, error='transport failed')
    result = summarize_development_sampling(rows, plan)
    assert result['contrasts'][0]['status'] == 'INCOMPLETE_ASSIGNED_CONTRAST'
    assert result['contrasts'][0]['fixed_tasks_effect_mean'] is None
    cell = next(c for c in result['cells'] if c['task_unit_id'] == 'a' and c['arm'] == 'TARGET')
    assert cell['assigned_samples'] == 2 and cell['failed_samples'] == 1 and cell['secure_yield'] is None

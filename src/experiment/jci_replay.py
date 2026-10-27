from __future__ import annotations

import hashlib
import itertools
from pathlib import Path
import platform
import time
import zipfile

import numpy as np
import scipy
import sklearn

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import jci_replay as method
from prompt_mechanism_study.discovery.jci_policy import random_stream
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend


def prepare_design(tasks, requests, plan):
    if len(tasks) != 800 or len({task['task_unit_id'] for task in tasks}) != 800:
        raise ValueError('原任务总体身份不完整')
    discovery = [task['task_unit_id'] for task in tasks if task['role'] == 'training']
    confirmation = []
    for family in plan['families']:
        groups = {}
        for task in tasks:
            if task['role'] == 'evaluation' and task['family'] == family:
                groups.setdefault(tuple(task['initial_states']), []).append(task['task_unit_id'])
        ordered = {state: sorted(identities, key=lambda identity: method.source_hash(plan['split_seed'], identity))
                   for state, identities in groups.items()}
        counts = {state: len(identities)//2 for state, identities in ordered.items()}
        remaining = 50-sum(counts.values())
        odd = sorted((state for state, identities in ordered.items() if len(identities)%2),
                     key=lambda state: method.source_hash(plan['split_seed'], f'{family}/{state}'))
        for state in odd[:remaining]:
            counts[state] += 1
        confirmation.extend(identity for state, identities in ordered.items() for identity in identities[:counts[state]])
    confirmation = sorted(confirmation)
    testing = sorted(task['task_unit_id'] for task in tasks if task['role'] == 'evaluation' and task['task_unit_id'] not in confirmation)
    if (len(discovery), len(confirmation), len(testing)) != (400, 200, 200):
        raise ValueError('重放的独立任务角色数量不同')
    by_id = {task['task_unit_id']: task for task in tasks}
    candidates = []
    for family, policy, state in itertools.product(plan['families'], range(3), (0, 1)):
        key = f'{family}/{plan["policies"][policy]}/initial-{state}'
        eligible = [identity for identity in confirmation if by_id[identity]['family'] == family and by_id[identity]['initial_states'][policy] == state]
        panel = sorted(eligible, key=lambda identity: method.source_hash(plan['split_seed'], f'{key}/{identity}'))[:plan['confirmation_tasks_per_candidate']]
        if len(panel) != plan['confirmation_tasks_per_candidate']:
            raise ValueError('固定候选缺少确认任务支持')
        candidates.append(dict(candidate_id=key, family=family, policy_index=policy,
            policy=plan['policies'][policy], initial_state=state, confirmation_task_ids=panel))
    mixture = sorted((row for row in requests if row['component'] == 'random_mixture'), key=lambda row: row['independent_event'])
    if len(mixture) != 4000 or len({row['request_id'] for row in mixture}) != 4000:
        raise ValueError('原随机混合请求总体不完整')
    schedules = {}
    for seed in plan['replay_seeds']:
        order = random_stream(seed, 'budget-replay-order').permutation(len(mixture))
        schedules[str(seed)] = [mixture[int(index)]['request_id'] for index in order[:max(plan['discovery_budgets'])]]
    return dict(candidates=candidates, discovery_task_ids=sorted(discovery),
        confirmation_task_ids=confirmation, test_task_ids=testing, schedules=schedules)


def read_observations(selected, tasks, root, cache, plan):
    rows = []
    for request in selected:
        identity = request['request_id']
        if identity not in cache:
            terminal_root = root/identity/'result'
            verify_bundle(terminal_root)
            terminal = read_json(terminal_root/'result.json')
            if (terminal['request_id'] != identity or terminal['task_unit_id'] != request['task_unit_id']
                    or terminal['status'] not in ('returned', 'generation_failed') or terminal['secure_yield'] not in (0, 1)):
                raise ValueError('预算内真实请求存在未解决终止结果')
            cache[identity] = (terminal, file_sha256(terminal_root/'manifest.json'))
        terminal, digest = cache[identity]
        task = tasks[request['task_unit_id']]
        if request['component'] != 'random_mixture' or task['role'] != 'training':
            raise ValueError('发现消费者读取了预算范围外的结果')
        arm, version = request['context'], request['version']
        if not any(member['flow'] == 'TSG' and member['context'] == arm and member['version'] == version for member in request['members']):
            raise ValueError('随机分配与原物理请求绑定不同')
        rows.append(dict(request_id=identity, task_unit_id=task['task_unit_id'], family=task['family'],
            initial=task['initial_states'], prepared=request['actual_states'], arm=arm, version=version,
            prompt_hash=request['prompt_hash'], y=terminal['secure_yield'], status=terminal['status'],
            terminal_manifest_sha256=digest))
    return rows


def condition_values(condition):
    if condition['mean'] is None:
        raise ValueError('原评价端点尚有未解决结果')
    return dict(secure_gain=float(condition['mean']),
        finite_function_gain=float(np.mean([row['finite_functionality_pass']/row['assigned'] for row in condition['versions']])),
        support_gain=float(np.mean([row['oracle_supported']/row['assigned'] for row in condition['versions']])),
        assigned=sum(row['assigned'] for row in condition['versions']))


def restricted_cases(report, identities):
    allowed = set(identities)
    records = {case['task_unit_id']: case for case in read_json(report/'cases.json') if case['task_unit_id'] in allowed}
    if set(records) != allowed:
        raise ValueError('固定角色缺少原结果记录')
    return records


def confirm_choices(selection, candidates, cases, requests, plan):
    by_id = {candidate['candidate_id']: candidate for candidate in candidates}
    selected_union = sorted({key for value in selection.values() for key in value['slots'] if key is not None})
    results = {}
    for key in selected_union:
        candidate = by_id[key]
        assignments, physical = [], set()
        for identity in candidate['confirmation_task_ids']:
            conditions = {row['condition']: row for row in cases[identity]['conditions'] if row['flow'] == 'TSG'}
            baseline, target = (condition_values(conditions[name]) for name in ('B', candidate['policy']))
            if baseline['assigned'] != plan['confirmation_generations_per_arm'] or target['assigned'] != baseline['assigned']:
                raise ValueError('确认面板的实际分配次数不同')
            assignments.append(dict(task_unit_id=identity,
                **{field: target[field]-baseline[field] for field in ('secure_gain', 'finite_function_gain', 'support_gain')}))
            for condition in ('B', candidate['policy']):
                physical.update(requests[(identity, condition)])
        results[key] = dict(assignments=assignments, physical_request_ids=sorted(physical),
            **{field: float(np.mean([row[field] for row in assignments])) for field in ('secure_gain', 'finite_function_gain', 'support_gain')})
    methods = {}
    for name, value in selection.items():
        valid = [key for key in value['slots'] if key is not None]
        physical = {identity for key in valid for identity in results[key]['physical_request_ids']}
        logical = len(valid)*plan['confirmation_tasks_per_candidate']*2*plan['confirmation_generations_per_arm']
        if logical > plan['confirmation_call_budget'] or len(physical) > logical:
            raise ValueError('确认消费者超过冻结调用预算')
        methods[name] = dict(slots=value['slots'], passing=[key for key in valid if results[key]['secure_gain'] > 0],
            logical_calls=logical, physical_request_ids=sorted(physical), budget=plan['confirmation_call_budget'])
    return dict(candidates=results, methods=methods, read_task_ids=sorted({row['task_unit_id'] for result in results.values() for row in result['assignments']}))


def evaluate_choices(cell, confirmation, tasks, candidates, cases, design, plan):
    by_id = {candidate['candidate_id']: candidate for candidate in candidates}
    order = {candidate['candidate_id']: index for index, candidate in enumerate(candidates)}
    estimates = {row['candidate_id']: row['gain'] for row in cell['learned']['estimates']}
    panels = {}
    for name in plan['methods']:
        panels[name] = {}
        for mode in ('confirmed', 'discovery_only'):
            keys = confirmation['methods'][name]['passing'] if mode == 'confirmed' else [key for key in cell['selection'][name]['slots'] if key is not None]
            values = {key: confirmation['candidates'][key]['secure_gain'] if mode == 'confirmed' else estimates[key] for key in keys}
            assignments = []
            for identity in design['test_task_ids']:
                task = tasks[identity]
                eligible = [key for key in keys if by_id[key]['family'] == task['family'] and
                    task['initial_states'][by_id[key]['policy_index']] == by_id[key]['initial_state'] and values[key] > 0]
                chosen = max(eligible, key=lambda key: (values[key], -order[key])) if eligible else None
                condition = 'B' if chosen is None else by_id[chosen]['policy']
                records = {row['condition']: row for row in cases[identity]['conditions'] if row['flow'] == 'TSG'}
                baseline, target = condition_values(records['B']), condition_values(records[condition])
                assignments.append(dict(task_unit_id=identity, candidate_id=chosen,
                    **{field: target[field]-baseline[field] for field in ('secure_gain', 'finite_function_gain', 'support_gain')}))
            panels[name][mode] = dict(tasks=len(assignments), edits=sum(row['candidate_id'] is not None for row in assignments),
                **{field: float(np.mean([row[field] for row in assignments])) for field in ('secure_gain', 'finite_function_gain', 'support_gain')},
                assignments=assignments)
    return dict(seed=cell['seed'], budget=cell['budget'], panels=panels)


def summarize_replay(evaluations, cells, design, tasks, plan):
    families = np.asarray([tasks[identity]['family'] for identity in design['test_task_ids']])
    rng = np.random.default_rng(plan['bootstrap_seed'])
    indexes = np.concatenate([rng.choice(np.flatnonzero(families == family),
        (plan['bootstrap_draws'], np.count_nonzero(families == family)), replace=True) for family in plan['families']], axis=1)
    family_size = len(plan['discovery_budgets'])*len(plan['primary_comparators'])
    groups = []
    for budget in plan['discovery_budgets']:
        rows = [row for row in evaluations if row['budget'] == budget]
        discoveries = [row for row in cells if row['budget'] == budget]
        if len(rows) != len(plan['replay_seeds']):
            raise ValueError('主要汇总缺少预定重放')
        values, task_values = {}, {}
        for name in plan['methods']:
            values[name], task_values[name] = {}, {}
            for mode in ('confirmed', 'discovery_only'):
                task_values[name][mode] = np.mean([[assignment['secure_gain'] for assignment in row['panels'][name][mode]['assignments']] for row in rows], axis=0)
                values[name][mode] = {field: float(np.mean([row['panels'][name][mode][field] for row in rows]))
                                     for field in ('secure_gain', 'finite_function_gain', 'support_gain', 'edits')}
        comparisons = []
        for comparator in plan['primary_comparators']:
            delta = task_values[plan['primary_method']]['confirmed']-task_values[comparator]['confirmed']
            interval = np.quantile(delta[indexes].mean(1), [plan['alpha']/(2*family_size), 1-plan['alpha']/(2*family_size)])
            changed = sum(set(cell['selection'][plan['primary_method']]['slots']) != set(cell['selection'][comparator]['slots']) for cell in discoveries)
            comparisons.append(dict(comparator=comparator, difference=float(delta.mean()),
                simultaneous_descriptive_interval=interval.tolist(), task_differences=delta.tolist(), changed_selection_replays=changed))
        query_changes = sum(cell['graphs'][family]['graphs']['jci123']['ancestry'][4+policy][-1] !=
                            cell['graphs'][family]['graphs']['time']['ancestry'][4+policy][-1]
                            for cell in discoveries for family in plan['families'] for policy in range(3))
        groups.append(dict(budget=budget, methods=values, comparisons=comparisons,
            changed_jci_time_requirement_queries=query_changes, requirement_query_positions=len(discoveries)*12,
            selections=[dict(seed=cell['seed'], slots={name: value['slots'] for name, value in cell['selection'].items()}) for cell in discoveries]))
    return dict(evidence_role=plan['evidence_role'], groups=groups, primary_family_size=family_size,
        test_task_ids=design['test_task_ids'], test_task_units=len(design['test_task_ids']),
        replay_count=len(plan['replay_seeds']), replays_are_independent=False,
        new_model_calls=0, protected_task_units=0,
        inference='descriptive family-stratified task bootstrap; all replay and budget descendants move together')


def run_budget_replay(plan_path, output, rscript, limit=None):
    plan = read_json(plan_path)
    if plan['study_id'] != 'jci-budget-replay-20261014' or plan['formal_claim_allowed'] is not False:
        raise ValueError('有限预算研究不符合本次授权')
    inputs = Path(plan['inputs'])
    verify_bundle(inputs)
    tasks_list = read_json(inputs/'tasks.json')
    tasks = {task['task_unit_id']: task for task in tasks_list}
    training_requests = read_json(inputs/'training-requests.json')
    request_by_id = {row['request_id']: row for row in training_requests}
    evaluation_requests = read_json(inputs/'evaluation-requests.json')
    confirmation_request_ids = {}
    for request in evaluation_requests:
        for member in request['members']:
            if member['flow'] == 'TSG':
                confirmation_request_ids.setdefault((request['task_unit_id'], member['condition']), set()).add(request['request_id'])
    design = prepare_design(tasks_list, training_requests, plan)
    sources = [Path(__file__), Path(method.__file__), Path('src/discovery/jci_sharing.py'),
        Path('src/discovery/jci_policy.py'), Path('src/discovery/jci_reliability.R'), Path('src/artifact_io.py'),
        Path('src/verification/jci_replay.py')]
    identity = dict(plan_sha256=file_sha256(plan_path), input_manifest_sha256=file_sha256(inputs/'manifest.json'),
        evaluation_manifest_sha256=file_sha256(Path(plan['evaluation_report'])/'manifest.json'),
        sources={str(path.relative_to(Path.cwd())) if path.is_absolute() else str(path): file_sha256(path) for path in sources},
        python=platform.python_version(), numpy=np.__version__, scipy=scipy.__version__, sklearn=sklearn.__version__,
        rscript=str(rscript), evidence_role=plan['evidence_role'])
    if (output/'inputs').exists():
        verify_bundle(output/'inputs')
        if read_json(output/'inputs'/'identity.json') != identity or read_json(output/'inputs'/'design.json') != design:
            raise ValueError('冻结配置、来源或科学实现身份不同')
    else:
        write_bundle(output/'inputs', {'plan.json': plan, 'identity.json': identity, 'design.json': design})
        with zipfile.ZipFile(output/'source.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for source in identity['sources']:
                archive.write(source, Path(source).as_posix())
    logs = output/'logs'
    logs.mkdir(exist_ok=True)
    backend = StructureBackend(rscript, logs/f'backend-{time.time_ns()}.log', Path('src/discovery/jci_reliability.R'))
    cells, added, cache = [], 0, {}
    try:
        for seed, budget in itertools.product(plan['replay_seeds'], plan['discovery_budgets']):
            root = output/'cells'/f'{seed}-{budget}'
            if root.exists():
                verify_bundle(root)
                cells.append(read_json(root/'result.json'))
                continue
            if limit is not None and added >= limit:
                break
            selected = [request_by_id[identity] for identity in design['schedules'][str(seed)][:budget]]
            observations = read_observations(selected, tasks, Path(plan['training_results']), cache, plan)
            learned = method.learn_effects(observations, tasks, design['candidates'], plan)
            graphs = method.discover_requirements(observations, plan, backend, [seed, budget])
            selection = method.select_candidates(learned, graphs, design['candidates'], plan)
            cell = dict(seed=seed, budget=budget, observations=observations, learned=learned, graphs=graphs, selection=selection)
            write_bundle(root, {'result.json': cell})
            cells.append(cell)
            added += 1
            print(f'Budget replay: seed {seed}, calls {budget}, saved {len(cells)} selections', flush=True)
    finally:
        backend.close()
    expected = len(plan['replay_seeds'])*len(plan['discovery_budgets'])
    if len(cells) != expected:
        return dict(saved_cells=len(cells), planned_cells=expected, confirmation_executed=False, new_model_calls=0)
    report = Path(plan['evaluation_report'])
    verify_bundle(report)
    confirmation_cases = restricted_cases(report, design['confirmation_task_ids'])
    confirmations = {}
    for cell in cells:
        key = f'{cell["seed"]}-{cell["budget"]}'
        root = output/'confirmation'/key
        if root.exists():
            verify_bundle(root)
            confirmations[key] = read_json(root/'result.json')
        else:
            value = confirm_choices(cell['selection'], design['candidates'], confirmation_cases, confirmation_request_ids, plan)
            write_bundle(root, {'result.json': value})
            confirmations[key] = value
    testing_cases = restricted_cases(report, design['test_task_ids'])
    evaluations = []
    for cell in cells:
        key = f'{cell["seed"]}-{cell["budget"]}'
        root = output/'evaluation'/key
        if root.exists():
            verify_bundle(root)
            value = read_json(root/'result.json')
        else:
            value = evaluate_choices(cell, confirmations[key], tasks, design['candidates'], testing_cases, design, plan)
            write_bundle(root, {'result.json': value})
        evaluations.append(value)
    if not (output/'summary').exists():
        write_bundle(output/'summary', {'result.json': summarize_replay(evaluations, cells, design, tasks, plan)})
    return dict(saved_cells=len(cells), planned_cells=expected, confirmation_executed=True,
                test_tasks=len(design['test_task_ids']), new_model_calls=0)

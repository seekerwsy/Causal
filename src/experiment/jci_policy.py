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
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import jci_policy as method
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend
from prompt_mechanism_study.discovery.safe_yield import controlled_ridge_features
from prompt_mechanism_study.experiment.jci_sharing import packed


def historical_data(plan, split_seed=None):
    inputs, analysis, report = [Path(plan[key]) for key in ('historical_inputs', 'historical_analysis', 'historical_report')]
    for root in (inputs, analysis, report):
        verify_bundle(root)
    tasks = read_json(inputs/'tasks.json')
    by_id = {task['task_unit_id']: task for task in tasks}
    policies = ('local', 'example', 'reference')
    effects = {(row['task_unit_id'], row['policy']): row['actual_edit_minus_baseline']
               for row in read_json(analysis/'training-effects.json')}
    requests = {}
    for request in read_json(inputs/'training-requests.json'):
        for member in request['members']:
            if member['flow'] == 'TSG' and member['condition'] in ('B', *policies):
                key = request['task_unit_id'], member['condition'], member['version']
                requests.setdefault(key, []).append(request)
    roles = {}
    split_seed = plan['seed'] if split_seed is None else split_seed
    for family in ('find', 'grep', 'tar', 'git'):
        ordered = sorted((task['task_unit_id'] for task in tasks if task['role'] == 'training' and task['family'] == family),
            key=lambda identity: hashlib.sha256(f'{split_seed}/{identity}'.encode()).hexdigest())
        if len(ordered) != 100:
            raise ValueError('历史训练总体与冻结输入不同')
        roles.update({identity: int(index >= plan['historical_training_per_family']) for index, identity in enumerate(ordered)})
    data = dict(w=[], x=[], a=[], y=[], features=[], effects=[], identity_zero=[], task_ids=[], request_ids=[], statuses=[])
    for identity in sorted(roles):
        task = by_id[identity]
        rng = method.random_stream(plan['seed'], 'historical', identity)
        assigned, version = int(rng.integers(0, 4)), int(rng.integers(1, 3))
        condition = 'B' if assigned == 0 else policies[assigned-1]
        request = sorted(requests[(identity, condition, version)], key=lambda row: row['request_id'])[0]
        terminal_root = Path('results/controlled-semantic-20260930/training')/request['request_id']/'result'
        verify_bundle(terminal_root)
        terminal = read_json(terminal_root/'result.json')
        if (terminal['request_id'] != request['request_id'] or terminal['task_unit_id'] != identity or
            terminal['status'] not in ('returned', 'generation_failed') or terminal['secure_yield'] not in (0, 1)):
            raise ValueError('真实历史请求与终止结果不一致')
        same = [all(task['conditions']['TSG'][str(v)][policy]['prompt_hash'] ==
                    task['conditions']['TSG'][str(v)]['B']['prompt_hash'] for v in (1, 2)) for policy in policies]
        data['w'].append(task['initial_states'])
        data['x'].append(request['actual_states'])
        data['a'].append(assigned)
        data['y'].append(terminal['secure_yield'])
        data['features'].append([controlled_ridge_features(task, policy) for policy in policies])
        data['effects'].append([0. if same[index] else effects[(identity, policy)] for index, policy in enumerate(policies)])
        data['identity_zero'].append(same)
        data['task_ids'].append(identity)
        data['request_ids'].append(request['request_id'])
        data['statuses'].append(terminal['status'])
    data = {key: value if key == 'task_ids' else np.asarray(value) for key, value in data.items()}
    training, calibration = [method.subset(data, np.asarray([i for i, identity in enumerate(data['task_ids']) if roles[identity] == role]))
                             for role in (0, 1)]
    cases = read_json(report/'cases.json')
    evaluation = dict(w=[], features=[], effects=[], identity_zero=[], task_ids=[], finite_function_effects=[], support_effects=[])
    for case in cases:
        identity = case['task_unit_id']
        task = by_id[identity]
        conditions = {row['condition']: row for row in case['conditions'] if row['flow'] == 'TSG'}
        same = [all(task['conditions']['TSG'][str(v)][policy]['prompt_hash'] ==
                    task['conditions']['TSG'][str(v)]['B']['prompt_hash'] for v in (1, 2)) for policy in policies]
        evaluation['task_ids'].append(identity)
        evaluation['w'].append(task['initial_states'])
        evaluation['features'].append([controlled_ridge_features(task, policy) for policy in policies])
        evaluation['effects'].append([conditions[policy]['mean']-conditions['B']['mean'] for policy in policies])
        evaluation['identity_zero'].append(same)
        for field, source in (('finite_function_effects', 'finite_functionality_pass'), ('support_effects', 'oracle_supported')):
            def fraction(condition):
                return float(np.mean([version[source]/version['assigned'] for version in condition['versions']]))
            evaluation[field].append([fraction(conditions[policy])-fraction(conditions['B']) for policy in policies])
    evaluation = {key: value if key == 'task_ids' else np.asarray(value) for key, value in evaluation.items()}
    if len(training['task_ids']) != 200 or len(calibration['task_ids']) != 200 or len(evaluation['task_ids']) != 400:
        raise ValueError('历史开发总体的完整任务分母不同')
    return training, calibration, evaluation, {str(root): file_sha256(root/'manifest.json') for root in (inputs, analysis, report)}


def run_historical(plan, backend, split_seed=None):
    training, calibration, evaluation, sources = historical_data(plan, split_seed)
    coordinates = ['historical'] if split_seed is None else ['historical', split_seed]
    learned = method.learn_policies(training, calibration, evaluation, plan, backend, coordinates)
    panels = {}
    for name, output in learned['outputs'].items():
        actions = np.asarray(output['actions'])
        selected = np.arange(len(actions)), actions
        gains = np.column_stack((np.zeros(len(actions)), evaluation['effects']))[selected]
        functionality = np.column_stack((np.zeros(len(actions)), evaluation['finite_function_effects']))[selected]
        support = np.column_stack((np.zeros(len(actions)), evaluation['support_effects']))[selected]
        panels[name] = dict(tasks=len(actions), edits=int(np.count_nonzero(actions)), secure_gain=float(gains.mean()),
            finite_function_gain=float(functionality.mean()), support_gain=float(support.mean()),
            assignments=[dict(task_unit_id=identity, action=int(action), secure_gain=float(gain), finite_function_gain=float(function),
                support_gain=float(coverage)) for identity, action, gain, function, coverage in
                zip(evaluation['task_ids'], actions, gains, functionality, support, strict=True)])
    return dict(evidence_role=plan['historical_role'], training=packed(training), calibration=packed(calibration),
                evaluation=packed(evaluation), source_hashes=sources, learned=learned, panels=panels, new_model_requests=0)


def summarize_exposed_direction(records, plan):
    if len(records) != len(plan['exposed_split_seeds']):
        raise ValueError('方向比较缺少预定划分')
    identities = records[0]['evaluation']['task_ids']
    if len(identities) != 400 or len(set(identities)) != 400:
        raise ValueError('方向比较的评价任务分母不同')
    if any(record['evaluation']['task_ids'] != identities for record in records):
        raise ValueError('各项划分的评价任务身份不同')
    tasks = read_json(Path(plan['historical_inputs'])/'tasks.json')
    family_by_id = {task['task_unit_id']: task['family'] for task in tasks}
    families = [family_by_id[identity] for identity in identities]
    methods = tuple(records[0]['panels'])
    task_values = {}
    outputs = {}
    for name in methods:
        task_values[name] = {}
        for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
            matrix = np.asarray([[assignment[field] for assignment in record['panels'][name]['assignments']]
                                 for record in records])
            task_values[name][field] = matrix.mean(axis=0)
        outputs[name] = dict(tasks=400, splits=len(records),
            **{field: float(values.mean()) for field, values in task_values[name].items()},
            mean_edits=float(np.mean([record['panels'][name]['edits'] for record in records])))
    rng = np.random.default_rng(plan['bootstrap_seed'])
    indexes = np.concatenate([rng.choice(np.flatnonzero(np.asarray(families) == family),
        size=(plan['bootstrap_draws'], families.count(family)), replace=True) for family in sorted(set(families))], axis=1)
    contrasts = []
    family_size = len(plan['primary_comparators'])
    for comparator in plan['primary_comparators']:
        differences = task_values[plan['primary_method']]['secure_gain']-task_values[comparator]['secure_gain']
        boot = differences[indexes].mean(axis=1)
        interval = np.quantile(boot, [plan['alpha']/(2*family_size), 1-plan['alpha']/(2*family_size)])
        contrasts.append(dict(comparator=comparator, difference=float(differences.mean()),
            simultaneous_descriptive_interval=interval.tolist(), task_differences=differences.tolist(),
            task_average_action_disagreement=float(np.mean([
                np.asarray(record['learned']['outputs'][plan['primary_method']]['actions']) !=
                np.asarray(record['learned']['outputs'][comparator]['actions']) for record in records]))))
    graph_changes = []
    for record, seed in zip(records, plan['exposed_split_seeds'], strict=True):
        graphs = record['learned']['graphs']
        graph_changes.append(dict(split_seed=seed,
            different_jci_time_pags=sum(graph['results']['time']['pag'] != graph['results']['jci123']['pag'] for graph in graphs),
            different_jci_time_ancestry=sum(graph['results']['time']['context_ancestry'] !=
                                           graph['results']['jci123']['context_ancestry'] for graph in graphs),
            nonancestry_support=record['learned']['nonancestry_support'],
            direction_ablation_action_differences=int(np.count_nonzero(
                np.asarray(record['learned']['outputs']['jci123']['actions']) !=
                np.asarray(record['learned']['outputs']['jci123_adjacency']['actions']))),
            selected={name: dict(family=None if choice['model'] is None else choice['model']['family'],
                penalty=None if choice['model'] is None else choice['model']['penalty'],
                strength=choice['strength'], origin=choice['origin'], calibration_gain=choice['calibration_gain'])
                for name, choice in record['learned']['choices'].items()},
            candidate_counts={name: len(options) for name, options in record['learned']['candidates'].items()}))
    return dict(evidence_role=plan['evidence_role'], evaluation_task_ids=identities, evaluation_families=families,
        independent_evaluation_task_units=400, split_count=len(records), splits_are_independent=False,
        new_model_requests=0, protected_task_units=0, method_values=outputs, primary_comparisons=contrasts,
        task_values={name: {field: values.tolist() for field, values in fields.items()} for name, fields in task_values.items()},
        graph_diagnostics=graph_changes, bootstrap_draws=plan['bootstrap_draws'], multiplicity_family_size=family_size,
        inference='descriptive stratified task-unit bootstrap on exposed outcomes; all split descendants move together')


def run_simulation_cell(plan, mechanism, n, repeat, backend, saved=None):
    training, beta = method.simulate_tasks(plan, mechanism, n, repeat, 'D')
    calibration, calibration_beta = method.simulate_tasks(plan, mechanism, n, repeat, 'CAL')
    np.testing.assert_array_equal(beta, calibration_beta)
    states = method.all_states(len(beta))
    evaluation = dict(w=states, identity_zero=states.astype(bool), task_ids=[f'state/{index}' for index in range(len(states))])
    if saved is not None and (packed(training) != saved['training'] or packed(calibration) != saved['calibration']):
        raise ValueError('复用结构的完整观测与预定随机计算不同')
    graphs = None if saved is None else saved['learned']['graphs']
    learned = method.learn_policies(training, calibration, evaluation, plan, backend, [mechanism, n, repeat], graphs)
    values = {name: method.exact_policy_value(output['scores'], beta, plan) for name, output in learned['outputs'].items()}
    return dict(mechanism=mechanism, n=n, repetition=repeat, beta=beta.tolist(),
        training=packed(training), calibration=packed(calibration), learned=learned, values=values)


def summarize(cells, plan):
    comparisons = ('full', 'direct_gate', 'direct_lcb', 'direct_envelope', 'time', 'jci12')
    family_size = len(plan['simulation']['mechanisms'])*len(plan['simulation']['tasks_per_role'])*len(comparisons)
    groups = []
    for mechanism, n in itertools.product(plan['simulation']['mechanisms'], plan['simulation']['tasks_per_role']):
        selected = [row for row in cells if row['mechanism'] == mechanism and row['n'] == n]
        if not selected:
            continue
        contrasts = []
        for name in comparisons:
            differences = np.asarray([row['values']['jci123']['gain']-row['values'][name]['gain'] for row in selected])
            se = float(np.std(differences, ddof=1)/np.sqrt(len(selected))) if len(selected) > 1 else None
            radius = float(t.ppf(1-.05/(2*family_size), len(selected)-1)*se) if se is not None else None
            contrasts.append(dict(comparator=name, difference=float(differences.mean()), paired_differences=differences.tolist(),
                simultaneous_interval=None if radius is None else [float(differences.mean()-radius), float(differences.mean()+radius)]))
        groups.append(dict(mechanism=mechanism, n=n, independent_repetitions=len(selected), comparisons=contrasts,
            mean_gains={name: float(np.mean([row['values'][name]['gain'] for row in selected])) for name in selected[0]['values']},
            equal_time_actions=sum(row['values']['time']['actions'] == row['values']['jci123']['actions'] for row in selected),
            equal_jci12_actions=sum(row['values']['jci12']['actions'] == row['values']['jci123']['actions'] for row in selected)))
    return dict(cells=len(cells), family_size=family_size, groups=groups)


def run_joint_policy(plan_path, output, rscript, limit=None, historical_only=False, source_results=None):
    plan = read_json(plan_path)
    if plan['study_id'] != 'jci-joint-policy-20261014' or plan['formal_claim_allowed'] is not False:
        raise ValueError('联合政策开发身份不符合本次授权')
    sources = [Path(__file__), Path(method.__file__), Path(method.__file__).with_suffix('.R'),
               Path('src/discovery/jci_sharing.py'), Path('src/discovery/safe_yield.py')]
    identity = dict(plan_sha256=file_sha256(plan_path), sources={str(path.relative_to(Path.cwd())) if path.is_absolute() else str(path):
        file_sha256(path) for path in sources}, python=platform.python_version(), numpy=np.__version__, scipy=scipy.__version__,
        sklearn=sklearn.__version__, rscript=str(rscript), new_model_requests=0)
    if source_results is not None:
        verify_bundle(source_results/'inputs')
        original_identity = read_json(source_results/'inputs'/'identity.json')
        if original_identity['plan_sha256'] != identity['plan_sha256']:
            raise ValueError('复用结构的冻结方案不同')
        for source in ('src/discovery/jci_policy.R', 'src/discovery/jci_sharing.py'):
            if original_identity['sources'][str(Path(source))] != file_sha256(Path(source)):
                raise ValueError('复用结构的条件检验或 R 算法不同')
        with zipfile.ZipFile(source_results/'source.zip') as archive:
            for source, digest in original_identity['sources'].items():
                if hashlib.sha256(archive.read(Path(source).as_posix())).hexdigest() != digest:
                    raise ValueError('复用结构的源码存档身份不同')
        identity['source_results'] = str(source_results)
        identity['source_archive_sha256'] = file_sha256(source_results/'source.zip')
    if (output/'inputs').exists():
        verify_bundle(output/'inputs')
        if read_json(output/'inputs'/'identity.json') != identity:
            raise ValueError('已冻结联合研究的实现或输入身份不同')
    else:
        write_bundle(output/'inputs', {'plan.json': plan, 'identity.json': identity})
    if 'exposed_split_seeds' in plan:
        if not historical_only or source_results is not None:
            raise ValueError('已暴露方向比较必须仅使用历史材料')
        seeds = plan['exposed_split_seeds']
        if len(seeds) != 8 or len(set(seeds)) != len(seeds):
            raise ValueError('方向比较必须保留八项预定独立任务划分')
        archive_path = output/'source.zip'
        if not archive_path.exists():
            with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
                for source in identity['sources']:
                    archive.write(source, Path(source).as_posix())
                archive.write('src/verification/jci_policy.py', 'src/verification/jci_policy.py')
        logs = output/'logs'
        logs.mkdir(exist_ok=True)
        backend = StructureBackend(rscript, logs/f'backend-{time.time_ns()}.log', Path(method.__file__).with_suffix('.R'))
        records, added = [], 0
        try:
            for seed in seeds:
                root = output/'splits'/str(seed)
                if root.exists():
                    verify_bundle(root)
                    records.append(read_json(root/'result.json'))
                    continue
                if limit is not None and added >= limit:
                    break
                result = run_historical(plan, backend, seed)
                result['split_seed'] = seed
                write_bundle(root, {'result.json': result})
                records.append(result)
                added += 1
                print(f'Exposed direction comparison: split {seed}, saved {len(records)}/{len(seeds)}', flush=True)
            if len(records) == len(seeds) and not (output/'summary').exists():
                write_bundle(output/'summary', {'result.json': summarize_exposed_direction(records, plan)})
        finally:
            backend.close()
        return dict(saved_splits=len(records), planned_splits=len(seeds),
                    complete=(output/'summary').exists(), new_model_requests=0)
    logs = output/'logs'
    logs.mkdir(exist_ok=True)
    backend = StructureBackend(rscript, logs/f'backend-{time.time_ns()}.log', Path(method.__file__).with_suffix('.R'))
    cells, added = [], 0
    try:
        if not historical_only:
            for mechanism, n, repeat in itertools.product(plan['simulation']['mechanisms'],
                plan['simulation']['tasks_per_role'], range(plan['simulation']['repetitions'])):
                root = output/'cells'/f'{mechanism}-{n}-{repeat:02}'
                if root.exists():
                    verify_bundle(root)
                    cells.append(read_json(root/'result.json'))
                    continue
                if limit is not None and added >= limit:
                    break
                saved = None
                source_root = None if source_results is None else source_results/'cells'/root.name
                if source_root is not None and source_root.exists():
                    verify_bundle(source_root)
                    saved = read_json(source_root/'result.json')
                result = run_simulation_cell(plan, mechanism, n, repeat, backend, saved)
                if saved is not None:
                    result['source_graph_manifest_sha256'] = file_sha256(source_root/'manifest.json')
                write_bundle(root, {'result.json': result})
                cells.append(result)
                added += 1
                print(f'Joint contexts: {mechanism} N={n} repetition={repeat}, saved {len(cells)}', flush=True)
        if historical_only or limit is None:
            if not (output/'historical').exists():
                write_bundle(output/'historical', {'result.json': run_historical(plan, backend)})
        expected = len(plan['simulation']['mechanisms'])*len(plan['simulation']['tasks_per_role'])*plan['simulation']['repetitions']
        if len(cells) == expected and not (output/'summary').exists():
            write_bundle(output/'summary', {'result.json': summarize(cells, plan)})
    finally:
        backend.close()
    return dict(saved_cells=len(cells), planned_cells=expected, historical_executed=(output/'historical').exists())

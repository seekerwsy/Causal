from __future__ import annotations

import hashlib
import itertools
import platform
from pathlib import Path
import time
import zipfile

import numpy as np
import scipy
import sklearn

from prompt_mechanism_study.artifact_io import file_sha256, packed, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import jci_sharing as method


def structures(training, view, plan, backend, seed):
    labels = ['E', 'A', 'W1', 'W2', 'W3']+(['X'] if view == 'prompt_state' else [])+['Y']
    columns = [training['e'], training['a'], *training['w'].T]
    if view == 'prompt_state':
        columns.append(training['x'])
    columns.append(training['y'])
    ci = method.ConditionalPermutation(np.column_stack(columns), labels, plan['ci_draws'], seed)
    results = {name: backend.search(labels, name, ci, plan['ci_alpha']) for name in ('time', 'jci')}
    return dict(labels=labels, results=results, queries=list(ci.cache.values()))


def proposals_from(search):
    return dict(full=[7], direct_checked=list(range(8)),
                time_checked=search['results']['time']['proposals'],
                jci_checked=search['results']['jci']['proposals'],
                jci_unchecked=search['results']['jci']['proposals'])


def simulate_cell(plan, mechanism, n, repetition, backend):
    training = method.draw_tasks(plan, mechanism, n, repetition, 0)
    calibration = method.draw_tasks(plan, mechanism, n, repetition, 1)
    qualification = method.qualification(calibration, plan)
    views = {}
    for view in plan['views']:
        search = structures(training, view, plan, backend,
                            [plan['seed'], mechanism, n, repetition])
        choices, fitted = method.select_models(training, calibration, proposals_from(search), qualification, plan)
        # 只有冻结选择完成后才读取机制真值，评价不产生训练标签。
        values = {name: {str(e): method.exact_value(choice, mechanism, e, plan) for e in range(4)}
                  for name, choice in choices.items()}
        views[view] = dict(structure=search, choices=choices, values=values,
                           fitted_models=len(fitted)//len(plan['thresholds']),
                           calibration_candidates=fitted)
    return dict(mechanism=mechanism, n=n, repetition=repetition, training=packed(training),
                calibration=packed(calibration), qualification=qualification, views=views)


def summarize(cells, plan):
    groups = []
    family_size = len(plan['mechanisms'])*len(plan['tasks_per_environment'])*len(plan['views'])*3
    for mechanism, n, view in itertools.product(plan['mechanisms'], plan['tasks_per_environment'], plan['views']):
        rows = [cell for cell in cells if cell['mechanism'] == mechanism and cell['n'] == n]
        if not rows:
            continue
        methods = ('full', 'direct_checked', 'time_checked', 'jci_checked', 'jci_unchecked')
        means = {name: {str(e): float(np.mean([row['views'][view]['values'][name][str(e)]['gain'] for row in rows]))
                        for e in range(4)} for name in methods}
        comparisons = []
        for comparator in ('full', 'direct_checked', 'time_checked'):
            differences = np.asarray([row['views'][view]['values']['jci_checked']['3']['gain']
                                      -row['views'][view]['values'][comparator]['3']['gain'] for row in rows])
            se = float(differences.std(ddof=1)/np.sqrt(len(rows))) if len(rows) > 1 else None
            radius = float(scipy.stats.t.ppf(1-.05/(2*family_size), len(rows)-1)*se) if se is not None else None
            comparisons.append(dict(comparator=comparator, difference=float(differences.mean()), mcse=se,
                simultaneous_interval=None if radius is None else [float(differences.mean()-radius), float(differences.mean()+radius)],
                paired_differences=differences.tolist()))
        groups.append(dict(mechanism=mechanism, n=n, view=view, independent_repetitions=len(rows),
            mean_gains=means, comparisons=comparisons,
            equal_graph_proposals=sum(row['views'][view]['structure']['results']['time']['proposals'] ==
                                      row['views'][view]['structure']['results']['jci']['proposals'] for row in rows),
            equal_checked_actions=sum(row['views'][view]['values']['time_checked']['3']['actions'] ==
                                      row['views'][view]['values']['jci_checked']['3']['actions'] for row in rows),
            qualified_sets=[sum(item['status'] == 'qualified' for item in row['qualification'].values()) for row in rows]))
    return dict(status='completed' if len(cells) == len(plan['mechanisms'])*len(plan['tasks_per_environment'])*plan['repetitions']
                else 'partial', family_size=family_size, groups=groups,
                inference='simultaneous descriptive t intervals across independent SCM repetitions; no formal real-task claim')


def historical_reanalysis(plan, repository, backend):
    inputs, analysis, report = [repository/plan[key] for key in ('historical_inputs', 'historical_analysis', 'historical_report')]
    for root in (inputs, analysis, report):
        verify_bundle(root)
    tasks = read_json(inputs/'tasks.json')
    by_id = {task['task_unit_id']: task for task in tasks}
    effects = read_json(analysis/'training-effects.json')
    cases = read_json(report/'cases.json')
    requests = read_json(inputs/'training-requests.json')
    request_map = {}
    for request in requests:
        for member in request['members']:
            if member['flow'] == 'TSG':
                key = request['task_unit_id'], member['condition'], member['version']
                request_map.setdefault(key, []).append(request)
    families = ('find', 'grep', 'tar', 'git')
    split = {}
    for family in families:
        identities = sorted((task['task_unit_id'] for task in tasks if task['role'] == 'training' and task['family'] == family),
                            key=lambda identity: hashlib.sha256(f'{plan["seed"]}/{identity}'.encode()).hexdigest())
        if len(identities) != 100:
            raise ValueError('历史开发任务数量与已冻结来源不符')
        split.update({identity: int(i >= 50) for i, identity in enumerate(identities)})
    policy_results = {}
    test_ids = [case['task_unit_id'] for case in cases]
    if len(test_ids) != 400 or len(set(test_ids)) != 400:
        raise ValueError('历史 E 任务分母不完整')
    test_w = np.asarray([by_id[identity]['initial_states'] for identity in test_ids])
    test_e = np.asarray([families.index(by_id[identity]['family']) for identity in test_ids])
    evaluation = {}
    for case in cases:
        conditions = {row['condition']: row for row in case['conditions'] if row['flow'] == 'TSG'}
        if any(conditions[name]['mean'] is None for name in ('B', 'local', 'example', 'reference')):
            raise ValueError('历史分配仍有未解决结果，不能直接重编码')
        evaluation[case['task_unit_id']] = conditions
    historical_plan = dict(plan, training_environments=[0, 1, 2, 3])
    for policy_index, policy in enumerate(('local', 'example', 'reference')):
        rows = [row for row in effects if row['policy'] == policy]
        data = dict(w=[], e=[], delta=[], a=[], x=[], y=[], task_ids=[], identity_zero=[],
                    structural_request_ids=[], generation_statuses=[])
        for row in rows:
            identity, task = row['task_unit_id'], by_id[row['task_unit_id']]
            same = all(task['conditions']['TSG'][str(version)][policy]['prompt_hash'] ==
                       task['conditions']['TSG'][str(version)]['B']['prompt_hash'] for version in (1, 2))
            data['w'].append(task['initial_states'])
            data['e'].append(families.index(task['family']))
            data['delta'].append(0. if same else row['actual_edit_minus_baseline'])
            data['task_ids'].append(identity)
            data['identity_zero'].append(same)
            rng = np.random.default_rng(int.from_bytes(hashlib.sha256(f'{plan["seed"]}/{policy}/{identity}'.encode()).digest()[:8], 'big'))
            assigned, version = int(rng.integers(0, 2)), int(rng.integers(1, 3))
            request = sorted(request_map[(identity, policy if assigned else 'B', version)], key=lambda item: item['request_id'])[0]
            terminal_root = repository/'results/controlled-semantic-20260930/training'/request['request_id']/'result'
            verify_bundle(terminal_root)
            terminal = read_json(terminal_root/'result.json')
            if (terminal['request_id'] != request['request_id'] or terminal['task_unit_id'] != identity
                    or terminal['status'] not in ('returned', 'generation_failed')
                    or terminal['secure_yield'] not in (0, 1)):
                raise ValueError('历史真实请求与终止记录不一致')
            data['a'].append(assigned)
            data['x'].append(request['actual_states'][policy_index])
            data['y'].append(terminal['secure_yield'])
            data['structural_request_ids'].append(request['request_id'])
            data['generation_statuses'].append(terminal['status'])
        data = {key: value if key == 'task_ids' else np.asarray(value) for key, value in data.items()}
        training_indexes = np.asarray([split[identity] == 0 for identity in data['task_ids']])
        training = {key: [identity for identity, selected in zip(value, training_indexes, strict=True) if selected]
                    if key == 'task_ids' else value[training_indexes] for key, value in data.items()}
        calibration = {key: [identity for identity, selected in zip(value, training_indexes, strict=True) if not selected]
                       if key == 'task_ids' else value[~training_indexes] for key, value in data.items()}
        qualification = method.qualification(calibration, historical_plan)
        views = {}
        identity_zero = np.asarray([all(by_id[identity]['conditions']['TSG'][str(version)][policy]['prompt_hash'] ==
                                       by_id[identity]['conditions']['TSG'][str(version)]['B']['prompt_hash']
                                       for version in (1, 2)) for identity in test_ids])
        for view in plan['views']:
            search = structures(training, view, historical_plan, backend, [plan['seed'], 'historical', policy])
            choices, _ = method.select_models(training, calibration, proposals_from(search), qualification, historical_plan)
            predictions = {}
            for name, choice in choices.items():
                predicted = np.zeros(400) if choice['model'] is None else method.predict_effect(choice['model'], test_w, test_e)
                predicted[identity_zero] = 0.
                predictions[name] = dict(predictions=predicted.tolist(), threshold=choice['threshold'])
            views[view] = dict(structure=search, choices=choices, predictions=predictions)
        policy_results[policy] = dict(training=packed(training), calibration=packed(calibration), qualification=qualification,
                                      views=views, test_identity_zero=identity_zero.tolist())
    panels = {}
    for view in plan['views']:
        panels[view] = {}
        for name in ('full', 'direct_checked', 'time_checked', 'jci_checked', 'jci_unchecked'):
            outputs = []
            for index, identity in enumerate(test_ids):
                candidates = []
                for policy in ('local', 'example', 'reference'):
                    prediction = policy_results[policy]['views'][view]['predictions'][name]
                    if prediction['threshold'] is not None and prediction['predictions'][index] > prediction['threshold']:
                        candidates.append((prediction['predictions'][index], policy))
                action = max(candidates, key=lambda item: item[0])[1] if candidates else 'B'
                selected, original = evaluation[identity][action], evaluation[identity]['B']
                def fraction(condition, key):
                    return float(np.mean([version[key]/version['assigned'] for version in condition['versions']]))
                outputs.append(dict(task_unit_id=identity, action=action,
                    secure_gain=selected['mean']-original['mean'],
                    finite_function_gain=fraction(selected, 'finite_functionality_pass')-fraction(original, 'finite_functionality_pass'),
                    support_gain=fraction(selected, 'oracle_supported')-fraction(original, 'oracle_supported')))
            panels[view][name] = dict(tasks=400, secure_gain=float(np.mean([row['secure_gain'] for row in outputs])),
                finite_function_gain=float(np.mean([row['finite_function_gain'] for row in outputs])),
                support_gain=float(np.mean([row['support_gain'] for row in outputs])),
                edits=sum(row['action'] != 'B' for row in outputs), assignments=outputs)
    return dict(evidence_role=plan['historical_role'], original_endpoint_retained=True, new_model_requests=0,
                source_hashes={str(root.relative_to(repository)): file_sha256(root/'manifest.json') for root in (inputs, analysis, report)},
                evaluation_task_ids=test_ids, evaluation_w=test_w.tolist(), evaluation_e=test_e.tolist(),
                policies=policy_results, panels=panels)


def run_jci_sharing(plan_path, output, rscript, limit=None, analyze_saved=False):
    repository = Path.cwd()
    plan = read_json(plan_path)
    if plan['study_id'] != 'jci-sharing-20261014' or plan['formal_claim_allowed'] is not False:
        raise ValueError('研究授权及证据身份不符合本次开发范围')
    for mechanism, e in itertools.product(plan['mechanisms'], range(4)):
        method.mechanism_parameters(mechanism, e, method.STATES)
    sources = [Path(__file__), Path(method.__file__), Path(method.__file__).with_suffix('.R')]
    identity = dict(plan_sha256=file_sha256(plan_path), sources={str(path.relative_to(repository)): file_sha256(path) for path in sources},
                    python=platform.python_version(), numpy=np.__version__, scipy=scipy.__version__, sklearn=sklearn.__version__,
                    rscript=str(rscript), evidence_role=plan['evidence_role'])
    frozen = output/'inputs'
    if frozen.exists():
        verify_bundle(frozen)
        original_identity = read_json(frozen/'identity.json')
        if original_identity != identity:
            if not analyze_saved:
                raise ValueError('已保存研究与当前实现身份不同，不能接续或覆盖')
            with zipfile.ZipFile(output/'source-initial.zip') as source_archive:
                for path, digest in original_identity['sources'].items():
                    normalized = Path(path).as_posix()
                    if hashlib.sha256(source_archive.read(normalized)).hexdigest() != digest:
                        raise ValueError('原计算实现存档与冻结身份不同')
                    if normalized != 'src/experiment/jci_sharing.py' and identity['sources'][path] != digest:
                        raise ValueError('仅分析接续不能修改科学消费者或结构后端')
            amendment = dict(original_identity=original_identity, analysis_identity=identity,
                source_archive_sha256=file_sha256(output/'source-initial.zip'),
                scope='read frozen terminal returned/generation_failed records; assemble saved computations; zero simulation reruns',
                preserved_request='controlled-training-ae77fa5126e8b291a8dc')
            if (output/'analysis-amendment').exists():
                verify_bundle(output/'analysis-amendment')
                if read_json(output/'analysis-amendment'/'result.json') != amendment:
                    raise ValueError('分析接续身份不同')
            else:
                write_bundle(output/'analysis-amendment', {'result.json': amendment})
    else:
        write_bundle(frozen, {'plan.json': plan, 'identity.json': identity})
    cells, added, started = [], 0, time.monotonic()
    log_directory = output/'logs'
    log_directory.mkdir(exist_ok=True)
    backend = method.StructureBackend(rscript, log_directory/f'backend-{time.time_ns()}.log')
    try:
        for mechanism, n, repetition in itertools.product(plan['mechanisms'], plan['tasks_per_environment'], range(plan['repetitions'])):
            root = output/'cells'/f'{mechanism}-{n}-{repetition:02}'
            if root.exists():
                verify_bundle(root)
                cells.append(read_json(root/'result.json'))
                continue
            if analyze_saved:
                raise ValueError('仅分析命令要求全部预定计算结果已经存在')
            if limit is not None and added >= limit:
                break
            if time.monotonic()-started >= plan['cpu_seconds_limit']:
                break
            result = simulate_cell(plan, mechanism, n, repetition, backend)
            write_bundle(root, {'result.json': result})
            cells.append(result)
            added += 1
            print(f'{mechanism} N={n} repetition={repetition} saved ({len(cells)} cells)', flush=True)
        expected = len(plan['mechanisms'])*len(plan['tasks_per_environment'])*plan['repetitions']
        if len(cells) == expected:
            history = output/'historical'
            if not history.exists():
                write_bundle(history, {'result.json': historical_reanalysis(plan, repository, backend)})
            if not (output/'summary').exists():
                write_bundle(output/'summary', {'result.json': summarize(cells, plan)})
    finally:
        backend.close()
    return dict(saved_cells=len(cells), planned_cells=len(plan['mechanisms'])*len(plan['tasks_per_environment'])*plan['repetitions'],
                historical_executed=(output/'historical').exists(), elapsed_seconds=time.monotonic()-started)


def recalibrate_saved_sharing(output):
    plan = read_json(output/'inputs'/'plan.json')
    root = output/'calibration-revision'
    design = dict(evidence_role='POST_HOC_EXPOSED_CALIBRATION_TARGET_CHECK',
                  source_input_manifest_sha256=file_sha256(output/'inputs'/'manifest.json'),
                  calibration_target='shared component g on independent CAL tasks; no known-environment deviation h',
                  full_attribute_reference='always a candidate; no sharing qualification granted',
                  unchanged=['tasks', 'outcomes', 'graphs', 'fit coefficients', 'sharing margin', 'qualification alpha'],
                  new_random_observations=0, new_model_requests=0,
                  implementation_sha256=file_sha256(Path(method.__file__)))
    write_bundle(root/'inputs', {'design.json': design})
    records = []
    for source in sorted((output/'cells').iterdir()):
        verify_bundle(source)
        original = read_json(source/'result.json')
        revised = method.recalibrate_shared_component(original, plan)
        revised['source_result_sha256'] = file_sha256(source/'result.json')
        write_bundle(root/'cells'/source.name, {'result.json': revised})
        records.append(revised)
    groups = []
    for mechanism, n, view in itertools.product(plan['mechanisms'], plan['tasks_per_environment'], plan['views']):
        selected = [row for row in records if row['mechanism'] == mechanism and row['n'] == n]
        methods = ('full', 'direct_checked', 'time_checked', 'jci_checked', 'jci_unchecked')
        groups.append(dict(mechanism=mechanism, n=n, view=view,
            mean_gains={name: float(np.mean([row['views'][view]['values'][name]['3']['gain'] for row in selected])) for name in methods},
            identical_checked_actions=sum(row['views'][view]['values']['time_checked']['3']['actions'] ==
                                          row['views'][view]['values']['jci_checked']['3']['actions'] for row in selected)))
    write_bundle(root/'summary', {'result.json': dict(groups=groups, evidence_role=design['evidence_role'], cells=len(records))})
    return dict(cells=len(records), groups=groups)

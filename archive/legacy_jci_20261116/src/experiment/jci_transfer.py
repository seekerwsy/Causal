from __future__ import annotations

import itertools
from pathlib import Path
import platform
import time
import zipfile

import numpy as np
import scipy
import sklearn

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import jci_transfer as method
from prompt_mechanism_study.discovery.jci_replay import source_hash
from prompt_mechanism_study.discovery.jci_structure import StructureBackend
from prompt_mechanism_study.discovery.policy_value import random_stream
from prompt_mechanism_study.experiment.jci_replay import read_observations


def validate_plan(plan):
    if (plan['study_id']!='jci-transfer-development-20261028'
            or plan['evidence_role']!='POST_HOC_EXPOSED_TRANSFER_METHOD_CHECK'
            or plan['formal_claim_allowed'] is not False):
        raise ValueError('跨环境研究必须保留已暴露材料开发身份')
    if plan['families']!=['find','grep','tar','git'] or plan['policies']!=['local','example','reference']:
        raise ValueError('原家族与表达政策身份不同')
    if plan['contexts']!=['B','local','example','reference','S'] or plan['propensity']!=0.2:
        raise ValueError('原随机分配规则不同')
    if (plan['source_training_fraction'],plan['target_adaptation_fraction'])!=(0.7,0.5):
        raise ValueError('任务角色比例不同')
    budgets = plan['target_budgets']
    if budgets!=sorted(set(budgets)) or not budgets or any(type(value) is not int or value<2 or value%2 for value in budgets):
        raise ValueError('目标预算必须为互异递增的正偶数')
    for key in ('ridge_penalties','deviation_penalties'):
        values = np.asarray(plan[key],dtype=float)
        if not len(values) or not np.isfinite(values).all() or np.any(values<=0):
            raise ValueError('正则化参数无效')
    if plan['candidate_limit']!=3 or plan['folds']<2 or plan['ci_draws']<99:
        raise ValueError('候选或计算配置无效')
    if plan['methods']!=['jci_transfer','time_transfer','adjacency_transfer','direct_invariance','direct_full']:
        raise ValueError('必须保留结构方法及全部预定直接比较')
    if plan['primary_method']!='jci_transfer' or plan['primary_comparators']!=['direct_full','direct_invariance','time_transfer','adjacency_transfer']:
        raise ValueError('主要比较族不同')


def prepare_design(tasks, requests, plan):
    if len(tasks)!=800 or len({row['task_unit_id'] for row in tasks})!=800:
        raise ValueError('原任务总体不完整')
    mixture = sorted((row for row in requests if row['component']=='random_mixture'),key=lambda row:row['independent_event'])
    if len(mixture)!=4000 or len({row['request_id'] for row in mixture})!=4000:
        raise ValueError('原随机混合请求不完整')
    cases = []
    for target,budget in itertools.product(plan['families'],plan['target_budgets']):
        roles = {name:[] for name in ('source_training','source_calibration','target_adaptation','target_calibration','test')}
        for family in plan['families']:
            group = sorted((row['task_unit_id'] for row in tasks if row['role']=='training' and row['family']==family),
                           key=lambda key:source_hash(plan['split_seed'],f'{target}/{family}/{key}'))
            if len(group)!=100:
                raise ValueError('家族任务数量不同')
            position = 50 if family==target else 70
            roles['target_adaptation' if family==target else 'source_training'].extend(group[:position])
            roles['target_calibration' if family==target else 'source_calibration'].extend(group[position:])
        roles['test'] = sorted(row['task_unit_id'] for row in tasks if row['role']=='evaluation' and row['family']==target)
        schedules = {}
        for name,identities in roles.items():
            if name=='test':
                continue
            allowed = set(identities)
            eligible = [row for row in mixture if row['task_unit_id'] in allowed]
            order = random_stream(plan['schedule_seed'],target,name).permutation(len(eligible))
            sequence = [eligible[int(index)]['request_id'] for index in order]
            count = budget//2 if name.startswith('target_') else len(sequence)
            if count>len(sequence):
                raise ValueError('冻结角色中的原始物理请求不足以支持预算')
            schedules[name] = sequence[:count]
        cases.append(dict(target=target,budget=budget,roles=roles,requests=schedules))
    return dict(cases=cases,task_units=800,original_mixture_requests=4000)


def evaluation_measurements(requests, terminals, tasks, task_ids, plan):
    allowed = set(task_ids)
    result = {key:{condition:[] for condition in plan['contexts'][:4]} for key in task_ids}
    seen = set()
    for request in requests:
        key = request['task_unit_id']
        if key not in allowed:
            continue
        terminal = terminals[request['request_id']]
        if terminal['task_unit_id']!=key or terminal['secure_yield'] not in (0,1):
            raise ValueError('最终评价缺少已解决端点')
        if terminal['status']=='generation_failed':
            if terminal['secure_yield']!=0 or terminal['code_valid'] is not False:
                raise ValueError('生成失败记录的产出状态不同')
            support,complete_known = 0.,0.
        elif terminal['status']=='returned':
            support = float(terminal['oracle_support'] is True)
            complete_known = float(terminal['complete_functionality'] in ('pass','fail'))
        else:
            raise ValueError('最终评价终止状态无效')
        for member in request['members']:
            condition = member['condition']
            if member['flow']!='TSG' or condition not in result[key]:
                continue
            position = key,condition,member['version'],member['repeat']
            if position in seen:
                raise ValueError('最终评价逻辑分配重复')
            seen.add(position)
            expected = tasks[key]['conditions']['TSG'][str(member['version'])][condition]['prompt_hash']
            if expected!=request['prompt_hash'] or expected!=terminal['prompt_hash']:
                raise ValueError('最终评价提示身份不同')
            result[key][condition].append(dict(request_id=request['request_id'],version=member['version'],repeat=member['repeat'],
                secure=float(terminal['secure_yield']),finite=float(terminal['functionality']=='finite_pass'),
                support=support,
                unknown=float(terminal['code_valid'] is True and terminal['security_label']=='unknown'),
                complete_known=complete_known))
    for key,conditions in result.items():
        for condition,rows in conditions.items():
            expected = {(version,repeat) for version in (1,2) for repeat in range(plan['evaluation_repeats_per_version'])}
            if {(row['version'],row['repeat']) for row in rows}!=expected:
                raise ValueError('最终评价必须保留全部表达与原生成分配')
            rows.sort(key=lambda row:(row['version'],row['repeat']))
    return result


def evaluate_case(cell, tasks, measurements, plan):
    identities = cell['design']['roles']['test']
    methods = {}
    for name,choice in cell['learned']['choices'].items():
        if choice['model_ids'] is None:
            scores = np.zeros((len(identities),3))
            actions = np.zeros(len(identities),dtype=int)
        else:
            scores = method.combined_scores(cell['learned']['models'],choice['model_ids'],tasks,identities,plan)
            actions = method.actions_for(scores,choice['threshold'])
        assignments = []
        for index,key in enumerate(identities):
            condition = plan['contexts'][int(actions[index])]
            baseline,target = measurements[key]['B'],measurements[key][condition]
            assignments.append(dict(task_unit_id=key,action=int(actions[index]),scores=scores[index].tolist(),
                baseline_requests=[row['request_id'] for row in baseline],target_requests=[row['request_id'] for row in target],
                **{f'{field}_gain':float(np.mean([row[field] for row in target])-np.mean([row[field] for row in baseline]))
                   for field in ('secure','finite','support','unknown')},
                complete_functionality_known=float(np.mean([row['complete_known'] for row in target]))))
        methods[name] = dict(assignments=assignments,task_units=len(assignments),
            **{field:float(np.mean([row[field] for row in assignments])) for field in
               ('secure_gain','finite_gain','support_gain','unknown_gain','complete_functionality_known')},
            edited_tasks=int(np.count_nonzero(actions)))
    return dict(target=cell['design']['target'],budget=cell['design']['budget'],methods=methods)


def summarize_transfer(evaluations, tasks, plan):
    identities = sorted(row['task_unit_id'] for row in tasks.values() if row['role']=='evaluation')
    families = np.asarray([tasks[key]['family'] for key in identities])
    rng = np.random.default_rng(plan['bootstrap_seed'])
    indexes = np.concatenate([rng.choice(np.flatnonzero(families==family),
        (plan['bootstrap_draws'],np.count_nonzero(families==family)),replace=True) for family in plan['families']],axis=1)
    family_size = len(plan['target_budgets'])*len(plan['primary_comparators'])
    groups = []
    for budget in plan['target_budgets']:
        selected = [row for row in evaluations if row['budget']==budget]
        if {row['target'] for row in selected}!=set(plan['families']):
            raise ValueError('主要汇总缺少目标环境')
        values,arrays,actions = {},{},{}
        for name in plan['methods']:
            assignments = {row['task_unit_id']:row for cell in selected for row in cell['methods'][name]['assignments']}
            if set(assignments)!=set(identities):
                raise ValueError('最终评价任务分母不同')
            arrays[name] = np.asarray([assignments[key]['secure_gain'] for key in identities])
            actions[name] = [assignments[key]['action'] for key in identities]
            values[name] = {field:float(np.mean([assignments[key][field] for key in identities])) for field in
                ('secure_gain','finite_gain','support_gain','unknown_gain','complete_functionality_known')}
            values[name]['edited_tasks'] = int(np.count_nonzero(actions[name]))
        comparisons = []
        for comparator in plan['primary_comparators']:
            difference = arrays[plan['primary_method']]-arrays[comparator]
            interval = np.quantile(difference[indexes].mean(axis=1),
                [plan['alpha']/(2*family_size),1-plan['alpha']/(2*family_size)])
            comparisons.append(dict(comparator=comparator,difference=float(difference.mean()),
                simultaneous_descriptive_interval=interval.tolist(),task_differences=difference.tolist(),
                changed_actions=sum(a!=b for a,b in zip(actions[plan['primary_method']],actions[comparator],strict=True)),
                practical_positive=bool(interval[0]>plan['practical_gain'])))
        groups.append(dict(budget=budget,methods=values,comparisons=comparisons))
    return dict(evidence_role=plan['evidence_role'],groups=groups,primary_family_size=family_size,
        test_task_ids=identities,test_task_units=len(identities),environment_folds_are_independent=False,
        inference='descriptive task-unit bootstrap within fixed families; all budgets move together',new_model_calls=0)


def run_transfer(plan_path, output, rscript, limit=None, selection_only=False):
    plan = read_json(plan_path)
    validate_plan(plan)
    if limit is not None and (type(limit) is not int or limit<1):
        raise ValueError('部分执行数量必须为正整数')
    inputs = Path(plan['inputs'])
    verify_bundle(inputs)
    tasks_list = read_json(inputs/'tasks.json')
    tasks = {row['task_unit_id']:row for row in tasks_list}
    requests = read_json(inputs/'training-requests.json')
    request_by_id = {row['request_id']:row for row in requests}
    design = prepare_design(tasks_list,requests,plan)
    sources = [Path(__file__),Path(method.__file__),Path('src/discovery/jci_transfer.R'),
        Path('src/discovery/jci_structure.py'),Path('src/discovery/jci_replay.py'),Path('src/discovery/policy_value.py'),
        Path('src/experiment/jci_replay.py'),Path('src/artifact_io.py'),Path('src/records.py')]
    hashes = {(path.relative_to(Path.cwd()) if path.is_absolute() else path).as_posix():file_sha256(path) for path in sources}
    identity = dict(plan_sha256=file_sha256(plan_path),input_manifest_sha256=file_sha256(inputs/'manifest.json'),sources=hashes,
        python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__,sklearn=sklearn.__version__,rscript=str(rscript))
    if (output/'inputs').exists():
        verify_bundle(output/'inputs')
        identity['source_archive_sha256'] = file_sha256(output/'source.zip')
        if read_json(output/'inputs/identity.json')!=identity or read_json(output/'inputs/design.json')!=design:
            raise ValueError('任务角色、预算、配置或执行源码已经改变')
    else:
        output.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(plan_path,'plan.json')
            for source in hashes:
                archive.write(source,source)
        identity['source_archive_sha256'] = file_sha256(output/'source.zip')
        write_bundle(output/'inputs',{'plan.json':plan,'identity.json':identity,'design.json':design})
    logs = output/'logs'
    logs.mkdir(exist_ok=True)
    cells,added,cache = [],0,{}
    backend = StructureBackend(rscript,logs/f'transfer-{time.time_ns()}.log',Path(method.__file__).with_suffix('.R'))
    try:
        for case in design['cases']:
            root = output/'cells'/f'{case["target"]}-{case["budget"]}'
            if root.exists():
                verify_bundle(root)
                cells.append(read_json(root/'result.json'))
                continue
            if limit is not None and added>=limit:
                break
            observations = {name:read_observations([request_by_id[key] for key in sequence],tasks,
                Path(plan['training_results']),cache,plan) for name,sequence in case['requests'].items()}
            fitting = observations['source_training']+observations['target_adaptation']
            structure = method.discover_transfer(fitting,tasks,plan,backend,[case['target'],case['budget']])
            learned = method.learn_transfer(fitting,observations['source_calibration'],observations['target_calibration'],
                tasks,structure,case['target'],plan)
            record = dict(design=case,observations=observations,structure=structure,learned=learned)
            if any(file_sha256(Path(path))!=digest for path,digest in hashes.items()):
                raise ValueError('执行期间科学实现发生了变化')
            write_bundle(root,{'result.json':record})
            cells.append(record)
            added += 1
            print(f'Saved transfer choices: {case["target"]}, {case["budget"]}; {len(cells)}/{len(design["cases"])}',flush=True)
    finally:
        backend.close()
    if len(cells)!=len(design['cases']) or selection_only:
        return dict(saved_cells=len(cells),planned_cells=len(design['cases']),evaluation_outcomes_read=False,new_model_calls=0)
    evaluation_root = Path(plan['evaluation_results'])
    verify_bundle(evaluation_root)
    terminals = {row['request_id']:row for row in read_json(evaluation_root/'results.json')}
    evaluation_requests = read_json(inputs/'evaluation-requests.json')
    task_ids = sorted(key for key,task in tasks.items() if task['role']=='evaluation')
    measurements = evaluation_measurements(evaluation_requests,terminals,tasks,task_ids,plan)
    evidence = output/'evaluation-inputs'
    if not evidence.exists():
        write_bundle(evidence,{'measurements.json':measurements,'identity.json':dict(
            evaluation_manifest_sha256=file_sha256(evaluation_root/'manifest.json'),all_choices_frozen=True)})
    evaluations = []
    for cell in cells:
        root = output/'evaluation'/f'{cell["design"]["target"]}-{cell["design"]["budget"]}'
        if root.exists():
            verify_bundle(root)
            result = read_json(root/'result.json')
        else:
            result = evaluate_case(cell,tasks,measurements,plan)
            write_bundle(root,{'result.json':result})
        evaluations.append(result)
    if not (output/'summary').exists():
        write_bundle(output/'summary',{'result.json':summarize_transfer(evaluations,tasks,plan)})
    return dict(saved_cells=len(cells),planned_cells=len(design['cases']),evaluation_outcomes_read=True,
        test_task_units=len(task_ids),evidence_role=plan['evidence_role'],new_model_calls=0)

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from functools import partial
import itertools
import os
from pathlib import Path
import platform
import time
import zipfile

import numpy as np
import scipy
from scipy.stats import t
import sklearn

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import jci_reliability as method
from prompt_mechanism_study.discovery.jci_policy import exact_policy_value
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend
from prompt_mechanism_study.experiment.jci_sharing import packed


def cell_name(coordinates):
    mechanism,size,generations,batch,repetition = coordinates
    return f'{mechanism}-n{size}-g{generations}-b{batch}-r{repetition:02}'


def planned_coordinates(plan):
    return [(mechanism,size,generations,batch,repetition)
        for batch,repetition,mechanism,size,generations in itertools.product(
            range(len(plan['batch_seeds'])),range(plan['repetitions_per_batch']),
            sorted(plan['simulation']['mechanisms']),plan['simulation']['tasks_per_role'],
            plan['simulation']['generations_per_assigned_prompt'])]


def execute_reliability_cell(plan, coordinates, rscript, logs):
    mechanism,size,generations,batch,repetition = coordinates
    training,beta = method.draw_reliability_tasks(plan,*coordinates,'D')
    calibration,other = method.draw_reliability_tasks(plan,*coordinates,'CAL')
    np.testing.assert_array_equal(beta,other)
    backend = StructureBackend(rscript,logs/f'{cell_name(coordinates)}-{time.time_ns()}.log',
                               Path('src/discovery/jci_reliability.R'))
    try:
        structure = method.discover_reliable_contexts(training,plan,backend,coordinates)
    finally:
        backend.close()
    learned = method.learn_reliable_policies(training,calibration,structure,plan,coordinates)
    ideal = method.learn_reliable_policies(training,calibration,structure,plan,coordinates,beta==0)
    for name,output in learned['outputs'].items():
        if output!=ideal['outputs'][name]:
            raise ValueError('真实零效果上限影响了实际方法的输出')
    ideal_indexes = sorted({index for group in ideal['calibration_groups']['ideal_structure'] for index in group['model_ids']}
                           |set(ideal['policy_model_ids']['ideal_structure']))
    ideal_record = dict(prior=(beta==0).astype(float).tolist(),
        models=[dict(model_id=index,**ideal['models'][index]) for index in ideal_indexes],
        calibration_groups=ideal['calibration_groups']['ideal_structure'],
        policy_model_ids=ideal['policy_model_ids']['ideal_structure'],choice=ideal['choices']['ideal_structure'],
        output=ideal['outputs']['ideal_structure'])
    value_plan = dict(simulation=dict(plan['simulation'],
        latent_outcome_coefficient=plan['simulation']['latent_outcome_by_mechanism'][mechanism]))
    outputs = dict(learned['outputs'],ideal_structure=ideal_record['output'])
    values = {name:exact_policy_value(output['scores'],beta,value_plan) for name,output in outputs.items()}
    return dict(mechanism=mechanism,n=size,generations=generations,batch=batch,repetition=repetition,
                beta=beta.tolist(),training=packed(training),calibration=packed(calibration),
                structure=structure,learned=learned,ideal_structure=ideal_record,values=values,
                evidence_role=plan['evidence_role'],new_model_requests=0)


def result_projection(record):
    beta = np.asarray(record['beta'])
    diagnostics = {}
    for name,graph in record['structure']['graphs'].items():
        ancestry = np.asarray(graph['ancestry'])[:len(beta),-1]
        raw = ancestry==-1
        guarded = np.asarray(record['structure']['guarded_priors'][name])>0
        diagnostics[name] = dict(active_positions=int(np.count_nonzero(beta)),
            false_raw_nonancestor=int(np.count_nonzero(raw & (beta!=0))),
            false_guarded_prior=int(np.count_nonzero(guarded & (beta!=0))),
            true_zero_prior=int(np.count_nonzero(guarded & (beta==0))),
            ambiguous_triples=len(graph['ambiguous_triples']))
    return {key:record[key] for key in ('mechanism','n','generations','batch','repetition','values')} | dict(
        diagnostics=diagnostics,choices={name:choice['model_id'] for name,choice in record['learned']['choices'].items()},
        ci_queries=len(record['structure']['queries']))


def summarize_reliability(records, plan):
    conditions = sorted({(row['mechanism'],row['n'],row['generations']) for row in records})
    family_size = len(plan['simulation']['mechanisms'])*len(plan['simulation']['tasks_per_role'])*len(
        plan['simulation']['generations_per_assigned_prompt'])*len(plan['primary_comparators'])
    groups = []
    for mechanism,size,generations in conditions:
        selected = [row for row in records if (row['mechanism'],row['n'],row['generations'])==(mechanism,size,generations)]
        comparisons = []
        for comparator in plan['primary_comparators']:
            differences = np.asarray([row['values'][plan['primary_method']]['gain']-row['values'][comparator]['gain'] for row in selected])
            radius = t.ppf(1-plan['alpha']/(2*family_size),len(selected)-1)*np.std(differences,ddof=1)/np.sqrt(len(selected))
            batch_means = [float(np.mean([difference for row,difference in zip(selected,differences,strict=True) if row['batch']==batch]))
                           for batch in range(len(plan['batch_seeds']))]
            comparisons.append(dict(comparator=comparator,mean_difference=float(np.mean(differences)),
                simultaneous_interval=[float(np.mean(differences)-radius),float(np.mean(differences)+radius)],
                batch_mean_differences=batch_means,paired_differences=differences.tolist(),
                reliable=bool(np.mean(differences)-radius>0 and min(batch_means)>0)))
        diagnostics = {name:{field:sum(row['diagnostics'][name][field] for row in selected)
                            for field in selected[0]['diagnostics'][name]} for name in plan['structural_methods']}
        groups.append(dict(mechanism=mechanism,n=size,generations=generations,independent_repetitions=len(selected),
            comparisons=comparisons,reliable_increment=all(row['reliable'] for row in comparisons),
            practical_increment=bool(min(row['mean_difference'] for row in comparisons)>=plan['practical_gain']),
            mean_gains={name:float(np.mean([row['values'][name]['gain'] for row in selected])) for name in selected[0]['values']},
            mean_regrets={name:float(np.mean([row['values'][name]['regret'] for row in selected])) for name in selected[0]['values']},
            baseline_choices={name:sum(row['choices'][name] is None for row in selected) for name in selected[0]['choices']},
            graph_diagnostics=diagnostics))
    return dict(evidence_role=plan['evidence_role'],cells=len(records),family_size=family_size,groups=groups,
        reliable_conditions=[{key:group[key] for key in ('mechanism','n','generations')} for group in groups if group['reliable_increment']],
        structural_searches=3*len(records),ci_queries=sum(row['ci_queries'] for row in records),
        independent_task_units=sum(2*row['n'] for row in records),
        simulated_generation_draws=sum(2*row['n']*row['generations'] for row in records),new_model_requests=0)


def run_reliability(plan_path, output, rscript, limit=None, workers=None):
    plan = read_json(plan_path)
    if plan['study_id']!='jci-policy-reliability-20261014' or plan['formal_claim_allowed'] is not False:
        raise ValueError('策略可靠性研究的冻结身份不同')
    sources = [Path('src/discovery/jci_reliability.py'),Path('src/discovery/jci_reliability.R'),Path(__file__),
        Path('src/discovery/jci_policy.py'),Path('src/discovery/jci_sharing.py'),Path('src/experiment/jci_sharing.py'),
        Path('src/artifact_io.py'),Path('src/records.py')]
    hashes = {str(source.relative_to(Path.cwd())) if source.is_absolute() else str(source):file_sha256(source) for source in sources}
    identity = dict(plan_sha256=file_sha256(plan_path),sources=hashes,python=platform.python_version(),
        numpy=np.__version__,scipy=scipy.__version__,sklearn=sklearn.__version__,rscript=str(rscript),
        openblas_threads=os.environ.get('OPENBLAS_NUM_THREADS'),omp_threads=os.environ.get('OMP_NUM_THREADS'),new_model_requests=0)
    verify_bundle(Path(plan['diagnosis_artifact']))
    identity['diagnosis_manifest_sha256'] = file_sha256(Path(plan['diagnosis_artifact'])/'manifest.json')
    identity['diagnosis_source_archive_sha256'] = file_sha256(Path(plan['diagnosis_source_archive']))
    if (output/'inputs').exists():
        identity['source_archive_sha256'] = file_sha256(output/'source.zip')
        verify_bundle(output/'inputs')
        if read_json(output/'inputs/identity.json')!=identity or read_json(output/'inputs/plan.json')!=plan:
            raise ValueError('策略可靠性研究的输入或实现已经改变')
    else:
        output.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(output/'source.zip','x') as archive:
            archive.write(plan_path,arcname='plan.json')
            for source in sources:
                archive.write(source,arcname=(source.relative_to(Path.cwd()) if source.is_absolute() else source).as_posix())
        identity['source_archive_sha256'] = file_sha256(output/'source.zip')
        write_bundle(output/'inputs',{'plan.json':plan,'identity.json':identity})
    logs = output/'logs'
    logs.mkdir(exist_ok=True)
    records,remaining = [],[]
    for coordinates in planned_coordinates(plan):
        root = output/'cells'/cell_name(coordinates)
        if root.exists():
            verify_bundle(root)
            records.append(result_projection(read_json(root/'result.json')))
        else:
            remaining.append(coordinates)
    if limit is not None:
        remaining = remaining[:limit]
    count = plan['workers'] if workers is None else workers
    if count<1 or count>plan['workers']:
        raise ValueError('计算并发数量超出预定范围')
    with ProcessPoolExecutor(max_workers=count) as executor:
        for start in range(0,len(remaining),count):
            block = remaining[start:start+count]
            results = executor.map(partial(execute_reliability_cell,plan,rscript=rscript,logs=logs),block)
            for coordinates,result in zip(block,results,strict=True):
                for source,digest in hashes.items():
                    if file_sha256(Path(source))!=digest:
                        raise ValueError('执行期间研究源码发生了变化')
                write_bundle(output/'cells'/cell_name(coordinates),{'result.json':result})
                records.append(result_projection(result))
                if len(records)%8==0 or limit is not None:
                    print(f'Reliability SCM repeats saved: {len(records)}/{len(planned_coordinates(plan))}; {cell_name(coordinates)}',flush=True)
    expected = len(planned_coordinates(plan))
    if len(records)==expected and not (output/'summary').exists():
        write_bundle(output/'summary',{'result.json':summarize_reliability(records,plan)})
    return dict(cells=len(records),planned_cells=expected,summary_completed=(output/'summary').exists(),new_model_requests=0)

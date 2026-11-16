from __future__ import annotations

import itertools
from pathlib import Path
import time

import networkx as nx
import numpy as np
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import jci_refit as method
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend


def run_zero_refit(parent, plan_path, rscript):
    verify_bundle(parent/'inputs')
    parent_plan = read_json(parent/'inputs'/'plan.json')
    plan = read_json(plan_path)
    if plan['study_id'] != 'jci-zero-effect-refit-20261014' or plan['formal_claim_allowed'] is not False:
        raise ValueError('零效果重新拟合的研究身份不同')
    output = parent/'zero-effect-refit'
    sources = [Path(__file__), Path(method.__file__), Path('src/discovery/jci_policy.py'), Path('src/discovery/jci_policy.R')]
    identity = dict(parent_input_manifest_sha256=file_sha256(parent/'inputs'/'manifest.json'), plan_sha256=file_sha256(plan_path),
        sources={str(source.relative_to(Path.cwd())) if source.is_absolute() else str(source): file_sha256(source) for source in sources},
        networkx=nx.__version__, new_random_observations=0, new_model_requests=0)
    if (output/'inputs').exists():
        verify_bundle(output/'inputs')
        if read_json(output/'inputs'/'identity.json') != identity:
            raise ValueError('零效果重新拟合的冻结实现不同')
    else:
        write_bundle(output/'inputs', {'plan.json': plan, 'identity.json': identity})
    if not (output/'graphical-oracle').exists():
        backend = StructureBackend(rscript, output/f'oracle-{time.time_ns()}.log', Path('src/discovery/jci_policy.R'))
        try:
            oracles = method.graphical_oracles(parent_plan, backend)
        finally:
            backend.close()
        write_bundle(output/'graphical-oracle', {'result.json': oracles})
    else:
        verify_bundle(output/'graphical-oracle')
        oracles = read_json(output/'graphical-oracle'/'result.json')
    records = []
    for source in sorted((parent/'cells').iterdir()):
        verify_bundle(source)
        root = output/'cells'/source.name
        if root.exists():
            verify_bundle(root)
            records.append(read_json(root/'result.json'))
            continue
        cell = read_json(source/'result.json')
        result = method.refit_cell(cell, parent_plan, plan, oracles)
        result['source_result_sha256'] = file_sha256(source/'result.json')
        write_bundle(root, {'result.json': result})
        records.append(result)
        print(f'Zero-effect refit saved: {source.name}', flush=True)
    expected = len(parent_plan['simulation']['mechanisms'])*len(parent_plan['simulation']['tasks_per_role'])*parent_plan['simulation']['repetitions']
    if len(records) == expected and not (output/'summary').exists():
        groups = []
        comparisons = [(name, 'jci123') for name in ('full', 'direct_null', 'direct_ci', 'direct_envelope', 'time', 'jci12')]
        comparisons += [(name, 'oracle_jci123') for name in ('oracle_time', 'oracle_jci12', 'oracle_direct_ci', 'full')]
        family_size = len(parent_plan['simulation']['mechanisms'])*len(parent_plan['simulation']['tasks_per_role'])*len(comparisons)
        for mechanism, n in itertools.product(parent_plan['simulation']['mechanisms'], parent_plan['simulation']['tasks_per_role']):
            selected = [record for record in records if record['mechanism'] == mechanism and record['n'] == n]
            contrasts = []
            for comparator, method_name in comparisons:
                differences = [record['values'][method_name]['gain']-record['values'][comparator]['gain'] for record in selected]
                radius = t.ppf(1-.05/(2*family_size), len(selected)-1)*np.std(differences, ddof=1)/np.sqrt(len(selected))
                contrasts.append(dict(method=method_name, comparator=comparator, difference=float(np.mean(differences)),
                    paired_differences=differences, simultaneous_interval=[float(np.mean(differences)-radius), float(np.mean(differences)+radius)]))
            groups.append(dict(mechanism=mechanism, n=n, independent_repetitions=len(selected), comparisons=contrasts,
                mean_gains={name: float(np.mean([record['values'][name]['gain'] for record in selected])) for name in selected[0]['values']},
                mean_marginal_mse={name: float(np.mean([record['marginal_estimation'][name] for record in selected]))
                                   for name in ('full', 'zero', 'empirical_shrinkage', 'oracle_jci123')}))
        write_bundle(output/'summary', {'result.json': dict(groups=groups, cells=len(records), family_size=family_size,
            evidence_role=plan['evidence_role'], uncertainty='descriptive intervals on exposed method-development inputs')})
    return dict(cells=len(records), planned_cells=expected, summary_completed=(output/'summary').exists())

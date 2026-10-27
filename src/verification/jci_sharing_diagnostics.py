from __future__ import annotations

from collections import Counter
import itertools
import json
import os
from pathlib import Path
import subprocess

import numpy as np

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


def diagnose_jci_sharing(output, rscript):
    plan = read_json(output/'inputs'/'plan.json')
    states = np.asarray(list(itertools.product((0, 1), repeat=3)))
    rows = []
    counts = Counter()
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        cell = read_json(root/'result.json')
        name = cell['mechanism']
        effects = []
        for e in range(3):
            if name == 'baseline_shift':
                effect = .8*(1-2*states[:, 0])*.25
            elif name == 'scope_sign':
                effect = .8*(1-2*states[:, 0])*.30*(2*states[:, 1]-1)
            elif name == 'effect_shift':
                effect = .8*(1-2*states[:, 0])*(.30-.15*e)
            else:
                q = (.95, .75, .55)[e]
                posterior = np.where(states[:, 1], q, 1-q)
                effect = (1-2*states[:, 0])*.25*(.95*posterior-.65*(1-posterior))
            effects.append(effect)
        exact_qualified = []
        exact_limits = {}
        for mask in range(8):
            selected = [j for j in range(3) if mask >> j & 1]
            sufficiency, invariance = 0., 0.
            keys = sorted({tuple(state[selected]) for state in states})
            for key in keys:
                indexes = [i for i, state in enumerate(states) if tuple(state[selected]) == key]
                means = [float(values[indexes].mean()) for values in effects]
                sufficiency = max(sufficiency, *[float(np.ptp(values[indexes])) for values in effects])
                invariance = max(invariance, float(np.ptp(means)))
            exact_limits[str(mask)] = dict(sufficiency=sufficiency, invariance=invariance)
            if max(sufficiency, invariance) <= plan['sharing_margin']+1e-12:
                exact_qualified.append(mask)
        observed = [int(mask) for mask, record in cell['qualification'].items() if record['status'] == 'qualified']
        checked_comparisons = [item for record in cell['qualification'].values() for item in record['comparisons']]
        statuses = Counter(item['status'] for item in checked_comparisons)
        interval_radii = [(item['high']-item['low'])/2 for item in checked_comparisons if 'high' in item]
        for view_name, view in cell['views'].items():
            time_graph, jci_graph = [view['structure']['results'][name] for name in ('time', 'jci')]
            matrices_different = time_graph['pag'] != jci_graph['pag']
            counts[(view_name, 'different_pag')] += matrices_different
            counts[(view_name, 'different_sufficient')] += time_graph['sufficient'] != jci_graph['sufficient']
            counts[(view_name, 'different_proposals')] += time_graph['proposals'] != jci_graph['proposals']
        rows.append(dict(mechanism=name, n=cell['n'], repetition=cell['repetition'],
                         exact_qualified=exact_qualified, exact_limits=exact_limits, observed_qualified=observed,
                         comparison_status_counts=dict(statuses), interval_radius_median=float(np.median(interval_radii)),
                         interval_radius_max=float(max(interval_radii))))
    environment = dict(os.environ, LC_ALL='C', LANG='C', LC_COLLATE='C', LC_CTYPE='C', LC_MONETARY='C', LC_TIME='C')
    completed = subprocess.run([str(rscript), str(Path(__file__).with_name('jci_queries.R')), str(output)],
        check=True, text=True, encoding='utf-8', capture_output=True, env=environment)
    queries = json.loads(completed.stdout)
    query_counts = Counter((row['view'], row['method'], row['variable'], row['identified_by_gbc']) for row in queries)
    history = read_json(output/'historical'/'result.json')
    history_counts = {}
    for name, policy in history['policies'].items():
        statuses = Counter(policy['training']['generation_statuses']+policy['calibration']['generation_statuses'])
        history_counts[name] = dict(statuses)
    result = dict(evidence_role='POST_HOC_CAUSE_LOCALIZATION_ON_FROZEN_DEVELOPMENT_RESULTS',
        cells=rows, graph_counts=[dict(view=view, field=field, count=count) for (view, field), count in sorted(counts.items())],
        causal_queries=queries,
        causal_query_counts=[dict(view=view, method=name, variable=variable, identified=identified, count=count)
                            for (view, name, variable, identified), count in sorted(query_counts.items())],
        historical_generation_statuses=history_counts,
        query_scope='GBC identification on estimated PAGs; graph errors, support and alternative identification routes are not resolved',
        producer_sha256=file_sha256(Path(__file__)), r_producer_sha256=file_sha256(Path(__file__).with_name('jci_queries.R')),
        backend_stderr=completed.stderr)
    write_bundle(output/'diagnostics', {'result.json': result})
    return dict(cells=len(rows), causal_queries=len(queries),
                cells_with_exact_sharing=sum(bool(row['exact_qualified']) for row in rows),
                cells_with_observed_sharing=sum(bool(row['observed_qualified']) for row in rows),
                graph_counts=result['graph_counts'], causal_query_counts=result['causal_query_counts'])

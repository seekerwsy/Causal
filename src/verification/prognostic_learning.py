"""Independent verifier for directional JCI discovery and cross-fitted prognostic learning."""

from __future__ import annotations

import hashlib
import json
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import networkx as nx
import numpy as np
from scipy.special import expit
from scipy.stats import random_table, t
from sklearn.ensemble import HistGradientBoostingClassifier

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


SCENARIOS = ('downstream_signal', 'target_new_attribute', 'upstream_control', 'misaligned_signal')


def _rng(seed, *coordinates):
    digest = hashlib.sha256(json.dumps([seed, *coordinates]).encode()).digest()[:8]
    return np.random.default_rng(int.from_bytes(digest, 'big'))


def _branch_layout(plan):
    lengths = plan['precursor_lengths']
    assert len(lengths) == 8 and sum(lengths) == 24
    branches, offset = [], 0
    for length in lengths:
        branches.append(
            dict(
                precursors=list(range(offset, offset + length)),
                terminal=offset + length,
                proxy=offset + length + 1,
                intermediate=offset + length + 2,
                noise_leaf=offset + length + 3,
            )
        )
        offset += length + 4
    return branches


def _independent_draw(rng, size, environment, scenario, plan, permutation, outcomes=True):
    context_strength = plan.get('context_effect_strength', 0.30)
    flip = plan.get('attribute_measurement_flip_probability', 0.0)
    q = plan['context_source_probabilities'] if environment == 0 else plan['context_target_probabilities']
    contexts = rng.binomial(1, np.asarray(q), size=(size, 2))
    raw = np.empty((size, 64), dtype=int)
    branches = _branch_layout(plan)
    for idx, branch in enumerate(branches):
        latent = rng.binomial(1, 0.5, size)
        first, *rest = branch['precursors']
        raw[:, first] = rng.binomial(1, 0.05 + context_strength * contexts[:, idx % 2] + 0.60 * latent)
        prev = first
        for cur in rest:
            raw[:, cur] = rng.binomial(1, 0.20 + 0.60 * raw[:, prev])
            prev = cur
        raw[:, branch['proxy']] = rng.binomial(1, 0.05 + 0.90 * latent)
        raw[:, branch['intermediate']] = rng.binomial(1, 0.20 + 0.60 * raw[:, branch['proxy']])
        raw[:, branch['noise_leaf']] = rng.binomial(1, 0.20 + 0.60 * raw[:, branch['intermediate']])
    for idx, branch in enumerate(branches):
        raw[:, branch['terminal']] = rng.binomial(
            1,
            0.10 + 0.40 * raw[:, branch['precursors'][-1]] + 0.40 * raw[:, branches[(idx + 1) % 8]['precursors'][-1]],
        )
    raw[:, 56:] = rng.binomial(1, 0.5, size=(size, 8))
    if scenario == 'upstream_control':
        positions = [branch['precursors'][0] for branch in branches]
    elif scenario == 'misaligned_signal':
        positions = [branch['intermediate'] for branch in branches]
    else:
        positions = [branch['terminal'] for branch in branches]
    score = (2 * raw[:, positions] - 1).sum(axis=1).astype(float)
    if scenario == 'target_new_attribute' and environment == 1:
        score = 0.7 * score + 0.8 * (2 * raw[:, branches[0]['noise_leaf']] - 1)
    avg = expit(score)
    eff = plan['effect_multiplier'] * avg * (1.0 - avg)
    x = np.column_stack((contexts, raw[:, permutation]))
    if flip:
        x[:, 2:] ^= rng.binomial(1, flip, size=(size, 64))
    out = dict(x=x, average=avg, effect=eff)
    if outcomes:
        a = rng.binomial(1, 0.5, size)
        p = avg + (a - 0.5) * eff
        out.update(a=a, y=rng.binomial(1, p))
    return out


def _verify_ci_queries(queries, data, labels, draws, seed):
    states, counts = np.unique(np.asarray(data), axis=0, return_counts=True)
    for query in queries:
        x, y = sorted((query['x'], query['y']))
        conditioned = tuple(sorted(query['conditioned']))
        rng = _rng(seed, (x, y, conditioned))
        cols = [labels.index(name) for name in conditioned]
        groups = np.unique(states[:, cols], axis=0, return_inverse=True)[1] if cols else np.zeros(len(states), dtype=int)
        stat, null, informative, tables = 0.0, np.zeros(draws), 0, []
        for group in np.unique(groups):
            chosen = groups == group
            xs, xi = np.unique(states[chosen, labels.index(x)], return_inverse=True)
            ys, yi = np.unique(states[chosen, labels.index(y)], return_inverse=True)
            table = np.zeros((len(xs), len(ys)), dtype=int)
            np.add.at(table, (xi, yi), counts[chosen])
            tables.append(table.tolist())
            if min(table.shape) == 1:
                continue
            informative += 1
            exp_t = np.outer(table.sum(1), table.sum(0)) / table.sum()
            stat += np.sum((table - exp_t) ** 2 / exp_t)
            samples = random_table.rvs(table.sum(1), table.sum(0), size=draws, random_state=rng)
            null += np.sum((samples - exp_t) ** 2 / exp_t, axis=(1, 2))
        exceedances = int(np.count_nonzero(null >= stat - 1e-12))
        assert query['tables'] == tables
        assert query['informative_strata'] == informative
        assert query['exceedances'] == exceedances
        np.testing.assert_allclose(query['statistic'], stat, atol=1e-10)
        assert query['p'] == ((exceedances + 1) / (draws + 1) if informative else None)


def _independent_roles(graph, *, n_contexts=2, n_attributes=None):
    if graph['status'] != 'evaluated':
        total = n_contexts + (64 if n_attributes is None else n_attributes)
        all_attrs = list(range(n_contexts, total))
        return dict(eligible=False, root=[], terminal=[], upstream=[], other=all_attrs, reachable=[])
    pag = np.asarray(graph['pag'])
    total = pag.shape[0] if n_attributes is None else n_contexts + n_attributes
    assert pag.ndim == 2 and pag.shape == (total, total) and total > n_contexts
    assert np.all(np.isin(pag, [0, 1, 2, 3]))
    assert np.all((pag != 0) == (pag.T != 0)) and not np.any(np.diag(pag))
    directed = nx.DiGraph()
    directed.add_nodes_from(range(total))
    directed.add_edges_from((int(u), int(v)) for u, v in np.argwhere((pag == 2) & (pag.T == 3)))
    cycles = any(len(c) > 1 for c in nx.strongly_connected_components(directed))
    conflicts = any(nx.has_path(directed, int(b), int(a)) for a, b in np.argwhere(pag == 2))
    ctx_bad = bool(np.any(pag[:, :n_contexts] == 2)) or bool(np.any(pag[:n_contexts, :n_contexts]))
    eligible = not cycles and not conflicts and not ctx_bad
    if not eligible:
        return dict(eligible=False, root=[], terminal=[], upstream=[], other=list(range(n_contexts, total)), reachable=[])
    ctx_nodes = set(range(n_contexts))
    root = sorted(set().union(*(set(directed.successors(ctx)) for ctx in range(n_contexts))) - ctx_nodes)
    reach = sorted(set().union(*(nx.descendants(directed, ctx) for ctx in range(n_contexts))) - ctx_nodes)
    reach_set = set(reach)
    term = sorted(node for node in reach if not (set(directed.successors(node)) & reach_set))
    up = sorted(reach_set - set(term))
    other = sorted(set(range(n_contexts, total)) - reach_set)
    return dict(eligible=True, root=root, terminal=term, upstream=up, other=other, reachable=reach)


def _independent_true_roles(plan, permutation):
    branches = _branch_layout(plan)
    inv = np.argsort(permutation) + 2
    root = sorted(int(inv[b['precursors'][0]]) for b in branches)
    term = sorted(int(inv[b['terminal']]) for b in branches)
    up = sorted(int(inv[p]) for b in branches for p in b['precursors'])
    reach = sorted(set(term) | set(up))
    other = sorted(set(range(2, 66)) - set(reach))
    return dict(eligible=True, root=root, terminal=term, upstream=up, other=other, reachable=reach)


def _ridge_solve(x, y, penalty):
    return np.linalg.solve(x.T @ x + penalty * np.eye(x.shape[1]), x.T @ y)


def verify_source_and_cross_fit_records(
    src_models,
    cross_fit,
    *,
    src_x,
    src_y,
    tgt_x,
    tgt_a,
    tgt_y,
    fit_seed,
    k_folds,
):
    """Independently verify source KKT optimality, Ridge normal equations, OOF predictions, and scores."""
    z_src = 2 * np.asarray(src_x) - 1
    y_src = np.asarray(src_y, dtype=float)
    for rec in src_models.values():
        if rec['kind'] == 'weighted_logit':
            chosen_idx = rec['selected']
            assert chosen_idx == min(range(len(rec['losses'])), key=lambda i: (rec['losses'][i], i))
            for grp in rec['groups']:
                coef = np.asarray(grp['coefficients'])
                w = np.asarray(grp['weights'])
                prob = expit(coef[0] + z_src @ coef[1:])
                grad = z_src.T @ (prob - y_src) + w / grp['C'] * coef[1:]
                kkt = max(float(abs(grad).max()), float(abs(np.sum(prob - y_src))))
                assert kkt <= 1e-3
        elif rec['kind'] == 'logit':
            coef = np.asarray(rec['coefficients'])
            feats = rec['features']
            ratio = float(rec['l1_ratio'])
            prob = expit(coef[0] + z_src[:, feats] @ coef[1:])
            grad = z_src[:, feats].T @ (prob - y_src) + (1.0 - ratio) / rec['C'] * coef[1:]
            nz = coef[1:] != 0
            grad[nz] += ratio / rec['C'] * np.sign(coef[1:][nz])
            viol = np.abs(grad)
            viol[~nz] = np.maximum(viol[~nz] - ratio / rec['C'], 0.0)
            kkt = max(float(viol.max()), float(abs(np.sum(prob - y_src))))
            assert kkt <= 1e-3

    boosted_params = src_models['boosted']['parameters']
    boosted_fit = HistGradientBoostingClassifier(
        learning_rate=0.1,
        min_samples_leaf=10,
        l2_regularization=1.0,
        early_stopping=False,
        random_state=fit_seed,
        **boosted_params,
    ).fit(z_src, y_src)

    def indep_predict(name, x_raw):
        rec = src_models[name]
        z = 2 * np.asarray(x_raw) - 1
        if rec['kind'] == 'boosted':
            return boosted_fit.predict_proba(z)[:, 1]
        coef = np.asarray(rec['coefficients'])
        return expit(coef[0] + z[:, rec['features']] @ coef[1:])

    x_tgt = np.asarray(tgt_x)
    a_tgt = np.asarray(tgt_a)
    y_tgt = np.asarray(tgt_y, dtype=float)
    n_tgt = len(y_tgt)
    outer_fold = np.arange(n_tgt) % k_folds
    design = np.column_stack((np.ones(n_tgt), 2 * x_tgt - 1))
    tgt_base_preds = {name: indep_predict(name, x_tgt) for name in src_models}

    for cf in cross_fit.values():
        oof = np.empty(n_tgt, dtype=float)
        for f_idx, fold_rec in enumerate(cf['folds']):
            assert fold_rec['fold'] == f_idx
            held = outer_fold == f_idx
            train = ~held
            bname = fold_rec['selected_base']
            pen = fold_rec['selected_penalty']
            x_tr, y_tr = design[train], y_tgt[train]
            base_tr = np.zeros(len(y_tr)) if bname == 'target_only' else tgt_base_preds[bname][train]
            base_te = np.zeros(int(held.sum())) if bname == 'target_only' else tgt_base_preds[bname][held]
            inner_fold = np.arange(len(y_tr)) % (k_folds - 1)
            sq_errs = []
            for inf in range(k_folds - 1):
                in_val = inner_fold == inf
                in_trn = ~in_val
                d_in = _ridge_solve(x_tr[in_trn], y_tr[in_trn] - base_tr[in_trn], pen)
                p_in = np.clip(base_tr[in_val] + x_tr[in_val] @ d_in, 0.0, 1.0)
                sq_errs.extend(((y_tr[in_val] - p_in) ** 2).tolist())
            np.testing.assert_allclose(fold_rec['inner_cv_loss'], float(np.mean(sq_errs)), atol=1e-10)
            delta = _ridge_solve(x_tr, y_tr - base_tr, pen)
            np.testing.assert_allclose(fold_rec['coefficients'], delta, atol=1e-9)
            oof[held] = np.clip(base_te + design[held] @ delta, 0.0, 1.0)
        np.testing.assert_allclose(cf['oof_predictions'], oof, atol=1e-12)
        scores = 2.0 * (2.0 * a_tgt - 1.0) * (y_tgt - oof)
        np.testing.assert_allclose(cf['scores'], scores, atol=1e-12)
        np.testing.assert_allclose(cf['effect'], float(scores.mean()), atol=1e-12)
        np.testing.assert_allclose(cf['standard_error'], float(scores.std(ddof=1) / np.sqrt(n_tgt)), atol=1e-12)
    return indep_predict


def _verify_cell(arguments):
    cell_path, plan = arguments
    verify_bundle(cell_path)
    cell = read_json(cell_path / 'result.json')
    batch, scenario, rep = cell['batch'], cell['scenario'], cell['repetition']
    scen_idx = plan['scenarios'].index(scenario)
    base = [plan['batch_seeds'][batch], scen_idx, rep]
    seed = lambda role: int(np.random.SeedSequence([*base, role]).generate_state(1)[0])

    perm = np.random.default_rng(seed(12)).permutation(64).tolist()
    assert perm == cell['permutation']
    for role, (name, size) in enumerate((('auxiliary', plan['auxiliary_size']), ('source', plan['source_size']), ('target', plan['target_size']))):
        expected = _independent_draw(np.random.default_rng(seed(role)), size, 0 if role < 2 else 1, scenario, plan, perm, outcomes=role != 0)
        for key in expected:
            if key in ('x', 'a', 'y'):
                np.testing.assert_array_equal(cell['data'][name][key], expected[key])

    labels = ['C1', 'C2', *[f'X{i:02d}' for i in range(64)]]
    aux_x = np.asarray(cell['data']['auxiliary']['x'])
    assert cell['ci_seed'] == seed(20)
    _verify_ci_queries(cell['queries'], aux_x, labels, plan['ci_draws'], seed(20))
    lookup = {(q['x'], q['y'], tuple(q['conditioned'])): q['p'] for q in cell['queries']}
    expected_ctx = [
        idx
        for idx in range(2, 66)
        if any(lookup[(labels[r], labels[idx], ())] is None or lookup[(labels[r], labels[idx], ())] < plan['ci_alpha'] for r in (0, 1))
    ]
    assert cell['context_attributes'] == expected_ctx

    roles = _independent_roles(cell['graph'], n_contexts=2, n_attributes=plan['attributes'])
    assert cell['roles']['eligible'] == roles['eligible']
    assert cell['roles']['root'] == roles['root']
    assert cell['roles']['terminal'] == roles['terminal']
    assert cell['roles']['upstream'] == roles['upstream']
    assert cell['roles']['other'] == roles['other']
    true_roles = _independent_true_roles(plan, perm)
    assert cell['true_roles']['root'] == true_roles['root']
    assert cell['true_roles']['terminal'] == true_roles['terminal']
    assert cell['true_roles']['upstream'] == true_roles['upstream']

    src_x = np.asarray(cell['data']['source']['x'])
    src_y = np.asarray(cell['data']['source']['y'], dtype=float)
    tgt_x = np.asarray(cell['data']['target']['x'])
    tgt_a = np.asarray(cell['data']['target']['a'])
    tgt_y = np.asarray(cell['data']['target']['y'], dtype=float)
    src_models = cell['source']['models']
    indep_predict = verify_source_and_cross_fit_records(
        src_models,
        cell['cross_fit'],
        src_x=src_x,
        src_y=src_y,
        tgt_x=tgt_x,
        tgt_a=tgt_a,
        tgt_y=tgt_y,
        fit_seed=seed(10),
        k_folds=plan['target_folds'],
    )

    # Independently replay risk integration.
    n_tgt = len(tgt_y)
    k_folds = plan['target_folds']
    test_rng = np.random.default_rng(seed(5))
    methods = list(cell['cross_fit'])
    sums = {name: 0.0 for name in methods}
    tau_sum, tau_sq = 0.0, 0.0
    remaining = plan['test_covariates']
    while remaining:
        sz = min(remaining, plan['test_batch_size'])
        sample = _independent_draw(test_rng, sz, 1, scenario, plan, perm, outcomes=False)
        g, tau = sample['average'], sample['effect']
        mat = np.column_stack((np.ones(sz), 2 * sample['x'] - 1))
        bpreds = {name: indep_predict(name, sample['x']) for name in src_models}
        for name in methods:
            acc = np.zeros(sz)
            for fold_rec in cell['cross_fit'][name]['folds']:
                bname = fold_rec['selected_base']
                coef = np.asarray(fold_rec['coefficients'])
                bvec = np.zeros(sz) if bname == 'target_only' else bpreds[bname]
                pred = np.clip(bvec + mat @ coef, 0.0, 1.0)
                acc += (g * (1.0 - pred) ** 2 + (1.0 - g) * pred ** 2) / k_folds
            sums[name] += float(acc.sum())
        tau_sum += float(tau.sum())
        tau_sq += float(tau @ tau)
        remaining -= sz

    cnt = plan['test_covariates']
    truth = tau_sum / cnt
    tau_var = (tau_sq - tau_sum ** 2 / cnt) / (cnt - 1)
    truth_sq = truth ** 2 - tau_var / cnt
    np.testing.assert_allclose(cell['integrated']['truth'], truth, atol=1e-12)
    for name in methods:
        risk = (4.0 * (sums[name] / cnt) - truth_sq) / n_tgt
        np.testing.assert_allclose(cell['integrated']['risks'][name], risk, atol=1e-12)

    return dict(
        batch=batch,
        scenario=scenario,
        repetition=rep,
        risks=cell['integrated']['risks'],
        diagnostics=cell['diagnostics'],
        queries=len(cell['queries']),
        direction_eligible=bool(roles['eligible']),
    )


def verify_directional_study(output_dir, *, workers=1):
    output = Path(output_dir)
    verify_bundle(output / 'inputs')
    verify_bundle(output / 'summary')
    plan = read_json(output / 'inputs' / 'plan.json')
    identity = read_json(output / 'inputs' / 'identity.json')
    summary = read_json(output / 'summary' / 'result.json')

    assert plan.get('formal_claim_allowed') is False and plan.get('new_provider_calls', 0) == 0
    assert summary.get('formal_claim_allowed') is False and summary.get('new_provider_calls', 0) == 0
    assert file_sha256(output / 'source.zip') == identity['source_archive_sha256']
    with zipfile.ZipFile(output / 'source.zip') as archive:
        for path, digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest() == digest

    cell_dirs = sorted((output / 'cells').iterdir())
    assert len(cell_dirs) == identity['declared_cells'] == summary['cells']
    if workers == 1:
        checked = [_verify_cell((p, plan)) for p in cell_dirs]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            checked = list(pool.map(_verify_cell, ((p, plan) for p in cell_dirs)))

    family = summary['comparison_family_size']
    for comp in summary['comparisons']:
        group = [row for row in checked if row['scenario'] == comp['scenario']]
        diffs = np.asarray([row['risks'][comp['baseline']] - row['risks'][comp['tested']] for row in group])
        mean = float(diffs.mean())
        base = float(np.mean([row['risks'][comp['baseline']] for row in group]))
        np.testing.assert_allclose(comp['difference'], mean, atol=1e-12)
        np.testing.assert_allclose(comp['relative_reduction'], mean / base, atol=1e-12)
        radius = float(t.ppf(1 - plan['component_alpha'] / (2 * family), len(group) - 1) * diffs.std(ddof=1) / np.sqrt(len(group)))
        np.testing.assert_allclose(comp['interval'], [mean - radius, mean + radius], atol=1e-12)
        batches = [float(np.mean([row['risks'][comp['baseline']] - row['risks'][comp['tested']] for row in group if row['batch'] == b])) for b in sorted({row['batch'] for row in group})]
        np.testing.assert_allclose(comp['batch_differences'], batches, atol=1e-12)
        full = len(group) == len(plan['batch_seeds']) * plan['repetitions_per_batch']
        expected_sup = full and (mean / base >= plan['minimum_relative_variance_reduction']) and (mean - radius > 0) and len(batches) == 2 and min(batches) > 0
        assert comp['supported'] == expected_sup
        expected_harm = (mean + radius < 0) and max(batches) < 0
        assert comp['harm_supported'] == expected_harm

    # Recompute every summary verdict from the independently checked comparisons (never echo them).
    pairs = [(tested, baseline) for tested in ('oracle', 'jci') for baseline in plan['primary_comparators']]
    pairs += [('jci', baseline) for baseline in plan['structural_comparators']]
    if 'target_only' in plan.get('extra_comparators', []):
        pairs += [('jci', 'target_only'), ('oracle', 'target_only')]
    expected_keys = sorted((s, a, b) for s in plan['scenarios'] for a, b in pairs)
    assert sorted((c['scenario'], c['tested'], c['baseline']) for c in summary['comparisons']) == expected_keys
    assert family == plan.get('comparison_family_size', len(expected_keys))
    jci = [c for c in summary['comparisons'] if c['tested'] == 'jci']
    downstream = [c for c in jci if c['scenario'] == 'downstream_signal']
    harm_by_scenario = {s: sum(1 for c in jci if c['scenario'] == s and c['harm_supported']) for s in plan['scenarios']}
    assert summary['downstream_gate_passed'] == (bool(downstream) and all(c['supported'] for c in downstream))
    assert summary['upstream_harm_count'] == harm_by_scenario.get('upstream_control', 0)
    if 'jci_harm_count_by_scenario' in summary:  # absent in bundles produced before 2026-11-16 negative-control upgrade
        assert summary['jci_harm_count_by_scenario'] == harm_by_scenario
        assert summary['jci_harm_total'] == sum(harm_by_scenario.values())
    assert summary['primary_passed'] == sum(1 for c in jci if c['baseline'] in plan['primary_comparators'] and c['supported'])
    assert summary['direction_eligible_cells'] == sum(1 for row in checked if row['direction_eligible'])

    result = dict(
        status='VERIFIED',
        study_id=plan['study_id'],
        cells=len(checked),
        queries_verified=sum(row['queries'] for row in checked),
        comparisons_verified=len(summary['comparisons']),
        downstream_gate_passed=summary['downstream_gate_passed'],
        upstream_harm_count=summary['upstream_harm_count'],
        jci_harm_count_by_scenario=harm_by_scenario,
        primary_passed=summary['primary_passed'],
        primary_total=summary['primary_total'],
        summary_sha256=file_sha256(output / 'summary' / 'result.json'),
    )
    write_bundle(output / 'verification', {'result.json': result})
    return result

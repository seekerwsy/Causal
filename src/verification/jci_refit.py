from __future__ import annotations

import itertools
from pathlib import Path

import numpy as np
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.verification.jci_policy import (
    independent_actions, independent_baseline, independent_calibration, independent_features,
    independent_fit, independent_prediction, independent_value,
)


def independent_zero_fit(training, family, penalty, nulls, indexes):
    indexes = np.asarray(indexes)
    source = np.asarray(training['w'])[indexes]
    assignment = np.asarray(training['a'])[indexes]
    outcome = np.asarray(training['y'])[indexes]
    width = source.shape[1]
    if family == 'arm_mean':
        baseline = np.mean([value for arm, value in zip(assignment, outcome, strict=True) if arm == 0 or nulls[int(arm)-1]])
        marginal = np.asarray([0. if nulls[index] else outcome[assignment == index+1].mean()-baseline for index in range(width)])
        return dict(baseline=float(baseline), marginal=marginal, coefficients=marginal/np.mean(1-source, axis=0))
    features = independent_features(training, family)[indexes]
    effects = np.zeros((len(indexes), features.shape[-1]))
    for row, arm in enumerate(assignment):
        if arm:
            effects[row] = features[row, int(arm)-1]
    baseline = independent_baseline(source)
    design = np.column_stack((np.ones(len(indexes)), baseline, effects))
    kept = np.r_[np.ones(1+baseline.shape[1], dtype=bool), np.repeat(~np.asarray(nulls), features.shape[-1]//width)]
    reduced = design[:, kept]
    gram = reduced.T@reduced/len(indexes)+np.diag(np.r_[0., np.full(reduced.shape[1]-1, penalty)])
    eigenvalues, eigenvectors = np.linalg.eigh(gram)
    if eigenvalues.min() <= 0:
        raise ValueError('独立约束设计无效')
    coefficient = eigenvectors@((eigenvectors.T@(reduced.T@outcome/len(indexes)))/eigenvalues)
    expanded = np.zeros(design.shape[1])
    expanded[kept] = coefficient
    return dict(coefficients=expanded)


def independent_zero_prediction(reference, destination, family):
    if family == 'arm_mean':
        return np.clip((1-np.asarray(destination['w']))*reference['coefficients'], -1., 1.)
    return independent_prediction(reference['coefficients'], destination, family, False)


def verify_zero_cell(parent, record, parent_plan, plan, oracles):
    training, calibration = parent['training'], parent['calibration']
    width = len(parent['beta'])
    states = np.asarray(list(itertools.product((0, 1), repeat=width)))
    evaluation = dict(w=states.tolist(), identity_zero=states.astype(bool).tolist())
    positions = {identity: index for index, identity in enumerate(training['task_ids'])}
    samples = [np.arange(len(positions))]+[np.asarray([positions[identity] for identity in graph['task_ids']])
              for graph in parent['learned']['graphs'][1:]]
    canonical = oracles[parent['mechanism']]
    source_order = [index for index, value in enumerate(canonical['beta']) if value != 0]+[index for index, value in enumerate(canonical['beta']) if value == 0]
    target_order = [index for index, value in enumerate(parent['beta']) if value != 0]+[index for index, value in enumerate(parent['beta']) if value == 0]
    mapping = dict(zip(target_order, source_order, strict=True))
    oracle_masks = {name: np.asarray([result['ancestry'][mapping[index]][-1] == -1 for index in range(width)])
                    for name, result in canonical['results'].items()}
    oracle_masks['direct_ci'] = np.asarray([canonical['direct_ci_nulls'][f'C{mapping[index]+1}'] for index in range(width)])
    for name, mask in oracle_masks.items():
        np.testing.assert_array_equal(mask, record['oracle_null_masks'][name])
    direct_support = []
    for queries in record['direct_ci_queries']:
        assert len(queries) == width
        support = []
        for query in queries:
            statistic = 0.
            for raw in query['tables']:
                table = np.asarray(raw)
                if min(table.shape) > 1:
                    expected = np.outer(table.sum(1), table.sum(0))/table.sum()
                    statistic += float(np.sum((table-expected)**2/expected))
            np.testing.assert_allclose(statistic, query['statistic'], atol=1e-10)
            assert query['p'] == (1+query['exceedances'])/(1+parent_plan['ci_draws'])
            support.append(query['p'] > parent_plan['ci_alpha'])
        direct_support.append(support)
    np.testing.assert_array_equal(np.mean(direct_support, axis=0), record['direct_ci_support'])
    supports = {name: np.asarray(value) for name, value in parent['learned']['nonancestry_support'].items()}
    supports['direct_ci'] = np.asarray(record['direct_ci_support'])
    cache, fits = {}, 0
    def refitted(family, penalty, mask, sample_index=0):
        nonlocal fits
        key = family, penalty, tuple(mask), sample_index
        if key not in cache:
            cache[key] = independent_zero_fit(training, family, penalty, mask, samples[sample_index])
            fits += 1
        return cache[key]
    nuisance_coef = independent_fit(training, 'full', parent_plan['simulation_nuisance_penalty'], samples[0])
    cal_features = independent_features(calibration, 'full')
    baseline = independent_baseline(calibration['w'])@nuisance_coef[1:-cal_features.shape[-1]]+nuisance_coef[0]
    nuisance = np.column_stack((baseline, baseline[:, None]+independent_prediction(nuisance_coef, calibration, 'full', False)))
    direct_maximum = {}
    def verify_model(model):
        reference = refitted(model['family'], model['penalty'], model['nulls'])
        if model['family'] == 'arm_mean':
            np.testing.assert_allclose(reference['baseline'], model['baseline'], atol=1e-12)
            np.testing.assert_allclose(reference['marginal'], model['marginal_effects'], atol=1e-12)
            np.testing.assert_allclose(reference['coefficients'], model['coefficients'], atol=1e-12)
        else:
            np.testing.assert_allclose(reference['coefficients'], [model['intercept'], *model['coefficients']], atol=2e-10, rtol=2e-9)
        return reference
    for name, candidates in record['candidates'].items():
        if name == 'direct_envelope':
            assert candidates[:-1] == record['candidates']['full']+record['candidates']['direct_null']+record['candidates']['direct_ci']
            assert candidates[-1]['calibration_gain'] == parent['learned']['choices']['direct_envelope']['calibration_gain']
            continue
        for candidate in candidates:
            if candidate['model'] is None:
                assert candidate['origin'] == 'baseline' and candidate['calibration_gain'] == 0.
                continue
            model, threshold = candidate['model'], candidate['threshold']
            reference = verify_model(model)
            if name == 'direct_null':
                key = model['family'], model['penalty']
                if key not in direct_maximum:
                    mask = np.zeros(width, dtype=bool)
                    point = independent_zero_prediction(refitted(*key, mask), evaluation, key[0])
                    boot = np.asarray([independent_zero_prediction(refitted(*key, mask, index), evaluation, key[0])
                                       for index in range(1, len(samples))])
                    standard = np.std(boot, ddof=1, axis=0)
                    statistic = np.divide(np.abs(point), standard, out=np.where(point == 0, 0., np.inf), where=standard > 0)
                    direct_maximum[key] = statistic.max(axis=0)
                expected_mask = direct_maximum[key] < threshold
            elif name == 'full' or threshold is None:
                expected_mask = np.zeros(width, dtype=bool)
            elif name.startswith('oracle_'):
                expected_mask = oracle_masks[name.removeprefix('oracle_')]
            else:
                expected_mask = supports[name] >= threshold
            np.testing.assert_array_equal(expected_mask, model['nulls'])
            scores = independent_zero_prediction(reference, calibration, model['family'])
            gain, actions = independent_calibration(calibration, scores, nuisance)
            np.testing.assert_allclose(gain, candidate['calibration_gain'], atol=1e-11)
            np.testing.assert_array_equal(actions, candidate['calibration_actions'])
    for name, choice in record['choices'].items():
        best = max(enumerate(record['candidates'][name]), key=lambda item: (item[1]['calibration_gain'], -item[0]))[1]
        assert choice == best
        if choice['origin'] == 'parent_direct':
            scores = np.asarray(parent['learned']['outputs']['direct_envelope']['scores'])
        elif choice['model'] is None:
            scores = np.zeros_like(states, dtype=float)
        else:
            scores = independent_zero_prediction(verify_model(choice['model']), evaluation, choice['model']['family'])
        np.testing.assert_allclose(scores, record['predictions'][name], atol=1e-10)
        reference = independent_value(scores, parent['beta'], parent_plan)
        for field in ('gain', 'value', 'regret'):
            np.testing.assert_allclose(reference[field], record['values'][name][field], atol=1e-12)
        assert independent_actions(scores).tolist() == record['values'][name]['actions']
    ordinary = refitted('arm_mean', 0., np.zeros(width, dtype=bool))
    constrained = refitted('arm_mean', 0., oracle_masks['jci123'])
    truth = (1-np.mean(parent_plan['simulation']['source_probability_by_latent']))*np.asarray(parent['beta'])
    np.testing.assert_allclose(np.mean((ordinary['marginal']-truth)**2), record['marginal_estimation']['full'], atol=1e-12)
    np.testing.assert_allclose(np.mean((constrained['marginal']-truth)**2), record['marginal_estimation']['oracle_jci123'], atol=1e-12)
    np.testing.assert_allclose(np.mean(truth**2), record['marginal_estimation']['zero'], atol=1e-12)
    assignment = np.asarray(training['a'])
    outcome = np.asarray(training['y'])
    counts = np.asarray([np.count_nonzero(assignment == arm) for arm in range(width+1)])
    np.testing.assert_array_equal(counts, record['marginal_estimation']['arm_counts'])
    sampling_variance = np.asarray([np.var(outcome[assignment == arm], ddof=1)/counts[arm]
                                   for arm in range(width+1)])
    squared_norm = sum(value**2 for value in ordinary['marginal'])
    shrinkage = (0. if squared_norm == 0 else
                 max(0., 1-sum(sampling_variance[1:]+sampling_variance[0])/squared_norm))
    np.testing.assert_allclose(shrinkage, record['marginal_estimation']['empirical_shrinkage_factor'], atol=1e-12)
    np.testing.assert_allclose(np.mean((shrinkage*ordinary['marginal']-truth)**2),
                               record['marginal_estimation']['empirical_shrinkage'], atol=1e-12)
    baseline_probability = (parent_plan['simulation']['baseline_probability']
        +.5*parent_plan['simulation']['latent_outcome_coefficient']
        +np.mean(parent_plan['simulation']['source_probability_by_latent'])*sum(parent['beta']))
    outcome_probability = baseline_probability+truth
    treated_variance = outcome_probability*(1-outcome_probability)/counts[1:]
    baseline_variance = baseline_probability*(1-baseline_probability)
    np.testing.assert_allclose(treated_variance+baseline_variance/counts[0],
        record['marginal_estimation']['fixed_count_reference_variance'], atol=1e-12)
    pool_count = counts[0]+sum(counts[1:][oracle_masks['jci123']])
    np.testing.assert_allclose(np.where(oracle_masks['jci123'], 0., treated_variance+baseline_variance/pool_count),
        record['marginal_estimation']['fixed_count_oracle_variance'], atol=1e-12)
    return fits


def marginal_diagnostics(records, plan):
    groups = []
    thresholds = plan['nonancestry_thresholds']
    coordinates = sorted({(record['mechanism'], record['n']) for record in records})
    comparators = ('full', 'zero', 'empirical_shrinkage', 'time', 'jci12', 'direct_ci')
    family_size = len(coordinates)*len(thresholds)*len(comparators)
    for mechanism, size in coordinates:
        selected = [row for row in records if (row['mechanism'], row['n']) == (mechanism, size)]
        for threshold in thresholds:
            errors = {name: [] for name in (*comparators, 'jci123')}
            false_zeros = {name: 0 for name in ('time', 'jci12', 'jci123', 'direct_ci')}
            for row in selected:
                truth = np.asarray(row['marginal_estimation']['true_marginal_effects'])
                for name in ('full', 'zero', 'empirical_shrinkage'):
                    errors[name].append(row['marginal_estimation'][name])
                for name in false_zeros:
                    model = next(candidate['model'] for candidate in row['candidates'][name]
                        if candidate['model'] is not None and candidate['model']['family'] == 'arm_mean'
                        and candidate['threshold'] == threshold)
                    error = np.asarray(model['marginal_effects'])-truth
                    errors[name].append(float(error@error/len(truth)))
                    false_zeros[name] += int(np.count_nonzero(np.asarray(model['nulls']) & (truth != 0)))
            comparisons = []
            for name in comparators:
                differences = np.asarray(errors['jci123'])-errors[name]
                radius = t.ppf(1-.05/(2*family_size), len(selected)-1)*np.std(differences, ddof=1)/np.sqrt(len(selected))
                comparisons.append(dict(comparator=name, mse_difference=float(differences.mean()),
                    paired_differences=differences.tolist(),
                    simultaneous_interval=[float(differences.mean()-radius), float(differences.mean()+radius)]))
            groups.append(dict(mechanism=mechanism, n=size, threshold=threshold, independent_repetitions=len(selected),
                mean_mse={name: float(np.mean(values)) for name, values in errors.items()},
                active_policy_positions=sum(int(np.count_nonzero(row['marginal_estimation']['true_marginal_effects'])) for row in selected),
                false_zero_positions=false_zeros, comparisons=comparisons))
    return dict(evidence_role='POST_HOC_EXPOSED_MARGINAL_ESTIMATION_DIAGNOSTIC', family_size=family_size,
                uncertainty='descriptive simultaneous paired t intervals; all frozen thresholds retained', groups=groups)


def verify_zero_refit(parent):
    output = parent/'zero-effect-refit'
    verify_bundle(output/'inputs')
    identity = read_json(output/'inputs'/'identity.json')
    assert identity['parent_input_manifest_sha256'] == file_sha256(parent/'inputs'/'manifest.json')
    for source, digest in identity['sources'].items():
        assert file_sha256(Path(source)) == digest
    parent_plan, plan = read_json(parent/'inputs'/'plan.json'), read_json(output/'inputs'/'plan.json')
    verify_bundle(output/'graphical-oracle')
    oracles = read_json(output/'graphical-oracle'/'result.json')
    fits, records = 0, []
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        source = parent/'cells'/root.name
        verify_bundle(source)
        record, original = read_json(root/'result.json'), read_json(source/'result.json')
        assert record['source_result_sha256'] == file_sha256(source/'result.json')
        fits += verify_zero_cell(original, record, parent_plan, plan, oracles)
        records.append(record)
        if len(records) % 16 == 0:
            print(f'Zero-effect independent verification: {len(records)} cells, {fits} fits', flush=True)
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    for group in summary['groups']:
        selected = [record for record in records if record['mechanism'] == group['mechanism'] and record['n'] == group['n']]
        assert len(selected) == group['independent_repetitions'] == parent_plan['simulation']['repetitions']
        for name, value in group['mean_gains'].items():
            np.testing.assert_allclose(value, np.mean([record['values'][name]['gain'] for record in selected]), atol=1e-12)
        for name, value in group['mean_marginal_mse'].items():
            np.testing.assert_allclose(value, np.mean([record['marginal_estimation'][name] for record in selected]), atol=1e-12)
        for comparison in group['comparisons']:
            differences = [row['values'][comparison['method']]['gain']-row['values'][comparison['comparator']]['gain'] for row in selected]
            np.testing.assert_allclose(sorted(differences), sorted(comparison['paired_differences']), atol=1e-12)
            radius = t.ppf(1-.05/(2*summary['family_size']), len(selected)-1)*np.std(differences, ddof=1)/np.sqrt(len(selected))
            np.testing.assert_allclose([np.mean(differences)-radius, np.mean(differences)+radius], comparison['simultaneous_interval'], atol=1e-12)
    expected = len(parent_plan['simulation']['mechanisms'])*len(parent_plan['simulation']['tasks_per_role'])*parent_plan['simulation']['repetitions']
    assert len(records) == expected
    diagnostic = marginal_diagnostics(records, plan)
    diagnostic['source_result_sha256'] = {root.name: file_sha256(root/'result.json')
        for root in sorted((output/'cells').iterdir())}
    diagnostic['implementation_sha256'] = file_sha256(Path(__file__))
    if not (output/'marginal-diagnostics').exists():
        write_bundle(output/'marginal-diagnostics', {'result.json': diagnostic})
    else:
        verify_bundle(output/'marginal-diagnostics')
        assert read_json(output/'marginal-diagnostics'/'result.json') == diagnostic
    result = dict(status='verified', cells=len(records), independently_refitted_models=fits,
                  marginal_errors_and_conditional_variances_verified=True, summary_means_verified=True,
                  verifier_sha256=file_sha256(Path(__file__)))
    if not (output/'verification').exists():
        write_bundle(output/'verification', {'result.json': result})
    return result

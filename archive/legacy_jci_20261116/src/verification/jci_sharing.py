from __future__ import annotations

import itertools
import hashlib
from pathlib import Path
import zipfile

import numpy as np
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


def independent_design(w, environments, mask, known):
    terms = [subset for subset in range(8) if subset & mask == subset]
    transformed = 2*np.asarray(w)-1
    full = np.asarray([[np.prod([row[j] for j in range(3) if subset & (1 << j)])
                        for subset in range(8)] for row in transformed], dtype=float)
    return np.column_stack((full[:, terms], *[
        full*(np.asarray(environments) == e)[:, None] for e in known]))


def verify_fit(training, model, moments=None):
    if moments is None:
        design = independent_design(training['w'], training['e'], model['mask'], model['environments'])
        gram = design.T@design/len(design)
        right = design.T@np.asarray(training['delta'])/len(design)
    else:
        gram, right = moments
    width = model['mask'].bit_count()
    shared = 2**width
    penalties = np.r_[0., np.full(shared-1, model['penalty']),
                       np.full(len(right)-shared, model['environment_penalty'])]
    eigenvalues, eigenvectors = np.linalg.eigh(gram+np.diag(penalties))
    if eigenvalues.min() <= 0:
        raise ValueError('独立复算的正则化设计无效')
    reference = eigenvectors@((eigenvectors.T@right)/eigenvalues)
    np.testing.assert_allclose(reference, [model['intercept'], *model['coefficients']], atol=2e-10, rtol=2e-9)
    return reference


def verify_choices(data, plan):
    checked = 0
    calibration = data['calibration']
    delta = np.asarray(calibration['delta'])
    cache, moments, calibration_designs = {}, {}, {}
    for view in data['views'].values():
        search = view['structure']
        for result in search['results'].values():
            pag = np.asarray(result['pag'])
            if result['status'] == 'determined':
                mag = np.asarray(result['mag'])
                assert np.array_equal(pag != 0, mag != 0)
                assert np.array_equal(pag[np.isin(pag, (2, 3))], mag[np.isin(pag, (2, 3))])
            assert 7 in result['proposals']
        if 'calibration_candidates' not in view:
            for choice in view['choices'].values():
                if choice['model'] is not None:
                    verify_fit(data['training'], choice['model'])
                    checked += 1
            continue
        for row in view['calibration_candidates']:
            model = row['model']
            key = model['mask'], model['penalty'], model['environment_penalty']
            if key not in cache:
                if model['mask'] not in moments:
                    train_design = independent_design(data['training']['w'], data['training']['e'], model['mask'], model['environments'])
                    moments[model['mask']] = (train_design.T@train_design/len(train_design),
                                              train_design.T@np.asarray(data['training']['delta'])/len(train_design))
                    calibration_designs[model['mask']] = independent_design(calibration['w'], calibration['e'], model['mask'], model['environments'])
                coefficients = verify_fit(data['training'], model, moments[model['mask']])
                design = calibration_designs[model['mask']]
                cache[key] = design@coefficients
                checked += 1
            action = np.zeros(len(delta), dtype=bool) if row['threshold'] is None else cache[key] > row['threshold']
            if 'fidelity' in calibration:
                action &= np.asarray(calibration['fidelity'], dtype=bool)
            np.testing.assert_allclose(np.mean(action*delta), row['calibration_value'], atol=1e-13)
        proposals = dict(full=[7], direct_checked=list(range(8)),
                         time_checked=search['results']['time']['proposals'],
                         jci_checked=search['results']['jci']['proposals'],
                         jci_unchecked=search['results']['jci']['proposals'])
        for name, choice in view['choices'].items():
            candidates = [row for row in view['calibration_candidates'] if row['model']['mask'] in proposals[name]
                          and (not name.endswith('_checked') or data['qualification'][str(row['model']['mask'])]['status'] == 'qualified')]
            if not candidates:
                assert choice['status'] == 'no_qualified_sharing_set' and choice['model'] is None
            else:
                best = max(candidates, key=lambda row: (row['calibration_value'],
                    2. if row['threshold'] is None else row['threshold'], row['model']['environment_penalty'],
                    row['model']['penalty'], -row['model']['mask'].bit_count(), -row['model']['mask']))
                assert choice['model'] == best['model'] and choice['threshold'] == best['threshold']
    return checked


def independent_value(choice, name, environment, plan):
    values, gains, regrets, actions = [], [], [], []
    p = (.15, .25, .35, .40)[environment]
    for state in itertools.product((0, 1), repeat=3):
        w1, w2, w3 = state
        if name == 'baseline_shift':
            baseline, gamma = .30+.10*w2+.05*environment, .25
        elif name == 'scope_sign':
            baseline, gamma = .50+.04*environment+.05*w3, .30*(2*w2-1)
        elif name == 'effect_shift':
            baseline, gamma = .45+.04*w3+.02*environment, .30-.15*environment
        else:
            baseline = .45+.05*w3+.02*environment
            q = (.95, .75, .55, .15)[environment]
            gamma = .25*(2*q-1)*(2*w2-1)
        tau = .8*(1-2*w1)*gamma
        if name == 'proxy_shift':
            posterior = q if w2 else 1-q
            tau = (1-2*w1)*.25*(.95*posterior-.65*(1-posterior))
        action = 0
        if choice['model'] is not None and choice['threshold'] is not None:
            model = choice['model']
            design = independent_design([state], [environment], model['mask'], model['environments'])
            action = int((design@np.asarray([model['intercept'], *model['coefficients']])).item() > choice['threshold'])
        weight = (p if w1 else 1-p)/4
        gain = action*tau
        values.append(weight*(baseline+w1*gamma+gain))
        gains.append(weight*gain)
        regrets.append(weight*(max(tau, 0)-gain))
        actions.append(action)
    return dict(value=sum(values), gain=sum(gains), regret=sum(regrets), actions=actions)


def verify_recalibration(original, revised, plan):
    calibration = original['calibration']
    for name, view in revised['views'].items():
        source = original['views'][name]
        assert len(view['calibration_candidates']) == len(source['calibration_candidates'])
        predictions = {}
        for saved, old in zip(view['calibration_candidates'], source['calibration_candidates'], strict=True):
            assert saved['model'] == old['model'] and saved['threshold'] == old['threshold']
            model = saved['model']
            key = model['mask'], model['penalty'], model['environment_penalty']
            if key not in predictions:
                design = independent_design(calibration['w'], [-1]*len(calibration['w']), model['mask'], model['environments'])
                predictions[key] = design@np.asarray([model['intercept'], *model['coefficients']])
            actions = np.zeros(len(calibration['w']), dtype=bool) if saved['threshold'] is None else predictions[key] > saved['threshold']
            actions &= np.asarray(calibration['fidelity'], dtype=bool)
            np.testing.assert_allclose(np.mean(actions*np.asarray(calibration['delta'])), saved['calibration_value'], atol=1e-13)
        proposals = dict(full=[7], direct_checked=list(range(8)),
                         time_checked=source['structure']['results']['time']['proposals'],
                         jci_checked=source['structure']['results']['jci']['proposals'],
                         jci_unchecked=source['structure']['results']['jci']['proposals'])
        for method, choice in view['choices'].items():
            eligible = [row for row in view['calibration_candidates'] if row['model']['mask'] in proposals[method] and (
                not method.endswith('_checked') or row['model']['mask'] == 7 or
                original['qualification'][str(row['model']['mask'])]['status'] == 'qualified')]
            reference = max(eligible, key=lambda row: (row['calibration_value'],
                2. if row['threshold'] is None else row['threshold'], row['model']['environment_penalty'],
                row['model']['penalty'], -row['model']['mask'].bit_count(), -row['model']['mask']))
            assert choice['model'] == reference['model'] and choice['threshold'] == reference['threshold']
            assert choice['sharing_qualified'] == (original['qualification'][str(choice['model']['mask'])]['status'] == 'qualified')
            for e in range(4):
                values = independent_value(choice, original['mechanism'], e, plan)
                for field in ('gain', 'value', 'regret'):
                    np.testing.assert_allclose(values[field], view['values'][method][str(e)][field], atol=1e-12)


def verify_jci_sharing(output: Path):
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs'/'plan.json')
    identity = read_json(output/'inputs'/'identity.json')
    if (output/'analysis-amendment').exists():
        verify_bundle(output/'analysis-amendment')
        amendment = read_json(output/'analysis-amendment'/'result.json')
        assert amendment['original_identity'] == identity
        assert file_sha256(output/'source-initial.zip') == amendment['source_archive_sha256']
        with zipfile.ZipFile(output/'source-initial.zip') as source_archive:
            for path, digest in identity['sources'].items():
                assert hashlib.sha256(source_archive.read(Path(path).as_posix())).hexdigest() == digest
        identity = amendment['analysis_identity']
        with zipfile.ZipFile(output/'source-after-analysis.zip') as source_archive:
            for path, digest in identity['sources'].items():
                assert hashlib.sha256(source_archive.read(Path(path).as_posix())).hexdigest() == digest
    else:
        for path, digest in identity['sources'].items():
            if file_sha256(Path(path)) != digest:
                raise ValueError('当前实现与运行冻结身份不同')
    cells, fits, queries, revisions = [], 0, 0, 0
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        data = read_json(root/'result.json')
        assert set(data['training']['task_ids']).isdisjoint(data['calibration']['task_ids'])
        for stage in ('training', 'calibration'):
            outcomes = np.asarray(data[stage]['outcomes'])
            expected = outcomes[:, 1].mean(1)-outcomes[:, 0].mean(1)
            np.testing.assert_array_equal(expected, data[stage]['delta'])
            same = np.asarray(data[stage]['fidelity']) == 0
            np.testing.assert_array_equal(expected[same], 0.)
        fits += verify_choices(data, plan)
        for view in data['views'].values():
            for query in view['structure']['queries']:
                statistic = 0.
                for raw in query['tables']:
                    table = np.asarray(raw)
                    if min(table.shape) > 1:
                        expected = np.outer(table.sum(1), table.sum(0))/table.sum()
                        statistic += float(((table-expected)**2/expected).sum())
                np.testing.assert_allclose(statistic, query['statistic'], atol=1e-10)
                assert query['p'] == (1+query['exceedances'])/(1+plan['ci_draws'])
                queries += 1
            for name, choice in view['choices'].items():
                for environment in range(4):
                    reference = independent_value(choice, data['mechanism'], environment, plan)
                    saved = view['values'][name][str(environment)]
                    for field in ('value', 'gain', 'regret'):
                        np.testing.assert_allclose(reference[field], saved[field], atol=1e-12)
                    assert reference['actions'] == saved['actions']
        cells.append(data)
        revised_root = output/'calibration-revision'/'cells'/root.name
        if revised_root.exists():
            verify_bundle(revised_root)
            revised = read_json(revised_root/'result.json')
            assert revised['source_result_sha256'] == file_sha256(root/'result.json')
            verify_recalibration(data, revised, plan)
            revisions += 1
        if len(cells) % 16 == 0:
            print(f'Independent verification: {len(cells)} cells, {fits} fits', flush=True)
    summary_verified = False
    if (output/'summary').exists():
        verify_bundle(output/'summary')
        summary = read_json(output/'summary'/'result.json')
        for group in summary['groups']:
            selected = [row for row in cells if row['mechanism'] == group['mechanism'] and row['n'] == group['n']]
            for comparison in group['comparisons']:
                difference = [row['views'][group['view']]['values']['jci_checked']['3']['gain']-
                              row['views'][group['view']]['values'][comparison['comparator']]['3']['gain'] for row in selected]
                np.testing.assert_allclose(sorted(difference), sorted(comparison['paired_differences']), atol=1e-12)
                se = float(np.std(difference, ddof=1)/np.sqrt(len(difference)))
                radius = t.ppf(1-.05/(2*summary['family_size']), len(difference)-1)*se
                np.testing.assert_allclose([np.mean(difference)-radius, np.mean(difference)+radius],
                                           comparison['simultaneous_interval'], atol=1e-12)
        summary_verified = True
    historical_verified = False
    if (output/'historical').exists():
        verify_bundle(output/'historical')
        historical = read_json(output/'historical'/'result.json')
        for root, digest in historical['source_hashes'].items():
            verify_bundle(Path(root))
            assert file_sha256(Path(root)/'manifest.json') == digest
        original_cases = read_json(Path(plan['historical_report'])/'cases.json')
        original_conditions = {case['task_unit_id']: {row['condition']: row for row in case['conditions'] if row['flow'] == 'TSG'}
                               for case in original_cases}
        for policy in historical['policies'].values():
            fits += verify_choices(policy, plan)
            for stage in ('training', 'calibration'):
                for request, outcome, status in zip(policy[stage]['structural_request_ids'], policy[stage]['y'], policy[stage]['generation_statuses'], strict=True):
                    root = Path('results/controlled-semantic-20260930/training')/request/'result'
                    verify_bundle(root)
                    terminal = read_json(root/'result.json')
                    assert terminal['secure_yield'] == outcome and terminal['status'] == status
            for view in policy['views'].values():
                for prediction in view['predictions'].values():
                    assert all(value == 0 for value, identical in zip(prediction['predictions'], policy['test_identity_zero'], strict=True) if identical)
        for view in historical['panels'].values():
            for panel in view.values():
                assert len(panel['assignments']) == panel['tasks'] == 400
                for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                    np.testing.assert_allclose(np.mean([row[field] for row in panel['assignments']]), panel[field], atol=1e-12)
                for row in panel['assignments']:
                    source = original_conditions[row['task_unit_id']]
                    np.testing.assert_allclose(source[row['action']]['mean']-source['B']['mean'], row['secure_gain'], atol=1e-12)
        historical_verified = True
    result = dict(status='verified', cells=len(cells), independently_refitted_models=fits,
                  independently_checked_ci_queries=queries, summary_verified=summary_verified,
                  historical_verified=historical_verified, independently_verified_calibration_revisions=revisions,
                  verifier_sha256=file_sha256(Path(__file__)))
    if not (output/'verification').exists():
        write_bundle(output/'verification', {'result.json': result})
    return result

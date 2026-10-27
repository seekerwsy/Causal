from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import zipfile

import numpy as np
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


def independent_features(data, family):
    source = np.asarray(data['w'])
    n, width = source.shape
    if 'effects' in data:
        return np.asarray(data['features']) if family == 'full' else np.broadcast_to(np.eye(width), (n, width, width)).copy()
    columns_per_policy = 1 if family == 'target_factorized' else width
    result = np.zeros((n, width, columns_per_policy*width))
    for policy in range(width):
        start = policy*columns_per_policy
        result[:, policy, start] = 1-source[:, policy]
        if family == 'full':
            offset = 1
            for attribute in range(width):
                if attribute != policy:
                    result[:, policy, start+offset] = (1-source[:, policy])*source[:, attribute]
                    offset += 1
    return result


def independent_baseline(source):
    source = np.asarray(source)
    columns = []
    for mask in range(1, 2**source.shape[1]):
        value = np.ones(len(source))
        for attribute in range(source.shape[1]):
            if mask & (1 << attribute):
                value *= 2*source[:, attribute]-1
        columns.append(value)
    return np.column_stack(columns)


def independent_fit(training, family, penalty, indexes):
    indexes = np.asarray(indexes)
    features = independent_features(training, family)[indexes]
    if 'effects' in training:
        design = features.reshape(-1, features.shape[-1])
        target = np.asarray(training['effects'])[indexes].reshape(-1)
    else:
        assignment = np.asarray(training['a'])[indexes]
        chosen = np.zeros((len(indexes), features.shape[-1]))
        for row, arm in enumerate(assignment):
            if arm:
                chosen[row] = features[row, int(arm)-1]
        design = np.column_stack((independent_baseline(np.asarray(training['w'])[indexes]), chosen))
        target = np.asarray(training['y'])[indexes]
    design = np.column_stack((np.ones(len(design)), design))
    gram = design.T@design/len(design)+np.diag(np.r_[0., np.full(design.shape[1]-1, penalty)])
    right = design.T@target/len(design)
    eigenvalues, eigenvectors = np.linalg.eigh(gram)
    if eigenvalues.min() <= 0:
        raise ValueError('独立核验的正则化设计无效')
    return eigenvectors@((eigenvectors.T@right)/eigenvalues)


def independent_prediction(coefficients, data, family, paired):
    features = independent_features(data, family)
    prediction = features@(coefficients[1:] if paired else coefficients[-features.shape[-1]:])
    if paired:
        prediction += coefficients[0]
    prediction = np.clip(prediction, -1., 1.)
    prediction[np.asarray(data['identity_zero'], dtype=bool)] = 0.
    return prediction


def independent_actions(scores):
    return np.asarray([max(range(len(row)+1), key=lambda arm: 0. if arm == 0 else row[arm-1]) for row in scores])


def independent_calibration(calibration, scores, nuisance):
    actions = independent_actions(scores)
    if 'effects' in calibration:
        values = [0. if arm == 0 else calibration['effects'][index][arm-1] for index, arm in enumerate(actions)]
    else:
        values = []
        probability = 1/(scores.shape[1]+1)
        for index, action in enumerate(actions):
            actual = calibration['a'][index]
            residual = calibration['y'][index]-nuisance[index, actual]
            weight = ((1. if actual == action else 0.)-(1. if actual == 0 else 0.))/probability
            values.append(nuisance[index, action]-nuisance[index, 0]+weight*residual)
    return float(np.mean(values)), actions


def independent_value(scores, beta, plan):
    actions = independent_actions(scores)
    states = list(itertools.product((0, 1), repeat=len(beta)))
    gain, value, regret = 0., 0., 0.
    for index, state in enumerate(states):
        effects = [(1-state[policy])*coefficient for policy, coefficient in enumerate(beta)]
        selected = 0. if actions[index] == 0 else effects[int(actions[index])-1]
        for latent in (0, 1):
            p = plan['simulation']['source_probability_by_latent'][latent]
            weight = .5*p**sum(state)*(1-p)**(len(state)-sum(state))
            baseline = plan['simulation']['baseline_probability']+plan['simulation']['latent_outcome_coefficient']*latent
            baseline += sum(coefficient*state[policy] for policy, coefficient in enumerate(beta))
            gain += weight*selected
            value += weight*(baseline+selected)
            regret += weight*(max(0., *effects)-selected)
    return dict(gain=gain, value=value, regret=regret, actions=actions.tolist())


def verify_learning(training, calibration, evaluation, learned, plan):
    if len(set(training['task_ids'])) != len(training['task_ids']) or set(training['task_ids']) & set(calibration['task_ids']):
        raise ValueError('训练与校准的独立任务身份不同')
    width = np.asarray(training['w']).shape[1]
    indexes_by_id = {identity: index for index, identity in enumerate(training['task_ids'])}
    graphs = learned['graphs']
    if graphs[0]['task_ids'] != training['task_ids'] or len(graphs) != 1+plan['subsamples']:
        raise ValueError('完整图和任务子样本数量不同')
    samples = [np.asarray([indexes_by_id[identity] for identity in graph['task_ids']]) for graph in graphs]
    query_count = 0
    for sample_index, (graph, indexes) in enumerate(zip(graphs, samples, strict=True)):
        assert len(set(indexes)) == len(indexes)
        if sample_index:
            assert len(indexes) == int(len(training['task_ids'])*plan['subsample_fraction'])
        values = np.column_stack((np.asarray(training['a'])[indexes, None] == np.arange(1, width+1),
                                  np.asarray(training['x'])[indexes], np.asarray(training['y'])[indexes])).astype(int)
        coordinates = {label: index for index, label in enumerate(graph['labels'])}
        for name, result in graph['results'].items():
            ancestry = np.asarray(result['ancestry'])
            assert ancestry.shape == (2*width+1, 2*width+1)
            assert set(result['context_ancestry']) == {f'C{index+1}' for index in range(width)}
            np.testing.assert_array_equal(ancestry[:width, -1], [result['context_ancestry'][f'C{index+1}'] for index in range(width)])
            if name == 'jci123':
                np.testing.assert_array_equal(np.asarray(result['pag'])[:width, :width], 2*(1-np.eye(width)))
        for query in graph['queries']:
            if plan.get('direct_context_queries', False):
                columns = [coordinates[label] for label in query['conditioned']]
                groups = {}
                for row in values:
                    groups.setdefault(tuple(row[columns]), []).append(row)
                expected_tables = []
                for key in sorted(groups):
                    rows = np.asarray(groups[key])
                    left, right = rows[:, coordinates[query['x']]], rows[:, coordinates[query['y']]]
                    left_states, right_states = sorted(set(left)), sorted(set(right))
                    expected_tables.append([[int(np.count_nonzero((left == a) & (right == b)))
                                             for b in right_states] for a in left_states])
                assert expected_tables == query['tables']
            statistic = 0.
            for raw in query['tables']:
                table = np.asarray(raw)
                if min(table.shape) > 1:
                    expected = np.outer(table.sum(1), table.sum(0))/table.sum()
                    statistic += float(np.sum((table-expected)**2/expected))
            np.testing.assert_allclose(statistic, query['statistic'], atol=1e-10)
            assert query['p'] == (1+query['exceedances'])/(1+plan['ci_draws'])
            query_count += 1
    supports = {name: np.mean([np.asarray(graph['results'][name]['ancestry'])[:width, -1] == -1 for graph in graphs[1:]], axis=0)
                for name in plan['structural_methods']}
    if plan.get('direct_context_queries', False):
        for graph in graphs:
            by_query = {(row['x'], row['y'], tuple(row['conditioned'])): row['p'] for row in graph['queries']}
            for policy in range(width):
                label = f'C{policy+1}'
                other = tuple(f'C{index+1}' for index in range(width) if index != policy)
                assert graph['direct_context_p'][label] == by_query[(label, 'Y', other)]
        supports['direct_ci'] = np.asarray([
            sum(graph['direct_context_p'][f'C{policy+1}'] >= plan['ci_alpha'] for graph in graphs[1:])/plan['subsamples']
            for policy in range(width)])
    if plan.get('adjacency_ablation', False):
        supports['jci123_adjacency'] = np.asarray([
            sum(graph['results']['jci123']['pag'][policy][-1] == 0 for graph in graphs[1:])/plan['subsamples']
            for policy in range(width)])
    for name in supports:
        np.testing.assert_array_equal(supports[name], learned['nonancestry_support'][name])
    paired = 'effects' in training
    cache, fits = {}, 0
    def coefficients(family, penalty, sample_index=0):
        nonlocal fits
        key = family, penalty, sample_index
        if key not in cache:
            cache[key] = independent_fit(training, family, penalty, samples[sample_index])
            fits += 1
        return cache[key]
    nuisance = None
    if not paired:
        model = learned['nuisance_model']
        coefficient = coefficients('full', plan['simulation_nuisance_penalty'])
        np.testing.assert_allclose(coefficient, [model['intercept'], *model['coefficients']], atol=2e-10, rtol=2e-9)
        features = independent_features(calibration, 'full')
        baseline = independent_baseline(calibration['w'])@coefficient[1:-features.shape[-1]]+coefficient[0]
        nuisance = np.column_stack((baseline, baseline[:, None]+independent_prediction(coefficient, calibration, 'full', False)))
    def scores_for(model, destination, origin, strength):
        if model is None:
            return np.zeros((len(destination['task_ids']), width))
        family, penalty = model['family'], model['penalty']
        coefficient = coefficients(family, penalty)
        np.testing.assert_allclose(coefficient, [model['intercept'], *model['coefficients']], atol=2e-10, rtol=2e-9)
        prediction = independent_prediction(coefficient, destination, family, paired)
        if origin in ('direct_gate', 'direct_lcb'):
            boot = np.asarray([independent_prediction(coefficients(family, penalty, index), destination, family, paired)
                               for index in range(1, len(samples))])
            prediction = (prediction*(1-strength*np.mean(boot <= 0, axis=0)) if origin == 'direct_gate'
                          else prediction-strength*np.std(boot, ddof=1, axis=0))
        elif origin in supports:
            prediction *= 1-strength*supports[origin]
        prediction[np.asarray(destination['identity_zero'], dtype=bool)] = 0.
        return prediction
    for name, candidates in learned['candidates'].items():
        if name == 'direct_envelope':
            direct = learned['candidates']['full']+learned['candidates']['direct_gate']+learned['candidates']['direct_lcb']
            if 'direct_ci' in learned['candidates']:
                direct += learned['candidates']['direct_ci']
            assert candidates == direct
            continue
        for candidate in candidates:
            scores = scores_for(candidate['model'], calibration, name, candidate['strength'])
            gain, actions = independent_calibration(calibration, scores, nuisance)
            np.testing.assert_allclose(gain, candidate['calibration_gain'], atol=1e-11)
            np.testing.assert_array_equal(actions, candidate['calibration_actions'])
    for name, choice in learned['choices'].items():
        candidates = learned['candidates'][name]
        best = max(enumerate(candidates), key=lambda item: (item[1]['calibration_gain'], -item[0]))[1]
        assert {key: choice[key] for key in best} == best
        scores = scores_for(choice['model'], evaluation, choice['origin'], choice['strength'])
        np.testing.assert_allclose(scores, learned['outputs'][name]['scores'], atol=1e-10)
        np.testing.assert_array_equal(independent_actions(scores), learned['outputs'][name]['actions'])
    return fits, query_count


def verify_joint_policy(output):
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs'/'plan.json')
    identity = read_json(output/'inputs'/'identity.json')
    if plan.get('budget_replay', False):
        from prompt_mechanism_study.verification.jci_replay import verify_budget_replay

        return verify_budget_replay(output)
    for source, digest in identity['sources'].items():
        assert file_sha256(Path(source)) == digest
    if 'exposed_split_seeds' in plan:
        return verify_exposed_direction(output, plan, identity)
    cells, total_fits, total_queries = [], 0, 0
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        cell = read_json(root/'result.json')
        width = len(cell['beta'])
        states = np.asarray(list(itertools.product((0, 1), repeat=width)))
        evaluation = dict(w=states.tolist(), identity_zero=states.astype(bool).tolist())
        fits, queries = verify_learning(cell['training'], cell['calibration'], evaluation, cell['learned'], plan)
        total_fits += fits
        total_queries += queries
        for name, result in cell['values'].items():
            reference = independent_value(cell['learned']['outputs'][name]['scores'], cell['beta'], plan)
            np.testing.assert_allclose([result[field] for field in ('gain', 'value', 'regret')],
                                       [reference[field] for field in ('gain', 'value', 'regret')], atol=1e-12)
            assert reference['actions'] == result['actions']
        cells.append(cell)
        if len(cells) % 16 == 0:
            print(f'Joint independent verification: {len(cells)} cells, {total_fits} fits', flush=True)
    if (output/'summary').exists():
        verify_bundle(output/'summary')
        summary = read_json(output/'summary'/'result.json')
        for group in summary['groups']:
            selected = [cell for cell in cells if cell['mechanism'] == group['mechanism'] and cell['n'] == group['n']]
            for comparison in group['comparisons']:
                differences = [row['values']['jci123']['gain']-row['values'][comparison['comparator']]['gain'] for row in selected]
                np.testing.assert_allclose(sorted(differences), sorted(comparison['paired_differences']), atol=1e-12)
                radius = t.ppf(1-.05/(2*summary['family_size']), len(selected)-1)*np.std(differences, ddof=1)/np.sqrt(len(selected))
                np.testing.assert_allclose([np.mean(differences)-radius, np.mean(differences)+radius], comparison['simultaneous_interval'], atol=1e-12)
    historical_verified = False
    if (output/'historical').exists():
        verify_bundle(output/'historical')
        history = read_json(output/'historical'/'result.json')
        fits, queries = verify_learning(history['training'], history['calibration'], history['evaluation'], history['learned'], plan)
        total_fits += fits
        total_queries += queries
        for source, digest in history['source_hashes'].items():
            verify_bundle(Path(source))
            assert file_sha256(Path(source)/'manifest.json') == digest
        for stage in ('training', 'calibration'):
            for request, outcome, status in zip(history[stage]['request_ids'], history[stage]['y'], history[stage]['statuses'], strict=True):
                terminal = Path('results/controlled-semantic-20260930/training')/request/'result'
                verify_bundle(terminal)
                record = read_json(terminal/'result.json')
                assert record['secure_yield'] == outcome and record['status'] == status
        for name, panel in history['panels'].items():
            assert len(panel['assignments']) == panel['tasks'] == 400
            for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                np.testing.assert_allclose(np.mean([row[field] for row in panel['assignments']]), panel[field], atol=1e-12)
            scores = np.asarray(history['learned']['outputs'][name]['scores'])
            gain, actions = independent_calibration(history['evaluation'], scores, None)
            np.testing.assert_allclose(gain, panel['secure_gain'], atol=1e-12)
            assert actions.tolist() == [row['action'] for row in panel['assignments']]
        historical_verified = True
    expected = len(plan['simulation']['mechanisms'])*len(plan['simulation']['tasks_per_role'])*plan['simulation']['repetitions']
    complete = len(cells) == expected and (output/'summary').exists() and historical_verified
    result = dict(status='verified' if complete else 'partial_checked', cells=len(cells),
        independently_refitted_models=total_fits, independently_checked_ci_queries=total_queries,
        historical_verified=historical_verified, verifier_sha256=file_sha256(Path(__file__)))
    if complete and not (output/'verification').exists():
        write_bundle(output/'verification', {'result.json': result})
    return result


def verify_exposed_direction(output, plan, identity):
    with zipfile.ZipFile(output/'source.zip') as archive:
        for source, digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(Path(source).as_posix())).hexdigest() == digest
    records, fits, queries = [], 0, 0
    requests_by_task = None
    baseline_evaluation = None
    original_tasks = read_json(Path(plan['historical_inputs'])/'tasks.json')
    by_task = {row['task_unit_id']: row for row in original_tasks}
    original_effects = {(row['task_unit_id'], row['policy']): row['actual_edit_minus_baseline']
                        for row in read_json(Path(plan['historical_analysis'])/'training-effects.json')}
    original_cases = {row['task_unit_id']: row for row in read_json(Path(plan['historical_report'])/'cases.json')}
    original_requests = {row['request_id']: row for row in read_json(Path(plan['historical_inputs'])/'training-requests.json')}
    policies = ('local', 'example', 'reference')
    terminal_records = {}
    verified_sources = {}
    for seed in plan['exposed_split_seeds']:
        root = output/'splits'/str(seed)
        if not root.exists():
            continue
        verify_bundle(root)
        record = read_json(root/'result.json')
        assert record['split_seed'] == seed
        training, calibration, evaluation = (record[key] for key in ('training', 'calibration', 'evaluation'))
        assert len(training['task_ids']) == len(calibration['task_ids']) == 200
        assert len(evaluation['task_ids']) == len(set(evaluation['task_ids'])) == 400
        assert set(training['task_ids']).isdisjoint(evaluation['task_ids'])
        assert set(calibration['task_ids']).isdisjoint(evaluation['task_ids'])
        expected_training = set()
        for family in ('find', 'grep', 'tar', 'git'):
            ordered = sorted((row['task_unit_id'] for row in original_tasks if row['role'] == 'training' and row['family'] == family),
                             key=lambda task: hashlib.sha256(f'{seed}/{task}'.encode()).hexdigest())
            expected_training.update(ordered[:50])
        assert set(training['task_ids']) == expected_training
        current_requests = {}
        for stage in (training, calibration):
            for index, (task, request, outcome, status) in enumerate(zip(stage['task_ids'], stage['request_ids'], stage['y'], stage['statuses'], strict=True)):
                current_requests[task] = request
                terminal = Path('results/controlled-semantic-20260930/training')/request/'result'
                if request not in terminal_records:
                    verify_bundle(terminal)
                    terminal_records[request] = read_json(terminal/'result.json')
                saved = terminal_records[request]
                assert saved['task_unit_id'] == task and saved['secure_yield'] == outcome and saved['status'] == status
                source = by_task[task]
                assert stage['w'][index] == source['initial_states']
                rng = np.random.default_rng(int.from_bytes(hashlib.sha256(json.dumps([plan['seed'], 'historical', task]).encode()).digest()[:8], 'big'))
                assert stage['a'][index] == int(rng.integers(0, 4))
                version = int(rng.integers(1, 3))
                condition = 'B' if stage['a'][index] == 0 else policies[stage['a'][index]-1]
                request_source = original_requests[request]
                assert request_source['task_unit_id'] == task and request_source['actual_states'] == stage['x'][index]
                assert any(member['flow'] == 'TSG' and member['condition'] == condition and member['version'] == version
                           for member in request_source['members'])
                for policy_index, policy in enumerate(policies):
                    same = all(source['conditions']['TSG'][str(version)][policy]['prompt_hash'] ==
                               source['conditions']['TSG'][str(version)]['B']['prompt_hash'] for version in (1, 2))
                    assert stage['identity_zero'][index][policy_index] == same
                    expected = 0. if same else original_effects[(task, policy)]
                    np.testing.assert_allclose(stage['effects'][index][policy_index], expected, atol=1e-12)
        if requests_by_task is None:
            requests_by_task, baseline_evaluation = current_requests, evaluation
        assert current_requests == requests_by_task and evaluation == baseline_evaluation
        for index, task in enumerate(evaluation['task_ids']):
            conditions = {row['condition']: row for row in original_cases[task]['conditions'] if row['flow'] == 'TSG'}
            for policy_index, policy in enumerate(policies):
                np.testing.assert_allclose(evaluation['effects'][index][policy_index],
                    conditions[policy]['mean']-conditions['B']['mean'], atol=1e-12)
                for field, counter in (('finite_function_effects', 'finite_functionality_pass'), ('support_effects', 'oracle_supported')):
                    values = [np.mean([version[counter]/version['assigned'] for version in conditions[name]['versions']])
                              for name in (policy, 'B')]
                    np.testing.assert_allclose(evaluation[field][index][policy_index], values[0]-values[1], atol=1e-12)
        for source, digest in record['source_hashes'].items():
            if source not in verified_sources:
                verify_bundle(Path(source))
                verified_sources[source] = file_sha256(Path(source)/'manifest.json')
            assert verified_sources[source] == digest
        count, checks = verify_learning(training, calibration, evaluation, record['learned'], plan)
        fits += count
        queries += checks
        for name, panel in record['panels'].items():
            actions = independent_actions(np.asarray(record['learned']['outputs'][name]['scores']))
            assert len(panel['assignments']) == panel['tasks'] == 400
            assert panel['edits'] == int(np.count_nonzero(actions))
            assert actions.tolist() == [row['action'] for row in panel['assignments']]
            assert evaluation['task_ids'] == [row['task_unit_id'] for row in panel['assignments']]
            for field, source in (('secure_gain', 'effects'), ('finite_function_gain', 'finite_function_effects'), ('support_gain', 'support_effects')):
                values = np.asarray([0. if action == 0 else evaluation[source][index][action-1]
                                     for index, action in enumerate(actions)])
                np.testing.assert_allclose(values, [row[field] for row in panel['assignments']], atol=1e-12)
                np.testing.assert_allclose(values.mean(), panel[field], atol=1e-12)
        records.append(record)
    complete = len(records) == len(plan['exposed_split_seeds'])
    if complete:
        verify_bundle(output/'summary')
        summary = read_json(output/'summary'/'result.json')
        task_ids = records[0]['evaluation']['task_ids']
        assert summary['evaluation_task_ids'] == task_ids
        task_family = {row['task_unit_id']: row['family'] for row in original_tasks}
        family_values = [task_family[task] for task in task_ids]
        assert summary['evaluation_families'] == family_values
        rng = np.random.default_rng(plan['bootstrap_seed'])
        indexes = np.concatenate([rng.choice([index for index, value in enumerate(family_values) if value == family],
            (plan['bootstrap_draws'], family_values.count(family)), replace=True) for family in sorted(set(family_values))], axis=1)
        mean_by_method = {}
        for name, values in summary['method_values'].items():
            mean_by_method[name] = {}
            assert values['tasks'] == 400 and values['splits'] == len(records)
            for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                averaged = np.asarray([[row[field] for row in record['panels'][name]['assignments']] for record in records]).mean(0)
                mean_by_method[name][field] = averaged
                np.testing.assert_allclose(averaged, summary['task_values'][name][field], atol=1e-12)
                np.testing.assert_allclose(averaged.mean(), values[field], atol=1e-12)
        for comparison in summary['primary_comparisons']:
            differences = mean_by_method[plan['primary_method']]['secure_gain']-mean_by_method[comparison['comparator']]['secure_gain']
            np.testing.assert_allclose(differences, comparison['task_differences'], atol=1e-12)
            np.testing.assert_allclose(differences.mean(), comparison['difference'], atol=1e-12)
            quantiles = [plan['alpha']/(2*len(plan['primary_comparators'])), 1-plan['alpha']/(2*len(plan['primary_comparators']))]
            np.testing.assert_allclose(np.quantile(differences[indexes].mean(1), quantiles),
                                       comparison['simultaneous_descriptive_interval'], atol=1e-12)
        for record, diagnostic in zip(records, summary['graph_diagnostics'], strict=True):
            for name in ('direct_gate', 'direct_ci', 'time', 'jci12', 'jci123', 'jci123_adjacency'):
                assert len(record['learned']['candidates'][name]) == diagnostic['candidate_counts'][name] == 51
            graphs = record['learned']['graphs']
            assert diagnostic['different_jci_time_pags'] == sum(graph['results']['time']['pag'] != graph['results']['jci123']['pag'] for graph in graphs)
            assert diagnostic['different_jci_time_ancestry'] == sum(graph['results']['time']['context_ancestry'] != graph['results']['jci123']['context_ancestry'] for graph in graphs)
            assert diagnostic['direction_ablation_action_differences'] == int(np.count_nonzero(
                np.asarray(record['learned']['outputs']['jci123']['actions']) != np.asarray(record['learned']['outputs']['jci123_adjacency']['actions'])))
    result = dict(status='verified' if complete else 'partial_checked', splits=len(records),
        independently_refitted_models=fits, independently_checked_ci_queries=queries,
        original_terminal_requests_checked=len(requests_by_task or {}), new_model_requests=0,
        verifier_sha256=file_sha256(Path(__file__)))
    if complete and not (output/'verification').exists():
        write_bundle(output/'verification', {'result.json': result})
    return result

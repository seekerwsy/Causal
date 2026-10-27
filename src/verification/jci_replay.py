from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import zipfile

import numpy as np

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


def independent_features(task, arm, prepared, prompt_hash, version, plan):
    effective = 0 if prompt_hash == task['conditions']['TSG'][str(version)]['B']['prompt_hash'] else arm
    initial = list(task['initial_states'])
    family = [int(task['family'] == value) for value in plan['families']]
    context = [int(effective == value) for value in range(1, 5)]
    return np.asarray(initial+family+list(prepared)+context+
        [a*b for a in context for b in initial]+[a*b for a in context for b in family], dtype=float)


def independent_counterfactual(task, arm, plan):
    result = []
    for version in (1, 2):
        condition = task['conditions']['TSG'][str(version)][plan['contexts'][arm]]
        result.append(independent_features(task, arm, condition['states'], condition['prompt_hash'], version, plan))
    return np.asarray(result)


def independent_model(design, target, weights, penalty):
    augmented = np.column_stack((np.ones(len(design)), design))
    normalized = weights/weights.sum()
    gram = augmented.T@(normalized[:, None]*augmented)+np.diag(np.r_[0., np.full(design.shape[1], penalty)])
    right = augmented.T@(normalized*target)
    values, vectors = np.linalg.eigh(gram)
    if values.min() <= 0:
        raise ValueError('独立重算的正则化设计无效')
    return vectors@((vectors.T@right)/values)


def independent_predict(coefficient, design):
    return np.clip(np.asarray(design)@coefficient[1:]+coefficient[0], 0., 1.)


def verify_replay_cell(cell, tasks, candidates, plan):
    rows = cell['observations']
    learned = cell['learned']
    identities = sorted({row['task_unit_id'] for row in rows})
    assert identities == learned['task_ids']
    index_by_id = {identity: index for index, identity in enumerate(identities)}
    units = np.asarray([index_by_id[row['task_unit_id']] for row in rows])
    counts = np.bincount(units, minlength=len(identities))
    np.testing.assert_array_equal(units, learned['request_task_indexes'])
    np.testing.assert_array_equal(counts, learned['request_counts'])
    folds = np.empty(len(identities), dtype=int)
    for family in plan['families']:
        selected = [index for index, identity in enumerate(identities) if tasks[identity]['family'] == family]
        selected.sort(key=lambda index: hashlib.sha256(f'{plan["fold_seed"]}/{identities[index]}'.encode()).hexdigest())
        for offset, index in enumerate(selected):
            folds[index] = offset%plan['folds']
    np.testing.assert_array_equal(folds, learned['task_folds'])
    design = np.asarray([independent_features(tasks[row['task_unit_id']], row['arm'], row['prepared'],
                         row['prompt_hash'], row['version'], plan) for row in rows])
    outcomes = np.asarray([row['y'] for row in rows])
    weights = 1/counts[units]
    losses, models, all_predictions = [], [], []
    for penalty in plan['ridge_penalties']:
        coefficients, predictions = [], np.empty(len(rows))
        for fold in range(plan['folds']):
            train = folds[units] != fold
            coefficient = independent_model(design[train], outcomes[train], weights[train], penalty)
            predictions[~train] = independent_predict(coefficient, design[~train])
            coefficients.append(coefficient)
        losses.append(float(weights@((outcomes-predictions)**2)/len(identities)))
        models.append(coefficients)
        all_predictions.append(predictions)
    np.testing.assert_allclose(losses, learned['losses'], atol=2e-10)
    chosen = min(range(len(losses)), key=lambda index: (losses[index], index))
    assert plan['ridge_penalties'][chosen] == learned['selected_penalty']
    coefficients = models[chosen]
    for saved, coefficient in zip(learned['models'], coefficients, strict=True):
        np.testing.assert_allclose(coefficient, [saved['intercept'], *saved['coefficients']], atol=3e-9)
    predictions = all_predictions[chosen]
    np.testing.assert_allclose(predictions, learned['observed_predictions'], atol=2e-10)
    means = np.asarray([[float(np.mean(independent_predict(coefficients[folds[index]], independent_counterfactual(tasks[identity], arm, plan))))
                         for arm in range(4)] for index, identity in enumerate(identities)])
    scores = means[:, 1:]-means[:, :1]
    for index, row in enumerate(rows):
        for policy in range(3):
            factor = float(row['arm'] == policy+1)-float(row['arm'] == 0)
            scores[units[index], policy] += factor*(row['y']-predictions[index])/(plan['propensity']*counts[units[index]])
    for index, identity in enumerate(identities):
        for policy, name in enumerate(plan['policies']):
            source = tasks[identity]['conditions']['TSG']
            if all(source[version][name]['prompt_hash'] == source[version]['B']['prompt_hash'] for version in ('1', '2')):
                scores[index, policy] = 0.
    np.testing.assert_allclose(means, learned['counterfactual_predictions'], atol=2e-10)
    np.testing.assert_allclose(scores, learned['task_scores'], atol=2e-9)
    estimates = {}
    population = [task for task in tasks.values() if task['role'] == 'training']
    for candidate, saved in zip(candidates, learned['estimates'], strict=True):
        policy, state = candidate['policy_index'], candidate['initial_state']
        selected = [index for index, identity in enumerate(identities) if tasks[identity]['family'] == candidate['family'] and tasks[identity]['initial_states'][policy] == state]
        matched = {identities[index] for index in selected}
        support = [len({row['task_unit_id'] for row in rows if row['task_unit_id'] in matched and row['arm'] == arm}) for arm in (0, policy+1)]
        evaluable = min(support) >= plan['minimum_distinct_tasks_per_comparison_arm'] and len(selected) >= 2
        coverage = sum(task['family'] == candidate['family'] and task['initial_states'][policy] == state for task in population)/400
        assert saved['candidate_id'] == candidate['candidate_id'] and saved['arm_task_support'] == support
        assert saved['evaluable'] == evaluable and saved['tasks'] == len(selected) and saved['coverage'] == coverage
        gain = float(scores[selected, policy].mean()) if evaluable else None
        standard_error = float(scores[selected, policy].std(ddof=1)/np.sqrt(len(selected))) if evaluable else None
        if evaluable:
            np.testing.assert_allclose([gain, standard_error, gain*coverage], [saved['gain'], saved['standard_error'], saved['score']], atol=2e-9)
        else:
            assert saved['gain'] is saved['standard_error'] is saved['score'] is None
        estimates[candidate['candidate_id']] = (gain, standard_error, coverage)
    query_count = 0
    for family, result in cell['graphs'].items():
        first = {}
        for row in rows:
            if row['family'] == family:
                first.setdefault(row['task_unit_id'], row)
        expected = list(first.values())
        assert result['request_ids'] == [row['request_id'] for row in expected]
        assert result['task_ids'] == [row['task_unit_id'] for row in expected]
        values = np.asarray([[*[int(row['arm'] == arm) for arm in range(1, 5)], *row['prepared'], row['y']] for row in expected])
        coordinates = {label: index for index, label in enumerate(result['labels'])}
        for graph in result['graphs'].values():
            assert np.asarray(graph['ancestry']).shape == (8, 8) and graph['conservative'] is True
        for query in result['queries']:
            groups = {}
            for row in values:
                groups.setdefault(tuple(row[[coordinates[label] for label in query['conditioned']]]), []).append(row)
            tables, statistic = [], 0.
            for key in sorted(groups):
                group = np.asarray(groups[key])
                x, y = group[:, coordinates[query['x']]], group[:, coordinates[query['y']]]
                table = np.asarray([[np.count_nonzero((x == a) & (y == b)) for b in sorted(set(y))] for a in sorted(set(x))])
                tables.append(table.tolist())
                if min(table.shape) > 1:
                    null = np.outer(table.sum(1), table.sum(0))/table.sum()
                    statistic += float(np.sum((table-null)**2/null))
            assert tables == query['tables']
            np.testing.assert_allclose(statistic, query['statistic'], atol=1e-10)
            assert query['p'] == (1+query['exceedances'])/(1+plan['ci_draws'])
            query_count += 1
    order = {candidate['candidate_id']: index for index, candidate in enumerate(candidates)}
    for name, selection in cell['selection'].items():
        ranking = []
        for candidate in candidates:
            key = candidate['candidate_id']
            gain, standard_error, coverage = estimates[key]
            tier, relation = 0, None
            if name in plan['structural_methods']:
                relation = cell['graphs'][candidate['family']]['graphs'][name]['ancestry'][4+candidate['policy_index']][-1]
                tier = int(relation == 1)
            if name == 'jci123_adjacency':
                tier = int(cell['graphs'][candidate['family']]['graphs']['jci123']['pag'][4+candidate['policy_index']][-1] != 0)
            value = None if gain is None else coverage*(gain-standard_error if name == 'direct_lcb' else gain)
            ranking.append(dict(candidate_id=key, tier=tier, ancestry=relation, score=value, eligible=value is not None and value > 0))
        for computed, saved in zip(ranking, selection['ranking'], strict=True):
            assert computed['candidate_id'] == saved['candidate_id'] and computed['tier'] == saved['tier'] and computed['ancestry'] == saved['ancestry']
            assert computed['eligible'] == saved['eligible']
            if computed['score'] is not None:
                np.testing.assert_allclose(computed['score'], saved['score'], atol=2e-9)
        eligible = sorted((row for row in ranking if row['eligible']), key=lambda row: (-row['tier'], -row['score'], order[row['candidate_id']]))
        slots = [row['candidate_id'] for row in eligible[:plan['selection_slots']]]
        slots += [None]*(plan['selection_slots']-len(slots))
        assert selection['slots'] == slots
    return len(plan['ridge_penalties'])*plan['folds'], query_count


def verify_budget_replay(output):
    verify_bundle(output/'inputs')
    plan, identity, design = [read_json(output/'inputs'/name) for name in ('plan.json', 'identity.json', 'design.json')]
    for source, digest in identity['sources'].items():
        assert file_sha256(Path(source)) == digest
    with zipfile.ZipFile(output/'source.zip') as archive:
        for source, digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(Path(source).as_posix())).hexdigest() == digest
    inputs = Path(plan['inputs'])
    verify_bundle(inputs)
    assert file_sha256(inputs/'manifest.json') == identity['input_manifest_sha256']
    assert file_sha256(Path(plan['evaluation_report'])/'manifest.json') == identity['evaluation_manifest_sha256']
    tasks = {row['task_unit_id']: row for row in read_json(inputs/'tasks.json')}
    requests = read_json(inputs/'training-requests.json')
    by_request = {row['request_id']: row for row in requests}
    mixture = sorted((row for row in requests if row['component'] == 'random_mixture'), key=lambda row: row['independent_event'])
    assert len(design['candidates']) == 24
    assert len(design['discovery_task_ids']) == 400 and len(design['confirmation_task_ids']) == len(design['test_task_ids']) == 200
    assert set(design['confirmation_task_ids']).isdisjoint(design['test_task_ids'])
    assert all(tasks[key]['role'] == 'training' for key in design['discovery_task_ids'])
    for family in plan['families']:
        groups = {}
        for task in tasks.values():
            if task['role'] == 'evaluation' and task['family'] == family:
                groups.setdefault(tuple(task['initial_states']), []).append(task['task_unit_id'])
        counts = {state: len(values)//2 for state, values in groups.items()}
        odd = [state for state, values in groups.items() if len(values)%2]
        odd.sort(key=lambda state: hashlib.sha256(f'{plan["split_seed"]}/{family}/{state}'.encode()).hexdigest())
        for state in odd[:50-sum(counts.values())]:
            counts[state] += 1
        expected = set()
        for state, values in groups.items():
            values.sort(key=lambda key: hashlib.sha256(f'{plan["split_seed"]}/{key}'.encode()).hexdigest())
            expected.update(values[:counts[state]])
        assert expected == {key for key in design['confirmation_task_ids'] if tasks[key]['family'] == family}
    for candidate in design['candidates']:
        eligible = [key for key in design['confirmation_task_ids'] if tasks[key]['family'] == candidate['family'] and tasks[key]['initial_states'][candidate['policy_index']] == candidate['initial_state']]
        eligible.sort(key=lambda key: hashlib.sha256(f'{plan["split_seed"]}/{candidate["candidate_id"]}/{key}'.encode()).hexdigest())
        assert candidate['confirmation_task_ids'] == eligible[:plan['confirmation_tasks_per_candidate']]
    for seed in plan['replay_seeds']:
        digest = hashlib.sha256(json.dumps([seed, 'budget-replay-order']).encode()).digest()
        rng = np.random.default_rng(int.from_bytes(digest[:8], 'big'))
        sequence = [mixture[int(index)]['request_id'] for index in rng.permutation(4000)[:max(plan['discovery_budgets'])]]
        assert sequence == design['schedules'][str(seed)]
    cells, fits, queries, checked_terminals = [], 0, 0, {}
    for seed, budget in itertools.product(plan['replay_seeds'], plan['discovery_budgets']):
        root = output/'cells'/f'{seed}-{budget}'
        if not root.exists():
            continue
        verify_bundle(root)
        cell = read_json(root/'result.json')
        assert cell['seed'] == seed and cell['budget'] == budget and len(cell['observations']) == budget
        assert [row['request_id'] for row in cell['observations']] == design['schedules'][str(seed)][:budget]
        for row in cell['observations']:
            request = by_request[row['request_id']]
            assert request['component'] == 'random_mixture' and request['task_unit_id'] == row['task_unit_id']
            assert (row['arm'], row['version'], row['prepared'], row['prompt_hash']) == (request['context'], request['version'], request['actual_states'], request['prompt_hash'])
            if row['request_id'] not in checked_terminals:
                terminal = Path(plan['training_results'])/row['request_id']/'result'
                verify_bundle(terminal)
                checked_terminals[row['request_id']] = (read_json(terminal/'result.json'), file_sha256(terminal/'manifest.json'))
            saved, digest = checked_terminals[row['request_id']]
            assert saved['secure_yield'] == row['y'] and saved['status'] == row['status'] and digest == row['terminal_manifest_sha256']
        count, checks = verify_replay_cell(cell, tasks, design['candidates'], plan)
        fits += count
        queries += checks
        cells.append(cell)
    complete = len(cells) == len(plan['replay_seeds'])*len(plan['discovery_budgets'])
    if complete:
        verify_confirmation_and_evaluation(output, cells, design, tasks, plan)
    result = dict(status='verified' if complete else 'partial_checked', cells=len(cells),
        independently_refitted_models=fits, independently_checked_ci_queries=queries,
        unique_original_discovery_requests_checked=len(checked_terminals), test_task_units=200,
        new_model_calls=0, verifier_sha256=file_sha256(Path(__file__)))
    if complete and not (output/'verification').exists():
        write_bundle(output/'verification', {'result.json': result})
    return result


def independent_condition(condition):
    result = {'secure_gain': float(condition['mean'])}
    for field, counter in (('finite_function_gain', 'finite_functionality_pass'), ('support_gain', 'oracle_supported')):
        result[field] = sum(version[counter]/version['assigned'] for version in condition['versions'])/len(condition['versions'])
    return result


def verify_confirmation_and_evaluation(output, cells, design, tasks, plan):
    report = Path(plan['evaluation_report'])
    verify_bundle(report)
    cases = {row['task_unit_id']: row for row in read_json(report/'cases.json')}
    requests = read_json(Path(plan['inputs'])/'evaluation-requests.json')
    physical_by_case = {}
    for request in requests:
        for member in request['members']:
            if member['flow'] == 'TSG':
                physical_by_case.setdefault((request['task_unit_id'], member['condition']), set()).add(request['request_id'])
    candidate_by_id = {row['candidate_id']: row for row in design['candidates']}
    candidate_order = {row['candidate_id']: index for index, row in enumerate(design['candidates'])}
    evaluations = []
    for cell in cells:
        name = f'{cell["seed"]}-{cell["budget"]}'
        root = output/'confirmation'/name
        verify_bundle(root)
        confirmation = read_json(root/'result.json')
        selected = {key for value in cell['selection'].values() for key in value['slots'] if key is not None}
        assert set(confirmation['candidates']) == selected
        checked_tasks = set()
        for key, result in confirmation['candidates'].items():
            candidate = candidate_by_id[key]
            assert [row['task_unit_id'] for row in result['assignments']] == candidate['confirmation_task_ids']
            physical = set()
            for assignment in result['assignments']:
                identity = assignment['task_unit_id']
                assert identity in design['confirmation_task_ids'] and identity not in design['test_task_ids']
                checked_tasks.add(identity)
                conditions = {row['condition']: row for row in cases[identity]['conditions'] if row['flow'] == 'TSG'}
                baseline, target = (independent_condition(conditions[condition]) for condition in ('B', candidate['policy']))
                for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                    np.testing.assert_allclose(assignment[field], target[field]-baseline[field], atol=1e-12)
                for condition in ('B', candidate['policy']):
                    assert sum(row['assigned'] for row in conditions[condition]['versions']) == plan['confirmation_generations_per_arm']
                    physical.update(physical_by_case[(identity, condition)])
            assert sorted(physical) == result['physical_request_ids']
            for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                np.testing.assert_allclose(np.mean([row[field] for row in result['assignments']]), result[field], atol=1e-12)
        assert sorted(checked_tasks) == confirmation['read_task_ids']
        for method, result in confirmation['methods'].items():
            slots = cell['selection'][method]['slots']
            assert slots == result['slots'] and len(slots) == plan['selection_slots']
            valid = [key for key in slots if key is not None]
            passing = [key for key in valid if confirmation['candidates'][key]['secure_gain'] > 0]
            assert passing == result['passing']
            logical = len(valid)*plan['confirmation_tasks_per_candidate']*2*plan['confirmation_generations_per_arm']
            physical = {request for key in valid for request in confirmation['candidates'][key]['physical_request_ids']}
            assert result['logical_calls'] == logical <= plan['confirmation_call_budget']
            assert result['physical_request_ids'] == sorted(physical) and len(physical) <= logical
        root = output/'evaluation'/name
        verify_bundle(root)
        evaluation = read_json(root/'result.json')
        assert (evaluation['seed'], evaluation['budget']) == (cell['seed'], cell['budget'])
        estimates = {row['candidate_id']: row['gain'] for row in cell['learned']['estimates']}
        for method in plan['methods']:
            for mode in ('confirmed', 'discovery_only'):
                panel = evaluation['panels'][method][mode]
                assert panel['tasks'] == 200 and [row['task_unit_id'] for row in panel['assignments']] == design['test_task_ids']
                selected = confirmation['methods'][method]['passing'] if mode == 'confirmed' else [key for key in cell['selection'][method]['slots'] if key is not None]
                values = {key: confirmation['candidates'][key]['secure_gain'] if mode == 'confirmed' else estimates[key] for key in selected}
                for assignment in panel['assignments']:
                    identity = assignment['task_unit_id']
                    applicable = [key for key in selected if candidate_by_id[key]['family'] == tasks[identity]['family'] and
                        candidate_by_id[key]['initial_state'] == tasks[identity]['initial_states'][candidate_by_id[key]['policy_index']] and values[key] > 0]
                    chosen = sorted(applicable, key=lambda key: (-values[key], candidate_order[key]))[0] if applicable else None
                    assert chosen == assignment['candidate_id']
                    condition = 'B' if chosen is None else candidate_by_id[chosen]['policy']
                    original = {row['condition']: row for row in cases[identity]['conditions'] if row['flow'] == 'TSG'}
                    baseline, target = independent_condition(original['B']), independent_condition(original[condition])
                    for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                        np.testing.assert_allclose(assignment[field], target[field]-baseline[field], atol=1e-12)
                assert panel['edits'] == sum(row['candidate_id'] is not None for row in panel['assignments'])
                for field in ('secure_gain', 'finite_function_gain', 'support_gain'):
                    np.testing.assert_allclose(panel[field], np.mean([row[field] for row in panel['assignments']]), atol=1e-12)
        evaluations.append(evaluation)
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    assert summary['test_task_ids'] == design['test_task_ids'] and summary['test_task_units'] == 200
    assert summary['replays_are_independent'] is False
    families = [tasks[identity]['family'] for identity in design['test_task_ids']]
    rng = np.random.default_rng(plan['bootstrap_seed'])
    bootstrap = np.concatenate([rng.choice([index for index, family in enumerate(families) if family == name],
        (plan['bootstrap_draws'], families.count(name)), replace=True) for name in plan['families']], axis=1)
    count = len(plan['discovery_budgets'])*len(plan['primary_comparators'])
    assert count == summary['primary_family_size'] == 6
    for group in summary['groups']:
        selected = [row for row in evaluations if row['budget'] == group['budget']]
        discoveries = [row for row in cells if row['budget'] == group['budget']]
        assert len(selected) == len(discoveries) == len(plan['replay_seeds'])
        task_values = {}
        for method in plan['methods']:
            task_values[method] = np.mean([[row['secure_gain'] for row in result['panels'][method]['confirmed']['assignments']] for result in selected], axis=0)
            for mode in ('confirmed', 'discovery_only'):
                for field in ('secure_gain', 'finite_function_gain', 'support_gain', 'edits'):
                    np.testing.assert_allclose(group['methods'][method][mode][field],
                        np.mean([row['panels'][method][mode][field] for row in selected]), atol=1e-12)
        for comparison in group['comparisons']:
            delta = task_values[plan['primary_method']]-task_values[comparison['comparator']]
            np.testing.assert_allclose(delta, comparison['task_differences'], atol=1e-12)
            np.testing.assert_allclose(delta.mean(), comparison['difference'], atol=1e-12)
            radius = [plan['alpha']/(2*count), 1-plan['alpha']/(2*count)]
            np.testing.assert_allclose(np.quantile(delta[bootstrap].mean(1), radius), comparison['simultaneous_descriptive_interval'], atol=1e-12)
            changes = sum(set(row['selection'][plan['primary_method']]['slots']) != set(row['selection'][comparison['comparator']]['slots']) for row in discoveries)
            assert changes == comparison['changed_selection_replays']
        changes = sum(row['graphs'][family]['graphs']['jci123']['ancestry'][4+policy][-1] !=
                      row['graphs'][family]['graphs']['time']['ancestry'][4+policy][-1]
                      for row in discoveries for family in plan['families'] for policy in range(3))
        assert changes == group['changed_jci_time_requirement_queries']

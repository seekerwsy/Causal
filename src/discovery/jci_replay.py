from __future__ import annotations

import hashlib

import numpy as np
from sklearn.linear_model import Ridge

from prompt_mechanism_study.discovery.jci_sharing import ConditionalPermutation


def source_hash(seed, value):
    return hashlib.sha256(f'{seed}/{value}'.encode()).hexdigest()


def features(task, arm, prepared, plan, identical=False):
    source = np.asarray(task['initial_states'], dtype=float)
    family = np.asarray([task['family'] == name for name in plan['families']], dtype=float)
    context = np.asarray([arm == index for index in range(1, 5)], dtype=float)
    if identical:
        context[:] = 0.
    return np.r_[source, family, prepared, context, np.outer(context, source).ravel(),
                 np.outer(context, family).ravel()]


def request_features(row, task, plan):
    baseline = task['conditions']['TSG'][str(row['version'])]['B']['prompt_hash']
    return features(task, row['arm'], row['prepared'], plan, row['prompt_hash'] == baseline)


def policy_features(task, arm, plan):
    rows = []
    for version in ('1', '2'):
        conditions = task['conditions']['TSG'][version]
        condition = conditions[plan['contexts'][arm]]
        rows.append(features(task, arm, condition['states'], plan,
                             condition['prompt_hash'] == conditions['B']['prompt_hash']))
    return np.asarray(rows)


def same_policy(task, policy):
    return all(task['conditions']['TSG'][version][policy]['prompt_hash'] ==
               task['conditions']['TSG'][version]['B']['prompt_hash'] for version in ('1', '2'))


def fit_model(design, outcome, weights, penalty):
    model = Ridge(alpha=penalty, fit_intercept=True, solver='cholesky')
    model.fit(design, outcome, sample_weight=weights/weights.sum())
    return dict(intercept=float(model.intercept_), coefficients=model.coef_.tolist(), penalty=penalty)


def predict(model, design):
    return np.clip(np.asarray(design)@np.asarray(model['coefficients'])+model['intercept'], 0., 1.)


def learn_effects(observations, tasks, candidates, plan):
    identities = sorted({row['task_unit_id'] for row in observations})
    index_by_id = {identity: index for index, identity in enumerate(identities)}
    units = np.asarray([index_by_id[row['task_unit_id']] for row in observations])
    counts = np.bincount(units, minlength=len(identities))
    weights = 1/counts[units]
    folds = np.empty(len(identities), dtype=int)
    for family in plan['families']:
        indexes = [index for index, identity in enumerate(identities) if tasks[identity]['family'] == family]
        ordered = sorted(indexes, key=lambda index: source_hash(plan['fold_seed'], identities[index]))
        folds[ordered] = np.arange(len(ordered))%plan['folds']
    design = np.asarray([request_features(row, tasks[row['task_unit_id']], plan) for row in observations])
    outcome = np.asarray([row['y'] for row in observations], dtype=float)
    if design.shape != (len(observations), 42) or not np.isfinite(design).all():
        raise ValueError('重放的共同结果特征不完整')
    candidates_by_penalty, losses = [], []
    for penalty in plan['ridge_penalties']:
        models, predictions = [], np.empty(len(observations))
        for fold in range(plan['folds']):
            train = folds[units] != fold
            test = ~train
            if not train.any() or not test.any():
                raise ValueError('任务交叉拟合缺少训练或评价支持')
            model = fit_model(design[train], outcome[train], weights[train], penalty)
            models.append(model)
            predictions[test] = predict(model, design[test])
        losses.append(float(np.sum(weights*(outcome-predictions)**2)/len(identities)))
        candidates_by_penalty.append((models, predictions))
    chosen = min(range(len(losses)), key=lambda index: (losses[index], index))
    models, predictions = candidates_by_penalty[chosen]
    counterfactual = np.asarray([[float(np.mean(predict(models[folds[index]], policy_features(tasks[identity], arm, plan))))
                                  for arm in range(4)] for index, identity in enumerate(identities)])
    scores = counterfactual[:, 1:]-counterfactual[:, :1]
    residual = outcome-predictions
    for index, row in enumerate(observations):
        for policy in range(3):
            indicator = int(row['arm'] == policy+1)-int(row['arm'] == 0)
            scores[units[index], policy] += indicator*residual[index]/(plan['propensity']*counts[units[index]])
    for index, identity in enumerate(identities):
        for policy, name in enumerate(plan['policies']):
            if same_policy(tasks[identity], name):
                scores[index, policy] = 0.
    estimates = []
    population = [task for task in tasks.values() if task['role'] == 'training']
    for candidate in candidates:
        policy = candidate['policy_index']
        matching = [index for index, identity in enumerate(identities) if tasks[identity]['family'] == candidate['family']
                    and tasks[identity]['initial_states'][policy] == candidate['initial_state']]
        eligible = {identities[index] for index in matching}
        support = [len({row['task_unit_id'] for row in observations if row['task_unit_id'] in eligible and row['arm'] == arm})
                   for arm in (0, policy+1)]
        evaluable = min(support) >= plan['minimum_distinct_tasks_per_comparison_arm'] and len(matching) >= 2
        coverage = sum(task['family'] == candidate['family'] and task['initial_states'][policy] == candidate['initial_state']
                       for task in population)/len(population)
        gain = float(scores[matching, policy].mean()) if evaluable else None
        standard_error = float(scores[matching, policy].std(ddof=1)/np.sqrt(len(matching))) if evaluable else None
        estimates.append(dict(candidate_id=candidate['candidate_id'], evaluable=evaluable, gain=gain,
            standard_error=standard_error, coverage=coverage, tasks=len(matching), arm_task_support=support,
            score=None if gain is None else coverage*gain))
    return dict(task_ids=identities, request_task_indexes=units.tolist(), request_counts=counts.tolist(),
        task_folds=folds.tolist(), losses=losses, selected_penalty=plan['ridge_penalties'][chosen],
        models=models, observed_predictions=predictions.tolist(), counterfactual_predictions=counterfactual.tolist(),
        task_scores=scores.tolist(), estimates=estimates)


def discover_requirements(observations, plan, backend, coordinates):
    first = {}
    for row in observations:
        first.setdefault(row['task_unit_id'], row)
    output = {}
    labels = ['C1', 'C2', 'C3', 'C4', 'X1', 'X2', 'X3', 'Y']
    for family in plan['families']:
        rows = [row for row in first.values() if row['family'] == family]
        if len(rows) < 4:
            raise ValueError('结构重放缺少独立任务支持')
        values = np.asarray([[*[int(row['arm'] == arm) for arm in range(1, 5)], *row['prepared'], row['y']] for row in rows])
        ci = ConditionalPermutation(values, labels, plan['ci_draws'], [*coordinates, family])
        graphs = {name: backend.search(labels, name, ci, plan['ci_alpha']) for name in plan['structural_methods']}
        for graph in graphs.values():
            matrix = np.asarray(graph['ancestry'])
            if matrix.shape != (8, 8) or not np.isin(matrix, (-1, 0, 1)).all():
                raise ValueError('要求状态的祖先判定无效')
        output[family] = dict(labels=labels, request_ids=[row['request_id'] for row in rows],
            task_ids=[row['task_unit_id'] for row in rows], graphs=graphs, queries=list(ci.cache.values()))
    return output


def select_candidates(learned, graphs, candidates, plan):
    output = {}
    for name in plan['methods']:
        ranked = []
        for candidate, estimate in zip(candidates, learned['estimates'], strict=True):
            tier, relation = 0, None
            if name in plan['structural_methods']:
                relation = graphs[candidate['family']]['graphs'][name]['ancestry'][4+candidate['policy_index']][-1]
                tier = int(relation == 1)
            elif name == 'jci123_adjacency':
                tier = int(graphs[candidate['family']]['graphs']['jci123']['pag'][4+candidate['policy_index']][-1] != 0)
            value = estimate['score']
            if name == 'direct_lcb' and value is not None:
                value = estimate['coverage']*(estimate['gain']-estimate['standard_error'])
            ranked.append(dict(candidate_id=candidate['candidate_id'], tier=tier, ancestry=relation, score=value,
                               eligible=estimate['evaluable'] and value > 0 if value is not None else False))
        eligible = [row for row in ranked if row['eligible']]
        order = {candidate['candidate_id']: index for index, candidate in enumerate(candidates)}
        eligible.sort(key=lambda row: (-row['tier'], -row['score'], order[row['candidate_id']]))
        slots = [row['candidate_id'] for row in eligible[:plan['selection_slots']]]
        slots += [None]*(plan['selection_slots']-len(slots))
        output[name] = dict(ranking=ranked, slots=slots)
    return output

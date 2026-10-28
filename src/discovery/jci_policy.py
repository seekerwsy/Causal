from __future__ import annotations

import itertools

import numpy as np
from sklearn.linear_model import Ridge

from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation
from prompt_mechanism_study.discovery.policy_value import (
    all_states, contrast_features, exact_policy_value, full_basis, random_stream, select_actions,
)


def subset(data, indexes):
    return {key: ([value[int(index)] for index in indexes] if key == 'task_ids' else np.asarray(value)[indexes])
            for key, value in data.items()}


def features_for(data, family):
    if 'effects' not in data:
        return contrast_features(np.asarray(data['w']), family == 'target_factorized')
    if family == 'full':
        return np.asarray(data['features'])
    n, width = np.asarray(data['effects']).shape
    return np.tile(np.eye(width)[None], (n, 1, 1))


def fit_contrasts(data, penalty, family):
    features = features_for(data, family)
    n, width, columns = features.shape
    learner = Ridge(alpha=penalty, fit_intercept=True, solver='cholesky')
    if 'effects' in data:
        design, target = features.reshape(n*width, columns), np.asarray(data['effects']).reshape(-1)
    else:
        assigned = np.asarray(data['a'])
        effect_design = np.zeros((n, columns))
        selected = assigned > 0
        effect_design[selected] = features[np.flatnonzero(selected), assigned[selected]-1]
        design, target = np.column_stack((full_basis(np.asarray(data['w'])), effect_design)), data['y']
    learner.fit(design, target, sample_weight=np.full(len(design), 1/len(design)))
    return dict(family=family, penalty=penalty, paired='effects' in data,
                intercept=float(learner.intercept_), coefficients=learner.coef_.tolist(),
                contrast_columns=columns)


def predict_contrasts(model, data):
    features = features_for(data, model['family'])
    coefficients = np.asarray(model['coefficients'])
    if model['paired']:
        prediction = features@coefficients+model['intercept']
    else:
        prediction = features@coefficients[-model['contrast_columns']:]
    prediction = np.clip(prediction, -1., 1.)
    prediction[np.asarray(data['identity_zero'], dtype=bool)] = 0.
    return prediction


def predict_means(model, data):
    if model['paired']:
        raise ValueError('完整差值模型不提供分配均值')
    columns = model['contrast_columns']
    baseline = full_basis(np.asarray(data['w']))@np.asarray(model['coefficients'][:-columns])+model['intercept']
    return np.column_stack((baseline, baseline[:, None]+predict_contrasts(model, data)))


def policy_gain(data, scores, nuisance=None):
    actions = select_actions(scores)
    n = len(actions)
    if 'effects' in data:
        gains = np.column_stack((np.zeros(n), data['effects']))[np.arange(n), actions]
    else:
        if nuisance is None or np.asarray(nuisance).shape != (n, scores.shape[1]+1):
            raise ValueError('随机分配评价需要共同训练所得的分配均值')
        assignment = np.asarray(data['a'])
        propensity = 1/(scores.shape[1]+1)
        residual = np.asarray(data['y'])-nuisance[np.arange(n), assignment]
        weights = ((assignment == actions).astype(float)-(assignment == 0).astype(float))/propensity
        gains = nuisance[np.arange(n), actions]-nuisance[:, 0]+weights*residual
    return float(np.mean(gains)), actions


def discover_contexts(data, indexes, plan, backend, seed):
    width = np.asarray(data['x']).shape[1]
    assigned = np.asarray(data['a'])[indexes]
    contexts = (assigned[:, None] == np.arange(1, width+1)).astype(int)
    labels = [f'C{i+1}' for i in range(width)]+[f'X{i+1}' for i in range(width)]+['Y']
    values = np.column_stack((contexts, np.asarray(data['x'])[indexes], np.asarray(data['y'])[indexes]))
    ci = ConditionalPermutation(values, labels, plan['ci_draws'], seed)
    results = {name: backend.search(labels, name, ci, plan['ci_alpha']) for name in plan['structural_methods']}
    direct_p = None
    if plan.get('direct_context_queries', False):
        direct_p = {label: ci.query(label, 'Y', [other for other in labels[:width] if other != label])
                    for label in labels[:width]}
    for result in results.values():
        ancestry = np.asarray(result['ancestry'])
        if ancestry.shape != (len(labels), len(labels)) or not np.isin(ancestry, (-1, 0, 1)).all():
            raise ValueError('因果祖先矩阵的维度或判定无效')
        if set(result['context_ancestry']) != set(labels[:width]):
            raise ValueError('上下文祖先判定的变量身份不同')
        np.testing.assert_array_equal(ancestry[:width, -1], [result['context_ancestry'][label] for label in labels[:width]])
    result = dict(task_ids=[data['task_ids'][int(index)] for index in indexes],
                  labels=labels, results=results, queries=list(ci.cache.values()))
    if direct_p is not None:
        result['direct_context_p'] = direct_p
    return result


def learn_policies(training, calibration, evaluation, plan, backend, coordinates, saved_graphs=None):
    n = len(training['task_ids'])
    indexes = [np.arange(n)]
    for repeat in range(plan['subsamples']):
        indexes.append(np.sort(random_stream(plan['seed'], *coordinates, 'subsample', repeat).choice(
            n, int(n*plan['subsample_fraction']), replace=False)))
    if saved_graphs is None:
        graphs = [discover_contexts(training, selected, plan, backend,
                  [plan['seed'], *coordinates, 'structure', index]) for index, selected in enumerate(indexes)]
    else:
        if len(saved_graphs) != len(indexes):
            raise ValueError('已保存结构的任务子样本数量不同')
        for graph, selected in zip(saved_graphs, indexes, strict=True):
            if graph['task_ids'] != [training['task_ids'][int(index)] for index in selected]:
                raise ValueError('已保存结构的独立任务身份不同')
        graphs = saved_graphs
    width = np.asarray(training['x']).shape[1]
    support = {name: np.mean([np.asarray(row['results'][name]['ancestry'])[:width, -1] == -1
                              for row in graphs[1:]], axis=0) for name in plan['structural_methods']}
    if plan.get('direct_context_queries', False):
        support['direct_ci'] = np.mean([[row['direct_context_p'][f'C{i+1}'] >= plan['ci_alpha']
                                        for i in range(width)] for row in graphs[1:]], axis=0)
    if plan.get('adjacency_ablation', False):
        support['jci123_adjacency'] = np.mean([
            np.asarray(row['results']['jci123']['pag'])[:width, -1] == 0 for row in graphs[1:]], axis=0)
    if any(value.shape != (width,) for value in support.values()):
        raise ValueError('政策非祖先支持必须逐项对应全部候选')
    nuisance = None
    if 'effects' not in training:
        nuisance_model = fit_contrasts(training, plan['simulation_nuisance_penalty'], 'full')
        nuisance = predict_means(nuisance_model, calibration)
    else:
        nuisance_model = None
    candidates = {name: [] for name in ('full', 'direct_gate', 'direct_lcb', *support)}
    if plan.get('include_null_candidate', False):
        for options in candidates.values():
            options.append(dict(model=None, strength=0., calibration_gain=0.,
                                calibration_actions=[0]*len(calibration['task_ids'])))
    for family, penalty in itertools.product(plan['learner_families'], plan['ridge_penalties']):
        model = fit_contrasts(training, penalty, family)
        prediction = predict_contrasts(model, calibration)
        boot = np.asarray([predict_contrasts(fit_contrasts(subset(training, chosen), penalty, family), calibration)
                           for chosen in indexes[1:]])
        direct_support = np.mean(boot <= 0, axis=0)
        dispersion = np.std(boot, ddof=1, axis=0)
        mechanisms = dict(full=[(0., prediction)])
        mechanisms['direct_gate'] = [(strength, prediction*(1-strength*direct_support)) for strength in plan['gate_strengths']]
        mechanisms['direct_lcb'] = [(strength, prediction-strength*dispersion) for strength in plan['lcb_multipliers']]
        for method in support:
            mechanisms[method] = [(strength, prediction*(1-strength*support[method])) for strength in plan['gate_strengths']]
        for name, options in mechanisms.items():
            for strength, scores in options:
                scores = scores.copy()
                scores[np.asarray(calibration['identity_zero'], dtype=bool)] = 0.
                gain, actions = policy_gain(calibration, scores, nuisance)
                candidates[name].append(dict(model=model, strength=strength, calibration_gain=gain,
                                             calibration_actions=actions.tolist()))
    candidates['direct_envelope'] = candidates['full']+candidates['direct_gate']+candidates['direct_lcb']
    if 'direct_ci' in candidates:
        candidates['direct_envelope'] += candidates['direct_ci']
    choices, outputs = {}, {}
    for name, options in candidates.items():
        chosen = max(enumerate(options), key=lambda item: (item[1]['calibration_gain'], -item[0]))[1]
        model = chosen['model']
        if model is None:
            choices[name] = dict(chosen, origin='null')
            outputs[name] = dict(scores=np.zeros((len(evaluation['task_ids']), width)).tolist(),
                                 actions=[0]*len(evaluation['task_ids']))
            continue
        prediction = predict_contrasts(model, evaluation)
        if name == 'direct_envelope':
            direct_methods = ('full', 'direct_gate', 'direct_lcb', 'direct_ci') if 'direct_ci' in candidates else (
                'full', 'direct_gate', 'direct_lcb')
            origin = next(method for method in direct_methods if chosen in candidates[method])
        else:
            origin = name
        if origin in ('direct_gate', 'direct_lcb'):
            boot = np.asarray([predict_contrasts(fit_contrasts(subset(training, selected), model['penalty'], model['family']), evaluation)
                               for selected in indexes[1:]])
            prediction = (prediction*(1-chosen['strength']*np.mean(boot <= 0, axis=0)) if origin == 'direct_gate'
                          else prediction-chosen['strength']*np.std(boot, ddof=1, axis=0))
        elif origin in support:
            prediction = prediction*(1-chosen['strength']*support[origin])
        prediction[np.asarray(evaluation['identity_zero'], dtype=bool)] = 0.
        choices[name] = dict(chosen, origin=origin)
        outputs[name] = dict(scores=prediction.tolist(), actions=select_actions(prediction).tolist())
    return dict(graphs=graphs, nonancestry_support={name: value.tolist() for name, value in support.items()},
                candidates=candidates, choices=choices, outputs=outputs, nuisance_model=nuisance_model)


def simulate_tasks(plan, mechanism, n, repeat, role):
    specification = plan['simulation']
    beta = np.asarray(specification['mechanisms'][mechanism])
    width = len(beta)
    rng = random_stream(plan['seed'], mechanism, n, repeat, role)
    permutation = random_stream(plan['seed'], mechanism, n, repeat, 'policy-permutation').permutation(width)
    beta = beta[permutation]
    latent = rng.integers(0, 2, size=n)
    source_probability = np.asarray(specification['source_probability_by_latent'])[latent]
    w = rng.binomial(1, source_probability[:, None], size=(n, width))
    assignment = rng.integers(0, width+1, size=n)
    x = w.copy()
    selected = np.flatnonzero(assignment > 0)
    x[selected, assignment[selected]-1] = 1
    probability = specification['baseline_probability']+specification['latent_outcome_coefficient']*latent+x@beta
    if np.any((probability < 0) | (probability > 1)):
        raise ValueError('计算机制的结果概率无效')
    outcome = rng.binomial(1, probability)
    identities = [f'{mechanism}/{n}/{repeat}/{role}/{index}' for index in range(n)]
    return dict(w=w, x=x, a=assignment, y=outcome, identity_zero=w.astype(bool), task_ids=identities), beta

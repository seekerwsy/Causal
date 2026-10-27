from __future__ import annotations

import itertools

import networkx as nx
import numpy as np
from sklearn.linear_model import Ridge

from prompt_mechanism_study.discovery import jci_policy as shared
from prompt_mechanism_study.discovery.jci_sharing import ConditionalPermutation


class GraphicalIndependence:
    def __init__(self, beta):
        self.graph = nx.DiGraph()
        self.graph.add_nodes_from(['U', 'R', 'Y'])
        for index, coefficient in enumerate(beta):
            context, state = f'C{index+1}', f'X{index+1}'
            self.graph.add_edges_from([('R', context), ('U', state), (context, state)])
            if coefficient != 0:
                self.graph.add_edge(state, 'Y')
        self.graph.add_edge('U', 'Y')
        self.queries = []

    def query(self, x, y, conditioned):
        separated = nx.is_d_separator(self.graph, {x}, {y}, set(conditioned))
        self.queries.append(dict(x=x, y=y, conditioned=list(conditioned), separated=separated))
        return float(separated)


def graphical_oracles(parent_plan, backend):
    records = {}
    for mechanism, beta in parent_plan['simulation']['mechanisms'].items():
        width = len(beta)
        labels = [f'C{index+1}' for index in range(width)]+[f'X{index+1}' for index in range(width)]+['Y']
        oracle = GraphicalIndependence(beta)
        results = {name: backend.search(labels, name, oracle, .05) for name in parent_plan['structural_methods']}
        direct = {f'C{index+1}': nx.is_d_separator(oracle.graph, {f'C{index+1}'}, {'Y'},
                  {f'C{other+1}' for other in range(width) if other != index}) for index in range(width)}
        records[mechanism] = dict(beta=beta, labels=labels, results=results, queries=oracle.queries, direct_ci_nulls=direct)
    return records


def oracle_nulls(record, beta):
    original = np.asarray(record['beta'])
    beta = np.asarray(beta)
    source_order = np.r_[np.flatnonzero(original), np.flatnonzero(original == 0)]
    target_order = np.r_[np.flatnonzero(beta), np.flatnonzero(beta == 0)]
    if len(source_order) != len(target_order) or np.count_nonzero(original) != np.count_nonzero(beta):
        raise ValueError('图形真值检查的政策映射不同')
    mapping = np.empty(len(beta), dtype=int)
    mapping[target_order] = source_order
    masks = {name: (np.asarray(result['ancestry'])[mapping, -1] == -1)
             for name, result in record['results'].items()}
    masks['direct_ci'] = np.asarray([record['direct_ci_nulls'][f'C{index+1}'] for index in mapping])
    return masks


def fit_zero_model(training, family, penalty, nulls):
    if 'effects' in training:
        raise ValueError('共同基线重新拟合使用单项随机分配的结果观测')
    nulls = np.asarray(nulls, dtype=bool)
    w, assignment, outcome = np.asarray(training['w']), np.asarray(training['a']), np.asarray(training['y'])
    width = w.shape[1]
    if nulls.shape != (width,) or not np.isfinite(outcome).all():
        raise ValueError('零效果约束或观测结果无效')
    if family == 'arm_mean':
        if set(np.unique(assignment)) != set(range(width+1)):
            raise ValueError('每个预定随机组都需要实际任务支持')
        pooled = np.isin(assignment, np.r_[0, np.flatnonzero(nulls)+1])
        baseline = float(outcome[pooled].mean())
        marginal = np.asarray([0. if nulls[index] else outcome[assignment == index+1].mean()-baseline for index in range(width)])
        eligibility = np.mean(1-w, axis=0)
        if np.any(eligibility <= 0):
            raise ValueError('每项 ADD 都需要实际来源状态支持')
        return dict(family=family, penalty=penalty, nulls=nulls.tolist(), baseline=baseline,
            marginal_effects=marginal.tolist(), eligibility=eligibility.tolist(), coefficients=(marginal/eligibility).tolist())
    features = shared.contrast_features(w, family == 'target_factorized')
    effect_columns = features.shape[-1]
    design = np.zeros((len(w), effect_columns))
    selected = np.flatnonzero(assignment > 0)
    design[selected] = features[selected, assignment[selected]-1]
    baseline = shared.full_basis(w)
    design = np.column_stack((baseline, design))
    per_policy = effect_columns//width
    retained = np.r_[np.ones(baseline.shape[1], dtype=bool), np.repeat(~nulls, per_policy)]
    learner = Ridge(alpha=penalty, fit_intercept=True, solver='cholesky')
    learner.fit(design[:, retained], outcome, sample_weight=np.full(len(w), 1/len(w)))
    coefficients = np.zeros(design.shape[1])
    coefficients[retained] = learner.coef_
    return dict(family=family, penalty=penalty, paired=False, nulls=nulls.tolist(),
                intercept=float(learner.intercept_), coefficients=coefficients.tolist(), contrast_columns=effect_columns)


def predict_zero_model(model, destination):
    if model['family'] == 'arm_mean':
        prediction = (1-np.asarray(destination['w']))*np.asarray(model['coefficients'])
        return np.clip(prediction, -1., 1.)
    return shared.predict_contrasts(model, destination)


def refit_cell(cell, parent_plan, plan, oracles):
    training, calibration = cell['training'], cell['calibration']
    width = len(cell['beta'])
    states = shared.all_states(width)
    evaluation = dict(w=states, identity_zero=states.astype(bool))
    nuisance = shared.predict_means(cell['learned']['nuisance_model'], calibration)
    positions = {identity: index for index, identity in enumerate(training['task_ids'])}
    samples = [np.asarray([positions[identity] for identity in graph['task_ids']]) for graph in cell['learned']['graphs'][1:]]
    oracle_masks = oracle_nulls(oracles[cell['mechanism']], cell['beta'])
    graph_support = {name: np.asarray(value) for name, value in cell['learned']['nonancestry_support'].items()}
    direct_queries, direct_support = [], []
    for sample_index, sample in enumerate(samples, 1):
        assignment = np.asarray(training['a'])[sample]
        contexts = (assignment[:, None] == np.arange(1, width+1)).astype(int)
        labels = [f'C{index+1}' for index in range(width)]+['Y']
        ci = ConditionalPermutation(np.column_stack((contexts, np.asarray(training['y'])[sample])), labels,
            parent_plan['ci_draws'], [parent_plan['seed'], cell['mechanism'], cell['n'], cell['repetition'], 'structure', sample_index])
        direct_support.append([ci.query(context, 'Y', [other for other in labels[:-1] if other != context]) > parent_plan['ci_alpha']
                               for context in labels[:-1]])
        direct_queries.append(list(ci.cache.values()))
    graph_support['direct_ci'] = np.mean(direct_support, axis=0)
    constraint_methods = (*parent_plan['structural_methods'], 'direct_ci')
    names = ('full', 'direct_null', 'direct_envelope', *constraint_methods,
             *[f'oracle_{name}' for name in constraint_methods])
    candidates = {name: [] for name in names}
    for name in candidates:
        candidates[name].append(dict(model=None, calibration_gain=0., calibration_actions=[0]*len(calibration['task_ids']), origin='baseline'))
    for family, penalty in itertools.product(plan['families'], plan['ridge_penalties']):
        reference = fit_zero_model(training, family, penalty, np.zeros(width, dtype=bool))
        base_prediction = predict_zero_model(reference, evaluation)
        boot = np.asarray([predict_zero_model(fit_zero_model(shared.subset(training, sample), family, penalty,
            np.zeros(width, dtype=bool)), evaluation) for sample in samples])
        standard = np.std(boot, ddof=1, axis=0)
        standardized = np.divide(np.abs(base_prediction), standard,
            out=np.where(base_prediction == 0, 0., np.inf), where=standard > 0)
        direct_maximum = standardized.max(axis=0)
        masks = dict(full=[(None, np.zeros(width, dtype=bool))])
        masks['direct_null'] = [(threshold, direct_maximum < threshold) for threshold in plan['direct_null_z_thresholds']]
        for name in constraint_methods:
            masks[name] = [(threshold, np.zeros(width, dtype=bool) if threshold is None else graph_support[name] >= threshold)
                           for threshold in plan['nonancestry_thresholds']]
            masks[f'oracle_{name}'] = [(threshold, np.zeros(width, dtype=bool) if threshold is None else oracle_masks[name])
                                      for threshold in plan['nonancestry_thresholds']]
        fitted = {}
        for name, options in masks.items():
            for threshold, mask in options:
                key = tuple(mask)
                if key not in fitted:
                    fitted[key] = fit_zero_model(training, family, penalty, mask)
                model = fitted[key]
                gain, actions = shared.policy_gain(calibration, predict_zero_model(model, calibration), nuisance)
                candidates[name].append(dict(model=model, threshold=threshold, calibration_gain=gain,
                                             calibration_actions=actions.tolist(), origin=name))
    parent_choice = cell['learned']['choices']['direct_envelope']
    parent_candidate = dict(model=None, origin='parent_direct', calibration_gain=parent_choice['calibration_gain'],
        calibration_actions=parent_choice['calibration_actions'], scores=cell['learned']['outputs']['direct_envelope']['scores'])
    candidates['direct_envelope'] = candidates['full']+candidates['direct_null']+candidates['direct_ci']+[parent_candidate]
    choices, values, predictions = {}, {}, {}
    for name, options in candidates.items():
        choice = max(enumerate(options), key=lambda item: (item[1]['calibration_gain'], -item[0]))[1]
        scores = (np.asarray(choice['scores']) if choice['origin'] == 'parent_direct' else
                  np.zeros_like(states, dtype=float) if choice['model'] is None else predict_zero_model(choice['model'], evaluation))
        choices[name] = choice
        predictions[name] = scores.tolist()
        values[name] = shared.exact_policy_value(scores, np.asarray(cell['beta']), parent_plan)
    source_probability = np.mean(parent_plan['simulation']['source_probability_by_latent'])
    truth = (1-source_probability)*np.asarray(cell['beta'])
    ordinary = fit_zero_model(training, 'arm_mean', 0., np.zeros(width, dtype=bool))
    constrained = fit_zero_model(training, 'arm_mean', 0., oracle_masks['jci123'])
    assignment, outcome = np.asarray(training['a']), np.asarray(training['y'])
    counts = np.bincount(assignment, minlength=width+1)
    if counts.min() < 2:
        raise ValueError('各随机组需要足够任务计算结果方差')
    variances = np.asarray([outcome[assignment == arm].var(ddof=1)/counts[arm] for arm in range(width+1)])
    ordinary_effect = np.asarray(ordinary['marginal_effects'])
    squared = float(ordinary_effect@ordinary_effect)
    shrinkage = 0. if squared == 0 else max(0., 1-float(np.sum(variances[1:]+variances[0]))/squared)
    baseline_probability = parent_plan['simulation']['baseline_probability']
    baseline_probability += .5*parent_plan['simulation']['latent_outcome_coefficient']+source_probability*np.sum(cell['beta'])
    arm_probabilities = baseline_probability+truth
    reference_variance = arm_probabilities*(1-arm_probabilities)/counts[1:]+baseline_probability*(1-baseline_probability)/counts[0]
    pool_count = counts[0]+counts[1:][oracle_masks['jci123']].sum()
    oracle_variance = np.where(oracle_masks['jci123'], 0.,
        arm_probabilities*(1-arm_probabilities)/counts[1:]+baseline_probability*(1-baseline_probability)/pool_count)
    mse = dict(full=float(np.mean((ordinary_effect-truth)**2)), zero=float(np.mean(truth**2)),
               empirical_shrinkage=float(np.mean((shrinkage*ordinary_effect-truth)**2)),
               oracle_jci123=float(np.mean((np.asarray(constrained['marginal_effects'])-truth)**2)),
               empirical_shrinkage_factor=shrinkage, arm_counts=counts.tolist(),
               fixed_count_reference_variance=reference_variance.tolist(), fixed_count_oracle_variance=oracle_variance.tolist(),
               true_marginal_effects=truth.tolist(), full_model=ordinary, oracle_jci123_model=constrained)
    return dict(mechanism=cell['mechanism'], n=cell['n'], repetition=cell['repetition'],
        oracle_null_masks={name: mask.tolist() for name, mask in oracle_masks.items()},
        candidates=candidates, choices=choices, predictions=predictions, values=values, marginal_estimation=mse,
        direct_ci_queries=direct_queries, direct_ci_support=graph_support['direct_ci'].tolist())

from __future__ import annotations

import itertools

import numpy as np
from scipy.stats import binom
from sklearn.linear_model import ElasticNet, Ridge

from prompt_mechanism_study.discovery.jci_policy import contrast_features, full_basis, random_stream, select_actions
from prompt_mechanism_study.discovery.jci_sharing import ConditionalPermutation


def exact_joint_distribution(beta, plan, generations):
    beta = np.asarray(beta, dtype=float)
    width = len(beta)
    specification = plan['simulation']
    rows, weights = [], []
    for latent, state, arm in itertools.product((0, 1), itertools.product((0, 1), repeat=width), range(width+1)):
        source_probability = specification['source_probability_by_latent'][latent]
        probability = .5*np.prod(np.where(state, source_probability, 1-source_probability))/(width+1)
        context = (np.arange(1, width+1) == arm).astype(int)
        prepared = np.asarray(state, dtype=int).copy()
        if arm:
            prepared[arm-1] = 1
        mean = specification['baseline_probability']+specification['latent_outcome_coefficient']*latent+prepared@beta
        if not 0 <= mean <= 1:
            raise ValueError('精确联合分布的结果概率无效')
        for outcome in range(generations+1):
            rows.append([*context, *prepared, outcome])
            weights.append(probability*binom.pmf(outcome,generations,mean))
    weights = np.asarray(weights)
    np.testing.assert_allclose(weights.sum(), 1., atol=1e-13)
    return np.asarray(rows, dtype=int), weights


def exact_conditional_association(rows, weights, labels, x, y, conditioned):
    indexes = {name: index for index, name in enumerate(labels)}
    selected = [indexes[name] for name in conditioned]
    groups = (np.unique(rows[:, selected], axis=0, return_inverse=True)[1]
              if selected else np.zeros(len(rows), dtype=int))
    divergence, maximum_gap = 0., 0.
    for group in np.unique(groups):
        chosen = groups == group
        x_values,xi = np.unique(rows[chosen,indexes[x]],return_inverse=True)
        y_values,yi = np.unique(rows[chosen,indexes[y]],return_inverse=True)
        cells = len(y_values)*xi+yi
        table = np.bincount(cells,weights=weights[chosen],minlength=len(x_values)*len(y_values)).reshape(len(x_values),len(y_values))
        if table.sum() == 0:
            continue
        expected = np.outer(table.sum(1), table.sum(0))/table.sum()
        maximum_gap = max(maximum_gap, float(np.max(np.abs(table-expected))))
        valid = expected > 0
        divergence += float(np.sum((table[valid]-expected[valid])**2/expected[valid]))
    return dict(independent=maximum_gap < 1e-12, maximum_joint_probability_gap=maximum_gap,
                conditional_pearson_divergence=divergence)


def draw_reliability_tasks(plan, mechanism, n, generations, batch, repetition, role):
    specification = plan['simulation']
    beta = np.asarray(specification['mechanisms'][mechanism],dtype=float)
    seed = plan['batch_seeds'][batch]
    coordinates = (mechanism,n,generations,batch,repetition)
    permutation = random_stream(seed,*coordinates,'policy-permutation').permutation(len(beta))
    beta = beta[permutation]
    latent_coefficient = specification['latent_outcome_by_mechanism'][mechanism]
    for latent in (0,1):
        lower = specification['baseline_probability']+latent_coefficient*latent+beta[beta<0].sum()
        upper = specification['baseline_probability']+latent_coefficient*latent+beta[beta>0].sum()
        if not 0 <= lower <= upper <= 1:
            raise ValueError('预定 SCM 的结果概率无效')
    rng = random_stream(seed,*coordinates,role)
    latent = rng.integers(0,2,n)
    source_probability = np.asarray(specification['source_probability_by_latent'])[latent]
    source = rng.binomial(1,source_probability[:,None],size=(n,len(beta)))
    assignment = rng.integers(0,len(beta)+1,n)
    prepared = source.copy()
    selected = np.flatnonzero(assignment>0)
    prepared[selected,assignment[selected]-1] = 1
    probability = specification['baseline_probability']+latent_coefficient*latent+prepared@beta
    successes = rng.binomial(generations,probability)
    identifiers = [f'{plan["study_id"]}/{mechanism}/{n}/{generations}/{batch}/{repetition}/{role}/{index}' for index in range(n)]
    data = dict(w=source,x=prepared,a=assignment,y=successes/generations,successes=successes,
                identity_zero=source.astype(bool),task_ids=identifiers)
    return data,beta


def discover_reliable_contexts(training, plan, backend, coordinates):
    width = np.asarray(training['w']).shape[1]
    labels = [f'C{index+1}' for index in range(width)]+[f'X{index+1}' for index in range(width)]+['Y']
    contexts = np.asarray(training['a'])[:,None] == np.arange(1,width+1)
    observations = np.column_stack((contexts,training['x'],training['successes']))
    ci = ConditionalPermutation(observations,labels,plan['ci_draws'],[plan['seed'],*coordinates,'structure'])
    graphs = {name:backend.search(labels,name,ci,plan['ci_alpha']) for name in plan['structural_methods']}
    direct, dependent = [], []
    for policy in range(width):
        x,y = sorted((labels[policy],'Y'))
        conditioned = tuple(label for label in labels[:width] if label!=labels[policy])
        value = ci.query(x,y,conditioned)
        query = ci.cache[(x,y,conditioned)]
        supported = query['informative_strata']>0
        direct.append(float(supported and value>=plan['ci_alpha']))
        dependent.append(bool(supported and value<plan['ci_alpha']))
    raw = {name:(np.asarray(graph['ancestry'])[:width,-1]==-1).astype(float)
           for name,graph in graphs.items()}
    raw['adjacency'] = (np.asarray(graphs['jci123']['pag'])[:width,-1]==0).astype(float)
    guarded = {name:(values*np.asarray(direct)).tolist() for name,values in raw.items()}
    guarded['direct_ci'] = direct
    guarded['jci123_unprotected'] = raw['jci123'].tolist()
    queries = [{key:value for key,value in query.items() if key!='tables'} for query in ci.cache.values()]
    return dict(labels=labels,graphs=graphs,raw_nonancestor={name:value.tolist() for name,value in raw.items()},
                guarded_priors=guarded,direct_dependence=dependent,queries=queries,
                task_ids=training['task_ids'],conditional_seed=[plan['seed'],*coordinates,'structure'])


def centered_effect_design(data, family):
    features = contrast_features(np.asarray(data['w']),family=='target_factorized')
    width = features.shape[1]
    assignment = np.asarray(data['a'])
    chosen = np.zeros((len(assignment),features.shape[2]))
    indexes = np.flatnonzero(assignment>0)
    chosen[indexes] = features[indexes,assignment[indexes]-1]
    return chosen-features.sum(axis=1)/(width+1)


def fit_nuisance(source, outcome, penalty):
    design = full_basis(np.asarray(source))
    learner = Ridge(alpha=penalty,fit_intercept=True,solver='cholesky')
    learner.fit(design,outcome,sample_weight=np.full(len(source),1/len(source)))
    return dict(intercept=float(learner.intercept_),coefficients=learner.coef_.tolist())


def nuisance_prediction(model, source):
    return np.clip(full_basis(np.asarray(source))@np.asarray(model['coefficients'])+model['intercept'],0.,1.)


def common_nuisance(training, calibration, plan, coordinates):
    n = len(training['task_ids'])
    folds = np.empty(n,dtype=int)
    permutation = random_stream(plan['seed'],*coordinates,'nuisance-fold').permutation(n)
    folds[permutation] = np.arange(n)%plan['nuisance_folds']
    crossfit = np.empty(n)
    models = []
    for fold in range(plan['nuisance_folds']):
        selected = folds!=fold
        model = fit_nuisance(training['w'][selected],training['y'][selected],plan['nuisance_penalty'])
        crossfit[~selected] = nuisance_prediction(model,training['w'][~selected])
        models.append(model)
    complete = fit_nuisance(training['w'],training['y'],plan['nuisance_penalty'])
    return dict(folds=folds.tolist(),crossfit_models=models,complete_model=complete,
                training_means=crossfit.tolist(),calibration_means=nuisance_prediction(complete,calibration['w']).tolist())


def fit_effect_ridge(design, target, family, penalties):
    scale = np.sqrt(np.asarray(penalties))
    if np.any(scale<=0) or not np.isfinite(scale).all():
        raise ValueError('效果惩罚必须保持正的有限值')
    learner = Ridge(alpha=1.,fit_intercept=True,solver='cholesky')
    learner.fit(design/scale,target,sample_weight=np.full(len(design),1/len(design)))
    return dict(kind='ridge',family=family,penalties=np.asarray(penalties).tolist(),
                intercept=float(learner.intercept_),coefficients=(learner.coef_/scale).tolist())


def fit_effect_elastic(design, target, family, penalty, ratio):
    learner = ElasticNet(alpha=penalty,l1_ratio=ratio,fit_intercept=True,max_iter=20000,tol=1e-10,selection='cyclic')
    learner.fit(design,target)
    if learner.n_iter_>=learner.max_iter:
        raise ValueError('ElasticNet 效果学习未收敛')
    return dict(kind='elastic_net',family=family,penalty=penalty,l1_ratio=ratio,iterations=int(learner.n_iter_),
                intercept=float(learner.intercept_),coefficients=learner.coef_.tolist())


def predict_effect_scores(model, source):
    features = contrast_features(np.asarray(source),model['family']=='target_factorized')
    return features@np.asarray(model['coefficients'])


def direct_score_prior(training, residual):
    design = np.column_stack((np.ones(len(residual)),centered_effect_design(training,'target_factorized')))
    if np.linalg.matrix_rank(design)!=design.shape[1]:
        raise ValueError('直接效果权重的实际分配支持不足')
    coefficient = np.linalg.lstsq(design,residual,rcond=None)[0]
    error = residual-design@coefficient
    inverse = np.linalg.inv(design.T@design)
    covariance = inverse@(design.T@(error[:,None]**2*design))@inverse
    variance = np.diag(covariance)[1:]
    if np.any(variance<=0):
        raise ValueError('直接效果权重的估计方差无效')
    z_squared = coefficient[1:]**2/variance
    return dict(prior=(1/(1+z_squared)).tolist(),coefficients=coefficient.tolist(),variance=variance.tolist())


def auxiliary_means(nuisance, model, source):
    features = contrast_features(np.asarray(source),True)
    effects = features@np.asarray(model['coefficients'])
    baseline = nuisance+model['intercept']-effects.sum(axis=1)/(effects.shape[1]+1)
    return np.clip(np.column_stack((baseline,baseline[:,None]+effects)),0.,1.)


def calibration_policy_gain(data, actions, auxiliary):
    assignment = np.asarray(data['a'])
    positions = np.arange(len(assignment))
    propensity = 1/auxiliary.shape[1]
    residual = np.asarray(data['y'])-auxiliary[positions,assignment]
    weight = ((assignment==actions).astype(float)-(assignment==0).astype(float))/propensity
    values = auxiliary[positions,actions]-auxiliary[:,0]+weight*residual
    return float(np.mean(values))


def learn_reliable_policies(training, calibration, structure, plan, coordinates, oracle_nulls=None):
    nuisance = common_nuisance(training,calibration,plan,coordinates)
    residual = np.asarray(training['y'])-np.asarray(nuisance['training_means'])
    n_cal = len(calibration['task_ids'])
    cal_order = random_stream(plan['seed'],*coordinates,'calibration-partition').permutation(n_cal)
    fit_indexes = np.sort(cal_order[:int(n_cal*plan['calibration_fit_fraction'])])
    policy_indexes = np.sort(cal_order[int(n_cal*plan['calibration_fit_fraction']):])
    design = {family:centered_effect_design(training,family) for family in plan['learner_families']}
    cal_design = {family:centered_effect_design(calibration,family) for family in plan['learner_families']}
    direct = direct_score_prior(training,residual)
    priors = dict(structure['guarded_priors'],direct_score=direct['prior'])
    if oracle_nulls is not None:
        priors['ideal_structure'] = np.asarray(oracle_nulls,dtype=float).tolist()
    models, cache = [], {}
    width = np.asarray(training['w']).shape[1]
    def save_model(model):
        family = model['family']
        prediction = np.asarray(nuisance['calibration_means'])+model['intercept']+cal_design[family]@np.asarray(model['coefficients'])
        model['calibration_fit_loss'] = float(np.mean((np.asarray(calibration['y'])[fit_indexes]-prediction[fit_indexes])**2))
        models.append(model)
        return len(models)-1
    def ridge_model(family, penalties):
        key = family,tuple(penalties)
        if key not in cache:
            cache[key] = save_model(fit_effect_ridge(design[family],residual,family,penalties))
        return cache[key]
    groups = {name:[] for name in ('ridge','elastic_net',*priors)}
    for family in plan['learner_families']:
        columns = design[family].shape[1]
        ordinary = [ridge_model(family,np.full(columns,penalty)) for penalty in plan['direct_penalties']]
        groups['ridge'].append(dict(family=family,strength=None,model_ids=ordinary))
        elastic = [save_model(fit_effect_elastic(design[family],residual,family,penalty,ratio))
                   for penalty,ratio in itertools.product(plan['direct_penalties'],plan['elastic_net_ratios'])]
        groups['elastic_net'].append(dict(family=family,strength=None,model_ids=elastic))
        for name,prior in priors.items():
            for strength in plan['prior_strengths']:
                weights = np.repeat(1-strength+strength*np.asarray(prior),columns//width)
                fitted = [ridge_model(family,penalty*weights) for penalty in plan['ridge_penalties']]
                groups[name].append(dict(family=family,strength=strength,model_ids=fitted))
    options = {}
    for name,entries in groups.items():
        selected = []
        for entry in entries:
            best = min(entry['model_ids'],key=lambda index:(models[index]['calibration_fit_loss'],index))
            entry['selected_model_id'] = best
            selected.append(best)
        options[name] = selected
    reference = options['ridge']
    for name in options:
        options[name] = list(dict.fromkeys([*reference,*options[name]]))
    direct_names = ('ridge','elastic_net','direct_score','direct_ci','adjacency')
    options['direct_envelope'] = list(dict.fromkeys(index for name in direct_names for index in options[name]))
    auxiliary = fit_effect_ridge(design['target_factorized'],residual,'target_factorized',np.full(width,plan['policy_nuisance_penalty']))
    cal_means = auxiliary_means(np.asarray(nuisance['calibration_means']),auxiliary,calibration['w'])
    policy_data = {key:(value if key=='task_ids' else np.asarray(value)[policy_indexes]) for key,value in calibration.items()}
    policy_data['task_ids'] = [calibration['task_ids'][index] for index in policy_indexes]
    all_gains, actions = {}, {}
    for index,model in enumerate(models):
        chosen = select_actions(predict_effect_scores(model,calibration['w']))
        actions[index] = chosen
        all_gains[index] = calibration_policy_gain(policy_data,chosen[policy_indexes],cal_means[policy_indexes])
        model['calibration_policy_gain'] = all_gains[index]
    states = np.asarray(list(itertools.product((0,1),repeat=width)))
    choices,outputs = {},{}
    for name,indexes in options.items():
        selected = max([None,*indexes],key=lambda index:(0. if index is None else all_gains[index],
                                                        1 if index is None else -index))
        if selected is None:
            choices[name] = dict(model_id=None,calibration_policy_gain=0.,action='baseline',effect_estimate=None)
            outputs[name] = dict(scores=np.zeros_like(states,dtype=float).tolist(),actions=[0]*len(states))
        else:
            score = predict_effect_scores(models[selected],states)
            choices[name] = dict(model_id=selected,calibration_policy_gain=all_gains[selected],action='learned_policy')
            outputs[name] = dict(scores=score.tolist(),actions=select_actions(score).tolist())
    return dict(nuisance=nuisance,direct_score=direct,models=models,calibration_groups=groups,
                calibration_fit_indexes=fit_indexes.tolist(),calibration_policy_indexes=policy_indexes.tolist(),
                policy_model_ids=options,choices=choices,outputs=outputs,policy_nuisance_model=auxiliary,
                coefficients_fixed_to_zero=False)

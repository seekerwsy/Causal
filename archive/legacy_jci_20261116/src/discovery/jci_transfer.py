from __future__ import annotations

import itertools

import numpy as np
from sklearn.linear_model import Ridge

from prompt_mechanism_study.discovery.jci_replay import (
    fit_model, policy_features, predict, request_features, same_policy, source_hash,
)
from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation


def task_weights(rows):
    identities, units = np.unique([row['task_unit_id'] for row in rows], return_inverse=True)
    counts = np.bincount(units)
    return identities.tolist(), units, 1/counts[units]


def state_basis(states, mask):
    states = np.asarray(states, dtype=int)
    if states.ndim != 2 or states.shape[1] != 3 or not np.isin(states,(0,1)).all() or mask not in range(8):
        raise ValueError('共享属性必须是三项完整初始状态的子集')
    z = 2*states-1
    return np.column_stack([np.prod(z[:,[bit for bit in range(3) if term>>bit&1]],axis=1)
                            for term in range(8) if term&mask==term])


def effect_design(tasks, identities, mask, plan, shared=True):
    states = np.asarray([tasks[key]['initial_states'] for key in identities])
    environments = np.asarray([plan['families'].index(tasks[key]['family']) for key in identities])
    complete = state_basis(states,7)
    if not shared:
        return np.concatenate([complete*(environments==index)[:,None] for index in range(4)],axis=1)
    contrast = np.eye(4,3)[environments]
    contrast[environments==3] = -1
    return np.column_stack((state_basis(states,mask),
        np.concatenate([complete*contrast[:,index,None] for index in range(3)],axis=1)))


def fit_effect(design, outcomes, weights, mask, penalty, deviation, shared):
    width = 2**mask.bit_count() if shared else design.shape[1]
    penalties = np.r_[np.full(width,penalty),np.full(design.shape[1]-width,deviation)]
    if not np.isfinite(penalties).all() or np.any(penalties<=0):
        raise ValueError('共享效果和环境差异必须使用正的有限惩罚')
    scale = np.sqrt(penalties)
    learner = Ridge(alpha=1.,fit_intercept=False,solver='cholesky')
    learner.fit(design/scale,outcomes,sample_weight=weights/weights.sum())
    return dict(mask=mask,shared=shared,penalty=penalty,deviation=deviation,
        penalties=penalties.tolist(),coefficients=(learner.coef_/scale).tolist())


def effect_scores(model, tasks, identities, plan):
    values = effect_design(tasks,identities,model['mask'],plan,model['shared'])@np.asarray(model['coefficients']).T
    for index,key in enumerate(identities):
        for policy,name in enumerate(plan['policies']):
            if same_policy(tasks[key],name):
                values[index,policy] = 0.
    return values


def actions_for(scores, threshold):
    scores = np.asarray(scores)
    if scores.ndim!=2 or scores.shape[1]!=3 or not np.isfinite(scores).all():
        raise ValueError('政策效果分数无效')
    actions = np.argmax(np.column_stack((np.zeros(len(scores)),scores)),axis=1)
    actions[scores.max(axis=1)<=threshold] = 0
    return actions


def combined_scores(models, model_ids, tasks, identities, plan):
    if len(model_ids)!=3:
        raise ValueError('每项政策必须保留独立的效果模型')
    return np.column_stack([effect_scores(models[index],tasks,identities,plan)[:,policy]
                            for policy,index in enumerate(model_ids)])


def estimate_pseudo_outcomes(rows, tasks, models, model_indexes, plan):
    identities,units,weights = task_weights(rows)
    observed = np.empty(len(rows))
    counterfactual = np.empty((len(identities),4))
    for index,row in enumerate(rows):
        model = models[model_indexes[row['task_unit_id']]]
        observed[index] = predict(model,request_features(row,tasks[row['task_unit_id']],plan)[None])[0]
    for index,key in enumerate(identities):
        model = models[model_indexes[key]]
        counterfactual[index] = [np.mean(predict(model,policy_features(tasks[key],arm,plan))) for arm in range(4)]
    scores = counterfactual[:,1:]-counterfactual[:,:1]
    for index,row in enumerate(rows):
        for policy in range(3):
            indicator = int(row['arm']==policy+1)-int(row['arm']==0)
            scores[units[index],policy] += weights[index]*indicator*(row['y']-observed[index])/plan['propensity']
    for index,key in enumerate(identities):
        for policy,name in enumerate(plan['policies']):
            if same_policy(tasks[key],name):
                scores[index,policy] = 0.
    return dict(task_ids=identities,request_task_indexes=units.tolist(),request_weights=weights.tolist(),
        observed_predictions=observed.tolist(),counterfactual=counterfactual.tolist(),scores=scores.tolist())


def nuisance_and_scores(fitting, source_calibration, target_calibration, tasks, plan):
    identities,units,weights = task_weights(fitting)
    ordered = sorted(identities,key=lambda key:source_hash(plan['fold_seed'],key))
    folds = {}
    for family in plan['families']:
        group = [key for key in ordered if tasks[key]['family']==family]
        folds.update({key:index%plan['folds'] for index,key in enumerate(group)})
    design = np.asarray([request_features(row,tasks[row['task_unit_id']],plan) for row in fitting])
    outcome = np.asarray([row['y'] for row in fitting])
    models = []
    for fold in range(plan['folds']):
        selected = np.asarray([folds[row['task_unit_id']]!=fold for row in fitting])
        if not selected.any() or selected.all():
            raise ValueError('任务交叉拟合缺少完整折分配')
        models.append(fit_model(design[selected],outcome[selected],weights[selected],plan['nuisance_penalty']))
    complete = fit_model(design,outcome,weights,plan['nuisance_penalty'])
    train = estimate_pseudo_outcomes(fitting,tasks,models,folds,plan)
    sources = estimate_pseudo_outcomes(source_calibration,tasks,[complete],
        {row['task_unit_id']:0 for row in source_calibration},plan)
    target = estimate_pseudo_outcomes(target_calibration,tasks,[complete],
        {row['task_unit_id']:0 for row in target_calibration},plan)
    return dict(folds=folds,models=models,complete_model=complete,training=train,source_calibration=sources,target_calibration=target)


def discover_transfer(rows, tasks, plan, backend, coordinates):
    first = {}
    for row in rows:
        first.setdefault(row['task_unit_id'],row)
    chosen = list(first.values())
    labels = ['E','C1','C2','C3','C4','W1','W2','W3','X1','X2','X3','Y']
    observations = np.asarray([[plan['families'].index(row['family']),
        *[int(row['arm']==arm) for arm in range(1,5)],*tasks[row['task_unit_id']]['initial_states'],
        *row['prepared'],row['y']] for row in chosen])
    ci = ConditionalPermutation(observations,labels,plan['ci_draws'],[plan['schedule_seed'],*coordinates,'structure'])
    graphs = {name:backend.search(labels,name,ci,plan['ci_alpha']) for name in ('time','jci')}
    return dict(labels=labels,task_ids=[row['task_unit_id'] for row in chosen],
        request_ids=[row['request_id'] for row in chosen],graphs=graphs,queries=list(ci.cache.values()))


def graph_masks(graph, adjacency=False):
    ancestry = np.asarray(graph['ancestry'])
    pag = np.asarray(graph['pag'])
    if ancestry.shape!=(12,12) or pag.shape!=(12,12):
        raise ValueError('跨环境结构维度无效')
    if adjacency:
        masks = [sum(1<<bit for bit in range(3) if pag[5+bit,-1]!=0),7]
    else:
        masks = [sum(1<<bit for bit in range(3) if ancestry[5+bit,-1]==1),
                 sum(1<<bit for bit in range(3) if ancestry[5+bit,-1]!=-1),7]
    return list(dict.fromkeys(masks))


def stability_proposals(scores, tasks, source_families, plan):
    identities = scores['task_ids']
    values = np.asarray(scores['scores'])
    ranking = []
    for mask in range(8):
        bits = [bit for bit in range(3) if mask>>bit&1]
        groups = {}
        for index,key in enumerate(identities):
            state = tuple(tasks[key]['initial_states'][bit] for bit in bits)
            groups.setdefault(state,{}).setdefault(tasks[key]['family'],[]).append(index)
        losses,valid = [],True
        for state,environment_groups in groups.items():
            if any(len(environment_groups.get(family,[]))<plan['stability_minimum_task_units'] for family in source_families):
                valid = False
                break
            means = np.asarray([values[environment_groups[family]].mean(axis=0) for family in source_families])
            losses.append(float(np.mean((means-means.mean(axis=0))**2)))
        ranking.append(dict(mask=mask,supported=valid,loss=float(np.mean(losses)) if valid and losses else None))
    eligible = sorted((row for row in ranking if row['supported']),key=lambda row:(row['loss'],row['mask']))
    masks = list(dict.fromkeys([row['mask'] for row in eligible[:plan['candidate_limit']-1]]+[7]))
    return masks,ranking


def learn_transfer(fitting, source_calibration, target_calibration, tasks, structure, target_family, plan):
    nuisance = nuisance_and_scores(fitting,source_calibration,target_calibration,tasks,plan)
    train,source,target = [nuisance[name] for name in ('training','source_calibration','target_calibration')]
    direct,stability = stability_proposals(source,tasks,[name for name in plan['families'] if name!=target_family],plan)
    masks = dict(jci_transfer=graph_masks(structure['graphs']['jci']),
        time_transfer=graph_masks(structure['graphs']['time']),
        adjacency_transfer=graph_masks(structure['graphs']['jci'],True),direct_invariance=direct,direct_full=[7])
    models,groups,cache = [],{},{}
    outcome = np.asarray(train['scores'])
    target_values = np.asarray(target['scores'])
    def get_model(mask,penalty,deviation,shared):
        key = mask,penalty,deviation,shared
        if key not in cache:
            design = effect_design(tasks,train['task_ids'],mask,plan,shared)
            model = fit_effect(design,outcome,np.ones(len(design)),mask,penalty,deviation,shared)
            prediction = effect_scores(model,tasks,source['task_ids'],plan)
            model['source_loss_by_policy'] = np.mean((np.asarray(source['scores'])-prediction)**2,axis=0).tolist()
            cache[key] = len(models)
            models.append(model)
        return cache[key]
    for name in plan['methods']:
        groups[name] = []
        specifications = [(mask,deviation,True) for mask,deviation in itertools.product(masks[name],plan['deviation_penalties'])]
        specifications.append((7,plan['deviation_penalties'][0],False))
        for policy in range(3):
            for mask,deviation,shared in specifications:
                indexes = [get_model(mask,penalty,deviation,shared) for penalty in plan['ridge_penalties']]
                selected = min(indexes,key=lambda index:(models[index]['source_loss_by_policy'][policy],index))
                groups[name].append(dict(policy=policy,mask=mask,deviation=deviation,shared=shared,
                    model_ids=indexes,selected_model_id=selected))
    candidates,choices = {},{}
    score_cache = {index:effect_scores(model,tasks,target['task_ids'],plan) for index,model in enumerate(models)}
    for name in plan['methods']:
        options = []
        combinations = []
        for deviation in plan['deviation_penalties']:
            per_policy = [[group['selected_model_id'] for group in groups[name]
                if group['policy']==policy and group['shared'] and group['deviation']==deviation] for policy in range(3)]
            combinations.extend(itertools.product(*per_policy))
        combinations.append(tuple(next(group['selected_model_id'] for group in groups[name]
            if group['policy']==policy and not group['shared']) for policy in range(3)))
        for indexes in dict.fromkeys(combinations):
            scores = np.column_stack([score_cache[index][:,policy] for policy,index in enumerate(indexes)])
            for threshold in plan['edit_thresholds']:
                actions = actions_for(scores,threshold)
                gain = float(np.column_stack((np.zeros(len(actions)),target_values))[np.arange(len(actions)),actions].mean())
                options.append(dict(model_ids=list(indexes),threshold=threshold,calibration_gain=gain))
        candidates[name] = options
        best = max(options,key=lambda row:(row['calibration_gain'],tuple(-index for index in row['model_ids']),-row['threshold']))
        choices[name] = best if best['calibration_gain']>0 else dict(model_ids=None,threshold=None,calibration_gain=0.)
    return dict(nuisance=nuisance,masks=masks,stability=stability,models=models,fit_groups=groups,
        policy_candidates=candidates,choices=choices,source_training_task_units=len(train['task_ids']))

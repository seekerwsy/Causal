from __future__ import annotations

import itertools

import numpy as np
import networkx as nx
from scipy.stats import binom

from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation


LABELS = ['E','A','W','Z1','Z2','Y']
SCENARIOS = ['shared','hidden_wording','latent_confounding','no_overlap',
             'effect_cancellation','near_threshold']
VERSIONS = np.asarray(list(itertools.product((0,1),repeat=2)))


def version_probabilities(w, u, e, scenario):
    w, u, e = np.broadcast_arrays(w,u,e)
    p1 = .25+.5*e
    if scenario == 'latent_confounding':
        p1 = .15+.4*e+.25*u+.1*w
    if scenario == 'no_overlap':
        p1 = e.astype(float)
    p2 = .2+.6*u
    return np.prod(np.where(VERSIONS[None,:,:],
        np.column_stack((p1,p2))[:,None,:],
        1-np.column_stack((p1,p2))[:,None,:]),axis=2)


def response_probability(w, u, a, e, z, hypothesis, scenario):
    beta = [.18,.10,.03,-.06][hypothesis]
    if scenario == 'near_threshold':
        beta = [.055,.045,.035,-.02][hypothesis]
    if scenario == 'effect_cancellation' and hypothesis == 0:
        beta = .18*(2*np.asarray(w)-1)
    probability = .28+.06*w+.08*u+.07*z[...,0]+.04*z[...,1]
    probability = probability+a*(beta+.04*(2*np.asarray(w)-1))
    if scenario == 'hidden_wording':
        probability = probability+.14*e*(2*np.asarray(a)-1)
    if not np.isfinite(probability).all() or np.any((probability<0)|(probability>1)):
        raise ValueError('机制模拟结果概率无效')
    return probability


def draw_tasks(rng, size, hypothesis, scenario, role, target_only=False):
    w, u = rng.integers(0,2,size=(2,size))
    a = rng.integers(0,2,size)
    e = np.zeros(size,dtype=int) if target_only else rng.integers(0,2,size)
    pools = np.asarray([version_probabilities(w,u,np.full(size,index),scenario) for index in (0,1)]).transpose(1,0,2)
    v = np.asarray([rng.choice(4,p=q) for q in pools[np.arange(size),e]])
    z = VERSIONS[v]
    probability = response_probability(w,u,a,e,z,hypothesis,scenario)
    y = rng.binomial(1,probability)
    return dict(task_ids=[f'{scenario}/{hypothesis}/{role}/{index}' for index in range(size)],
        w=w.tolist(),u=u.tolist(),a=a.tolist(),e=e.tolist(),z=z.tolist(),y=y.tolist(),
        target_weights=pools[:,0].tolist(),propensity=.5 if target_only else .25)


def observation_matrix(data):
    return np.column_stack([data['e'],data['a'],data['w'],data['z'],data['y']])


def exact_population(hypothesis, scenario):
    observations, weights = [], []
    for w,u,a,e in itertools.product((0,1),repeat=4):
        q = version_probabilities(np.array([w]),np.array([u]),np.array([e]),scenario)[0]
        for v,z in enumerate(VERSIONS):
            p = float(response_probability(w,u,a,e,z,hypothesis,scenario))
            for y in (0,1):
                if q[v] > 0:
                    observations.append([e,a,w,*z,y])
                    weights.append(q[v]*(p if y else 1-p)/16)
    return np.asarray(observations), np.asarray(weights)


class PopulationIndependence:
    def __init__(self, observations, weights):
        self.observations, self.weights, self.cache = observations,weights,{}

    def query(self,x,y,conditioned):
        key = (*sorted((x,y)),tuple(sorted(conditioned)))
        if key in self.cache:
            return self.cache[key]['p']
        columns = [LABELS.index(name) for name in conditioned]
        groups = np.unique(self.observations[:,columns],axis=0,return_inverse=True)[1] if columns else np.zeros(len(self.weights),dtype=int)
        maximum, supported = 0.,True
        for group in np.unique(groups):
            chosen = groups==group
            table = np.zeros((2,2))
            np.add.at(table,(self.observations[chosen,LABELS.index(x)],
                             self.observations[chosen,LABELS.index(y)]),self.weights[chosen])
            if np.any(table.sum(0)==0) or np.any(table.sum(1)==0):
                supported = False
            expected = np.outer(table.sum(1),table.sum(0))/table.sum()
            maximum = max(maximum,float(np.max(np.abs(table-expected))))
        p = (1. if maximum<1e-12 else 0.) if supported else None
        self.cache[key] = dict(x=x,y=y,conditioned=list(conditioned),p=p,
            status='tested' if supported else 'insufficient_support',maximum_gap=maximum)
        return p


class GraphIndependence(PopulationIndependence):
    def __init__(self, observations, weights, scenario):
        super().__init__(observations,weights)
        self.graph = nx.DiGraph([('E','Z1'),('U','Z2'),('U','Y'),('W','Y'),
                                ('A','Y'),('Z1','Y'),('Z2','Y')])
        if scenario == 'latent_confounding':
            self.graph.add_edges_from([('U','Z1'),('W','Z1')])
        if scenario == 'hidden_wording':
            self.graph.add_edge('E','Y')

    def query(self,x,y,conditioned):
        supported = super().query(x,y,conditioned)
        if supported is None:
            return None
        p = float(nx.is_d_separator(self.graph,{x},{y},set(conditioned)))
        key = (*sorted((x,y)),tuple(sorted(conditioned)))
        self.cache[key]['p'] = p
        return p


def conditioning(mask):
    return ['A','W']+[f'Z{bit+1}' for bit in range(2) if mask>>bit&1]


def overlap(data, mask, minimum, epsilon):
    groups = {}
    for a,w,z,e in zip(data['a'],data['w'],data['z'],data['e'],strict=True):
        key = (a,w,*[z[bit] for bit in range(2) if mask>>bit&1])
        groups.setdefault(key,[0,0])[e] += 1
    required = list(itertools.product((0,1),repeat=2+mask.bit_count()))
    cells = []
    supported = True
    for key in required:
        counts = groups.get(key,[0,0])
        fraction = counts[1]/sum(counts) if sum(counts) else None
        valid = min(counts)>=minimum and epsilon<=fraction<=1-epsilon if fraction is not None else False
        supported = supported and valid
        cells.append(dict(cell=list(key),counts=counts,auxiliary_fraction=fraction,supported=valid))
    return dict(supported=supported,cells=cells)


def sharing_queries(ci, data, plan):
    results = []
    for mask in range(4):
        support = overlap(data,mask,plan['minimum_per_environment'],plan['overlap_epsilon'])
        p = ci.query('E','Y',conditioning(mask))
        results.append(dict(mask=mask,conditioned=conditioning(mask),p=p,overlap=support,
            candidate=bool(support['supported'] and p is not None and p>plan['ci_alpha'])))
    return results


def graph_proposals(graph, queries):
    proposed = []
    if graph['status']=='evaluated' and graph['pag'][0][-1] == 0:
        for separating in graph['separating_sets']:
            if all(name in ('A','W','Z1','Z2') for name in separating):
                mask = sum(1<<bit for bit in range(2) if f'Z{bit+1}' in separating)
                if queries[mask]['candidate']:
                    proposed.append(mask)
    return sorted(set(proposed))


def fit_cells(data, mask=None, target_only=False):
    cells = {}
    for a,e,w,z,y in zip(data['a'],data['e'],data['w'],data['z'],data['y'],strict=True):
        if target_only and e != 0:
            continue
        key = (a,w,*z) if mask is None else (a,w,*[z[bit] for bit in range(2) if mask>>bit&1])
        if mask is None and not target_only:
            key = (e,*key)
        total,successes = cells.get(key,(0,0))
        cells[key] = (total+1,successes+y)
    return dict(mask=mask,target_only=target_only,
        cells=[dict(key=list(key),count=n,successes=s,prediction=(s+.5)/(n+1)) for key,(n,s) in sorted(cells.items())])


def predict_cells(model, a, e, w, z):
    a,e,w = np.broadcast_arrays(a,e,w)
    z = np.broadcast_to(z,(*a.shape,2))
    cells = {tuple(row['key']):row['prediction'] for row in model['cells']}
    values = []
    for av,ev,wv,zv in zip(a.flat,e.flat,w.flat,z.reshape(-1,2),strict=True):
        key = (int(av),int(wv),*map(int,zv)) if model['mask'] is None else (
            int(av),int(wv),*[int(zv[bit]) for bit in range(2) if model['mask']>>bit&1])
        if model['mask'] is None and not model['target_only']:
            key = (int(ev),*key)
        # Beta(1/2,1/2) 先验同时定义空单元的预测。
        values.append(cells.get(key,.5))
    return np.asarray(values).reshape(a.shape)


def corrected_scores(data, model):
    w,a,e,y,z = [np.asarray(data[name]) for name in ('w','a','e','y','z')]
    n = len(w)
    integrated = np.asarray([np.sum(np.asarray(data['target_weights'])*predict_cells(
        model,np.full((n,4),arm),np.zeros((n,4),dtype=int),np.broadcast_to(w[:,None],(n,4)),
        np.broadcast_to(VERSIONS,(n,4,2))),axis=1) for arm in (0,1)]).T
    observed = predict_cells(model,a,e,w,z)
    scores = integrated.copy()
    for arm in (0,1):
        scores[:,arm] += ((a==arm)&(e==0))*(y-observed)/data['propensity']
    return dict(integrated=integrated.tolist(),observed=observed.tolist(),scores=scores.tolist(),
        effect=float(np.mean(scores[:,1]-scores[:,0])),
        standard_error=float(np.std(scores[:,1]-scores[:,0],ddof=1)/np.sqrt(n)))


def select_models(discovery, calibration, ranking, proposals):
    models = [fit_cells(discovery,None,True),fit_cells(discovery,None,False)]
    mask_ids = {}
    for mask in range(4):
        mask_ids[mask] = len(models)
        models.append(fit_cells(discovery,mask))
    target = np.asarray(calibration['e'])==0
    if not target.any():
        raise ValueError('Calibration data 缺少目标环境观测')
    losses = []
    for model in models:
        prediction = predict_cells(model,*[np.asarray(calibration[name]) for name in ('a','e','w','z')])
        losses.append(float(np.mean((np.asarray(calibration['y'])[target]-prediction[target])**2)))
    groups = {'target_only':[0],'unshared':[1],'pooled_full':[mask_ids[3]],
              **{name:[1]+[mask_ids[mask] for mask in masks] for name,masks in proposals.items()}}
    choices = {name:min(ids,key=lambda index:(losses[index],index)) for name,ids in groups.items()}
    estimates = {name:corrected_scores(ranking,models[index]) for name,index in choices.items()}
    return dict(models=models,target_prediction_losses=losses,groups=groups,choices=choices,estimates=estimates)


def exact_correction_check(hypothesis, scenario):
    maximum = 0.
    conditional_maximum = 0.
    for w,u,arm in itertools.product((0,1),repeat=3):
        q = version_probabilities(np.array([w]),np.array([u]),np.array([0]),scenario)[0]
        truth = np.asarray([response_probability(w,u,arm,0,z,hypothesis,scenario) for z in VERSIONS])
        # 任意错误预测用于穷举随机化恒等式，不作为实验观测。
        prediction = np.asarray([.9,.1,.8,.2]) if arm else np.asarray([.1,.9,.2,.8])
        integrated = float(q@prediction)
        expectation = 0.
        for a,e,v in itertools.product((0,1),(0,1),range(4)):
            probability = response_probability(w,u,a,e,VERSIONS[v],hypothesis,scenario)
            weights = version_probabilities(np.array([w]),np.array([u]),np.array([e]),scenario)[0]
            contribution = integrated+(4*(probability-prediction[v]) if a==arm and e==0 else 0.)
            expectation += .25*weights[v]*contribution
        maximum = max(maximum,abs(expectation-float(q@truth)))
        conditional_maximum = max(conditional_maximum,abs(integrated-float(q@truth)))
    return dict(maximum_corrected_bias=maximum,maximum_uncorrected_bias=conditional_maximum)


def true_target_effect(hypothesis, scenario):
    values = []
    for w,u in itertools.product((0,1),repeat=2):
        q = version_probabilities(np.array([w]),np.array([u]),np.array([0]),scenario)[0]
        effect = [response_probability(w,u,1,0,z,hypothesis,scenario)-
                  response_probability(w,u,0,0,z,hypothesis,scenario) for z in VERSIONS]
        values.append(q@effect)
    return float(np.mean(values))


def paired_difference_probabilities(hypothesis,scenario):
    minus,plus = 0.,0.
    for w,u in itertools.product((0,1),repeat=2):
        q = version_probabilities(np.array([w]),np.array([u]),np.array([0]),scenario)[0]
        mu = [sum(q[v]*response_probability(w,u,a,0,z,hypothesis,scenario)
                  for v,z in enumerate(VERSIONS)) for a in (0,1)]
        minus += .25*mu[0]*(1-mu[1])
        plus += .25*mu[1]*(1-mu[0])
    return dict(minus=minus,zero=1-minus-plus,plus=plus)


def confirmation_power(probabilities,size,plan):
    active = probabilities['minus']+probabilities['plus']
    count = np.arange(size+1)
    radius = np.sqrt(2*np.log(2*plan['hypotheses']/plan['confirmation_alpha'])/size)
    cutoff = np.floor((count+size*(plan['practical_effect']+radius))/2).astype(int)
    mass = binom.pmf(count,size,active)
    if abs(mass.sum()-1)>1e-8:
        raise ValueError('确认能力计算的二项分布质量不完整')
    return float(mass@binom.sf(cutoff,count,probabilities['plus']/active))

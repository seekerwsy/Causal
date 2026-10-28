from __future__ import annotations

import hashlib
import itertools
import json

import numpy as np


def random_stream(seed, *coordinates):
    digest = hashlib.sha256(json.dumps([seed, *coordinates]).encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], 'big'))


def all_states(width):
    return np.asarray(list(itertools.product((0, 1), repeat=width)), dtype=int)


def full_basis(w):
    transformed = 2*np.asarray(w)-1
    return np.column_stack([np.prod(transformed[:, [j for j in range(w.shape[1]) if mask >> j & 1]], axis=1)
                            for mask in range(1, 1 << w.shape[1])])


def contrast_features(w, factorized):
    w = np.asarray(w)
    n, width = w.shape
    blocks = []
    for policy in range(width):
        terms = (1-w[:, policy])[:, None]
        if not factorized:
            terms = np.column_stack((terms, terms*w[:, np.arange(width) != policy]))
        block = np.zeros((n, width, terms.shape[1]*width))
        block[:, policy, policy*terms.shape[1]:(policy+1)*terms.shape[1]] = terms
        blocks.append(block)
    return sum(blocks)


def select_actions(scores):
    scores = np.asarray(scores)
    if scores.ndim != 2 or not np.isfinite(scores).all():
        raise ValueError('完整候选分数无效')
    extended = np.column_stack((np.zeros(len(scores)), scores))
    return np.argmax(extended, axis=1)


def exact_policy_value(scores, beta, plan):
    states = all_states(len(beta))
    actions = select_actions(np.asarray(scores))
    if len(actions) != len(states):
        raise ValueError('有限状态评价任务不完整')
    specification = plan['simulation']
    gains, values, regrets = [], [], []
    for latent, source_probability in enumerate(specification['source_probability_by_latent']):
        weights = .5*np.prod(np.where(states, source_probability, 1-source_probability), axis=1)
        effects = (1-states)*beta
        gain = np.column_stack((np.zeros(len(states)), effects))[np.arange(len(states)), actions]
        baseline = specification['baseline_probability']+specification['latent_outcome_coefficient']*latent+states@beta
        gains.append(float(weights@gain))
        values.append(float(weights@(baseline+gain)))
        regrets.append(float(weights@(np.maximum(0, effects.max(axis=1))-gain)))
    return dict(gain=sum(gains), value=sum(values), regret=sum(regrets), actions=actions.tolist())

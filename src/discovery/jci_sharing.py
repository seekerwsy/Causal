from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import time

import numpy as np
from scipy.stats import random_table, t
from sklearn.linear_model import Ridge


STATES = np.asarray(list(itertools.product((0, 1), repeat=3)), dtype=int)


def basis(w, mask=7):
    w = np.asarray(w, dtype=float)
    if w.ndim != 2 or w.shape[1] != 3 or not np.isin(w, (0, 1)).all():
        raise ValueError('来源属性必须是完整的三个二元状态')
    selected = [subset for subset in range(8) if subset & mask == subset]
    z = 2*w-1
    return np.column_stack([np.prod(z[:, [j for j in range(3) if subset >> j & 1]], axis=1)
                            for subset in selected])


def mechanism_parameters(name, e, w, latent=None):
    w = np.asarray(w)
    if name == 'baseline_shift':
        baseline = .30+.10*w[:, 1]+.05*e
        gamma = np.full(len(w), .25)
    elif name == 'scope_sign':
        baseline = .50+.04*e+.05*w[:, 2]
        gamma = .30*(2*w[:, 1]-1)
    elif name == 'effect_shift':
        baseline = .45+.04*w[:, 2]+.02*e
        gamma = np.full(len(w), .30-.15*e)
    elif name == 'proxy_shift':
        baseline = .45+.05*w[:, 2]+.02*e
        gamma = .25*(2*latent-1) if latent is not None else (
            .25*(2*(.95, .75, .55, .15)[e]-1)*(2*w[:, 1]-1))
    else:
        raise ValueError('未冻结的计算机制')
    if np.any(baseline < 0) or np.any(baseline > 1) or np.any(baseline+gamma < 0) or np.any(baseline+gamma > 1):
        raise ValueError('计算机制的概率超出定义范围')
    return baseline, gamma


def state_probabilities(e):
    p = (.15, .25, .35, .40)[e]
    return np.where(STATES[:, 0], p, 1-p)*.25


def draw_tasks(plan, mechanism, n, repetition, stage):
    parts = []
    for e in plan['training_environments']:
        rng = np.random.default_rng(np.random.SeedSequence([
            plan['seed'], plan['mechanisms'].index(mechanism), n, repetition, stage, e]))
        w = rng.integers(0, 2, (n, 3))
        w[:, 0] = rng.random(n) < (.15, .25, .35, .40)[e]
        latent = rng.integers(0, 2, n)
        if mechanism == 'proxy_shift':
            w[:, 1] = np.bitwise_xor(latent, rng.random(n) >= (.95, .75, .55, .15)[e])
        fidelity_probability = (np.asarray(plan['proxy_fidelity_by_latent'])[latent]
                                if mechanism == 'proxy_shift' else plan['preparation_fidelity'])
        fidelity = rng.random(n) < fidelity_probability
        states = np.column_stack((w[:, 0], np.bitwise_xor(w[:, 0], fidelity)))
        baseline, gamma = mechanism_parameters(mechanism, e, w, latent)
        probabilities = baseline[:, None]+states*gamma[:, None]
        outcomes = (rng.random((n, 2, plan['generations_per_arm'])) < probabilities[:, :, None]).astype(int)
        outcomes[~fidelity, 1] = outcomes[~fidelity, 0]
        a = rng.integers(0, 2, n)
        parts.append(dict(w=w, e=np.full(n, e), delta=outcomes[:, 1].mean(1)-outcomes[:, 0].mean(1),
                          a=a, x=states[np.arange(n), a], y=outcomes[np.arange(n), a, 0],
                          fidelity=fidelity.astype(int), states=states, outcomes=outcomes,
                          task_ids=[f'{mechanism}/{n}/{repetition}/{stage}/{e}/{i}' for i in range(n)]))
    return {key: (sum((part[key] for part in parts), []) if key == 'task_ids'
                  else np.concatenate([part[key] for part in parts])) for key in parts[0]}


class ConditionalPermutation:
    def __init__(self, data, labels, draws, seed):
        self.data, self.labels = np.asarray(data, dtype=int), tuple(labels)
        self.draws, self.seed, self.cache = draws, seed, {}
        if self.data.shape[1] != len(labels) or draws < 99:
            raise ValueError('条件检验输入或抽样数量无效')

    def query(self, x, y, conditioned):
        x, y = sorted((x, y))
        conditioned = tuple(sorted(conditioned))
        key = (x, y, conditioned)
        if key in self.cache:
            return self.cache[key]['p']
        indexes = {name: i for i, name in enumerate(self.labels)}
        columns = [indexes[name] for name in conditioned]
        _, groups = np.unique(self.data[:, columns], axis=0, return_inverse=True) if columns else (
            None, np.zeros(len(self.data), dtype=int))
        query_seed = int.from_bytes(hashlib.sha256(json.dumps([self.seed, key]).encode()).digest()[:8], 'big')
        rng = np.random.default_rng(query_seed)
        observed, simulated, informative = 0., np.zeros(self.draws), 0
        tables = []
        for group in np.unique(groups):
            rows = self.data[groups == group]
            _, xi = np.unique(rows[:, indexes[x]], return_inverse=True)
            _, yi = np.unique(rows[:, indexes[y]], return_inverse=True)
            table = np.zeros((xi.max()+1, yi.max()+1), dtype=int)
            np.add.at(table, (xi, yi), 1)
            tables.append(table.tolist())
            if min(table.shape) == 1:
                continue
            informative += 1
            expected = np.outer(table.sum(1), table.sum(0))/table.sum()
            observed += float(np.sum((table-expected)**2/expected))
            null = random_table.rvs(table.sum(1), table.sum(0), size=self.draws, random_state=rng)
            simulated += np.sum((null-expected)**2/expected, axis=(1, 2))
        exceedances = int(np.count_nonzero(simulated >= observed-1e-12))
        p = (1+exceedances)/(1+self.draws)
        self.cache[key] = dict(x=x, y=y, conditioned=list(conditioned), p=p, statistic=observed,
                               informative_strata=informative, tables=tables, exceedances=exceedances)
        return p


class StructureBackend:
    def __init__(self, rscript, log, r_source=None):
        environment = dict(os.environ, LC_ALL='C', LANG='C', LC_COLLATE='C', LC_CTYPE='C',
                           LC_MONETARY='C', LC_TIME='C')
        self.log = log.open('x', encoding='utf-8')
        source = Path(__file__).with_suffix('.R') if r_source is None else Path(r_source)
        self.process = subprocess.Popen([str(rscript), str(source)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding='utf-8',
            env=environment)

    def search(self, labels, method, ci, alpha):
        started = time.monotonic()
        self.process.stdin.write(json.dumps(dict(labels=labels, method=method, alpha=alpha))+'\n')
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(f'真实 FCI 后端终止，退出状态 {self.process.poll()}；请核对后端日志')
            answer = json.loads(line)
            if answer['type'] == 'result':
                answer['seconds'] = time.monotonic()-started
                return answer
            if answer['type'] != 'query':
                raise ValueError('结构后端返回了未规定的记录')
            p = ci.query(answer['x'], answer['y'], answer['conditioned'])
            self.process.stdin.write(json.dumps(dict(p=p))+'\n')
            self.process.stdin.flush()

    def close(self):
        self.process.stdin.close()
        code = self.process.wait(timeout=30)
        self.log.close()
        if code:
            raise RuntimeError(f'结构后端退出状态异常：{code}')


def qualification(calibration, plan):
    cells = {}
    for e in plan['training_environments']:
        for state in STATES:
            values = calibration['delta'][(calibration['e'] == e) & np.all(calibration['w'] == state, axis=1)]
            cells[(e, tuple(state))] = dict(n=len(values), mean=float(values.mean()) if len(values) else None,
                                           variance=float(values.var(ddof=1)) if len(values) > 1 else None)
    # 同一冻结检验族包括全部属性子集，结构方法不缩小多重比较分母。
    comparisons = []
    environments = plan['training_environments']
    for mask in range(8):
        dimensions = [j for j in range(3) if mask >> j & 1]
        keys = sorted({tuple(state[dimensions]) for state in STATES})
        for key in keys:
            matching = [tuple(state) for state in STATES if tuple(state[dimensions]) == key]
            # 共同均匀来源权重使条件分布变化不会被混同为效果变化。
            for e1, e2 in itertools.combinations(environments, 2):
                comparisons.append((mask, 'invariance', [(e1, s, 1/len(matching)) for s in matching]
                                     +[(e2, s, -1/len(matching)) for s in matching]))
            for e in environments:
                for first, second in itertools.combinations(matching, 2):
                    comparisons.append((mask, 'sufficiency', [(e, first, 1.), (e, second, -1.)]))
    records = {mask: [] for mask in range(8)}
    total = len(comparisons)
    for mask, kind, terms in comparisons:
        if any(cells[(e, state)]['n'] < plan['minimum_cell_tasks'] for e, state, _ in terms):
            records[mask].append(dict(kind=kind, status='insufficient_support'))
            continue
        mean = sum(coefficient*cells[(e, state)]['mean'] for e, state, coefficient in terms)
        variance = sum(coefficient**2*cells[(e, state)]['variance']/cells[(e, state)]['n']
                       for e, state, coefficient in terms)
        degrees = min(cells[(e, state)]['n']-1 for e, state, _ in terms)
        radius = float(t.ppf(1-plan['qualification_alpha']/(2*total), degrees)*np.sqrt(variance))
        low, high, margin = mean-radius, mean+radius, plan['sharing_margin']
        status = 'qualified' if low >= -margin and high <= margin else (
            'refuted' if low > margin or high < -margin else 'unresolved')
        records[mask].append(dict(kind=kind, status=status, mean=mean, low=low, high=high))
    return {str(mask): dict(status=('qualified' if all(row['status'] == 'qualified' for row in rows)
                                  else 'refuted' if any(row['status'] == 'refuted' for row in rows)
                                  else 'unresolved'), comparisons=rows, family_size=total)
            for mask, rows in records.items()}


def design_matrix(w, e, mask, environments):
    shared = basis(w, mask)
    full = basis(w)
    deviations = np.column_stack([full*(np.asarray(e) == environment)[:, None] for environment in environments])
    return np.column_stack((shared[:, 1:], deviations))


def fit_effect_model(training, mask, penalty, environment_penalty, environments):
    design = design_matrix(training['w'], training['e'], mask, environments)
    shared_width = basis(training['w'], mask).shape[1]-1
    penalties = np.r_[np.full(shared_width, penalty), np.full(design.shape[1]-shared_width, environment_penalty)]
    scale = np.sqrt(penalties)
    learner = Ridge(alpha=1., fit_intercept=True, solver='cholesky')
    learner.fit(design/scale, training['delta'], sample_weight=np.full(len(design), 1/len(design)))
    return dict(mask=mask, penalty=penalty, environment_penalty=environment_penalty,
                environments=list(environments), intercept=float(learner.intercept_),
                coefficients=(learner.coef_/scale).tolist())


def predict_effect(model, w, e):
    design = design_matrix(w, e, model['mask'], model['environments'])
    return design@np.asarray(model['coefficients'])+model['intercept']


def select_models(training, calibration, proposals, qualifications, plan):
    masks = sorted(set().union(*map(set, proposals.values())))
    fitted = []
    for mask, penalty, environment_penalty in itertools.product(masks, plan['ridge_penalties'], plan['environment_penalties']):
        model = fit_effect_model(training, mask, penalty, environment_penalty, plan['training_environments'])
        prediction = predict_effect(model, calibration['w'], calibration['e'])
        for threshold in plan['thresholds']:
            actions = np.zeros(len(prediction), dtype=bool) if threshold is None else prediction > threshold
            if 'identity_zero' in calibration:
                actions &= ~calibration['identity_zero']
            elif 'fidelity' in calibration:
                actions &= calibration['fidelity'].astype(bool)
            model_value = float(np.mean(actions*calibration['delta']))
            fitted.append(dict(model=model, threshold=threshold, calibration_value=model_value))
    choices = {}
    for name, allowed in proposals.items():
        eligible = [row for row in fitted if row['model']['mask'] in allowed and (
            not name.endswith('_checked') or qualifications[str(row['model']['mask'])]['status'] == 'qualified')]
        if not eligible:
            choices[name] = dict(model=None, threshold=None, calibration_value=0., status='no_qualified_sharing_set')
            continue
        selected = max(eligible, key=lambda row: (row['calibration_value'],
            2. if row['threshold'] is None else row['threshold'], row['model']['environment_penalty'],
            row['model']['penalty'], -row['model']['mask'].bit_count(), -row['model']['mask']))
        choices[name] = dict(selected, status='selected')
    return choices, fitted


def actions_for(choice, w, e):
    if choice['model'] is None or choice['threshold'] is None:
        return np.zeros(len(w), dtype=int)
    return (predict_effect(choice['model'], w, e) > choice['threshold']).astype(int)


def exact_value(choice, mechanism, e, plan):
    baseline, gamma = mechanism_parameters(mechanism, e, STATES)
    tau = plan['preparation_fidelity']*(1-2*STATES[:, 0])*gamma
    if mechanism == 'proxy_shift':
        q = (.95, .75, .55, .15)[e]
        posterior = np.where(STATES[:, 1], q, 1-q)
        low, high = plan['proxy_fidelity_by_latent']
        tau = (1-2*STATES[:, 0])*.25*(high*posterior-low*(1-posterior))
    original = baseline+STATES[:, 0]*gamma
    weights = state_probabilities(e)
    actions = actions_for(choice, STATES, np.full(8, e))
    gain = float(weights@(actions*tau))
    optimum = float(weights@np.maximum(tau, 0))
    return dict(gain=gain, value=float(weights@original)+gain, regret=optimum-gain,
                optimal_gain=optimum, actions=actions.tolist(), tau=tau.tolist(), weights=weights.tolist())


def recalibrate_shared_component(saved, plan):
    calibration = {key: np.asarray(value) if key != 'task_ids' else value
                   for key, value in saved['calibration'].items()}
    predictions = {}
    views = {}
    for view_name, view in saved['views'].items():
        candidates = []
        for original in view['calibration_candidates']:
            model, threshold = original['model'], original['threshold']
            key = model['mask'], model['penalty'], model['environment_penalty']
            if key not in predictions:
                predictions[key] = predict_effect(model, calibration['w'], np.full(len(calibration['w']), -1))
            action = np.zeros(len(calibration['w']), dtype=bool) if threshold is None else predictions[key] > threshold
            action &= calibration['fidelity'].astype(bool)
            candidates.append(dict(model=model, threshold=threshold,
                                   calibration_value=float(np.mean(action*calibration['delta']))))
        proposals = dict(full=[7], direct_checked=list(range(8)),
                         time_checked=view['structure']['results']['time']['proposals'],
                         jci_checked=view['structure']['results']['jci']['proposals'],
                         jci_unchecked=view['structure']['results']['jci']['proposals'])
        choices = {}
        for name, masks in proposals.items():
            eligible = [row for row in candidates if row['model']['mask'] in masks and (
                not name.endswith('_checked') or row['model']['mask'] == 7 or
                saved['qualification'][str(row['model']['mask'])]['status'] == 'qualified')]
            selected = max(eligible, key=lambda row: (row['calibration_value'],
                2. if row['threshold'] is None else row['threshold'], row['model']['environment_penalty'],
                row['model']['penalty'], -row['model']['mask'].bit_count(), -row['model']['mask']))
            choices[name] = dict(selected, status='selected',
                sharing_qualified=saved['qualification'][str(selected['model']['mask'])]['status'] == 'qualified')
        views[view_name] = dict(choices=choices,
            values={name: {str(e): exact_value(choice, saved['mechanism'], e, plan) for e in range(4)}
                    for name, choice in choices.items()}, calibration_candidates=candidates)
    return dict(mechanism=saved['mechanism'], n=saved['n'], repetition=saved['repetition'], views=views)

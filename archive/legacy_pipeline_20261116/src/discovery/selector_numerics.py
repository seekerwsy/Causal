"""Shared numerical solver for Discovery ranking, never confirmatory verification."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence

import numpy as np


def sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-min(value, 700.0)))
    exponential = math.exp(max(value, -700.0))
    return exponential / (1.0 + exponential)


def fit_ridge_logit(
    design: Sequence[Sequence[float]],
    outcomes: Sequence[int],
    ridge_lambda: float,
    *,
    maximum_iterations: int,
) -> list[float]:
    """Fit an already constructed design; column zero is an unpenalized intercept.

    The Atomic caller supplies standardization, design columns and iteration limits.
    Row order and floating-point accumulation are preserved for reproducibility.
    """
    width = len(design[0]) if design else 1
    weights = [0.0] * width
    max_norm = max((sum(value * value for value in row) for row in design), default=1.0)
    step = 1.0 / (0.25 * max_norm + ridge_lambda + 1.0)
    for _ in range(maximum_iterations):
        gradient = [0.0] * width
        for row, outcome in zip(design, outcomes, strict=True):
            probability = sigmoid(
                sum(weight * value for weight, value in zip(weights, row, strict=True))
            )
            for index, value in enumerate(row):
                gradient[index] += (probability - outcome) * value / len(design)
        for index in range(1, width):
            gradient[index] += ridge_lambda * weights[index]
        updated = [weight - step * value for weight, value in zip(weights, gradient, strict=True)]
        if max(abs(left - right) for left, right in zip(updated, weights, strict=True)) < 1e-10:
            weights = updated
            break
        weights = updated
    return weights


class TaskEqualRidge:
    def __init__(self, feature_kinds, penalty, minimum_task_support=4):
        if any(kind not in ('discrete', 'continuous') for kind in feature_kinds) or penalty <= 0:
            raise ValueError('Ridge 属性定义或惩罚值无效')
        self.feature_kinds, self.penalty = tuple(feature_kinds), float(penalty)
        if type(minimum_task_support) is not int or minimum_task_support < 1:
            raise ValueError('属性取值的最小任务支持无效')
        self.minimum_task_support = minimum_task_support

    def fit(self, rows):
        if not rows:
            raise ValueError('缺少训练政策')
        identities = np.asarray([row['task_unit_id'] for row in rows])
        self.tasks = sorted(set(identities))
        counts = Counter(identities)
        weights = np.asarray([1 / counts[identity] for identity in identities]) / len(self.tasks)
        x = np.asarray([row['features'] for row in rows], dtype=float)
        y = np.asarray([row['delta_pn'] for row in rows], dtype=float)
        if (x.shape != (len(rows), len(self.feature_kinds)) or np.isinf(x).any()
                or not np.isfinite(y).all() or np.any(abs(y) > 1)):
            raise ValueError('属性矩阵或完整政策效果无效')
        self.allowed, self.means, self.scales, self.retained = [], [], [], []
        for index, kind in enumerate(self.feature_kinds):
            column = x[:, index].copy()
            finite = np.isfinite(column)
            values = None
            if kind == 'discrete':
                values = [float(value) for value in np.unique(column[finite])
                          if len(set(identities[column == value])) >= self.minimum_task_support]
                finite &= np.isin(column, values)
            elif len(set(identities[finite])) < self.minimum_task_support:
                finite[:] = False
            mean = float(np.average(column[finite], weights=weights[finite])) if finite.any() else 0.
            filled = np.where(finite, column, mean)
            variance = float(np.sum(weights*(filled-mean)**2))
            self.allowed.append(values)
            self.means.append(mean)
            self.scales.append(float(np.sqrt(variance)) if variance > 1e-15 else 1.)
            self.retained.append(variance > 1e-15)
        z = self.transform(rows)
        design = np.column_stack((np.ones(len(rows)), z))
        regularizer = np.eye(design.shape[1])*self.penalty
        regularizer[0, 0] = 0
        self.coefficients = np.linalg.solve(design.T@(weights[:, None]*design)+regularizer,
                                            design.T@(weights*y))
        return self

    def transform(self, rows):
        x = np.asarray([row['features'] for row in rows], dtype=float)
        if x.shape != (len(rows), len(self.feature_kinds)) or np.isinf(x).any():
            raise ValueError('待预测属性矩阵无效')
        for index, allowed in enumerate(self.allowed):
            invalid = ~np.isfinite(x[:, index])
            if allowed is not None:
                invalid |= ~np.isin(x[:, index], allowed)
            x[invalid, index] = self.means[index]
        return ((x-np.asarray(self.means))/np.asarray(self.scales))[:, self.retained]

    def predict(self, rows):
        design = np.column_stack((np.ones(len(rows)), self.transform(rows)))
        return np.clip(design@self.coefficients, -1., 1.)

    def record(self):
        return dict(penalty=self.penalty, feature_kinds=self.feature_kinds, allowed=self.allowed,
                    means=self.means, scales=self.scales, retained=self.retained,
                    coefficients=self.coefficients.tolist(), training_task_ids=self.tasks)


def fit_task_equal_ridge(rows, feature_kinds, task_folds=None, penalties=(.01, .1, 1., 10.),
                         minimum_task_support=4):
    tasks = sorted({row['task_unit_id'] for row in rows})
    if len(tasks) < 2:
        raise ValueError('完整任务留一验证需要至少两个训练任务')
    if task_folds is not None:
        if set(task_folds) != set(tasks) or set(task_folds.values()) != set(range(5)):
            raise ValueError('固定五折验证必须包含每项完整任务')
        groups = [[identity for identity in tasks if task_folds[identity] == fold] for fold in range(5)]
    else:
        groups = [[identity] for identity in tasks]
    evaluations = []
    for penalty in penalties:
        folds = []
        for identities in groups:
            training = [row for row in rows if row['task_unit_id'] not in identities]
            validation = [row for row in rows if row['task_unit_id'] in identities]
            learner = TaskEqualRidge(feature_kinds, penalty, minimum_task_support).fit(training)
            error = learner.predict(validation)-np.asarray([row['delta_pn'] for row in validation])
            task_errors = [float(np.mean([float(error[index])**2 for index, row in enumerate(validation)
                                          if row['task_unit_id'] == identity])) for identity in identities]
            fold = dict(mse=float(np.mean(task_errors)), retained=learner.retained)
            if task_folds is not None:
                fold['task_unit_ids'] = identities
            else:
                fold['task_unit_id'] = identities[0]
            folds.append(fold)
        task_mean_error = sum(fold['mse']*len(group) for fold, group in zip(folds, groups, strict=True))/len(tasks)
        evaluations.append(dict(penalty=penalty, mse=float(task_mean_error), folds=folds))
    chosen = min(evaluations, key=lambda value: (value['mse'], -value['penalty']))
    return TaskEqualRidge(feature_kinds, chosen['penalty'], minimum_task_support).fit(rows), evaluations

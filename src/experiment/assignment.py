"""Fold-nested randomized assignment satisfying design condition D1 (docs/jci-method.md).

Task units are sorted by `task_unit_id`, assigned to cross-fitting folds by index (`i mod K`),
and randomized *within* each fold: every fold receives floor(n_k/2) units per arm, and an odd
fold's remaining unit is assigned by an independent fair coin. Each fold uses its own RNG
stream, so assignments in fold k are independent of every unit outside fold k, and every unit
has marginal treatment probability exactly 1/2. The fold partition is fixed before assignment
and never depends on outcomes or covariates.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

ASSIGNMENT_SCHEMA = 'fold-nested-complete-randomization-v1'


def task_unit_folds(n: int, folds: int) -> np.ndarray:
    """Deterministic index fold partition shared with task-unit cross-fitting."""
    if folds < 2 or n < folds:
        raise ValueError('fold-nested assignment requires folds >= 2 and n >= folds')
    return np.arange(n) % folds


def assign_fold_nested(task_unit_ids: Sequence[str], folds: int, seed: int) -> dict:
    ids = list(task_unit_ids)
    if any(not isinstance(item, str) or not item for item in ids):
        raise ValueError('task_unit_id values must be non-empty strings')
    if len(set(ids)) != len(ids):
        raise ValueError('task units must be deduplicated before assignment')
    if type(seed) is not int or seed < 0:
        raise ValueError('assignment seed must be a non-negative integer')
    ordered = sorted(ids)
    fold_of = task_unit_folds(len(ordered), folds)
    arms = np.empty(len(ordered), dtype=int)
    for fold in range(folds):
        members = np.flatnonzero(fold_of == fold)
        rng = np.random.default_rng(np.random.SeedSequence([seed, fold]))
        half = len(members) // 2
        block = np.r_[np.ones(half, dtype=int), np.zeros(half, dtype=int)]
        if len(members) % 2:
            block = np.r_[block, rng.integers(0, 2)]
        arms[members] = rng.permutation(block)
    return dict(
        schema=ASSIGNMENT_SCHEMA,
        seed=seed,
        folds=folds,
        assignments=[
            dict(task_unit_id=unit, fold=int(fold), arm=int(arm))
            for unit, fold, arm in zip(ordered, fold_of, arms)
        ],
    )


__all__ = ['ASSIGNMENT_SCHEMA', 'assign_fold_nested', 'task_unit_folds']

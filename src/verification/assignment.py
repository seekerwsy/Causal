"""Independent replay of fold-nested assignment (design condition D1) without production helpers."""

from __future__ import annotations

import numpy as np


def verify_fold_nested_assignment(record: dict) -> dict:
    assert record.get('schema') == 'fold-nested-complete-randomization-v1'
    folds, seed, rows = record['folds'], record['seed'], record['assignments']
    ids = [row['task_unit_id'] for row in rows]
    assert ids == sorted(ids) and len(set(ids)) == len(ids), 'task units must be sorted and unique'
    assert folds >= 2 and len(rows) >= folds
    for index, row in enumerate(rows):
        assert row['fold'] == index % folds, f'fold of {row["task_unit_id"]} is not index-determined'
        assert row['arm'] in (0, 1)
    for fold in range(folds):
        members = [row for row in rows if row['fold'] == fold]
        generator = np.random.default_rng(np.random.SeedSequence([seed, fold]))
        pairs = len(members) // 2
        expected = [1] * pairs + [0] * pairs
        if len(members) % 2:
            expected.append(int(generator.integers(0, 2)))
        expected = generator.permutation(np.asarray(expected, dtype=int)).tolist()
        assert [row['arm'] for row in members] == expected, f'fold {fold} assignment does not replay'
        treated = sum(row['arm'] for row in members)
        assert pairs <= treated <= pairs + len(members) % 2, f'fold {fold} is not within-fold balanced'
    return dict(status='VERIFIED', units=len(rows), folds=folds, treated=sum(row['arm'] for row in rows))


__all__ = ['verify_fold_nested_assignment']

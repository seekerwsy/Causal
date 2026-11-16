from __future__ import annotations

from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery.selector_numerics import fit_task_equal_ridge


def select_policy(candidates, predictions, *, minimum_gain=0.):
    if len(candidates) != len(predictions) or not np.isfinite(predictions).all():
        raise ValueError('候选或共同预测无效')
    if not np.isfinite(minimum_gain) or not 0 <= minimum_gain <= 1 or any(abs(value) > 1 for value in predictions):
        raise ValueError('安全收益及预定阈值必须处于有效范围')
    names = [row['policy'] if 'policy' in row else row['policy_hash'] for row in candidates]
    if any(not isinstance(name, str) or not name or name == 'B' for name in names) or len(set(names)) != len(names):
        raise ValueError('候选政策身份必须唯一且完整')
    scores = dict(zip(names, map(float, predictions), strict=True))
    eligible = [index for index, value in enumerate(predictions) if value > minimum_gain]
    if not eligible:
        return dict(action='B', direction=0, scores=scores, effect=0., objective='safe_yield', minimum_gain=minimum_gain)
    chosen = max(eligible, key=lambda index: float(predictions[index]))
    return dict(action=names[chosen], direction=1, scores=scores, effect=float(predictions[chosen]),
                objective='safe_yield', minimum_gain=minimum_gain)


def controlled_ridge_features(task, policy):
    names = ('local', 'example', 'reference')
    families = ('find', 'grep', 'tar', 'git')
    if policy not in names or task['family'] not in families:
        raise ValueError('辅助预测政策或操作家族未知')
    initial = task['initial_states']
    states, lengths = [], []
    for version in ('1', '2'):
        conditions = task['conditions']['TSG'][version]
        original = task['prompts'][conditions['B']['prompt_hash']]
        edited = task['prompts'][conditions[policy]['prompt_hash']]
        states.append(conditions[policy]['states'])
        changes = sum((b-a)+(d-c) for tag, a, b, c, d
                      in SequenceMatcher(None, original, edited, autojunk=False).get_opcodes() if tag != 'equal')
        lengths.append(min(1., changes / len(original)))
    if states[0] != states[1] or len(initial) != 3:
        raise ValueError('两套表达的辅助预测状态不一致')
    blueprint = task['measurement']['blueprint']
    objects = sum(key.endswith('_query') for key in blueprint)
    features = [*initial, *[a-b for a, b in zip(states[0], initial, strict=True)],
                *[int(policy == name) for name in names],
                *[int(task['family'] == family) for family in families],
                objects, objects, sum(lengths)/2]
    if len(features) != 16 or not np.isfinite(features).all():
        raise ValueError('辅助预测的十六项特征不完整')
    return features


def prepare_safe_decisions(inputs: Path, analysis: Path, output: Path, minimum_gain: float):
    if not np.isfinite(minimum_gain) or not 0 <= minimum_gain <= 1:
        raise ValueError('安全收益及预定阈值必须处于有效范围')
    verify_bundle(inputs)
    verify_bundle(analysis)
    tasks = read_json(inputs / 'tasks.json')
    training = read_json(analysis / 'training-features.json')
    training_ids = {task['task_unit_id'] for task in tasks if task['role'] == 'training'}
    names = ('local', 'example', 'reference')
    positions = {(row['task_unit_id'], row['policy']) for row in training}
    if (len(positions) != len(training) or positions != {(identity, name) for identity in training_ids for name in names}
            or any(len(row['features']) != 16 for row in training)):
        raise ValueError('完整任务及全部候选的随机政策差标签必须保留')
    folds = read_json(inputs / 'task-folds.json')
    learner, validation = fit_task_equal_ridge(training, ['continuous'] * 16, task_folds=folds,
        penalties=(.01, .1, 1., 10., 100.), minimum_task_support=1)
    decisions = []
    for task in tasks:
        if task['role'] != 'evaluation':
            continue
        candidates = [dict(policy=name, features=controlled_ridge_features(task, name)) for name in names]
        gains = learner.predict(candidates).tolist()
        decisions.append(dict(case_id=task['case_id'], task_unit_id=task['task_unit_id'],
            actual_edit_gains=gains, choice=select_policy(candidates, gains, minimum_gain=minimum_gain)))
    counts = Counter(row['choice']['action'] for row in decisions)
    write_bundle(output, {'decisions.json': decisions, 'learner.json': learner.record(),
        'cross-validation.json': validation, 'identity.json': dict(
            evidence_role='POST_HOC_EXPOSED_METHOD_CHECK', objective='actual_edit_minus_baseline_secure_yield',
            minimum_gain=minimum_gain, training_tasks=len(training_ids), training_positions=len(training),
            target_tasks=len(decisions), action_counts=dict(counts), target_tasks_previously_exposed=True,
            evaluation_outcomes_read=False, input_manifest_sha256=file_sha256(inputs / 'manifest.json'),
            analysis_manifest_sha256=file_sha256(analysis / 'manifest.json'),
            implementation_sha256=file_sha256(Path(__file__)),
            numerics_sha256=file_sha256(Path(__file__).with_name('selector_numerics.py')))})
    return dict(action_counts=dict(counts), target_tasks=len(decisions), minimum_gain=minimum_gain)

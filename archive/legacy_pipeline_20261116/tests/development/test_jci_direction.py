from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.experiment.jci_policy import historical_data
from prompt_mechanism_study.verification.jci_policy import verify_joint_policy, verify_learning


PLAN = read_json(Path('data/method/jci-sharing-20261014/direction-plan.json'))
OUTPUT = Path('results/jci-direction-comparison-20261014')


def test_exposed_splits_preserve_physical_requests_and_complete_populations():
    first = historical_data(PLAN, PLAN['exposed_split_seeds'][0])
    second = historical_data(PLAN, PLAN['exposed_split_seeds'][1])
    request_maps = []
    for training, calibration, evaluation, _ in (first, second):
        assert len(training['task_ids']) == len(calibration['task_ids']) == 200
        assert len(evaluation['task_ids']) == 400
        assert set(training['task_ids']).isdisjoint(calibration['task_ids'])
        assert set(training['task_ids']).isdisjoint(evaluation['task_ids'])
        request_maps.append({task: request for data in (training, calibration)
                             for task, request in zip(data['task_ids'], data['request_ids'], strict=True)})
    assert request_maps[0] == request_maps[1]
    assert first[0]['task_ids'] != second[0]['task_ids']
    assert first[2]['task_ids'] == second[2]['task_ids']
    np.testing.assert_array_equal(first[2]['effects'], second[2]['effects'])


def test_executed_direction_comparison_independently_replays_all_scientific_outputs():
    result = verify_joint_policy(OUTPUT)
    assert result['status'] == 'verified'
    assert result['splits'] == 8 and result['original_terminal_requests_checked'] == 400
    assert result['independently_refitted_models'] == 720
    summary = read_json(OUTPUT/'summary'/'result.json')
    assert summary['independent_evaluation_task_units'] == 400
    assert summary['splits_are_independent'] is False
    assert len(summary['primary_comparisons']) == 4


def test_representative_executed_split_replays_equal_budget_direction_consumers():
    record = read_json(OUTPUT/'splits'/str(PLAN['exposed_split_seeds'][0])/'result.json')
    fits, queries = verify_learning(record['training'], record['calibration'], record['evaluation'], record['learned'], PLAN)
    assert fits == 90 and queries > 0
    for method in ('direct_gate', 'direct_ci', 'time', 'jci12', 'jci123', 'jci123_adjacency'):
        assert len(record['learned']['candidates'][method]) == 51
        assert record['learned']['candidates'][method][0]['model'] is None

import pytest

from prompt_mechanism_study.discovery.safe_yield import select_policy


def test_signed_gain_selection_preserves_baseline_threshold_and_ties():
    candidates = [dict(policy=name) for name in ('local', 'example', 'reference')]
    choice = select_policy(candidates, [-.8, .05, .02])
    assert choice['action'] == 'example' and choice['effect'] == .05 and choice['direction'] == 1
    assert select_policy(candidates, [-.8, -.05, 0])['action'] == 'B'
    assert select_policy(candidates, [-.8, .05, .02], minimum_gain=.05)['action'] == 'B'
    assert select_policy(candidates, [.05, .05, .02])['action'] == 'local'
    with pytest.raises(ValueError, match='有效范围'):
        select_policy(candidates, [1.1, .02, .03])

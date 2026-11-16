from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery.jci_reliability import (
    draw_reliability_tasks, exact_conditional_association, exact_joint_distribution, fit_effect_ridge,
)
from prompt_mechanism_study.discovery.policy_value import exact_policy_value, select_actions
from prompt_mechanism_study.verification.jci_policy import independent_value


PLAN = read_json(Path('configs/jci-smoke.json'))
LABELS = ['C1', 'C2', 'C3', 'C4', 'X1', 'X2', 'X3', 'X4', 'Y']


def test_randomization_preserves_task_roles_and_count_outcomes():
    training, beta = draw_reliability_tasks(PLAN, 'cancelling_dense', 128, 8, 0, 0, 'D')
    calibration, other = draw_reliability_tasks(PLAN, 'cancelling_dense', 128, 8, 0, 0, 'CAL')
    np.testing.assert_array_equal(beta, other)
    assert set(training['task_ids']).isdisjoint(calibration['task_ids'])
    assert len(set(training['task_ids'])) == 128
    contexts = training['a'][:, None] == np.arange(1, 5)
    assert np.all(contexts.sum(axis=1) <= 1)
    assert np.issubdtype(training['successes'].dtype, np.integer)
    assert training['successes'].max() > 1
    np.testing.assert_allclose(training['y'], training['successes']/8)


def test_population_cancellation_does_not_remove_the_randomized_effect():
    plan = dict(PLAN, simulation=dict(PLAN['simulation'], latent_outcome_coefficient=0.25))
    rows, weights = exact_joint_distribution([0.08, 0.12, 0.12, 0.08], plan, 1)
    assert exact_conditional_association(rows, weights, LABELS, 'C1', 'Y', [])['independent']
    assert not exact_conditional_association(rows, weights, LABELS, 'C1', 'Y', ['C2', 'C3', 'C4'])['independent']
    assert np.all(rows[:, :4].sum(axis=1) <= 1)
    np.testing.assert_allclose(weights.sum(), 1., atol=1e-13)


def test_finite_penalties_match_independent_augmented_least_squares():
    rng = np.random.default_rng(202610149900)
    design = rng.normal(size=(91, 8))
    target = rng.normal(size=91)
    penalties = np.array([0.001, 0.01, 0.1, 1., 0.0001, 0.005, 0.05, 0.5])
    model = fit_effect_ridge(design, target, 'full', penalties)
    complete = np.column_stack((np.ones(91), design))
    augmented = np.vstack((complete/np.sqrt(91), np.diag(np.sqrt(np.r_[0., penalties]))))
    reference = np.linalg.lstsq(augmented, np.r_[target/np.sqrt(91), np.zeros(9)], rcond=None)[0]
    np.testing.assert_allclose(np.r_[model['intercept'], model['coefficients']], reference, atol=1e-11)


def test_policy_value_keeps_baseline_and_matches_independent_enumeration():
    beta = np.array([0.18, -0.12, 0., 0.])
    scores = np.random.default_rng(20261028).normal(size=(16, 4))
    plan = dict(PLAN, simulation=dict(PLAN['simulation'], latent_outcome_coefficient=0.25))
    actual = exact_policy_value(scores, beta, plan)
    expected = independent_value(scores, beta, plan)
    for field in ('gain', 'value', 'regret'):
        np.testing.assert_allclose(actual[field], expected[field], atol=1e-13)
    np.testing.assert_array_equal(select_actions(np.array([[0., -0.1], [-0.1, -0.2], [0.1, 0.1]])), [0, 0, 1])

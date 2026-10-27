from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery.jci_policy import (
    all_states, contrast_features, discover_contexts, exact_policy_value, fit_contrasts,
    full_basis, policy_gain, predict_contrasts, predict_means, simulate_tasks,
)
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend
from prompt_mechanism_study.verification.jci_policy import verify_learning


PLAN = read_json(Path('data/method/jci-sharing-20261014/joint-plan.json'))


def test_joint_assignments_preserve_atomic_edits_and_independent_tasks():
    training, beta = simulate_tasks(PLAN, 'signed', 128, 0, 'D')
    calibration, other = simulate_tasks(PLAN, 'signed', 128, 0, 'CAL')
    assert set(training['task_ids']).isdisjoint(calibration['task_ids'])
    np.testing.assert_array_equal(beta, other)
    assert len(training['y']) == len(training['task_ids']) == 128
    assert 'effects' not in training and 'latent' not in training
    assert np.all(np.count_nonzero(training['x']-training['w'], axis=1) <= 1)
    assigned = training['a'] > 0
    np.testing.assert_array_equal(training['x'][np.flatnonzero(assigned), training['a'][assigned]-1], 1)


def test_joint_outcome_fit_matches_independent_augmented_least_squares():
    training, _ = simulate_tasks(PLAN, 'signed', 128, 0, 'D')
    for family in PLAN['learner_families']:
        model = fit_contrasts(training, .01, family)
        features = contrast_features(training['w'], family == 'target_factorized')
        effects = np.zeros((128, features.shape[-1]))
        selected = np.flatnonzero(training['a'] > 0)
        effects[selected] = features[selected, training['a'][selected]-1]
        design = np.column_stack((np.ones(128), full_basis(training['w']), effects))
        penalty = np.diag(np.r_[0., np.full(design.shape[1]-1, np.sqrt(.01))])
        independent = np.linalg.lstsq(np.vstack((design/np.sqrt(128), penalty)),
            np.r_[training['y']/np.sqrt(128), np.zeros(design.shape[1])], rcond=None)[0]
        np.testing.assert_allclose(independent, [model['intercept'], *model['coefficients']], atol=1e-10)
        prediction = predict_contrasts(model, training)
        np.testing.assert_array_equal(prediction[training['identity_zero']], 0.)
        gain, actions = policy_gain(training, np.full_like(prediction, -1.), predict_means(model, training))
        assert gain == 0. and np.all(actions == 0)


def test_exact_value_retains_harmful_single_requirement_policy():
    _, beta = simulate_tasks(PLAN, 'signed', 128, 0, 'D')
    negative = int(np.flatnonzero(beta < 0)[0])
    states = all_states(len(beta))
    scores = np.zeros_like(states, dtype=float)
    scores[:, negative] = 1-states[:, negative]
    result = exact_policy_value(scores, beta, PLAN)
    expected_gain = .575*beta[negative]
    expected_baseline = .20+.25*.5+.425*beta.sum()
    np.testing.assert_allclose([result['gain'], result['value']], [expected_gain, expected_baseline+expected_gain], atol=1e-12)
    assert result['gain'] < 0


def test_real_jci123_preserves_random_context_background(tmp_path):
    training, _ = simulate_tasks(PLAN, 'signed', 128, 0, 'D')
    backend = StructureBackend(Path('D:/R/R-4.3.1/bin/x64/Rscript.exe'), tmp_path/'backend.log',
                               Path('src/discovery/jci_policy.R'))
    try:
        result = discover_contexts(training, np.arange(128), PLAN, backend, [PLAN['seed'], 'test'])
    finally:
        backend.close()
    graph = np.asarray(result['results']['jci123']['pag'])
    for method in PLAN['structural_methods']:
        ancestral = np.asarray(result['results'][method]['ancestry'])
        assert ancestral.shape == (9, 9)
        assert set(result['results'][method]['context_ancestry']) == {'C1', 'C2', 'C3', 'C4'}
        np.testing.assert_array_equal(ancestral[:4, -1],
            [result['results'][method]['context_ancestry'][f'C{index}'] for index in range(1, 5)])
    np.testing.assert_array_equal(graph[:4, :4], 2*(1-np.eye(4, dtype=int)))
    for context in range(4):
        for system in range(4, 9):
            if graph[context, system]:
                assert graph[context, system] == 2 and graph[system, context] == 3
    assert all(row['p'] == (1+row['exceedances'])/2000 for row in result['queries'])


def test_independent_replay_of_executed_joint_development_cell():
    cell = read_json(Path('results/jci-joint-policy-20261014-ancestry/cells/sparse-128-00/result.json'))
    states = all_states(4)
    evaluation = dict(w=states.tolist(), identity_zero=states.astype(bool).tolist())
    fits, queries = verify_learning(cell['training'], cell['calibration'], evaluation, cell['learned'], PLAN)
    assert fits == 90 and queries > 0

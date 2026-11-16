from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery.jci_sharing import (
    STATES, ConditionalPermutation, basis, draw_tasks, exact_value, fit_effect_model, mechanism_parameters,
    recalibrate_shared_component,
)
from prompt_mechanism_study.verification.jci_sharing import independent_value, verify_fit
from prompt_mechanism_study.verification.jci_sharing import independent_design
from prompt_mechanism_study.verification.jci_sharing import verify_recalibration


PLAN = read_json(Path('data/method/jci-sharing-20261014/plan.json'))


def test_full_source_basis_and_latent_probabilities():
    design = basis(STATES)
    np.testing.assert_allclose(design.T@design, np.eye(8)*8)
    for name in PLAN['mechanisms']:
        for environment in range(4):
            for latent in (np.zeros(8), np.ones(8)):
                baseline, gamma = mechanism_parameters(name, environment, STATES, latent)
                assert np.all((baseline >= 0) & (baseline <= 1))
                assert np.all((baseline+gamma >= 0) & (baseline+gamma <= 1))


def test_real_scm_draws_preserve_task_units_and_identical_inputs():
    first = draw_tasks(PLAN, 'proxy_shift', 128, 0, 0)
    other = draw_tasks(PLAN, 'proxy_shift', 128, 0, 1)
    assert len(first['task_ids']) == len(set(first['task_ids'])) == 384
    assert set(first['task_ids']).isdisjoint(other['task_ids'])
    identical = first['fidelity'] == 0
    np.testing.assert_array_equal(first['outcomes'][identical, 0], first['outcomes'][identical, 1])
    np.testing.assert_array_equal(first['delta'][identical], 0.)
    for mask in range(8):
        model = fit_effect_model(first, mask, .01, .1, [0, 1, 2])
        verify_fit(first, model)
        design = independent_design(first['w'], first['e'], mask, [0, 1, 2])
        shared = 2**mask.bit_count()
        penalties = np.r_[0., np.full(shared-1, .01), np.full(design.shape[1]-shared, .1)]
        augmented = np.vstack((design/np.sqrt(len(design)), np.diag(np.sqrt(penalties))))
        reference = np.linalg.lstsq(augmented, np.r_[first['delta']/np.sqrt(len(design)),
                                                   np.zeros(design.shape[1])], rcond=None)[0]
        np.testing.assert_allclose(reference, [model['intercept'], *model['coefficients']], atol=1e-10)
        choice = dict(model=model, threshold=.05)
        for environment in range(4):
            observed = exact_value(choice, 'proxy_shift', environment, PLAN)
            reference = independent_value(choice, 'proxy_shift', environment, PLAN)
            np.testing.assert_allclose([observed['gain'], observed['value'], observed['regret']],
                                       [reference['gain'], reference['value'], reference['regret']], atol=1e-12)


def test_conditional_random_table_queries_are_symmetric_and_counted():
    actual = draw_tasks(PLAN, 'scope_sign', 128, 0, 0)
    test = ConditionalPermutation(np.column_stack((actual['a'], actual['w'][:, 1], actual['y'])),
                                  ['A', 'W2', 'Y'], 199, 20261014)
    p = test.query('A', 'Y', ['W2'])
    assert test.query('Y', 'A', ['W2']) == p
    assert len(test.cache) == 1
    record = next(iter(test.cache.values()))
    assert p == (1+record['exceedances'])/200
    assert record['informative_strata'] == 2


def test_shared_component_calibration_on_executed_development_material():
    saved = read_json(Path('results/jci-sharing-20261014/cells/baseline_shift-128-00/result.json'))
    revised = recalibrate_shared_component(saved, PLAN)
    verify_recalibration(saved, revised, PLAN)
    for view in revised['views'].values():
        assert view['choices']['jci_checked']['model']['mask'] == 7
        assert view['choices']['jci_checked']['sharing_qualified'] is False

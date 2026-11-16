from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.records import canonical_json
from prompt_mechanism_study.discovery.jci_refit import fit_zero_model, graphical_oracles, oracle_nulls, predict_zero_model
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend
from prompt_mechanism_study.verification.jci_policy import independent_baseline, independent_features
from prompt_mechanism_study.verification.jci_refit import marginal_diagnostics, verify_zero_cell


PLAN = read_json(Path('data/method/jci-sharing-20261014/joint-plan.json'))
CELL = Path('results/jci-joint-policy-20261014-ancestry/cells/sparse-128-00/result.json')


def test_zero_constraints_refit_all_assigned_tasks():
    cell = read_json(CELL)
    training = cell['training']
    nulls = np.asarray(cell['beta']) == 0
    model = fit_zero_model(training, 'full', .01, nulls)
    features = independent_features(training, 'full')
    assignment = np.asarray(training['a'])
    effect_design = np.zeros((len(assignment), features.shape[-1]))
    for index, arm in enumerate(assignment):
        if arm:
            effect_design[index] = features[index, arm-1]
    design = np.column_stack((np.ones(len(assignment)), independent_baseline(training['w']), effect_design))
    retained = np.r_[np.ones(16, dtype=bool), np.repeat(~nulls, 4)]
    selected = design[:, retained]
    penalties = np.diag(np.r_[0., np.full(selected.shape[1]-1, np.sqrt(.01))])
    coefficients = np.linalg.lstsq(np.vstack((selected/np.sqrt(len(selected)), penalties)),
        np.r_[np.asarray(training['y'])/np.sqrt(len(selected)), np.zeros(selected.shape[1])], rcond=None)[0]
    expanded = np.r_[model['intercept'], model['coefficients']]
    np.testing.assert_allclose(expanded[retained], coefficients, atol=1e-10)
    np.testing.assert_array_equal(expanded[~retained], 0.)
    np.testing.assert_array_equal(predict_zero_model(model, training)[:, nulls], 0.)


def test_arm_mean_pool_uses_real_outcomes_and_complete_denominator():
    cell = read_json(CELL)
    training = cell['training']
    nulls = np.asarray(cell['beta']) == 0
    model = fit_zero_model(training, 'arm_mean', 0., nulls)
    assignment, outcome = np.asarray(training['a']), np.asarray(training['y'])
    control = np.isin(assignment, np.r_[0, np.flatnonzero(nulls)+1])
    assert np.count_nonzero(control)+np.count_nonzero(~control) == 128
    assert model['baseline'] == outcome[control].mean()
    for policy in range(4):
        expected = 0. if nulls[policy] else outcome[assignment == policy+1].mean()-outcome[control].mean()
        np.testing.assert_allclose(model['marginal_effects'][policy], expected)


def test_real_graphical_fci_identifies_zero_constraints(tmp_path):
    backend = StructureBackend(Path('D:/R/R-4.3.1/bin/x64/Rscript.exe'), tmp_path/'backend.log', Path('src/discovery/jci_policy.R'))
    try:
        records = graphical_oracles(PLAN, backend)
    finally:
        backend.close()
    for record in records.values():
        beta = np.asarray(record['beta'])[::-1]
        masks = oracle_nulls(record, beta)
        np.testing.assert_array_equal(masks['jci123'], beta == 0)
        np.testing.assert_array_equal(masks['direct_ci'], beta == 0)
        np.testing.assert_array_equal(masks['time'], False)
        np.testing.assert_array_equal(masks['jci12'], False)


def test_independent_refit_selection_and_value_on_executed_cell():
    root = Path('results/jci-joint-policy-20261014-ancestry')
    parent = read_json(CELL)
    record = read_json(root/'zero-effect-refit/cells/sparse-128-00/result.json')
    plan = read_json(root/'zero-effect-refit/inputs/plan.json')
    oracle = read_json(root/'zero-effect-refit/graphical-oracle/result.json')
    assert verify_zero_cell(parent, record, PLAN, plan, oracle) > 100


def test_actual_graph_marginal_diagnostic_preserves_frozen_thresholds():
    root = Path('results/jci-joint-policy-20261014-ancestry/zero-effect-refit')
    records = [read_json(path) for path in sorted((root/'cells').glob('sparse-512-*/result.json'))]
    plan = read_json(root/'inputs/plan.json')
    result = marginal_diagnostics(records, plan)
    assert canonical_json(result)
    assert [row['threshold'] for row in result['groups']] == plan['nonancestry_thresholds']
    assert all(row['independent_repetitions'] == 16 and row['active_policy_positions'] == 16
               for row in result['groups'])
    consensus = result['groups'][-1]
    np.testing.assert_allclose(consensus['mean_mse']['full'], .003291273831507051, atol=1e-12)
    np.testing.assert_allclose(consensus['mean_mse']['jci123'], .001879032308399894, atol=1e-12)
    assert {row['comparator'] for row in consensus['comparisons']} == {
        'full', 'zero', 'empirical_shrinkage', 'time', 'jci12', 'direct_ci'}

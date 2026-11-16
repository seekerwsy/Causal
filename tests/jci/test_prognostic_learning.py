import shutil
from pathlib import Path

import networkx as nx
import numpy as np
import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.discovery import prognostic_learning as method
from prompt_mechanism_study.discovery.jci_structure import discover_jci_pag
from prompt_mechanism_study.verification.prognostic_learning import verify_directional_study


def _true_merged_dag(plan, permutation):
    branches = method.merged_attribute_layout(plan)
    inverse = np.argsort(permutation) + 2
    labels = ['C1', 'C2', *[f'X{i:02d}' for i in range(64)]]
    dag = nx.DiGraph()
    dag.add_nodes_from(labels)
    for b, branch in enumerate(branches):
        latent = f'U{b}'
        dag.add_node(latent)
        seq = [f'C{(b % 2) + 1}', *[labels[int(inverse[k])] for k in branch['precursors']]]
        dag.add_edges_from(zip(seq, seq[1:]))
        dag.add_edge(latent, labels[int(inverse[branch['precursors'][0]])])
        proxy = labels[int(inverse[branch['proxy']])]
        inter = labels[int(inverse[branch['intermediate']])]
        leaf = labels[int(inverse[branch['noise_leaf']])]
        dag.add_edges_from([(latent, proxy), (proxy, inter), (inter, leaf)])
    for b in range(8):
        term = labels[int(inverse[branches[b]['terminal']])]
        dag.add_edge(labels[int(inverse[branches[b]['precursors'][-1]])], term)
        dag.add_edge(labels[int(inverse[branches[(b + 1) % 8]['precursors'][-1]])], term)
    return dag, labels


def test_native_jci12_pag_recovers_exact_roles_and_blocks_latent_branches():
    plan = read_json(Path('configs/jci-directional-grouped-smoke.json'))
    perm = list(range(64))
    dag, labels = _true_merged_dag(plan, perm)

    class OracleCI:
        def __init__(self):
            self.cache = {}

        def query(self, x, y, conditioned):
            p = 1.0 if nx.is_d_separator(dag, {x}, {y}, set(conditioned)) else 0.0
            self.cache[(x, y, tuple(conditioned))] = {'p': p}
            return p

    pag_res = discover_jci_pag(labels, OracleCI(), 0.05, max_order=3, majority_rule=True)
    assert pag_res['status'] == 'evaluated' and pag_res['backend'] == 'python-jci12'
    checks = method.attribute_direction_checks(pag_res)
    assert checks['eligible'] is True
    roles = method.pag_role_groups(pag_res)
    true_roles = method.pag_role_groups(method.merged_attribute_graph(plan, perm))
    assert roles['root'] == true_roles['root'] and len(roles['root']) == 8
    assert roles['terminal'] == true_roles['terminal'] and len(roles['terminal']) == 8
    assert roles['upstream'] == true_roles['upstream'] and len(roles['upstream']) == 24
    assert roles['other'] == true_roles['other'] and len(roles['other']) == 32


def test_direction_guard_falls_back_gracefully_on_cyclic_or_conflicted_pag():
    pag = np.zeros((66, 66), dtype=int)
    pag[0, 2], pag[2, 0] = 2, 3
    pag[2, 3], pag[3, 2] = 2, 3
    pag[3, 4], pag[4, 3] = 2, 3
    pag[4, 2], pag[2, 4] = 2, 3
    bad_graph = dict(status='evaluated', pag=pag.tolist())
    checks = method.attribute_direction_checks(bad_graph)
    assert checks['eligible'] is False and checks['status'] == 'invalid' and [2, 3, 4] in checks['cyclic_components']
    roles = method.pag_role_groups(bad_graph)
    assert roles['eligible'] is False
    assert roles['root'] == [] and roles['terminal'] == [] and roles['upstream'] == [] and roles['other'] == list(range(2, 66))
    profiles = method.role_weight_profiles(roles, [0.0, 8.0, 100.0])
    assert len(profiles) == 1 and profiles[0]['profile'] == 'uniform'


def test_cross_fitting_is_fold_isolated_and_finite_sample_unbiased():
    plan = read_json(Path('configs/jci-directional-grouped-smoke.json'))
    rng = np.random.default_rng(777)
    perm = list(range(64))
    n = 64
    target = method.draw_merged_attributes(rng, n, 1, 'downstream_signal', plan, perm, outcomes=True)
    # Build deterministic dummy source models (independent of target) with deliberate misspecification.
    dummy_fit = type(
        'DummyModel',
        (),
        {'predict_proba': staticmethod(lambda z: np.column_stack((1 - np.full(len(z), 0.73), np.full(len(z), 0.73))))},
    )()
    source_models = {
        name: (dummy_fit, list(range(66)))
        for name in ('jci', 'oracle', *method.PRIMARY_COMPARATORS, *method.STRUCTURAL_COMPARATORS)
    }
    cf_a = method.cross_fit_target_effects(source_models, target, plan)

    # Zero-leakage check: modifying Y inside fold 0 must NOT alter fold 0's predictions/coefficients.
    perturbed = {k: v.copy() for k, v in target.items()}
    fold0 = np.arange(n) % plan['target_folds'] == 0
    perturbed['y'][fold0] = 1 - perturbed['y'][fold0]
    cf_b = method.cross_fit_target_effects(source_models, perturbed, plan)
    np.testing.assert_allclose(
        np.asarray(cf_a['jci']['oof_predictions'])[fold0],
        np.asarray(cf_b['jci']['oof_predictions'])[fold0],
        atol=1e-14,
    )
    assert cf_a['jci']['folds'][0] == cf_b['jci']['folds'][0]

    # Exact randomization unbiasedness under fixed target covariates and outcomes.
    # Fix X and potential outcomes (Y0, Y1); average randomized score over repeated independent A draws.
    base_sample = method.draw_merged_attributes(np.random.default_rng(888), 64, 1, 'upstream_control', plan, perm, outcomes=False)
    p0 = base_sample['average'] - 0.5 * base_sample['effect']
    p1 = base_sample['average'] + 0.5 * base_sample['effect']
    true_tau = float(np.mean(p1 - p0))
    est_taus = []
    mc_rng = np.random.default_rng(999)
    for _ in range(150):
        a_draw = mc_rng.binomial(1, 0.5, 64)
        y_draw = mc_rng.binomial(1, np.where(a_draw == 1, p1, p0))
        res = method.cross_fit_target_effects(source_models, dict(x=base_sample['x'], a=a_draw, y=y_draw), plan)
        est_taus.append(res['jci']['effect'])
    assert abs(float(np.mean(est_taus)) - true_tau) < 0.025


def test_misaligned_negative_control_loads_only_on_unreachable_attributes():
    plan = read_json(Path('configs/jci-directional-grouped-smoke.json'))
    perm = np.random.default_rng(5).permutation(64).tolist()
    true_roles = method.pag_role_groups(method.merged_attribute_graph(plan, perm))
    inverse = np.argsort(perm) + 2
    outcome_columns = sorted(int(inverse[b['intermediate']]) for b in method.merged_attribute_layout(plan))
    # No structural profile in the JCI menu (root / upstream / terminal / reachable) contains the outcome attributes.
    assert set(outcome_columns) <= set(true_roles['other'])
    assert not set(outcome_columns) & set(true_roles['reachable'])
    sample = method.draw_merged_attributes(np.random.default_rng(6), 4096, 0, 'misaligned_signal', plan, perm, outcomes=False)
    expected = 1.0 / (1.0 + np.exp(-(2 * sample['x'][:, outcome_columns] - 1).sum(axis=1)))
    np.testing.assert_allclose(sample['average'], expected)


def test_smoke_execution_and_independent_verification(tmp_path):
    output = tmp_path / 'smoke'
    summary = method.run_directional_study(Path('configs/jci-directional-grouped-smoke.json'), output, workers=2)
    assert summary['cells'] == 8 and summary['formal_claim_allowed'] is False
    assert set(summary['jci_harm_count_by_scenario']) == set(method.SCENARIOS)
    verified = verify_directional_study(output, workers=2)
    assert verified['status'] == 'VERIFIED' and verified['cells'] == 8
    assert read_json(output / 'summary' / 'result.json') == summary

    # The verifier recomputes verdict fields; a re-hashed summary with a forged verdict must be rejected.
    forged = dict(summary, upstream_harm_count=summary['upstream_harm_count'] + 1)
    shutil.rmtree(output / 'summary')
    shutil.rmtree(output / 'verification')
    write_bundle(output / 'summary', {'result.json': forged})
    with pytest.raises(AssertionError):
        verify_directional_study(output, workers=2)

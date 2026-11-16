import itertools
from pathlib import Path

import numpy as np
import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery.jci_transfer import actions_for, fit_effect, state_basis
from prompt_mechanism_study.experiment.jci_transfer import validate_plan


def test_saturated_source_basis_preserves_all_binary_states():
    states = np.asarray(list(itertools.product((0,1),repeat=3)))
    basis = state_basis(states,7)
    np.testing.assert_allclose(basis.T@basis,8*np.eye(8),atol=1e-13)
    assert state_basis(states,0).shape==(8,1)
    for mask in range(8):
        assert state_basis(states,mask).shape[1]==2**mask.bit_count()


def test_shared_multivariate_fit_matches_independent_weighted_least_squares():
    rng = np.random.default_rng(20261028)
    design = rng.normal(size=(80,26))
    outcomes = rng.normal(size=(80,3))
    weights = rng.uniform(0.2,1.,size=80)
    actual = fit_effect(design,outcomes,weights,1,0.01,0.1,True)
    normalized = weights/weights.sum()
    penalties = np.asarray([0.01]*2+[0.1]*24)
    augmented = np.vstack((np.sqrt(normalized[:,None])*design,np.diag(np.sqrt(penalties))))
    target = np.vstack((np.sqrt(normalized[:,None])*outcomes,np.zeros((26,3))))
    reference = np.linalg.lstsq(augmented,target,rcond=None)[0]
    np.testing.assert_allclose(actual['coefficients'],reference.T,atol=1e-11)


def test_transfer_retains_baseline_and_exposed_evidence_identity():
    np.testing.assert_array_equal(actions_for(np.array([[0.,-0.1,0.],[-0.1,-0.2,-0.3],[0.1,0.1,0.]]),0.),[0,0,1])
    plan = read_json(Path('configs/jci-transfer.json'))
    validate_plan(plan)
    plan['formal_claim_allowed'] = True
    with pytest.raises(ValueError):
        validate_plan(plan)

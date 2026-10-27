from pathlib import Path

import numpy as np

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.discovery.jci_reliability import exact_conditional_association, exact_joint_distribution, fit_effect_ridge
from prompt_mechanism_study.experiment.jci_reliability import execute_reliability_cell
from prompt_mechanism_study.verification.jci_reliability import verify_reliable_learning


PARENT = Path('results/jci-joint-policy-20261014-ancestry')
PLAN = read_json(PARENT/'inputs/plan.json')
LABELS = ['C1','C2','C3','C4','X1','X2','X3','X4','Y']


def test_exact_population_exposes_context_mixture_cancellation():
    rows,weights = exact_joint_distribution([.08,.12,.12,.08],PLAN,1)
    marginal = exact_conditional_association(rows,weights,LABELS,'C1','Y',[])
    conditional = exact_conditional_association(rows,weights,LABELS,'C1','Y',['C2','C3','C4'])
    assert marginal['independent'] and not conditional['independent']
    treated = rows[:,0]==1
    baseline = np.all(rows[:,:4]==0,axis=1)
    difference = weights[treated]@rows[treated,-1]/weights[treated].sum()
    difference -= weights[baseline]@rows[baseline,-1]/weights[baseline].sum()
    np.testing.assert_allclose(difference,.575*.08,atol=1e-13)
    np.testing.assert_allclose(weights.sum(),1.,atol=1e-13)


def test_exact_joint_law_retains_mutually_exclusive_atomic_assignments():
    rows,weights = exact_joint_distribution([.18,-.12,0.,0.],PLAN,1)
    assert np.max(rows[:,:4].sum(axis=1)) == 1
    for policy in range(4):
        selected = rows[:,policy]==1
        np.testing.assert_allclose(weights[selected].sum(),.2,atol=1e-13)
        assert np.all(rows[selected,4+policy]==1)
    independent = exact_conditional_association(rows,weights,LABELS,'C3','Y',['C1','C2','C4'])
    assert independent['independent']


def test_weighted_penalty_matches_augmented_least_squares():
    rng = np.random.default_rng(202610149900)
    design = rng.normal(size=(91,8))
    target = rng.normal(size=91)
    penalties = np.array([.001,.01,.1,1.,.0001,.005,.05,.5])
    model = fit_effect_ridge(design,target,'full',penalties)
    actual = np.r_[model['intercept'],model['coefficients']]
    complete = np.column_stack((np.ones(91),design))
    augmented = np.vstack((complete/np.sqrt(91),np.diag(np.sqrt(np.r_[0.,penalties]))))
    reference = np.linalg.lstsq(augmented,np.r_[target/np.sqrt(91),np.zeros(9)],rcond=None)[0]
    np.testing.assert_allclose(actual,reference,atol=1e-11)


def test_real_conservative_fci_count_outcome_and_independent_consumer(tmp_path):
    plan = read_json(Path('data/method/jci-reliability-20261014/plan.json'))
    plan['study_id'] = 'jci-policy-reliability-development-canary-20261014'
    plan['batch_seeds'] = [202610149901,202610149902]
    plan['seed'] = 2026101499
    plan['evidence_role'] = 'EXPOSED_DEVELOPMENT_CANARY'
    coordinates = ('cancelling_dense',128,8,0,0)
    write_bundle(tmp_path/'inputs',{'plan.json':plan,'coordinates.json':list(coordinates)})
    logs = tmp_path/'logs'
    logs.mkdir()
    record = execute_reliability_cell(plan,coordinates,Path('D:/R/R-4.3.1/bin/x64/Rscript.exe'),logs)
    write_bundle(tmp_path/'cell',{'result.json':record})
    assert max(record['training']['successes'])>1
    fits,queries = verify_reliable_learning(record,plan)
    assert fits>100 and queries>20
    assert record['learned']['coefficients_fixed_to_zero'] is False
    assert all(graph['conservative'] for graph in record['structure']['graphs'].values())


def test_executed_population_information_preserves_direct_randomization_boundary():
    root = Path('results/jci-reliability-20261014/population-information')
    records = read_json(root/'result.json')['records']
    assert len(records)==16
    false = 0
    for record in records:
        truth = np.asarray(record['beta'])==0
        direct = np.asarray(record['direct_population_independence'])
        raw = np.asarray(record['graphs']['jci123']['ancestry'])[:4,-1]==-1
        np.testing.assert_array_equal(direct,truth)
        np.testing.assert_array_equal(raw & direct,truth)
        assert record['markov_violations']==0
        false += np.count_nonzero(raw & ~truth)
    assert false==5
    assert sum(record['faithfulness_violations'] for record in records)==17

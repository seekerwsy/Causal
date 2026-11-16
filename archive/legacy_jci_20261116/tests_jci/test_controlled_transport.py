from pathlib import Path

import numpy as np
import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery import controlled_transport as controlled


@pytest.mark.parametrize('scenario',controlled.SCENARIOS)
def test_population_and_probability_correction(scenario):
    q = [.5,.5] if scenario=='no_shift' else [.75,.25]
    for h in range(4):
        states,source,_ = controlled.population([.5,.5],h,scenario)
        _,target,_ = controlled.population(q,h,scenario)
        np.testing.assert_allclose([source.sum(),target.sum()],1,atol=1e-14)
        rows = states[:,[0,1,2,3,5,6,7,8]]
        np.testing.assert_allclose(source*controlled.weight(rows,q),target,atol=1e-14)
        means = []
        for arm in (0,1):
            assigned = states.copy()
            assigned[:,2] = arm
            means.append(controlled.probabilities(assigned,h,scenario)[2])
        truth = target@(means[1]-means[0])
        arbitrary = np.array([.15+.1*rows[:,0],.7-.2*rows[:,5]])
        py = controlled.probabilities(states,h,scenario)[2]
        residual = 2*(2*states[:,2]-1)*(py-arbitrary[states[:,2],np.arange(len(states))])
        for mixing in (0.,.37,1.):
            estimate = target@(arbitrary[1]-arbitrary[0])+mixing*(source*controlled.weight(rows,q))@residual+(1-mixing)*target@residual
            np.testing.assert_allclose(estimate,truth,atol=1e-14)


def test_sufficient_sets_retain_proxy_and_collider_context():
    assert controlled.structure('irrelevant_context')['minimal']==[4]
    assert controlled.structure('confounded_proxy')['minimal']==[14]
    assert controlled.structure('multi_target')['minimal']==[15]
    assert controlled.structure('unobserved_attribute')['minimal']==[11]
    assert 4 not in controlled.structure('confounded_proxy')['valid']


def test_weighted_leave_one_out_and_prediction_binding():
    plan = read_json(Path('configs/jci-oracle-feasibility.json'))
    rng = np.random.default_rng(712409)
    train = controlled.draw(rng,128,[.5,.5],0,'confounded_proxy')
    held = controlled.draw(rng,64,[.5,.5],0,'confounded_proxy')
    target = controlled.draw(rng,32,[.75,.25],0,'confounded_proxy')
    catalog,outputs = controlled.fit_catalog(train,held,target,[.75,.25],controlled.structure('confounded_proxy'),plan)
    for arm,record in enumerate(catalog):
        rows = train[train[:,2]==arm]
        weights = controlled.weight(rows,[.75,.25])
        for model in record['models']:
            x = controlled.design(rows,model['mask'])
            scores = []
            for alpha in plan['ridge_penalties']:
                inverse = np.linalg.inv(x.T@(weights[:,None]*x)+alpha*np.eye(x.shape[1]))
                beta = inverse@x.T@(weights*rows[:,-1])
                leverage = weights*np.sum((x@inverse)*x,axis=1)
                scores.append(np.mean(weights*((rows[:,-1]-x@beta)/(1-leverage))**2))
            np.testing.assert_allclose(model['scores'],scores,atol=1e-10)
            assert model['alpha']==plan['ridge_penalties'][np.argmin(scores)]
        for name,index in record['choices'].items():
            model = record['models'][index]
            for role,rows in [('held',held),('target',target)]:
                np.testing.assert_allclose(outputs[name][role][arm],np.clip(controlled.design(rows,model['mask'])@model['coefficients'],0,1))


def test_count_region_does_not_degenerate_at_zero_differences():
    lower,upper = controlled.count_interval([0]*32,.05/32)
    assert -2<lower<0<upper<2

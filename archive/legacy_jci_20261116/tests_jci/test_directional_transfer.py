from pathlib import Path

import networkx as nx
import numpy as np
import pytest

from prompt_mechanism_study.artifact_io import read_json, write_json_new
from prompt_mechanism_study.discovery import directional_transfer as method
from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation, StructureBackend


def test_target_correction_under_all_declared_mechanism_changes():
    for scenario in method.SCENARIOS:
        for h in range(4):
            rows,u,mass,py = method.population(1,h,scenario)
            np.testing.assert_allclose(mass.sum(),1,atol=1e-14)
            assert np.all((py>=0)&(py<=1))
            model = dict(mask=0,contexts=False,mode='shared',coefficients=[0.]*4)
            risk = method.exact_risk(model,h,scenario,16)
            arms = []
            for arm in (0,1):
                assigned = rows.copy()
                assigned[:,2] = arm
                arms.append(method.probabilities(np.insert(assigned,4,u,axis=1),1,h,scenario)[2])
            np.testing.assert_allclose(risk['exact_effect'],mass@(arms[1]-arms[0]),atol=1e-13)
            np.testing.assert_allclose(16*risk['exact_effect_variance'],4*risk['target_prognostic_risk']-risk['exact_effect']**2,atol=1e-13)


def test_context_query_is_not_prediction_sufficiency_or_unrestricted_model():
    accepted = method.oracle_context_masks('confounded_proxy')
    assert 1 in accepted and 3 not in accepted and 35 in accepted
    assert 63 not in accepted
    assert all(not mask&1 for mask in method.oracle_context_masks('unobserved_attribute'))
    graph = method.true_graph('confounded_proxy')
    assert not nx.has_path(graph,'N','Y')
    assert not nx.is_d_separator(graph,{'C2'},{'Y'},{'N'})


def test_partial_graph_queries_conservatively_cover_dag_completions():
    rng = np.random.default_rng(841)
    for _ in range(16):
        dag = nx.DiGraph()
        dag.add_nodes_from(range(8))
        dag.add_edges_from((i,j) for i in range(8) for j in range(i+1,8) if rng.random()<.2)
        pag = np.zeros((8,8),dtype=int)
        for i,j in dag.edges:
            pag[i,j],pag[j,i] = 2,3
        circles = pag.copy()
        for i,j in zip(*np.nonzero(circles)):
            if rng.random()<.5:
                circles[i,j] = 1
        for mask in range(32):
            conditioned = {2}|{3+bit for bit in range(4) if mask>>bit&1}
            expected = nx.is_d_separator(dag,{0},{7},conditioned)
            assert method.possible_separation(pag,0,7,conditioned)==expected
            if method.possible_separation(circles,0,7,conditioned):
                assert expected
    pag = np.zeros((8,8),dtype=int)
    pag[1,4],pag[4,1],pag[4,7],pag[7,4] = 2,3,2,2
    assert method.possible_separation(pag,1,7,set())
    assert not method.possible_separation(pag,1,7,{4})


def test_unknown_graphs_do_not_produce_independence_certificates():
    graphs = [dict(status='insufficient_support',labels=method.ARM_LABELS,arm=arm,pag=None) for arm in (0,1)]
    masks,records = method.context_masks(graphs)
    assert masks==[]
    assert records[63]['status']=='unrestricted' and records[63]['queries']==[]
    assert all(record['status']=='unknown' for record in records if record['mask']<48)
    with pytest.raises(ValueError):
        ConditionalPermutation([[0,.7],[1,.2]],['X','Y'],199,1)
    ci = ConditionalPermutation([[0,0],[0,1]],['X','Y'],199,1,minimum_per_level=2)
    assert ci.query('X','Y',[]) is None
    assert ConditionalPermutation([[0,0],[0,1]],['X','Y'],199,1).query('X','Y',[]) is None


def test_actual_arm_specific_fci_retains_cancellation_and_natural_baseline(tmp_path,request):
    backend = StructureBackend(request.config.getoption('--rscript'),tmp_path/'arms.log',Path('src/discovery/jci_context.R'))
    graphs = []
    for arm in (0,1):
        ci = method.PopulationQueries(0,'cancellation',arm)
        assert ci.query('C2','Y',[])==0
        graph = backend.search(ci.labels,'directional',ci,.05)
        assert graph['status']=='evaluated'
        assert graph['context_variables']==['C1','C2']
        same = backend.search(ci.labels,'fci_same_knowledge',method.PopulationQueries(0,'cancellation',arm),.05)
        assert same['pag']==graph['pag']
        graph.update(labels=ci.labels,arm=arm)
        graphs.append(graph)
        assert graph['pag'][1][-1]!=0
    backend.close()
    accepted,queries = method.context_masks(graphs)
    assert 33 in accepted
    assert all(record['status']!='supported' for record in queries if not record['mask']&32)
    from prompt_mechanism_study.verification.directional_transfer import context_query_masks
    assert context_query_masks(graphs,63)==(accepted,queries)


def test_partial_context_predictors_and_full_target_correction():
    source = method.draw(np.random.default_rng(410),128,0,0,'proxy_mechanism_change','source')
    target = method.draw(np.random.default_rng(411),32,1,0,'proxy_mechanism_change','target')
    model = method.fit(source,target,17,1.,'deviation',10.)
    rows = np.asarray(target['observations'])
    changed = rows.copy()
    changed[:,5] = 1-changed[:,5]
    np.testing.assert_allclose(method.predict(model,rows,0),method.predict(model,changed,0),atol=1e-12)
    assert np.max(np.abs(method.predict(model,rows)-method.predict(model,changed)))>1e-6
    from prompt_mechanism_study.verification.directional_transfer import verify_fit
    verify_fit(model,source,target)
    assert method.design(rows,16).shape[1]==8
    assert method.design(rows,32).shape[1]==8


def test_query_scopes_and_observable_precision_bound():
    records = {record['mask']:record for record in method.oracle_query_diagnostics('proxy_mechanism_change')}
    assert records[1]['source_context_supported'] and records[1]['target_environment_separated']
    assert not records[1]['prediction_sufficient']
    assert records[35]['source_context_supported'] and records[35]['prediction_sufficient']
    assert not records[35]['target_environment_separated']
    source = method.draw(np.random.default_rng(843),128,0,0,'unobserved_attribute','source')
    target = method.draw(np.random.default_rng(844),16,1,0,'unobserved_attribute','target')
    model = method.fit(source,target,14,1.,'deviation',10.,allowed=14)
    assert method.observable_optimal_variance(0,'unobserved_attribute',16)<=method.exact_risk(model,0,'unobserved_attribute',16)['exact_effect_variance']+1e-12


def test_averaged_arm_calibration_is_target_score_second_moment():
    source = method.draw(np.random.default_rng(510),128,0,0,'proxy_mechanism_change','source')
    target = method.draw(np.random.default_rng(511),32,1,0,'proxy_mechanism_change','target')
    calibration = method.draw(np.random.default_rng(512),32,1,0,'proxy_mechanism_change','calibration')
    model = method.fit(source,target,33,1.,'deviation',10.)
    score = method.scores(model,calibration)
    np.testing.assert_allclose(method.calibration_loss(model,calibration),np.mean(np.square(score['scores']))/4,atol=1e-12)


def test_source_residual_transport_counterexample_and_target_correction():
    source = np.zeros((8,9),dtype=int)
    source[:,2] = np.repeat([0,1],4)
    source[:,5] = np.tile([0,0,0,1],2)
    source[:,-1] = source[:,2]
    target = source.copy()
    target[:,5] = np.tile([0,1,1,1],2)
    model = dict(mask=2,contexts=False,mode='shared',coefficients=[.25,.25,0.,.25,0.,.25,0.,0.])
    corrected = method.scores(model,dict(observations=target.tolist()))
    np.testing.assert_allclose(corrected['effect'],1.,atol=1e-14)
    source_residual = 1-source[:,5].mean()
    target_residual = 1-target[:,5].mean()
    np.testing.assert_allclose(target[:,5].mean()+.5*(source_residual+target_residual),1.25)


def test_missing_attribute_is_excluded_from_shared_and_target_models():
    source = method.draw(np.random.default_rng(610),128,0,0,'unobserved_attribute','source')
    target = method.draw(np.random.default_rng(611),16,1,0,'unobserved_attribute','target')
    model = method.fit(source,target,2,1.,'deviation',10.,allowed=14)
    rows = np.asarray(target['observations'])
    changed = rows.copy()
    changed[:,4] = 1-changed[:,4]
    np.testing.assert_allclose(method.predict(model,rows),method.predict(model,changed),atol=1e-12)
    assert 'X' not in method.graph_labels('unobserved_attribute')


def test_directional_stages_and_independent_verification(tmp_path,request):
    from prompt_mechanism_study.experiment.context_validation import run_directional_validation
    from prompt_mechanism_study.verification.directional_transfer import verify_directional
    plan = read_json(Path('configs/jci-directional-smoke.json'))
    plan.update(scenarios=['proxy_mechanism_change','cancellation','unobserved_attribute'],
        source_discovery_task_units=128,target_fitting_task_units=8,
        target_calibration_task_units=8,target_ranking_task_units=16,
        ridge_penalties=[1.],deviation_penalties=[10.],confirmation_task_units_per_hypothesis=1024)
    output = tmp_path/'directional'
    result = run_directional_validation(write_json_new(tmp_path/'plan.json',plan),output,Path(request.config.getoption('--rscript')),workers=2)
    assert result['cells']==6 and result['new_model_calls']==0
    assert result['effect_estimator']=='target_randomization_only'
    assert result['graph_component_status']=='BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS'
    checked = verify_directional(output,workers=2)
    assert checked['status']=='VERIFIED' and checked['models']>100


def test_exposed_context_preparation_cannot_claim_independent_representation_advantage(tmp_path):
    from prompt_mechanism_study.experiment.context_validation import prepare_directional_contexts
    from prompt_mechanism_study.verification.context_validation import verify_preparation
    root = Path('data/method/jci-context-preparation-20261030')
    output = tmp_path/'prepared'
    result = prepare_directional_contexts(root/'sources',root/'annotations.json',output)
    assert result['task_units']==4 and result['prepared_prompts']==32 and result['graph_advantage']=='NOT_TESTED'
    checked = verify_preparation(output)
    assert checked['status']=='VERIFIED' and checked['semantic_review']=='PENDING_INDEPENDENT_REVIEW'


def test_invalid_roles_rejected_before_any_new_output(tmp_path):
    from prompt_mechanism_study.experiment.context_validation import run_directional_validation
    plan = read_json(Path('configs/jci-directional-smoke.json'))
    plan['target_calibration_task_units'] = 8
    output = tmp_path/'invalid'
    with pytest.raises(ValueError):
        run_directional_validation(write_json_new(tmp_path/'bad.json',plan),output,Path('Rscript'))
    assert not output.exists()

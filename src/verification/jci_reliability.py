from __future__ import annotations

from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from functools import partial
import hashlib
import itertools
import json
import subprocess
import zipfile

import networkx as nx
import numpy as np
from scipy.stats import random_table, t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery.jci_reliability import exact_conditional_association, exact_joint_distribution
from prompt_mechanism_study.discovery.jci_sharing import StructureBackend
from prompt_mechanism_study.verification.jci_policy import independent_actions, independent_baseline, independent_features, independent_value


def diagnose_false_zeros(parent, output, rscript, limit=None):
    verify_bundle(parent/'inputs')
    plan = read_json(parent/'inputs'/'plan.json')
    workspace = Path('.test-tmp/jci-reliability-trace')
    workspace.mkdir(exist_ok=True)
    raw = workspace/('representative.json' if limit is not None else 'complete.json')
    with (workspace/'stderr.log').open('w',encoding='utf-8') as errors:
        subprocess.run([str(rscript),'src/verification/jci_trace.R',str(parent),str(raw),str(limit or 0)],
                       check=True,stderr=errors)
    traced = read_json(raw)
    laws, dag_cache, identities = {}, {}, {}
    for row in traced['traces']:
        source = parent/'cells'/row['cell']
        if row['cell'] not in identities:
            verify_bundle(source)
            identities[row['cell']] = file_sha256(source/'result.json')
            cell = read_json(source/'result.json')
            beta = tuple(cell['beta'])
            labels = cell['learned']['graphs'][0]['labels']
            laws[row['cell']] = (labels,*exact_joint_distribution(beta,plan,1))
            graph = nx.DiGraph()
            graph.add_edges_from([('U','Y')])
            for index, coefficient in enumerate(beta,1):
                graph.add_edges_from([('R',f'C{index}'),('U',f'X{index}'),(f'C{index}',f'X{index}')])
                if coefficient:
                    graph.add_edge(f'X{index}','Y')
            dag_cache[row['cell']] = graph
        if row['removal_query'] is not None:
            labels, values, weights = laws[row['cell']]
            query = row['removal_query']
            row['exact_distribution'] = exact_conditional_association(values,weights,labels,
                query['x'],query['y'],query['conditioned'])
            row['dag_separated'] = nx.is_d_separator(dag_cache[row['cell']],{query['x']},{query['y']},set(query['conditioned']))
    summary = []
    for mechanism, size, method in sorted({(row['mechanism'],row['n'],row['method']) for row in traced['traces']}):
        selected = [row for row in traced['traces'] if (row['mechanism'],row['n'],row['method'])==(mechanism,size,method)]
        active = [row for row in selected if row['beta']!=0]
        false = [row for row in active if row['final_ancestry']==-1]
        removed = [row for row in false if not row['context_outcome_adjacent']]
        summary.append(dict(mechanism=mechanism,n=size,method=method,active_policy_graph_positions=len(active),
            false_nonancestor_positions=len(false),deleted_context_outcome_positions=len(removed),
            unconditional_removals=sum(not row['separating_set'] for row in removed),
            zero_informative_strata=sum(row['removal_query']['informative_strata']==0 for row in removed),
            exact_dependence_nonrejections=sum(not row['exact_distribution']['independent'] for row in removed),
            exact_independence_with_dag_connection=sum(row['exact_distribution']['independent'] and not row['dag_separated'] for row in removed),
            temporal_orientation_changed=sum(row['initial_ancestry']!=row['final_ancestry'] for row in false)))
    result = dict(evidence_role='POST_HOC_EXPOSED_FALSE_ZERO_CAUSE_DIAGNOSTIC',cells=traced['cells'],
        graph_searches=traced['cells']*9*3,summary=summary,traces=traced['traces'],source_results=identities,
        parent_input_manifest_sha256=file_sha256(parent/'inputs'/'manifest.json'),
        implementation_sha256=file_sha256(Path(__file__)),r_implementation_sha256=file_sha256(Path('src/verification/jci_trace.R')))
    write_bundle(output,{'result.json':result})
    return dict(cells=result['cells'],graph_searches=result['graph_searches'],summary=summary)


def independent_stream(seed, *coordinates):
    encoded = json.dumps([seed,*coordinates]).encode()
    return np.random.default_rng(int.from_bytes(hashlib.sha256(encoded).digest()[:8],'big'))


def independent_centered_design(data, family):
    features = independent_features(data,family)
    result = -np.sum(features,axis=1)/(features.shape[1]+1)
    for index,arm in enumerate(data['a']):
        if arm:
            result[index] += features[index,int(arm)-1]
    return result


def independent_ridge(design, target, penalties):
    complete = np.column_stack((np.ones(len(design)),design))
    gram = complete.T@complete/len(complete)+np.diag(np.r_[0.,penalties])
    values,vectors = np.linalg.eigh(gram)
    if values.min()<=0:
        raise ValueError('独立核验的惩罚设计无效')
    right = complete.T@np.asarray(target)/len(complete)
    return vectors@((vectors.T@right)/values)


def check_effect_model(model, design, residual):
    coefficient = np.asarray(model['coefficients'])
    complete = np.r_[model['intercept'],coefficient]
    if model['kind']=='ridge':
        penalties = np.asarray(model['penalties'])
        assert np.all(penalties>0) and np.isfinite(penalties).all()
        reference = independent_ridge(design,residual,penalties)
        np.testing.assert_allclose(reference,complete,atol=2e-8,rtol=2e-8)
    elif model['kind']=='elastic_net':
        error = design@coefficient+model['intercept']-residual
        gradient = design.T@error/len(design)+model['penalty']*(1-model['l1_ratio'])*coefficient
        nonzero = coefficient!=0
        threshold = model['penalty']*model['l1_ratio']
        np.testing.assert_allclose(gradient[nonzero]+threshold*np.sign(coefficient[nonzero]),0.,atol=2e-7)
        assert np.all(np.abs(gradient[~nonzero])<=threshold+2e-7)
        np.testing.assert_allclose(error.mean(),0.,atol=1e-10)
        assert 0<=model['iterations']<20000
    else:
        raise ValueError('独立核验发现未声明的效果模型')


def verify_drawn_tasks(data, beta, plan, coordinates, role):
    mechanism,size,generations,batch,repetition = coordinates
    seed = plan['batch_seeds'][batch]
    base = np.asarray(plan['simulation']['mechanisms'][mechanism])
    permutation = independent_stream(seed,*coordinates,'policy-permutation').permutation(len(base))
    np.testing.assert_array_equal(base[permutation],beta)
    rng = independent_stream(seed,*coordinates,role)
    latent = rng.integers(0,2,size)
    probability = np.asarray(plan['simulation']['source_probability_by_latent'])[latent]
    source = rng.binomial(1,probability[:,None],size=(size,len(beta)))
    assignment = rng.integers(0,len(beta)+1,size)
    prepared = np.asarray([[1 if arm==policy+1 else source[index,policy] for policy in range(len(beta))]
                           for index,arm in enumerate(assignment)])
    mean = (plan['simulation']['baseline_probability']
        +plan['simulation']['latent_outcome_by_mechanism'][mechanism]*latent+prepared@beta)
    successes = rng.binomial(generations,mean)
    np.testing.assert_array_equal(source,data['w'])
    np.testing.assert_array_equal(prepared,data['x'])
    np.testing.assert_array_equal(assignment,data['a'])
    np.testing.assert_array_equal(successes,data['successes'])
    np.testing.assert_array_equal(source.astype(bool),data['identity_zero'])
    np.testing.assert_allclose(successes/generations,data['y'],atol=1e-15)
    expected = [f'{plan["study_id"]}/{mechanism}/{size}/{generations}/{batch}/{repetition}/{role}/{index}' for index in range(size)]
    assert data['task_ids']==expected and len(set(expected))==size


def reconstructed_ci_statistic(states, counts, levels, labels, query):
    indexes = {name:index for index,name in enumerate(labels)}
    columns = [indexes[name] for name in [*query['conditioned'],query['x'],query['y']]]
    dimensions = tuple(levels[index] for index in columns)
    cells = np.ravel_multi_index(states[:,columns].T,dimensions)
    table = np.bincount(cells,weights=counts,minlength=int(np.prod(dimensions))).reshape((-1,*dimensions[-2:]))
    row_sums,column_sums = table.sum(axis=2),table.sum(axis=1)
    totals = table.sum(axis=(1,2))
    numerator = row_sums[:,:,None]*column_sums[:,None,:]
    expected = np.divide(numerator,totals[:,None,None],out=np.zeros_like(table),where=totals[:,None,None]>0)
    statistic = np.divide((table-expected)**2,expected,out=np.zeros_like(table),where=expected>0).sum()
    informative = int(np.count_nonzero((np.count_nonzero(row_sums,axis=1)>1)&(np.count_nonzero(column_sums,axis=1)>1)))
    return float(statistic),informative


def verify_direct_randomization_test(observations, labels, query, draws, seed):
    indexes = {name:index for index,name in enumerate(labels)}
    columns = [indexes[name] for name in query['conditioned']]
    groups = np.unique(observations[:,columns],axis=0,return_inverse=True)[1]
    key = query['x'],query['y'],tuple(query['conditioned'])
    rng = np.random.default_rng(int.from_bytes(hashlib.sha256(json.dumps([seed,key]).encode()).digest()[:8],'big'))
    simulated = np.zeros(draws)
    statistic = 0.
    for group in range(int(groups.max())+1):
        selected = observations[groups==group]
        left,right = selected[:,indexes[query['x']]],selected[:,indexes[query['y']]]
        table = np.asarray([[np.count_nonzero((left==x)&(right==y)) for y in sorted(set(right))]
                            for x in sorted(set(left))])
        if table.shape[0]<=1 or table.shape[1]<=1:
            continue
        row,column = table.sum(axis=1),table.sum(axis=0)
        expectation = row[:,None]*column[None,:]/table.sum()
        statistic += float(np.sum((table-expectation)**2/expectation))
        null = random_table.rvs(row,column,size=draws,random_state=rng)
        simulated += np.sum((null-expectation)**2/expectation,axis=(1,2))
    assert query['exceedances']==int(np.count_nonzero(simulated>=statistic-1e-12))
    np.testing.assert_allclose(statistic,query['statistic'],atol=1e-10)


def verify_structure(record, plan):
    training = record['training']
    structure = record['structure']
    width = len(record['beta'])
    labels = [f'C{index+1}' for index in range(width)]+[f'X{index+1}' for index in range(width)]+['Y']
    assert structure['labels']==labels and structure['task_ids']==training['task_ids']
    expected_seed = [plan['seed'],record['mechanism'],record['n'],record['generations'],record['batch'],record['repetition'],'structure']
    assert structure['conditional_seed']==expected_seed
    contexts = np.asarray(training['a'])[:,None]==np.arange(1,width+1)
    observations = np.column_stack((contexts,training['x'],training['successes'])).astype(int)
    states,counts = np.unique(observations,axis=0,return_counts=True)
    levels = [2]*(2*width)+[record['generations']+1]
    queries = {}
    for query in structure['queries']:
        key = query['x'],query['y'],tuple(query['conditioned'])
        assert key not in queries and list(query['conditioned'])==sorted(query['conditioned'])
        assert query['x']<query['y'] and query['x'] not in query['conditioned'] and query['y'] not in query['conditioned']
        statistic,informative = reconstructed_ci_statistic(states,counts,levels,labels,query)
        np.testing.assert_allclose(statistic,query['statistic'],atol=1e-8,rtol=1e-10)
        assert informative==query['informative_strata']
        assert 0<=query['exceedances']<=plan['ci_draws']
        assert query['p']==(1+query['exceedances'])/(1+plan['ci_draws'])
        queries[key] = query
    direct,dependent = [],[]
    for policy in range(width):
        key = labels[policy],'Y',tuple(name for name in labels[:width] if name!=labels[policy])
        query = queries[key]
        verify_direct_randomization_test(observations,labels,query,plan['ci_draws'],expected_seed)
        direct.append(float(query['informative_strata']>0 and query['p']>=plan['ci_alpha']))
        dependent.append(bool(query['informative_strata']>0 and query['p']<plan['ci_alpha']))
    assert dependent==structure['direct_dependence']
    priors = {}
    for name in plan['structural_methods']:
        graph = structure['graphs'][name]
        assert graph['conservative'] is True and graph['pcalg']=='2.7.12'
        pag,ancestry = np.asarray(graph['pag']),np.asarray(graph['ancestry'])
        assert pag.shape==ancestry.shape==(2*width+1,2*width+1)
        assert np.isin(pag,(0,1,2,3)).all() and np.isin(ancestry,(-1,0,1)).all()
        np.testing.assert_array_equal(pag==0,pag.T==0)
        np.testing.assert_array_equal(np.diag(pag),0)
        np.testing.assert_array_equal(ancestry[:width,-1],[graph['context_ancestry'][label] for label in labels[:width]])
        if name=='jci123':
            np.testing.assert_array_equal(pag[:width,:width],2*(1-np.eye(width,dtype=int)))
        raw = (ancestry[:width,-1]==-1).astype(float)
        np.testing.assert_array_equal(raw,structure['raw_nonancestor'][name])
        priors[name] = raw*np.asarray(direct)
    raw_adjacency = (np.asarray(structure['graphs']['jci123']['pag'])[:width,-1]==0).astype(float)
    np.testing.assert_array_equal(raw_adjacency,structure['raw_nonancestor']['adjacency'])
    priors['adjacency'] = raw_adjacency*np.asarray(direct)
    priors['direct_ci'] = np.asarray(direct)
    priors['jci123_unprotected'] = np.asarray(structure['raw_nonancestor']['jci123'])
    for name,prior in priors.items():
        np.testing.assert_array_equal(prior,structure['guarded_priors'][name])
    return priors,len(queries)


def verify_reliable_learning(record, plan):
    training,calibration = record['training'],record['calibration']
    learned = record['learned']
    coordinates = (record['mechanism'],record['n'],record['generations'],record['batch'],record['repetition'])
    beta = np.asarray(record['beta'])
    verify_drawn_tasks(training,beta,plan,coordinates,'D')
    verify_drawn_tasks(calibration,beta,plan,coordinates,'CAL')
    assert set(training['task_ids']).isdisjoint(calibration['task_ids'])
    priors,query_count = verify_structure(record,plan)
    assert learned['coefficients_fixed_to_zero'] is False
    n = len(training['task_ids'])
    source_basis = independent_baseline(training['w'])
    cal_basis = independent_baseline(calibration['w'])
    folds = np.empty(n,dtype=int)
    permutation = independent_stream(plan['seed'],*coordinates,'nuisance-fold').permutation(n)
    folds[permutation] = np.arange(n)%plan['nuisance_folds']
    np.testing.assert_array_equal(folds,learned['nuisance']['folds'])
    training_mean = np.empty(n)
    fits = 0
    for fold,saved in enumerate(learned['nuisance']['crossfit_models']):
        selected = folds!=fold
        reference = independent_ridge(source_basis[selected],np.asarray(training['y'])[selected],
                                      np.full(source_basis.shape[1],plan['nuisance_penalty']))
        np.testing.assert_allclose(reference,[saved['intercept'],*saved['coefficients']],atol=1e-9)
        training_mean[~selected] = np.clip(reference[0]+source_basis[~selected]@reference[1:],0.,1.)
        fits += 1
    complete = independent_ridge(source_basis,training['y'],np.full(source_basis.shape[1],plan['nuisance_penalty']))
    np.testing.assert_allclose(complete,[learned['nuisance']['complete_model']['intercept'],
        *learned['nuisance']['complete_model']['coefficients']],atol=1e-9)
    cal_mean = np.clip(complete[0]+cal_basis@complete[1:],0.,1.)
    np.testing.assert_allclose(training_mean,learned['nuisance']['training_means'],atol=1e-9)
    np.testing.assert_allclose(cal_mean,learned['nuisance']['calibration_means'],atol=1e-9)
    residual = np.asarray(training['y'])-training_mean
    cal_order = independent_stream(plan['seed'],*coordinates,'calibration-partition').permutation(n)
    boundary = int(n*plan['calibration_fit_fraction'])
    fit_indexes,policy_indexes = np.sort(cal_order[:boundary]),np.sort(cal_order[boundary:])
    np.testing.assert_array_equal(fit_indexes,learned['calibration_fit_indexes'])
    np.testing.assert_array_equal(policy_indexes,learned['calibration_policy_indexes'])
    assert set(fit_indexes).isdisjoint(policy_indexes) and len(fit_indexes)+len(policy_indexes)==n
    designs = {family:independent_centered_design(training,family) for family in plan['learner_families']}
    cal_designs = {family:independent_centered_design(calibration,family) for family in plan['learner_families']}
    score_design = np.column_stack((np.ones(n),designs['target_factorized']))
    score_coef = np.linalg.solve(score_design.T@score_design,score_design.T@residual)
    score_error = residual-score_design@score_coef
    inverse = np.linalg.inv(score_design.T@score_design)
    covariance = inverse@np.einsum('ni,nj,n->ij',score_design,score_design,score_error**2)@inverse
    variance = np.diag(covariance)[1:]
    priors['direct_score'] = 1/(1+score_coef[1:]**2/variance)
    np.testing.assert_allclose(score_coef,learned['direct_score']['coefficients'],atol=1e-9)
    np.testing.assert_allclose(variance,learned['direct_score']['variance'],atol=1e-9)
    np.testing.assert_allclose(priors['direct_score'],learned['direct_score']['prior'],atol=1e-9)
    auxiliary = learned['policy_nuisance_model']
    check_effect_model(auxiliary,designs['target_factorized'],residual)
    np.testing.assert_allclose(auxiliary['penalties'],plan['policy_nuisance_penalty'],atol=1e-15)
    cal_features = independent_features(calibration,'target_factorized')
    auxiliary_effect = cal_features@np.asarray(auxiliary['coefficients'])
    baseline = cal_mean+auxiliary['intercept']-auxiliary_effect.sum(axis=1)/(len(beta)+1)
    means = np.clip(np.column_stack((baseline,baseline[:,None]+auxiliary_effect)),0.,1.)
    cal_assignment = np.asarray(calibration['a'])
    position = np.arange(n)
    outcome_residual = np.asarray(calibration['y'])-means[position,cal_assignment]
    def policy_gain(scores):
        action = independent_actions(scores)
        values = means[position,action]-means[:,0]
        values += (len(beta)+1)*outcome_residual*((cal_assignment==action).astype(float)-(cal_assignment==0).astype(float))
        return float(values[policy_indexes].mean())
    models = learned['models']
    for model in models:
        family = model['family']
        check_effect_model(model,designs[family],residual)
        prediction = cal_mean+model['intercept']+cal_designs[family]@np.asarray(model['coefficients'])
        loss = float(np.mean((np.asarray(calibration['y'])[fit_indexes]-prediction[fit_indexes])**2))
        np.testing.assert_allclose(loss,model['calibration_fit_loss'],atol=1e-9)
        scores = independent_features(calibration,family)@np.asarray(model['coefficients'])
        np.testing.assert_allclose(policy_gain(scores),model['calibration_policy_gain'],atol=1e-9)
        fits += 1
    chosen_by_method = {}
    for name,groups in learned['calibration_groups'].items():
        chosen_by_method[name] = []
        for group in groups:
            family,strength = group['family'],group['strength']
            columns = designs[family].shape[1]
            for offset,index in enumerate(group['model_ids']):
                model = models[index]
                assert model['family']==family
                if name=='elastic_net':
                    penalty,ratio = list(itertools.product(plan['direct_penalties'],plan['elastic_net_ratios']))[offset]
                    assert model['kind']=='elastic_net' and model['penalty']==penalty and model['l1_ratio']==ratio
                else:
                    penalty = (plan['direct_penalties'] if name=='ridge' else plan['ridge_penalties'])[offset]
                    prior = np.ones(len(beta)) if name=='ridge' else 1-strength+strength*priors[name]
                    np.testing.assert_allclose(model['penalties'],penalty*np.repeat(prior,columns//len(beta)),atol=1e-12)
            selected = min(group['model_ids'],key=lambda index:(models[index]['calibration_fit_loss'],index))
            assert selected==group['selected_model_id']
            chosen_by_method[name].append(selected)
    for name,selected in chosen_by_method.items():
        expected = list(dict.fromkeys([*chosen_by_method['ridge'],*selected]))
        assert expected==learned['policy_model_ids'][name]
    direct_names = ('ridge','elastic_net','direct_score','direct_ci','adjacency')
    expected_direct = list(dict.fromkeys(index for name in direct_names for index in learned['policy_model_ids'][name]))
    assert expected_direct==learned['policy_model_ids']['direct_envelope']
    states = np.asarray(list(itertools.product((0,1),repeat=len(beta))))
    evaluation = dict(w=states.tolist(),identity_zero=states.astype(bool).tolist())
    value_plan = dict(simulation=dict(plan['simulation'],latent_outcome_coefficient=
        plan['simulation']['latent_outcome_by_mechanism'][record['mechanism']]))
    for name,options in learned['policy_model_ids'].items():
        best = max(options,key=lambda index:(models[index]['calibration_policy_gain'],-index))
        best = None if models[best]['calibration_policy_gain']<=0 else best
        assert best==learned['choices'][name]['model_id']
        if best is None:
            scores = np.zeros_like(states,dtype=float)
            assert learned['choices'][name]['effect_estimate'] is None
        else:
            scores = independent_features(evaluation,models[best]['family'])@np.asarray(models[best]['coefficients'])
        np.testing.assert_allclose(scores,learned['outputs'][name]['scores'],atol=1e-9)
        np.testing.assert_array_equal(independent_actions(scores),learned['outputs'][name]['actions'])
        reference = independent_value(scores,beta,value_plan)
        for field in ('gain','value','regret'):
            np.testing.assert_allclose(reference[field],record['values'][name][field],atol=1e-12)
    ideal = record['ideal_structure']
    np.testing.assert_array_equal(ideal['prior'],beta==0)
    ideal_models = {model['model_id']:model for model in ideal['models']}
    for model in ideal_models.values():
        family = model['family']
        check_effect_model(model,designs[family],residual)
        prediction = cal_mean+model['intercept']+cal_designs[family]@np.asarray(model['coefficients'])
        np.testing.assert_allclose(np.mean((np.asarray(calibration['y'])[fit_indexes]-prediction[fit_indexes])**2),
                                   model['calibration_fit_loss'],atol=1e-9)
        np.testing.assert_allclose(policy_gain(independent_features(calibration,family)@np.asarray(model['coefficients'])),
                                   model['calibration_policy_gain'],atol=1e-9)
        fits += 1
    ideal_selected = []
    for group in ideal['calibration_groups']:
        columns = designs[group['family']].shape[1]
        weights = np.repeat(1-group['strength']+group['strength']*(beta==0),columns//len(beta))
        for index,penalty in zip(group['model_ids'],plan['ridge_penalties'],strict=True):
            np.testing.assert_allclose(ideal_models[index]['penalties'],penalty*weights,atol=1e-12)
        selected = min(group['model_ids'],key=lambda index:(ideal_models[index]['calibration_fit_loss'],index))
        assert selected==group['selected_model_id']
        ideal_selected.append(selected)
    ideal_reference = ideal['policy_model_ids'][:len(chosen_by_method['ridge'])]
    for reference_id,index in zip(ideal_reference,chosen_by_method['ridge'],strict=True):
        current,ordinary = ideal_models[reference_id],models[index]
        assert current['family']==ordinary['family']
        np.testing.assert_allclose(current['penalties'],ordinary['penalties'],atol=1e-12)
    assert ideal['policy_model_ids']==list(dict.fromkeys([*ideal_reference,*ideal_selected]))
    best = max(ideal['policy_model_ids'],key=lambda index:(ideal_models[index]['calibration_policy_gain'],-index))
    best = None if ideal_models[best]['calibration_policy_gain']<=0 else best
    assert ideal['choice']['model_id']==best
    scores = (np.zeros_like(states,dtype=float) if best is None else
        independent_features(evaluation,ideal_models[best]['family'])@np.asarray(ideal_models[best]['coefficients']))
    np.testing.assert_allclose(scores,ideal['output']['scores'],atol=1e-9)
    np.testing.assert_array_equal(independent_actions(scores),ideal['output']['actions'])
    reference = independent_value(scores,beta,value_plan)
    for field in ('gain','value','regret'):
        np.testing.assert_allclose(reference[field],record['values']['ideal_structure'][field],atol=1e-12)
    return fits+2,query_count


def verify_reliability_record(path, plan):
    verify_bundle(path.parent)
    record = read_json(path)
    assert record['evidence_role']==plan['evidence_role'] and record['new_model_requests']==0
    fits,queries = verify_reliable_learning(record,plan)
    beta = np.asarray(record['beta'])
    diagnostics = {}
    for name,graph in record['structure']['graphs'].items():
        raw = np.asarray(graph['ancestry'])[:len(beta),-1]==-1
        guarded = np.asarray(record['structure']['guarded_priors'][name])>0
        diagnostics[name] = dict(active_positions=int(np.count_nonzero(beta)),
            false_raw_nonancestor=int(np.count_nonzero(raw & (beta!=0))),
            false_guarded_prior=int(np.count_nonzero(guarded & (beta!=0))),
            true_zero_prior=int(np.count_nonzero(guarded & (beta==0))),
            ambiguous_triples=len(graph['ambiguous_triples']))
    projection = {key:record[key] for key in ('mechanism','n','generations','batch','repetition','values')}
    projection['diagnostics'] = diagnostics
    projection['choices'] = {name:choice['model_id'] for name,choice in record['learned']['choices'].items()}
    return projection,fits,queries


def verify_reliability(output, workers=4):
    verifier_sources = {str(path):file_sha256(path) for path in (
        Path(__file__),Path('src/verification/jci_policy.py'))}
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs/plan.json')
    identity = read_json(output/'inputs/identity.json')
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        assert hashlib.sha256(archive.read('plan.json')).hexdigest()==identity['plan_sha256']
        assert json.loads(archive.read('plan.json'))==plan
        for source,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(source.replace('\\','/'))).hexdigest()==digest
            assert file_sha256(Path(source))==digest
    diagnosis = Path(plan['diagnosis_artifact'])
    verify_bundle(diagnosis)
    assert file_sha256(diagnosis/'manifest.json')==identity['diagnosis_manifest_sha256']
    assert file_sha256(Path(plan['diagnosis_source_archive']))==identity['diagnosis_source_archive_sha256']
    assert 1<=workers<=plan['workers']
    paths = sorted((output/'cells').glob('*/result.json'))
    records,fit_count,query_count = [],0,0
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for record,fits,queries in executor.map(partial(verify_reliability_record,plan=plan),paths):
            records.append(record)
            fit_count += fits
            query_count += queries
            if len(records)%32==0:
                print(f'Independently verified reliability cells: {len(records)}/{len(paths)}',flush=True)
    actual = {(row['mechanism'],row['n'],row['generations'],row['batch'],row['repetition']) for row in records}
    expected = set(itertools.product(sorted(plan['simulation']['mechanisms']),plan['simulation']['tasks_per_role'],
        plan['simulation']['generations_per_assigned_prompt'],range(len(plan['batch_seeds'])),range(plan['repetitions_per_batch'])))
    assert len(actual)==len(records) and actual.issubset(expected)
    complete = actual==expected
    if complete:
        verify_bundle(output/'summary')
        summary = read_json(output/'summary/result.json')
        conditions = sorted({row[:3] for row in expected})
        family = len(conditions)*len(plan['primary_comparators'])
        assert summary['cells']==len(records) and summary['family_size']==family
        assert summary['evidence_role']==plan['evidence_role']
        assert summary['structural_searches']==3*len(records) and summary['ci_queries']==query_count
        assert summary['independent_task_units']==sum(2*row['n'] for row in records)
        assert summary['simulated_generation_draws']==sum(2*row['n']*row['generations'] for row in records)
        assert summary['new_model_requests']==0
        assert [(row['mechanism'],row['n'],row['generations']) for row in summary['groups']]==conditions
        reliable_conditions = []
        for group in summary['groups']:
            selected = [row for row in records if all(row[field]==group[field] for field in ('mechanism','n','generations'))]
            assert len(selected)==group['independent_repetitions']==len(plan['batch_seeds'])*plan['repetitions_per_batch']
            assert [row['comparator'] for row in group['comparisons']]==plan['primary_comparators']
            reliable,smallest = True,float('inf')
            for comparison in group['comparisons']:
                comparator = comparison['comparator']
                difference = np.asarray([row['values'][plan['primary_method']]['gain']-row['values'][comparator]['gain'] for row in selected])
                np.testing.assert_allclose(sorted(difference),sorted(comparison['paired_differences']),atol=1e-14)
                center = float(difference.sum()/len(selected))
                error = float(np.sqrt(np.sum((difference-center)**2)/(len(selected)*(len(selected)-1))))
                bound = t.isf(plan['alpha']/(2*family),len(selected)-1)*error
                np.testing.assert_allclose(comparison['mean_difference'],center,atol=1e-12)
                np.testing.assert_allclose(comparison['simultaneous_interval'],[center-bound,center+bound],atol=1e-12)
                batches = [float(np.mean([delta for row,delta in zip(selected,difference,strict=True) if row['batch']==batch]))
                           for batch in range(len(plan['batch_seeds']))]
                np.testing.assert_allclose(comparison['batch_mean_differences'],batches,atol=1e-12)
                passed = bool(center-bound>0 and all(value>0 for value in batches))
                assert comparison['reliable']==passed
                reliable &= passed
                smallest = min(smallest,center)
            assert group['reliable_increment']==reliable
            assert group['practical_increment']==(smallest>=plan['practical_gain'])
            if reliable:
                reliable_conditions.append({field:group[field] for field in ('mechanism','n','generations')})
            for name in selected[0]['values']:
                for field,target in (('gain','mean_gains'),('regret','mean_regrets')):
                    np.testing.assert_allclose(group[target][name],np.mean([row['values'][name][field] for row in selected]),atol=1e-12)
            for name in selected[0]['choices']:
                assert group['baseline_choices'][name]==sum(row['choices'][name] is None for row in selected)
            for name in plan['structural_methods']:
                for field in group['graph_diagnostics'][name]:
                    assert group['graph_diagnostics'][name][field]==sum(row['diagnostics'][name][field] for row in selected)
        assert summary['reliable_conditions']==reliable_conditions
    for path,digest in verifier_sources.items():
        assert file_sha256(Path(path))==digest
    result = dict(status='VERIFIED',complete=complete,cells=len(records),planned_cells=len(expected),
        independently_verified_effect_models=fit_count,independently_reconstructed_ci_statistics=query_count,
        independently_replayed_direct_ci_tests=4*len(records),
        randomization_and_role_separation_verified=True,finite_penalties_verified=True,
        ideal_structure_separated_verified=True,policy_selection_and_exact_values_verified=True,
        simultaneous_comparisons_verified=complete,source_archive_verified=True,
        implementation_sha256=file_sha256(Path(__file__)),verification_sources=verifier_sources)
    if complete and not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result


def diagnose_population_information(parent, output, rscript):
    verify_bundle(parent/'inputs')
    plan = read_json(parent/'inputs/plan.json')
    logs = Path('.test-tmp/jci-population-information')
    logs.mkdir(exist_ok=True)
    labels = ['C1','C2','C3','C4','X1','X2','X3','X4','Y']
    records = []
    for mechanism,generations in itertools.product(sorted(plan['simulation']['mechanisms']),
                                                   plan['simulation']['generations_per_assigned_prompt']):
        beta = np.asarray(plan['simulation']['mechanisms'][mechanism])
        specification = dict(simulation=dict(plan['simulation'],latent_outcome_coefficient=
            plan['simulation']['latent_outcome_by_mechanism'][mechanism]))
        rows,weights = exact_joint_distribution(beta,specification,generations)
        dag = nx.DiGraph()
        if specification['simulation']['latent_outcome_coefficient']:
            dag.add_edge('U','Y')
        for index in range(4):
            dag.add_edges_from([('R',labels[index]),('U',labels[4+index]),(labels[index],labels[4+index])])
            if beta[index]:
                dag.add_edge(labels[4+index],'Y')
        class PopulationIndependence:
            def __init__(self):
                self.cache = {}

            def query(self, x, y, conditioned):
                key = *sorted((x,y)),tuple(sorted(conditioned))
                if key not in self.cache:
                    result = exact_conditional_association(rows,weights,labels,*key)
                    result['dag_separated'] = nx.is_d_separator(dag,{key[0]},{key[1]},set(key[2]))
                    self.cache[key] = result
                return float(self.cache[key]['independent'])
        ci = PopulationIndependence()
        backend = StructureBackend(rscript,logs/f'{mechanism}-g{generations}.log',Path('src/discovery/jci_reliability.R'))
        try:
            graphs = {name:backend.search(labels,name,ci,plan['ci_alpha']) for name in plan['structural_methods']}
        finally:
            backend.close()
        direct = [bool(ci.query(label,'Y',[other for other in labels[:4] if other!=label])) for label in labels[:4]]
        queries = [dict(x=key[0],y=key[1],conditioned=list(key[2]),**value) for key,value in ci.cache.items()]
        records.append(dict(mechanism=mechanism,generations=generations,beta=beta.tolist(),
            true_zero_policies=(beta==0).tolist(),direct_population_independence=direct,graphs=graphs,
            queries=queries,faithfulness_violations=sum(query['independent'] and not query['dag_separated'] for query in queries),
            markov_violations=sum(query['dag_separated'] and not query['independent'] for query in queries)))
        print(f'Exact population JCI information checked: {mechanism}, generations={generations}',flush=True)
    result = dict(evidence_role='POST_HOC_POPULATION_INFORMATION_DIAGNOSTIC',records=records,
        parent_input_manifest_sha256=file_sha256(parent/'inputs/manifest.json'),new_model_requests=0,
        implementation_sha256=file_sha256(Path(__file__)),
        distribution_implementation_sha256=file_sha256(Path('src/discovery/jci_reliability.py')),
        r_implementation_sha256=file_sha256(Path('src/discovery/jci_reliability.R')))
    write_bundle(output,{'result.json':result})
    return dict(conditions=len(records),direct_population_nulls_equal_true_nulls=all(
        record['true_zero_policies']==record['direct_population_independence'] for record in records),
        markov_violations=sum(record['markov_violations'] for record in records),
        faithfulness_violations=sum(record['faithfulness_violations'] for record in records))

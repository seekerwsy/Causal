from __future__ import annotations

import hashlib
from concurrent.futures import ProcessPoolExecutor
import itertools
import json
import multiprocessing
from pathlib import Path
import zipfile

import numpy as np
import networkx as nx
from scipy.stats import binom, random_table, t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


LABELS = ['C1','C2','A','W','X','N','D1','D2','Y']


def random_generator(seed,*coordinates):
    return np.random.default_rng(int.from_bytes(hashlib.sha256(json.dumps([seed,*coordinates]).encode()).digest()[:8],'big'))


def probabilities(rows,u,environment,h,scenario):
    c1,c2,a,w,x,n,d1,d2 = np.asarray(rows)[:,:8].T
    probe = .02 if scenario=='weak_context' else .2
    px = .15+.6*c1+.05*w
    pn = .05+.65*u+probe*c2 if environment==0 or scenario=='stable_proxy' else .7-.5*u+probe*c2
    effect = [.18,.12,.02,-.06][h]+.1*(2*x-1)+.1*(2*u-1)
    py = .32+.1*x+.12*u+.02*w+a*effect
    py += .03*c2 if scenario=='source_spillover' else 0
    py += .04*(2*a-1) if scenario=='outcome_shift' and environment==1 else 0
    py += .03*n+.02*a*(2*n-1) if scenario=='nuisance_is_causal' else 0
    return px,pn,py


def replay(data,rng,h,scenario):
    n = len(data['observations'])
    c1,c2,a,w,u,d1,d2 = rng.integers(0,2,size=(n,7)).T
    rows = np.column_stack((c1,c2,a,w,np.zeros(n,dtype=int),np.zeros(n,dtype=int),d1,d2))
    px,pn,_ = probabilities(rows,u,data['environment'],h,scenario)
    rows[:,4],rows[:,5] = rng.binomial(1,px),rng.binomial(1,pn)
    py = probabilities(rows,u,data['environment'],h,scenario)[2]
    rows = np.column_stack((rows,rng.binomial(1,py)))
    np.testing.assert_array_equal(data['observations'],rows)
    np.testing.assert_array_equal(data['u'],u)
    assert data['task_ids']==[f'{data["identity"]}/{index}' for index in range(n)]
    return rng


def matrix(rows,model):
    indexes = [2,3]+[4+bit for bit in range(4) if model['mask']&(2**bit)]
    indexes += [bit for bit in (0,1) if model['contexts'] or model['mask']&(1<<(4+bit))]
    values = 2*np.asarray(rows)[:,indexes]-1
    columns = [np.ones(len(values))]
    for degree in (1,2,3):
        columns += [np.prod(values[:,selected],axis=1) for selected in itertools.combinations(range(len(indexes)),degree)]
    return np.column_stack(columns)


def prediction(model,rows,environment=1):
    if 'components' in model:
        bases = {}
        output = np.zeros(len(rows))
        for weight,component in zip(model['weights'],model['components'],strict=True):
            if weight==0:
                continue
            key = component['mask'],component['contexts'],component['mode']=='deviation'
            if key not in bases:
                base = matrix(rows,component)
                if key[2]:
                    base = np.column_stack((base,environment*matrix(rows,dict(mask=component.get('allowed',15),contexts=True))))
                bases[key] = base
            output += weight*np.clip(bases[key]@np.asarray(component['coefficients']),0,1)
        return output
    design = matrix(rows,model)
    if model['mode']=='deviation':
        correction = matrix(rows,dict(mask=model.get('allowed',15),contexts=True))
        design = np.column_stack((design,environment*correction))
    return np.clip(design@np.asarray(model['coefficients']),0,1)


def calibration_error(model,data):
    rows = np.asarray(data['observations'])
    zero,one = rows.copy(),rows.copy()
    zero[:,2],one[:,2] = 0,1
    mean = (prediction(model,zero)+prediction(model,one))/2
    return float(np.mean((rows[:,-1]-mean)**2))


def verify_fit(model,source,target):
    rows = np.asarray(target['observations'] if model['mode']=='target' else source['observations']+target['observations'])
    design = matrix(rows,model)
    penalty = np.full(design.shape[1],model['penalty'])
    if model['mode']=='deviation':
        environment = np.r_[np.zeros(len(source['observations'])),np.ones(len(target['observations']))]
        correction = matrix(rows,dict(mask=model.get('allowed',15),contexts=True))
        design = np.column_stack((design,correction*environment[:,None]))
        penalty = np.r_[penalty,np.full(correction.shape[1],model['deviation'])]
    coefficient = np.asarray(model['coefficients'])
    # 正惩罚使目标严格凸，独立重建正规方程即可检查唯一解。
    assert np.all(penalty>0)
    residual = design.T@(design@coefficient-rows[:,-1])+penalty*coefficient
    np.testing.assert_allclose(residual,0.,atol=2e-8)


def verify_scores(record,model,data):
    rows = np.asarray(data['observations'])
    zero,one = rows.copy(),rows.copy()
    zero[:,2],one[:,2] = 0,1
    p0,p1 = prediction(model,zero),prediction(model,one)
    values = []
    for row,left,right in zip(rows,p0,p1,strict=True):
        value = right-left
        if row[2]:
            value += 2*(row[-1]-right)
        else:
            value -= 2*(row[-1]-left)
        values.append(value)
    np.testing.assert_allclose(record['predictions'],np.column_stack((p0,p1)),atol=1e-12)
    np.testing.assert_allclose(record['scores'],values,atol=1e-12)
    np.testing.assert_allclose(np.square(values),4*(rows[:,-1]-(p0+p1)/2)**2,atol=1e-12)
    np.testing.assert_allclose(record['effect'],np.mean(values),atol=1e-12)
    np.testing.assert_allclose(record['standard_error'],np.std(values,ddof=1)/np.sqrt(len(values)),atol=1e-12)


def verify_queries(queries,data,labels,draws,seed):
    states,counts = np.unique(np.asarray(data),axis=0,return_counts=True)
    for query in queries:
        x,y = sorted((query['x'],query['y']))
        conditioned = tuple(sorted(query['conditioned']))
        rng = random_generator(seed,(x,y,conditioned))
        columns = [labels.index(name) for name in conditioned]
        groups = np.unique(states[:,columns],axis=0,return_inverse=True)[1] if columns else np.zeros(len(states),dtype=int)
        statistic,null,informative,tables = 0.,np.zeros(draws),0,[]
        supported = True
        for group in np.unique(groups):
            chosen = groups==group
            xs,xi = np.unique(states[chosen,labels.index(x)],return_inverse=True)
            ys,yi = np.unique(states[chosen,labels.index(y)],return_inverse=True)
            table = np.zeros((len(xs),len(ys)),dtype=int)
            np.add.at(table,(xi,yi),counts[chosen])
            tables.append(table.tolist())
            if min(table.shape)==1:
                supported = False
                continue
            informative += 1
            supported = supported and min(table.sum(0))>=2 and min(table.sum(1))>=2
            expected = np.outer(table.sum(1),table.sum(0))/table.sum()
            statistic += np.sum((table-expected)**2/expected)
            samples = random_table.rvs(table.sum(1),table.sum(0),size=draws,random_state=rng)
            null += np.sum((samples-expected)**2/expected,axis=(1,2))
        exceedances = int(np.count_nonzero(null>=statistic-1e-12))
        assert query['tables']==tables and query['informative_strata']==informative and query['exceedances']==exceedances
        np.testing.assert_allclose(query['statistic'],statistic,atol=1e-10)
        assert query['p']==((exceedances+1)/(draws+1) if informative and supported else None)


def exact_population(h,scenario,environment=1):
    values = np.asarray(list(itertools.product((0,1),repeat=9)))
    u = values[:,4]
    rows = values[:,[0,1,2,3,5,6,7,8]]
    px,pn,py = probabilities(rows,u,environment,h,scenario)
    weights = (np.where(rows[:,4],px,1-px)*np.where(rows[:,5],pn,1-pn))/128
    return rows,u,weights,py


def verify_risk(record,model,h,scenario,ranking_size):
    rows,u,weights,py = exact_population(h,scenario)
    zero,one = rows.copy(),rows.copy()
    zero[:,2],one[:,2] = 0,1
    p0,p1 = prediction(model,zero),prediction(model,one)
    observed = np.where(rows[:,2],p1,p0)
    gamma0 = p1-p0+2*(2*rows[:,2]-1)*(0-observed)
    gamma1 = p1-p0+2*(2*rows[:,2]-1)*(1-observed)
    mean = weights@((1-py)*gamma0+py*gamma1)
    second = weights@((1-py)*gamma0**2+py*gamma1**2)
    brier = weights@(py*(1-observed)**2+(1-py)*observed**2)
    np.testing.assert_allclose(record['exact_effect'],mean,atol=1e-12)
    np.testing.assert_allclose(record['exact_effect_variance'],(second-mean**2)/ranking_size,atol=1e-12)
    np.testing.assert_allclose(record['target_brier_risk'],brier,atol=1e-12)
    np.testing.assert_allclose(record['target_prediction_excess_risk'],weights@((observed-py)**2),atol=1e-12)
    prognosis = (p0+p1)/2
    prognostic_risk = weights@(py*(1-prognosis)**2+(1-py)*prognosis**2)
    np.testing.assert_allclose(record['target_prognostic_risk'],prognostic_risk,atol=1e-12)
    np.testing.assert_allclose(second,4*prognostic_risk,atol=1e-12)
    return float(mean)


def proposals(graph):
    if graph['status']!='evaluated':
        return [],[]
    ancestry,pag = np.asarray(graph['ancestry']),np.asarray(graph['pag'])
    assert ancestry.shape==pag.shape==(9,9) and graph['conservative']
    np.testing.assert_array_equal(pag==0,pag.T==0)
    selected = [sum(2**bit for bit in range(4) if ancestry[bit+4,-1]==1),
                sum(2**bit for bit in range(4) if ancestry[bit+4,-1]!=-1)]
    return sorted(set(selected)),[sum(2**bit for bit in range(4) if pag[bit+4,-1])]


def verify_frozen_directional(output):
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs'/'plan.json')
    assert plan['nomination_rule']=='absolute_effect' and plan['confirmation_directions']=='both'
    assert plan['calibration_objective']=='averaged_arm_prediction_squared_error'
    assert plan['target_correction']=='all_measured_pre_assignment_attributes'
    identity = read_json(output/'inputs'/'identity.json')
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    verify_bundle(output/'oracle')
    oracles = read_json(output/'oracle'/'result.json')
    for scenario in plan['scenarios']:
        for h,oracle in enumerate(oracles[scenario]):
            rows,u,weights,py = exact_population(h,scenario,0)
            observations = np.column_stack((np.repeat(rows,2,axis=0),np.tile([0,1],len(rows))))
            masses = np.column_stack((weights*(1-py),weights*py)).ravel()
            for query in oracle['queries']:
                columns = [LABELS.index(name) for name in query['conditioned']]
                groups = np.unique(observations[:,columns],axis=0,return_inverse=True)[1] if columns else np.zeros(len(masses),dtype=int)
                tables = np.zeros((groups.max()+1,2,2))
                np.add.at(tables,(groups,observations[:,LABELS.index(query['x'])],observations[:,LABELS.index(query['y'])]),masses)
                expected = tables.sum(2)[:,:,None]*tables.sum(1)[:,None,:]/tables.sum((1,2))[:,None,None]
                assert query['p']==float(np.max(np.abs(tables-expected))<1e-12)
            rows,u,weights,_ = exact_population(h,scenario)
            means = []
            for a in (0,1):
                assigned = rows.copy()
                assigned[:,2] = a
                means.append(probabilities(assigned,u,1,h,scenario)[2])
            minus,plus = weights@(means[0]*(1-means[1])),weights@(means[1]*(1-means[0]))
            np.testing.assert_allclose(oracle['target_effect'],plus-minus,atol=1e-12)
            np.testing.assert_allclose([oracle['difference_distribution']['minus'],oracle['difference_distribution']['plus']],[minus,plus],atol=1e-12)
            n = plan['confirmation_task_units_per_hypothesis']
            counts = np.arange(n+1)
            cutoff = np.floor(counts+n*(plan['practical_effect']+np.sqrt(2*np.log(8/plan['confirmation_alpha'])/n)))
            for direction,opposite,favorable in (('positive',minus,plus),('negative',plus,minus)):
                power = np.sum(binom.pmf(counts,n,opposite)*binom.sf(cutoff,n-counts,favorable/(1-opposite)))
                np.testing.assert_allclose(oracle['confirmation_power'][direction],power,atol=1e-10)
                if favorable-opposite>plan['practical_effect']:
                    assert power>=plan['minimum_confirmation_power']
    cells,models_checked,queries_checked = [],0,0
    for path in sorted((output/'cells').iterdir()):
        verify_bundle(path)
        cell = read_json(path/'result.json')
        scenario,batch,repetition = cell['scenario'],cell['batch'],cell['repetition']
        seed = plan['batch_seeds'][batch]
        truths = []
        for row in cell['hypotheses']:
            h = row['hypothesis']
            coordinates = scenario,repetition,h
            identities = []
            for role,data in row['data'].items():
                replay(data,random_generator(seed,*coordinates,role),h,scenario)
                assert data['identity']==f'{seed}/{scenario}/{repetition}/{h}/{role}'
                assert len(data['observations'])==plan[f'{role}_task_units']
                identities += data['task_ids']
            assert len(identities)==len(set(identities))
            source,target,calibration,ranking = [row['data'][role] for role in ('source_discovery','target_fitting','target_calibration','target_ranking')]
            verify_queries(row['ci_queries'],source['observations'],LABELS,plan['ci_draws'],[seed,*coordinates,'graph'])
            learned = row['learned']
            joint = np.asarray(source['observations'])
            joint = np.column_stack((2*joint[:,0]+joint[:,1],joint[:,2:]))
            inv = learned['invariance_queries']
            verify_queries(inv['queries'],joint,['C','A','W','X','N','D1','D2','Y'],plan['ci_draws'],[seed,*coordinates,'invariance'])
            queries_checked += len(row['ci_queries'])+len(inv['queries'])
            accepted = []
            for decision in inv['decisions']:
                conditioned = sorted(['A','W']+[LABELS[4+bit] for bit in range(4) if decision['mask']>>bit&1])
                query = next(query for query in inv['queries'] if query['conditioned']==conditioned)
                complete = all(len(table)==4 for table in query['tables'])
                assert decision['complete_context_support']==complete and decision['p']==query['p']
                assert decision['accepted']==(complete and query['p'] is not None and query['p']>plan['ci_alpha'])
                if decision['accepted']:
                    accepted.append(decision['mask'])
            direction,adjacency = proposals(row['graph'])
            assert learned['proposals']['directional']==direction and learned['proposals']['adjacency']==adjacency
            assert learned['proposals']['direct_invariance']==accepted
            assert learned['proposals']['oracle_graph']==([3] if scenario=='nuisance_is_causal' else [1])
            assert learned['proposals']['population_graph']==proposals(oracles[scenario][h]['graph'])[0]
            def model_id(mask,penalty,mode='shared',deviation=None,contexts=False):
                matching = [index for index,model in enumerate(learned['models']) if
                    (model['mask'],model['penalty'],model['mode'],model['deviation'],model['contexts'])==
                    (mask,penalty,mode,deviation,contexts)]
                assert len(matching)==1
                return matching[0]
            target_ids = [model_id(15,penalty,'target',contexts=True) for penalty in plan['ridge_penalties']]
            pooled_ids = [model_id(15,penalty,contexts=True) for penalty in plan['ridge_penalties']]
            deviation_ids = [model_id(15,penalty,'deviation',deviation,True) for penalty,deviation in
                itertools.product(plan['ridge_penalties'],plan['deviation_penalties'])]
            common_ids = target_ids+pooled_ids+deviation_ids
            expected_groups = {name:common_ids+[model_id(mask,penalty,'deviation',deviation) for mask,penalty,deviation in
                itertools.product(masks,plan['ridge_penalties'],plan['deviation_penalties'])]
                for name,masks in learned['proposals'].items()}
            expected_groups['target_only'] = target_ids
            expected_groups['direct_deviation'] = common_ids
            expected_groups['direct_pooled'] = target_ids+pooled_ids
            assert learned['groups']==expected_groups
            for model in learned['models']:
                verify_fit(model,source,target)
            models_checked += len(learned['models'])
            losses = [calibration_error(model,calibration) for model in learned['models']]
            np.testing.assert_allclose(learned['losses'],losses,atol=1e-12)
            for name,options in learned['groups'].items():
                chosen = min(options,key=lambda index:(losses[index],index))
                assert learned['choices'][name]==chosen
                verify_scores(learned['estimates'][name],learned['models'][chosen],ranking)
                verify_risk(row['exact_risks'][name],learned['models'][chosen],h,scenario,plan['target_ranking_task_units'])
            data = row['all_target_data']
            replay(data,random_generator(seed,*coordinates,'all_budget_target'),h,scenario)
            assert len(data['observations'])==plan['source_discovery_task_units']+plan['target_fitting_task_units']
            identities += data['task_ids']
            for model in row['all_target_models']:
                assert model['mode']=='target' and model['mask']==15 and model['contexts']
                verify_fit(model,source,data)
            models_checked += len(row['all_target_models'])
            losses = [calibration_error(model,calibration) for model in row['all_target_models']]
            np.testing.assert_allclose(row['all_target_losses'],losses,atol=1e-12)
            chosen = min(range(len(losses)),key=lambda index:(losses[index],index))
            assert chosen==row['all_target_choice']
            verify_scores(learned['estimates']['all_budget_target'],row['all_target_models'][chosen],ranking)
            truth = verify_risk(row['exact_risks']['all_budget_target'],row['all_target_models'][chosen],h,scenario,plan['target_ranking_task_units'])
            truths.append(truth)
            confirmation = cell['confirmation'][h]
            rng = replay(confirmation['data'],random_generator(seed,*coordinates,'confirmation'),h,scenario)
            assert len(confirmation['data']['observations'])==plan['confirmation_task_units_per_hypothesis']
            identities += confirmation['data']['task_ids']
            assert len(identities)==len(set(identities))
            base = np.asarray(confirmation['data']['observations'])
            outcomes = np.empty((2,len(base)),dtype=int)
            outcomes[base[:,2],np.arange(len(base))] = base[:,-1]
            for a in (0,1):
                missing = base[:,2]!=a
                observed = base[missing,:-1].copy()
                observed[:,2] = a
                py = probabilities(observed,np.asarray(confirmation['data']['u'])[missing],1,h,scenario)[2]
                outcomes[a,missing] = rng.binomial(1,py)
            np.testing.assert_array_equal(confirmation['y'],outcomes)
            effect = float(np.mean(outcomes[1]-outcomes[0]))
            radius = np.sqrt(2*np.log(8/plan['confirmation_alpha'])/len(base))
            direction = int(effect-radius>plan['practical_effect'])-int(effect+radius<-plan['practical_effect'])
            assert confirmation['effect']==effect and confirmation['confirmed']==bool(direction)
            assert confirmation['confirmed_direction']==direction
            np.testing.assert_allclose(confirmation['interval'],[effect-radius,effect+radius],atol=1e-12)
        for name,selected in cell['nominations'].items():
            values = truths if name=='oracle_top_k' else [h['learned']['estimates'][name]['effect'] for h in cell['hypotheses']]
            assert selected==sorted(range(4),key=lambda h:(-abs(values[h]),h))[:2]
            decision = cell['decisions'][name]
            assert decision['selected']==selected
            assert decision['confirmed_count']==sum(cell['confirmation'][h]['confirmed'] for h in selected)
            assert decision['true_effect_count']==sum(abs(truths[h])>plan['practical_effect'] for h in selected)
            assert decision['true_positive_count']==sum(truths[h]>plan['practical_effect'] for h in selected)
            assert decision['true_negative_count']==sum(truths[h]<-plan['practical_effect'] for h in selected)
            for direction,label in ((1,'positive'),(-1,'negative')):
                assert decision[f'confirmed_{label}_count']==sum(cell['confirmation'][h]['confirmed_direction']==direction for h in selected)
            assert decision['false_confirmed_count']==sum(cell['confirmation'][h]['confirmed'] and
                cell['confirmation'][h]['confirmed_direction']*truths[h]<=plan['practical_effect'] for h in selected)
        cells.append(cell)
    assert len(cells)==len(plan['scenarios'])*len(plan['batch_seeds'])*plan['repetitions_per_batch']
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    for row in summary['rows']:
        group = [cell for cell in cells if cell['scenario']==row['scenario']]
        for name,values in row['methods'].items():
            risks = [h['exact_risks'][name] for cell in group for h in cell['hypotheses']]
            np.testing.assert_allclose(values['mean_exact_effect_variance'],np.mean([risk['exact_effect_variance'] for risk in risks]),atol=1e-12)
            np.testing.assert_allclose(values['mean_target_brier_risk'],np.mean([risk['target_brier_risk'] for risk in risks]),atol=1e-12)
            np.testing.assert_allclose(values['mean_target_prognostic_risk'],np.mean([risk['target_prognostic_risk'] for risk in risks]),atol=1e-12)
            errors = [h['learned']['estimates'][name]['effect']-h['exact_risks'][name]['exact_effect'] for cell in group for h in cell['hypotheses']]
            np.testing.assert_allclose(values['empirical_effect_root_mean_square_error'],np.sqrt(np.mean(np.square(errors))),atol=1e-12)
            for field in ('confirmed_count','confirmed_positive_count','confirmed_negative_count',
                    'true_effect_count','true_positive_count','true_negative_count','false_confirmed_count'):
                assert values[f'mean_{field}']==np.mean([cell['decisions'][name][field] for cell in group])
        for field in ('confirmed_count','true_effect_count'):
            assert row['oracle_top_k'][f'mean_{field}']==np.mean([cell['decisions']['oracle_top_k'][field] for cell in group])
        for comparison in row['comparisons']:
            differences = [np.mean([h['exact_risks'][comparison['baseline']]['exact_effect_variance']-h['exact_risks']['directional']['exact_effect_variance']
                                   for h in cell['hypotheses']]) for cell in group]
            critical = t.ppf(1-.05/(4*len(plan['scenarios'])*len(plan['primary_comparators'])),len(group)-1)
            margin = critical*np.std(differences,ddof=1)/np.sqrt(len(group))
            np.testing.assert_allclose(comparison['approximate_simultaneous_t_interval'],[np.mean(differences)-margin,np.mean(differences)+margin],atol=1e-12)
            np.testing.assert_allclose(comparison['variance_reduction'],np.mean(differences),atol=1e-12)
            np.testing.assert_allclose(comparison['batch_reductions'],[
                np.mean([value for value,cell in zip(differences,group,strict=True) if cell['batch']==batch]) for batch in range(2)],atol=1e-12)
            gains = [cell['decisions']['directional']['confirmed_count']-
                cell['decisions'][comparison['baseline']]['confirmed_count'] for cell in group]
            gain_margin = critical*np.std(gains,ddof=1)/np.sqrt(len(group))
            np.testing.assert_allclose(comparison['confirmed_count_gain'],np.mean(gains),atol=1e-12)
            np.testing.assert_allclose(comparison['confirmed_count_simultaneous_t_interval'],
                [np.mean(gains)-gain_margin,np.mean(gains)+gain_margin],atol=1e-12)
            np.testing.assert_allclose(comparison['confirmed_count_batch_gains'],[
                np.mean([value for value,cell in zip(gains,group,strict=True) if cell['batch']==batch]) for batch in range(2)],atol=1e-12)
    result = dict(status='VERIFIED',evidence_role=plan['evidence_role'],cells=len(cells),models=models_checked,
        ci_queries=queries_checked,source_archive_sha256=identity['source_archive_sha256'],
        verifier_sha256=file_sha256(Path(__file__)),new_model_calls=0)
    if not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result


def verify_sharing_round(output):
    verify_bundle(output/'inputs')
    identity = read_json(output/'inputs'/'identity.json')
    plan = read_json(output/'inputs'/'plan.json')
    parent_plan = read_json(output/'inputs'/'parent-plan.json')
    parent = Path(identity['parent'])
    assert file_sha256(parent/'inputs'/'manifest.json')==identity['parent_manifest_sha256']
    assert file_sha256(parent/'verification'/'result.json')==identity['parent_verification_sha256']
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    cells,mixtures = [],0
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        verify_bundle(parent/'cells'/root.name)
        assert file_sha256(parent/'cells'/root.name/'result.json')==read_json(root/'result.json')['parent_cell_sha256']
        cell = read_json(root/'result.json')
        original = read_json(parent/'cells'/root.name/'result.json')
        cells.append(cell)
        for h,row in enumerate(cell['hypotheses']):
            source = original['hypotheses'][h]
            joint = [[environment,*values] for environment,role in ((0,'source_discovery'),(1,'target_fitting'))
                for values in source['data'][role]['observations']]
            seed = [parent_plan['batch_seeds'][cell['batch']],cell['scenario'],cell['repetition'],h,'sharing']
            verify_queries(row['queries'],joint,['E',*LABELS],plan['ci_draws'],seed)
            accepted = []
            for decision in row['decisions']:
                if row['graph']['status']!='evaluated':
                    assert decision['status']=='unknown'
                    continue
                pag = np.asarray(row['graph']['pag'])
                conditioned = {3,4}|{5+bit for bit in range(4) if decision['mask']>>bit&1}
                ancestors = set(conditioned)
                while True:
                    extended = ancestors|{i for i in range(10) for j in ancestors if pag[i,j] and pag[j,i]!=2 and pag[i,j]!=3}
                    if extended==ancestors:
                        break
                    ancestors = extended
                def reaches(path):
                    if path[-1]==9:
                        return True
                    for next_node in range(10):
                        node = path[-1]
                        if next_node in path or not pag[node,next_node]:
                            continue
                        if len(path)>1:
                            marks = (pag[path[-2],node],pag[next_node,node])
                            if not ((3 not in marks and node in ancestors) or
                                    (marks!=(2,2) and node not in conditioned)):
                                continue
                        if reaches([*path,next_node]):
                            return True
                    return False
                status = 'unknown' if reaches([0]) else 'separated'
                assert decision['status']==status
                if status=='separated':
                    accepted.append(decision['mask'])
            assert row['selected_masks']==accepted
            common = source['learned']['groups']['direct_deviation']
            direct = [mask for mask in range(16) if any(query['x']=='E' and query['y']=='Y' and
                query['conditioned']==sorted(['A','W']+[LABELS[4+bit] for bit in range(4) if mask>>bit&1])
                and query['p'] is not None and query['p']>plan['ci_alpha'] for query in row['queries'])]
            assert row['direct_masks']==direct
            dag = nx.DiGraph([('C1','X'),('W','X'),('C2','N'),('U','N'),('U','Y'),('X','Y'),('W','Y'),('A','Y')])
            dag.add_nodes_from(('E','D1','D2'))
            if cell['scenario']!='stable_proxy':
                dag.add_edge('E','N')
            if cell['scenario']=='source_spillover':
                dag.add_edge('C2','Y')
            if cell['scenario']=='outcome_shift':
                dag.add_edge('E','Y')
            if cell['scenario']=='nuisance_is_causal':
                dag.add_edge('N','Y')
            oracle = [mask for mask in range(16) if nx.is_d_separator(dag,{'E'},{'Y'},
                {'A','W'}|{name for bit,name in enumerate(('X','N','D1','D2')) if mask>>bit&1})]
            assert row['oracle_masks']==oracle
            for name,record in row['results'].items():
                indexes = record['indexes']
                family_name = name.rsplit('_',1)[0]
                if family_name in ('separator','oracle_separator','direct_domain','ancestor','adjacency'):
                    if row['graph']['status']=='evaluated':
                        ancestry = np.asarray(row['graph']['ancestry'])
                        ancestors = sorted(set((sum(2**bit for bit in range(4) if ancestry[5+bit,9]==1),
                            sum(2**bit for bit in range(4) if ancestry[5+bit,9]!=-1))))
                        adjacency = [sum(2**bit for bit in range(4) if row['graph']['pag'][5+bit][9])]
                    else:
                        ancestors,adjacency = [],[]
                    masks = dict(separator=accepted,oracle_separator=oracle,direct_domain=direct,
                        ancestor=ancestors,adjacency=adjacency)[family_name]
                    expected = sorted(set(common)|{i for i,model in enumerate(source['learned']['models']) if
                        model['mode']=='deviation' and not model['contexts'] and model['mask'] in masks})
                else:
                    expected = source['learned']['groups'][dict(ancestor='directional').get(family_name,family_name)]
                assert indexes==expected
                models = [source['learned']['models'][index] for index in indexes]
                weights = np.asarray(record['weights'])
                assert np.min(weights)>=-1e-10 and abs(weights.sum()-1)<1e-10
                anchor = np.asarray([1/len(common) if index in common else 0. for index in indexes])
                np.testing.assert_allclose(record['anchor'],anchor,atol=1e-12)
                calibration = np.asarray(source['data']['target_calibration']['observations'])
                zero,one = calibration.copy(),calibration.copy()
                zero[:,2],one[:,2] = 0,1
                design = np.asarray([(prediction(model,zero)+prediction(model,one))/2 for model in models]).T
                if name.endswith('_single'):
                    assert weights[np.argmin(np.mean((design-calibration[:,-1,None])**2,axis=0))]==1.
                else:
                    gradient = 2*design.T@(design@weights-calibration[:,-1])/len(calibration)+2*plan['aggregation_penalty']*(weights-anchor)
                    active = weights>1e-6
                    level = np.mean(gradient[active])
                    assert np.max(np.abs(gradient[active]-level))<1e-5
                    assert np.all(gradient[~active]>=level-1e-5)
                model = dict(components=models,weights=weights)
                verify_scores(record['estimate'],model,source['data']['target_ranking'])
                verify_risk(record['risk'],model,h,cell['scenario'],parent_plan['target_ranking_task_units'])
                mixtures += 1
        for name,indexes in cell['nominations'].items():
            effects = [row['results'][name]['estimate']['effect'] for row in cell['hypotheses']]
            assert indexes==sorted(range(4),key=lambda h:(-abs(effects[h]),h))[:2]
            assert cell['confirmed'][name]==sum(original['confirmation'][h]['confirmed'] for h in indexes)
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    assert summary['cells']==len(cells)==len(plan['scenarios'])*len(plan['batches'])*len(plan['repetitions'])
    for row in summary['rows']:
        group = [cell for cell in cells if cell['scenario']==row['scenario']]
        for name,record in row['methods'].items():
            np.testing.assert_allclose(record['mean_variance'],np.mean([h['results'][name]['risk']['exact_effect_variance'] for cell in group for h in cell['hypotheses']]),atol=1e-12)
            assert record['mean_confirmed']==np.mean([cell['confirmed'][name] for cell in group])
    family = 2*len(parent_plan['scenarios'])*len(plan['comparison_methods'])
    for record in summary['comparisons']:
        group = [cell for cell in cells if cell['scenario']==record['scenario']]
        gains = [cell['confirmed'][plan['comparison_reference']]-cell['confirmed'][record['baseline']] for cell in group]
        radius = np.sqrt(8*np.log(2*family/.05)/len(group))
        np.testing.assert_allclose(record['confirmed_interval'],[max(-2,np.mean(gains)-radius),min(2,np.mean(gains)+radius)])
        assert record['confirmed_gain']==np.mean(gains)
        differences = [np.mean([h['results'][record['baseline']]['risk']['exact_effect_variance']-
            h['results'][plan['comparison_reference']]['risk']['exact_effect_variance'] for h in cell['hypotheses']]) for cell in group]
        variance_radius = 8/parent_plan['target_ranking_task_units']*np.sqrt(np.log(2*family/.05)/(2*len(group)))
        np.testing.assert_allclose(record['variance_reduction'],np.mean(differences),atol=1e-12)
        np.testing.assert_allclose(record['variance_interval'],[np.mean(differences)-variance_radius,np.mean(differences)+variance_radius],atol=1e-12)
    result = dict(status='VERIFIED',cells=len(cells),mixtures=mixtures,evidence_role=plan['evidence_role'],
        source_archive_sha256=identity['source_archive_sha256'],verifier_sha256=file_sha256(Path(__file__)),new_model_calls=0)
    if not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result


def verify_information(output):
    verify_bundle(output/'inputs')
    identity = read_json(output/'inputs'/'identity.json')
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    parent = Path(identity['parent'])
    plan = read_json(output/'inputs'/'plan.json')
    verify_bundle(parent/'inputs')
    verify_bundle(parent/'summary')
    assert file_sha256(parent/'inputs'/'plan.json')==identity['parent_plan_sha256']
    assert file_sha256(parent/'summary'/'result.json')==identity['parent_summary_sha256']
    checked,cells = 0,[]
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        verify_bundle(parent/'cells'/root.name)
        cell = read_json(root/'result.json')
        original = read_json(parent/'cells'/root.name/'result.json')
        cells.append(cell)
        assert file_sha256(parent/'cells'/root.name/'result.json')==cell['parent_cell_sha256']
        for audit,row in zip(cell['hypotheses'],original['hypotheses'],strict=True):
            h = row['hypothesis']
            assert audit['hypothesis']==h
            for model,risk in zip(row['learned']['models'],audit['risks'],strict=True):
                observed,u,weights,_ = exact_population(h,cell['scenario'])
                zero,one = observed.copy(),observed.copy()
                zero[:,2],one[:,2] = 0,1
                p0,p1 = prediction(model,zero),prediction(model,one)
                means = [probabilities(values,u,1,h,cell['scenario'])[2] for values in (zero,one)]
                truth = float(weights@(means[1]-means[0]))
                signal = means[0]+means[1]
                target_error = float(weights@((p0+p1-signal)**2))
                irreducible = float(weights@(2*signal-signal**2)-truth**2)
                variance = (target_error+irreducible)/plan['target_ranking_task_units']
                np.testing.assert_allclose(risk['complete_state_prognostic_error'],target_error,atol=1e-12)
                np.testing.assert_allclose(risk['exact_effect_variance'],variance,atol=1e-12)
                checked += 1
            variances = [risk['exact_effect_variance'] for risk in audit['risks']]
            best = min(range(len(variances)),key=lambda index:(variances[index],index))
            assert audit['information']['catalog_oracle_model']==best
            for name,indexes in row['learned']['groups'].items():
                choice = row['learned']['choices'][name]
                optimum = min(indexes,key=lambda index:(variances[index],index))
                result = audit['information']['groups'][name]
                assert (result['selected_model'],result['pool_oracle_model'])==(choice,optimum)
                np.testing.assert_allclose([result['selection_loss'],result['restriction_loss']],
                    [variances[choice]-variances[optimum],variances[optimum]-variances[best]],atol=1e-12)
            proposals = row['learned']['proposals']['directional']
            compatible = [mask for mask in range(16) if proposals and
                all(not (min(proposals)>>bit&1) or mask>>bit&1 for bit in range(4)) and
                all(max(proposals)>>bit&1 or not (mask>>bit&1) for bit in range(4))]
            indexes = sorted(set(row['learned']['groups']['direct_deviation']) | {i for i,model in
                enumerate(row['learned']['models']) if model['mode']=='deviation' and not model['contexts'] and model['mask'] in compatible})
            optimum = min(indexes,key=lambda index:(variances[index],index))
            conversion = audit['information']['directional_conversion']
            assert conversion['compatible_masks']==compatible and conversion['pool_oracle_model']==optimum
            np.testing.assert_allclose([conversion['pool_oracle_variance'],conversion['endpoint_conversion_loss'],conversion['remaining_restriction_loss']],
                [variances[optimum],audit['information']['groups']['directional']['pool_oracle_variance']-variances[optimum],variances[optimum]-variances[best]],atol=1e-12)
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    assert len(cells)==summary['cells']
    for row in summary['rows']:
        records = [hypothesis['information'] for cell in cells if cell['scenario']==row['scenario'] for hypothesis in cell['hypotheses']]
        np.testing.assert_allclose(row['catalog_oracle_variance'],np.mean([record['catalog_oracle_variance'] for record in records]),atol=1e-12)
        for name,values in row['methods'].items():
            for field,value in values.items():
                np.testing.assert_allclose(value,np.mean([record['groups'][name][field] for record in records]),atol=1e-12)
        for field,value in row['directional_conversion'].items():
            np.testing.assert_allclose(value,np.mean([record['directional_conversion'][field] for record in records]),atol=1e-12)
    result = dict(status='VERIFIED',evidence_role=identity['evidence_role'],models=checked,cells=summary['cells'],
        parent_source_sha256=identity['parent_source_sha256'],verifier_sha256=file_sha256(Path(__file__)),new_model_calls=0)
    if not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result


def oracle_probabilities(states,h,scenario):
    c1,c2,a,w,u,x,n,_,_ = states.T
    px = .15+.6*c1+.05*w
    pn = .05+.65*u+.2*c2
    if scenario=='irrelevant_context':
        pn = .25+.2*c2
    elif scenario=='multi_target':
        px,pn = .1+.45*c1+.15*c2+.05*w,.05+.55*u+.2*c2+.1*c1
    elif scenario=='weak_context':
        px,pn = .15+.06*c1+.05*w,.05+.65*u+.02*c2
    y = .36+.1*x+.12*u+.02*w+a*(np.asarray([.12,.06,0.,-.10])[h]+.1*(2*x-1)+.1*(2*u-1))
    if scenario=='all_relevant':
        y = y+.025*n+.02*a*(2*n-1)
    if scenario=='cancellation':
        y = y+.04*(2*a-1)*(2*c2-1)
    return px,pn,y


def oracle_sample(seed,coordinates,size,q,h,scenario,role):
    rng = random_generator(seed,*coordinates,h,role)
    states = rng.integers(2,size=(size,9))
    for index in (0,1):
        states[:,index] = rng.binomial(1,q[index],size)
    px,pn,_ = oracle_probabilities(states,h,scenario)
    states[:,5] = rng.binomial(1,px)
    states[:,6] = rng.binomial(1,pn)
    y = rng.binomial(1,oracle_probabilities(states,h,scenario)[2])
    return np.column_stack((states[:,[0,1,2,3,5,6,7,8]],y))


def oracle_matrix(rows,mask):
    columns = [3]+[column for bit,column in enumerate([0,1,4,5,6,7]) if mask&(1<<bit)]
    raw = 2*rows[:,columns]-1
    return np.column_stack([np.ones(len(rows))]+[raw[:,index] for index in range(raw.shape[1])]+
        [raw[:,i]*raw[:,j] for i,j in itertools.combinations(range(raw.shape[1]),2)])


def verify_oracle_catalog(catalog,train,held,target,q,specification,plan):
    from sklearn.linear_model import ElasticNetCV
    from sklearn.ensemble import HistGradientBoostingRegressor
    results = {name:[] for name in ['oracle',*plan['comparators']]}
    allowed = specification['allowed']
    columns = [3]+[column for bit,column in enumerate([0,1,4,5,6,7]) if allowed&(1<<bit)]
    for arm,record in enumerate(catalog):
        assert record['arm']==arm
        rows = train[train[:,2]==arm]
        weights = np.prod(np.where(rows[:,:2],q,1-np.asarray(q))*2,axis=1)
        models = record['models']
        assert [model['mask'] for model in models]==[mask for mask in range(64) if mask&allowed==mask]
        for model in models:
            x = oracle_matrix(rows,model['mask'])
            scores,coefficients = [],[]
            gram,rhs = x.T@(weights[:,None]*x),x.T@(weights*rows[:,-1])
            for alpha in plan['ridge_penalties']:
                inverse = np.linalg.inv(gram+alpha*np.eye(x.shape[1]))
                coef = inverse@rhs
                leverage = weights*np.einsum('ij,ij->i',x@inverse,x)
                scores.append(float(np.mean(weights*((rows[:,-1]-x@coef)/(1-leverage))**2)))
                coefficients.append(coef)
            best = int(np.argmin(scores))
            assert model['alpha']==plan['ridge_penalties'][best]
            np.testing.assert_allclose(model['scores'],scores,atol=2e-9,rtol=2e-8)
            np.testing.assert_allclose(model['loss'],scores[best],atol=2e-9,rtol=2e-8)
            np.testing.assert_allclose(model['coefficients'],coefficients[best],atol=2e-9,rtol=2e-8)
        candidates = [i for i,model in enumerate(models) if model['mask'] in specification['minimal']+[allowed]]
        choices = dict(oracle=min(candidates,key=lambda i:(models[i]['loss'],i)),
            ridge_full=next(i for i,m in enumerate(models) if m['mask']==allowed),
            subset_search=min(range(len(models)),key=lambda i:(models[i]['loss'],i)))
        assert record['choices']==choices
        for name,index in choices.items():
            model = models[index]
            results[name].append([np.clip(oracle_matrix(data,model['mask'])@model['coefficients'],0,1) for data in (held,target)])
        x = oracle_matrix(rows,allowed)
        elastic = ElasticNetCV(alphas=plan['elastic_penalties'],l1_ratio=[.25,.75],cv=3,
            fit_intercept=False,max_iter=50000,tol=1e-6).fit(x,rows[:,-1],sample_weight=weights)
        assert record['elastic']['alpha']==elastic.alpha_ and record['elastic']['l1_ratio']==elastic.l1_ratio_
        np.testing.assert_allclose(record['elastic']['coefficients'],elastic.coef_,atol=1e-10)
        np.testing.assert_allclose(record['elastic']['mse_path'],elastic.mse_path_,atol=1e-10)
        results['elastic_full'].append([np.clip(elastic.predict(oracle_matrix(data,allowed)),0,1) for data in (held,target)])
        tree = HistGradientBoostingRegressor(**plan['boosting']).fit(rows[:,columns],rows[:,-1],sample_weight=weights)
        results['boosted_full'].append([np.clip(tree.predict(data[:,columns]),0,1) for data in (held,target)])
    return results


def verify_oracle_summary(cells,summary,plan):
    from scipy.stats import beta
    from scipy.optimize import linprog
    names = ['oracle','ridge_full','elastic_full','boosted_full','subset_search']
    assert summary['cells']==len(cells)
    assert summary['estimated_jci_searches']==summary['new_provider_calls']==0
    assert summary['evidence_role']==plan['evidence_role']
    assert summary['count_inference']=='STRATIFIED_MULTINOMIAL_CLOPPER_PEARSON_REGION_WITH_BONFERRONI'
    assert summary['mse_inference']=='PAIRED_STRATIFIED_DEVELOPMENT_BOOTSTRAP'
    ordered = sorted(cells,key=lambda c:(plan['scenarios'].index(c['scenario']),c['source_size'],c['target_size'],c['batch'],c['repetition']))
    groups = []
    conditions = sorted({(c['scenario'],c['source_size'],c['target_size']) for c in cells})
    assert len(summary['rows'])==len(conditions)
    for condition,row in zip(conditions,summary['rows'],strict=True):
        group = [c for c in ordered if (c['scenario'],c['source_size'],c['target_size'])==condition]
        assert [row['scenario'],row['source_size'],row['target_size']]==list(condition)
        assert row['repetitions']==len(group) and row['core']==group[0]['core']
        if row['core']:
            groups.append(group)
        for name in names:
            errors = np.asarray([h['estimates'][name]['effect']-h['truth'] for c in group for h in c['hypotheses']])
            np.testing.assert_allclose([row['methods'][name][key] for key in ('mean_confirmed','mse','bias')],
                [np.mean([c['confirmed'][name] for c in group]),np.mean(errors**2),errors.mean()],atol=1e-12)
    assert summary['core_cells']==sum(map(len,groups))
    errors = np.asarray([[[np.mean([(h['estimates'][name]['effect']-h['truth'])**2 for h in c['hypotheses']])
        for name in names] for c in group] for group in groups])
    rng = np.random.default_rng(plan['batch_seeds'][0])
    indexes = rng.integers(errors.shape[1],size=(plan['bootstrap_draws'],len(groups),errors.shape[1]))
    boot = np.asarray([np.mean([errors[j,indexes[b,j]] for j in range(len(groups))],axis=(0,1)) for b in range(len(indexes))])
    decisions = []
    k = len(plan['comparators'])
    assert len(summary['comparisons'])==k
    for name,comparison in zip(plan['comparators'],summary['comparisons'],strict=True):
        assert comparison['baseline']==name
        intervals,differences = [],[]
        for group in groups:
            delta = np.asarray([c['confirmed']['oracle']-c['confirmed'][name] for c in group])
            differences.append(delta.mean())
            n = len(delta)
            alpha = plan['comparison_alpha']/(k*len(groups)*10)
            bounds = []
            for value in range(-2,3):
                successes = np.count_nonzero(delta==value)
                bounds.append((0 if successes==0 else beta.ppf(alpha,successes,n-successes+1),
                    1 if successes==n else beta.ppf(1-alpha,successes+1,n-successes)))
            objectives = [linprog(sign*np.arange(-2,3),A_eq=[[1]*5],b_eq=[1],bounds=bounds,method='highs') for sign in (1,-1)]
            assert all(result.success for result in objectives)
            intervals.append([objectives[0].fun,-objectives[1].fun])
        gain = np.mean(differences)
        interval = np.mean(intervals,axis=0)
        batch = [np.mean([c['confirmed']['oracle']-c['confirmed'][name] for group in groups for c in group if c['batch']==index]) for index in (0,1)]
        index = names.index(name)
        reduction = 1-errors[:,:,0].mean()/errors[:,:,index].mean()
        quantiles = np.quantile(1-boot[:,0]/boot[:,index],[plan['comparison_alpha']/(2*k),1-plan['comparison_alpha']/(2*k)])
        np.testing.assert_allclose(comparison['confirmed_gain'],gain,atol=1e-12)
        np.testing.assert_allclose(comparison['simultaneous_count_interval'],interval,atol=1e-12)
        np.testing.assert_allclose(comparison['batch_gains'],batch,atol=1e-12)
        np.testing.assert_allclose(comparison['relative_mse_reduction'],reduction,atol=1e-12)
        np.testing.assert_allclose(comparison['mse_bootstrap_interval'],quantiles,atol=1e-12)
        decisions.append(interval[0]>0 and gain>=plan['minimum_confirmation_gain'] and min(batch)>0 and
            reduction>=plan['minimum_relative_mse_reduction'] and quantiles[0]>0)
    assert summary['decision']==('ORACLE_VALUE_SUPPORTED' if all(decisions) else 'ORACLE_VALUE_NOT_ESTABLISHED_DO_NOT_EXPAND')


def verify_oracle_feasibility(output):
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs'/'plan.json')
    identity = read_json(output/'inputs'/'identity.json')
    assert plan['formal_claim_allowed'] is False and plan['estimated_jci_searches']==plan['new_provider_calls']==0
    assert plan['evidence_role']=='NON_CLAIM_PROSPECTIVE_ORACLE_FEASIBILITY'
    assert plan['hypotheses']==4 and plan['nomination_count']==2 and len(set(plan['batch_seeds']))==2
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
        assert archive.read('src/verification/directional_transfer.py')==Path(__file__).read_bytes()
    parent = Path(identity['parent'])
    for part in ('inputs','summary','verification'):
        verify_bundle(parent/part)
    assert file_sha256(parent/'verification'/'result.json')==identity['parent_verification_sha256']
    specifications = read_json(output/'inputs'/'structures.json')
    expected_minimal = dict(irrelevant_context=[4],confounded_proxy=[14],multi_target=[15],all_relevant=[14],
        weak_context=[14],cancellation=[14],no_shift=[14],unobserved_attribute=[11])
    for scenario,spec in specifications.items():
        assert spec['minimal']==expected_minimal[scenario]
        assert spec['allowed']==(59 if scenario=='unobserved_attribute' else 63)
        graph = nx.DiGraph(spec['edges'])
        graph.add_nodes_from(['D1','D2'])
        valid = []
        for mask in range(64):
            if mask&spec['allowed']!=mask:
                continue
            kept = {'A','W'}|{name for bit,name in enumerate(['C1','C2','X','N','D1','D2']) if mask&(1<<bit)}
            omitted = {name for bit,name in enumerate(['C1','C2','X','N','D1','D2']) if spec['allowed']&(1<<bit) and not mask&(1<<bit)}
            if nx.is_d_separator(graph,{'Y'},omitted,kept):
                valid.append(mask)
        assert valid==spec['valid']
    names = ['oracle',*plan['comparators']]
    cells,coordinates_seen = [],set()
    expected = set()
    for scenario in plan['scenarios']:
        core = scenario in plan['core_scenarios']
        sizes = itertools.product(plan['source_sizes'],plan['target_sizes']) if core else [(plan['boundary_source_size'],plan['boundary_target_size'])]
        for ns,nt in sizes:
            expected.update((scenario,ns,nt,batch,rep) for batch in (0,1) for rep in range(plan['core_repetitions_per_batch'] if core else plan['boundary_repetitions_per_batch']))
    for root in sorted((output/'cells').iterdir()):
        verify_bundle(root)
        cell = read_json(root/'result.json')
        scenario,ns,nt,batch,rep = [cell[key] for key in ('scenario','source_size','target_size','batch','repetition')]
        coordinate = (scenario,ns,nt,batch,rep)
        assert coordinate in expected and coordinate not in coordinates_seen
        coordinates_seen.add(coordinate)
        seed = plan['batch_seeds'][batch]
        coordinates = [scenario,ns,nt,rep]
        q = [.5,.5] if scenario=='no_shift' else plan['target_context_probabilities']
        assert cell['q']==q and cell['core']==(scenario in plan['core_scenarios'])
        assert len(cell['hypotheses'])==4
        for h,record in enumerate(cell['hypotheses']):
            assert record['hypothesis']==h and record['task_id_prefix']==f'{seed}/{scenario}/{ns}/{nt}/{rep}/{h}'
            source = oracle_sample(seed,coordinates,ns,[.5,.5],h,scenario,'source')
            target = oracle_sample(seed,coordinates,nt,q,h,scenario,'target')
            np.testing.assert_array_equal(record['source'],source)
            np.testing.assert_array_equal(record['target'],target)
            predictions = {name:[np.zeros((2,ns)),np.zeros((2,nt))] for name in names}
            assert len(record['folds'])==2
            for fold,catalog in enumerate(record['folds']):
                held = np.arange(ns)%2==fold
                output_predictions = verify_oracle_catalog(catalog,source[~held],source[held],target,q,specifications[scenario],plan)
                for name,arms in output_predictions.items():
                    predictions[name][0][:,held] = np.asarray([arm[0] for arm in arms])
                    predictions[name][1] += np.asarray([arm[1] for arm in arms])/2
            weights = np.prod(np.where(source[:,:2],q,1-np.asarray(q))*2,axis=1)
            effective = ns/np.prod([2*(value**2+(1-value)**2) for value in q])
            mixing = effective/(effective+nt)
            np.testing.assert_allclose(record['mixing'],mixing,atol=1e-14)
            for name,(sp,tp) in predictions.items():
                measured = record['estimates'][name]
                np.testing.assert_allclose(measured['source_predictions'],sp,atol=1e-10)
                np.testing.assert_allclose(measured['target_predictions'],tp,atol=1e-10)
                sr = 2*(2*source[:,2]-1)*(source[:,-1]-sp[source[:,2],np.arange(ns)])
                tr = 2*(2*target[:,2]-1)*(target[:,-1]-tp[target[:,2],np.arange(nt)])
                estimate = (tp[1]-tp[0]).mean()+mixing*np.mean(weights*sr)+(1-mixing)*tr.mean()
                np.testing.assert_allclose(measured['effect'],estimate,atol=1e-10)
            states = np.asarray(list(itertools.product((0,1),repeat=9)))
            px,pn,_ = oracle_probabilities(states,h,scenario)
            mass = np.where(states[:,0],q[0],1-q[0])*np.where(states[:,1],q[1],1-q[1])/32
            mass *= np.where(states[:,5],px,1-px)*np.where(states[:,6],pn,1-pn)
            means = []
            for arm in (0,1):
                assigned = states.copy()
                assigned[:,2] = arm
                means.append(oracle_probabilities(assigned,h,scenario)[2])
            p0,p1 = means
            probabilities = [mass@(p0*(1-p1)),mass@(p0*p1+(1-p0)*(1-p1)),mass@(p1*(1-p0))]
            np.testing.assert_allclose(record['truth'],mass@(p1-p0),atol=1e-14)
            confirmation = record['confirmation']
            np.testing.assert_allclose(confirmation['probabilities'],probabilities,atol=1e-14)
            counts = random_generator(seed,*coordinates,h,'confirmation').multinomial(plan['confirmation_task_units'],probabilities)
            np.testing.assert_array_equal(confirmation['counts'],counts)
            effect = (counts[2]-counts[0])/plan['confirmation_task_units']
            radius = np.sqrt(2*np.log(2*4/plan['confirmation_alpha'])/plan['confirmation_task_units'])
            np.testing.assert_allclose([confirmation['effect'],confirmation['radius']],[effect,radius],atol=1e-14)
            direction = int(effect-radius>plan['practical_effect'])-int(effect+radius<-plan['practical_effect'])
            assert confirmation['direction']==direction and confirmation['task_units']==plan['confirmation_task_units']
        for name in names:
            nominated = sorted(range(4),key=lambda h:(-abs(cell['hypotheses'][h]['estimates'][name]['effect']),h))[:2]
            assert cell['nominations'][name]==nominated
            assert cell['confirmed'][name]==sum(cell['hypotheses'][h]['confirmation']['direction']!=0 for h in nominated)
        cells.append(cell)
    assert coordinates_seen==expected
    verify_bundle(output/'summary')
    verify_oracle_summary(cells,read_json(output/'summary'/'result.json'),plan)
    result = dict(status='VERIFIED',cells=len(cells),effect_estimates=len(cells)*4*len(names),
        evidence_role=plan['evidence_role'],source_archive_sha256=identity['source_archive_sha256'],
        verifier_sha256=file_sha256(Path(__file__)),estimated_jci_searches=0,new_provider_calls=0)
    if not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result


def context_probabilities(rows,u,environment,h,scenario):
    states = np.insert(np.asarray(rows)[:,:8],4,u,axis=1)
    base = scenario if scenario in ('irrelevant_context','confounded_proxy','multi_target','all_relevant',
        'weak_context','cancellation','no_shift','unobserved_attribute') else 'confounded_proxy'
    px,pn,py = oracle_probabilities(states,h,base)
    if scenario=='proxy_mechanism_change' and environment==1:
        pn = .05+.20*u+.65*rows[:,1]
    if scenario=='source_spillover':
        py = py+.03*rows[:,1]
    if scenario=='outcome_shift' and environment==1:
        py = py+.04*(2*rows[:,2]-1)
    return px,pn,py


def context_population(h,scenario,environment=1):
    states = np.asarray(list(itertools.product((0,1),repeat=9)))
    rows,u = states[:,[0,1,2,3,5,6,7,8]],states[:,4]
    px,pn,py = context_probabilities(rows,u,environment,h,scenario)
    q = [.75,.25] if environment==1 and scenario!='no_shift' else [.5,.5]
    mass = np.where(rows[:,0],q[0],1-q[0])*np.where(rows[:,1],q[1],1-q[1])/32
    mass *= np.where(rows[:,4],px,1-px)*np.where(rows[:,5],pn,1-pn)
    return rows,u,mass,py


def context_replay(data,rng,h,scenario):
    n = len(data['observations'])
    states = rng.integers(0,2,size=(n,9))
    q = [.75,.25] if data['environment']==1 and scenario!='no_shift' else [.5,.5]
    states[:,0] = rng.binomial(1,q[0],n)
    states[:,1] = rng.binomial(1,q[1],n)
    rows,u = states[:,[0,1,2,3,5,6,7,8]],states[:,4]
    px,pn,_ = context_probabilities(rows,u,data['environment'],h,scenario)
    rows[:,4],rows[:,5] = rng.binomial(1,px),rng.binomial(1,pn)
    py = context_probabilities(rows,u,data['environment'],h,scenario)[2]
    rows = np.column_stack((rows,rng.binomial(1,py)))
    np.testing.assert_array_equal(data['observations'],rows)
    np.testing.assert_array_equal(data['u'],u)
    assert data['task_ids']==[f'{data["identity"]}/{i}' for i in range(n)]
    return rng


def context_query_masks(graphs,allowed,skeleton=False):
    names = ['X','N','D1','D2','C1','C2']
    decisions = []
    for mask in range(64):
        if mask&allowed!=mask:
            continue
        selected = [name for bit,name in enumerate(names) if mask&(1<<bit)]
        queries = []
        for arm,graph in enumerate(graphs):
            labels = graph['labels']
            for context in [name for name in ('C1','C2') if name not in selected]:
                separated = False
                if graph['status']=='evaluated':
                    pag = np.asarray(graph['pag'])
                    if skeleton:
                        pag = np.where(pag,1,0)
                    conditioned = {labels.index(name) for name in ['W',*selected]}
                    ancestors = set(conditioned)
                    pending = list(conditioned)
                    while pending:
                        destination = pending.pop()
                        for origin in range(len(labels)):
                            if origin not in ancestors and pag[origin,destination] and pag[destination,origin]!=2 and pag[origin,destination]!=3:
                                ancestors.add(origin)
                                pending.append(origin)
                    pending_paths = [[labels.index(context)]]
                    connected = False
                    while pending_paths:
                        path = pending_paths.pop()
                        if path[-1]==labels.index('Y'):
                            connected = True
                            break
                        for following in range(len(labels)):
                            node = path[-1]
                            if following in path or not pag[node,following]:
                                continue
                            if len(path)>1:
                                marks = (pag[path[-2],node],pag[following,node])
                                can_collider = 3 not in marks and node in ancestors
                                can_noncollider = marks!=(2,2) and node not in conditioned
                                if not(can_collider or can_noncollider):
                                    continue
                            pending_paths.append(path+[following])
                    separated = not connected
                queries.append(dict(arm=arm,context=context,conditioned=['W',*selected],data_role='source_discovery',
                    query_type='source_context_separation',status='separated' if separated else 'unknown'))
        status = 'unrestricted' if not queries else ('supported' if all(q['status']=='separated' for q in queries) else 'unknown')
        decisions.append(dict(mask=mask,status=status,queries=queries))
    return [row['mask'] for row in decisions if row['status']=='supported'],decisions


def context_true_graph(scenario):
    graph = nx.DiGraph([('C1','X'),('W','X'),('C2','N'),('U','Y'),('X','Y'),('W','Y')])
    graph.add_nodes_from(['D1','D2'])
    if scenario!='irrelevant_context':
        graph.add_edge('U','N')
    if scenario=='multi_target':
        graph.add_edges_from([('C2','X'),('C1','N')])
    if scenario=='all_relevant':
        graph.add_edge('N','Y')
    if scenario in ('cancellation','source_spillover'):
        graph.add_edge('C2','Y')
    return graph


def context_true_masks(scenario):
    graph = context_true_graph(scenario)
    allowed = 62 if scenario=='unobserved_attribute' else 63
    masks = []
    for mask in range(64):
        kept = {name for bit,name in enumerate(['X','N','D1','D2','C1','C2']) if mask&(1<<bit)}
        remaining = {'C1','C2'}-kept
        if mask&allowed==mask and remaining and nx.is_d_separator(graph,{'Y'},remaining,kept|{'W'}):
            masks.append(mask)
    return masks


def verify_context_risk(record,model,h,scenario,ranking_size):
    rows,u,mass,py = context_population(h,scenario)
    zero,one = rows.copy(),rows.copy()
    zero[:,2],one[:,2] = 0,1
    p0,p1 = prediction(model,zero),prediction(model,one)
    prognosis = (p0+p1)/2
    assigned = np.where(rows[:,2],p1,p0)
    truth = float(mass@(2*(2*rows[:,2]-1)*py))
    risk = float(mass@(py*(1-prognosis)**2+(1-py)*prognosis**2))
    expected = dict(exact_effect=truth,exact_effect_variance=(4*risk-truth**2)/ranking_size,
        target_prognostic_risk=risk,target_prediction_excess_risk=float(mass@((assigned-py)**2)),
        target_brier_risk=float(mass@(py*(1-assigned)**2+(1-py)*assigned**2)))
    for key,value in expected.items():
        np.testing.assert_allclose(record[key],value,atol=1e-11)
    return truth


def verify_query_information(row,h,scenario,size):
    source = context_true_graph(scenario)
    domain = source.copy()
    domain.add_node('E')
    if scenario!='no_shift':
        domain.add_edges_from([('E','C1'),('E','C2')])
    if scenario=='proxy_mechanism_change':
        domain.add_edge('E','N')
    if scenario=='outcome_shift':
        domain.add_edge('E','Y')
    allowed = 62 if scenario=='unobserved_attribute' else 63
    names = ['X','N','D1','D2','C1','C2']
    observed = {name for i,name in enumerate(names) if allowed&(1<<i)}
    diagnostics = []
    for mask in range(64):
        if mask&allowed!=mask:
            continue
        kept = {name for i,name in enumerate(names) if mask&(1<<i)}
        remaining = {'C1','C2'}-kept
        diagnostics.append(dict(mask=mask,source_context_supported=bool(remaining) and nx.is_d_separator(source,{'Y'},remaining,kept|{'W'}),
            prediction_sufficient=nx.is_d_separator(source,{'Y'},observed-kept,kept|{'W'}),
            target_environment_separated=nx.is_d_separator(domain,{'E'},{'Y'},kept|{'W'})))
    return diagnostics


def verify_catalog_information(row,h,scenario,size):
    rows,u,mass,py = context_population(h,scenario)
    states = [rows.copy(),rows.copy()]
    states[0][:,2],states[1][:,2] = 0,1
    means = [context_probabilities(state,u,1,h,scenario)[2] for state in states]
    truth = float(mass@(means[1]-means[0]))
    bases = {}
    assert len(row['catalog_risks'])==len(row['learned']['models'])
    for model,risk in zip(row['learned']['models'],row['catalog_risks'],strict=True):
        key = model['mask'],model['contexts'],model['mode']=='deviation',model['allowed']
        if key not in bases:
            pair = [matrix(state,model) for state in states]
            if key[2]:
                pair = [np.column_stack((base,matrix(state,dict(mask=model['allowed'],contexts=True)))) for base,state in zip(pair,states,strict=True)]
            bases[key] = pair
        signal = sum(np.clip(base@np.asarray(model['coefficients']),0,1) for base in bases[key])
        second = mass@(4*py-4*signal*py+signal**2)
        np.testing.assert_allclose([risk['exact_effect'],risk['exact_effect_variance'],risk['complete_state_prognostic_error']],
            [truth,(second-truth**2)/size,mass@((signal-means[0]-means[1])**2)],atol=1e-11)
    columns = [0,1,3,5,6,7]+([4] if scenario!='unobserved_attribute' else [])
    groups = np.unique(rows[:,columns],axis=0,return_inverse=True)[1]
    total,signal = np.zeros(groups.max()+1),np.zeros(groups.max()+1)
    np.add.at(total,groups,mass)
    np.add.at(signal,groups,mass*(means[0]+means[1]))
    signal = signal[groups]/total[groups]
    optimum = float((mass@(4*py-4*signal*py+signal**2)-truth**2)/size)
    information = row['information']
    np.testing.assert_allclose(information['observable_optimal_effect_variance'],optimum,atol=1e-12)
    values = np.asarray([risk['exact_effect_variance'] for risk in row['catalog_risks']])
    assert information['catalog_oracle_model']==int(np.argmin(values))
    np.testing.assert_allclose(information['catalog_oracle_variance'],values.min(),atol=1e-12)
    assert optimum<=values.min()+1e-12
    for name,options in row['learned']['groups'].items():
        record = information['groups'][name]
        best = min(options,key=lambda i:(values[i],i))
        selected = row['learned']['choices'][name]
        assert record['selected_model']==selected and record['pool_oracle_model']==best
        np.testing.assert_allclose([record['selection_loss'],record['restriction_loss']],
            [values[selected]-values[best],values[best]-values.min()],atol=1e-12)


def _directional_verification_partition(arguments):
    return verify_directional(arguments[0],_cell_paths=arguments[1])


def verify_directional(output,workers=1,_cell_paths=None):
    if type(workers) is not int or workers<1:
        raise ValueError('独立验证进程数量必须为正整数')
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs'/'plan.json')
    assert plan['evidence_role']=='NON_CLAIM_SOURCE_CONTEXT_QUERY_SIMULATION' and plan['formal_claim_allowed'] is False
    assert plan['effect_estimator']=='target_randomization_only'
    assert plan['structure_query']=='arm_stratified_source_context_separation'
    assert plan['primary_comparators']==['direct_search']
    assert len(plan['batch_seeds'])==len(set(plan['batch_seeds']))==2
    assert plan['component_alpha']==plan['graph_component_alpha']==.01 and plan['confirmation_alpha']==.03
    identity = read_json(output/'inputs'/'identity.json')
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    verify_bundle(output/'oracle')
    oracles = read_json(output/'oracle'/'result.json')
    models_checked,queries_checked = 0,0
    for scenario in plan['scenarios']:
        for h,oracle in enumerate(oracles[scenario]):
            assert oracle['true_query_diagnostics']==verify_query_information(oracle,h,scenario,plan['target_ranking_task_units'])
            rows,u,mass,py = context_population(h,scenario,0)
            labels = oracle['graph'][0]['labels']
            for arm,record in enumerate(oracle['queries']):
                assert record['arm']==arm and oracle['graph'][arm]['arm']==arm
                selected = rows[:,2]==arm
                observed = rows[selected][:,[LABELS.index(name) for name in labels[:-1]]]
                values = np.column_stack((np.repeat(observed,2,axis=0),np.tile([0,1],len(observed))))
                weights = np.column_stack((2*mass[selected]*(1-py[selected]),2*mass[selected]*py[selected])).ravel()
                for query in record['queries']:
                    columns = [labels.index(name) for name in query['conditioned']]
                    groups = np.unique(values[:,columns],axis=0,return_inverse=True)[1] if columns else np.zeros(len(values),dtype=int)
                    tables = np.zeros((groups.max()+1,2,2))
                    np.add.at(tables,(groups,values[:,labels.index(query['x'])],values[:,labels.index(query['y'])]),weights)
                    product = tables.sum(2)[:,:,None]*tables.sum(1)[:,None,:]/tables.sum((1,2))[:,None,None]
                    assert query['p']==float(np.max(np.abs(tables-product))<1e-12)
            rows,u,mass,_ = context_population(h,scenario)
            means = []
            for arm in (0,1):
                assigned = rows.copy()
                assigned[:,2] = arm
                means.append(context_probabilities(assigned,u,1,h,scenario)[2])
            minus,plus = mass@(means[0]*(1-means[1])),mass@(means[1]*(1-means[0]))
            np.testing.assert_allclose(oracle['target_effect'],plus-minus,atol=1e-12)
            np.testing.assert_allclose([oracle['difference_distribution']['minus'],oracle['difference_distribution']['plus']],[minus,plus],atol=1e-12)
            n = plan['confirmation_task_units_per_hypothesis']
            counts = np.arange(n+1)
            cutoff = np.floor(counts+n*(plan['practical_effect']+np.sqrt(2*np.log(8/plan['confirmation_alpha'])/n)))
            for name,opposite,favorable in [('positive',minus,plus),('negative',plus,minus)]:
                power = binom.pmf(counts,n,opposite)@binom.sf(cutoff,n-counts,favorable/(1-opposite))
                np.testing.assert_allclose(oracle['confirmation_power'][name],power,atol=1e-10)
    cells,all_ids = [],set()
    roots = sorted((output/'cells').iterdir()) if _cell_paths is None else _cell_paths
    if workers>1 and _cell_paths is None:
        partitions = [(output,roots[index::workers]) for index in range(min(workers,len(roots)))]
        with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
            for part,model_count,query_count in pool.map(_directional_verification_partition,partitions):
                cells.extend(part)
                models_checked += model_count
                queries_checked += query_count
        roots = []
    for root in roots:
        verify_bundle(root)
        cell = read_json(root/'result.json')
        scenario,batch,repetition = cell['scenario'],cell['batch'],cell['repetition']
        seed = plan['batch_seeds'][batch]
        truths = []
        allowed = 62 if scenario=='unobserved_attribute' else 63
        for h,row in enumerate(cell['hypotheses']):
            assert row['hypothesis']==h
            coordinates = scenario,repetition,h
            for role,data in row['data'].items():
                context_replay(data,random_generator(seed,*coordinates,role),h,scenario)
                assert data['identity']==f'{seed}/{scenario}/{repetition}/{h}/{role}'
                assert len(data['observations'])==plan[f'{role}_task_units']
                assert not all_ids.intersection(data['task_ids'])
                all_ids.update(data['task_ids'])
            source,target,calibration,ranking = [row['data'][role] for role in ('source_discovery','target_fitting','target_calibration','target_ranking')]
            labels = ['C1','C2','W',*(['X'] if allowed&1 else []),'N','D1','D2','Y']
            observed = np.asarray(source['observations'])
            assert len(row['graph'])==len(row['ci_queries'])==2
            for arm,graph in enumerate(row['graph']):
                assert graph['arm']==arm and graph['labels']==labels and graph['conservative']
                assert graph.get('context_variables',['C1','C2'])==['C1','C2']
                selected = observed[:,2]==arm
                assert graph['task_units']==selected.sum() and row['ci_queries'][arm]['arm']==arm
                data = observed[selected][:,[LABELS.index(name) for name in labels]]
                verify_queries(row['ci_queries'][arm]['queries'],data,labels,plan['ci_draws'],[seed,*coordinates,'graph',arm])
                queries_checked += len(row['ci_queries'][arm]['queries'])
                if graph['status']=='evaluated':
                    pag = np.asarray(graph['pag'])
                    assert all(query['p'] is not None for query in row['ci_queries'][arm]['queries'])
                    assert pag.shape==(len(labels),len(labels))
                    np.testing.assert_array_equal(pag!=0,pag.T!=0)
                else:
                    assert graph['status']=='insufficient_support' and graph['pag'] is None
                    assert not selected.any() or any(query['p'] is None for query in row['ci_queries'][arm]['queries'])
            learned = row['learned']
            direct,decisions = context_query_masks(row['graph'],allowed)
            skeleton,skeleton_decisions = context_query_masks(row['graph'],allowed,True)
            population,population_decisions = context_query_masks(oracles[scenario][h]['graph'],allowed)
            expected = dict(directional=direct,adjacency=skeleton,direct_search=[mask for mask in range(64) if mask&allowed==mask],
                oracle_graph=context_true_masks(scenario),population_graph=population)
            assert learned['proposals']==expected
            assert learned['context_queries']==decisions and learned['skeleton_queries']==skeleton_decisions
            assert learned['population_context_queries']==population_decisions
            assert learned['query_scope']=='SOURCE_CONTEXT_SUGGESTION_NOT_TARGET_CERTIFICATE'
            def model_id(mask,penalty,mode='shared',deviation=None,contexts=False):
                if mask&48==48:
                    mask,contexts = mask&15,True
                matching = [i for i,m in enumerate(learned['models']) if (m['mask'],m['penalty'],m['mode'],m['deviation'],m['contexts'])==
                    (mask,penalty,mode,deviation,contexts)]
                assert len(matching)==1
                return matching[0]
            targets = [model_id(allowed&15,p,'target',contexts=True) for p in plan['ridge_penalties']]
            pooled = [model_id(allowed&15,p,contexts=True) for p in plan['ridge_penalties']]
            deviations = [model_id(allowed&15,p,'deviation',d,True) for p,d in itertools.product(plan['ridge_penalties'],plan['deviation_penalties'])]
            common = targets+pooled+deviations
            groups = {name:common+[model_id(mask,p,'deviation',d) for mask,p,d in itertools.product(masks,plan['ridge_penalties'],plan['deviation_penalties'])]
                for name,masks in expected.items()}
            groups.update(target_only=targets,direct_deviation=common,direct_pooled=targets+pooled)
            assert learned['groups']==groups
            for model in learned['models']:
                assert model['allowed']==allowed&15
                verify_fit(model,source,target)
            models_checked += len(learned['models'])
            verify_catalog_information(row,h,scenario,plan['target_ranking_task_units'])
            losses = [calibration_error(model,calibration) for model in learned['models']]
            np.testing.assert_allclose(learned['losses'],losses,atol=1e-11)
            for name,options in groups.items():
                chosen = min(options,key=lambda index:(losses[index],index))
                assert learned['choices'][name]==chosen
                verify_scores(learned['estimates'][name],learned['models'][chosen],ranking)
                truth = verify_context_risk(row['exact_risks'][name],learned['models'][chosen],h,scenario,plan['target_ranking_task_units'])
            truths.append(truth)
            confirmation = cell['confirmation'][h]
            assert confirmation['data']['identity']==f'{seed}/{scenario}/{repetition}/{h}/confirmation'
            rng = context_replay(confirmation['data'],random_generator(seed,*coordinates,'confirmation'),h,scenario)
            assert not all_ids.intersection(confirmation['data']['task_ids'])
            all_ids.update(confirmation['data']['task_ids'])
            confirmed = np.asarray(confirmation['data']['observations'])
            outcomes = np.asarray(confirmation['y'])
            assert len(confirmed)==plan['confirmation_task_units_per_hypothesis']
            np.testing.assert_array_equal(outcomes[confirmed[:,2],np.arange(len(confirmed))],confirmed[:,-1])
            for arm in (0,1):
                missing = confirmed[:,2]!=arm
                assigned = confirmed[missing,:-1].copy()
                assigned[:,2] = arm
                py = context_probabilities(assigned,np.asarray(confirmation['data']['u'])[missing],1,h,scenario)[2]
                np.testing.assert_array_equal(outcomes[arm,missing],rng.binomial(1,py))
            effect = (outcomes[1]-outcomes[0]).mean()
            radius = np.sqrt(2*np.log(8/plan['confirmation_alpha'])/len(confirmed))
            direction = int(effect-radius>plan['practical_effect'])-int(effect+radius<-plan['practical_effect'])
            np.testing.assert_allclose(confirmation['effect'],effect,atol=1e-12)
            np.testing.assert_allclose(confirmation['interval'],[effect-radius,effect+radius],atol=1e-12)
            assert confirmation['confirmed_direction']==direction and confirmation['confirmed']==bool(direction)
        for name,selected in cell['nominations'].items():
            values = truths if name=='oracle_top_k' else [h['learned']['estimates'][name]['effect'] for h in cell['hypotheses']]
            assert selected==sorted(range(4),key=lambda i:(-abs(values[i]),i))[:2]
            decisions = cell['decisions'][name]
            assert decisions['selected']==selected
            for field,expected in dict(true_effect_count=sum(abs(truths[h])>plan['practical_effect'] for h in selected),
                true_positive_count=sum(truths[h]>plan['practical_effect'] for h in selected),true_negative_count=sum(truths[h]<-plan['practical_effect'] for h in selected),
                confirmed_count=sum(cell['confirmation'][h]['confirmed'] for h in selected),
                confirmed_positive_count=sum(cell['confirmation'][h]['confirmed_direction']==1 for h in selected),
                confirmed_negative_count=sum(cell['confirmation'][h]['confirmed_direction']==-1 for h in selected),
                false_confirmed_count=sum(cell['confirmation'][h]['confirmed'] and cell['confirmation'][h]['confirmed_direction']*truths[h]<=plan['practical_effect'] for h in selected)).items():
                assert decisions[field]==expected
        cells.append(dict(scenario=scenario,batch=batch,repetition=repetition,decisions=cell['decisions'],
            hypotheses=[dict(exact_risks=h['exact_risks'],graph=h['graph'],learned=dict(choices=h['learned']['choices'],
                estimates={name:dict(effect=value['effect']) for name,value in h['learned']['estimates'].items()})) for h in cell['hypotheses']]))
    if _cell_paths is not None:
        return cells,models_checked,queries_checked
    cells.sort(key=lambda cell:(cell['scenario'],cell['batch'],cell['repetition']))
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    assert summary['cells']==len(cells)==len(plan['scenarios'])*2*plan['repetitions_per_batch']
    assert {(c['scenario'],c['batch'],c['repetition']) for c in cells}==set(itertools.product(plan['scenarios'],range(2),range(plan['repetitions_per_batch'])))
    assert summary['graph_component_status']=='BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS'
    assert summary['graph_representation_advantage_tested'] is False and summary['effect_estimator']=='target_randomization_only'
    for row in summary['rows']:
        group = [c for c in cells if c['scenario']==row['scenario']]
        for name,record in row['methods'].items():
            risks = [h['exact_risks'][name] for c in group for h in c['hypotheses']]
            errors = [h['learned']['estimates'][name]['effect']-h['exact_risks'][name]['exact_effect'] for c in group for h in c['hypotheses']]
            for field,key in [('mean_exact_effect_variance','exact_effect_variance'),('mean_target_brier_risk','target_brier_risk'),('mean_target_prognostic_risk','target_prognostic_risk')]:
                np.testing.assert_allclose(record[field],np.mean([r[key] for r in risks]),atol=1e-12)
            np.testing.assert_allclose(record['empirical_effect_root_mean_square_error'],np.sqrt(np.mean(np.square(errors))),atol=1e-12)
            for field in ('confirmed_count','confirmed_positive_count','confirmed_negative_count','true_effect_count','true_positive_count','true_negative_count','false_confirmed_count'):
                np.testing.assert_allclose(record[f'mean_{field}'],np.mean([c['decisions'][name][field] for c in group]))
        assert row['total_graphs']==8*len(group)
        assert row['evaluated_graphs']==sum(g['status']=='evaluated' for c in group for h in c['hypotheses'] for g in h['graph'])
        for comparison in row['comparisons']:
            name = comparison['baseline']
            delta = np.asarray([np.mean([h['exact_risks'][name]['exact_effect_variance']-h['exact_risks']['directional']['exact_effect_variance'] for h in c['hypotheses']]) for c in group])
            radius = t.ppf(1-plan['component_alpha']/(2*len(plan['scenarios'])),len(group)-1)*delta.std(ddof=1)/np.sqrt(len(group))
            baseline = np.mean([h['exact_risks'][name]['exact_effect_variance'] for c in group for h in c['hypotheses']])
            batches = [float(delta[[c['batch']==batch for c in group]].mean()) for batch in (0,1)]
            np.testing.assert_allclose(comparison['variance_reduction'],delta.mean(),atol=1e-12)
            np.testing.assert_allclose(comparison['approximate_simultaneous_t_interval'],[delta.mean()-radius,delta.mean()+radius],atol=1e-12)
            np.testing.assert_allclose(comparison['relative_variance_reduction'],delta.mean()/baseline,atol=1e-12)
            np.testing.assert_allclose(comparison['batch_reductions'],batches,atol=1e-12)
            assert comparison['precision_supported']==bool(delta.mean()/baseline>=plan['minimum_relative_variance_reduction'] and delta.mean()-radius>0 and min(batches)>0)
            gains = [c['decisions']['directional']['confirmed_count']-c['decisions'][name]['confirmed_count'] for c in group]
            np.testing.assert_allclose(comparison['confirmed_count_gain'],np.mean(gains))
            np.testing.assert_allclose(comparison['confirmed_count_batch_gains'],[np.mean([v for v,c in zip(gains,group,strict=True) if c['batch']==b]) for b in (0,1)])
    result = dict(status='VERIFIED',evidence_role=plan['evidence_role'],cells=len(cells),models=models_checked,ci_queries=queries_checked,
        source_archive_sha256=identity['source_archive_sha256'],verifier_sha256=file_sha256(Path(__file__)),new_model_calls=0)
    if not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result

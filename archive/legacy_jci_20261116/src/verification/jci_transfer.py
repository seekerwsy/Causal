from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import zipfile

import numpy as np

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.verification.jci_replay import independent_counterfactual, independent_features, independent_model
from prompt_mechanism_study.verification.jci_reliability import reconstructed_ci_statistic


def independent_design(tasks, identities, mask, plan, shared):
    result = []
    terms = [term for term in range(8) if term&mask==term]
    for key in identities:
        state = [2*value-1 for value in tasks[key]['initial_states']]
        complete = [float(np.prod([state[bit] for bit in range(3) if term>>bit&1])) for term in range(8)]
        environment = plan['families'].index(tasks[key]['family'])
        if shared:
            row = [complete[term] for term in terms]
            for column in range(3):
                multiplier = -1 if environment==3 else int(environment==column)
                row.extend(multiplier*value for value in complete)
        else:
            row = [value*int(environment==column) for column in range(4) for value in complete]
        result.append(row)
    return np.asarray(result)


def independent_scores(model, tasks, identities, plan):
    values = independent_design(tasks,identities,model['mask'],plan,model['shared'])@np.asarray(model['coefficients']).T
    for index,key in enumerate(identities):
        for policy,name in enumerate(plan['policies']):
            source = tasks[key]['conditions']['TSG']
            if all(source[str(version)][name]['prompt_hash']==source[str(version)]['B']['prompt_hash'] for version in (1,2)):
                values[index,policy] = 0.
    return values


def independent_actions(scores, threshold):
    return np.asarray([0 if max(row)<=threshold else max(range(4),key=lambda action:0. if action==0 else row[action-1])
                       for row in scores],dtype=int)


def verify_roles(case, tasks, requests, plan):
    target,budget = case['target'],case['budget']
    expected = {name:[] for name in case['roles']}
    for family in plan['families']:
        identities = [key for key,task in tasks.items() if task['family']==family and task['role']=='training']
        identities.sort(key=lambda key:hashlib.sha256(f'{plan["split_seed"]}/{target}/{family}/{key}'.encode()).hexdigest())
        boundary = 50 if family==target else 70
        expected['target_adaptation' if family==target else 'source_training'].extend(identities[:boundary])
        expected['target_calibration' if family==target else 'source_calibration'].extend(identities[boundary:])
    expected['test'] = sorted(key for key,task in tasks.items() if task['family']==target and task['role']=='evaluation')
    assert expected==case['roles']
    assert [len(expected[name]) for name in ('source_training','source_calibration','target_adaptation','target_calibration','test')]==[210,90,50,50,100]
    identities = [key for group in expected.values() for key in group]
    assert len(set(identities))==len(identities)
    mixture = sorted((row for row in requests if row['component']=='random_mixture'),key=lambda row:row['independent_event'])
    for name,sequence in case['requests'].items():
        allowed = set(expected[name])
        rows = [row for row in mixture if row['task_unit_id'] in allowed]
        seed = int.from_bytes(hashlib.sha256(json.dumps([plan['schedule_seed'],target,name]).encode()).digest()[:8],'big')
        order = np.random.default_rng(seed).permutation(len(rows))
        count = budget//2 if name.startswith('target_') else len(rows)
        assert sequence==[rows[int(index)]['request_id'] for index in order[:count]]
    assert sum(len(case['requests'][name]) for name in ('target_adaptation','target_calibration'))==budget


def verify_nuisance_and_pseudo(cell, tasks, plan):
    observations,learned = cell['observations'],cell['learned']
    fitting = observations['source_training']+observations['target_adaptation']
    nuisance = learned['nuisance']
    identities = sorted({row['task_unit_id'] for row in fitting})
    folds = {}
    for family in plan['families']:
        ordered = sorted((key for key in identities if tasks[key]['family']==family),
            key=lambda key:hashlib.sha256(f'{plan["fold_seed"]}/{key}'.encode()).hexdigest())
        folds.update({key:index%plan['folds'] for index,key in enumerate(ordered)})
    assert folds==nuisance['folds']
    counts = {key:sum(row['task_unit_id']==key for row in fitting) for key in identities}
    design = np.asarray([independent_features(tasks[row['task_unit_id']],row['arm'],row['prepared'],
        row['prompt_hash'],row['version'],plan) for row in fitting])
    weights = np.asarray([1/counts[row['task_unit_id']] for row in fitting])
    outcome = np.asarray([row['y'] for row in fitting])
    for index,model in enumerate([*nuisance['models'],nuisance['complete_model']]):
        selected = np.ones(len(fitting),dtype=bool) if index==plan['folds'] else np.asarray([folds[row['task_unit_id']]!=index for row in fitting])
        expected = independent_model(design[selected],outcome[selected],weights[selected],plan['nuisance_penalty'])
        np.testing.assert_allclose(np.r_[model['intercept'],model['coefficients']],expected,atol=1e-9)
    for role,rows in (('training',fitting),('source_calibration',observations['source_calibration']),('target_calibration',observations['target_calibration'])):
        saved = nuisance[role]
        keys = sorted({row['task_unit_id'] for row in rows})
        assert keys==saved['task_ids']
        unit_indexes = {key:index for index,key in enumerate(keys)}
        row_predictions = []
        means = []
        for key in keys:
            model = nuisance['models'][folds[key]] if role=='training' else nuisance['complete_model']
            coefficient = np.asarray(model['coefficients'])
            means.append([np.clip(independent_counterfactual(tasks[key],arm,plan)@coefficient+model['intercept'],0.,1.).mean()
                          for arm in range(4)])
        means = np.asarray(means)
        scores = means[:,1:]-means[:,:1]
        request_counts = {key:sum(row['task_unit_id']==key for row in rows) for key in keys}
        for row in rows:
            key = row['task_unit_id']
            model = nuisance['models'][folds[key]] if role=='training' else nuisance['complete_model']
            x = independent_features(tasks[key],row['arm'],row['prepared'],row['prompt_hash'],row['version'],plan)
            prediction = float(np.clip(x@np.asarray(model['coefficients'])+model['intercept'],0.,1.))
            row_predictions.append(prediction)
            for policy in range(3):
                multiplier = (int(row['arm']==policy+1)-int(row['arm']==0))/(plan['propensity']*request_counts[key])
                scores[unit_indexes[key],policy] += multiplier*(row['y']-prediction)
        for index,key in enumerate(keys):
            for policy,name in enumerate(plan['policies']):
                if all(tasks[key]['conditions']['TSG'][str(version)][name]['prompt_hash']==
                       tasks[key]['conditions']['TSG'][str(version)]['B']['prompt_hash'] for version in (1,2)):
                    scores[index,policy] = 0.
        np.testing.assert_allclose(scores,saved['scores'],atol=1e-9)
        np.testing.assert_allclose(means,saved['counterfactual'],atol=1e-9)
        np.testing.assert_allclose(row_predictions,saved['observed_predictions'],atol=1e-9)
        np.testing.assert_allclose(saved['request_weights'],[1/request_counts[row['task_unit_id']] for row in rows],atol=1e-12)
        assert saved['request_task_indexes']==[unit_indexes[row['task_unit_id']] for row in rows]
    return plan['folds']+1


def verify_graphs(cell, tasks, plan):
    fitting = cell['observations']['source_training']+cell['observations']['target_adaptation']
    first = {}
    for row in fitting:
        first.setdefault(row['task_unit_id'],row)
    structure = cell['structure']
    rows = list(first.values())
    assert structure['task_ids']==[row['task_unit_id'] for row in rows]
    assert structure['request_ids']==[row['request_id'] for row in rows]
    labels = ['E','C1','C2','C3','C4','W1','W2','W3','X1','X2','X3','Y']
    assert structure['labels']==labels
    data = np.asarray([[plan['families'].index(row['family']),*[int(row['arm']==arm) for arm in range(1,5)],
        *tasks[row['task_unit_id']]['initial_states'],*row['prepared'],row['y']] for row in rows],dtype=int)
    states,counts = np.unique(data,axis=0,return_counts=True)
    seen = set()
    for query in structure['queries']:
        key = query['x'],query['y'],tuple(query['conditioned'])
        assert key not in seen
        seen.add(key)
        statistic,informative = reconstructed_ci_statistic(states,counts,[4]+[2]*11,labels,query)
        np.testing.assert_allclose(statistic,query['statistic'],atol=1e-8)
        assert informative==query['informative_strata']
        assert query['p']==(query['exceedances']+1)/(plan['ci_draws']+1)
    masks = {}
    for name,graph in structure['graphs'].items():
        assert graph['conservative'] and graph['pcalg']=='2.7.12'
        pag,ancestry = np.asarray(graph['pag']),np.asarray(graph['ancestry'])
        assert pag.shape==ancestry.shape==(12,12)
        np.testing.assert_array_equal(pag==0,pag.T==0)
        assert not pag[1:5,0].any() and not pag[1:5,5:8].any()
        definite = sum(2**bit for bit in range(3) if ancestry[bit+5,-1]==1)
        possible = sum(2**bit for bit in range(3) if ancestry[bit+5,-1]!=-1)
        masks['jci_transfer' if name=='jci' else 'time_transfer'] = list(dict.fromkeys([definite,possible,7]))
    pag = np.asarray(structure['graphs']['jci']['pag'])
    masks['adjacency_transfer'] = list(dict.fromkeys([sum(2**bit for bit in range(3) if pag[bit+5,-1]),7]))
    source = cell['learned']['nuisance']['source_calibration']
    source_families = [family for family in plan['families'] if family!=cell['design']['target']]
    ranking = []
    for mask in range(8):
        groups = {}
        for index,key in enumerate(source['task_ids']):
            coordinate = tuple(value for bit,value in enumerate(tasks[key]['initial_states']) if mask>>bit&1)
            groups.setdefault(coordinate,{}).setdefault(tasks[key]['family'],[]).append(index)
        valid = all(all(len(group.get(family,[]))>=plan['stability_minimum_task_units'] for family in source_families) for group in groups.values())
        loss = None
        if valid:
            deviations = []
            for group in groups.values():
                means = np.asarray([np.asarray(source['scores'])[group[family]].mean(axis=0) for family in source_families])
                deviations.append(float(np.mean((means-means.mean(axis=0))**2)))
            loss = float(np.mean(deviations))
        ranking.append(dict(mask=mask,supported=valid,loss=loss))
    for actual,expected in zip(cell['learned']['stability'],ranking,strict=True):
        assert actual['mask']==expected['mask'] and actual['supported']==expected['supported']
        if expected['loss'] is None:
            assert actual['loss'] is None
        else:
            np.testing.assert_allclose(actual['loss'],expected['loss'],atol=1e-12)
    ordered = sorted((row for row in ranking if row['supported']),key=lambda row:(row['loss'],row['mask']))
    masks['direct_invariance'] = list(dict.fromkeys([row['mask'] for row in ordered[:plan['candidate_limit']-1]]+[7]))
    masks['direct_full'] = [7]
    assert masks==cell['learned']['masks']
    return len(seen)


def verify_effects_and_choices(cell, tasks, plan):
    learned = cell['learned']
    nuisance = learned['nuisance']
    training,source,target = [nuisance[name] for name in ('training','source_calibration','target_calibration')]
    n = len(training['task_ids'])
    for model in learned['models']:
        design = independent_design(tasks,training['task_ids'],model['mask'],plan,model['shared'])
        width = 2**model['mask'].bit_count() if model['shared'] else design.shape[1]
        penalties = np.asarray([model['penalty']]*width+[model['deviation']]*(design.shape[1]-width))
        assert np.isfinite(penalties).all() and np.all(penalties>0)
        np.testing.assert_allclose(penalties,model['penalties'],atol=1e-14)
        gram = design.T@design/n+np.diag(penalties)
        values,vectors = np.linalg.eigh(gram)
        reference = vectors@((vectors.T@(design.T@np.asarray(training['scores'])/n))/values[:,None])
        np.testing.assert_allclose(reference.T,model['coefficients'],atol=1e-8)
        expected_loss = np.mean((np.asarray(source['scores'])-independent_scores(model,tasks,source['task_ids'],plan))**2,axis=0)
        np.testing.assert_allclose(expected_loss,model['source_loss_by_policy'],atol=1e-9)
    target_scores = {index:independent_scores(model,tasks,target['task_ids'],plan) for index,model in enumerate(learned['models'])}
    model_lookup = {(model['mask'],model['penalty'],model['deviation'],model['shared']):index
                    for index,model in enumerate(learned['models'])}
    assert len(model_lookup)==len(learned['models'])
    for name in plan['methods']:
        specifications = [(*coordinate,True) for coordinate in itertools.product(learned['masks'][name],plan['deviation_penalties'])]
        specifications.append((7,plan['deviation_penalties'][0],False))
        groups = []
        for policy in range(3):
            for mask,deviation,shared in specifications:
                indexes = [model_lookup[(mask,penalty,deviation,shared)] for penalty in plan['ridge_penalties']]
                selected = min(indexes,key=lambda index:(learned['models'][index]['source_loss_by_policy'][policy],index))
                groups.append(dict(policy=policy,mask=mask,deviation=deviation,shared=shared,model_ids=indexes,selected_model_id=selected))
        assert groups==learned['fit_groups'][name]
        combinations = []
        for deviation in plan['deviation_penalties']:
            selections = [[group['selected_model_id'] for group in groups if group['policy']==policy and group['shared'] and group['deviation']==deviation]
                          for policy in range(3)]
            combinations.extend(itertools.product(*selections))
        combinations.append(tuple(next(group['selected_model_id'] for group in groups if group['policy']==policy and not group['shared']) for policy in range(3)))
        candidates = []
        for indexes in dict.fromkeys(combinations):
            scores = np.column_stack([target_scores[index][:,policy] for policy,index in enumerate(indexes)])
            for threshold in plan['edit_thresholds']:
                actions = independent_actions(scores,threshold)
                gains = [0. if action==0 else target['scores'][index][int(action)-1] for index,action in enumerate(actions)]
                candidates.append(dict(model_ids=list(indexes),threshold=threshold,calibration_gain=float(np.mean(gains))))
        actual = learned['policy_candidates'][name]
        assert len(actual)==len(candidates)
        for saved,reference in zip(actual,candidates,strict=True):
            assert saved['model_ids']==reference['model_ids'] and saved['threshold']==reference['threshold']
            np.testing.assert_allclose(saved['calibration_gain'],reference['calibration_gain'],atol=1e-9)
        best = max(candidates,key=lambda row:(row['calibration_gain'],tuple(-index for index in row['model_ids']),-row['threshold']))
        choice = learned['choices'][name]
        if best['calibration_gain']<=0:
            assert choice==dict(model_ids=None,threshold=None,calibration_gain=0.)
        else:
            assert choice['model_ids']==best['model_ids'] and choice['threshold']==best['threshold']
            np.testing.assert_allclose(choice['calibration_gain'],best['calibration_gain'],atol=1e-9)
    return len(learned['models'])


def verify_evaluation(output, cells, tasks, inputs, plan):
    verify_bundle(output/'evaluation-inputs')
    identity = read_json(output/'evaluation-inputs/identity.json')
    root = Path(plan['evaluation_results'])
    verify_bundle(root)
    assert identity['all_choices_frozen'] is True
    assert file_sha256(root/'manifest.json')==identity['evaluation_manifest_sha256']
    terminals = {row['request_id']:row for row in read_json(root/'results.json')}
    measurements = {key:{name:[] for name in plan['contexts'][:4]} for key,task in tasks.items() if task['role']=='evaluation'}
    for request in read_json(inputs/'evaluation-requests.json'):
        key = request['task_unit_id']
        terminal = terminals[request['request_id']]
        assert terminal['task_unit_id']==key and terminal['secure_yield'] in (0,1)
        assert terminal['status'] in ('returned','generation_failed')
        failed = terminal['status']=='generation_failed'
        if failed:
            assert terminal['secure_yield']==0 and terminal['code_valid'] is False
        for member in request['members']:
            name = member['condition']
            if member['flow']!='TSG' or name not in measurements[key]:
                continue
            expected = tasks[key]['conditions']['TSG'][str(member['version'])][name]['prompt_hash']
            assert expected==request['prompt_hash']==terminal['prompt_hash']
            measurements[key][name].append(dict(request_id=request['request_id'],version=member['version'],repeat=member['repeat'],
                secure=float(terminal['secure_yield']),finite=float(terminal['functionality']=='finite_pass'),
                support=0. if failed else float(terminal['oracle_support'] is True),
                unknown=float(terminal['code_valid'] is True and terminal['security_label']=='unknown'),
                complete_known=0. if failed else float(terminal['complete_functionality'] in ('pass','fail'))))
    for conditions in measurements.values():
        for rows in conditions.values():
            rows.sort(key=lambda row:(row['version'],row['repeat']))
            assert [(row['version'],row['repeat']) for row in rows]==[(version,repeat) for version in (1,2) for repeat in range(plan['evaluation_repeats_per_version'])]
    assert measurements==read_json(output/'evaluation-inputs/measurements.json')
    evaluations = []
    for cell in cells:
        case = cell['design']
        path = output/'evaluation'/f'{case["target"]}-{case["budget"]}'
        verify_bundle(path)
        evaluation = read_json(path/'result.json')
        assert evaluation['target']==case['target'] and evaluation['budget']==case['budget']
        identities = case['roles']['test']
        for name,choice in cell['learned']['choices'].items():
            if choice['model_ids'] is None:
                scores = np.zeros((len(identities),3))
                actions = np.zeros(len(identities),dtype=int)
            else:
                scores = np.column_stack([independent_scores(cell['learned']['models'][index],tasks,identities,plan)[:,policy]
                    for policy,index in enumerate(choice['model_ids'])])
                actions = independent_actions(scores,choice['threshold'])
            panel = evaluation['methods'][name]
            assert [row['task_unit_id'] for row in panel['assignments']]==identities
            assert panel['task_units']==100 and panel['edited_tasks']==np.count_nonzero(actions)
            for index,assignment in enumerate(panel['assignments']):
                key = identities[index]
                assert assignment['action']==actions[index]
                np.testing.assert_allclose(assignment['scores'],scores[index],atol=1e-9)
                baseline = measurements[key]['B']
                selected = measurements[key][plan['contexts'][int(actions[index])]]
                assert assignment['baseline_requests']==[row['request_id'] for row in baseline]
                assert assignment['target_requests']==[row['request_id'] for row in selected]
                for field in ('secure','finite','support','unknown'):
                    expected = sum(row[field] for row in selected)/len(selected)-sum(row[field] for row in baseline)/len(baseline)
                    np.testing.assert_allclose(assignment[f'{field}_gain'],expected,atol=1e-12)
                np.testing.assert_allclose(assignment['complete_functionality_known'],np.mean([row['complete_known'] for row in selected]),atol=1e-12)
            for field in ('secure_gain','finite_gain','support_gain','unknown_gain','complete_functionality_known'):
                np.testing.assert_allclose(panel[field],np.mean([row[field] for row in panel['assignments']]),atol=1e-12)
        evaluations.append(evaluation)
    return evaluations


def verify_summary(output, evaluations, tasks, plan):
    verify_bundle(output/'summary')
    summary = read_json(output/'summary/result.json')
    keys = sorted(key for key,task in tasks.items() if task['role']=='evaluation')
    assert summary['test_task_ids']==keys and summary['test_task_units']==400
    assert summary['evidence_role']==plan['evidence_role'] and summary['new_model_calls']==0
    assert summary['environment_folds_are_independent'] is False
    family_size = len(plan['target_budgets'])*len(plan['primary_comparators'])
    assert summary['primary_family_size']==family_size
    rng = np.random.default_rng(plan['bootstrap_seed'])
    groups = [[index for index,key in enumerate(keys) if tasks[key]['family']==family] for family in plan['families']]
    resampled = np.column_stack([rng.choice(group,size=(plan['bootstrap_draws'],len(group)),replace=True) for group in groups])
    assert [group['budget'] for group in summary['groups']]==plan['target_budgets']
    for group in summary['groups']:
        selected = [row for row in evaluations if row['budget']==group['budget']]
        values,actions = {},{}
        for name in plan['methods']:
            assigned = {row['task_unit_id']:row for cell in selected for row in cell['methods'][name]['assignments']}
            assert set(assigned)==set(keys)
            values[name] = np.asarray([assigned[key]['secure_gain'] for key in keys])
            actions[name] = [assigned[key]['action'] for key in keys]
            for field in ('secure_gain','finite_gain','support_gain','unknown_gain','complete_functionality_known'):
                np.testing.assert_allclose(group['methods'][name][field],np.mean([assigned[key][field] for key in keys]),atol=1e-12)
            assert group['methods'][name]['edited_tasks']==np.count_nonzero(actions[name])
        assert [row['comparator'] for row in group['comparisons']]==plan['primary_comparators']
        for comparison in group['comparisons']:
            name = comparison['comparator']
            difference = values[plan['primary_method']]-values[name]
            expected = np.percentile(difference[resampled].mean(axis=1),
                [100*plan['alpha']/(2*family_size),100*(1-plan['alpha']/(2*family_size))])
            np.testing.assert_allclose(difference,comparison['task_differences'],atol=1e-12)
            np.testing.assert_allclose(difference.mean(),comparison['difference'],atol=1e-12)
            np.testing.assert_allclose(expected,comparison['simultaneous_descriptive_interval'],atol=1e-12)
            assert comparison['changed_actions']==sum(a!=b for a,b in zip(actions[plan['primary_method']],actions[name],strict=True))
            assert comparison['practical_positive']==bool(expected[0]>plan['practical_gain'])


def verify_transfer(output):
    verify_bundle(output/'inputs')
    plan,identity,design = [read_json(output/'inputs'/name) for name in ('plan.json','identity.json','design.json')]
    assert plan['formal_claim_allowed'] is False and plan['evidence_role']=='POST_HOC_EXPOSED_TRANSFER_METHOD_CHECK'
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        assert hashlib.sha256(archive.read('plan.json')).hexdigest()==identity['plan_sha256']
        assert json.loads(archive.read('plan.json'))==plan
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    inputs = Path(plan['inputs'])
    verify_bundle(inputs)
    assert file_sha256(inputs/'manifest.json')==identity['input_manifest_sha256']
    tasks = {row['task_unit_id']:row for row in read_json(inputs/'tasks.json')}
    requests = read_json(inputs/'training-requests.json')
    originals = {row['request_id']:row for row in requests}
    assert [(row['target'],row['budget']) for row in design['cases']]==list(itertools.product(plan['families'],plan['target_budgets']))
    cells,cache,models,queries = [],{},0,0
    for case in design['cases']:
        verify_roles(case,tasks,requests,plan)
        root = output/'cells'/f'{case["target"]}-{case["budget"]}'
        if not root.exists():
            continue
        verify_bundle(root)
        cell = read_json(root/'result.json')
        assert cell['design']==case
        for role,rows in cell['observations'].items():
            assert [row['request_id'] for row in rows]==case['requests'][role]
            for row in rows:
                key = row['request_id']
                original = originals[key]
                assert row['task_unit_id'] in case['roles'][role]
                assert original['task_unit_id']==row['task_unit_id']
                assert (row['arm'],row['version'],row['prepared'],row['prompt_hash'])==(
                    original['context'],original['version'],original['actual_states'],original['prompt_hash'])
                if key not in cache:
                    terminal = Path(plan['training_results'])/key/'result'
                    verify_bundle(terminal)
                    cache[key] = read_json(terminal/'result.json'),file_sha256(terminal/'manifest.json')
                result,digest = cache[key]
                assert row['terminal_manifest_sha256']==digest
                assert result['secure_yield']==row['y'] and result['status']==row['status']
        models += verify_nuisance_and_pseudo(cell,tasks,plan)
        queries += verify_graphs(cell,tasks,plan)
        models += verify_effects_and_choices(cell,tasks,plan)
        cells.append(cell)
        print(f'Independently checked transfer cell {len(cells)}: {case["target"]}, {case["budget"]}',flush=True)
    choices_complete = len(cells)==len(design['cases'])
    complete = choices_complete and (output/'summary').exists()
    if complete:
        evaluations = verify_evaluation(output,cells,tasks,inputs,plan)
        verify_summary(output,evaluations,tasks,plan)
    else:
        assert not (output/'evaluation-inputs').exists() and not (output/'summary').exists()
    result = dict(status='VERIFIED' if complete else 'CHOICES_VERIFIED' if choices_complete else 'PARTIAL_CHECKED',
        complete=complete,choices_complete=choices_complete,cells=len(cells),
        independent_model_fits=models,independently_checked_ci_queries=queries,
        original_training_requests_checked=len(cache),test_task_units=400 if complete else 0,
        task_roles_and_budgets_verified=True,policy_choices_verified=True,
        evaluation_and_intervals_verified=complete,new_model_calls=0,verifier_sha256=file_sha256(Path(__file__)))
    if complete and not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result

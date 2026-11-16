from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import zipfile

import numpy as np
from scipy.stats import binom, random_table, t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle


def verify_preparation(output):
    from prompt_mechanism_study.records import content_hash
    from prompt_mechanism_study.tsg.prompt_tsg import prompt_tsg_from_record, validate_prompt_tsg
    for directory in ('inputs','preparation','review','summary'):
        verify_bundle(output/directory)
    identity = read_json(output/'inputs'/'identity.json')
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        for path,digest in identity['implementation_sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    source_path = Path(identity['sources'])
    verify_bundle(source_path)
    assert file_sha256(source_path/'manifest.json')==identity['source_manifest_sha256']
    sources = read_json(output/'inputs'/'sources.json')
    assert sources==read_json(source_path/'sources.json')
    annotations = read_json(output/'inputs'/'annotations.json')
    assert content_hash(annotations)==identity['annotations_content_sha256']
    assert identity['formal_claim_allowed'] is False
    prepared = read_json(output/'preparation'/'result.json')
    packet = read_json(output/'review'/'packet.json')
    assert len(sources)==len(prepared)==len(packet['cases'])==4
    assert len({row['task_unit_id'] for row in prepared})==4
    count = 0
    for source,row,case in zip(sources,prepared,packet['cases'],strict=True):
        annotation = annotations['families'][source['family']]
        assert row['task_unit_id']==source['task_unit_id']==case['task_unit_id']
        assert row['family']==source['family']==case['family']
        assert row['original_prompt_hash']==source['prompt_hash']==content_hash(source['prompt'])
        assert row['role']=='preparation_only' and row['semantic_review']=='PENDING_INDEPENDENT_REVIEW'
        assert row['outcome_status']=='NOT_GENERATED' and row['outcome_overlap_status']=='NOT_OBSERVED'
        assert row['automatic_graph_accuracy_established'] is False
        assert case['source']==source['prompt'] and case['policy']==annotation['requirement']
        assert case['binding']==dict(direct_target='primary_operation',input_role='primary_path',comparison_target=False)
        assert len(row['versions'])==len(case['versions'])==4
        factors = []
        for version,review in zip(row['versions'],case['versions'],strict=True):
            control,treated = version['arms']
            assert [control['arm'],treated['arm']]==[0,1]
            assert treated['prompt']==control['prompt']+'\n\nAdditional security requirement: '+annotation['requirement']
            normalized = control['prompt'].replace(annotation['reference_operation'],annotation['primary_operation'])
            assert sorted(normalized.split('\n\n'))==sorted(source['prompt'].split('\n\n'))
            assert review==dict(version_id=version['version_id'],control=control['prompt'],treated=treated['prompt'])
            for arm in (control,treated):
                assert arm['prompt_hash']==content_hash(arm['prompt'])
                assert arm['independent_representation_treatment'] is False
                graph = prompt_tsg_from_record(arm['graph'])
                validate_prompt_tsg(graph,prompt=arm['prompt'],catalog=row['catalog'])
                nodes = {node.node_id:node for node in graph.nodes}
                semantic = {node.semantic_id:node for node in graph.nodes}
                facts = {fact['semantic_id']:fact for fact in arm['flat']['facts']}
                assert len(facts)==len(graph.nodes)
                for node in graph.nodes:
                    assert facts[node.semantic_id]==dict(semantic_id=node.semantic_id,node_type=node.node_type,
                        evidence_start=node.evidence_start,evidence_end=node.evidence_end,
                        evidence_text=arm['prompt'][node.evidence_start:node.evidence_end])
                flat_edges = {(edge['source'],edge['relation'],edge['target']) for edge in arm['flat']['relations']}
                edges = {(nodes[edge.source_id].semantic_id,edge.edge_type,nodes[edge.target_id].semantic_id) for edge in graph.edges}
                assert flat_edges==edges and len(flat_edges)==len(arm['flat']['relations'])
                assert arm['flat']['requirement_structures']==arm['graph']['requirement_structures']
                assert ('primary_path','used_by','primary_operation') in edges
                assert ('comparison_path','used_by','comparison_operation') in edges
                if arm['arm']:
                    assert {(a,b,c) for a,b,c in edges if a=='no_shell'}=={('no_shell','constrains','primary_operation')}
                    assert arm['prompt'][semantic['no_shell'].evidence_start:semantic['no_shell'].evidence_end]==annotation['requirement']
                else:
                    assert 'no_shell' not in semantic
                    x = int(semantic['primary_operation'].evidence_start>semantic['comparison_operation'].evidence_start)
                    quote = arm['prompt'][semantic['primary_operation'].evidence_start:semantic['primary_operation'].evidence_end]
                    n = int(quote==annotation['reference_operation'])
                    assert quote in (annotation['primary_operation'],annotation['reference_operation'])
                    distance = abs(semantic['primary_operation'].evidence_start-semantic['primary_path'].evidence_start)/len(arm['prompt'])
                    assert version['realization_factors']==[x,n]
                    assert version['measured_graph_attributes']==dict(normalized_binding_evidence_distance=distance,
                        primary_mention_after_comparison=x,role_reference_requires_declaration=n)
                    factors.append((x,n))
                count += 1
        assert set(factors)==set(itertools.product((0,1),repeat=2))
        assert [(context['c1'],context['c2']) for context in row['contexts']]==list(itertools.product((0,1),repeat=2))
        for context in row['contexts']:
            p,q = .25+.5*context['c1'],.25+.5*context['c2']
            expected = [(p if x else 1-p)*(q if n else 1-q) for x,n in factors]
            assert context['version_probabilities']==expected and sum(expected)==1 and min(expected)==.0625
    summary = read_json(output/'summary'/'result.json')
    assert summary['task_units']==4 and summary['versions']==16 and summary['prepared_prompts']==count==32
    assert summary['semantic_review']=='PENDING_INDEPENDENT_REVIEW' and summary['outcome_overlap']=='NOT_OBSERVED'
    assert summary['causal_information_gain']=='NOT_ESTABLISHED' and summary['graph_advantage']=='NOT_TESTED'
    assert summary['new_model_calls']==0
    result = dict(status='VERIFIED',evidence_role=identity['evidence_role'],task_units=4,prepared_prompts=count,
        semantic_review='PENDING_INDEPENDENT_REVIEW',new_model_calls=0,
        verifier_sha256=file_sha256(Path(__file__)))
    if not (output/'verification').exists():
        write_bundle(output/'verification',{'result.json':result})
    return result


def stream(seed,*coordinates):
    digest = hashlib.sha256(json.dumps([seed,*coordinates]).encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8],'big'))


def probability(w,u,a,e,z,h,scenario):
    effects = [.055,.045,.035,-.02] if scenario=='near_threshold' else [.18,.10,.03,-.06]
    effect = effects[h]
    if scenario=='effect_cancellation' and h==0:
        effect = .18*(2*w-1)
    result = .28+.06*w+.08*u+.07*z[0]+.04*z[1]+a*(effect+.04*(2*w-1))
    return result+(.14*e*(2*a-1) if scenario=='hidden_wording' else 0)


def pool(w,u,e,scenario):
    first = e if scenario=='no_overlap' else (.15+.4*e+.25*u+.1*w if scenario=='latent_confounding' else .25+.5*e)
    second = .2+.6*u
    return [(first if z1 else 1-first)*(second if z2 else 1-second)
            for z1,z2 in itertools.product((0,1),repeat=2)]


def verify_draw(data,plan,scenario,repetition,h,role,target=False):
    rng = stream(plan['seed'],scenario,repetition,h,role)
    n = len(data['w'])
    w,u = rng.integers(0,2,size=(2,n))
    a = rng.integers(0,2,n)
    e = np.zeros(n,dtype=int) if target else rng.integers(0,2,n)
    q = [pool(wi,ui,ei,scenario) for wi,ui,ei in zip(w,u,e,strict=True)]
    versions = [tuple(itertools.product((0,1),repeat=2))[rng.choice(4,p=qi)] for qi in q]
    means = [probability(wi,ui,ai,ei,z,h,scenario) for wi,ui,ai,ei,z in zip(w,u,a,e,versions,strict=True)]
    y = rng.binomial(1,means)
    for field,value in (('w',w),('u',u),('a',a),('e',e),('z',versions),('y',y)):
        np.testing.assert_array_equal(data[field],value)
    np.testing.assert_allclose(data['target_weights'],[pool(wi,ui,0,scenario) for wi,ui in zip(w,u,strict=True)],atol=1e-14)
    assert data['propensity']==(.5 if target else .25)
    assert data['task_ids']==[f'{scenario}/{h}/{role}/{index}' for index in range(n)]


def model_key(model,a,e,w,z):
    values = [a,w]+(list(z) if model['mask'] is None else [z[j] for j in (0,1) if model['mask']&(2**j)])
    if model['mask'] is None and not model['target_only']:
        values.insert(0,e)
    return tuple(values)


def verify_model(model,data):
    cells = {}
    for i,y in enumerate(data['y']):
        if model['target_only'] and data['e'][i]!=0:
            continue
        key = model_key(model,*[data[field][i] for field in ('a','e','w','z')])
        cells.setdefault(key,[]).append(y)
    expected = [dict(key=list(key),count=len(values),successes=sum(values),
        prediction=(sum(values)+.5)/(len(values)+1)) for key,values in sorted(cells.items())]
    assert model['cells']==expected


def predictions(model,data):
    mapping = {tuple(cell['key']):cell['prediction'] for cell in model['cells']}
    return [mapping.get(model_key(model,*row),.5) for row in zip(
        data['a'],data['e'],data['w'],data['z'],strict=True)]


def verify_scores(record,model,data):
    mapping = {tuple(cell['key']):cell['prediction'] for cell in model['cells']}
    values = []
    integrals,observed = [],[]
    for index,w in enumerate(data['w']):
        means = [sum(data['target_weights'][index][j]*mapping.get(model_key(model,a,0,w,z),.5)
            for j,z in enumerate(itertools.product((0,1),repeat=2))) for a in (0,1)]
        pred = mapping.get(model_key(model,data['a'][index],data['e'][index],w,data['z'][index]),.5)
        score = means.copy()
        if data['e'][index]==0:
            score[data['a'][index]] += (data['y'][index]-pred)/data['propensity']
        values.append(score)
        integrals.append(means)
        observed.append(pred)
    np.testing.assert_allclose(record['integrated'],integrals,atol=1e-13)
    np.testing.assert_allclose(record['observed'],observed,atol=1e-13)
    np.testing.assert_allclose(record['scores'],values,atol=1e-13)
    differences = np.diff(values,axis=1)[:,0]
    np.testing.assert_allclose(record['effect'],np.mean(differences),atol=1e-13)
    np.testing.assert_allclose(record['standard_error'],np.std(differences,ddof=1)/np.sqrt(len(values)),atol=1e-13)


def verify_ci(queries,data,plan,seed):
    labels = ['E','A','W','Z1','Z2','Y']
    observations = np.column_stack([data['e'],data['a'],data['w'],data['z'],data['y']])
    for query in queries:
        x,y = sorted((query['x'],query['y']))
        conditioned = tuple(sorted(query['conditioned']))
        key = (x,y,conditioned)
        rng = np.random.default_rng(int.from_bytes(hashlib.sha256(json.dumps([seed,key]).encode()).digest()[:8],'big'))
        groups = {}
        for row in observations:
            group = tuple(row[labels.index(name)] for name in conditioned)
            groups.setdefault(group,[]).append(row)
        tables,simulated,statistic,informative = [],np.zeros(plan['ci_draws']),0.,0
        supported = True
        for _,rows in sorted(groups.items()):
            table = np.zeros((2,2),dtype=int)
            for row in rows:
                table[row[labels.index(x)],row[labels.index(y)]] += 1
            table = table[table.sum(axis=1)>0][:,table.sum(axis=0)>0]
            tables.append(table.tolist())
            if min(table.shape)==1:
                supported = False
                continue
            informative += 1
            supported = supported and min(table.sum(0))>=2 and min(table.sum(1))>=2
            expected = np.outer(table.sum(1),table.sum(0))/table.sum()
            statistic += np.sum((table-expected)**2/expected)
            null = random_table.rvs(table.sum(1),table.sum(0),size=plan['ci_draws'],random_state=rng)
            simulated += np.sum((null-expected)**2/expected,axis=(1,2))
        count = int(np.count_nonzero(simulated>=statistic-1e-12))
        p = (count+1)/(plan['ci_draws']+1) if supported and informative else None
        assert query['tables']==tables and query['exceedances']==count and query['informative_strata']==informative
        assert query['p']==p
        np.testing.assert_allclose(query['statistic'],statistic,atol=1e-12)


def verify_confirmation(record,plan,scenario,repetition,h):
    rng = stream(plan['seed'],scenario,repetition,h,'confirmation')
    n = plan['confirmation_task_units_per_hypothesis']
    w,u = rng.integers(0,2,size=(2,n))
    np.testing.assert_array_equal(record['w'],w)
    np.testing.assert_array_equal(record['u'],u)
    q = [pool(wi,ui,0,scenario) for wi,ui in zip(w,u,strict=True)]
    versions = list(itertools.product((0,1),repeat=2))
    ys = []
    for a in (0,1):
        v = [int(rng.choice(4,p=qi)) for qi in q]
        ps = [probability(wi,ui,a,0,versions[vi],h,scenario) for wi,ui,vi in zip(w,u,v,strict=True)]
        outcome = rng.binomial(1,ps)
        np.testing.assert_array_equal(record['versions'][a],v)
        np.testing.assert_array_equal(record['y'][a],outcome)
        ys.append(outcome)
    effect = np.mean(ys[1]-ys[0])
    radius = np.sqrt(2*np.log(8/plan['confirmation_alpha'])/n)
    np.testing.assert_allclose(record['simultaneous_interval'],[effect-radius,effect+radius],atol=1e-13)
    assert record['effect']==effect and record['confirmed']==(effect-radius>plan['practical_effect'])


def verify_population(oracle,scenario,h):
    joint = []
    for w,u,a,e,z1,z2,y in itertools.product((0,1),repeat=7):
        z = (z1,z2)
        mass = pool(w,u,e,scenario)[2*z1+z2]/16
        mean = probability(w,u,a,e,z,h,scenario)
        joint.append(((e,a,w,z1,z2,y),mass*(mean if y else 1-mean)))
    valid = []
    for mask in range(4):
        tables = {}
        for row,mass in joint:
            if mass==0:
                continue
            e,a,w,z1,z2,y = row
            key = (a,w,*[z for bit,z in enumerate((z1,z2)) if mask>>bit&1])
            tables.setdefault(key,np.zeros((2,2)))[e,y] += mass
        supported = all(np.all(table.sum(0)>0) and np.all(table.sum(1)>0) for table in tables.values())
        independent = all(np.max(np.abs(table-np.outer(table.sum(1),table.sum(0))/table.sum()))<1e-12 for table in tables.values())
        if supported and independent:
            valid.append(mask)
    assert oracle['true_masks']==valid
    corrected,uncorrected = 0.,0.
    for w,u,arm in itertools.product((0,1),repeat=3):
        model = [.9,.1,.8,.2] if arm else [.1,.9,.2,.8]
        target_q = pool(w,u,0,scenario)
        integral = sum(q*m for q,m in zip(target_q,model,strict=True))
        truth = sum(target_q[v]*probability(w,u,arm,0,z,h,scenario)
                    for v,z in enumerate(itertools.product((0,1),repeat=2)))
        expectation = 0.
        for e,a in itertools.product((0,1),repeat=2):
            for v,z in enumerate(itertools.product((0,1),repeat=2)):
                mean = probability(w,u,a,e,z,h,scenario)
                score = integral+(4*(mean-model[v]) if e==0 and a==arm else 0)
                expectation += .25*pool(w,u,e,scenario)[v]*score
        corrected = max(corrected,abs(expectation-truth))
        uncorrected = max(uncorrected,abs(integral-truth))
    np.testing.assert_allclose(oracle['exact_correction']['maximum_corrected_bias'],corrected,atol=1e-13)
    np.testing.assert_allclose(oracle['exact_correction']['maximum_uncorrected_bias'],uncorrected,atol=1e-13)


def verify_sharing(row,plan):
    data = row['data']['discovery']
    for mask,query in enumerate(row['sharing_queries']):
        expected = []
        for key in itertools.product((0,1),repeat=2+mask.bit_count()):
            counts = [0,0]
            for a,w,z,e in zip(data['a'],data['w'],data['z'],data['e'],strict=True):
                if (a,w,*[z[bit] for bit in (0,1) if mask>>bit&1])==key:
                    counts[e] += 1
            fraction = counts[1]/sum(counts) if sum(counts) else None
            valid = fraction is not None and min(counts)>=plan['minimum_per_environment'] and plan['overlap_epsilon']<=fraction<=1-plan['overlap_epsilon']
            expected.append(dict(cell=list(key),counts=counts,auxiliary_fraction=fraction,supported=valid))
        assert query['overlap']['cells']==expected
        assert query['overlap']['supported']==all(cell['supported'] for cell in expected)
        assert query['candidate']==(query['overlap']['supported'] and query['p'] is not None and query['p']>plan['ci_alpha'])
        matches = [ci for ci in row['ci_queries'] if ci['x']=='E' and ci['y']=='Y' and ci['conditioned']==query['conditioned']]
        assert len(matches)==1 and matches[0]['p']==query['p']
    assert row['proposals']['direct_invariance']==[q['mask'] for q in row['sharing_queries'] if q['candidate']]
    for name,graph in row['graphs'].items():
        expected = []
        if graph['status']=='evaluated' and graph['pag'][0][-1]==0:
            for separating in graph['separating_sets']:
                assert set(separating)<=set(('A','W','Z1','Z2'))
                mask = int('Z1' in separating)+2*int('Z2' in separating)
                if row['sharing_queries'][mask]['candidate']:
                    expected.append(mask)
        assert row['proposals'][name]==sorted(set(expected))


def verify_validation(output):
    verify_bundle(output/'inputs')
    plan = read_json(output/'inputs'/'plan.json')
    identity = read_json(output/'inputs'/'identity.json')
    assert file_sha256(output/'source.zip')==identity['source_archive_sha256']
    with zipfile.ZipFile(output/'source.zip') as archive:
        assert set(archive.namelist())==set(identity['sources'])
        for path,digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest()==digest
    verify_bundle(output/'oracle')
    oracle = read_json(output/'oracle'/'result.json')
    for scenario in plan['scenarios']:
        for h in range(4):
            verify_population(oracle[scenario][h],scenario,h)
    cells,query_count = [],0
    for path in sorted((output/'cells').iterdir()):
        verify_bundle(path)
        cell = read_json(path/'result.json')
        scenario,repetition = cell['scenario'],cell['repetition']
        truths = []
        for row in cell['hypotheses']:
            h = row['hypothesis']
            all_ids = []
            for role,data in row['data'].items():
                verify_draw(data,plan,scenario,repetition,h,role)
                all_ids.extend(data['task_ids'])
            assert len(set(all_ids))==len(all_ids)
            verify_ci(row['ci_queries'],row['data']['discovery'],plan,[plan['seed'],scenario,repetition,h])
            query_count += len(row['ci_queries'])
            verify_sharing(row,plan)
            learned = row['learned']
            for model in learned['models']:
                verify_model(model,row['data']['discovery'])
            calibration = row['data']['calibration_selection']
            losses = [np.mean([(y-p)**2 for y,p,e in zip(calibration['y'],predictions(model,calibration),calibration['e'],strict=True) if e==0])
                      for model in learned['models']]
            np.testing.assert_allclose(learned['target_prediction_losses'],losses,atol=1e-13)
            for name,options in learned['groups'].items():
                index = min(options,key=lambda i:(losses[i],i))
                assert learned['choices'][name]==index
                verify_scores(learned['estimates'][name],learned['models'][index],row['data']['calibration_ranking'])
            for role,data in row['all_target_data'].items():
                verify_draw(data,plan,scenario,repetition,h,'all_target_'+role,True)
            target = row['all_target_data']
            combined = {key:target['discovery'][key]+target['calibration_selection'][key]
                        for key in target['discovery'] if key!='propensity'}
            verify_model(row['all_target_model'],combined)
            verify_scores(learned['estimates']['all_budget_target'],row['all_target_model'],target['calibration_ranking'])
            truth = np.mean([sum(pool(w,u,0,scenario)[v]*(probability(w,u,1,0,z,h,scenario)-probability(w,u,0,0,z,h,scenario))
                for v,z in enumerate(itertools.product((0,1),repeat=2))) for w,u in itertools.product((0,1),repeat=2)])
            np.testing.assert_allclose(oracle[scenario][h]['target_effect'],truth,atol=1e-13)
            assert oracle[scenario][h]['exact_correction']['maximum_corrected_bias']<1e-12
            truths.append(truth)
            verify_confirmation(cell['confirmation'][h],plan,scenario,repetition,h)
        for name,selected in cell['nominations'].items():
            scores = truths if name=='oracle_top_k' else [row['learned']['estimates'][name]['effect'] for row in cell['hypotheses']]
            assert selected==sorted(range(4),key=lambda h:(-scores[h],h))[:2]
            decision = cell['decisions'][name]
            assert decision['selected']==selected
            assert decision['confirmed_count']==sum(cell['confirmation'][h]['confirmed'] for h in selected)
            assert decision['true_positive_count']==sum(truths[h]>plan['practical_effect'] for h in selected)
            assert decision['harmful_count']==sum(truths[h]<0 for h in selected)
        cells.append(cell)
    assert len(cells)==len(plan['scenarios'])*plan['repetitions']
    verify_bundle(output/'summary')
    summary = read_json(output/'summary'/'result.json')
    for result in summary['rows']:
        selected = [cell for cell in cells if cell['scenario']==result['scenario']]
        for name,values in result['methods'].items():
            assert values['mean_confirmed_count']==np.mean([cell['decisions'][name]['confirmed_count'] for cell in selected])
        for comparison in result['comparisons']:
            differences = [cell['decisions']['jci']['confirmed_count']-cell['decisions'][comparison['baseline']]['confirmed_count'] for cell in selected]
            margin = t.ppf(1-.05/(2*len(plan['scenarios'])*3),len(selected)-1)*np.std(differences,ddof=1)/np.sqrt(len(selected))
            np.testing.assert_allclose(comparison['simultaneous_monte_carlo_interval'],[np.mean(differences)-margin,np.mean(differences)+margin],atol=1e-13)
    result = dict(status='VERIFIED',evidence_role=plan['evidence_role'],cells=len(cells),ci_queries=query_count,
        execution_source_sha256=identity['source_archive_sha256'],verifier_sha256=file_sha256(Path(__file__)),new_model_calls=0)
    if (output/'verification').exists():
        verify_bundle(output/'verification')
        previous = read_json(output/'verification'/'result.json')
        assert {key:value for key,value in previous.items() if key!='verifier_sha256'}=={
            key:value for key,value in result.items() if key!='verifier_sha256'}
    else:
        write_bundle(output/'verification',{'result.json':result})
    return result


def verify_power(output):
    verify_bundle(output/'inputs')
    verify_bundle(output/'summary')
    plan = read_json(output/'inputs'/'parent_plan.json')
    design = read_json(output/'inputs'/'design.json')
    summary = read_json(output/'summary'/'result.json')
    assert design['size_grid']==[2**power for power in range(10,21)]
    assert summary['evidence_role']=='POST_HOC_CONFIRMATION_POWER_DIAGNOSTIC'
    checked = 0
    for row in summary['rows']:
        h,scenario = row['hypothesis'],row['scenario']
        probabilities = np.zeros(3)
        for w,u in itertools.product((0,1),repeat=2):
            means = [sum(pool(w,u,0,scenario)[v]*probability(w,u,a,0,z,h,scenario)
                for v,z in enumerate(itertools.product((0,1),repeat=2))) for a in (0,1)]
            probabilities += .25*np.array([means[0]*(1-means[1]),
                means[0]*means[1]+(1-means[0])*(1-means[1]),means[1]*(1-means[0])])
        np.testing.assert_allclose([row['difference_distribution'][key] for key in ('minus','zero','plus')],probabilities,atol=1e-13)
        for check in row['checks']:
            n = check['task_units']
            minus = np.arange(n+1)
            margin = plan['practical_effect']+np.sqrt(2*np.log(8/plan['confirmation_alpha'])/n)
            cutoff = np.floor(minus+n*margin).astype(int)
            # 按负向任务数量条件化，独立重算三项分布尾部。
            value = np.sum(binom.pmf(minus,n,probabilities[0])*
                binom.sf(cutoff,n-minus,probabilities[2]/(1-probabilities[0])))
            np.testing.assert_allclose(check['power'],value,atol=1e-10,rtol=1e-9)
            checked += 1
        eligible = [check['task_units'] for check in row['checks'] if check['power']>=design['desired_power']]
        assert row['selected_grid_task_units']==(eligible[0] if eligible else None)
    result = dict(status='VERIFIED',rows=len(summary['rows']),power_calculations=checked,
        evidence_role=summary['evidence_role'],verifier_sha256=file_sha256(Path(__file__)),new_model_calls=0)
    if (output/'verification').exists():
        verify_bundle(output/'verification')
        previous = read_json(output/'verification'/'result.json')
        assert {key:value for key,value in previous.items() if key!='verifier_sha256'}=={
            key:value for key,value in result.items() if key!='verifier_sha256'}
    else:
        write_bundle(output/'verification',{'result.json':result})
    return result

from __future__ import annotations

from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import itertools
import multiprocessing
import platform
import zipfile

import numpy as np
import networkx as nx
import scipy
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery import context_sharing as method
from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation, StructureBackend
from prompt_mechanism_study.discovery.policy_value import random_stream


def _prognostic_cell(arguments):
    from prompt_mechanism_study.discovery import prognostic_learning as learning
    scenario,n,batch,repetition,plan,output,rscript = arguments
    seed = plan['batch_seeds'][batch]
    backend = StructureBackend(rscript,output/'backend'/f'{scenario}-{n}-{batch}-{repetition}.log',Path('src/discovery/jci_context.R'))
    records,confirmation = [],[]
    for h in range(4):
        coordinates = (scenario,n,repetition,h)
        data = {role:learning.draw(random_stream(seed,*coordinates,role),size,environment,h,scenario,
            f'{seed}/{scenario}/{n}/{repetition}/{h}/{role}') for role,size,environment in (
            ('source',plan['source_task_units'],0),('fit',n,1),('calibration',n,1),('ranking',2*n,1))}
        graphs,queries = [],[]
        source = np.asarray(data['source']['observations'])
        labels = learning.labels(scenario)
        for arm in (0,1):
            observed = source[source[:,2]==arm][:,[learning.context.LABELS.index(name) for name in labels]]
            ci = ConditionalPermutation(observed,labels,plan['ci_draws'],[seed,*coordinates,'graph',arm],minimum_per_level=2)
            graph = backend.search(labels,'directional',ci,plan['ci_alpha'])
            graph.update(labels=labels,arm=arm,task_units=len(observed))
            graphs.append(graph)
            queries.append(list(ci.cache.values()))
        suggestion_seed = int(random_stream(seed,*coordinates,'suggestions').integers(2**63))
        learned = learning.learn(data,graphs,scenario,plan,suggestion_seed)
        records.append(dict(data=data,graphs=graphs,ci_queries=queries,suggestion_seed=suggestion_seed,
            learned=learned,risks=learning.risks(learned,h,scenario,2*n)))
        rng = random_stream(seed,*coordinates,'confirmation')
        count = plan['confirmation_task_units']
        base = learning.draw(rng,count,1,h,scenario,f'{seed}/{scenario}/{n}/{repetition}/{h}/confirmation')
        observed = np.asarray(base['observations'])
        outcomes = np.empty((2,count),dtype=int)
        outcomes[observed[:,2],np.arange(count)] = observed[:,-1]
        for arm in (0,1):
            missing = observed[:,2]!=arm
            states = np.insert(observed[missing,:-1],4,np.asarray(base['u'])[missing],axis=1)
            states[:,2] = arm
            outcomes[arm,missing] = rng.binomial(1,learning.probabilities(states,1,h,scenario)[2])
        effect = float(np.mean(outcomes[1]-outcomes[0]))
        radius = float(np.sqrt(2*np.log(8/plan['confirmation_alpha'])/count))
        direction = int(effect-radius>plan['practical_effect'])-int(effect+radius<-plan['practical_effect'])
        confirmation.append(dict(data=base,y=outcomes.tolist(),effect=effect,radius=radius,direction=direction))
    backend.close()
    nominations = {name:sorted(range(4),key=lambda h:(-abs(records[h]['learned']['estimates'][name]['effect']),h))[:2] for name in learning.METHODS}
    decisions = {name:dict(confirmed=sum(confirmation[h]['direction']!=0 for h in chosen),
        positive=sum(confirmation[h]['direction']==1 for h in chosen),negative=sum(confirmation[h]['direction']==-1 for h in chosen)) for name,chosen in nominations.items()}
    cell = dict(scenario=scenario,target_size=n,batch=batch,repetition=repetition,hypotheses=records,
        confirmation=confirmation,nominations=nominations,decisions=decisions)
    write_bundle(output/'cells'/f'{scenario}-{n}-{batch}-{repetition}',{'result.json':cell})
    return dict(scenario=scenario,target_size=n,batch=batch,repetition=repetition,decisions=decisions,
        variances={name:float(np.mean([r['risks']['groups'][name]['selected'] for r in records])) for name in learning.METHODS})


def run_prognostic_validation(plan_path,output,rscript,workers=1):
    from prompt_mechanism_study.discovery import prognostic_learning as learning
    plan = read_json(plan_path)
    if (plan['evidence_role']!='NON_CLAIM_PROGNOSTIC_STRUCTURE_LEARNING' or plan['formal_claim_allowed']
            or plan.get('target_correction_penalty_rule')!='independent_of_source_support'
            or plan['new_provider_calls']!=0 or not set(plan['scenarios'])<=set(learning.SCENARIOS)
            or len(set(plan['batch_seeds']))!=2 or plan['primary_comparators']!=['direct','direct_invariance']
            or workers<1 or any(n<8 for n in plan['target_sizes']) or plan['repetitions_per_batch']<1
            or plan['source_task_units']<32 or min(plan['ridge_penalties']+plan['deviation_penalties'])<=0
            or plan['structure_strengths'][0]!=0 or min(plan['structure_strengths'])<0):
        raise ValueError('平均结果学习设计无效')
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/discovery/prognostic_learning.py','src/discovery/directional_transfer.py',
        'src/discovery/context_sharing.py','src/discovery/policy_value.py','src/discovery/jci_structure.py','src/discovery/jci_context.R',
        'src/experiment/context_validation.py','src/verification/prognostic_learning.py','src/verification/directional_transfer.py',
        'src/artifact_io.py','src/records.py','src/cli.py','src/__main__.py','pyproject.toml')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    write_bundle(output/'inputs',{'plan.json':plan,'identity.json':dict(workers=workers,python=platform.python_version(),
        numpy=np.__version__,scipy=scipy.__version__,source_archive_sha256=file_sha256(output/'source.zip'),
        sources={path.as_posix():file_sha256(path) for path in paths})})
    (output/'backend').mkdir()
    tasks = [(s,n,b,r,plan,output,rscript) for s,n,b,r in itertools.product(plan['scenarios'],plan['target_sizes'],range(2),range(plan['repetitions_per_batch']))]
    if workers==1:
        cells = [_prognostic_cell(task) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
            cells = list(pool.map(_prognostic_cell,tasks))
    family = len(plan['scenarios'])*len(plan['target_sizes'])*len(plan['primary_comparators'])
    rows = []
    for scenario,n in itertools.product(plan['scenarios'],plan['target_sizes']):
        group = [c for c in cells if (c['scenario'],c['target_size'])==(scenario,n)]
        comparisons = []
        for name in plan['primary_comparators']:
            differences = np.asarray([c['variances'][name]-c['variances']['jci'] for c in group])
            radius = float(t.ppf(1-plan['component_alpha']/(2*family),len(group)-1)*differences.std(ddof=1)/np.sqrt(len(group)))
            relative = float(differences.mean()/np.mean([c['variances'][name] for c in group]))
            batches = [float(differences[[c['batch']==b for c in group]].mean()) for b in (0,1)]
            comparisons.append(dict(baseline=name,relative_reduction=relative,interval=[float(differences.mean()-radius),float(differences.mean()+radius)],
                batch_reductions=batches,supported=bool(relative>=plan['minimum_relative_variance_reduction'] and differences.mean()>radius and min(batches)>0)))
        rows.append(dict(scenario=scenario,target_size=n,comparisons=comparisons,
            methods={name:dict(variance=float(np.mean([c['variances'][name] for c in group])),
                confirmed=sum(c['decisions'][name]['confirmed'] for c in group),positive=sum(c['decisions'][name]['positive'] for c in group),
                negative=sum(c['decisions'][name]['negative'] for c in group)) for name in learning.METHODS}))
    result = dict(evidence_role=plan['evidence_role'],cells=len(cells),rows=rows,new_model_calls=0,
        graph_component_status='BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS')
    write_bundle(output/'summary',{'result.json':result})
    return result


def validate_plan(plan):
    if (plan['evidence_role']!='NON_CLAIM_CONTEXT_MECHANISM_SIMULATION'
            or plan['formal_claim_allowed'] is not False or plan['scenarios']!=method.SCENARIOS):
        raise ValueError('必须保留预定机制与模拟证据身份')
    if (plan['hypotheses'],plan['nomination_count'])!=(4,2):
        raise ValueError('必须比较四项完整假设并提名两项')
    for name in ('repetitions','discovery_task_units','calibration_selection_task_units',
                 'calibration_ranking_task_units','confirmation_task_units_per_hypothesis'):
        if type(plan[name]) is not int or plan[name]<2:
            raise ValueError('任务数量或独立重复数量无效')
    if plan['ci_draws']<99 or plan['minimum_per_environment']<2 or not 0<plan['overlap_epsilon']<.5:
        raise ValueError('条件检验与重叠规则无效')


def confirmation(rng, hypothesis, scenario, plan):
    n = plan['confirmation_task_units_per_hypothesis']
    w,u = rng.integers(0,2,size=(2,n))
    q = method.version_probabilities(w,u,np.zeros(n,dtype=int),scenario)
    outcomes,versions = [],[]
    for arm in (0,1):
        v = np.asarray([rng.choice(4,p=row) for row in q])
        p = method.response_probability(w,u,arm,0,method.VERSIONS[v],hypothesis,scenario)
        outcomes.append(rng.binomial(1,p))
        versions.append(v.tolist())
    differences = outcomes[1]-outcomes[0]
    # 全部四项假设的同时 Hoeffding 界覆盖任何独立选择的候选集合。
    radius = np.sqrt(2*np.log(2*plan['hypotheses']/plan['confirmation_alpha'])/n)
    interval = [float(differences.mean()-radius),float(differences.mean()+radius)]
    return dict(w=w.tolist(),u=u.tolist(),versions=versions,y=[row.tolist() for row in outcomes],
        effect=float(differences.mean()),simultaneous_interval=interval,
        confirmed=interval[0]>plan['practical_effect'])


def oracle_information(scenario,hypothesis,plan,backend):
    observations,weights = method.exact_population(hypothesis,scenario)
    truth = method.PopulationIndependence(observations,weights)
    true_masks = [mask for mask in range(4) if truth.query('E','Y',method.conditioning(mask))==1.]
    graph_ci = method.GraphIndependence(observations,weights,scenario)
    graphs = {}
    for name,ci in (('true_graph',graph_ci),('population_ci',truth)):
        graph = backend.search(method.LABELS,'jci',ci,plan['ci_alpha'])
        masks = []
        if graph['status']=='evaluated' and graph['pag'][0][-1]==0:
            for separating in graph['separating_sets']:
                mask = sum(1<<bit for bit in range(2) if f'Z{bit+1}' in separating)
                if truth.query('E','Y',method.conditioning(mask))==1.:
                    masks.append(mask)
        graphs[name] = dict(graph=graph,masks=sorted(set(masks)),queries=list(ci.cache.values()))
    return dict(true_masks=true_masks,graphs=graphs,
        exact_correction=method.exact_correction_check(hypothesis,scenario),
        target_effect=method.true_target_effect(hypothesis,scenario))


def execute_cell(scenario,repetition,plan,oracles,backend):
    hypotheses = []
    for h in range(4):
        streams = lambda role:random_stream(plan['seed'],scenario,repetition,h,role)
        data = {name:method.draw_tasks(streams(name),plan[key],h,scenario,name) for name,key in (
            ('discovery','discovery_task_units'),('calibration_selection','calibration_selection_task_units'),
            ('calibration_ranking','calibration_ranking_task_units'))}
        all_ids = [key for part in data.values() for key in part['task_ids']]
        if len(set(all_ids))!=len(all_ids):
            raise ValueError('任务谱系跨越数据角色')
        ci = ConditionalPermutation(method.observation_matrix(data['discovery']),method.LABELS,
            plan['ci_draws'],[plan['seed'],scenario,repetition,h],minimum_per_level=2)
        graphs = {name:backend.search(method.LABELS,name,ci,plan['ci_alpha'])
                  for name in ('jci','fci_same_knowledge')}
        queries = method.sharing_queries(ci,data['discovery'],plan)
        oracle = oracles[h]
        proposals = {'direct_invariance':[row['mask'] for row in queries if row['candidate']],
            **{name:method.graph_proposals(graph,queries) for name,graph in graphs.items()},
            'oracle_sharing':oracle['true_masks'],
            **{name:row['masks'] for name,row in oracle['graphs'].items()}}
        learned = method.select_models(data['discovery'],data['calibration_selection'],data['calibration_ranking'],proposals)
        # 相同代码生成预算全部用于目标环境，保留同一完整属性和预测修正。
        all_target = {name:method.draw_tasks(streams('all_target_'+name),plan[key],h,scenario,
            'all_target_'+name,target_only=True) for name,key in (
                ('discovery','discovery_task_units'),('calibration_selection','calibration_selection_task_units'),
                ('calibration_ranking','calibration_ranking_task_units'))}
        combined_target = {key:all_target['discovery'][key]+all_target['calibration_selection'][key]
                           for key in all_target['discovery'] if key!='propensity'}
        combined_target['propensity'] = .5
        target_model = method.fit_cells(combined_target,None,True)
        target_estimate = method.corrected_scores(all_target['calibration_ranking'],target_model)
        learned['estimates']['all_budget_target'] = target_estimate
        hypotheses.append(dict(hypothesis=h,data=data,graphs=graphs,sharing_queries=queries,
            ci_queries=list(ci.cache.values()),proposals=proposals,learned=learned,
            all_target_data=all_target,all_target_model=target_model))
    methods = list(hypotheses[0]['learned']['estimates'])
    nominations = {}
    for name in methods:
        ordering = sorted(range(4),key=lambda h:(-hypotheses[h]['learned']['estimates'][name]['effect'],h))
        nominations[name] = ordering[:plan['nomination_count']]
    # 固定所有方法的选择以后，才产生独立确认结果。
    confirmed = [confirmation(random_stream(plan['seed'],scenario,repetition,h,'confirmation'),h,scenario,plan)
                 for h in range(4)]
    truth = [row['target_effect'] for row in oracles]
    nominations['oracle_top_k'] = sorted(range(4),key=lambda h:(-truth[h],h))[:plan['nomination_count']]
    decisions = {name:dict(selected=selected,
        confirmed_count=sum(confirmed[h]['confirmed'] for h in selected),
        true_positive_count=sum(truth[h]>plan['practical_effect'] for h in selected),
        harmful_count=sum(truth[h]<0 for h in selected)) for name,selected in nominations.items()}
    return dict(scenario=scenario,repetition=repetition,hypotheses=hypotheses,
        nominations=nominations,confirmation=confirmed,decisions=decisions)


def summarize(cells,plan):
    rows = []
    family_size = len(plan['scenarios'])*3
    quantile = t.ppf(1-.05/(2*family_size),plan['repetitions']-1)
    for scenario in plan['scenarios']:
        group = [cell for cell in cells if cell['scenario']==scenario]
        results = {}
        for name in group[0]['decisions']:
            gains = [cell['decisions'][name]['confirmed_count'] for cell in group]
            errors = [cell['hypotheses'][h]['learned']['estimates'][name]['effect']-
                      method.true_target_effect(h,scenario) for cell in group for h in range(4)] if name!='oracle_top_k' else []
            results[name] = dict(mean_confirmed_count=float(np.mean(gains)),
                mean_true_positive_count=float(np.mean([cell['decisions'][name]['true_positive_count'] for cell in group])),
                effect_root_mean_square_error=float(np.sqrt(np.mean(np.square(errors)))) if errors else None)
        comparisons = []
        for baseline in ('target_only','direct_invariance','all_budget_target'):
            differences = np.asarray([cell['decisions']['jci']['confirmed_count']-
                                      cell['decisions'][baseline]['confirmed_count'] for cell in group])
            se = differences.std(ddof=1)/np.sqrt(len(group))
            interval = [float(differences.mean()-quantile*se),float(differences.mean()+quantile*se)]
            comparisons.append(dict(baseline=baseline,mean_difference=float(differences.mean()),
                simultaneous_monte_carlo_interval=interval))
        jci_equal = all(cell['nominations']['jci']==cell['nominations']['fci_same_knowledge'] for cell in group)
        rows.append(dict(scenario=scenario,repetitions=len(group),methods=results,comparisons=comparisons,
            jci_fci_same_nominations=jci_equal,
            unsupported_sharing_queries=sum(not query['overlap']['supported'] for cell in group for h in cell['hypotheses'] for query in h['sharing_queries']),
            false_sharing_proposals=sum(mask not in [m for m in range(4) if
                method.PopulationIndependence(*method.exact_population(h['hypothesis'],scenario)).query('E','Y',method.conditioning(m))==1.]
                for cell in group for h in cell['hypotheses'] for mask in h['proposals']['jci'])))
    return dict(evidence_role=plan['evidence_role'],new_model_calls=0,rows=rows,
        per_method_discovery_calibration_calls=4*sum(plan[key] for key in (
            'discovery_task_units','calibration_selection_task_units','calibration_ranking_task_units')),
        per_method_confirmation_calls=2*plan['nomination_count']*plan['confirmation_task_units_per_hypothesis'],
        preparation_and_audit_costs_measured=False,
        complete_functionality_evidence=False,representation_advantage_evidence=False)


def run_validation(plan_path,output,rscript):
    plan = read_json(plan_path)
    validate_plan(plan)
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/discovery/context_sharing.py','src/discovery/jci_context.R',
        'src/discovery/jci_structure.py','src/discovery/policy_value.py','src/experiment/context_validation.py',
        'src/artifact_io.py','src/records.py','src/cli.py')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    identity = dict(python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__,
        source_archive_sha256=file_sha256(output/'source.zip'),sources={path.as_posix():file_sha256(path) for path in paths})
    write_bundle(output/'inputs',{'plan.json':plan,'identity.json':identity})
    backend = StructureBackend(rscript,output/'backend.log',Path('src/discovery/jci_context.R'))
    oracles = {scenario:[oracle_information(scenario,h,plan,backend) for h in range(4)] for scenario in plan['scenarios']}
    write_bundle(output/'oracle',{'result.json':oracles})
    cells = []
    for scenario in plan['scenarios']:
        for repetition in range(plan['repetitions']):
            cell = execute_cell(scenario,repetition,plan,oracles[scenario],backend)
            write_bundle(output/'cells'/f'{scenario}-{repetition:03d}',{'result.json':cell})
            cells.append(cell)
    backend.close()
    result = summarize(cells,plan)
    write_bundle(output/'summary',{'result.json':result})
    return result


def diagnose_power(parent,output):
    verify_bundle(parent/'inputs')
    plan = read_json(parent/'inputs'/'plan.json')
    design = dict(evidence_role='POST_HOC_CONFIRMATION_POWER_DIAGNOSTIC',
        parent_plan_sha256=file_sha256(parent/'inputs'/'plan.json'),desired_power=.8,
        size_grid=[2**power for power in range(10,21)],
        rule='first size on the fixed grid with exact power >= 0.8; no finite bound claimed below practical threshold',
        sources={name:file_sha256(Path(name)) for name in ('src/discovery/context_sharing.py','src/experiment/context_validation.py')})
    write_bundle(output/'inputs',{'design.json':design,'parent_plan.json':plan})
    rows,cache = [],{}
    for scenario in plan['scenarios']:
        for h in range(4):
            distribution = method.paired_difference_probabilities(h,scenario)
            truth = distribution['plus']-distribution['minus']
            checks = []
            sizes = design['size_grid'] if truth>plan['practical_effect'] else [plan['confirmation_task_units_per_hypothesis']]
            for size in sizes:
                key = (tuple(distribution.values()),size)
                if key not in cache:
                    cache[key] = method.confirmation_power(distribution,size,plan)
                checks.append(dict(task_units=size,power=cache[key]))
                if checks[-1]['power']>=design['desired_power']:
                    break
            qualifying = [row['task_units'] for row in checks if row['power']>=design['desired_power']]
            rows.append(dict(scenario=scenario,hypothesis=h,target_effect=truth,
                difference_distribution=distribution,checks=checks,
                selected_grid_task_units=qualifying[0] if qualifying else None))
    result = dict(evidence_role=design['evidence_role'],rows=rows,new_model_calls=0)
    write_bundle(output/'summary',{'result.json':result})
    return result


def _directional_cell(arguments):
    from prompt_mechanism_study.discovery import directional_transfer as directional
    scenario,batch,repetition,plan,oracle,output,rscript = arguments
    backend = StructureBackend(rscript,output/'backend'/f'{scenario}-{batch}-{repetition:03d}.log',Path('src/discovery/jci_context.R'))
    hypotheses = []
    seed = plan['batch_seeds'][batch]
    for h in range(4):
        coordinates = (scenario,repetition,h)
        data = {role:directional.draw(random_stream(seed,*coordinates,role),plan[size],environment,
            h,scenario,f'{seed}/{scenario}/{repetition}/{h}/{role}') for role,size,environment in (
            ('source_discovery','source_discovery_task_units',0),('target_fitting','target_fitting_task_units',1),
            ('target_calibration','target_calibration_task_units',1),('target_ranking','target_ranking_task_units',1))}
        graphs,queries = [],[]
        source_rows = np.asarray(data['source_discovery']['observations'])
        labels = directional.graph_labels(scenario)
        for arm in (0,1):
            selected = source_rows[:,2]==arm
            rows = source_rows[selected][:,[directional.LABELS.index(name) for name in labels]]
            if len(rows):
                ci = ConditionalPermutation(rows,labels,plan['ci_draws'],[seed,*coordinates,'graph',arm],minimum_per_level=2)
                graph = backend.search(labels,'directional',ci,plan['ci_alpha'])
                records = list(ci.cache.values())
            else:
                graph,records = dict(status='insufficient_support',pag=None,conservative=True),[]
            graph.update(arm=arm,labels=labels,task_units=int(selected.sum()))
            graphs.append(graph)
            queries.append(dict(arm=arm,queries=records))
        learned = directional.learn(data['source_discovery'],data['target_fitting'],data['target_calibration'],
            data['target_ranking'],graphs,oracle[h]['graph'],scenario,plan,[seed,*coordinates,'invariance'])
        selected_models = {name:learned['models'][index] for name,index in learned['choices'].items()}
        risks = {name:directional.exact_risk(model,h,scenario,plan['target_ranking_task_units']) for name,model in selected_models.items()}
        truth = next(iter(risks.values()))['exact_effect']
        if any(abs(row['exact_effect']-truth)>1e-12 for row in risks.values()):
            raise ValueError('随机分配修正没有恢复固定目标效果')
        catalog = directional.catalog_risks(learned['models'],h,scenario,plan['target_ranking_task_units'])
        information = directional.query_information(learned,catalog,directional.observable_optimal_variance(h,scenario,plan['target_ranking_task_units']))
        hypotheses.append(dict(hypothesis=h,data=data,graph=graphs,ci_queries=queries,learned=learned,
            exact_risks=risks,catalog_risks=catalog,information=information))
    backend.close()
    nominations = {name:sorted(range(4),key=lambda h:(-abs(hypotheses[h]['learned']['estimates'][name]['effect']),h))[:2]
        for name in hypotheses[0]['learned']['estimates']}
    truths = [row['exact_risks']['directional']['exact_effect'] for row in hypotheses]
    nominations['oracle_top_k'] = sorted(range(4),key=lambda h:(-abs(truths[h]),h))[:2]
    confirmations = []
    for h in range(4):
        rng = random_stream(plan['batch_seeds'][batch],scenario,repetition,h,'confirmation')
        n = plan['confirmation_task_units_per_hypothesis']
        base = directional.draw(rng,n,1,h,scenario,f'{seed}/{scenario}/{repetition}/{h}/confirmation')
        observed = np.asarray(base['observations'])
        outcomes = np.empty((2,n),dtype=int)
        outcomes[observed[:,2],np.arange(n)] = observed[:,-1]
        for a in (0,1):
            missing = observed[:,2]!=a
            rows = observed[missing,:-1].copy()
            rows[:,2] = a
            _,_,p = directional.probabilities(np.insert(rows,4,np.asarray(base['u'])[missing],axis=1),1,h,scenario)
            outcomes[a,missing] = rng.binomial(1,p)
        effect = float(np.mean(outcomes[1]-outcomes[0]))
        margin = np.sqrt(2*np.log(2*plan['hypotheses']/plan['confirmation_alpha'])/n)
        direction = int(effect-margin>plan['practical_effect'])-int(effect+margin<-plan['practical_effect'])
        confirmations.append(dict(data=base,y=outcomes.tolist(),effect=effect,
            interval=[float(effect-margin),float(effect+margin)],confirmed=bool(direction),confirmed_direction=direction))
    decisions = {name:dict(selected=selected,
        true_effect_count=sum(abs(truths[h])>plan['practical_effect'] for h in selected),
        true_positive_count=sum(truths[h]>plan['practical_effect'] for h in selected),
        true_negative_count=sum(truths[h]<-plan['practical_effect'] for h in selected),
        confirmed_count=sum(confirmations[h]['confirmed'] for h in selected),
        confirmed_positive_count=sum(confirmations[h]['confirmed_direction']==1 for h in selected),
        confirmed_negative_count=sum(confirmations[h]['confirmed_direction']==-1 for h in selected),
        false_confirmed_count=sum(confirmations[h]['confirmed'] and confirmations[h]['confirmed_direction']*truths[h]<=plan['practical_effect'] for h in selected))
        for name,selected in nominations.items()}
    cell = dict(scenario=scenario,batch=batch,repetition=repetition,hypotheses=hypotheses,
        nominations=nominations,confirmation=confirmations,decisions=decisions)
    write_bundle(output/'cells'/f'{scenario}-{batch}-{repetition:03d}',{'result.json':cell})
    return dict(scenario=scenario,batch=batch,repetition=repetition,decisions=decisions,
        hypotheses=[dict(exact_risks=row['exact_risks'],graph=row['graph'],
            learned=dict(choices=row['learned']['choices'],estimates={name:dict(effect=value['effect']) for name,value in row['learned']['estimates'].items()})) for row in hypotheses])


def run_directional_validation(plan_path,output,rscript,workers=1):
    from prompt_mechanism_study.discovery import directional_transfer as directional
    plan = read_json(plan_path)
    if type(workers) is not int or workers<1:
        raise ValueError('并行进程数量必须为正整数')
    if (plan['evidence_role']!='NON_CLAIM_SOURCE_CONTEXT_QUERY_SIMULATION'
            or plan['formal_claim_allowed'] is not False or not plan['scenarios']
            or len(set(plan['scenarios']))!=len(plan['scenarios']) or not set(plan['scenarios'])<=set(directional.SCENARIOS)
            or (plan['hypotheses'],plan['nomination_count'])!=(4,2) or len(set(plan['batch_seeds']))!=2
            or plan['calibration_objective']!='averaged_arm_prediction_squared_error'
            or plan['target_correction']!='all_measured_pre_assignment_attributes'
            or plan['nomination_rule']!='absolute_effect' or plan['confirmation_directions']!='both'
            or plan['structure_query']!='arm_stratified_source_context_separation'
            or plan['effect_estimator']!='target_randomization_only'
            or plan['confirmation_power_role']!='diagnostic_only'
            or plan['primary_comparators']!=['direct_search']
            or plan['target_fitting_task_units']!=plan['target_calibration_task_units']
            or plan['target_ranking_task_units']!=2*plan['target_fitting_task_units']
            or plan['component_alpha']!=.01 or plan['confirmation_alpha']!=.03
            or plan['graph_component_alpha']!=.01):
        raise ValueError('方向共享验证的身份或预定比较不同')
    for name in ('source_discovery_task_units','target_fitting_task_units','target_calibration_task_units',
            'target_ranking_task_units','repetitions_per_batch','confirmation_task_units_per_hypothesis'):
        if type(plan[name]) is not int or plan[name]<1:
            raise ValueError('任务预算与重复数量必须为正整数')
    if any(value<=0 for value in plan['ridge_penalties']+plan['deviation_penalties']):
        raise ValueError('共享和目标修正惩罚必须保持正值')
    if not 0<plan['minimum_relative_variance_reduction']<1:
        raise ValueError('精度改善阈值必须位于零与一之间')
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/discovery/directional_transfer.py','src/discovery/context_sharing.py','src/discovery/jci_context.R',
        'src/discovery/jci_structure.py','src/discovery/policy_value.py','src/experiment/context_validation.py',
        'src/verification/directional_transfer.py','src/tsg/prepared_prompts.py','src/artifact_io.py','src/records.py','src/cli.py','src/__main__.py','pyproject.toml')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    identity = dict(python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__,workers=workers,
        source_archive_sha256=file_sha256(output/'source.zip'),sources={path.as_posix():file_sha256(path) for path in paths})
    write_bundle(output/'inputs',{'plan.json':plan,'identity.json':identity})
    backend = StructureBackend(rscript,output/'backend.log',Path('src/discovery/jci_context.R'))
    oracles = {}
    for scenario in plan['scenarios']:
        oracles[scenario] = []
        for h in range(4):
            graphs,queries = [],[]
            for arm in (0,1):
                ci = directional.PopulationQueries(h,scenario,arm)
                graph = backend.search(ci.labels,'directional',ci,plan['ci_alpha'])
                graph.update(arm=arm,labels=ci.labels)
                graphs.append(graph)
                queries.append(dict(arm=arm,queries=list(ci.cache.values())))
            observed,u,weights,_ = directional.population(1,h,scenario)
            means = []
            for a in (0,1):
                assigned = observed.copy()
                assigned[:,2] = a
                means.append(directional.probabilities(np.insert(assigned,4,u,axis=1),1,h,scenario)[2])
            distribution = dict(minus=float(weights@(means[0]*(1-means[1]))),
                plus=float(weights@(means[1]*(1-means[0]))))
            powers = directional.confirmation_powers(distribution,plan['confirmation_task_units_per_hypothesis'],plan)
            truth = distribution['plus']-distribution['minus']
            oracles[scenario].append(dict(graph=graphs,queries=queries,
                true_query_diagnostics=directional.oracle_query_diagnostics(scenario),
                confirmation_power=powers,target_effect=truth,difference_distribution=distribution))
    write_bundle(output/'oracle',{'result.json':oracles})
    backend.close()
    (output/'backend').mkdir()
    tasks = [(scenario,batch,repetition,plan,oracles[scenario],output,rscript) for scenario,batch,repetition in
        itertools.product(plan['scenarios'],range(2),range(plan['repetitions_per_batch']))]
    if workers==1:
        cells = [_directional_cell(task) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
            cells = list(pool.map(_directional_cell,tasks))
    rows = []
    for scenario in plan['scenarios']:
        group = [cell for cell in cells if cell['scenario']==scenario]
        summaries = {}
        for name in group[0]['hypotheses'][0]['learned']['estimates']:
            risks = [h['exact_risks'][name] for cell in group for h in cell['hypotheses']]
            errors = [h['learned']['estimates'][name]['effect']-h['exact_risks'][name]['exact_effect'] for cell in group for h in cell['hypotheses']]
            summaries[name] = dict(mean_exact_effect_variance=float(np.mean([row['exact_effect_variance'] for row in risks])),
                mean_target_brier_risk=float(np.mean([row['target_brier_risk'] for row in risks])),
                mean_target_prognostic_risk=float(np.mean([row['target_prognostic_risk'] for row in risks])),
                empirical_effect_root_mean_square_error=float(np.sqrt(np.mean(np.square(errors)))),
                **{f'mean_{field}':float(np.mean([cell['decisions'][name][field] for cell in group]))
                   for field in ('confirmed_count','confirmed_positive_count','confirmed_negative_count',
                       'true_effect_count','true_positive_count','true_negative_count','false_confirmed_count')})
        comparisons = []
        for baseline in plan['primary_comparators']:
            differences = np.asarray([np.mean([h['exact_risks'][baseline]['exact_effect_variance']-
                h['exact_risks']['directional']['exact_effect_variance'] for h in cell['hypotheses']]) for cell in group])
            critical = t.ppf(1-plan['component_alpha']/(2*len(plan['scenarios'])*len(plan['primary_comparators'])),len(group)-1)
            margin = critical*differences.std(ddof=1)/np.sqrt(len(group))
            gains = np.asarray([cell['decisions']['directional']['confirmed_count']-
                cell['decisions'][baseline]['confirmed_count'] for cell in group])
            reference = np.mean([np.mean([h['exact_risks'][baseline]['exact_effect_variance'] for h in cell['hypotheses']]) for cell in group])
            comparisons.append(dict(baseline=baseline,variance_reduction=float(differences.mean()),
                approximate_simultaneous_t_interval=[float(differences.mean()-margin),float(differences.mean()+margin)],
                batch_reductions=[float(differences[[cell['batch']==batch for cell in group]].mean()) for batch in range(2)],
                confirmed_count_gain=float(gains.mean()),
                relative_variance_reduction=float(differences.mean()/reference),
                precision_supported=bool(differences.mean()/reference>=plan['minimum_relative_variance_reduction'] and differences.mean()-margin>0
                    and all(differences[[cell['batch']==batch for cell in group]].mean()>0 for batch in (0,1))),
                confirmed_count_batch_gains=[float(gains[[cell['batch']==batch for cell in group]].mean()) for batch in range(2)]))
        rows.append(dict(scenario=scenario,methods=summaries,comparisons=comparisons,
            oracle_top_k={f'mean_{field}':float(np.mean([cell['decisions']['oracle_top_k'][field] for cell in group]))
                for field in ('confirmed_count','true_effect_count')},
            evaluated_graphs=sum(graph['status']=='evaluated' for cell in group for h in cell['hypotheses'] for graph in h['graph']),
            total_graphs=len(group)*8,
            different_direction_adjacency_choices=sum(h['learned']['choices']['directional']!=h['learned']['choices']['adjacency'] for cell in group for h in cell['hypotheses'])))
    result = dict(evidence_role=plan['evidence_role'],rows=rows,cells=len(cells),new_model_calls=0,
        structure_precision_and_nomination_evaluated=True,
        graph_representation_advantage_tested=False,
        graph_component_status='BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS',
        query_scope='SOURCE_CONTEXT_SUGGESTION_NOT_TARGET_CERTIFICATE',
        effect_estimator='target_randomization_only',
        confirmation_directions=plan['confirmation_directions'],
        calibration_objective=plan['calibration_objective'],
        same_allocated_target_budget=plan['target_fitting_task_units']+plan['target_calibration_task_units']+plan['target_ranking_task_units'],
        source_observation_cost=plan['source_discovery_task_units'])
    write_bundle(output/'summary',{'result.json':result})
    return result


def diagnose_information(parent,output):
    from prompt_mechanism_study.discovery import directional_transfer as directional
    for name in ('inputs','summary','verification'):
        verify_bundle(parent/name)
    plan = read_json(parent/'inputs'/'plan.json')
    parent_identity = read_json(parent/'inputs'/'identity.json')
    if read_json(parent/'verification'/'result.json')['source_archive_sha256']!=parent_identity['source_archive_sha256']:
        raise ValueError('来源结果与独立验证的执行身份不同')
    if file_sha256(parent/'source.zip')!=parent_identity['source_archive_sha256']:
        raise ValueError('来源执行归档发生变化')
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/discovery/directional_transfer.py','src/discovery/context_sharing.py',
        'src/discovery/jci_structure.py','src/discovery/policy_value.py','src/experiment/context_validation.py',
        'src/verification/directional_transfer.py','src/artifact_io.py','src/records.py','src/cli.py','pyproject.toml')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    identity = dict(evidence_role='POST_HOC_FROZEN_MODEL_INFORMATION_AUDIT',parent=str(parent),
        parent_plan_sha256=file_sha256(parent/'inputs'/'plan.json'),
        parent_summary_sha256=file_sha256(parent/'summary'/'result.json'),
        parent_source_sha256=parent_identity['source_archive_sha256'],
        source_archive_sha256=file_sha256(output/'source.zip'),
        sources={path.as_posix():file_sha256(path) for path in paths})
    write_bundle(output/'inputs',{'identity.json':identity,'plan.json':plan})
    records = []
    for root in sorted((parent/'cells').iterdir()):
        verify_bundle(root)
        cell = read_json(root/'result.json')
        hypotheses = []
        for row in cell['hypotheses']:
            risks = directional.catalog_risks(row['learned']['models'],row['hypothesis'],cell['scenario'],plan['target_ranking_task_units'])
            for name,index in row['learned']['choices'].items():
                np.testing.assert_allclose(risks[index]['exact_effect_variance'],row['exact_risks'][name]['exact_effect_variance'],atol=1e-12)
            hypotheses.append(dict(hypothesis=row['hypothesis'],risks=risks,
                information=directional.information_losses(row['learned'],risks)))
        result = dict(scenario=cell['scenario'],batch=cell['batch'],repetition=cell['repetition'],
            parent_cell_sha256=file_sha256(root/'result.json'),hypotheses=hypotheses)
        write_bundle(output/'cells'/root.name,{'result.json':result})
        records.append(result)
    rows = []
    for scenario in plan['scenarios']:
        selected = [h['information'] for cell in records if cell['scenario']==scenario for h in cell['hypotheses']]
        methods = {}
        for name in selected[0]['groups']:
            methods[name] = {field:float(np.mean([row['groups'][name][field] for row in selected])) for field in (
                'selected_variance','pool_oracle_variance','selection_loss','restriction_loss')}
        rows.append(dict(scenario=scenario,methods=methods,
            catalog_oracle_variance=float(np.mean([row['catalog_oracle_variance'] for row in selected])),
            directional_conversion={field:float(np.mean([row['directional_conversion'][field] for row in selected]))
                for field in ('pool_oracle_variance','endpoint_conversion_loss','remaining_restriction_loss')}))
    result = dict(evidence_role=identity['evidence_role'],rows=rows,cells=len(records),
        parent_source_sha256=identity['parent_source_sha256'],new_model_calls=0,
        oracle_selection_is_diagnostic_only=True)
    write_bundle(output/'summary',{'result.json':result})
    return result


def run_sharing_round(parent,output,plan_path,rscript):
    from prompt_mechanism_study.discovery import directional_transfer as directional
    plan = read_json(plan_path)
    if (plan['evidence_role']!='POST_HOC_EXPOSED_SHARING_DEVELOPMENT' or plan['formal_claim_allowed']
            or plan['aggregation_penalty']<=0 or rscript is None):
        raise ValueError('开发身份、聚合惩罚或 R 后端无效')
    for part in ('inputs','summary','verification'):
        verify_bundle(parent/part)
    parent_plan = read_json(parent/'inputs'/'plan.json')
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/discovery/directional_transfer.py','src/discovery/jci_context.R',
        'src/discovery/jci_structure.py','src/discovery/context_sharing.py','src/discovery/policy_value.py',
        'src/experiment/context_validation.py','src/verification/directional_transfer.py','src/artifact_io.py',
        'src/records.py','src/cli.py','pyproject.toml')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    identity = dict(parent=str(parent),parent_manifest_sha256=file_sha256(parent/'inputs'/'manifest.json'),
        parent_verification_sha256=file_sha256(parent/'verification'/'result.json'),
        source_archive_sha256=file_sha256(output/'source.zip'),sources={str(path):file_sha256(path) for path in paths})
    write_bundle(output/'inputs',{'plan.json':plan,'identity.json':identity,'parent-plan.json':parent_plan})
    backend = StructureBackend(rscript,output/'backend.log',Path('src/discovery/jci_context.R'))
    cells = []
    for root in sorted((parent/'cells').iterdir()):
        scenario_name,batch_name,repetition_name = root.name.rsplit('-',2)
        if (int(repetition_name) not in plan['repetitions'] or scenario_name not in plan['scenarios']
                or int(batch_name) not in plan['batches']):
            continue
        verify_bundle(root)
        original = read_json(root/'result.json')
        records = []
        for row in original['hypotheses']:
            data,learned = row['data'],row['learned']
            joint = [[environment,*values] for environment,role in ((0,'source_discovery'),(1,'target_fitting'))
                for values in data[role]['observations']]
            labels = ['E',*directional.LABELS]
            seed = [parent_plan['batch_seeds'][original['batch']],original['scenario'],original['repetition'],row['hypothesis'],'sharing']
            ci = ConditionalPermutation(joint,labels,plan['ci_draws'],seed,minimum_per_level=plan['minimum_per_level'])
            graph = backend.search(labels,'directional',ci,plan['ci_alpha'])
            selected,decisions = directional.separating_masks(graph)
            direct = []
            for mask in range(16):
                conditioned = ['A','W']+[directional.LABELS[4+bit] for bit in range(4) if mask>>bit&1]
                probability = ci.query('E','Y',conditioned)
                if probability is not None and probability>plan['ci_alpha']:
                    direct.append(mask)
            dag = directional.true_graph(original['scenario'])
            dag.add_node('E')
            if original['scenario']!='stable_proxy':
                dag.add_edge('E','N')
            if original['scenario']=='outcome_shift':
                dag.add_edge('E','Y')
            oracle = [mask for mask in range(16) if nx.is_d_separator(dag,{'E'},{'Y'},
                {'A','W'}|{name for bit,name in enumerate(('X','N','D1','D2')) if mask>>bit&1})]
            models = learned['models']
            common = learned['groups']['direct_deviation']
            def group(masks):
                return sorted(set(common)|{i for i,model in enumerate(models) if model['mode']=='deviation'
                    and not model['contexts'] and model['mask'] in masks})
            if graph['status']=='evaluated':
                ancestry,pag = np.asarray(graph['ancestry']),np.asarray(graph['pag'])
                ancestor_masks = sorted(set((sum(1<<bit for bit in range(4) if ancestry[5+bit,9]==1),
                    sum(1<<bit for bit in range(4) if ancestry[5+bit,9]!=-1))))
                adjacent_masks = [sum(1<<bit for bit in range(4) if pag[5+bit,9]!=0)]
            else:
                ancestor_masks,adjacent_masks = [],[]
            groups = dict(ancestor=group(ancestor_masks),separator=group(selected),
                oracle_separator=group(oracle),adjacency=group(adjacent_masks),
                direct_invariance=learned['groups']['direct_invariance'],direct_domain=group(direct),
                direct_search=learned['groups']['direct_search'])
            calibration = np.asarray(data['target_calibration']['observations'])
            zero,one = calibration.copy(),calibration.copy()
            zero[:,2],one[:,2] = 0,1
            predictions = np.asarray([(directional.predict(model,zero)+directional.predict(model,one))/2 for model in models])
            results = {}
            for name,indexes in groups.items():
                anchor = np.asarray([1/len(common) if index in common else 0. for index in indexes])
                for selection in ('single','aggregate'):
                    if selection=='single':
                        weights = np.zeros(len(indexes))
                        weights[np.argmin(np.mean((predictions[indexes]-calibration[:,-1])**2,axis=1))] = 1.
                    else:
                        weights = directional.aggregate(predictions[indexes],calibration[:,-1],anchor,plan['aggregation_penalty'])
                    mixture = dict(components=[models[index] for index in indexes],weights=weights)
                    results[f'{name}_{selection}'] = dict(indexes=indexes,weights=weights.tolist(),anchor=anchor.tolist(),
                        risk=directional.exact_risk(mixture,row['hypothesis'],original['scenario'],parent_plan['target_ranking_task_units']),
                        estimate=directional.scores(mixture,data['target_ranking']))
            records.append(dict(hypothesis=row['hypothesis'],graph=graph,queries=list(ci.cache.values()),
                decisions=decisions,selected_masks=selected,direct_masks=direct,oracle_masks=oracle,results=results))
        nominations = {name:sorted(range(4),key=lambda h:(-abs(records[h]['results'][name]['estimate']['effect']),h))[:2]
            for name in records[0]['results']}
        confirmed = {name:sum(original['confirmation'][h]['confirmed'] for h in indexes) for name,indexes in nominations.items()}
        cell = dict(scenario=original['scenario'],batch=original['batch'],repetition=original['repetition'],
            parent_cell_sha256=file_sha256(root/'result.json'),hypotheses=records,nominations=nominations,confirmed=confirmed)
        write_bundle(output/'cells'/root.name,{'result.json':cell})
        cells.append(cell)
    backend.close()
    comparisons = []
    family = 2*len(parent_plan['scenarios'])*len(plan['comparison_methods'])
    for scenario in plan['scenarios']:
        group = [cell for cell in cells if cell['scenario']==scenario]
        for baseline in plan['comparison_methods']:
            reference = plan['comparison_reference']
            gains = [cell['confirmed'][reference]-cell['confirmed'][baseline] for cell in group]
            differences = [np.mean([h['results'][baseline]['risk']['exact_effect_variance']-
                h['results'][reference]['risk']['exact_effect_variance'] for h in cell['hypotheses']]) for cell in group]
            radius = np.sqrt(8*np.log(2*family/.05)/len(group))
            variance_radius = 8/parent_plan['target_ranking_task_units']*np.sqrt(np.log(2*family/.05)/(2*len(group)))
            comparisons.append(dict(scenario=scenario,baseline=baseline,confirmed_gain=float(np.mean(gains)),
                confirmed_interval=[float(max(-2,np.mean(gains)-radius)),float(min(2,np.mean(gains)+radius))],
                variance_reduction=float(np.mean(differences)),variance_interval=[float(np.mean(differences)-variance_radius),float(np.mean(differences)+variance_radius)]))
    result = dict(evidence_role=plan['evidence_role'],cells=len(cells),new_model_calls=0,comparisons=comparisons,
        rows=[dict(scenario=scenario,methods={name:dict(
            mean_variance=float(np.mean([h['results'][name]['risk']['exact_effect_variance'] for cell in cells if cell['scenario']==scenario for h in cell['hypotheses']])),
            mean_confirmed=float(np.mean([cell['confirmed'][name] for cell in cells if cell['scenario']==scenario])))
            for name in cells[0]['confirmed']}) for scenario in plan['scenarios']],
        separated_queries=sum(record['status']=='separated' for cell in cells for h in cell['hypotheses'] for record in h['decisions']),
        evaluated_graphs=sum(h['graph']['status']=='evaluated' for cell in cells for h in cell['hypotheses']),
        uncertainty='DESCRIPTIVE_POST_HOC_NOT_POWERED_FOR_CONFIRMATION_GAIN')
    write_bundle(output/'summary',{'result.json':result})
    return result


def run_oracle_feasibility(parent,output,plan_path):
    import warnings
    from sklearn.exceptions import ConvergenceWarning
    from prompt_mechanism_study.discovery import controlled_transport as controlled
    warnings.simplefilter('error',ConvergenceWarning)
    plan = read_json(plan_path)
    if (plan['evidence_role']!='NON_CLAIM_PROSPECTIVE_ORACLE_FEASIBILITY' or plan['formal_claim_allowed']
            or not set(plan['scenarios'])<=set(controlled.SCENARIOS) or len(set(plan['batch_seeds']))!=2
            or plan['hypotheses']!=4 or plan['nomination_count']!=2 or plan['estimated_jci_searches']!=0
            or plan['new_provider_calls']!=0):
        raise ValueError('真实结构可行性设计无效')
    for part in ('inputs','summary','verification'):
        verify_bundle(parent/part)
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/discovery/controlled_transport.py','src/experiment/context_validation.py',
        'src/verification/directional_transfer.py','src/artifact_io.py','src/records.py','src/cli.py',
        'src/discovery/policy_value.py','src/discovery/context_sharing.py','src/discovery/jci_structure.py','pyproject.toml')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    identity = dict(parent=str(parent),parent_verification_sha256=file_sha256(parent/'verification'/'result.json'),
        source_archive_sha256=file_sha256(output/'source.zip'),sources={path.as_posix():file_sha256(path) for path in paths},
        python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__)
    specifications = {scenario:controlled.structure(scenario) for scenario in plan['scenarios']}
    write_bundle(output/'inputs',{'plan.json':plan,'identity.json':identity,'structures.json':specifications})
    cells = []
    for scenario in plan['scenarios']:
        core = scenario in plan['core_scenarios']
        sizes = itertools.product(plan['source_sizes'],plan['target_sizes']) if core else [(plan['boundary_source_size'],plan['boundary_target_size'])]
        q = [.5,.5] if scenario=='no_shift' else plan['target_context_probabilities']
        for ns,nt in sizes:
            for batch,seed in enumerate(plan['batch_seeds']):
                for repetition in range(plan['core_repetitions_per_batch'] if core else plan['boundary_repetitions_per_batch']):
                    coordinates = [scenario,ns,nt,repetition]
                    records = []
                    for h in range(4):
                        source = controlled.draw(random_stream(seed,*coordinates,h,'source'),ns,[.5,.5],h,scenario)
                        target = controlled.draw(random_stream(seed,*coordinates,h,'target'),nt,q,h,scenario)
                        folds,outputs = [],[]
                        for fold in (0,1):
                            held = np.arange(ns)%2==fold
                            catalog,predictions = controlled.fit_catalog(source[~held],source[held],target,q,specifications[scenario],plan)
                            folds.append(catalog)
                            outputs.append(predictions)
                        estimates,mixing = controlled.estimate(source,target,q,outputs,plan)
                        values,mass,_ = controlled.population(q,h,scenario)
                        means = []
                        for arm in (0,1):
                            assigned = values.copy()
                            assigned[:,2] = arm
                            means.append(controlled.probabilities(assigned,h,scenario)[2])
                        probabilities = np.asarray([mass@(means[0]*(1-means[1])),
                            mass@(means[0]*means[1]+(1-means[0])*(1-means[1])),mass@(means[1]*(1-means[0]))])
                        truth = float(mass@(means[1]-means[0]))
                        count = random_stream(seed,*coordinates,h,'confirmation').multinomial(plan['confirmation_task_units'],probabilities)
                        effect = float((count[2]-count[0])/count.sum())
                        radius = float(np.sqrt(2*np.log(2*plan['hypotheses']/plan['confirmation_alpha'])/count.sum()))
                        direction = int(effect-radius>plan['practical_effect'])-int(effect+radius<-plan['practical_effect'])
                        records.append(dict(hypothesis=h,source=source.tolist(),target=target.tolist(),folds=folds,
                            estimates=estimates,mixing=mixing,truth=truth,
                            task_id_prefix=f'{seed}/{scenario}/{ns}/{nt}/{repetition}/{h}',
                            confirmation=dict(probabilities=probabilities.tolist(),counts=count.tolist(),effect=effect,
                                radius=radius,direction=direction,task_units=int(count.sum()))))
                    nominations = {name:sorted(range(4),key=lambda h:(-abs(records[h]['estimates'][name]['effect']),h))[:2]
                        for name in controlled.METHODS}
                    confirmed = {name:sum(records[h]['confirmation']['direction']!=0 for h in selected) for name,selected in nominations.items()}
                    cell = dict(scenario=scenario,source_size=ns,target_size=nt,batch=batch,repetition=repetition,
                        q=q,core=core,hypotheses=records,nominations=nominations,confirmed=confirmed)
                    write_bundle(output/'cells'/f'{scenario}-{ns}-{nt}-{batch}-{repetition:03d}',{'result.json':cell})
                    cells.append(cell)
    result = controlled.feasibility_summary(cells,plan)
    write_bundle(output/'summary',{'result.json':result})
    return result


def prepare_directional_contexts(sources_path,annotations_path,output):
    from prompt_mechanism_study.records import content_hash
    from prompt_mechanism_study.tsg.prepared_prompts import directional_context_versions
    verify_bundle(sources_path)
    source_identity = read_json(sources_path/'identity.json')
    if source_identity['formal_claim_allowed'] is not False or source_identity['natural_population'] is not False:
        raise ValueError('当前准备只能使用已暴露受控开发来源')
    sources = read_json(sources_path/'sources.json')
    annotations = read_json(annotations_path)
    if annotations['independent_semantic_review']!='PENDING' or annotations['role']!='preparation_only':
        raise ValueError('作者准备不能冒充独立审查或正式数据角色')
    if len(sources)!=4 or {row['family'] for row in sources}!=set(annotations['families']):
        raise ValueError('固定来源与作者绑定覆盖不同')
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    paths = [Path(name) for name in ('src/tsg/prepared_prompts.py','src/tsg/prompt_tsg.py','src/tsg/prompt_contract.py',
        'src/experiment/context_validation.py','src/discovery/context_sharing.py','src/discovery/jci_structure.py',
        'src/discovery/policy_value.py','src/verification/context_validation.py','src/artifact_io.py','src/records.py',
        'src/cli.py','pyproject.toml')]
    with zipfile.ZipFile(output/'source.zip','x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path,path.as_posix())
    identity = dict(evidence_role=annotations['evidence_role'],sources=str(sources_path),
        source_manifest_sha256=file_sha256(sources_path/'manifest.json'),
        annotations_sha256=file_sha256(annotations_path),annotations_content_sha256=content_hash(annotations),formal_claim_allowed=False,
        implementation_sha256=file_sha256(Path('src/tsg/prepared_prompts.py')),
        source_archive_sha256=file_sha256(output/'source.zip'),
        implementation_sources={path.as_posix():file_sha256(path) for path in paths})
    write_bundle(output/'inputs',{'identity.json':identity,'annotations.json':annotations,'sources.json':sources})
    prepared = [directional_context_versions(source,annotations['families'][source['family']]) for source in sources]
    write_bundle(output/'preparation',{'result.json':prepared})
    questions = [
        '新增要求是否只约束主集合对应的工具调用，并且只表达一项完整的禁止 shell 解释要求？',
        '位置移动和集合角色引用是否保持原始非目标功能、作用范围、条件与错误行为？',
        '原始提示是否没有表达这一完整实现要求？不要据此判断已有代码是否缺少保护。',
        '是否存在把比较集合的操作错误绑定为主集合操作、或把路径对象误当作要求的直接执行目标？',
        '共同版本池及非零概率是否只证明设计支持，仍然缺少实际结果重叠和因果辨识证据？']
    review = dict(questions=questions,review_status='PENDING',author=annotations['author'],
        cases=[dict(task_unit_id=row['task_unit_id'],family=row['family'],source=source['prompt'],
            policy=annotations['families'][row['family']]['requirement'],
            binding=dict(direct_target='primary_operation',input_role='primary_path',comparison_target=False),
            versions=[dict(version_id=version['version_id'],control=version['arms'][0]['prompt'],
                treated=version['arms'][1]['prompt']) for version in row['versions']])
            for row,source in zip(prepared,sources,strict=True)])
    write_bundle(output/'review',{'packet.json':review})
    result = dict(status='MECHANICAL_PREPARATION_COMPLETE',evidence_role=identity['evidence_role'],
        task_units=4,context_assignments_per_task=4,versions=16,prepared_prompts=32,
        minimum_design_version_probability=.0625,
        semantic_review='PENDING_INDEPENDENT_REVIEW',outcome_overlap='NOT_OBSERVED',
        causal_information_gain='NOT_ESTABLISHED',graph_advantage='NOT_TESTED',
        same_author_encodings_are_independent_treatments=False,new_model_calls=0)
    write_bundle(output/'summary',{'result.json':result})
    return result

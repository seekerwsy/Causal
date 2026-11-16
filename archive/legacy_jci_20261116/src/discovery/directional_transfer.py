from __future__ import annotations

import itertools

import networkx as nx
import numpy as np
from sklearn.linear_model import Ridge
from sklearn.preprocessing import PolynomialFeatures
from scipy.optimize import minimize

from prompt_mechanism_study.discovery.context_sharing import confirmation_power
from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation


LABELS = ['C1','C2','A','W','X','N','D1','D2','Y']
ARM_LABELS = ['C1','C2','W','X','N','D1','D2','Y']
PREDICTORS = ['X','N','D1','D2','C1','C2']
SCENARIOS = ['irrelevant_context','confounded_proxy','multi_target','all_relevant',
    'weak_context','cancellation','no_shift','unobserved_attribute',
    'proxy_mechanism_change','source_spillover','outcome_shift']

CONTROLLED_SCENARIOS = ['irrelevant_context','confounded_proxy','multi_target','all_relevant',
    'weak_context','cancellation','no_shift','unobserved_attribute']


def controlled_probabilities(values,hypothesis,scenario):
    c1,c2,a,w,u,x,n,d1,d2 = np.asarray(values).T
    px = .15+(.06 if scenario=='weak_context' else .6)*c1+.05*w
    pn = .05+.65*u+(.02 if scenario=='weak_context' else .2)*c2
    if scenario=='irrelevant_context':
        pn = .25+.2*c2
    if scenario=='multi_target':
        px = .1+.45*c1+.15*c2+.05*w
        pn = .05+.55*u+.2*c2+.1*c1
    py = .36+.1*x+.12*u+.02*w+a*([.12,.06,0.,-.10][hypothesis]+.1*(2*x-1)+.1*(2*u-1))
    if scenario=='all_relevant':
        py += .025*n+.02*a*(2*n-1)
    if scenario=='cancellation':
        py += .04*(2*a-1)*(2*c2-1)
    if scenario not in CONTROLLED_SCENARIOS or any(np.any((p<0)|(p>1)) for p in (px,pn,py)):
        raise ValueError('受控机制名称或概率无效')
    return px,pn,py


def separating_masks(graph):
    if graph['status']!='evaluated':
        return [],[dict(mask=mask,status='unknown') for mask in range(16)]
    pag = np.asarray(graph['pag'])
    network = nx.from_numpy_array((pag!=0).astype(int))
    possible = nx.DiGraph()
    possible.add_nodes_from(range(10))
    possible.add_edges_from((i,j) for i,j in itertools.permutations(range(10),2)
        if pag[i,j] and pag[j,i]!=2 and pag[i,j]!=3)
    decisions = []
    for mask in range(16):
        conditioned = {3,4}|{5+bit for bit in range(4) if mask>>bit&1}
        ancestors = conditioned | set().union(*(nx.ancestors(possible,node) for node in conditioned))
        connected = False
        for path in nx.all_simple_paths(network,0,9):
            active = True
            for left,node,right in zip(path,path[1:],path[2:]):
                first,second = pag[left,node],pag[right,node]
                collider = first!=3 and second!=3 and node in ancestors
                noncollider = not (first==second==2) and node not in conditioned
                if not (collider or noncollider):
                    active = False
                    break
            if active:
                connected = True
                break
        decisions.append(dict(mask=mask,status='unknown' if connected else 'separated'))
    return [row['mask'] for row in decisions if row['status']=='separated'],decisions


def aggregate(predictions,outcomes,anchor,penalty):
    matrix = np.asarray(predictions).T
    anchor = np.asarray(anchor)
    def objective(weights):
        error = matrix@weights-outcomes
        return float(np.mean(error**2)+penalty*np.sum((weights-anchor)**2))
    def gradient(weights):
        return 2*matrix.T@(matrix@weights-outcomes)/len(outcomes)+2*penalty*(weights-anchor)
    result = minimize(objective,anchor,jac=gradient,method='SLSQP',bounds=[(0.,1.)]*len(anchor),
        constraints=[dict(type='eq',fun=lambda weights:weights.sum()-1,jac=lambda weights:np.ones(len(weights)))],
        options=dict(ftol=1e-12,maxiter=1000))
    if not result.success:
        raise RuntimeError(result.message)
    return result.x


def probabilities(values,environment,hypothesis,scenario):
    if scenario not in SCENARIOS or environment not in (0,1):
        raise ValueError('上下文机制或环境无效')
    base = scenario if scenario in CONTROLLED_SCENARIOS else 'confounded_proxy'
    px,pn,py = controlled_probabilities(values,hypothesis,base)
    c1,c2,a,w,u,x,n,d1,d2 = np.asarray(values).T
    if environment==1 and scenario=='proxy_mechanism_change':
        pn = .05+.20*u+.65*c2
    if scenario=='source_spillover':
        py = py+.03*c2
    if scenario=='outcome_shift' and environment==1:
        py = py+.04*(2*a-1)
    if np.any((py<0)|(py>1)):
        raise ValueError('方向机制的结果概率无效')
    return px,pn,py


def draw(rng,size,environment,hypothesis,scenario,identity):
    values = rng.integers(0,2,size=(size,9))
    q = [.75,.25] if environment==1 and scenario!='no_shift' else [.5,.5]
    values[:,0] = rng.binomial(1,q[0],size)
    values[:,1] = rng.binomial(1,q[1],size)
    px,pn,_ = probabilities(values,environment,hypothesis,scenario)
    values[:,5],values[:,6] = rng.binomial(1,px),rng.binomial(1,pn)
    _,_,py = probabilities(values,environment,hypothesis,scenario)
    y = rng.binomial(1,py)
    return dict(identity=identity,task_ids=[f'{identity}/{index}' for index in range(size)],
        observations=np.column_stack((values[:,[0,1,2,3,5,6,7,8]],y)).tolist(),u=values[:,4].tolist(),environment=environment)


def population(environment,hypothesis,scenario):
    values = np.asarray(list(itertools.product((0,1),repeat=9)))
    px,pn,py = probabilities(values,environment,hypothesis,scenario)
    q = [.75,.25] if environment==1 and scenario!='no_shift' else [.5,.5]
    weights = np.where(values[:,0],q[0],1-q[0])*np.where(values[:,1],q[1],1-q[1])/32
    weights *= np.where(values[:,5],px,1-px)*np.where(values[:,6],pn,1-pn)
    observations = values[:,[0,1,2,3,5,6,7,8]]
    np.testing.assert_allclose(weights.sum(),1.,atol=1e-13)
    return observations,values[:,4],weights,py


class PopulationQueries:
    def __init__(self,hypothesis,scenario,arm):
        observations,_,weights,py = population(0,hypothesis,scenario)
        selected = observations[:,2]==arm
        observations,weights,py = observations[selected][:,[0,1,3,4,5,6,7]],2*weights[selected],py[selected]
        self.labels = graph_labels(scenario)
        observations = observations[:,[ARM_LABELS.index(name) for name in self.labels[:-1]]]
        self.data = np.repeat(observations,2,axis=0)
        self.data = np.column_stack((self.data,np.tile([0,1],len(observations))))
        self.weights = np.column_stack((weights*(1-py),weights*py)).ravel()
        self.cache = {}

    def query(self,x,y,conditioned):
        key = (*sorted((x,y)),tuple(sorted(conditioned)))
        if key not in self.cache:
            columns = [self.labels.index(name) for name in conditioned]
            groups = np.unique(self.data[:,columns],axis=0,return_inverse=True)[1] if columns else np.zeros(len(self.data),dtype=int)
            maximum = 0.
            for group in np.unique(groups):
                chosen = groups==group
                table = np.zeros((2,2))
                np.add.at(table,(self.data[chosen,self.labels.index(x)],self.data[chosen,self.labels.index(y)]),self.weights[chosen])
                maximum = max(maximum,float(np.max(np.abs(table-np.outer(table.sum(1),table.sum(0))/table.sum()))))
            self.cache[key] = dict(x=x,y=y,conditioned=list(conditioned),p=float(maximum<1e-12),maximum_gap=maximum)
        return self.cache[key]['p']


def true_graph(scenario):
    graph = nx.DiGraph([('C1','X'),('W','X'),('C2','N'),('U','N'),('U','Y'),
                        ('X','Y'),('W','Y'),('A','Y')])
    graph.add_nodes_from(('D1','D2'))
    if scenario=='source_spillover':
        graph.add_edge('C2','Y')
    if scenario=='irrelevant_context':
        graph.remove_edge('U','N')
    if scenario=='multi_target':
        graph.add_edges_from([('C2','X'),('C1','N')])
    if scenario=='cancellation':
        graph.add_edge('C2','Y')
    if scenario=='all_relevant':
        graph.add_edge('N','Y')
    return graph


def masks(graph):
    if graph['status']!='evaluated':
        return dict(directional=[],adjacency=[])
    ancestry,pag = np.asarray(graph['ancestry']),np.asarray(graph['pag'])
    indexes = [4,5,6,7]
    certain = sum(1<<bit for bit,index in enumerate(indexes) if ancestry[index,-1]==1)
    possible = sum(1<<bit for bit,index in enumerate(indexes) if ancestry[index,-1]!=-1)
    adjacent = sum(1<<bit for bit,index in enumerate(indexes) if pag[index,-1]!=0)
    return dict(directional=sorted(set((certain,possible))),adjacency=[adjacent])


def design(observations,mask,contexts=False):
    selected = [2,3]+[4+bit for bit in range(4) if mask>>bit&1]
    selected += [bit for bit in (0,1) if contexts or mask>>(4+bit)&1]
    values = 2*np.asarray(observations)[:,selected]-1
    return PolynomialFeatures(degree=3,interaction_only=True,include_bias=True).fit_transform(values)


def fit(source,target,mask,penalty,mode='shared',deviation=None,contexts=False,allowed=15):
    observations = np.asarray(target['observations'] if mode=='target' else source['observations']+target['observations'])
    matrix = design(observations,mask,contexts)
    penalties = np.full(matrix.shape[1],penalty)
    if mode=='deviation':
        environment = np.r_[np.zeros(len(source['observations'])),np.ones(len(target['observations']))]
        correction = design(observations,allowed,True)
        matrix = np.column_stack((matrix,correction*environment[:,None]))
        penalties = np.r_[penalties,np.full(correction.shape[1],deviation)]
    scale = np.sqrt(penalties)
    learner = Ridge(alpha=1.,fit_intercept=False,solver='cholesky').fit(matrix/scale,observations[:,-1])
    return dict(mask=mask,contexts=contexts,mode=mode,penalty=penalty,deviation=deviation,allowed=allowed,
        coefficients=(learner.coef_/scale).tolist())


def predict(model,observations,environment=1):
    if 'components' in model:
        matrices = {}
        result = np.zeros(len(observations))
        for weight,component in zip(model['weights'],model['components'],strict=True):
            if weight==0:
                continue
            key = component['mask'],component['contexts'],component['mode']=='deviation'
            if key not in matrices:
                matrix = design(observations,key[0],key[1])
                matrices[key] = np.column_stack((matrix,design(observations,component.get('allowed',15),True)*environment)) if key[2] else matrix
            result += weight*np.clip(matrices[key]@np.asarray(component['coefficients']),0.,1.)
        return result
    matrix = design(observations,model['mask'],model['contexts'])
    if model['mode']=='deviation':
        matrix = np.column_stack((matrix,design(observations,model.get('allowed',15),True)*environment))
    return np.clip(matrix@np.asarray(model['coefficients']),0.,1.)


def calibration_loss(model,data):
    observed = np.asarray(data['observations'])
    control,treated = observed.copy(),observed.copy()
    control[:,2],treated[:,2] = 0,1
    prognosis = (predict(model,control)+predict(model,treated))/2
    return float(np.mean((observed[:,-1]-prognosis)**2))


def confirmation_powers(distribution,size,plan):
    positive = confirmation_power(distribution,size,plan)
    negative = confirmation_power(dict(plus=distribution['minus'],minus=distribution['plus']),size,plan)
    return dict(positive=positive,negative=negative)


def scores(model,data):
    observed = np.asarray(data['observations'])
    control,treated = observed.copy(),observed.copy()
    control[:,2],treated[:,2] = 0,1
    p0,p1 = predict(model,control),predict(model,treated)
    pa = np.where(observed[:,2],p1,p0)
    values = p1-p0+2*(2*observed[:,2]-1)*(observed[:,-1]-pa)
    return dict(effect=float(values.mean()),standard_error=float(values.std(ddof=1)/np.sqrt(len(values))),
        predictions=np.column_stack((p0,p1)).tolist(),scores=values.tolist())


def exact_risk(model,hypothesis,scenario,ranking_size):
    observations,_,weights,py = population(1,hypothesis,scenario)
    prediction = predict(model,observations)
    p0,p1 = observations.copy(),observations.copy()
    p0[:,2],p1[:,2] = 0,1
    sum_prediction = predict(model,p0)+predict(model,p1)
    a = observations[:,2]
    gamma_means = (2*a-1)*(2*py-sum_prediction)
    gamma_squares = 4*py-4*sum_prediction*py+sum_prediction**2
    mean = float(weights@gamma_means)
    variance = float(weights@gamma_squares-mean**2)
    return dict(target_brier_risk=float(weights@((prediction-py)**2+py*(1-py))),
        target_prediction_excess_risk=float(weights@((prediction-py)**2)),
        target_prognostic_risk=float(weights@((sum_prediction/2-py)**2+py*(1-py))),
        exact_effect=mean,exact_effect_variance=variance/ranking_size)


def invariance_masks(source,plan,seed):
    observed = np.asarray(source['observations'])
    joint = np.column_stack((2*observed[:,0]+observed[:,1],observed[:,2:]))
    labels = ['C','A','W','X','N','D1','D2','Y']
    ci = ConditionalPermutation(joint,labels,plan['ci_draws'],seed,minimum_per_level=2)
    results = []
    for mask in range(16):
        conditioned = ['A','W']+[LABELS[4+bit] for bit in range(4) if mask>>bit&1]
        p = ci.query('C','Y',conditioned)
        key = ('C','Y',tuple(sorted(conditioned)))
        complete = all(len(table)==4 for table in ci.cache[key]['tables'])
        results.append(dict(mask=mask,p=p,complete_context_support=complete,
            accepted=complete and p is not None and p>plan['ci_alpha']))
    return [row['mask'] for row in results if row['accepted']],dict(queries=list(ci.cache.values()),decisions=results)


def allowed_mask(scenario):
    return 62 if scenario=='unobserved_attribute' else 63


def graph_labels(scenario):
    return [name for name in ARM_LABELS if name!='X' or scenario!='unobserved_attribute']


def possible_separation(pag,left,right,conditioned):
    pag = np.asarray(pag)
    network = nx.from_numpy_array((pag!=0).astype(int))
    possible = nx.DiGraph()
    possible.add_nodes_from(range(len(pag)))
    possible.add_edges_from((i,j) for i,j in itertools.permutations(range(len(pag)),2)
        if pag[i,j] and pag[j,i]!=2 and pag[i,j]!=3)
    ancestors = set(conditioned)|set().union(*(nx.ancestors(possible,node) for node in conditioned))
    for path in nx.all_simple_paths(network,left,right):
        active = True
        for previous,node,following in zip(path,path[1:],path[2:]):
            first,second = pag[previous,node],pag[following,node]
            collider = first!=3 and second!=3 and node in ancestors
            noncollider = not(first==second==2) and node not in conditioned
            if not(collider or noncollider):
                active = False
                break
        if active:
            return False
    return True


def context_masks(graphs,allowed=63,skeleton=False):
    decisions = []
    for mask in range(64):
        if mask&allowed!=mask:
            continue
        selected = [name for bit,name in enumerate(PREDICTORS) if mask>>bit&1]
        queries = [name for name in ('C1','C2') if name not in selected]
        statuses = []
        for arm,graph in enumerate(graphs):
            labels = graph['labels']
            conditioned = ['W',*selected]
            for context in queries:
                separated = False
                if graph['status']=='evaluated':
                    pag = np.asarray(graph['pag'])
                    if skeleton:
                        pag = (pag!=0).astype(int)
                    separated = possible_separation(pag,labels.index(context),labels.index('Y'),
                        {labels.index(name) for name in conditioned})
                statuses.append(dict(arm=arm,context=context,conditioned=conditioned,
                    data_role='source_discovery',query_type='source_context_separation',
                    status='separated' if separated else 'unknown'))
        status = 'unrestricted' if not queries else ('supported' if all(row['status']=='separated' for row in statuses) else 'unknown')
        decisions.append(dict(mask=mask,status=status,queries=statuses))
    return [row['mask'] for row in decisions if row['status']=='supported'],decisions


def oracle_context_masks(scenario):
    graph = true_graph(scenario)
    graph.remove_node('A')
    accepted = []
    for mask in range(64):
        if mask&allowed_mask(scenario)!=mask:
            continue
        selected = {name for bit,name in enumerate(PREDICTORS) if mask>>bit&1}
        contexts = {'C1','C2'}-selected
        if contexts and all(nx.is_d_separator(graph,{'Y'},{context},selected|{'W'}) for context in contexts):
            accepted.append(mask)
    return accepted


def oracle_query_diagnostics(scenario):
    source = true_graph(scenario)
    source.remove_node('A')
    domain = source.copy()
    domain.add_node('E')
    if scenario!='no_shift':
        domain.add_edges_from([('E','C1'),('E','C2')])
    if scenario=='proxy_mechanism_change':
        domain.add_edge('E','N')
    if scenario=='outcome_shift':
        domain.add_edge('E','Y')
    allowed = allowed_mask(scenario)
    observed = {name for bit,name in enumerate(PREDICTORS) if allowed>>bit&1}
    supported = oracle_context_masks(scenario)
    result = []
    for mask in range(64):
        if mask&allowed!=mask:
            continue
        kept = {name for bit,name in enumerate(PREDICTORS) if mask>>bit&1}
        result.append(dict(mask=mask,source_context_supported=mask in supported,
            prediction_sufficient=nx.is_d_separator(source,{'Y'},observed-kept,kept|{'W'}),
            target_environment_separated=nx.is_d_separator(domain,{'E'},{'Y'},kept|{'W'})))
    return result


def observable_optimal_variance(h,scenario,size):
    rows,u,mass,py = population(1,h,scenario)
    columns = [0,1,3,5,6,7]+([4] if scenario!='unobserved_attribute' else [])
    groups = np.unique(rows[:,columns],axis=0,return_inverse=True)[1]
    means = []
    for arm in (0,1):
        assigned = rows.copy()
        assigned[:,2] = arm
        means.append(probabilities(np.insert(assigned,4,u,axis=1),1,h,scenario)[2])
    total = np.bincount(groups,weights=mass)
    signal = np.bincount(groups,weights=mass*(means[0]+means[1]))/total
    truth = float(mass@(means[1]-means[0]))
    risk = float(mass@(py*(1-signal[groups]/2)**2+(1-py)*(signal[groups]/2)**2))
    return (4*risk-truth**2)/size


def query_information(learned,risks,observable_variance):
    values = np.asarray([risk['exact_effect_variance'] for risk in risks])
    best = int(np.argmin(values))
    groups = {}
    for name,indexes in learned['groups'].items():
        optimum = min(indexes,key=lambda i:(values[i],i))
        selected = learned['choices'][name]
        groups[name] = dict(selected_model=selected,pool_oracle_model=optimum,
            selection_loss=float(values[selected]-values[optimum]),
            restriction_loss=float(values[optimum]-values[best]))
    return dict(observable_optimal_effect_variance=float(observable_variance),
        catalog_oracle_model=best,catalog_oracle_variance=float(values[best]),groups=groups)


def learn(source,target,calibration,ranking,graph,oracle_graph,scenario,plan,seed):
    allowed = allowed_mask(scenario)
    selected,decisions = context_masks(graph,allowed)
    adjacency,ablation = context_masks(graph,allowed,skeleton=True)
    population_selected,population_decisions = context_masks(oracle_graph,allowed)
    specifications = dict(directional=selected,adjacency=adjacency,
        direct_search=[mask for mask in range(64) if mask&allowed==mask],
        oracle_graph=oracle_context_masks(scenario),population_graph=population_selected)
    models,cache = [],{}
    def fitted(mask,penalty,mode='shared',deviation=None,contexts=False):
        if mask&48==48:
            mask,contexts = mask&15,True
        key = mask,penalty,mode,deviation,contexts
        if key not in cache:
            cache[key] = len(models)
            models.append(fit(source,target,mask,penalty,mode,deviation,contexts,allowed&15))
        return cache[key]
    target_ids = [fitted(allowed&15,value,'target',contexts=True) for value in plan['ridge_penalties']]
    pooled_ids = [fitted(allowed&15,value,contexts=True) for value in plan['ridge_penalties']]
    deviation_ids = [fitted(allowed&15,value,'deviation',delta,True) for value,delta in itertools.product(
        plan['ridge_penalties'],plan['deviation_penalties'])]
    common_ids = target_ids+pooled_ids+deviation_ids
    groups = {name:common_ids+[fitted(mask,value,'deviation',delta) for mask,value,delta in
              itertools.product(selected,plan['ridge_penalties'],plan['deviation_penalties'])]
              for name,selected in specifications.items()}
    groups['direct_deviation'] = common_ids
    groups['direct_pooled'] = target_ids+pooled_ids
    groups['target_only'] = target_ids
    losses = [calibration_loss(model,calibration) for model in models]
    choices = {name:min(indexes,key=lambda index:(losses[index],index)) for name,indexes in groups.items()}
    estimates = {name:scores(models[index],ranking) for name,index in choices.items()}
    return dict(models=models,groups=groups,losses=losses,choices=choices,estimates=estimates,
        proposals=specifications,context_queries=decisions,skeleton_queries=ablation,
        population_context_queries=population_decisions,query_scope='SOURCE_CONTEXT_SUGGESTION_NOT_TARGET_CERTIFICATE')


def catalog_risks(models,hypothesis,scenario,ranking_size):
    observed,u,weights,py = population(1,hypothesis,scenario)
    states = [observed.copy(),observed.copy()]
    states[0][:,2],states[1][:,2] = 0,1
    matrices,predictions = {},[]
    for model in models:
        key = model['mask'],model['contexts'],model['mode']=='deviation'
        if key not in matrices:
            pair = [design(rows,key[0],key[1]) for rows in states]
            matrices[key] = [np.column_stack((value,design(rows,model.get('allowed',15),True))) for value,rows in
                zip(pair,states,strict=True)] if key[2] else pair
        predictions.append([np.clip(value@np.asarray(model['coefficients']),0.,1.) for value in matrices[key]])
    values = np.asarray(predictions)
    sums = values.sum(axis=1)
    truth = float(weights@(2*(2*observed[:,2]-1)*py))
    second = (4*py-4*sums*py+sums**2)@weights
    true_means = [probabilities(np.insert(rows,4,u,axis=1),1,hypothesis,scenario)[2] for rows in states]
    signal = true_means[0]+true_means[1]
    return [dict(exact_effect=truth,exact_effect_variance=float((value-truth**2)/ranking_size),
        complete_state_prognostic_error=float(weights@((total-signal)**2)))
        for value,total in zip(second,sums,strict=True)]


def information_losses(learned,risks):
    variances = np.asarray([row['exact_effect_variance'] for row in risks])
    catalog_best = int(np.argmin(variances))
    groups = {}
    for name,indexes in learned['groups'].items():
        best = min(indexes,key=lambda index:(variances[index],index))
        chosen = learned['choices'][name]
        groups[name] = dict(selected_model=chosen,pool_oracle_model=best,
            selected_variance=float(variances[chosen]),pool_oracle_variance=float(variances[best]),
            selection_loss=float(variances[chosen]-variances[best]),
            restriction_loss=float(variances[best]-variances[catalog_best]))
    proposals = learned['proposals']['directional']
    compatible = [mask for mask in range(16) if proposals and mask&min(proposals)==min(proposals)
                  and mask|max(proposals)==max(proposals)]
    indexes = sorted(set(learned['groups']['direct_deviation']) | {i for i,model in enumerate(learned['models']) if
               model['mode']=='deviation' and not model['contexts'] and model['mask'] in compatible})
    optimum = min(indexes,key=lambda index:(variances[index],index))
    conversion = dict(compatible_masks=compatible,pool_oracle_model=optimum,
        pool_oracle_variance=float(variances[optimum]),
        endpoint_conversion_loss=float(groups['directional']['pool_oracle_variance']-variances[optimum]),
        remaining_restriction_loss=float(variances[optimum]-variances[catalog_best]))
    return dict(catalog_oracle_model=catalog_best,catalog_oracle_variance=float(variances[catalog_best]),
        groups=groups,directional_conversion=conversion)

from __future__ import annotations

import itertools

import networkx as nx
import numpy as np
from scipy.optimize import linprog
from scipy.stats import beta, norm, t
from sklearn.ensemble import HistGradientBoostingClassifier, HistGradientBoostingRegressor
from sklearn.decomposition import PCA
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import ElasticNetCV, LogisticRegression, LogisticRegressionCV, Ridge, RidgeCV
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import PolynomialFeatures
from scipy.special import expit, logit


SCENARIOS = ['irrelevant_context','confounded_proxy','multi_target','all_relevant',
    'weak_context','cancellation','no_shift','unobserved_attribute']
NAMES = ['C1','C2','X','N','D1','D2']
COLUMNS = [0,1,4,5,6,7]
METHODS = ['oracle','ridge_full','elastic_full','boosted_full','subset_search']


def probabilities(values,h,scenario):
    c1,c2,a,w,u,x,n,d1,d2 = np.asarray(values).T
    px = .15+(.06 if scenario=='weak_context' else .6)*c1+.05*w
    pn = .05+.65*u+(.02 if scenario=='weak_context' else .2)*c2
    if scenario=='irrelevant_context':
        pn = .25+.2*c2
    if scenario=='multi_target':
        px = .1+.45*c1+.15*c2+.05*w
        pn = .05+.55*u+.2*c2+.1*c1
    py = .36+.1*x+.12*u+.02*w+a*([.12,.06,0.,-.10][h]+.1*(2*x-1)+.1*(2*u-1))
    if scenario=='all_relevant':
        py += .025*n+.02*a*(2*n-1)
    if scenario=='cancellation':
        py += .04*(2*a-1)*(2*c2-1)
    if scenario not in SCENARIOS or any(np.any((p<0)|(p>1)) for p in (px,pn,py)):
        raise ValueError('受控机制名称或概率无效')
    return px,pn,py


def draw(rng,size,q,h,scenario):
    values = rng.integers(0,2,size=(size,9))
    values[:,0] = rng.binomial(1,q[0],size)
    values[:,1] = rng.binomial(1,q[1],size)
    px,pn,_ = probabilities(values,h,scenario)
    values[:,5],values[:,6] = rng.binomial(1,px),rng.binomial(1,pn)
    py = probabilities(values,h,scenario)[2]
    return np.column_stack((values[:,[0,1,2,3,5,6,7,8]],rng.binomial(1,py)))


def population(q,h,scenario):
    values = np.asarray(list(itertools.product((0,1),repeat=9)))
    px,pn,py = probabilities(values,h,scenario)
    mass = np.where(values[:,0],q[0],1-q[0])*np.where(values[:,1],q[1],1-q[1])/32
    mass *= np.where(values[:,5],px,1-px)*np.where(values[:,6],pn,1-pn)
    return values,mass,py


def structure(scenario):
    graph = nx.DiGraph([('C1','X'),('W','X'),('C2','N'),('U','Y'),('X','Y'),('W','Y'),('A','Y')])
    graph.add_nodes_from(('D1','D2'))
    if scenario!='irrelevant_context':
        graph.add_edge('U','N')
    if scenario=='multi_target':
        graph.add_edges_from([('C2','X'),('C1','N')])
    if scenario=='all_relevant':
        graph.add_edge('N','Y')
    if scenario=='cancellation':
        graph.add_edge('C2','Y')
    allowed = 59 if scenario=='unobserved_attribute' else 63
    valid = []
    for mask in range(64):
        if mask|allowed!=allowed:
            continue
        kept = {'W','A'}|{name for bit,name in enumerate(NAMES) if mask>>bit&1}
        omitted = {name for bit,name in enumerate(NAMES) if allowed>>bit&1 and not mask>>bit&1}
        if nx.is_d_separator(graph,{'Y'},omitted,kept):
            valid.append(mask)
    minimal = [mask for mask in valid if not any(other!=mask and other&mask==other for other in valid)]
    return dict(allowed=allowed,minimal=minimal,valid=valid,edges=list(graph.edges))


def weight(rows,q):
    return np.prod(np.where(np.asarray(rows)[:,:2],np.asarray(q),1-np.asarray(q))/.5,axis=1)


def columns(mask):
    return [3]+[column for bit,column in enumerate(COLUMNS) if mask>>bit&1]


def design(rows,mask):
    return PolynomialFeatures(degree=2,interaction_only=True,include_bias=True).fit_transform(2*np.asarray(rows)[:,columns(mask)]-1)


def fit_catalog(train,held,target,q,specification,plan):
    catalogs,outputs = [],{}
    for arm in (0,1):
        rows = train[train[:,2]==arm]
        weights = weight(rows,q)
        models = []
        for mask in range(64):
            if mask|specification['allowed']!=specification['allowed']:
                continue
            matrix = design(rows,mask)
            fit = RidgeCV(alphas=plan['ridge_penalties'],fit_intercept=False,gcv_mode='svd',
                store_cv_results=True).fit(matrix,rows[:,-1],sample_weight=weights)
            models.append(dict(mask=mask,alpha=float(fit.alpha_),coefficients=fit.coef_.tolist(),
                scores=np.mean(fit.cv_results_,axis=0).tolist(),loss=float(-fit.best_score_)))
        indexes = {model['mask']:i for i,model in enumerate(models)}
        oracle_options = sorted(set(specification['minimal']+[specification['allowed']]))
        choices = dict(oracle=min((indexes[mask] for mask in oracle_options),key=lambda i:(models[i]['loss'],i)),
            ridge_full=indexes[specification['allowed']],subset_search=min(range(len(models)),key=lambda i:(models[i]['loss'],i)))
        prediction_pairs = {}
        for name,index in choices.items():
            model = models[index]
            prediction_pairs[name] = [np.clip(design(data,model['mask'])@model['coefficients'],0,1)
                for data in (held,target)]
        matrix = design(rows,specification['allowed'])
        elastic = ElasticNetCV(alphas=plan['elastic_penalties'],l1_ratio=[.25,.75],cv=3,
            fit_intercept=False,max_iter=50000,tol=1e-6).fit(matrix,rows[:,-1],sample_weight=weights)
        prediction_pairs['elastic_full'] = [np.clip(elastic.predict(design(data,specification['allowed'])),0,1)
            for data in (held,target)]
        tree = HistGradientBoostingRegressor(**plan['boosting']).fit(rows[:,columns(specification['allowed'])],rows[:,-1],sample_weight=weights)
        prediction_pairs['boosted_full'] = [np.clip(tree.predict(data[:,columns(specification['allowed'])]),0,1) for data in (held,target)]
        for name,pair in prediction_pairs.items():
            outputs.setdefault(name,[]).append(pair)
        catalogs.append(dict(arm=arm,models=models,choices=choices,
            elastic=dict(alpha=float(elastic.alpha_),l1_ratio=float(elastic.l1_ratio_),coefficients=elastic.coef_.tolist(),
                mse_path=elastic.mse_path_.tolist())))
    return catalogs,{name:dict(held=np.asarray([pair[0] for pair in value]),
        target=np.asarray([pair[1] for pair in value])) for name,value in outputs.items()}


def estimate(source,target,q,outputs,plan):
    ns,nt = len(source),len(target)
    effective = ns/np.prod(2*(np.asarray(q)**2+(1-np.asarray(q))**2))
    mixing = effective/(effective+nt)
    result = {}
    for name in METHODS:
        held_predictions = np.zeros((2,ns))
        target_predictions = np.zeros((2,nt))
        for fold,output in enumerate(outputs):
            selected = np.arange(ns)%2==fold
            held_predictions[:,selected] = output[name]['held']
            target_predictions += output[name]['target']/2
        source_residual = 2*(2*source[:,2]-1)*(source[:,-1]-held_predictions[source[:,2],np.arange(ns)])
        target_residual = 2*(2*target[:,2]-1)*(target[:,-1]-target_predictions[target[:,2],np.arange(nt)])
        effect = float(np.mean(target_predictions[1]-target_predictions[0])+
            mixing*np.mean(weight(source,q)*source_residual)+(1-mixing)*target_residual.mean())
        result[name] = dict(effect=effect,source_predictions=held_predictions.tolist(),target_predictions=target_predictions.tolist())
    return result,mixing


def count_interval(values,alpha):
    support = np.arange(-2,3,dtype=float)
    counts = np.asarray([sum(value==point for value in values) for point in support])
    n = len(values)
    bounds = [(0. if count==0 else float(beta.ppf(alpha/10,count,n-count+1)),
        1. if count==n else float(beta.ppf(1-alpha/10,count+1,n-count))) for count in counts]
    lower = linprog(support,A_eq=np.ones((1,5)),b_eq=[1.],bounds=bounds,method='highs')
    upper = linprog(-support,A_eq=np.ones((1,5)),b_eq=[1.],bounds=bounds,method='highs')
    if not lower.success or not upper.success:
        raise RuntimeError('确认数量置信区域不可解')
    return [float(lower.fun),float(-upper.fun)]


def feasibility_summary(cells,plan):
    conditions = sorted(set((cell['scenario'],cell['source_size'],cell['target_size']) for cell in cells))
    rows = []
    core_groups = []
    for condition in conditions:
        group = [cell for cell in cells if (cell['scenario'],cell['source_size'],cell['target_size'])==condition]
        if group[0]['core']:
            core_groups.append(group)
        methods = {}
        for name in METHODS:
            errors = [h['estimates'][name]['effect']-h['truth'] for cell in group for h in cell['hypotheses']]
            methods[name] = dict(mean_confirmed=float(np.mean([cell['confirmed'][name] for cell in group])),
                mse=float(np.mean(np.square(errors))),bias=float(np.mean(errors)))
        rows.append(dict(scenario=condition[0],source_size=condition[1],target_size=condition[2],
            repetitions=len(group),core=group[0]['core'],methods=methods))
    mse = np.asarray([[[np.mean([(h['estimates'][name]['effect']-h['truth'])**2 for h in cell['hypotheses']])
        for name in METHODS] for cell in group] for group in core_groups])
    rng = np.random.default_rng(plan['batch_seeds'][0])
    draws = rng.integers(mse.shape[1],size=(plan['bootstrap_draws'],len(core_groups),mse.shape[1]))
    boot = mse[np.arange(len(core_groups))[None,:,None],draws].mean(axis=(1,2))
    comparisons = []
    k = len(plan['comparators'])
    for name in plan['comparators']:
        intervals,gains,batch_gains = [],[],[[],[]]
        for group in core_groups:
            differences = [cell['confirmed']['oracle']-cell['confirmed'][name] for cell in group]
            intervals.append(count_interval(differences,plan['comparison_alpha']/(k*len(core_groups))))
            gains.append(np.mean(differences))
            for batch in (0,1):
                batch_gains[batch].extend(cell['confirmed']['oracle']-cell['confirmed'][name] for cell in group if cell['batch']==batch)
        index = METHODS.index(name)
        reduction = 1-mse[:,:,0].mean()/mse[:,:,index].mean()
        distribution = 1-boot[:,0]/boot[:,index]
        comparisons.append(dict(baseline=name,confirmed_gain=float(np.mean(gains)),
            simultaneous_count_interval=np.mean(intervals,axis=0).tolist(),
            batch_gains=[float(np.mean(values)) for values in batch_gains],
            relative_mse_reduction=float(reduction),mse_bootstrap_interval=np.quantile(distribution,
                [plan['comparison_alpha']/(2*k),1-plan['comparison_alpha']/(2*k)]).tolist()))
    proceed = all(row['simultaneous_count_interval'][0]>0 and row['confirmed_gain']>=plan['minimum_confirmation_gain']
        and min(row['batch_gains'])>0 and row['relative_mse_reduction']>=plan['minimum_relative_mse_reduction']
        and row['mse_bootstrap_interval'][0]>0 for row in comparisons)
    return dict(evidence_role=plan['evidence_role'],cells=len(cells),core_cells=sum(len(group) for group in core_groups),
        rows=rows,comparisons=comparisons,decision='ORACLE_VALUE_SUPPORTED' if proceed else 'ORACLE_VALUE_NOT_ESTABLISHED_DO_NOT_EXPAND',
        estimated_jci_searches=0,new_provider_calls=0,
        count_inference='STRATIFIED_MULTINOMIAL_CLOPPER_PEARSON_REGION_WITH_BONFERRONI',
        mse_inference='PAIRED_STRATIFIED_DEVELOPMENT_BOOTSTRAP')


def highdim_draw(rng,size,environment,scenario,plan,permutation,outcomes=True):
    if scenario not in ('distributed_signal','target_mechanism_change','dense_control'):
        raise ValueError('多属性机制名称无效')
    q = plan['context_source_probabilities'] if environment==0 else plan['context_target_probabilities']
    contexts = rng.binomial(1,np.asarray(q),size=(size,2))
    attributes = rng.binomial(1,.5,size=(size,plan['attributes']))
    for index in range(plan['active_attributes']):
        attributes[:,index] = rng.binomial(1,.35+.30*contexts[:,index%2])
    if scenario=='target_mechanism_change':
        for index in range(plan['active_attributes'],plan['attributes']):
            attributes[:,index] = rng.binomial(1,.20+.60*contexts[:,index%2])
    x = np.column_stack((contexts,attributes))
    z = 2*x-1
    linear = z[:,2:2+plan['active_attributes']].sum(axis=1).astype(float)
    if scenario=='dense_control':
        linear = np.sqrt(plan['active_attributes']/z.shape[1])*z.sum(axis=1)
    elif scenario=='target_mechanism_change' and environment==1:
        linear = .7*linear+.8*z[:,2+plan['active_attributes']]
    average = expit(linear)
    effect = plan['effect_multiplier']*average*(1-average)
    if sorted(permutation)!=list(range(plan['attributes'])):
        raise ValueError('属性位置置换无效')
    x = np.column_stack((contexts,attributes[:,permutation]))
    output = dict(x=x,average=average,effect=effect)
    if outcomes:
        a = rng.binomial(1,.5,size)
        probability = average+(a-.5)*effect
        if np.any((probability<=0)|(probability>=1)):
            raise ValueError('多属性机制结果概率无效')
        output.update(a=a,y=rng.binomial(1,probability))
    return output


def certify_logistic_coefficients(x,y,coefficient,inverse,ratio):
    if not np.any(coefficient[:-1]):
        coefficient[-1] = logit(y.mean())
    probability = expit(x@coefficient[:-1]+coefficient[-1])
    gradient = x.T@(probability-y)+(1-ratio)/inverse*coefficient[:-1]
    nonzero = coefficient[:-1]!=0
    gradient[nonzero] += ratio/inverse*np.sign(coefficient[:-1][nonzero])
    violation = np.abs(gradient)
    violation[~nonzero] = np.maximum(violation[~nonzero]-ratio/inverse,0)
    if max(float(violation.max()),float(abs(np.sum(probability-y))))>1e-3:
        raise ValueError('来源逻辑回归系数没有满足最优性条件')
    return coefficient


def highdim_source_models(source,scenario,plan,seed,oracle_features,include_oracle=True):
    x,y = 2*source['x']-1,source['y']
    folds = list(StratifiedKFold(plan['source_cv_folds'],shuffle=True,random_state=seed).split(x,y))
    models,records = {},{}
    full = list(range(x.shape[1]))
    for name in (('oracle','full_logit','sparse_logit') if include_oracle else ('full_logit','sparse_logit')):
        features = oracle_features if name=='oracle' and scenario!='dense_control' else full
        ratios = plan['l1_ratios'] if name=='sparse_logit' else [0.]
        model = LogisticRegressionCV(Cs=plan['inverse_penalties'],l1_ratios=ratios,cv=folds,
            scoring='neg_brier_score',solver='saga' if name=='sparse_logit' else 'lbfgs',
            max_iter=100000,tol=1e-8,fit_intercept=True,random_state=seed,
            use_legacy_attributes=False).fit(x[:,features],y)
        paths = model.coefs_paths_[:,:,:,0,:].copy()
        scores = model.scores_.copy()
        if name=='sparse_logit':
            for fold,(train,held) in enumerate(folds):
                for ri,ratio in enumerate(ratios):
                    for ci,inverse in enumerate(plan['inverse_penalties']):
                        beta = certify_logistic_coefficients(x[train],y[train],paths[fold,ri,ci],inverse,ratio)
                        scores[fold,ri,ci] = -np.mean((y[held]-expit(x[held]@beta[:-1]+beta[-1]))**2)
            ri,ci = np.unravel_index(scores.mean(axis=0).argmax(),scores.shape[1:])
            model = LogisticRegression(C=plan['inverse_penalties'][ci],l1_ratio=ratios[ri],solver='saga',
                max_iter=100000,tol=1e-8,fit_intercept=True,random_state=seed).fit(x,y)
            beta = certify_logistic_coefficients(x,y,np.r_[model.coef_[0],model.intercept_[0]],model.C,model.l1_ratio)
            model.coef_[0],model.intercept_[0] = beta[:-1],beta[-1]
        models[name] = (model,features)
        records[name] = dict(kind='logit',features=features,coefficients=np.r_[model.intercept_,model.coef_[0]].tolist(),
            C=float(model.C if name=='sparse_logit' else model.C_),
            l1_ratio=float(model.l1_ratio if name=='sparse_logit' else model.l1_ratio_),cv_scores=scores.tolist(),
            cv_paths=paths.tolist(),cv_ratios=ratios)
    pipeline = Pipeline([('screen',SelectKBest(f_classif)),
        ('model',LogisticRegression(l1_ratio=0.,solver='lbfgs',max_iter=10000,tol=1e-8,random_state=seed))])
    search = GridSearchCV(pipeline,{'screen__k':plan['screen_sizes'],'model__C':plan['screen_inverse_penalties']},
        cv=folds,scoring='neg_brier_score',error_score='raise').fit(x,y)
    selected = search.best_estimator_
    fitted = selected.named_steps['model']
    models['screened_logit'] = (selected,full)
    records['screened_logit'] = dict(kind='logit',features=selected.named_steps['screen'].get_support(indices=True).tolist(),
        coefficients=np.r_[fitted.intercept_,fitted.coef_[0]].tolist(),C=float(fitted.C),l1_ratio=0.,
        cv_params=search.cv_results_['params'],cv_means=search.cv_results_['mean_test_score'].tolist(),
        cv_selected=int(search.best_index_))
    tree = GridSearchCV(HistGradientBoostingClassifier(learning_rate=.1,min_samples_leaf=10,l2_regularization=1.,
        early_stopping=False,random_state=seed),{'max_depth':plan['boost_depths'],'max_iter':plan['boost_iterations']},
        cv=folds,scoring='neg_brier_score',error_score='raise').fit(x,y)
    models['boosted'] = (tree.best_estimator_,full)
    records['boosted'] = dict(kind='boosted',parameters=tree.best_params_,
        cv_params=tree.cv_results_['params'],cv_means=tree.cv_results_['mean_test_score'].tolist(),
        cv_selected=int(tree.best_index_))
    if include_oracle and scenario=='dense_control':
        np.testing.assert_allclose(records['oracle']['coefficients'],records['full_logit']['coefficients'],atol=0,rtol=0)
    return models,dict(models=records,folds=[dict(train=train.tolist(),held=held.tolist()) for train,held in folds],seed=seed)


def highdim_weighted_models(source,base_c,feature_sets,strengths):
    x,y = 2*np.asarray(source['x'])-1,np.asarray(source['y'])
    models,records = {},{}
    for name,kept in feature_sets.items():
        for index,strength in enumerate(strengths):
            weights = np.asarray([1. if column<2 or column in kept else 1.+strength for column in range(x.shape[1])])
            scale = np.sqrt(weights)
            model = LogisticRegression(C=base_c,l1_ratio=0.,solver='newton-cholesky',
                max_iter=10000,tol=1e-10,fit_intercept=True).fit(x/scale,y)
            model.coef_[0] /= scale
            probability = model.predict_proba(x)[:,1]
            residual = x.T@(probability-y)+weights/base_c*model.coef_[0]
            maximum = max(float(abs(residual).max()),float(abs(np.sum(probability-y))))
            if maximum>1e-3:
                raise ValueError('加权来源逻辑回归没有满足最优性条件')
            key = f'{name}:{index}'
            models[key] = model,list(range(x.shape[1]))
            records[key] = dict(coefficients=np.r_[model.intercept_,model.coef_[0]].tolist(),
                C=base_c,weights=weights.tolist(),strength=strength,kept=list(kept),maximum_kkt_residual=maximum)
    return models,records


def highdim_prediction(model,x):
    fitted,features = model
    data = (2*np.asarray(x)-1)[:,features]
    if isinstance(fitted,HistGradientBoostingRegressor):
        return fitted.predict(data)
    return fitted.predict_proba(data)[:,1]


def highdim_adaptation(models,data,plan):
    fit_data,calibration,ranking = (data[key] for key in ('fit','calibration','ranking'))
    design = lambda x: np.column_stack((np.ones(len(x)),2*np.asarray(x)-1))
    xf,xc,xr = (design(row['x']) for row in (fit_data,calibration,ranking))
    results = {}
    for name,model in models.items():
        fit_prediction,cal_prediction,rank_prediction = (highdim_prediction(model,row['x']) for row in (fit_data,calibration,ranking))
        residual = fit_data['y']-fit_prediction
        candidates = []
        for penalty in plan['correction_penalties']:
            coefficients = Ridge(alpha=penalty,fit_intercept=False,solver='cholesky').fit(xf,residual).coef_
            independent = np.linalg.solve(xf.T@xf+penalty*np.eye(xf.shape[1]),xf.T@residual)
            np.testing.assert_allclose(coefficients,independent,atol=1e-10)
            prediction = np.clip(cal_prediction+xc@coefficients,0,1)
            candidates.append(dict(penalty=penalty,coefficients=coefficients.tolist(),
                loss=float(np.mean((calibration['y']-prediction)**2))))
        selected = min(range(len(candidates)),key=lambda i:(candidates[i]['loss'],i))
        prediction = np.clip(rank_prediction+xr@candidates[selected]['coefficients'],0,1)
        scores = 2*(2*ranking['a']-1)*(ranking['y']-prediction)
        results[name] = dict(candidates=candidates,selected=selected,effect=float(scores.mean()),
            standard_error=float(scores.std(ddof=1)/np.sqrt(len(scores))),
            source_predictions=dict(fit=fit_prediction.tolist(),calibration=cal_prediction.tolist(),ranking=rank_prediction.tolist()))
    return results


def highdim_integrate(models,adaptation,scenario,plan,seed,ranking_size,permutation,sampler=highdim_draw,comparison_pairs=None):
    rng = np.random.default_rng(seed)
    names = list(models)
    sums = {name:np.zeros(3) for name in [*names,'bayes']}
    pairs = [(name,'oracle',name) for name in plan['primary_comparators']] if comparison_pairs is None else [
        (tested+'|'+baseline,tested,baseline) for tested,baseline in comparison_pairs]
    differences = {key:np.zeros(2) for key,_,_ in pairs}
    tau_sum,tau_square = 0.,0.
    remaining = plan['test_covariates']
    while remaining:
        size = min(remaining,plan['test_batch_size'])
        sample = sampler(rng,size,1,scenario,plan,permutation,outcomes=False)
        g,tau = sample['average'],sample['effect']
        matrix = np.column_stack((np.ones(size),2*sample['x']-1))
        values = {}
        for name in names:
            record = adaptation[name]
            correction = record['candidates'][record['selected']]['coefficients']
            prediction = np.clip(highdim_prediction(models[name],sample['x'])+matrix@correction,0,1)
            values[name] = g*(1-prediction)**2+(1-g)*prediction**2
        values['bayes'] = g*(1-g)
        for name,value in values.items():
            sums[name] += [value.sum(),value@value,value@tau]
        for key,tested,baseline in pairs:
            difference = values[baseline]-values[tested]
            differences[key] += [difference.sum(),difference@difference]
        tau_sum += tau.sum()
        tau_square += tau@tau
        remaining -= size
    count = plan['test_covariates']
    truth = tau_sum/count
    tau_variance = (tau_square-tau_sum**2/count)/(count-1)
    truth_squared = truth**2-tau_variance/count
    risks,errors = {},{}
    for name,(total,square,cross) in sums.items():
        mean = total/count
        risks[name] = float((4*mean-truth_squared)/ranking_size)
        influence_sum = 4*total-2*truth*tau_sum
        influence_square = 16*square+4*truth**2*tau_square-16*truth*cross
        variance = max(0.,(influence_square-influence_sum**2/count)/(count-1))
        errors[name] = float(np.sqrt(variance/count)/ranking_size)
    paired = {name:float(4*np.sqrt(max(0.,(square-total**2/count)/(count-1))/count)/ranking_size)
        for name,(total,square) in differences.items()}
    return dict(risks=risks,integration_standard_errors=errors,paired_integration_standard_errors=paired,
        truth=float(truth),truth_standard_error=float(np.sqrt(tau_variance/count)),
        test_seed=seed,test_covariates=count,raw_sums={name:value.tolist() for name,value in sums.items()},
        difference_sums={name:value.tolist() for name,value in differences.items()},tau_sum=float(tau_sum),tau_square=float(tau_square))


def merged_attribute_layout(plan):
    lengths = plan['precursor_lengths']
    if len(lengths)!=8 or sum(lengths)!=24 or any(type(length) is not int or length<1 for length in lengths):
        raise ValueError('汇合机制的前驱数量无效')
    branches,offset = [],0
    for length in lengths:
        branches.append(dict(precursors=list(range(offset,offset+length)),terminal=offset+length,
            proxy=offset+length+1,intermediate=offset+length+2,noise_leaf=offset+length+3))
        offset += length+4
    if offset!=56:
        raise ValueError('汇合机制的属性数量不同')
    return branches


def merged_attribute_graph(plan,permutation):
    branches = merged_attribute_layout(plan)
    inverse = np.argsort(permutation)+2
    graph = nx.DiGraph()
    graph.add_nodes_from(range(66))
    bidirected = []
    for index,branch in enumerate(branches):
        sequence = [index%2,*[int(inverse[key]) for key in branch['precursors']]]
        graph.add_edges_from(zip(sequence,sequence[1:]))
        terminal = int(inverse[branch['terminal']])
        graph.add_edge(int(inverse[branch['precursors'][-1]]),terminal)
        graph.add_edge(int(inverse[branches[(index+1)%8]['precursors'][-1]]),terminal)
        proxy = int(inverse[branch['proxy']])
        graph.add_edges_from(((proxy,int(inverse[branch['intermediate']])),
            (int(inverse[branch['intermediate']]),int(inverse[branch['noise_leaf']]))))
        bidirected.append((int(inverse[branch['precursors'][0]]),proxy))
    if not nx.is_directed_acyclic_graph(graph):
        raise ValueError('汇合机制存在有向环')
    pag = np.zeros((66,66),dtype=int)
    for source,target in graph.edges:
        pag[source,target],pag[target,source] = 2,3
    for source,target in bidirected:
        if nx.has_path(graph,source,target) or nx.has_path(graph,target,source):
            raise ValueError('潜在共同原因不符合祖先图边界')
        pag[source,target]=pag[target,source]=2
    return dict(status='evaluated',pag=pag.tolist(),method='TRUE_ATTRIBUTE_GRAPH_DIAGNOSTIC',
        estimated_jci_searches=0,directed_edges=list(graph.edges),bidirected_edges=bidirected)


def attribute_geometry_shapes(graph,context,context_strength):
    if graph['status']!='evaluated':
        complete = list(range(2,66))
        return dict(background=complete,skeleton=[complete for _ in range(6)],propagated=[complete for _ in range(10)])
    adjacency = np.asarray(graph['pag'])!=0
    network = nx.from_numpy_array(adjacency)
    distances = [nx.single_source_shortest_path_length(network,root) for root in (0,1)]
    members = sorted(set().union(*(set(values) for values in distances))-{0,1})
    responsive = sorted(set(members)&set(context))
    degrees = adjacency.sum(axis=1)
    distance = {index:min(values.get(index,67) for values in distances) for index in members}
    median = float(np.median([distance[index] for index in responsive])) if responsive else None
    geometry = [members,responsive,[index for index in responsive if degrees[index]<=2],
        [index for index in responsive if degrees[index]>=3],
        [index for index in responsive if distance[index]>=median] if responsive else [],
        [index for index in responsive if distance[index]<=median] if responsive else []]
    transition = adjacency/np.maximum(1,degrees[:,None])
    strength = np.r_[1.,1.,np.asarray(context_strength)]
    propagated = list(geometry)
    for alpha in (.5,.9):
        score = np.linalg.solve(np.eye(66)-alpha*transition,(1-alpha)*strength)
        ranked = sorted(members,key=lambda index:(-score[index],index))
        propagated.extend(sorted(ranked[:count]) for count in (8,16))
    return dict(background=members,skeleton=geometry,propagated=propagated)


def merged_attribute_draw(rng,size,environment,scenario,plan,permutation,outcomes=True):
    if scenario not in ('downstream_signal','target_new_attribute','upstream_control') or sorted(permutation)!=list(range(64)):
        raise ValueError('汇合机制名称或属性位置无效')
    context_strength = plan.get('context_effect_strength',.30)
    measurement_error = plan.get('attribute_measurement_flip_probability',0.)
    if not 0<=context_strength<=.30 or not 0<=measurement_error<.5:
        raise ValueError('上下文强度或属性测量误差无效')
    q = plan['context_source_probabilities'] if environment==0 else plan['context_target_probabilities']
    contexts = rng.binomial(1,np.asarray(q),size=(size,2))
    raw = np.empty((size,64),dtype=int)
    branches = merged_attribute_layout(plan)
    for index,branch in enumerate(branches):
        latent = rng.binomial(1,.5,size)
        first,*following = branch['precursors']
        raw[:,first] = rng.binomial(1,.05+context_strength*contexts[:,index%2]+.60*latent)
        previous = first
        for current in following:
            raw[:,current] = rng.binomial(1,.20+.60*raw[:,previous])
            previous = current
        raw[:,branch['proxy']] = rng.binomial(1,.05+.90*latent)
        raw[:,branch['intermediate']] = rng.binomial(1,.20+.60*raw[:,branch['proxy']])
        raw[:,branch['noise_leaf']] = rng.binomial(1,.20+.60*raw[:,branch['intermediate']])
    for index,branch in enumerate(branches):
        raw[:,branch['terminal']] = rng.binomial(1,.10+.40*raw[:,branch['precursors'][-1]]
            +.40*raw[:,branches[(index+1)%8]['precursors'][-1]])
    raw[:,56:] = rng.binomial(1,.5,size=(size,8))
    positions = [branch['precursors'][0] if scenario=='upstream_control' else branch['terminal'] for branch in branches]
    score = (2*raw[:,positions]-1).sum(axis=1).astype(float)
    if scenario=='target_new_attribute' and environment==1:
        score = .7*score+.8*(2*raw[:,branches[0]['noise_leaf']]-1)
    average = expit(score)
    effect = plan['effect_multiplier']*average*(1-average)
    output = dict(x=np.column_stack((contexts,raw[:,permutation])),average=average,effect=effect)
    if measurement_error:
        output['x'][:,2:] ^= rng.binomial(1,measurement_error,size=(size,64))
    if outcomes:
        assigned = rng.binomial(1,.5,size)
        probability = average+(assigned-.5)*effect
        if np.any((probability<=0)|(probability>=1)):
            raise ValueError('汇合机制结果概率无效')
        output.update(a=assigned,y=rng.binomial(1,probability))
    return output


def attribute_draw(rng,size,environment,scenario,plan,permutation,outcomes=True):
    if plan.get('attribute_topology')=='merged':
        return merged_attribute_draw(rng,size,environment,scenario,plan,permutation,outcomes)
    if scenario not in ('downstream_signal','target_new_attribute','upstream_control'):
        raise ValueError('结果测量前属性机制名称无效')
    q = plan['context_source_probabilities'] if environment==0 else plan['context_target_probabilities']
    contexts = rng.binomial(1,np.asarray(q),size=(size,2))
    attributes = np.empty((size,64),dtype=int)
    for branch in range(8):
        offset = 6*branch
        latent = rng.binomial(1,.5,size)
        attributes[:,offset] = rng.binomial(1,.05+.30*contexts[:,branch%2]+.60*latent)
        attributes[:,offset+1] = rng.binomial(1,.20+.60*attributes[:,offset])
        attributes[:,offset+2] = rng.binomial(1,.20+.60*attributes[:,offset+1])
        attributes[:,offset+3] = rng.binomial(1,.05+.90*latent)
        attributes[:,offset+4] = rng.binomial(1,.20+.60*attributes[:,offset+3])
        attributes[:,offset+5] = rng.binomial(1,.20+.60*attributes[:,offset+4])
    attributes[:,48:] = rng.binomial(1,.5,size=(size,16))
    positions = np.arange(0 if scenario=='upstream_control' else 2,48,6)
    linear = (2*attributes[:,positions]-1).sum(axis=1).astype(float)
    if scenario=='target_new_attribute' and environment==1:
        linear = .7*linear+.8*(2*attributes[:,5]-1)
    average = expit(linear)
    effect = plan['effect_multiplier']*average*(1-average)
    if sorted(permutation)!=list(range(64)):
        raise ValueError('属性列序无效')
    output = dict(x=np.column_stack((contexts,attributes[:,permutation])),average=average,effect=effect)
    if outcomes:
        a = rng.binomial(1,.5,size)
        probability = average+(a-.5)*effect
        if np.any((probability<=0)|(probability>=1)):
            raise ValueError('结果机制概率无效')
        output.update(a=a,y=rng.binomial(1,probability))
    return output


def attribute_weighted_cv(source,folds,shape_catalog,plan):
    x,y = 2*np.asarray(source['x'])-1,np.asarray(source['y'])
    models,records = {},{}
    for name,shapes in shape_catalog.items():
        groups,fitted = [],[]
        for shape,kept in enumerate(shapes):
            for strength in plan['structure_strengths']:
                weights = np.asarray([1. if index<2 or index in kept else 1.+strength for index in range(66)])
                scale = np.sqrt(weights)
                model = LogisticRegressionCV(Cs=plan['inverse_penalties'],l1_ratios=[0.],cv=folds,
                    scoring='neg_brier_score',solver='newton-cholesky',max_iter=10000,tol=1e-10,
                    fit_intercept=True,use_legacy_attributes=False).fit(x/scale,y)
                paths = model.coefs_paths_[:,0,:,0,:].copy()
                paths[:,:,:-1] /= scale
                scores = model.scores_[:,0,:].copy()
                model.coef_[0] /= scale
                coefficient = np.r_[model.intercept_,model.coef_[0]]
                probability = model.predict_proba(x)[:,1]
                gradient = x.T@(probability-y)+weights/model.C_*coefficient[1:]
                maximum = max(float(abs(gradient).max()),float(abs(np.sum(probability-y))))
                if maximum>1e-3:
                    raise ValueError('结构预测器最终解未满足最优性条件')
                groups.append(dict(shape=shape,kept=list(kept),strength=strength,weights=weights.tolist(),
                    C=float(model.C_),coefficients=coefficient.tolist(),cv_paths=paths.tolist(),cv_scores=scores.tolist(),
                    maximum_kkt_residual=maximum))
                fitted.append(model)
        losses = [-float(np.asarray(group['cv_scores']).mean(axis=0).max()) for group in groups]
        selected = min(range(len(groups)),key=lambda index:(losses[index],index))
        models[name] = fitted[selected],list(range(66))
        records[name] = dict(kind='weighted_logit',groups=groups,losses=losses,selected=selected,
            coefficients=groups[selected]['coefficients'],features=list(range(66)))
    return models,records


def attribute_pca_model(auxiliary,source,folds,plan):
    x,y = 2*np.asarray(source['x'])-1,np.asarray(source['y'])
    transforms = [FrozenEstimator(PCA(n_components=dimension,svd_solver='full').fit(2*auxiliary-1))
        for dimension in plan['pca_dimensions']]
    pipeline = Pipeline([('basis',transforms[0]),
        ('model',LogisticRegression(l1_ratio=0.,solver='newton-cholesky',tol=1e-10,max_iter=10000))])
    search = GridSearchCV(pipeline,{'basis':transforms,'model__C':plan['inverse_penalties']},cv=folds,
        scoring='neg_brier_score',error_score='raise').fit(x,y)
    selected = search.best_estimator_
    basis,fitted = selected.named_steps['basis'].estimator,selected.named_steps['model']
    raw_coefficient = fitted.coef_[0]@basis.components_
    raw_intercept = float(fitted.intercept_[0]-basis.mean_@raw_coefficient)
    parameters = [dict(dimension=int(row['basis'].estimator.n_components),C=float(row['model__C']))
        for row in search.cv_results_['params']]
    record = dict(kind='pca',coefficients=[raw_intercept,*raw_coefficient.tolist()],features=list(range(66)),
        components=basis.components_.tolist(),mean=basis.mean_.tolist(),eigenvalues=basis.explained_variance_.tolist(),
        pc_coefficients=[float(fitted.intercept_[0]),*fitted.coef_[0].tolist()],C=float(fitted.C),
        cv_params=parameters,cv_means=search.cv_results_['mean_test_score'].tolist(),cv_selected=int(search.best_index_),
        cv_split_scores=[search.cv_results_[f'split{index}_test_score'].tolist() for index in range(len(folds))])
    return (selected,list(range(66))),record


def attribute_target_selection(models,data,plan):
    augmented = {name:model for name,model in models.items()}
    augmented.update({name+'__full':models['full_logit'] for name in models})
    all_adaptations = highdim_adaptation(augmented,data,plan)
    selected_models,selected_adaptations,choices = {},{},{}
    for name in models:
        candidates = [name,name+'__full']
        selected = min(candidates,key=lambda key:(all_adaptations[key]['candidates'][all_adaptations[key]['selected']]['loss'],candidates.index(key)))
        selected_models[name] = augmented[selected]
        selected_adaptations[name] = all_adaptations[selected]
        choices[name] = selected
    return selected_models,selected_adaptations,dict(candidates=all_adaptations,choices=choices)


def attribute_comparison_family(plan):
    local = len(plan['scenarios'])*(2*len(plan['primary_comparators'])+len(plan['structural_comparators']))
    family = plan.get('comparison_family_size',local)
    if type(family) is not int or family<local or not 0<plan['component_alpha']<1:
        raise ValueError('比较家族或错误概率无效')
    return family


def attribute_budget_curve(plan,summaries):
    sizes = plan['target_sizes']
    baselines = plan['primary_comparators']+plan['structural_comparators']
    same = [dict(target_size=size,**comparison) for size in sizes
        for comparison in summaries[size]['comparisons']]
    family = len(same)+len(plan['scenarios'])*len(baselines)*len(plan['cross_budget_pairs'])
    if family!=attribute_comparison_family(plan):
        raise ValueError('完整预算比较家族不匹配')
    cross = []
    for lower,upper in plan['cross_budget_pairs']:
        for scenario in plan['scenarios']:
            left = {(row['batch'],row['repetition']):row for row in summaries[lower]['rows'] if row['scenario']==scenario}
            right = {(row['batch'],row['repetition']):row for row in summaries[upper]['rows'] if row['scenario']==scenario}
            keys = sorted(left)
            if set(left)!=set(right) or len(keys)!=2*plan['repetitions_per_batch']:
                raise ValueError('跨预算配对单元不完整')
            for baseline in baselines:
                values = np.asarray([right[key]['risks'][baseline]-left[key]['risks']['jci'] for key in keys])
                mean = float(values.mean())
                base = float(np.mean([right[key]['risks'][baseline] for key in keys]))
                radius = float(t.ppf(1-plan['component_alpha']/(2*family),len(keys)-1)*values.std(ddof=1)/np.sqrt(len(keys)))
                batches = [float(np.mean([value for value,key in zip(values,keys,strict=True) if key[0]==batch])) for batch in (0,1)]
                error = max(left[key]['mc_errors']['jci']+right[key]['mc_errors'][baseline] for key in keys)
                supported = mean-radius>5*error and min(batches)>0
                cross.append(dict(scenario=scenario,tested='jci',baseline=baseline,
                    lower_target_size=lower,upper_target_size=upper,repetitions=len(keys),difference=mean,
                    relative_reduction=mean/base,interval=[mean-radius,mean+radius],batch_differences=batches,
                    maximum_integration_error_bound=error,supported=bool(supported),
                    lower_target_outcomes=4*lower,upper_target_outcomes=4*upper,
                    target_budget_reduction=1-lower/upper,
                    total_outcome_budget_reduction=1-(plan['source_size']+4*lower)/(plan['source_size']+4*upper)))
    primary = [row for row in same if row['target_size']==plan['primary_target_size']
        and row['scenario']=='downstream_signal' and row['tested']=='jci']
    efficiency = [row for row in cross if [row['lower_target_size'],row['upper_target_size']]==plan['primary_cross_budget_pair']
        and row['scenario']=='downstream_signal']
    return dict(evidence_role=plan['evidence_role'],comparison_family_size=family,
        same_budget_comparisons=same,cross_budget_comparisons=cross,
        low_budget_variance_gain=len(primary)==len(baselines) and all(row['supported'] for row in primary),
        half_target_budget_gain=len(efficiency)==len(baselines) and all(row['supported'] for row in efficiency),
        independent_source_learning_units=len(summaries[sizes[0]]['rows']),
        budget_cells=sum(len(summaries[size]['rows']) for size in sizes),tsg_gain_established=False,
        formal_claim_allowed=False,new_provider_calls=0)


def attribute_estimation_diagnostics(cell, plan):
    ranking = cell['data']['ranking']
    x = np.column_stack((np.ones(len(ranking['x'])), 2 * np.asarray(ranking['x']) - 1))
    truth = cell['integrated']['truth']
    truth_margin = 5 * cell['integrated']['truth_standard_error']
    methods = ['jci', *plan['primary_comparators'], *plan['structural_comparators']]
    estimates = {}
    for name in methods:
        chosen = cell['selection']['choices'][name]
        model = cell['selection']['candidates'][chosen]
        correction = model['candidates'][model['selected']]['coefficients']
        prediction = np.clip(np.asarray(model['source_predictions']['ranking']) + x @ correction, 0, 1)
        scores = 2 * (2 * np.asarray(ranking['a']) - 1) * (np.asarray(ranking['y']) - prediction)
        estimate = float(scores.mean())
        standard_error = float(scores.std(ddof=1) / np.sqrt(len(scores)))
        np.testing.assert_allclose([estimate, standard_error], [model['effect'], model['standard_error']], atol=1e-12)
        low, high = estimate - norm.ppf(.975) * standard_error, estimate + norm.ppf(.975) * standard_error
        if low <= truth - truth_margin and truth + truth_margin <= high:
            coverage = 'covered'
        elif high < truth - truth_margin or low > truth + truth_margin:
            coverage = 'not_covered'
        else:
            coverage = 'integration_boundary_unknown'
        estimates[name] = dict(estimate=estimate, standard_error=standard_error, integrated_truth=truth,
            estimation_error=estimate - truth, squared_error=(estimate - truth) ** 2,
            conditional_variance=cell['integrated']['risks'][name], coverage=coverage,
            full_predictor_selected=chosen.endswith('__full'))
    estimated = np.asarray(cell['graph']['pag'])
    underlying = np.asarray(merged_attribute_graph(plan, cell['permutation'])['pag'])
    directed = (estimated == 2) & (estimated.T == 3)
    correct = directed & (underlying == 2) & (underlying.T == 3)
    clean_observation = plan.get('attribute_measurement_flip_probability', 0.) == 0
    return dict(estimates=estimates, direction_status=cell['direction_checks']['status'],
        definite_directed_edges=int(directed.sum()),
        disagreements_with_noiseless_mechanism=int(directed.sum() - correct.sum()),
        observed_graph_truth_available=clean_observation,
        tsg_accuracy_measured=False, coverage_interval='normal_wald_95_descriptive',
        integration_truth_margin=truth_margin)

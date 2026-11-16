"""Context-anchored directional JCI discovery and task-unit K-fold cross-fitted learning."""

from __future__ import annotations

import itertools
import platform
import warnings
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import networkx as nx
import numpy as np
import scipy
import sklearn
from scipy.special import expit, logit
from scipy.stats import norm, t
from sklearn.decomposition import PCA
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression, LogisticRegressionCV, Ridge
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_bundle
from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation, StructureBackend
from prompt_mechanism_study.experiment.assignment import task_unit_folds


SCENARIOS = ('downstream_signal', 'target_new_attribute', 'upstream_control', 'misaligned_signal')
SCENARIO_OUTCOME_ROLE = dict(
    downstream_signal='terminal',
    target_new_attribute='terminal',
    upstream_control='root',
    misaligned_signal='intermediate',
)
PRIMARY_COMPARATORS = (
    'direct_uniform',
    'direct_context',
    'full_logit',
    'sparse_logit',
    'screened_logit',
    'boosted',
    'pca',
)
STRUCTURAL_COMPARATORS = ('skeleton_background', 'shuffled', 'propagated_skeleton')


def merged_attribute_layout(plan):
    lengths = plan['precursor_lengths']
    if len(lengths) != 8 or sum(lengths) != 24 or any(type(length) is not int or length < 1 for length in lengths):
        raise ValueError('Confluence mechanism requires 8 branches with 24 total precursor nodes')
    branches, offset = [], 0
    for length in lengths:
        branches.append(
            dict(
                precursors=list(range(offset, offset + length)),
                terminal=offset + length,
                proxy=offset + length + 1,
                intermediate=offset + length + 2,
                noise_leaf=offset + length + 3,
            )
        )
        offset += length + 4
    if offset != 56:
        raise ValueError('Confluence mechanism branch layout must total 56 structural attributes')
    return branches


def merged_attribute_graph(plan, permutation):
    branches = merged_attribute_layout(plan)
    inverse = np.argsort(permutation) + 2
    graph = nx.DiGraph()
    graph.add_nodes_from(range(66))
    bidirected = []
    for index, branch in enumerate(branches):
        sequence = [index % 2, *[int(inverse[key]) for key in branch['precursors']]]
        graph.add_edges_from(zip(sequence, sequence[1:]))
        terminal = int(inverse[branch['terminal']])
        graph.add_edge(int(inverse[branch['precursors'][-1]]), terminal)
        graph.add_edge(int(inverse[branches[(index + 1) % 8]['precursors'][-1]]), terminal)
        proxy = int(inverse[branch['proxy']])
        graph.add_edges_from(
            (
                (proxy, int(inverse[branch['intermediate']])),
                (int(inverse[branch['intermediate']]), int(inverse[branch['noise_leaf']])),
            )
        )
        bidirected.append((int(inverse[branch['precursors'][0]]), proxy))
    if not nx.is_directed_acyclic_graph(graph):
        raise ValueError('True confluence DAG contains a cycle')
    pag = np.zeros((66, 66), dtype=int)
    for source, target in graph.edges:
        pag[source, target], pag[target, source] = 2, 3
    for source, target in bidirected:
        if nx.has_path(graph, source, target) or nx.has_path(graph, target, source):
            raise ValueError('Latent confounder pair violates ancestral graph boundary')
        pag[source, target] = pag[target, source] = 2
    return dict(
        status='evaluated',
        pag=pag.tolist(),
        method='TRUE_ATTRIBUTE_GRAPH_DIAGNOSTIC',
        estimated_jci_searches=0,
        directed_edges=list(graph.edges),
        bidirected_edges=bidirected,
    )


def draw_merged_attributes(rng, size, environment, scenario, plan, permutation, outcomes=True):
    if scenario not in SCENARIOS or sorted(permutation) != list(range(64)):
        raise ValueError('Invalid scenario name or attribute permutation')
    context_strength = plan.get('context_effect_strength', 0.30)
    measurement_error = plan.get('attribute_measurement_flip_probability', 0.0)
    if not 0 <= context_strength <= 0.30 or not 0 <= measurement_error < 0.5:
        raise ValueError('Context strength or attribute measurement error is out of bounds')
    q = plan['context_source_probabilities'] if environment == 0 else plan['context_target_probabilities']
    contexts = rng.binomial(1, np.asarray(q), size=(size, 2))
    raw = np.empty((size, 64), dtype=int)
    branches = merged_attribute_layout(plan)
    for index, branch in enumerate(branches):
        latent = rng.binomial(1, 0.5, size)
        first, *following = branch['precursors']
        raw[:, first] = rng.binomial(1, 0.05 + context_strength * contexts[:, index % 2] + 0.60 * latent)
        previous = first
        for current in following:
            raw[:, current] = rng.binomial(1, 0.20 + 0.60 * raw[:, previous])
            previous = current
        raw[:, branch['proxy']] = rng.binomial(1, 0.05 + 0.90 * latent)
        raw[:, branch['intermediate']] = rng.binomial(1, 0.20 + 0.60 * raw[:, branch['proxy']])
        raw[:, branch['noise_leaf']] = rng.binomial(1, 0.20 + 0.60 * raw[:, branch['intermediate']])
    for index, branch in enumerate(branches):
        raw[:, branch['terminal']] = rng.binomial(
            1,
            0.10 + 0.40 * raw[:, branch['precursors'][-1]] + 0.40 * raw[:, branches[(index + 1) % 8]['precursors'][-1]],
        )
    raw[:, 56:] = rng.binomial(1, 0.5, size=(size, 8))
    # Outcome-relevant attribute per branch. `misaligned_signal` is a negative control: the outcome
    # loads only on latent-confounded proxy-chain intermediates, which are never context-reachable
    # (true role V_other), so no structural profile in the JCI menu matches the outcome mechanism.
    role_key = SCENARIO_OUTCOME_ROLE[scenario]
    positions = [branch['precursors'][0] if role_key == 'root' else branch[role_key] for branch in branches]
    score = (2 * raw[:, positions] - 1).sum(axis=1).astype(float)
    if scenario == 'target_new_attribute' and environment == 1:
        score = 0.7 * score + 0.8 * (2 * raw[:, branches[0]['noise_leaf']] - 1)
    average = expit(score)
    effect = plan['effect_multiplier'] * average * (1 - average)
    output = dict(x=np.column_stack((contexts, raw[:, permutation])), average=average, effect=effect)
    if measurement_error:
        output['x'][:, 2:] ^= rng.binomial(1, measurement_error, size=(size, 64))
    if outcomes:
        assigned = rng.binomial(1, 0.5, size)
        probability = average + (assigned - 0.5) * effect
        if np.any((probability <= 0) | (probability >= 1)):
            raise ValueError('Mechanism outcome probability out of (0, 1)')
        output.update(a=assigned, y=rng.binomial(1, probability))
    return output


def attribute_direction_checks(graph):
    if graph['status'] != 'evaluated':
        return dict(
            status='unavailable',
            eligible=False,
            cyclic_components=[],
            arrowhead_conflicts=[],
            context_conflicts=[],
        )
    pag = np.asarray(graph['pag'])
    if (
        pag.shape != (66, 66)
        or np.any(~np.isin(pag, [0, 1, 2, 3]))
        or np.any((pag != 0) != (pag.T != 0))
        or np.any(np.diag(pag))
    ):
        raise ValueError('Invalid PAG matrix dimensions or endpoint marks')
    directed = nx.DiGraph()
    directed.add_nodes_from(range(66))
    directed.add_edges_from((int(a), int(b)) for a, b in np.argwhere((pag == 2) & (pag.T == 3)))
    components = sorted(
        sorted(component) for component in nx.strongly_connected_components(directed) if len(component) > 1
    )
    conflicts = [(int(a), int(b)) for a, b in np.argwhere(pag == 2) if nx.has_path(directed, int(b), int(a))]
    context_conflicts = np.argwhere(pag[:, :2] == 2).tolist()
    eligible = not components and not conflicts and not context_conflicts and pag[0, 1] == 0
    return dict(
        status='passed' if eligible else 'invalid',
        eligible=bool(eligible),
        cyclic_components=components,
        arrowhead_conflicts=[list(pair) for pair in conflicts],
        context_conflicts=context_conflicts,
    )


def pag_role_groups(graph):
    """Decompose context-reachable attributes into canonical JCI entry/exit roles."""
    if graph['status'] != 'evaluated':
        return dict(
            eligible=False,
            leaves=list(range(2, 66)),
            root=[],
            terminal=[],
            upstream=[],
            other=list(range(2, 66)),
            reachable=[],
        )
    pag = np.asarray(graph['pag'])
    if pag.shape != (66, 66) or np.any((pag != 0) != (pag.T != 0)) or np.any(np.diag(pag)):
        raise ValueError('Invalid PAG adjacency matrix')
    skeleton = nx.from_numpy_array((pag != 0).astype(int))
    connected = nx.node_connected_component(skeleton, 0) | nx.node_connected_component(skeleton, 1)
    leaves = sorted(node for node in connected if node >= 2 and skeleton.degree(node) == 1)
    if not attribute_direction_checks(graph)['eligible']:
        return dict(
            eligible=False,
            leaves=leaves,
            root=[],
            terminal=[],
            upstream=[],
            other=list(range(2, 66)),
            reachable=[],
        )
    directed = nx.DiGraph()
    directed.add_nodes_from(range(66))
    directed.add_edges_from((int(left), int(right)) for left, right in np.argwhere((pag == 2) & (pag.T == 3)))
    root = sorted((set(directed.successors(0)) | set(directed.successors(1))) - {0, 1})
    reachable = sorted((nx.descendants(directed, 0) | nx.descendants(directed, 1)) - {0, 1})
    reachable_set = set(reachable)
    terminal = sorted(node for node in reachable if not (set(directed.successors(node)) & reachable_set))
    upstream = sorted(reachable_set - set(terminal))
    other = sorted(set(range(2, 66)) - reachable_set)
    return dict(
        eligible=True,
        leaves=leaves,
        root=root,
        terminal=terminal,
        upstream=upstream,
        other=other,
        reachable=reachable,
    )


def role_weight_profiles(roles, strengths):
    """Build role-grouped penalty weight vectors (uniform fallback + root/upstream/downstream/reachable)."""
    profiles = [dict(profile='uniform', strength=0.0, kept=list(range(2, 66)), weights=[1.0] * 66)]
    if not roles['reachable']:
        return profiles
    role_sets = [
        ('downstream', roles['terminal']),
        ('root', roles.get('root', [])),
        ('upstream', roles['upstream']),
        ('reachable', sorted(set(roles['terminal']) | set(roles['upstream']))),
    ]
    for strength in strengths:
        if strength <= 0:
            continue
        seen_kept = set()
        for name, kept in role_sets:
            kept_tuple = tuple(kept)
            if not kept_tuple or len(kept_tuple) == 64 or kept_tuple in seen_kept:
                continue
            seen_kept.add(kept_tuple)
            kept_set = set(kept_tuple)
            weights = [1.0 if idx < 2 or idx in kept_set else 1.0 + float(strength) for idx in range(66)]
            profiles.append(dict(profile=name, strength=float(strength), kept=list(kept_tuple), weights=weights))
    return profiles


def attribute_geometry_shapes(graph, context, context_strength):
    if graph['status'] != 'evaluated':
        complete = list(range(2, 66))
        return dict(background=complete, skeleton=[complete for _ in range(6)], propagated=[complete for _ in range(10)])
    adjacency = np.asarray(graph['pag']) != 0
    network = nx.from_numpy_array(adjacency)
    distances = [nx.single_source_shortest_path_length(network, root) for root in (0, 1)]
    members = sorted(set().union(*(set(values) for values in distances)) - {0, 1})
    responsive = sorted(set(members) & set(context))
    degrees = adjacency.sum(axis=1)
    distance = {index: min(values.get(index, 67) for values in distances) for index in members}
    median = float(np.median([distance[index] for index in responsive])) if responsive else None
    geometry = [
        members,
        responsive,
        [index for index in responsive if degrees[index] <= 2],
        [index for index in responsive if degrees[index] >= 3],
        [index for index in responsive if distance[index] >= median] if responsive else [],
        [index for index in responsive if distance[index] <= median] if responsive else [],
    ]
    transition = adjacency / np.maximum(1, degrees[:, None])
    strength = np.r_[1.0, 1.0, np.asarray(context_strength)]
    propagated = list(geometry)
    for alpha in (0.5, 0.9):
        score = np.linalg.solve(np.eye(66) - alpha * transition, (1 - alpha) * strength)
        ranked = sorted(members, key=lambda index: (-score[index], index))
        propagated.extend(sorted(ranked[:count]) for count in (8, 16))
    return dict(background=members, skeleton=geometry, propagated=propagated)


def certify_logistic_coefficients(x, y, coefficient, inverse, ratio):
    if not np.any(coefficient[:-1]):
        coefficient[-1] = logit(np.clip(y.mean(), 1e-12, 1.0 - 1e-12))
    probability = expit(x @ coefficient[:-1] + coefficient[-1])
    gradient = x.T @ (probability - y) + (1.0 - ratio) / inverse * coefficient[:-1]
    nonzero = coefficient[:-1] != 0
    gradient[nonzero] += ratio / inverse * np.sign(coefficient[:-1][nonzero])
    violation = np.abs(gradient)
    violation[~nonzero] = np.maximum(violation[~nonzero] - ratio / inverse, 0.0)
    if max(float(violation.max()), float(abs(np.sum(probability - y)))) > 1e-3:
        raise ValueError('Penalized logistic regression failed KKT optimality tolerance')
    return coefficient


def _logistic_kkt_residual(x, y, coef, intercept, inverse, ratio):
    probability = expit(x @ coef + intercept)
    gradient = x.T @ (probability - y) + (1.0 - ratio) / inverse * coef
    nonzero = coef != 0
    gradient[nonzero] += ratio / inverse * np.sign(coef[nonzero])
    violation = np.abs(gradient)
    violation[~nonzero] = np.maximum(violation[~nonzero] - ratio / inverse, 0.0)
    return max(float(violation.max()), float(abs(np.sum(probability - y))))


def _fit_elastic_net_logistic(x, y, inverse, ratio, *, init=None, tol=1e-5, max_iter=5000):
    """Deterministic accelerated proximal gradient (FISTA with restart) for Elastic-Net logistic regression."""
    n, d = x.shape
    design = np.column_stack((np.ones(n), x))
    lip = 0.25 * float(np.linalg.norm(design, ord=2) ** 2) + (1.0 - ratio) / inverse
    step = 1.0 / lip
    thresh = (ratio / inverse) * step
    l2_coef = (1.0 - ratio) / inverse

    w = np.zeros(d + 1, dtype=float) if init is None else np.asarray(init, dtype=float).copy()
    if init is None:
        w[0] = logit(np.clip(y.mean(), 1e-12, 1.0 - 1e-12))
    z = w.copy()
    t = 1.0
    for iteration in range(max_iter):
        prob = expit(design @ z)
        grad = design.T @ (prob - y)
        grad[1:] += l2_coef * z[1:]
        u = z - step * grad
        w_next = u.copy()
        if thresh > 0.0:
            w_next[1:] = np.sign(u[1:]) * np.maximum(np.abs(u[1:]) - thresh, 0.0)
        if np.dot(z - w_next, w_next - w) > 0.0:
            t = 1.0
            z = w_next.copy()
        else:
            t_next = 0.5 * (1.0 + np.sqrt(1.0 + 4.0 * t * t))
            z = w_next + ((t - 1.0) / t_next) * (w_next - w)
            t = t_next
        w = w_next
        if iteration % 25 == 24 or iteration == max_iter - 1:
            if not np.any(w[1:]):
                w[0] = logit(np.clip(y.mean(), 1e-12, 1.0 - 1e-12))
                z = w.copy()
            if _logistic_kkt_residual(x, y, w[1:], w[0], inverse, ratio) <= tol:
                break
    return w


def _fit_sparse_logit_cv(x, y, folds, plan):
    ratios = plan['l1_ratios']
    inverses = plan['inverse_penalties']
    scores = np.empty((len(folds), len(ratios), len(inverses)), dtype=float)
    paths = np.empty((len(folds), len(ratios), len(inverses), x.shape[1] + 1), dtype=float)
    for fold, (train, held) in enumerate(folds):
        for ri, ratio in enumerate(ratios):
            w_init = None
            for ci, inverse in enumerate(inverses):
                w_init = _fit_elastic_net_logistic(x[train], y[train], inverse, ratio, init=w_init)
                beta = certify_logistic_coefficients(x[train], y[train], np.r_[w_init[1:], w_init[0]], inverse, ratio)
                paths[fold, ri, ci] = beta
                scores[fold, ri, ci] = -float(np.mean((y[held] - expit(x[held] @ beta[:-1] + beta[-1])) ** 2))
    ri, ci = np.unravel_index(scores.mean(axis=0).argmax(), scores.shape[1:])
    best_ratio, best_inverse = ratios[ri], inverses[ci]
    w_final = _fit_elastic_net_logistic(x, y, best_inverse, best_ratio)
    beta = certify_logistic_coefficients(x, y, np.r_[w_final[1:], w_final[0]], best_inverse, best_ratio)
    return beta[:-1], float(beta[-1]), best_inverse, best_ratio, scores, paths


def _fit_weighted_profiles(x, y, folds, profiles, plan):
    groups = []
    fitted = []
    for item in profiles:
        weights = np.asarray(item['weights'], dtype=float)
        scale = np.sqrt(weights)
        model = LogisticRegressionCV(
            Cs=plan['inverse_penalties'],
            l1_ratios=[0.0],
            cv=folds,
            scoring='neg_brier_score',
            solver='newton-cholesky',
            max_iter=10000,
            tol=1e-10,
            fit_intercept=True,
            use_legacy_attributes=False,
        ).fit(x / scale, y)
        paths = model.coefs_paths_[:, 0, :, 0, :].copy()
        paths[:, :, :-1] /= scale
        scores = model.scores_[:, 0, :].copy()
        model.coef_[0] /= scale
        coefficient = np.r_[model.intercept_, model.coef_[0]]
        probability = model.predict_proba(x)[:, 1]
        gradient = x.T @ (probability - y) + weights / model.C_ * coefficient[1:]
        maximum = max(float(abs(gradient).max()), float(abs(np.sum(probability - y))))
        if maximum > 1e-3:
            raise ValueError('Weighted logistic fit failed KKT optimality tolerance')
        groups.append(
            dict(
                profile=item['profile'],
                strength=item['strength'],
                kept=item['kept'],
                weights=weights.tolist(),
                C=float(model.C_),
                coefficients=coefficient.tolist(),
                cv_paths=paths.tolist(),
                cv_scores=scores.tolist(),
                maximum_kkt_residual=maximum,
            )
        )
        fitted.append(model)
    losses = [-float(np.asarray(group['cv_scores']).mean(axis=0).max()) for group in groups]
    selected = min(range(len(groups)), key=lambda index: (losses[index], index))
    return (fitted[selected], list(range(66))), dict(
        kind='weighted_logit',
        groups=groups,
        losses=losses,
        selected=selected,
        selected_profile=groups[selected]['profile'],
        selected_strength=groups[selected]['strength'],
        coefficients=groups[selected]['coefficients'],
        features=list(range(66)),
    )


def _shape_list_to_profiles(shapes, strengths):
    profiles = [dict(profile='uniform', strength=0.0, kept=list(range(2, 66)), weights=[1.0] * 66)]
    for shape_idx, kept in enumerate(shapes):
        kept_set = set(kept)
        for strength in strengths:
            if strength <= 0:
                continue
            weights = [1.0 if idx < 2 or idx in kept_set else 1.0 + float(strength) for idx in range(66)]
            profiles.append(
                dict(profile=f'shape_{shape_idx}', strength=float(strength), kept=list(kept), weights=weights)
            )
    return profiles


def fit_source_learners(
    auxiliary,
    source,
    roles,
    graph,
    context_attributes,
    context_strength,
    shuffle_perm,
    true_roles,
    plan,
    seed,
):
    x, y = 2 * np.asarray(source['x']) - 1, np.asarray(source['y'])
    folds = list(StratifiedKFold(plan['source_cv_folds'], shuffle=True, random_state=seed).split(x, y))
    models, records = {}, {}
    full = list(range(66))
    full_model = LogisticRegressionCV(
        Cs=plan['inverse_penalties'],
        l1_ratios=[0.0],
        cv=folds,
        scoring='neg_brier_score',
        solver='lbfgs',
        max_iter=100000,
        tol=1e-8,
        fit_intercept=True,
        random_state=seed,
        use_legacy_attributes=False,
    ).fit(x, y)
    models['full_logit'] = (full_model, full)
    records['full_logit'] = dict(
        kind='logit',
        features=full,
        coefficients=np.r_[full_model.intercept_, full_model.coef_[0]].tolist(),
        C=float(full_model.C_),
        l1_ratio=0.0,
        cv_scores=full_model.scores_.tolist(),
        cv_paths=full_model.coefs_paths_[:, :, :, 0, :].tolist(),
        cv_ratios=[0.0],
    )

    sp_coef, sp_int, sp_c, sp_ratio, sp_scores, sp_paths = _fit_sparse_logit_cv(x, y, folds, plan)
    sparse_model = LogisticRegression(C=sp_c, l1_ratio=sp_ratio, fit_intercept=True)
    sparse_model.classes_ = np.array([0, 1])
    sparse_model.coef_ = sp_coef[None, :]
    sparse_model.intercept_ = np.array([sp_int])
    models['sparse_logit'] = (sparse_model, full)
    records['sparse_logit'] = dict(
        kind='logit',
        features=full,
        coefficients=[sp_int, *sp_coef.tolist()],
        C=float(sp_c),
        l1_ratio=float(sp_ratio),
        cv_scores=sp_scores.tolist(),
        cv_paths=sp_paths.tolist(),
        cv_ratios=list(plan['l1_ratios']),
    )

    pipeline = Pipeline(
        [
            ('screen', SelectKBest(f_classif)),
            ('model', LogisticRegression(l1_ratio=0.0, solver='lbfgs', max_iter=10000, tol=1e-8, random_state=seed)),
        ]
    )
    search = GridSearchCV(
        pipeline,
        {'screen__k': plan['screen_sizes'], 'model__C': plan['screen_inverse_penalties']},
        cv=folds,
        scoring='neg_brier_score',
        error_score='raise',
    ).fit(x, y)
    selected = search.best_estimator_
    fitted = selected.named_steps['model']
    models['screened_logit'] = (selected, full)
    records['screened_logit'] = dict(
        kind='logit',
        features=selected.named_steps['screen'].get_support(indices=True).tolist(),
        coefficients=np.r_[fitted.intercept_, fitted.coef_[0]].tolist(),
        C=float(fitted.C),
        l1_ratio=0.0,
        cv_params=search.cv_results_['params'],
        cv_means=search.cv_results_['mean_test_score'].tolist(),
        cv_selected=int(search.best_index_),
    )

    tree = GridSearchCV(
        HistGradientBoostingClassifier(
            learning_rate=0.1,
            min_samples_leaf=10,
            l2_regularization=1.0,
            early_stopping=False,
            random_state=seed,
        ),
        {'max_depth': plan['boost_depths'], 'max_iter': plan['boost_iterations']},
        cv=folds,
        scoring='neg_brier_score',
        error_score='raise',
    ).fit(x, y)
    models['boosted'] = (tree.best_estimator_, full)
    records['boosted'] = dict(
        kind='boosted',
        parameters=tree.best_params_,
        cv_params=tree.cv_results_['params'],
        cv_means=tree.cv_results_['mean_test_score'].tolist(),
        cv_selected=int(tree.best_index_),
    )

    aux_x = 2 * np.asarray(auxiliary['x']) - 1
    transforms = [FrozenEstimator(PCA(n_components=dim, svd_solver='full').fit(aux_x)) for dim in plan['pca_dimensions']]
    pca_pipe = Pipeline(
        [
            ('basis', transforms[0]),
            ('model', LogisticRegression(l1_ratio=0.0, solver='newton-cholesky', tol=1e-10, max_iter=10000)),
        ]
    )
    pca_search = GridSearchCV(
        pca_pipe,
        {'basis': transforms, 'model__C': plan['inverse_penalties']},
        cv=folds,
        scoring='neg_brier_score',
        error_score='raise',
    ).fit(x, y)
    pca_est = pca_search.best_estimator_
    basis, pca_logit = pca_est.named_steps['basis'].estimator, pca_est.named_steps['model']
    raw_coef = pca_logit.coef_[0] @ basis.components_
    raw_intercept = float(pca_logit.intercept_[0] - basis.mean_ @ raw_coef)
    models['pca'] = (pca_est, full)
    records['pca'] = dict(
        kind='pca',
        coefficients=[raw_intercept, *raw_coef.tolist()],
        features=full,
        components=basis.components_.tolist(),
        mean=basis.mean_.tolist(),
        eigenvalues=basis.explained_variance_.tolist(),
        pc_coefficients=[float(pca_logit.intercept_[0]), *pca_logit.coef_[0].tolist()],
        C=float(pca_logit.C),
        cv_params=[
            dict(dimension=int(row['basis'].estimator.n_components), C=float(row['model__C']))
            for row in pca_search.cv_results_['params']
        ],
        cv_means=pca_search.cv_results_['mean_test_score'].tolist(),
        cv_selected=int(pca_search.best_index_),
    )

    shuffled_roles = dict(
        eligible=roles['eligible'],
        reachable=list(roles['reachable']),
        root=sorted(2 + int(shuffle_perm[idx - 2]) for idx in roles['root']),
        terminal=sorted(2 + int(shuffle_perm[idx - 2]) for idx in roles['terminal']),
        upstream=sorted(2 + int(shuffle_perm[idx - 2]) for idx in roles['upstream']),
    )
    geometry = attribute_geometry_shapes(graph, context_attributes, context_strength)
    strengths = plan['structure_strengths']
    weighted_specs = {
        'jci': role_weight_profiles(roles, strengths),
        'oracle': role_weight_profiles(true_roles, strengths),
        'shuffled': role_weight_profiles(shuffled_roles, strengths),
        'skeleton_background': _shape_list_to_profiles(geometry['skeleton'], strengths),
        'propagated_skeleton': _shape_list_to_profiles(geometry['propagated'], strengths),
        'direct_context': _shape_list_to_profiles([context_attributes], strengths),
        'direct_uniform': _shape_list_to_profiles([], strengths),
    }
    for key, profiles in weighted_specs.items():
        models[key], records[key] = _fit_weighted_profiles(x, y, folds, profiles, plan)

    return models, dict(
        models=records,
        folds=[dict(train=train.tolist(), held=held.tolist()) for train, held in folds],
        seed=seed,
        geometry=geometry,
    )


def predict_source_model(model_entry, x_obs):
    fitted, features = model_entry
    data = (2 * np.asarray(x_obs) - 1)[:, features]
    return fitted.predict_proba(data)[:, 1]


def cross_fit_target_effects(source_models, target_data, plan):
    """Task-unit K-fold cross-fitted target adaptation and unbiased residual effect scoring.

    Outer folds and inner CV folds depend ONLY on deterministic row indices, never on A or Y,
    and A never enters predictor design matrices. Thus g_hat^{(-k)} is independent of (A_i, Y_i)
    for every i in outer fold I_k, guaranteeing exact finite-sample unbiasedness.
    """
    x_obs = np.asarray(target_data['x'])
    a = np.asarray(target_data['a'])
    y = np.asarray(target_data['y'], dtype=float)
    n = len(y)
    k_folds = plan['target_folds']
    if k_folds < 2 or n < k_folds:
        raise ValueError('Task-unit cross-fitting requires at least 2 folds and n >= target_folds')

    outer_fold = task_unit_folds(n, k_folds)  # same partition that fold-nested assignment (D1) randomizes within
    design = np.column_stack((np.ones(n), 2 * x_obs - 1))
    penalties = plan['correction_penalties']
    if any(p <= 0 or not np.isfinite(p) for p in penalties):
        raise ValueError('Target correction penalties must be strictly positive and finite')

    source_preds = {name: predict_source_model(model, x_obs) for name, model in source_models.items()}
    all_methods = ['jci', 'oracle', *PRIMARY_COMPARATORS, *STRUCTURAL_COMPARATORS, 'target_only']
    results = {}

    for method in all_methods:
        oof_pred = np.empty(n, dtype=float)
        fold_records = []
        candidate_bases = ['target_only'] if method == 'target_only' else (
            ['full_logit'] if method == 'full_logit' else [method, 'full_logit']
        )
        for fold in range(k_folds):
            held_mask = outer_fold == fold
            train_mask = ~held_mask
            x_tr, y_tr = design[train_mask], y[train_mask]
            x_te = design[held_mask]
            inner_fold = np.arange(len(y_tr)) % (k_folds - 1)

            best_tuple = None
            best_choice = None
            inner_losses = {}
            for base_idx, base_name in enumerate(candidate_bases):
                base_tr = np.zeros(len(y_tr)) if base_name == 'target_only' else source_preds[base_name][train_mask]
                for pen_idx, penalty in enumerate(penalties):
                    sq_errors = []
                    for inf in range(k_folds - 1):
                        in_val = inner_fold == inf
                        in_trn = ~in_val
                        resid = y_tr[in_trn] - base_tr[in_trn]
                        coef = Ridge(alpha=penalty, fit_intercept=False, solver='cholesky').fit(x_tr[in_trn], resid).coef_
                        pred_val = np.clip(base_tr[in_val] + x_tr[in_val] @ coef, 0.0, 1.0)
                        sq_errors.extend(((y_tr[in_val] - pred_val) ** 2).tolist())
                    loss = float(np.mean(sq_errors))
                    inner_losses[f'{base_name}|{penalty}'] = loss
                    score_key = (loss, base_idx, pen_idx)
                    if best_tuple is None or score_key < best_tuple:
                        best_tuple = score_key
                        best_choice = (base_name, penalty)

            chosen_base, chosen_pen = best_choice
            base_full_tr = np.zeros(len(y_tr)) if chosen_base == 'target_only' else source_preds[chosen_base][train_mask]
            base_full_te = np.zeros(int(held_mask.sum())) if chosen_base == 'target_only' else source_preds[chosen_base][held_mask]
            final_coef = Ridge(alpha=chosen_pen, fit_intercept=False, solver='cholesky').fit(x_tr, y_tr - base_full_tr).coef_
            independent = np.linalg.solve(
                x_tr.T @ x_tr + chosen_pen * np.eye(x_tr.shape[1]),
                x_tr.T @ (y_tr - base_full_tr),
            )
            np.testing.assert_allclose(final_coef, independent, atol=1e-10)
            oof_pred[held_mask] = np.clip(base_full_te + x_te @ final_coef, 0.0, 1.0)
            fold_records.append(
                dict(
                    fold=fold,
                    selected_base=chosen_base,
                    selected_penalty=float(chosen_pen),
                    inner_cv_loss=float(best_tuple[0]),
                    coefficients=final_coef.tolist(),
                )
            )

        scores = 2.0 * (2.0 * a - 1.0) * (y - oof_pred)
        results[method] = dict(
            effect=float(scores.mean()),
            standard_error=float(scores.std(ddof=1) / np.sqrt(n)),
            oof_predictions=oof_pred.tolist(),
            scores=scores.tolist(),
            folds=fold_records,
            fallback_folds=sum(1 for row in fold_records if row['selected_base'] == 'full_logit' and method != 'full_logit'),
        )
    return results


def integrate_cross_fitted_risk(source_models, cross_fit, scenario, plan, seed, permutation):
    rng = np.random.default_rng(seed)
    methods = list(cross_fit)
    k_folds = plan['target_folds']
    n_target = plan['target_size']
    sums = {name: np.zeros(3) for name in [*methods, 'bayes']}
    pairs = [(tested, baseline) for tested in ('oracle', 'jci') for baseline in PRIMARY_COMPARATORS]
    pairs += [('jci', baseline) for baseline in STRUCTURAL_COMPARATORS]
    pairs += [('jci', 'target_only'), ('oracle', 'target_only')]
    pair_keys = [(f'{tested}|{baseline}', tested, baseline) for tested, baseline in pairs]
    differences = {key: np.zeros(2) for key, _, _ in pair_keys}
    tau_sum, tau_square = 0.0, 0.0
    remaining = plan['test_covariates']

    while remaining:
        size = min(remaining, plan['test_batch_size'])
        sample = draw_merged_attributes(rng, size, 1, scenario, plan, permutation, outcomes=False)
        g, tau = sample['average'], sample['effect']
        matrix = np.column_stack((np.ones(size), 2 * sample['x'] - 1))
        base_preds = {name: predict_source_model(model, sample['x']) for name, model in source_models.items()}
        values = {}
        for name in methods:
            acc = np.zeros(size)
            for fold_row in cross_fit[name]['folds']:
                bname = fold_row['selected_base']
                coef = np.asarray(fold_row['coefficients'])
                base_vec = np.zeros(size) if bname == 'target_only' else base_preds[bname]
                pred = np.clip(base_vec + matrix @ coef, 0.0, 1.0)
                acc += (g * (1.0 - pred) ** 2 + (1.0 - g) * pred ** 2) / k_folds
            values[name] = acc
        values['bayes'] = g * (1.0 - g)
        for name, value in values.items():
            sums[name] += [value.sum(), value @ value, value @ tau]
        for key, tested, baseline in pair_keys:
            diff = values[baseline] - values[tested]
            differences[key] += [diff.sum(), diff @ diff]
        tau_sum += tau.sum()
        tau_square += tau @ tau
        remaining -= size

    count = plan['test_covariates']
    truth = tau_sum / count
    tau_variance = (tau_square - tau_sum ** 2 / count) / (count - 1)
    truth_squared = truth ** 2 - tau_variance / count
    risks, errors = {}, {}
    for name, (total, square, cross) in sums.items():
        mean = total / count
        risks[name] = float((4.0 * mean - truth_squared) / n_target)
        influence_sum = 4.0 * total - 2.0 * truth * tau_sum
        influence_square = 16.0 * square + 4.0 * truth ** 2 * tau_square - 16.0 * truth * cross
        variance = max(0.0, (influence_square - influence_sum ** 2 / count) / (count - 1))
        errors[name] = float(np.sqrt(variance / count) / n_target)
    paired = {
        key: float(4.0 * np.sqrt(max(0.0, (sq - tot ** 2 / count) / (count - 1)) / count) / n_target)
        for key, (tot, sq) in differences.items()
    }
    return dict(
        risks=risks,
        integration_standard_errors=errors,
        paired_integration_standard_errors=paired,
        truth=float(truth),
        truth_standard_error=float(np.sqrt(tau_variance / count)),
        test_seed=seed,
        test_covariates=count,
    )


def comparison_pairs_for_plan(plan):
    pairs = [(tested, baseline) for tested in ('oracle', 'jci') for baseline in plan['primary_comparators']]
    pairs += [('jci', baseline) for baseline in plan['structural_comparators']]
    if 'target_only' in plan.get('extra_comparators', []):
        pairs += [('jci', 'target_only'), ('oracle', 'target_only')]
    return pairs


def validate_directional_plan(plan):
    if plan.get('formal_claim_allowed') is not False or plan.get('new_provider_calls', 0) != 0:
        raise ValueError('Bounded study plan must keep formal_claim_allowed=false and zero provider calls')
    if len(set(plan.get('batch_seeds', []))) != len(plan.get('batch_seeds', [])) or len(plan.get('batch_seeds', [])) != 2:
        raise ValueError('Plan must specify two distinct batch_seeds')
    if plan.get('target_folds', 0) < 2 or plan.get('target_size', 0) < plan.get('target_folds', 0):
        raise ValueError('Plan target_folds must be >= 2 and <= target_size')
    if any(p <= 0 for p in plan.get('correction_penalties', [])) or any(p <= 0 for p in plan.get('inverse_penalties', [])):
        raise ValueError('All regularization penalties must be strictly positive')
    if any(s < 0 for s in plan.get('structure_strengths', [])):
        raise ValueError('Structure penalty strengths must be non-negative')
    if plan.get('maximum_skeleton_conditioning_order', 0) < 1 or not 0 < plan.get('component_alpha', 0) < 1:
        raise ValueError('Invalid conditioning order or component_alpha')
    if set(plan.get('scenarios', [])) - set(SCENARIOS):
        raise ValueError('Plan contains unsupported scenarios')


def _execute_cell(arguments):
    coordinates, plan, output, rscript = arguments
    batch, scenario_index, repetition = coordinates
    scenario = plan['scenarios'][scenario_index]
    base = [plan['batch_seeds'][batch], scenario_index, repetition]
    seed = lambda role: int(np.random.SeedSequence([*base, role]).generate_state(1)[0])
    permutation = np.random.default_rng(seed(12)).permutation(64).tolist()

    data = {}
    for role, (name, size) in enumerate(
        (
            ('auxiliary', plan['auxiliary_size']),
            ('source', plan['source_size']),
            ('target', plan['target_size']),
        )
    ):
        sampled = draw_merged_attributes(
            np.random.default_rng(seed(role)),
            size,
            0 if role < 2 else 1,
            scenario,
            plan,
            permutation,
            outcomes=role != 0,
        )
        data[name] = {key: sampled[key] for key in (('x',) if role == 0 else ('x', 'a', 'y'))}

    cell_name = f'{scenario}-b{batch}-r{repetition:02d}'
    labels = ['C1', 'C2', *[f'X{index:02d}' for index in range(64)]]
    ci = ConditionalPermutation(data['auxiliary']['x'], labels, plan['ci_draws'], seed(20))
    log_name = f'{cell_name}.structure.json' if rscript is None else f'{cell_name}.R.log'
    backend = StructureBackend(rscript, output / log_name, Path('src/discovery/jci_context.R'))
    try:
        graph = backend.search(
            labels,
            plan.get('structure_method', 'attribute_majority_merged'),
            ci,
            plan['ci_alpha'],
            max_order=plan['maximum_skeleton_conditioning_order'],
        )
    finally:
        backend.close()

    context_attributes, context_strength = [], []
    for index in range(2, 66):
        values = [ci.query(labels[root], labels[index], []) for root in (0, 1)]
        if any(value is None or value < plan['ci_alpha'] for value in values):
            context_attributes.append(index)
        context_strength.append(
            max([0.0, *[-np.log10(max(value, 1.0 / (plan['ci_draws'] + 1)) / plan['ci_alpha']) for value in values if value is not None]])
        )

    direction_checks = attribute_direction_checks(graph)
    roles = pag_role_groups(graph)
    true_graph = merged_attribute_graph(plan, permutation)
    true_roles = pag_role_groups(true_graph)
    shuffle = np.random.default_rng(seed(21)).permutation(64)

    warnings.simplefilter('error', ConvergenceWarning)
    source_models, source_record = fit_source_learners(
        data['auxiliary'],
        data['source'],
        roles,
        graph,
        context_attributes,
        context_strength,
        shuffle,
        true_roles,
        plan,
        seed(10),
    )
    cross_fit = cross_fit_target_effects(source_models, data['target'], plan)
    integrated = integrate_cross_fitted_risk(source_models, cross_fit, scenario, plan, seed(5), permutation)

    truth = integrated['truth']
    truth_margin = 5.0 * integrated['truth_standard_error']
    diagnostics = {}
    for method, cf_rec in cross_fit.items():
        est, se = cf_rec['effect'], cf_rec['standard_error']
        low, high = est - norm.ppf(0.975) * se, est + norm.ppf(0.975) * se
        if low <= truth - truth_margin and truth + truth_margin <= high:
            coverage = 'covered'
        elif high < truth - truth_margin or low > truth + truth_margin:
            coverage = 'not_covered'
        else:
            coverage = 'integration_boundary_unknown'
        diagnostics[method] = dict(
            estimate=est,
            standard_error=se,
            estimation_error=est - truth,
            squared_error=(est - truth) ** 2,
            conditional_variance=integrated['risks'][method],
            coverage=coverage,
            fallback_folds=cf_rec['fallback_folds'],
        )

    write_bundle(
        output / 'cells' / cell_name,
        {
            'result.json': dict(
                batch=batch,
                scenario=scenario,
                repetition=repetition,
                coordinates=base,
                permutation=permutation,
                data={role: {k: v.tolist() for k, v in row.items()} for role, row in data.items()},
                graph=graph,
                direction_checks=direction_checks,
                roles=roles,
                true_roles=true_roles,
                ci_seed=seed(20),
                queries=list(ci.cache.values()),
                context_attributes=context_attributes,
                context_strength=context_strength,
                shuffle=shuffle.tolist(),
                source=source_record,
                cross_fit=cross_fit,
                integrated=integrated,
                diagnostics=diagnostics,
            )
        },
    )
    return dict(
        batch=batch,
        scenario=scenario,
        repetition=repetition,
        risks=integrated['risks'],
        diagnostics=diagnostics,
        direction_eligible=direction_checks['eligible'],
        selected_profile=source_record['models']['jci']['selected_profile'],
        queries=len(ci.cache),
    )


def run_directional_study(plan_path, output_dir, *, rscript=None, workers=1):
    plan = read_json(Path(plan_path))
    validate_directional_plan(plan)
    if workers < 1:
        raise ValueError('workers must be >= 1')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)

    sources = [
        Path(name)
        for name in (
            'src/discovery/prognostic_learning.py',
            'src/discovery/jci_structure.py',
            'src/discovery/jci_context.R',
            'src/experiment/assignment.py',
            'src/verification/prognostic_learning.py',
            'src/artifact_io.py',
            'src/records.py',
            'src/cli.py',
            'pyproject.toml',
        )
    ]
    with zipfile.ZipFile(output / 'source.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            archive.write(source, source.as_posix())

    tasks = list(itertools.product(range(len(plan['batch_seeds'])), range(len(plan['scenarios'])), range(plan['repetitions_per_batch'])))
    write_bundle(
        output / 'inputs',
        {
            'plan.json': plan,
            'identity.json': dict(
                source_archive_sha256=file_sha256(output / 'source.zip'),
                sources={path.as_posix(): file_sha256(path) for path in sources},
                python=platform.python_version(),
                numpy=np.__version__,
                scipy=scipy.__version__,
                sklearn=sklearn.__version__,
                backend='native' if rscript is None else str(rscript),
                declared_cells=len(tasks),
                workers=workers,
            ),
        },
    )

    if workers == 1:
        rows = [_execute_cell((task, plan, output, rscript)) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(_execute_cell, ((task, plan, output, rscript) for task in tasks)))

    pairs = comparison_pairs_for_plan(plan)
    family = plan.get('comparison_family_size', len(plan['scenarios']) * len(pairs))
    comparisons = []
    scenario_diagnostics = []
    for scenario in plan['scenarios']:
        group = [row for row in rows if row['scenario'] == scenario]
        for tested, baseline in pairs:
            diffs = np.asarray([row['risks'][baseline] - row['risks'][tested] for row in group])
            mean = float(diffs.mean())
            base_risk = float(np.mean([row['risks'][baseline] for row in group]))
            radius = (
                float(t.ppf(1 - plan['component_alpha'] / (2 * family), len(group) - 1) * diffs.std(ddof=1) / np.sqrt(len(group)))
                if len(group) > 1
                else None
            )
            batches = [
                float(np.mean([row['risks'][baseline] - row['risks'][tested] for row in group if row['batch'] == b]))
                for b in sorted({row['batch'] for row in group})
            ]
            rel = mean / base_risk
            supported = (
                len(group) == len(plan['batch_seeds']) * plan['repetitions_per_batch']
                and rel >= plan['minimum_relative_variance_reduction']
                and radius is not None
                and mean - radius > 0
                and len(batches) == 2
                and min(batches) > 0
            )
            harm_supported = radius is not None and mean + radius < 0 and max(batches) < 0
            comparisons.append(
                dict(
                    scenario=scenario,
                    tested=tested,
                    baseline=baseline,
                    repetitions=len(group),
                    difference=mean,
                    base_risk=base_risk,
                    relative_reduction=rel,
                    interval=None if radius is None else [mean - radius, mean + radius],
                    batch_differences=batches,
                    supported=bool(supported),
                    harm_supported=bool(harm_supported),
                )
            )

        for method in ('jci', 'oracle', *plan['primary_comparators'], *plan['structural_comparators'], 'target_only'):
            if method not in group[0]['diagnostics']:
                continue
            errs = [row['diagnostics'][method]['estimation_error'] for row in group]
            vars_ = [row['diagnostics'][method]['conditional_variance'] for row in group]
            covs = [row['diagnostics'][method]['coverage'] for row in group]
            scenario_diagnostics.append(
                dict(
                    scenario=scenario,
                    method=method,
                    bias=float(np.mean(errs)),
                    mse=float(np.mean(np.square(errs))),
                    mean_conditional_variance=float(np.mean(vars_)),
                    covered=sum(1 for c in covs if c == 'covered'),
                    total=len(covs),
                    fallback_folds=sum(row['diagnostics'][method]['fallback_folds'] for row in group),
                )
            )

    jci_primary = [c for c in comparisons if c['tested'] == 'jci' and c['baseline'] in plan['primary_comparators']]
    jci_downstream = [c for c in comparisons if c['tested'] == 'jci' and c['scenario'] == 'downstream_signal']
    jci_upstream = [c for c in comparisons if c['tested'] == 'jci' and c['scenario'] == 'upstream_control']
    harm_by_scenario = {
        scenario: sum(1 for c in comparisons if c['tested'] == 'jci' and c['scenario'] == scenario and c['harm_supported'])
        for scenario in plan['scenarios']
    }
    summary = dict(
        study_id=plan['study_id'],
        evidence_role=plan['evidence_role'],
        cells=len(rows),
        comparison_family_size=family,
        downstream_gate_passed=bool(jci_downstream) and all(c['supported'] for c in jci_downstream),
        upstream_harm_count=sum(1 for c in jci_upstream if c['harm_supported']),
        jci_harm_count_by_scenario=harm_by_scenario,
        jci_harm_total=sum(harm_by_scenario.values()),
        primary_passed=sum(1 for c in jci_primary if c['supported']),
        primary_total=len(jci_primary),
        direction_eligible_cells=sum(1 for r in rows if r['direction_eligible']),
        comparisons=comparisons,
        diagnostics=scenario_diagnostics,
        rows=rows,
        formal_claim_allowed=False,
        new_provider_calls=0,
    )
    write_bundle(output / 'summary', {'result.json': summary})
    return summary

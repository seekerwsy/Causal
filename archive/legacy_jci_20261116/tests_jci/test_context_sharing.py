from pathlib import Path

import numpy as np
import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery import context_sharing as method
from prompt_mechanism_study.discovery.jci_structure import ConditionalPermutation, StructureBackend
from prompt_mechanism_study.experiment.context_validation import confirmation, validate_plan
from prompt_mechanism_study.verification.context_validation import verify_model, verify_scores


def test_randomization_correction_is_exact_under_all_registered_mechanisms():
    for scenario in method.SCENARIOS:
        for h in range(4):
            check = method.exact_correction_check(h,scenario)
            assert check['maximum_corrected_bias']<1e-12
            assert check['maximum_uncorrected_bias']>.05


def test_context_encoding_never_qualifies_as_sharing():
    data = method.draw_tasks(np.random.default_rng(20261029),2048,0,'no_overlap','discovery')
    ci = ConditionalPermutation(method.observation_matrix(data),method.LABELS,199,42,minimum_per_level=2)
    assert ci.query('E','Y',['A','W','Z1']) is None
    assert not method.overlap(data,1,2,.1)['supported']
    assert ci.cache[('E','Y',('A','W','Z1'))]['status']=='insufficient_support'


def test_population_sharing_distinguishes_hidden_wording_and_latent_confounding():
    for scenario,expected in (('shared',[1,3]),('hidden_wording',[]),
                              ('latent_confounding',[]),('no_overlap',[])):
        ci = method.PopulationIndependence(*method.exact_population(0,scenario))
        masks = [mask for mask in range(4) if ci.query('E','Y',method.conditioning(mask))==1.]
        assert masks==expected


def test_full_version_integration_and_scores_match_independent_calculation():
    fitting = method.draw_tasks(np.random.default_rng(700),256,1,'hidden_wording','discovery')
    ranking = method.draw_tasks(np.random.default_rng(701),256,1,'hidden_wording','calibration_ranking')
    for mask in (None,0,1,2,3):
        model = method.fit_cells(fitting,mask)
        verify_model(model,fitting)
        verify_scores(method.corrected_scores(ranking,model),model,ranking)


def test_confirmation_preserves_full_denominator_and_registered_family():
    plan = read_json(Path('configs/jci-context-validation.json'))
    validate_plan(plan)
    record = confirmation(np.random.default_rng(201),0,'shared',plan)
    assert len(record['y'][0])==len(record['y'][1])==plan['confirmation_task_units_per_hypothesis']
    radius = np.sqrt(2*np.log(8/plan['confirmation_alpha'])/len(record['y'][0]))
    np.testing.assert_allclose(record['simultaneous_interval'],[record['effect']-radius,record['effect']+radius])
    plan['formal_claim_allowed'] = True
    with pytest.raises(ValueError):
        validate_plan(plan)


def test_real_fci_retains_actual_separating_sets(tmp_path,request):
    ci = method.PopulationIndependence(*method.exact_population(0,'shared'))
    backend = StructureBackend(request.config.getoption('--rscript'),tmp_path/'backend.log',
                               Path('src/discovery/jci_context.R'))
    graph = backend.search(method.LABELS,'jci',ci,.05)
    comparison = backend.search(method.LABELS,'fci_same_knowledge',ci,.05)
    backend.close()
    assert graph['pag']==comparison['pag']
    assert graph['pag'][0][-1]==0
    assert graph['separating_sets']
    assert any('Z1' in separating for separating in graph['separating_sets'])


def test_exact_confirmation_power_matches_exhaustive_single_unit_distribution():
    from scipy.stats import multinomial
    plan = read_json(Path('configs/jci-context-validation.json'))
    # 使用声明机制的真实概率，穷举独立任务的三项分布。
    distribution = method.paired_difference_probabilities(0,'shared')
    n = 20
    radius = np.sqrt(2*np.log(8/plan['confirmation_alpha'])/n)
    expected = 0.
    for minus in range(n+1):
        for plus in range(n-minus+1):
            if (plus-minus)/n>plan['practical_effect']+radius:
                expected += multinomial.pmf([minus,n-minus-plus,plus],n,list(distribution.values()))
    np.testing.assert_allclose(method.confirmation_power(distribution,n,plan),expected,atol=1e-14)

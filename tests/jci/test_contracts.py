from copy import deepcopy
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.cli import _build_parser
from prompt_mechanism_study.discovery.prognostic_learning import (
    run_directional_study,
    validate_directional_plan,
)
from prompt_mechanism_study.experiment.natural_study import validate_natural_plan


PLAN = read_json(Path('configs/jci-directional-grouped-smoke.json'))
NATURAL_PLAN = read_json(Path('configs/jci-natural-task-smoke.json'))


@pytest.mark.parametrize('field,value', [
    ('formal_claim_allowed', True),
    ('new_provider_calls', 1),
    ('batch_seeds', [2026111691, 2026111691]),
    ('correction_penalties', [0.0]),
    ('inverse_penalties', [-1.0]),
    ('structure_strengths', [-0.5]),
    ('target_folds', 1),
    ('maximum_skeleton_conditioning_order', 0),
])
def test_invalid_scientific_contract_fails_before_execution(field, value):
    plan = deepcopy(PLAN)
    plan[field] = value
    with pytest.raises(ValueError):
        validate_directional_plan(plan)


def test_invalid_execution_budget_creates_no_experiment(tmp_path):
    output = tmp_path / 'experiment'
    with pytest.raises(ValueError):
        run_directional_study(Path('configs/jci-directional-grouped-smoke.json'), output, workers=0)
    assert not output.exists()


def test_active_cli_surface_uses_single_method_path():
    parser = _build_parser()
    smoke = parser.parse_args(['study', 'smoke', 'results/smoke'])
    natural = parser.parse_args(['study', 'natural-smoke', 'results/natural'])
    run = parser.parse_args(['study', 'run', 'results/run', '--plan', 'plan.json'])
    verify = parser.parse_args(['study', 'verify', 'results/run'])
    inspect_cmd = parser.parse_args(['study', 'inspect-tsg', 'input.json', 'results/tsg'])
    assert smoke.action == 'smoke' and smoke.plan == Path('configs/jci-directional-grouped-smoke.json')
    assert natural.action == 'natural-smoke' and natural.plan == Path('configs/jci-natural-task-smoke.json')
    assert run.action == 'run' and verify.action == 'verify' and inspect_cmd.action == 'inspect-tsg'


@pytest.mark.parametrize('field,value', [
    ('formal_claim_allowed', True),
    ('new_provider_calls', 1),
    ('study_mode', 'simulation'),
    ('target_folds', 1),
    ('practical_margin', 0.0),
    ('correction_penalties', [-1.0]),
])
def test_invalid_natural_plan_contract_fails_before_execution(field, value):
    plan = deepcopy(NATURAL_PLAN)
    plan[field] = value
    with pytest.raises(ValueError):
        validate_natural_plan(plan)

from copy import deepcopy
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.cli import _build_parser
from prompt_mechanism_study.experiment.jci_reliability import run_reliability, validate_reliability_plan


PLAN = read_json(Path('configs/jci-smoke.json'))


@pytest.mark.parametrize('field,value', [
    ('formal_claim_allowed', True),
    ('evidence_role', 'FORMAL_CONFIRMATION'),
    ('conservative_colliders', False),
    ('prior_strengths', [1.]),
    ('batch_seeds', [1, 1]),
    ('ridge_penalties', [0.]),
])
def test_invalid_scientific_contract_fails_before_execution(field, value):
    plan = deepcopy(PLAN)
    plan[field] = value
    with pytest.raises(ValueError):
        validate_reliability_plan(plan)


def test_invalid_execution_budget_creates_no_experiment(tmp_path):
    output = tmp_path/'experiment'
    with pytest.raises(ValueError):
        run_reliability(Path('configs/jci-smoke.json'), output, Path('Rscript'), workers=0)
    assert not output.exists()


def test_replay_has_an_explicit_command_and_separate_verifier():
    parser = _build_parser()
    run = parser.parse_args(['study', 'jci-replay', 'results/replay', '--plan', 'plan.json', '--rscript', 'Rscript'])
    verify = parser.parse_args(['study', 'verify-jci-replay', 'results/replay'])
    assert run.action == 'jci-replay' and verify.output == run.output

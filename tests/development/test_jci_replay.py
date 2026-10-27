from pathlib import Path

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.experiment.jci_replay import prepare_design
from prompt_mechanism_study.verification.jci_replay import verify_budget_replay, verify_replay_cell


PLAN = read_json(Path('data/method/jci-sharing-20261014/budget-plan.json'))
INPUTS = Path(PLAN['inputs'])
OUTPUT = Path('results/jci-budget-replay-20261014')


def test_fixed_metadata_design_separates_roles_and_bounds_real_request_prefixes():
    tasks = read_json(INPUTS/'tasks.json')
    requests = read_json(INPUTS/'training-requests.json')
    design = prepare_design(tasks, requests, PLAN)
    assert len(design['candidates']) == 24
    assert len(design['discovery_task_ids']) == 400
    assert len(design['confirmation_task_ids']) == len(design['test_task_ids']) == 200
    assert set(design['confirmation_task_ids']).isdisjoint(design['test_task_ids'])
    allowed = {row['request_id'] for row in requests if row['component'] == 'random_mixture'}
    assert len(allowed) == 4000
    for sequence in design['schedules'].values():
        assert len(sequence) == len(set(sequence)) == 1024
        assert set(sequence) <= allowed
    for candidate in design['candidates']:
        assert len(candidate['confirmation_task_ids']) == 8
        assert set(candidate['confirmation_task_ids']) <= set(design['confirmation_task_ids'])
    assert PLAN['selection_slots']*8*2*4 == PLAN['confirmation_call_budget'] == 192


def test_representative_executed_real_budget_replay_recomputes_shared_estimation_and_selection():
    root = OUTPUT
    design = read_json(root/'inputs'/'design.json')
    cell = read_json(root/'cells'/f'{PLAN["replay_seeds"][0]}-{PLAN["discovery_budgets"][0]}'/'result.json')
    tasks = {row['task_unit_id']: row for row in read_json(INPUTS/'tasks.json')}
    fits, queries = verify_replay_cell(cell, tasks, design['candidates'], PLAN)
    assert fits == 20 and queries > 0
    assert len(cell['observations']) == 128


def test_complete_executed_budget_replay_independently_checks_budget_confirmation_and_test():
    result = verify_budget_replay(OUTPUT)
    assert result['status'] == 'verified' and result['cells'] == 24
    assert result['independently_refitted_models'] == 480
    assert result['test_task_units'] == 200 and result['new_model_calls'] == 0

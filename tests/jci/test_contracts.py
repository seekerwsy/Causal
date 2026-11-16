"""Pre-execution contract guards and active CLI surface tests."""

from copy import deepcopy
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.cli import _build_parser
from prompt_mechanism_study.discovery.mechanism_discovery import (
    run_mechanism_simulation_study,
    validate_mechanism_plan,
)
from prompt_mechanism_study.experiment.natural_study import validate_natural_plan


MECH_PLAN = read_json(Path("configs/jci-mechanism-smoke.json"))
NATURAL_PLAN = read_json(Path("configs/jci-natural-task-smoke.json"))
VLLM_PLAN = read_json(Path("configs/jci-local-vllm-pilot.json"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("formal_claim_allowed", True),
        ("new_provider_calls", 1),
        ("study_mode", "legacy_unpaired"),
        ("batch_seeds", [2026111601, 2026111601]),
        ("scenarios", ["unknown_scenario"]),
        ("n_discovery", 0),
        ("ci_draws", 50),
        ("maximum_skeleton_conditioning_order", 0),
        ("practical_margin", 0.0),
    ],
)
def test_invalid_mechanism_plan_fails_before_execution(field, value):
    plan = deepcopy(MECH_PLAN)
    plan[field] = value
    with pytest.raises(ValueError):
        validate_mechanism_plan(plan)


def test_invalid_worker_count_creates_no_output(tmp_path):
    output = tmp_path / "experiment"
    with pytest.raises(ValueError):
        run_mechanism_simulation_study(Path("configs/jci-mechanism-smoke.json"), output, workers=0)
    assert not output.exists()


def test_active_cli_surface_uses_single_method_path():
    parser = _build_parser()
    smoke = parser.parse_args(["study", "smoke", "results/smoke"])
    natural = parser.parse_args(["study", "natural-smoke", "results/natural"])
    run = parser.parse_args(["study", "run", "results/run", "--plan", "plan.json"])
    verify = parser.parse_args(["study", "verify", "results/run"])
    inspect_cmd = parser.parse_args(["study", "inspect-tsg", "input.json", "results/tsg"])
    assert smoke.action == "smoke" and smoke.plan == Path("configs/jci-mechanism-smoke.json")
    assert natural.action == "natural-smoke" and natural.plan == Path("configs/jci-natural-task-smoke.json")
    assert run.action == "run" and verify.action == "verify" and inspect_cmd.action == "inspect-tsg"


@pytest.mark.parametrize(
    "field,value",
    [
        ("formal_claim_allowed", True),
        ("new_provider_calls", 1),
        ("study_mode", "simulation"),
        ("provider_mode", "remote_unknown"),
        ("ci_draws", 20),
        ("practical_margin", 0.0),
        ("maximum_skeleton_conditioning_order", 0),
    ],
)
def test_invalid_natural_plan_fails_before_execution(field, value):
    plan = deepcopy(NATURAL_PLAN)
    plan[field] = value
    with pytest.raises(ValueError):
        validate_natural_plan(plan)


def test_local_vllm_pilot_plan_passes_contract():
    validate_natural_plan(VLLM_PLAN)

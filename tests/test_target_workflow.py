from __future__ import annotations
import json
from dataclasses import replace
import pytest
from prompt_mechanism_study.cli import main
from prompt_mechanism_study.interaction_selector import (
    pair_preoutcome_data_sha256,
    pair_shadow_data_sha256,
    freeze_pair_preoutcome_design,
    pair_preoutcome_observations,
    run_pair_shadow_qualification,
)
from prompt_mechanism_study.prioritization import (
    atomic_preoutcome_data_sha256,
    discovery_data_sha256,
    freeze_atomic_candidate_folds,
    atomic_preoutcome_observations,
    run_atomic_shadow_qualification,
)
from prompt_mechanism_study.verification import (
    load_and_verify_target_result_bundle,
)
from prompt_mechanism_study.target_workflow import SMOKE_STAGES
from prompt_mechanism_study.reviewer_fixture import load_reviewer_smoke_fixture
from prompt_mechanism_study import target_workflow


@pytest.mark.parametrize('summary', [
    {'requirements': [{'criterion': 'An obsolete task'}], 'environment_dependencies': ['obsolete-library'], 'parent_contract_applies_to_current_input': False},
])
def test_functional_review_uses_original_task_without_missing_or_inapplicable_summary(summary):
    from prompt_mechanism_study.measurement import measure_generated_code

    requests = []

    def complete(request, *_):
        requests.append(request)
        if len(requests) == 1:
            return b'{"code":"def count(items): return len(items)"}'
        return b'{"verdict":"pass","evidence_lines":[1],"reason":"Returns the item count."}'

    measured, evidence = measure_generated_code(
        assignment_id="source-summary-fixture", generation_request={"language": "python"},
        generation_evaluator={}, generation_prompt="fixture", source_task_prompt="Return the item count.",
        functional_contract={"language": "python", **summary}, functional_evaluator={},
        functional_prompt="fixture", security_profile_id="python.fixture", complete=complete,
        security_evaluate=lambda *_: {"security_label": "unknown"},
    )
    assert measured.functional_status.value == "pass"
    assert len(requests) == 2
    request = evidence["functional_request"]
    assert request["functional_task"] == "Return the item count."
    assert request["requirements"] == request["environment_dependencies"] == []
    assert request["source_context"]["specification_scope"] == "unresolved"
    assert all(request["blindness"].values())


@pytest.mark.milestone
def test_target_reviewer_smoke_traverses_seven_stages_and_replays(
    tmp_path,
    capsys,
    monkeypatch,
) -> None:
    output = tmp_path / "target-reviewer-smoke"
    measured_rows = []
    measure = target_workflow.measure_generated_code

    def record_measurement(**kwargs):
        result = measure(**kwargs)
        measured_rows.append(result)
        return result

    monkeypatch.setattr(target_workflow, "measure_generated_code", record_measurement)
    assert main(["study", "smoke", str(output)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    verified = load_and_verify_target_result_bundle(output)

    assert len(measured_rows) == 80
    assert {row.oracle_status.value for row, _ in measured_rows} == {"secure", "insecure"}
    for row, raw in measured_rows:
        assert row.code_status.value == "valid"
        assert raw["syntax_valid"] is True
        assert row.oracle_status.value == ("insecure" if "verify=False" in raw["code"] else "secure")
        assert row.functional_status.value == "pass"
        assert raw["functional_response"] is not None
        assert all(raw["functional_request"]["blindness"].values())

    assert receipt["status"] == "TARGET_REVIEWER_SMOKE_VERIFIED"
    assert tuple(receipt["stages"]) == SMOKE_STAGES
    assert receipt["stage_count"] == 7
    assert receipt["assignment_count"] == 80
    assert receipt["measurement_count"] == 80
    assert receipt["outcome_count"] == 80
    assert receipt["provider_calls_made"] == 0
    assert receipt["evidence_level"] == "tested"
    assert receipt["package_status"] == "NON_CLAIM_TEST_ARTIFACT"
    assert receipt["scientific_claim_allowed"] is False
    assert verified["bundle_sha256"] == receipt["result_bundle_sha256"]


def test_zero_discoverable_candidates_keep_empty_fixed_slots(tmp_path, monkeypatch) -> None:
    original = target_workflow.load_reviewer_smoke_fixture

    def unsupported_inputs(*args):
        inputs = original(*args)
        return replace(
            inputs,
            atomic_plan=replace(inputs.atomic_plan, cross_fit_folds=100),
            pair_plan=replace(inputs.pair_plan, minimum_cell_task_units=100),
        )

    monkeypatch.setattr(target_workflow, "load_reviewer_smoke_fixture", unsupported_inputs)
    output = tmp_path / "zero-candidates"
    receipt = target_workflow.run_target_reviewer_smoke(output)
    assert receipt["assignment_count"] == receipt["outcome_count"] == 0
    assert receipt["scientific_claim_allowed"] is False
    assert load_and_verify_target_result_bundle(output)["scientific_claim_allowed"] is False


def test_target_selectors_require_exact_preoutcome_fold_replay() -> None:
    inputs = load_reviewer_smoke_fixture()
    atomic_preoutcome = atomic_preoutcome_observations(inputs.atomic_observations)
    pair_preoutcome_rows = pair_preoutcome_observations(inputs.pair_observations)
    assert all(not hasattr(item, "outcome") for item in atomic_preoutcome)
    assert all(not hasattr(item, "outcome") for item in pair_preoutcome_rows)
    atomic_folds = freeze_atomic_candidate_folds(
        inputs.atomic_universe,
        atomic_preoutcome,
        inputs.atomic_plan,
    )
    outcome_changed_atomic = tuple(
        replace(item, outcome=1 - item.outcome)
        for item in inputs.atomic_observations
    )
    rebuilt_atomic = replace(inputs.atomic_universe, preoutcome_data_sha256=
                             atomic_preoutcome_data_sha256(atomic_preoutcome_observations(outcome_changed_atomic)))
    assert rebuilt_atomic.universe_id == inputs.atomic_universe.universe_id
    assert discovery_data_sha256(outcome_changed_atomic) != discovery_data_sha256(inputs.atomic_observations)
    changed_covariates = (replace(atomic_preoutcome[0], covariates=(("source_code", 99.0),)), *atomic_preoutcome[1:])
    with pytest.raises(ValueError, match="pre-outcome|preoutcome"):
        freeze_atomic_candidate_folds(inputs.atomic_universe, changed_covariates, inputs.atomic_plan)
    assert atomic_folds == freeze_atomic_candidate_folds(
        inputs.atomic_universe,
        atomic_preoutcome_observations(outcome_changed_atomic),
        inputs.atomic_plan,
    )
    atomic_manifest = atomic_folds.manifests[0]
    left_index, right_index = _same_group_different_fold(
        atomic_manifest.assignments,
        group_name="target_state",
    )
    atomic_assignments = list(atomic_manifest.assignments)
    atomic_assignments[left_index] = replace(
        atomic_assignments[left_index],
        fold=atomic_manifest.assignments[right_index].fold,
    )
    atomic_assignments[right_index] = replace(
        atomic_assignments[right_index],
        fold=atomic_manifest.assignments[left_index].fold,
    )
    tampered_atomic = replace(
        atomic_folds,
        manifests=(
            replace(
                atomic_manifest,
                assignments=tuple(atomic_assignments),
            ),
        ),
    )
    with pytest.raises(ValueError, match="Atomic fold freeze failed outcome-blind replay"):
        run_atomic_shadow_qualification(
            inputs.atomic_universe,
            inputs.atomic_observations,
            inputs.atomic_plan,
            inputs.atomic_fci_evidence,
            fold_freeze=tampered_atomic,
        )

    pair_preoutcome = freeze_pair_preoutcome_design(
        inputs.pair_universe,
        pair_preoutcome_rows,
        inputs.pair_plan,
    )
    outcome_changed_pair = tuple(
        replace(item, outcome=1 - item.outcome)
        for item in inputs.pair_observations
    )
    rebuilt_pair = replace(inputs.pair_universe, preoutcome_data_sha256=
                           pair_preoutcome_data_sha256(pair_preoutcome_observations(outcome_changed_pair)))
    assert rebuilt_pair.universe_id == inputs.pair_universe.universe_id
    assert pair_shadow_data_sha256(outcome_changed_pair) != pair_shadow_data_sha256(inputs.pair_observations)
    assert pair_preoutcome == freeze_pair_preoutcome_design(
        inputs.pair_universe,
        pair_preoutcome_observations(outcome_changed_pair),
        inputs.pair_plan,
    )
    pair_manifest = pair_preoutcome.fold_manifests[0]
    left_index, right_index = _same_group_different_fold(
        pair_manifest.assignments,
        group_name="cell",
    )
    pair_assignments = list(pair_manifest.assignments)
    pair_assignments[left_index] = replace(
        pair_assignments[left_index],
        fold=pair_manifest.assignments[right_index].fold,
    )
    pair_assignments[right_index] = replace(
        pair_assignments[right_index],
        fold=pair_manifest.assignments[left_index].fold,
    )
    tampered_pair = replace(
        pair_preoutcome,
        fold_manifests=(
            replace(pair_manifest, assignments=tuple(pair_assignments)),
        ),
    )
    with pytest.raises(ValueError, match="Pair pre-outcome freeze failed outcome-blind replay"):
        run_pair_shadow_qualification(
            inputs.pair_universe,
            inputs.pair_observations,
            inputs.pair_relation_evidence,
            inputs.pair_plan,
            preoutcome_freeze=tampered_pair,
        )


def _same_group_different_fold(assignments, *, group_name: str) -> tuple[int, int]:
    for left_index, left in enumerate(assignments):
        for right_index, right in enumerate(assignments[left_index + 1 :], left_index + 1):
            if getattr(left, group_name) == getattr(right, group_name) and left.fold != right.fold:
                return left_index, right_index
    raise AssertionError("fixture lacks two same-group assignments in different folds")

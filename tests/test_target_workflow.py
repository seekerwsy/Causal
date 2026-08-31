from __future__ import annotations

import json
from dataclasses import replace

import pytest

from prompt_mechanism_study.cli import main
from prompt_mechanism_study.interaction_selector import (
    freeze_pair_preoutcome_design,
    pair_preoutcome_observations,
    run_pair_shadow_qualification,
)
from prompt_mechanism_study.prioritization import (
    freeze_atomic_candidate_folds,
    atomic_preoutcome_observations,
    run_atomic_shadow_qualification,
)
from prompt_mechanism_study.selector_verify import (
    load_and_verify_target_result_bundle,
)
from prompt_mechanism_study.target_workflow import (
    SMOKE_STAGES,
    _smoke_atomic_fci_evidence,
    _smoke_discovery_inputs,
    _smoke_pair_relation_evidence,
)


@pytest.mark.reviewer
@pytest.mark.milestone
def test_target_reviewer_smoke_traverses_seven_stages_and_replays(
    tmp_path,
    capsys,
) -> None:
    output = tmp_path / "target-reviewer-smoke"

    assert main(["study", "smoke", str(output)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    verified = load_and_verify_target_result_bundle(output)

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
    assert main(["study", "verify-result", str(output)]) == 0


@pytest.mark.reviewer
def test_cli_exposes_stage_groups_instead_of_flat_operations(capsys) -> None:
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "study" in help_text
    assert "data" in help_text
    assert "curate" in help_text
    assert "representation" in help_text
    assert "qualification" in help_text
    assert "artifact" in help_text
    assert "target-study" not in help_text
    assert "dataset-prep" not in help_text


@pytest.mark.reviewer
def test_target_selectors_require_exact_preoutcome_fold_replay() -> None:
    inputs = _smoke_discovery_inputs()
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
            _smoke_atomic_fci_evidence(
                inputs.atomic_universe,
                inputs.atomic_policy,
            ),
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
            _smoke_pair_relation_evidence(
                inputs.pair_policy,
                inputs.pair_observations,
            ),
            inputs.pair_plan,
            preoutcome_freeze=tampered_pair,
        )


def _same_group_different_fold(assignments, *, group_name: str) -> tuple[int, int]:
    for left_index, left in enumerate(assignments):
        for right_index, right in enumerate(assignments[left_index + 1 :], left_index + 1):
            if getattr(left, group_name) == getattr(right, group_name) and left.fold != right.fold:
                return left_index, right_index
    raise AssertionError("fixture lacks two same-group assignments in different folds")

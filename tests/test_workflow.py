from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import complete_measurements, example_study
from secaware.artifact_io import verify_bundle
from secaware.cli import main
from secaware.intervention import Arm
from secaware.measurement import FunctionalLabel, SecurityLabel
from secaware.workflow import analyze


@pytest.mark.reviewer
def test_study_identity_binds_population_interventions_and_randomization() -> None:
    first = example_study(seed=11)
    replay = example_study(seed=11)
    changed = example_study(seed=12)
    assert first.study_id == replay.study_id
    assert first.study_id != changed.study_id


@pytest.mark.reviewer
def test_analysis_is_replayable_from_frozen_measurements() -> None:
    study = example_study()
    measurements, failures = complete_measurements(study)
    assert analyze(study, measurements, failures) == analyze(study, measurements, failures)


@pytest.mark.milestone
def test_freeze_measure_outcome_infer_smoke() -> None:
    study = example_study()
    measurements, failures = complete_measurements(study)
    result = analyze(study, measurements, failures)
    assert result.security.difference == 1.0
    assert len(result.outcomes) == len(study.randomization.assignments)


@pytest.mark.milestone
def test_cli_reproduce_and_independent_verify(tmp_path: Path) -> None:
    study = example_study()
    security = {
        Arm.TARGET: SecurityLabel.SECURE,
        Arm.NOOP: SecurityLabel.INSECURE,
        Arm.PLACEBO: SecurityLabel.INSECURE,
        Arm.GENERIC: SecurityLabel.INSECURE,
    }
    rows = [
        {
            "task_id": assignment.task_id,
            "model_id": assignment.model_id,
            "request_slot": assignment.request_slot,
            "security": security[assignment.arm].value,
            "functionality": FunctionalLabel.PASS.value,
        }
        for assignment in study.randomization.assignments
    ]
    spec = {
        "seed": 17,
        "models": ["model.a"],
        "slots": list(range(8)),
        "tasks": [
            {
                "task_id": task.task_id,
                "cluster_id": task.cluster_id,
                "cwe": task.cwe,
                "prompt": task.prompt,
            }
            for task in study.population.tasks
        ],
        "candidates": [
            {
                "task_id": candidate.task_id,
                "feature_id": candidate.feature_id,
                "operation": candidate.operation.value,
                "rationale": candidate.rationale,
            }
            for candidate in study.candidates
        ],
        "interventions": [
            {
                "task_id": bundle.task_id,
                "arms": {item.arm.value: item.text for item in bundle.arms},
            }
            for bundle in study.interventions
        ],
        "measurements": rows,
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    output = tmp_path / "output"

    assert main(["reproduce", str(spec_path), str(output)]) == 0
    assert main(["verify", str(output)]) == 0
    verify_bundle(output)
    summary = json.loads((output / "analysis.json").read_text(encoding="utf-8"))
    assert summary["security"]["difference"] == 1.0

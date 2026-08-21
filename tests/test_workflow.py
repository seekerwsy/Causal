from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import complete_measurements, example_study, measurement_document, protocol_spec
from prompt_mechanism_study.artifact_io import verify_bundle
from prompt_mechanism_study.cli import main
from prompt_mechanism_study.workflow import analyze


@pytest.mark.reviewer
def test_freeze_identity_is_outcome_blind_and_replayable() -> None:
    first = example_study()
    replay = example_study()
    assert first == replay
    assert first.study_id == replay.study_id
    assert not hasattr(first, "measurements")


@pytest.mark.reviewer
def test_analysis_replays_from_frozen_study_and_external_measurements() -> None:
    study = example_study()
    rows = complete_measurements(study)
    assert analyze(study, rows) == analyze(study, rows)


@pytest.mark.milestone
def test_cli_freeze_then_analyze_then_verify(tmp_path: Path) -> None:
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol_spec()), encoding="utf-8")
    freeze_root = tmp_path / "freeze"
    assert main(["freeze", str(protocol_path), str(freeze_root)]) == 0
    verify_bundle(freeze_root)

    study = example_study()
    measurement_path = tmp_path / "measurements.json"
    measurement_path.write_text(
        json.dumps(measurement_document(study, complete_measurements(study))),
        encoding="utf-8",
    )
    analysis_root = tmp_path / "analysis"
    assert (
        main(
            [
                "analyze",
                str(freeze_root),
                str(measurement_path),
                str(analysis_root),
            ]
        )
        == 0
    )
    assert main(["verify", str(analysis_root)]) == 0
    summary = json.loads((analysis_root / "analysis.json").read_text(encoding="utf-8"))
    assert summary["study_id"] == study.study_id


@pytest.mark.milestone
def test_cli_rejects_cross_study_measurements(tmp_path: Path) -> None:
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol_spec()), encoding="utf-8")
    freeze_root = tmp_path / "freeze"
    main(["freeze", str(protocol_path), str(freeze_root)])
    study = example_study()
    document = measurement_document(study, complete_measurements(study))
    document["study_id"] = "study_" + "0" * 64
    measurement_path = tmp_path / "measurements.json"
    measurement_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen study"):
        main(["analyze", str(freeze_root), str(measurement_path), str(tmp_path / "analysis")])

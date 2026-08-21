from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import analyze_functional_judge_v3_single_candidate as analysis
from scripts import plan_functional_judge_v3_single_candidate as plan_module


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture(tmp_path: Path) -> SimpleNamespace:
    pilot = [
        {
            "case_id": "pilot-fail",
            "task_id": "task-a",
            "seed_id": 1,
            "code_text": "x = 1",
            "expected_status": "fail",
        },
        {
            "case_id": "pilot-pass",
            "task_id": "task-a",
            "seed_id": 2,
            "code_text": "x = 2",
            "expected_status": "pass",
        },
    ]
    remaining = [
        {
            "case_id": f"remaining-{index:02d}",
            "task_id": "task-a",
            "seed_id": 100 + index,
            "code_text": f"x = {index}",
            "expected_status": "pass" if index % 2 else "fail",
        }
        for index in range(22)
    ]
    metadata = {
        row["case_id"]: {"split": "tune" if row in pilot else "validation"}
        for row in [*pilot, *remaining]
    }
    thresholds = {
        "tune_cases": 8,
        "tune_min_correct": 8,
        "tune_max_false_pass": 0,
        "tune_max_equivalence_inconsistency": 0,
        "tune_role": "engineering_regression_gate_not_ranking",
        "validation_cases": 16,
        "validation_min_correct": 15,
        "validation_max_false_pass": 0,
        "validation_max_equivalence_inconsistency": 0,
        "validation_max_invalid": 0,
    }
    plan = {
        "plan_id": "functional_judge_v3_single_candidate_plan_" + "1" * 64,
        "pilot_case_ids": ["pilot-fail", "pilot-pass"],
        "thresholds": thresholds,
        "candidate": {
            "candidate_id": "qwen35flash-requirement-aggregate-v3",
            "candidate_role": "new_candidate",
            "protocol_version": "v3",
            "model_id": "qwen3.5-flash-2026-02-23",
            "evaluator_config_sha256": "1" * 64,
            "evaluator_policy_sha256": "2" * 64,
            "shared_evaluator_coordinates_sha256": "3" * 64,
        },
    }
    root = tmp_path / "run"
    return SimpleNamespace(
        plan=plan,
        metadata=metadata,
        pilot=pilot,
        remaining=remaining,
        pilot_root=root / "pilot",
        remaining_root=root / "remaining",
        transition_root=root / "pilot-transition",
        analysis_root=root / "analysis",
    )


def _run(fixture: SimpleNamespace, *, phase: str) -> dict[str, object]:
    cases = fixture.pilot if phase == "pilot" else fixture.remaining
    return {
        "root": str(fixture.pilot_root if phase == "pilot" else fixture.remaining_root),
        "root_manifest_sha256": "c" * 64 if phase == "pilot" else "d" * 64,
        **fixture.plan["candidate"],
        "measurement_method": "blind_static_llm_v3_requirement_aggregate",
        "cases": cases,
        "result_by_case": {
            row["case_id"]: {
                "case_id": row["case_id"],
                "expected_status": row["expected_status"],
                "actual_status": row["expected_status"],
                "consistent": True,
            }
            for row in cases
        },
        "traces": [{} for _ in cases],
        "trace_validity": [True for _ in cases],
        "passes": [object() for _ in cases],
        "outcomes": [object() for _ in cases],
        "started_at_utc": "9999-01-01T00:00:00+00:00" if phase == "remaining" else None,
    }


def test_plan_is_the_single_campaign_authority(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    run = _run(fixture, phase="pilot")

    assert analysis._candidate_matches_plan(run, fixture.plan, 2)
    run["evaluator_config_sha256"] = "f" * 64
    assert not analysis._candidate_matches_plan(run, fixture.plan, 2)


def test_pilot_transition_and_final_gate_need_no_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    pilot = _run(fixture, phase="pilot")
    remaining = _run(fixture, phase="remaining")
    monkeypatch.setattr(analysis.analyzer_core, "_run_slice", lambda _root: pilot)
    pilot_args = argparse.Namespace(
        output_dir=fixture.transition_root,
        pilot_run_dir=fixture.pilot_root,
        remaining_run_dir=None,
        pilot_transition_dir=None,
    )
    assert analysis._pilot_gate(pilot_args, plan=fixture.plan, raw_argv=["pilot-gate"])
    transition = _json(fixture.transition_root / "report.json")
    assert transition["remaining_authorized"] is True
    assert "campaign_receipt_id" not in transition

    monkeypatch.setattr(
        analysis.analyzer_core,
        "_run_slice",
        lambda root: pilot if Path(root) == fixture.pilot_root else remaining,
    )
    summary = {
        "candidate_id": fixture.plan["candidate"]["candidate_id"],
        "candidate_role": "new_candidate",
        "protocol_version": "v3",
        "provider_evidence": {"trace_records": 24},
        "gate_passed": True,
    }
    case_rows = [
        {"case_id": row["case_id"], "correct": True}
        for row in [*fixture.pilot, *fixture.remaining]
    ]
    monkeypatch.setattr(
        analysis.analyzer_core,
        "_candidate_summary",
        lambda *_args, **_kwargs: (summary, case_rows),
    )
    final_args = argparse.Namespace(
        output_dir=fixture.analysis_root,
        pilot_run_dir=fixture.pilot_root,
        remaining_run_dir=fixture.remaining_root,
        pilot_transition_dir=fixture.transition_root,
    )
    assert analysis._final_analysis(
        final_args,
        plan=fixture.plan,
        metadata=fixture.metadata,
        contracts={},
        raw_argv=["final"],
    )
    report = _json(fixture.analysis_root / "report.json")
    assert report["eligible_as_engineering_guardrail"] is True
    assert report["comparison_or_ranking_performed"] is False
    assert "campaign_receipt_id" not in report


def test_pilot_rows_keep_accuracy_separate_from_artifact_validity() -> None:
    case = {"case_id": "pilot-fail", "expected_status": "fail"}
    run = {
        "cases": [case],
        "result_by_case": {
            "pilot-fail": {
                "expected_status": "fail",
                "actual_status": "unknown",
                "consistent": True,
            }
        },
    }
    rows = analysis._pilot_rows(run, {"pilot-fail"})
    assert rows[0]["closure_valid"] is True
    assert rows[0]["correct"] is False


def test_single_candidate_plan_freezes_only_one_candidate() -> None:
    assert plan_module._EVALUATION_DESIGN["expected_candidates"] == 1
    assert plan_module._EVALUATION_DESIGN["expected_total_functional_judge_provider_attempts"] == 24
    assert plan_module._EVALUATION_DESIGN["historical_trace_reuse_allowed"] is False


def test_pilot_selection_falls_back_deterministically_when_tune_has_one_class() -> None:
    tune = [
        {"case_id": "case-c", "expected_status": "fail"},
        {"case_id": "case-a", "expected_status": "fail"},
        {"case_id": "case-b", "expected_status": "fail"},
    ]
    assert [row["case_id"] for row in plan_module._select_pilot_cases(tune)] == [
        "case-a",
        "case-b",
    ]

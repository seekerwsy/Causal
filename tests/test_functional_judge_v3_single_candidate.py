from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import analyze_functional_judge_v3_single_candidate as analysis
from scripts import freeze_functional_judge_v3_single_candidate_campaign as freezer
from scripts import plan_functional_judge_v3_single_candidate as plan_module

from secaware.pipeline.artifact import canonical_sha256


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    deployment_root = tmp_path / "deployment"
    plan_dir = tmp_path / "plan"
    deployment_root.mkdir()
    plan_dir.mkdir()
    prompt = deployment_root / "functional_judge_v3.txt"
    config = deployment_root / "evaluator-v3.json"
    spec = deployment_root / "calibration-spec.json"
    prompt.write_text("frozen v3 prompt\n", encoding="utf-8")
    config.write_text("{}\n", encoding="utf-8")
    spec.write_text("{}\n", encoding="utf-8")
    prompt_sha = freezer.campaign._sha256_file(prompt)
    config_sha = freezer.campaign._sha256_file(config)

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
    contracts = [{"task_id": "task-a", "contract": "frozen"}]
    plan_module._write_jsonl(plan_dir / "pilot-cases.jsonl", pilot)
    plan_module._write_jsonl(plan_dir / "remaining-cases.jsonl", remaining)
    plan_module._write_jsonl(plan_dir / "contracts.jsonl", contracts)
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
        "calibration_spec_sha256": freezer.campaign._sha256_file(spec),
        "case_counts": {
            "total": 24,
            "tune": 8,
            "validation": 16,
            "families": 4,
            "pilot": 2,
            "remaining": 22,
        },
        "pilot_case_ids": ["pilot-fail", "pilot-pass"],
        "thresholds": thresholds,
        "fresh_holdout_authorities": {
            "sha256": {
                "v3_evaluator_config": config_sha,
                "v3_system_prompt": prompt_sha,
            }
        },
    }
    evaluator = SimpleNamespace(
        candidate_id="qwen35flash-requirement-aggregate-v3",
        candidate_role="new_candidate",
        protocol_version="v3",
        model_id="qwen3.5-flash-2026-02-23",
        source_sha256=config_sha,
    )

    monkeypatch.setattr(
        freezer.campaign,
        "_verify_deployment",
        lambda *_args: (
            {
                "path": str(deployment_root / "DEPLOYMENT_MANIFEST.json"),
                "sha256": "2" * 64,
                "deployment_id": "fixture",
                "deployed_commit": "3" * 40,
                "files_manifest_path": str(deployment_root / "DEPLOYMENT_FILES.sha256"),
                "files_manifest_sha256": "4" * 64,
                "listed_files": 1,
                "execution_module_origins": [],
            },
            deployment_root,
            {},
        ),
    )
    monkeypatch.setattr(freezer.campaign, "_require_deployment_file", lambda *_a, **_k: None)
    monkeypatch.setattr(
        freezer.plan_module,
        "_load_closed_plan",
        lambda *_a, **_k: (plan, metadata, {}),
    )
    monkeypatch.setattr(freezer.campaign, "_load_evaluator", lambda *_a, **_k: evaluator)

    def preflight(_root, *, expected_count, phase, **_kwargs):
        return {
            "path": str(_root),
            "root_manifest_sha256": "5" * 64,
            "candidate_id": evaluator.candidate_id,
            "candidate_role": "new_candidate",
            "protocol_version": "v3",
            "phase": phase,
            "case_count": expected_count,
            "provider_cases_sha256": "6" * 64,
            "run_case_inputs_sha256": "7" * 64,
            "planned_evaluations_sha256": "8" * 64,
            "evaluator_config_sha256": config_sha,
            "evaluator_policy_sha256": "9" * 64,
            "shared_evaluator_coordinates_sha256": "a" * 64,
            "provider_attempts": 0,
            "provider_attempt_scope": "included_closed_run_trace_records",
        }

    monkeypatch.setattr(freezer.campaign, "_verify_preflight", preflight)
    future = tmp_path / "future"
    args = argparse.Namespace(
        deployment_manifest=deployment_root / "DEPLOYMENT_MANIFEST.json",
        deployed_commit="3" * 40,
        plan_dir=plan_dir,
        calibration_spec=spec,
        expected_plan_id=plan["plan_id"],
        expected_plan_root_manifest_sha256="b" * 64,
        v3_system_prompt=prompt,
        v3_evaluator_config=config,
        pilot_preflight_dir=tmp_path / "preflight-pilot",
        remaining_preflight_dir=tmp_path / "preflight-remaining",
        pilot_output_dir=future / "pilot",
        remaining_output_dir=future / "remaining",
        pilot_transition_output_dir=future / "pilot-transition",
        analysis_output_dir=future / "analysis",
        output_dir=future / "receipt",
    )
    receipt = freezer._freeze(args, raw_argv=["--fixture"])
    return SimpleNamespace(
        args=args,
        plan=plan,
        metadata=metadata,
        receipt=receipt,
        receipt_dir=args.output_dir,
        pilot=pilot,
        remaining=remaining,
    )


def test_minimal_receipt_has_no_historical_runtime_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    receipt = fixture.receipt
    assert receipt["budget"]["functional_judge_provider_attempts"] == 24
    assert receipt["budget"]["by_phase"] == {"pilot": 2, "remaining": 22}
    assert receipt["history"] == {
        "runtime_dependency": False,
        "included_in_analysis": False,
        "location": "separate immutable failure handoffs and experiment checkpoint",
    }
    serialized = json.dumps(receipt, sort_keys=True).casefold()
    assert "attempt_a06" not in serialized
    assert "attempt_a07" not in serialized
    assert "attempt_f135" not in serialized
    assert "historical_authorities" not in receipt
    assert receipt["receipt_id"] == (
        "functional_judge_v3_single_candidate_campaign_receipt_"
        + canonical_sha256({key: value for key, value in receipt.items() if key != "receipt_id"})
    )
    freezer.verify_closed_manifest(
        fixture.receipt_dir / "artifact-manifest.json", label="minimal receipt test"
    )


def test_minimal_receipt_refuses_existing_future_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    fixture.args.output_dir = tmp_path / "second-receipt"
    Path(fixture.args.pilot_output_dir).mkdir(parents=True)
    with pytest.raises(ValueError, match="future campaign output path already exists"):
        freezer._freeze(fixture.args, raw_argv=["--fixture"])


def _run(fixture, *, phase: str) -> dict[str, object]:
    cases = fixture.pilot if phase == "pilot" else fixture.remaining
    results = {
        row["case_id"]: {
            "case_id": row["case_id"],
            "expected_status": row["expected_status"],
            "actual_status": row["expected_status"],
            "consistent": True,
        }
        for row in cases
    }
    return {
        "root": str(
            fixture.args.pilot_output_dir if phase == "pilot" else fixture.args.remaining_output_dir
        ),
        "root_manifest_sha256": "c" * 64 if phase == "pilot" else "d" * 64,
        "candidate_id": fixture.receipt["candidate"]["candidate_id"],
        "candidate_role": "new_candidate",
        "protocol_version": "v3",
        "measurement_method": "blind_static_llm_v3_requirement_aggregate",
        "evaluator_policy_sha256": fixture.receipt["candidate"]["evaluator_policy_sha256"],
        "model_id": fixture.receipt["candidate"]["model_id"],
        "evaluator_config_sha256": fixture.receipt["candidate"]["evaluator_config_sha256"],
        "shared_evaluator_coordinates_sha256": fixture.receipt["candidate"][
            "shared_evaluator_coordinates_sha256"
        ],
        "cases": cases,
        "result_by_case": results,
        "traces": [{} for _ in cases],
        "trace_validity": [True for _ in cases],
        "passes": [object() for _ in cases],
        "outcomes": [object() for _ in cases],
        "started_at_utc": "9999-01-01T00:00:00+00:00" if phase == "remaining" else None,
    }


def test_one_analyzer_handles_pilot_transition_and_final_absolute_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    pilot = _run(fixture, phase="pilot")
    remaining = _run(fixture, phase="remaining")
    monkeypatch.setattr(analysis.analyzer_core, "_run_slice", lambda _root: pilot)
    pilot_args = argparse.Namespace(
        output_dir=fixture.args.pilot_transition_output_dir,
        pilot_run_dir=fixture.args.pilot_output_dir,
        remaining_run_dir=None,
        pilot_transition_dir=None,
    )
    assert analysis._pilot_gate(
        pilot_args,
        plan=fixture.plan,
        receipt=fixture.receipt,
        raw_argv=["--mode", "pilot-gate"],
    )
    transition = _json(fixture.args.pilot_transition_output_dir / "report.json")
    assert transition["status"] == analysis._PILOT_PASS
    assert transition["remaining_authorized"] is True

    monkeypatch.setattr(
        analysis.analyzer_core,
        "_run_slice",
        lambda root: pilot if Path(root) == Path(fixture.args.pilot_output_dir) else remaining,
    )
    summary = {
        "candidate_id": fixture.receipt["candidate"]["candidate_id"],
        "candidate_role": "new_candidate",
        "protocol_version": "v3",
        "provider_evidence": {"trace_records": 24},
        "gate_passed": True,
        "tune_engineering_regression_gate_not_ranking": {"correct": 8, "cases": 8},
        "validation": {"correct": 16, "cases": 16, "false_pass": 0, "invalid": 0},
    }
    case_rows = [
        {"case_id": row["case_id"], "correct": True} for row in [*fixture.pilot, *fixture.remaining]
    ]
    monkeypatch.setattr(
        analysis.analyzer_core,
        "_candidate_summary",
        lambda *_a, **_k: (summary, case_rows),
    )
    final_args = argparse.Namespace(
        output_dir=fixture.args.analysis_output_dir,
        pilot_run_dir=fixture.args.pilot_output_dir,
        remaining_run_dir=fixture.args.remaining_output_dir,
        pilot_transition_dir=fixture.args.pilot_transition_output_dir,
    )
    assert analysis._final_analysis(
        final_args,
        plan=fixture.plan,
        metadata=fixture.metadata,
        contracts={},
        receipt=fixture.receipt,
        raw_argv=["--mode", "final"],
    )
    report = _json(fixture.args.analysis_output_dir / "report.json")
    assert report["status"] == analysis._FINAL_PASS
    assert report["eligible_as_engineering_guardrail"] is True
    assert report["historical_runs_included"] is False
    assert report["comparison_or_ranking_performed"] is False


def test_single_candidate_plan_freezes_only_one_candidate() -> None:
    assert plan_module._EVALUATION_DESIGN == {
        "analysis_kind": "single_candidate_absolute_holdout",
        "candidate_role": "new_candidate",
        "candidate_protocol_version": "v3",
        "expected_candidates": 1,
        "expected_slices": 2,
        "expected_single_pass_attempts": 24,
        "expected_total_functional_judge_provider_attempts": 24,
        "historical_comparison_allowed": False,
        "historical_trace_reuse_allowed": False,
    }


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

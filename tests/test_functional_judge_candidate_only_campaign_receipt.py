from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
)
from secaware.pipeline.artifact import canonical_sha256

ROOT = Path(__file__).parents[1]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def candidate_only_fixture(tmp_path_factory):
    root = tmp_path_factory.mktemp("functional-judge-candidate-only-receipt")
    calibration_helpers = _load_module(
        "candidate_only_calibration_helpers",
        ROOT / "tests" / "test_functional_judge_calibration.py",
    )
    receipt_helpers = _load_module(
        "candidate_only_full_receipt_helpers",
        ROOT / "tests" / "test_functional_judge_calibration_campaign_receipt.py",
    )
    module = _load_module(
        "freeze_functional_judge_candidate_only_campaign_tested",
        ROOT / "scripts" / "freeze_functional_judge_candidate_only_campaign.py",
    )
    full = module.full_campaign

    with pytest.MonkeyPatch.context() as patch:
        plan_dir, canary, spec_path = calibration_helpers._build_plan(root, patch)
    deployment = receipt_helpers._build_deployment(
        root / "deployment",
        spec_path,
        module._execution_code_paths(),
    )
    baseline_config = Path(deployment["baseline_config"])
    new_config = Path(deployment["new_config"])

    preflights: dict[str, Path] = {}
    for candidate, config in (("baseline", baseline_config), ("new_candidate", new_config)):
        for phase, cases_name in (
            ("pilot", "pilot-cases.jsonl"),
            ("remaining", "remaining-cases.jsonl"),
        ):
            stage = f"{candidate}_{phase}"
            output = root / "preflights" / stage
            receipt_helpers._run_preflight(
                canary,
                output_dir=output,
                cases_path=plan_dir / cases_name,
                contracts_path=plan_dir / "contracts.jsonl",
                evaluator_config=config,
            )
            preflights[stage] = output

    execution_root = root / "source-execution"
    source_receipt_root = execution_root / "administration" / "campaign-receipt"
    baseline_pilot = execution_root / "candidate-runs" / "01-baseline-pilot"
    baseline_remaining = execution_root / "candidate-runs" / "02-baseline-remaining"
    source_full_values: dict[str, object] = {
        "deployment-manifest": deployment["manifest"],
        "deployed-commit": deployment["commit"],
        "source-final-delivery": root / "final-delivery.json",
        "sidecar-dir": root / "overlay",
        "plan-dir": plan_dir,
        "calibration-spec": deployment["spec"],
        "baseline-evaluator-config": baseline_config,
        "new-candidate-evaluator-config": new_config,
        "baseline-pilot-preflight-dir": preflights["baseline_pilot"],
        "baseline-remaining-preflight-dir": preflights["baseline_remaining"],
        "new-candidate-pilot-preflight-dir": preflights["new_candidate_pilot"],
        "new-candidate-remaining-preflight-dir": preflights["new_candidate_remaining"],
        "baseline-pilot-output-dir": baseline_pilot,
        "baseline-remaining-output-dir": baseline_remaining,
        "new-candidate-pilot-output-dir": (execution_root / "candidate-runs" / "03-old-v2-pilot"),
        "new-candidate-remaining-output-dir": (
            execution_root / "candidate-runs" / "04-old-v2-remaining"
        ),
        "analysis-output-dir": execution_root / "analysis",
        "output-dir": source_receipt_root,
    }
    source_full_argv: list[str] = []
    for name, value in source_full_values.items():
        source_full_argv.extend((f"--{name}", str(value)))

    deployment_root = Path(deployment["root"])
    deployed_execution_paths = [Path(path) for path in deployment["execution_paths"]]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(full, "_REPOSITORY_ROOT", deployment_root)
        patch.setattr(full, "_execution_code_paths", lambda: deployed_execution_paths)
        full_args = full._parse_args(source_full_argv)
        full._freeze_campaign(full_args, raw_argv=source_full_argv)

    with pytest.MonkeyPatch.context() as patch:
        baseline_runs = calibration_helpers._run_candidate(
            canary,
            patch,
            plan_dir,
            execution_root / "candidate-runs" / "baseline-build",
            "evaluator-qwen35flash-v1.json",
        )
        old_v2_runs = calibration_helpers._run_candidate(
            canary,
            patch,
            plan_dir,
            root / "old-v2-build",
            "evaluator-qwen35flash-v2b.json",
        )
    baseline_pilot.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(baseline_runs[0]), baseline_pilot)
    shutil.move(str(baseline_runs[1]), baseline_remaining)
    (execution_root / "candidate-runs" / "baseline-build").rmdir()
    old_v2_error = execution_root / "candidate-runs" / "03-old-v2-pilot"
    shutil.move(str(old_v2_runs[0]), old_v2_error)
    (old_v2_error / "artifact-manifest.json").unlink()
    old_v2_passes = [
        json.loads(line)
        for line in (old_v2_error / "functional_judge_passes.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ][:1]
    old_v2_outcomes = [
        json.loads(line)
        for line in (old_v2_error / "program_functional_outcomes.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ][:1]
    (old_v2_error / "functional_judge_passes.jsonl").unlink()
    (old_v2_error / "program_functional_outcomes.jsonl").unlink()
    _write_jsonl(old_v2_error / "functional_judge_passes.partial.jsonl", old_v2_passes)
    _write_jsonl(old_v2_error / "program_functional_outcomes.partial.jsonl", old_v2_outcomes)
    old_v2_report_path = old_v2_error / "report.json"
    old_v2_report = json.loads(old_v2_report_path.read_text(encoding="utf-8"))
    old_v2_report["status"] = "ERROR"
    old_v2_report["completed_case_count"] = 1
    old_v2_report["case_results"] = old_v2_report["case_results"][:1]
    old_v2_report["failure"] = {"error_code": 23, "error_stage": "functional_judge"}
    _write_json(old_v2_report_path, old_v2_report)
    write_closed_manifest_atomic(old_v2_error, label="source old-v2 error run fixture")
    shutil.rmtree(root / "old-v2-build")

    source_receipt = json.loads(
        (source_receipt_root / "campaign-receipt.json").read_text(encoding="utf-8")
    )
    plan = json.loads((plan_dir / "plan.json").read_text(encoding="utf-8"))
    spec = json.loads(Path(deployment["spec"]).read_text(encoding="utf-8"))
    source_handoff = execution_root / "final-delivery.json"
    _write_json(
        source_handoff,
        {
            "schema_version": "1.0",
            "status": "FUNCTIONAL_JUDGE_CALIBRATION_STOPPED_V2_PILOT_ERROR",
            "role": "engineering_calibration_failure_handoff",
            "claim": False,
            "scientific_claim_allowed": False,
            "delivery_id": "source-attempt-06-failure-handoff",
            "attempt": {
                "execution_root": str(execution_root.resolve()),
                "deployed_commit": deployment["commit"],
                "deployment_manifest_sha256": _sha256_file(Path(deployment["manifest"])),
            },
            "authorities": {
                "campaign_receipt_id": source_receipt["receipt_id"],
                "campaign_receipt_manifest_sha256": _sha256_file(
                    source_receipt_root / "artifact-manifest.json"
                ),
                "plan_id": plan["plan_id"],
                "plan_manifest_sha256": _sha256_file(plan_dir / "artifact-manifest.json"),
                "executable_sidecar_manifest_sha256": _sha256_file(
                    root / "overlay" / "artifact-manifest.json"
                ),
                "source_final_delivery_sha256": spec["source_final_delivery_sha256"],
            },
            "analysis": {
                "candidate_selection_made": False,
                "v2_gate_evaluated": False,
            },
            "candidate_roots": [
                {
                    "stage": "baseline_pilot",
                    "status": "FAIL",
                    "completed_cases": 2,
                    "trace_records": 2,
                    "root_manifest_sha256": _sha256_file(baseline_pilot / "artifact-manifest.json"),
                },
                {
                    "stage": "baseline_remaining",
                    "status": "FAIL",
                    "completed_cases": 22,
                    "trace_records": 22,
                    "root_manifest_sha256": _sha256_file(
                        baseline_remaining / "artifact-manifest.json"
                    ),
                },
                {
                    "stage": "new_candidate_pilot",
                    "status": "ERROR",
                    "completed_cases": 1,
                    "trace_records": 2,
                    "root_manifest_sha256": _sha256_file(old_v2_error / "artifact-manifest.json"),
                },
                {
                    "stage": "new_candidate_remaining",
                    "status": "NOT_STARTED",
                    "future_output_absent": True,
                    "trace_records": 0,
                },
            ],
            "new_calls": {
                "functional_judge_provider_trace_attempts": 26,
                "generation_provider_attempts": 0,
                "security_oracle_executions": 0,
            },
            "closed_trace_budget": {
                "observed_total": 26,
                "scope": "included_closed_run_trace_records",
                "absolute_global_call_claim_allowed": False,
            },
        },
    )
    write_closed_manifest_atomic(execution_root, label="source attempt execution root")

    baseline_payload = json.loads(baseline_config.read_text(encoding="utf-8"))
    new_payload = json.loads(new_config.read_text(encoding="utf-8"))
    superseded_execution = root / "superseded-attempt"
    superseded_error = superseded_execution / "candidate-runs" / "01-qwen35flash-prompt-v1-pilot"
    shutil.copytree(baseline_pilot, superseded_error)
    (superseded_error / "artifact-manifest.json").unlink()
    traces = [
        json.loads(line)
        for line in (superseded_error / "llm_exchange_trace.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ][:1]
    _write_jsonl(superseded_error / "llm_exchange_trace.jsonl", traces)
    (superseded_error / "functional_judge_passes.jsonl").unlink()
    (superseded_error / "program_functional_outcomes.jsonl").unlink()
    superseded_report_path = superseded_error / "report.json"
    superseded_report = json.loads(superseded_report_path.read_text(encoding="utf-8"))
    superseded_report["status"] = "ERROR"
    superseded_report["completed_case_count"] = 0
    superseded_report["case_results"] = []
    superseded_report["provider_attempts"] = 1
    superseded_report["new_calls"]["functional_judge_provider_attempts"] = 1
    superseded_report["failure"] = {"error_code": 23, "error_stage": "functional_judge"}
    _write_json(superseded_report_path, superseded_report)
    write_closed_manifest_atomic(superseded_error, label="superseded baseline error fixture")
    superseded_handoff = superseded_execution / "final-delivery.json"
    _write_json(
        superseded_handoff,
        {
            "schema_version": "1.0",
            "status": "FUNCTIONAL_JUDGE_V2B_CALIBRATION_STOPPED_BASELINE_PILOT_ERROR",
            "role": "engineering_calibration_failure_handoff",
            "claim": False,
            "scientific_claim_allowed": False,
            "delivery_id": "superseded-attempt-07-failure-handoff",
            "attempt": {"execution_root": str(superseded_execution.resolve())},
            "authorities": {
                "plan_id": plan["plan_id"],
                "source_final_delivery_sha256": spec["source_final_delivery_sha256"],
                "executable_sidecar_manifest_sha256": _sha256_file(
                    root / "overlay" / "artifact-manifest.json"
                ),
                "active_baseline_config_sha256": _sha256_file(baseline_config),
                "active_v2b_config_sha256": _sha256_file(new_config),
            },
            "analysis": {
                "candidate_selection_made": False,
                "v2b_gate_evaluated": False,
            },
            "candidate_roots": [
                {
                    "stage": "baseline_pilot",
                    "status": "ERROR",
                    "completed_cases": 0,
                    "trace_records": 1,
                    "root_manifest_sha256": _sha256_file(
                        superseded_error / "artifact-manifest.json"
                    ),
                },
                {"stage": "baseline_remaining", "status": "NOT_STARTED"},
                {"stage": "new_candidate_pilot", "status": "NOT_STARTED"},
                {"stage": "new_candidate_remaining", "status": "NOT_STARTED"},
            ],
            "new_calls": {
                "functional_judge_provider_trace_attempts": 1,
                "generation_provider_attempts": 0,
                "security_oracle_executions": 0,
            },
            "closed_trace_budget": {
                "observed_total": 1,
                "scope": "included_closed_run_trace_records",
                "absolute_global_call_claim_allowed": False,
            },
            "test_only_config_coordinates": {
                "baseline_candidate_id": baseline_payload["candidate_id"],
                "new_candidate_id": new_payload["candidate_id"],
            },
        },
    )
    write_closed_manifest_atomic(
        superseded_execution,
        label="superseded attempt execution root fixture",
    )
    analyzer = module.analyzer
    loaded_plan, metadata, contracts = analyzer._load_plan(
        plan_dir,
        calibration_spec_path=Path(deployment["spec"]),
        expected_plan_id=plan["plan_id"],
        expected_root_manifest_sha256=_sha256_file(plan_dir / "artifact-manifest.json"),
    )
    baseline_slices = [analyzer._run_slice(baseline_pilot), analyzer._run_slice(baseline_remaining)]
    baseline_summary, baseline_case_rows = analyzer._candidate_summary(
        baseline_payload["candidate_id"],
        baseline_slices,
        metadata,
        contracts,
        set(loaded_plan["pilot_case_ids"]),
        loaded_plan["thresholds"],
    )
    compatibility_root = root / "baseline-reuse-compatibility"
    compatibility_root.mkdir()
    compatibility_deployment = root / "compatibility-deployment"
    compatibility_baseline = (
        compatibility_deployment
        / "data"
        / "functional-judge"
        / "blind-calibration-v3"
        / "evaluator-qwen35flash-v1.json"
    )
    compatibility_spec = compatibility_baseline.with_name("calibration-spec.json")
    compatibility_analyzer = (
        compatibility_deployment / "scripts" / "analyze_functional_judge_calibration.py"
    )
    compatibility_baseline.parent.mkdir(parents=True)
    compatibility_analyzer.parent.mkdir(parents=True)
    shutil.copy2(baseline_config, compatibility_baseline)
    shutil.copy2(Path(deployment["spec"]), compatibility_spec)
    shutil.copy2(
        ROOT / "scripts" / "analyze_functional_judge_calibration.py", compatibility_analyzer
    )
    compatibility_inventory = compatibility_deployment / "DEPLOYMENT_FILES.sha256"
    compatibility_inventory.write_text("test compatibility inventory\n", encoding="utf-8")
    compatibility_manifest = compatibility_deployment / "DEPLOYMENT_MANIFEST.json"
    _write_json(
        compatibility_manifest,
        {
            "schema_version": "1.0",
            "deployed_commit": deployment["commit"],
            "deployment_files": {
                "path": compatibility_inventory.name,
                "sha256": _sha256_file(compatibility_inventory),
            },
        },
    )
    authority_paths = {
        "attempt_06_manifest": execution_root / "artifact-manifest.json",
        "attempt_06_v1_pilot_manifest": baseline_pilot / "artifact-manifest.json",
        "attempt_06_v1_remaining_manifest": baseline_remaining / "artifact-manifest.json",
        "current_active_v1_config": compatibility_baseline,
        "current_analyzer": compatibility_analyzer,
        "current_calibration_spec": compatibility_spec,
        "current_plan_manifest": plan_dir / "artifact-manifest.json",
        "deployment_inventory": compatibility_inventory,
        "deployment_manifest": compatibility_manifest,
    }
    authority_hashes = {
        "schema_version": "1.0",
        "authorities": {
            name: {"path": str(path.resolve()), "sha256": _sha256_file(path)}
            for name, path in authority_paths.items()
        },
    }
    _write_json(compatibility_root / "authority-hashes-before.json", authority_hashes)
    _write_json(compatibility_root / "authority-hashes-after.json", authority_hashes)
    _write_json(compatibility_root / "command.json", {"schema_version": "1.0"})
    (compatibility_root / "compatibility-probe.py").write_text(
        '"""Frozen test compatibility probe."""\n',
        encoding="utf-8",
    )
    _write_json(compatibility_root / "environment.json", {"schema_version": "1.0"})
    _write_json(compatibility_root / "error-ledger.json", {"errors": []})
    compatibility_core = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_JUDGE_BASELINE_REUSE_COMPATIBILITY_PASS",
        "scientific_claim_allowed": False,
        "reuse_authorized_by_this_diagnostic": False,
        "performance_metrics_republished": False,
        "decision_scope": (
            "Compatibility evidence only; candidate selection and scientific reuse require "
            "the separately frozen campaign authority."
        ),
        "purpose": "Read-only zero-call test compatibility diagnostic.",
        "deployed_commit": deployment["commit"],
        "case_closure_digest": canonical_sha256(baseline_case_rows),
        "compatibility": {name: True for name in sorted(module._COMPATIBILITY_FLAGS)},
        "new_calls": {
            "analyzer_provider_attempts": 0,
            "functional_judge_provider_attempts": 0,
            "generation_provider_attempts": 0,
            "oracle_executions": 0,
        },
        "source_evidence": {
            "included_closed_functional_judge_trace_records": 24,
            "included_closed_functional_judge_trace_scope": (
                "read_only_attempt_06_baseline_roots_not_new_calls"
            ),
        },
        "plan": {
            "path": str(plan_dir.resolve()),
            "manifest_sha256": _sha256_file(plan_dir / "artifact-manifest.json"),
            "plan_id": plan["plan_id"],
            "case_count": 24,
            "pilot_case_count": 2,
            "remaining_case_count": 22,
            "contract_count": 4,
            "provider_cases_sha256": plan["provider_cases_sha256"],
            "contracts_sha256": plan["contracts_sha256"],
            "case_metadata_sha256": plan["case_metadata_sha256"],
        },
        "baseline": {
            "candidate_id": baseline_payload["candidate_id"],
            "candidate_role": "baseline",
            "protocol_version": "v1",
            "measurement_method": baseline_summary["measurement_method"],
            "model_id": baseline_payload["model_id"],
            "evaluator_config_sha256": _sha256_file(baseline_config),
            "evaluator_policy_sha256": baseline_summary["evaluator_policy_sha256"],
            "shared_evaluator_coordinates_sha256": baseline_summary[
                "shared_evaluator_coordinates_sha256"
            ],
            "run_roots": [
                {
                    "manifest_sha256": _sha256_file(baseline_pilot / "artifact-manifest.json"),
                    "path": str(baseline_pilot.resolve()),
                    "phase": "pilot",
                    "report_status": next(
                        row["report_status"]
                        for row in baseline_summary["run_roots"]
                        if row["phase"] == "pilot"
                    ),
                },
                {
                    "manifest_sha256": _sha256_file(baseline_remaining / "artifact-manifest.json"),
                    "path": str(baseline_remaining.resolve()),
                    "phase": "remaining",
                    "report_status": next(
                        row["report_status"]
                        for row in baseline_summary["run_roots"]
                        if row["phase"] == "remaining"
                    ),
                },
            ],
            "source_closed_artifact_counts": baseline_summary["provider_evidence"],
        },
    }
    compatibility_report = {
        **compatibility_core,
        "diagnostic_id": "functional_judge_baseline_reuse_compatibility_"
        + canonical_sha256(compatibility_core),
    }
    _write_json(compatibility_root / "report.json", compatibility_report)
    write_closed_manifest_atomic(
        compatibility_root,
        label="baseline reuse compatibility diagnostic fixture",
    )
    expected_constants = {
        "_EXPECTED_SOURCE_EXECUTION_MANIFEST_SHA256": _sha256_file(
            execution_root / "artifact-manifest.json"
        ),
        "_EXPECTED_SOURCE_HANDOFF_SHA256": _sha256_file(source_handoff),
        "_EXPECTED_SOURCE_RECEIPT_ID": source_receipt["receipt_id"],
        "_EXPECTED_SOURCE_RECEIPT_MANIFEST_SHA256": _sha256_file(
            source_receipt_root / "artifact-manifest.json"
        ),
        "_EXPECTED_BASELINE_PILOT_MANIFEST_SHA256": _sha256_file(
            baseline_pilot / "artifact-manifest.json"
        ),
        "_EXPECTED_BASELINE_REMAINING_MANIFEST_SHA256": _sha256_file(
            baseline_remaining / "artifact-manifest.json"
        ),
        "_EXPECTED_SOURCE_OLD_V2_ERROR_MANIFEST_SHA256": _sha256_file(
            old_v2_error / "artifact-manifest.json"
        ),
        "_EXPECTED_COMPATIBILITY_ID": compatibility_report["diagnostic_id"],
        "_EXPECTED_COMPATIBILITY_MANIFEST_SHA256": _sha256_file(
            compatibility_root / "artifact-manifest.json"
        ),
        "_EXPECTED_COMPATIBILITY_AUTHORITY_HASHES_SHA256": _sha256_file(
            compatibility_root / "authority-hashes-before.json"
        ),
        "_EXPECTED_SUPERSEDED_EXECUTION_MANIFEST_SHA256": _sha256_file(
            superseded_execution / "artifact-manifest.json"
        ),
        "_EXPECTED_SUPERSEDED_HANDOFF_SHA256": _sha256_file(superseded_handoff),
        "_EXPECTED_SUPERSEDED_ERROR_MANIFEST_SHA256": _sha256_file(
            superseded_error / "artifact-manifest.json"
        ),
    }
    return {
        "root": root,
        "module": module,
        "full": full,
        "plan": plan_dir,
        "sidecar": root / "overlay",
        "spec": Path(deployment["spec"]),
        "delivery": root / "final-delivery.json",
        "baseline_config": baseline_config,
        "new_config": new_config,
        "new_preflights": {
            "new_candidate_pilot": preflights["new_candidate_pilot"],
            "new_candidate_remaining": preflights["new_candidate_remaining"],
        },
        "deployment_root": deployment_root,
        "deployment_execution_paths": deployed_execution_paths,
        "deployment_manifest": Path(deployment["manifest"]),
        "deployed_commit": deployment["commit"],
        "source_execution": execution_root,
        "source_receipt": source_receipt_root,
        "source_handoff": source_handoff,
        "superseded_handoff": superseded_handoff,
        "superseded_execution": superseded_execution,
        "superseded_error": superseded_error,
        "compatibility": compatibility_root,
        "old_v2_error": old_v2_error,
        "baseline_pilot": baseline_pilot,
        "baseline_remaining": baseline_remaining,
        "expected_constants": expected_constants,
    }


def _bind_execution_to_deployment(fixture: dict[str, object], monkeypatch) -> None:
    module = fixture["module"]
    full = fixture["full"]
    deployment_root = Path(fixture["deployment_root"])
    deployed_paths = [Path(path) for path in fixture["deployment_execution_paths"]]
    monkeypatch.setattr(module, "_REPOSITORY_ROOT", deployment_root)
    monkeypatch.setattr(module, "_execution_code_paths", lambda: deployed_paths)
    monkeypatch.setattr(full, "_REPOSITORY_ROOT", deployment_root)
    monkeypatch.setattr(full, "_execution_code_paths", lambda: deployed_paths)
    expected_constants = fixture["expected_constants"]
    assert isinstance(expected_constants, dict)
    for name, value in expected_constants.items():
        monkeypatch.setattr(module, name, value)


def _candidate_only_argv(
    fixture: dict[str, object],
    *,
    tag: str,
    receipt_dir: Path,
    overrides: dict[str, object] | None = None,
) -> tuple[list[str], dict[str, Path]]:
    root = Path(fixture["root"])
    preflights = fixture["new_preflights"]
    assert isinstance(preflights, dict)
    values: dict[str, object] = {
        "deployment-manifest": fixture["deployment_manifest"],
        "deployed-commit": fixture["deployed_commit"],
        "source-final-delivery": fixture["delivery"],
        "sidecar-dir": fixture["sidecar"],
        "plan-dir": fixture["plan"],
        "calibration-spec": fixture["spec"],
        "baseline-evaluator-config": fixture["baseline_config"],
        "new-candidate-evaluator-config": fixture["new_config"],
        "source-execution-dir": fixture["source_execution"],
        "source-campaign-receipt-dir": fixture["source_receipt"],
        "source-failure-handoff": fixture["source_handoff"],
        "superseded-attempt-final-delivery": fixture["superseded_handoff"],
        "baseline-reuse-compatibility-dir": fixture["compatibility"],
        "baseline-pilot-run-dir": fixture["baseline_pilot"],
        "baseline-remaining-run-dir": fixture["baseline_remaining"],
        "source-old-v2-error-run-dir": fixture["old_v2_error"],
        "superseded-execution-dir": fixture["superseded_execution"],
        "superseded-error-run-dir": fixture["superseded_error"],
        "new-candidate-pilot-preflight-dir": preflights["new_candidate_pilot"],
        "new-candidate-remaining-preflight-dir": preflights["new_candidate_remaining"],
        "new-candidate-pilot-output-dir": root / "future" / tag / "v2b-pilot",
        "new-candidate-remaining-output-dir": root / "future" / tag / "v2b-remaining",
        "analysis-output-dir": root / "future" / tag / "analysis",
        "output-dir": receipt_dir,
    }
    values.update(overrides or {})
    argv: list[str] = []
    for name, value in values.items():
        argv.extend((f"--{name}", str(value)))
    future = {
        name: Path(value)
        for name, value in values.items()
        if name.endswith("-output-dir") and name != "output-dir"
    }
    return argv, future


def _copy_reclosed(source: Path, destination: Path, mutate) -> Path:
    shutil.copytree(source, destination)
    (destination / "artifact-manifest.json").unlink()
    mutate(destination)
    write_closed_manifest_atomic(destination, label="reclosed candidate-only attack fixture")
    return destination


def test_candidate_only_receipt_reuses_closed_baseline_and_authorizes_only_24_new_calls(
    candidate_only_fixture,
    monkeypatch,
    tmp_path: Path,
) -> None:
    module = candidate_only_fixture["module"]
    _bind_execution_to_deployment(candidate_only_fixture, monkeypatch)
    receipt_dir = tmp_path / "candidate-only-receipt"
    argv, future = _candidate_only_argv(
        candidate_only_fixture,
        tag="positive",
        receipt_dir=receipt_dir,
    )
    receipt = module._freeze_campaign(module._parse_args(argv), raw_argv=argv)
    manifest = verify_closed_manifest(
        receipt_dir / "artifact-manifest.json",
        label="candidate-only receipt test",
    )
    assert {row["path"] for row in manifest["files"]} == {
        "campaign-receipt.json",
        "command.json",
        "environment.json",
    }
    core = {key: value for key, value in receipt.items() if key != "receipt_id"}
    assert receipt["receipt_id"] == (
        "functional_judge_candidate_only_campaign_receipt_" + canonical_sha256(core)
    )
    assert receipt["claim"] is False
    assert receipt["scientific_claim_allowed"] is False
    assert [row["case_count"] for row in receipt["stages"]] == [2, 22]
    assert receipt["expected_new_calls"]["functional_judge_provider_trace_attempts_total"] == 24
    assert receipt["cross_campaign_baseline_reuse"]["reused_closed_trace_records"] == 24
    assert receipt["cross_campaign_baseline_reuse"]["new_provider_calls_for_reuse"] == 0
    compatibility = receipt["cross_campaign_baseline_reuse"]["read_only_compatibility_authority"]
    assert compatibility["compatibility_flags"] == 20
    assert compatibility["reuse_authorized_by_this_diagnostic"] is False
    excluded_old_v2 = receipt["cross_campaign_baseline_reuse"]["excluded_old_candidate_error_run"]
    assert excluded_old_v2["received_trace_records"] == 2
    assert excluded_old_v2["partial_pass_records"] == 1
    assert receipt["superseded_attempt"]["error_run"]["received_trace_records"] == 1
    assert receipt["closed_trace_ledger"] == {
        "provider_attempt_scope": "included_closed_run_trace_records",
        "source_attempt_06_closed": 26,
        "source_attempt_06_reused_baseline": 24,
        "source_attempt_06_excluded_old_v2_error": 2,
        "superseded_attempt_07_excluded_repeated_v1_error": 1,
        "closed_before_this_campaign": 27,
        "new_authorized_candidate_traces": 24,
        "expected_closed_after_candidate_completion": 51,
        "expected_analysis_input_traces": 48,
        "excluded_from_analysis_traces": 3,
        "absolute_global_provider_call_claim_allowed": False,
    }
    assert receipt["analysis_output"]["expected_trace_records"] == 48
    assert receipt["limitations"][0]["limitation_id"] == (
        "recording_transport_post_return_trace_gap"
    )
    assert all(not path.exists() for path in future.values())
    with pytest.raises(FileExistsError):
        module._freeze_campaign(module._parse_args(argv), raw_argv=argv)


def test_candidate_only_archive_script_starts_without_editable_source_path(
    candidate_only_fixture,
) -> None:
    deployment_root = Path(candidate_only_fixture["deployment_root"])
    bytecode_before = {
        path.relative_to(deployment_root).as_posix()
        for path in deployment_root.rglob("*")
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
    }
    assert bytecode_before == set()
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(deployment_root / "scripts" / "freeze_functional_judge_candidate_only_campaign.py"),
            "--help",
        ],
        cwd=deployment_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--baseline-reuse-compatibility-dir" in completed.stdout
    bytecode_after = {
        path.relative_to(deployment_root).as_posix()
        for path in deployment_root.rglob("*")
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
    }
    assert bytecode_after == set()


@pytest.mark.parametrize(
    "attack",
    (
        "baseline_root",
        "baseline_policy",
        "plan",
        "baseline_case",
        "preflight",
        "output_exists",
        "source_handoff",
        "old_v2_error_root",
        "superseded_trace_ledger",
        "superseded_error_root",
        "compatibility",
        "compatibility_authority",
        "new_config",
    ),
)
def test_candidate_only_receipt_rejects_cross_campaign_and_tampered_authorities(
    candidate_only_fixture,
    monkeypatch,
    tmp_path: Path,
    attack: str,
) -> None:
    module = candidate_only_fixture["module"]
    _bind_execution_to_deployment(candidate_only_fixture, monkeypatch)
    overrides: dict[str, object] = {}
    receipt_dir = tmp_path / f"receipt-{attack}"
    if attack == "baseline_root":
        copied = tmp_path / "copied-identical-baseline-pilot"
        shutil.copytree(Path(candidate_only_fixture["baseline_pilot"]), copied)
        overrides["baseline-pilot-run-dir"] = copied
    elif attack == "baseline_policy":

        def mutate_policy(root: Path) -> None:
            config = json.loads((root / "config.json").read_text(encoding="utf-8"))
            config["evaluator_policy_sha256"] = "f" * 64
            _write_json(root / "config.json", config)

        overrides["baseline-pilot-run-dir"] = _copy_reclosed(
            Path(candidate_only_fixture["baseline_pilot"]),
            tmp_path / "baseline-policy-attack",
            mutate_policy,
        )
    elif attack == "plan":

        def mutate_plan(root: Path) -> None:
            plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
            plan["thresholds"]["validation_min_correct"] = 16
            core = {key: value for key, value in plan.items() if key != "plan_id"}
            plan["plan_id"] = "functional_judge_calibration_plan_" + canonical_sha256(core)
            _write_json(root / "plan.json", plan)

        overrides["plan-dir"] = _copy_reclosed(
            Path(candidate_only_fixture["plan"]),
            tmp_path / "plan-attack",
            mutate_plan,
        )
    elif attack == "baseline_case":

        def mutate_case(root: Path) -> None:
            rows = [
                json.loads(line)
                for line in (root / "canary_cases.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            rows[0]["code_text"] += "\n# tampered"
            _write_jsonl(root / "canary_cases.jsonl", rows)

        overrides["baseline-pilot-run-dir"] = _copy_reclosed(
            Path(candidate_only_fixture["baseline_pilot"]),
            tmp_path / "baseline-case-attack",
            mutate_case,
        )
    elif attack == "preflight":
        preflights = candidate_only_fixture["new_preflights"]
        assert isinstance(preflights, dict)
        overrides["new-candidate-pilot-preflight-dir"] = preflights["new_candidate_remaining"]
    elif attack == "source_handoff":
        handoff = json.loads(
            Path(candidate_only_fixture["source_handoff"]).read_text(encoding="utf-8")
        )
        next(row for row in handoff["candidate_roots"] if row["stage"] == "baseline_pilot")[
            "root_manifest_sha256"
        ] = "f" * 64
        attacked = tmp_path / "source-execution-copy"
        shutil.copytree(Path(candidate_only_fixture["source_execution"]), attacked)
        (attacked / "artifact-manifest.json").unlink()
        _write_json(attacked / "final-delivery.json", handoff)
        write_closed_manifest_atomic(attacked, label="attacked source execution root")
        overrides.update(
            {
                "source-execution-dir": attacked,
                "source-campaign-receipt-dir": attacked / "administration" / "campaign-receipt",
                "source-failure-handoff": attacked / "final-delivery.json",
                "baseline-pilot-run-dir": attacked / "candidate-runs" / "01-baseline-pilot",
                "baseline-remaining-run-dir": (
                    attacked / "candidate-runs" / "02-baseline-remaining"
                ),
            }
        )
    elif attack == "old_v2_error_root":
        copied = tmp_path / "copied-old-v2-error"
        shutil.copytree(Path(candidate_only_fixture["old_v2_error"]), copied)
        overrides["source-old-v2-error-run-dir"] = copied
    elif attack == "superseded_trace_ledger":
        handoff = json.loads(
            Path(candidate_only_fixture["superseded_handoff"]).read_text(encoding="utf-8")
        )
        handoff["new_calls"]["functional_judge_provider_trace_attempts"] = 2
        attacked = tmp_path / "superseded-handoff-attack.json"
        _write_json(attacked, handoff)
        overrides["superseded-attempt-final-delivery"] = attacked
    elif attack == "superseded_error_root":
        copied = tmp_path / "copied-superseded-error"
        shutil.copytree(Path(candidate_only_fixture["superseded_error"]), copied)
        overrides["superseded-error-run-dir"] = copied
    elif attack == "compatibility":

        def mutate_compatibility(root: Path) -> None:
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            report["compatibility"]["all_case_closures_valid"] = False
            core = {key: value for key, value in report.items() if key != "diagnostic_id"}
            report["diagnostic_id"] = (
                "functional_judge_baseline_reuse_compatibility_" + canonical_sha256(core)
            )
            _write_json(root / "report.json", report)

        overrides["baseline-reuse-compatibility-dir"] = _copy_reclosed(
            Path(candidate_only_fixture["compatibility"]),
            tmp_path / "compatibility-attack",
            mutate_compatibility,
        )
    elif attack == "compatibility_authority":

        def mutate_compatibility_authority(root: Path) -> None:
            hashes = json.loads((root / "authority-hashes-before.json").read_text(encoding="utf-8"))
            hashes["authorities"]["attempt_06_manifest"]["sha256"] = "f" * 64
            _write_json(root / "authority-hashes-before.json", hashes)
            _write_json(root / "authority-hashes-after.json", hashes)

        overrides["baseline-reuse-compatibility-dir"] = _copy_reclosed(
            Path(candidate_only_fixture["compatibility"]),
            tmp_path / "compatibility-authority-attack",
            mutate_compatibility_authority,
        )
    elif attack == "new_config":
        overrides["new-candidate-evaluator-config"] = candidate_only_fixture["baseline_config"]

    argv, future = _candidate_only_argv(
        candidate_only_fixture,
        tag=f"attack-{attack}",
        receipt_dir=receipt_dir,
        overrides=overrides,
    )
    if attack == "output_exists":
        next(iter(future.values())).mkdir(parents=True)
    with pytest.raises((ValueError, FileExistsError)):
        module._freeze_campaign(module._parse_args(argv), raw_argv=argv)
    assert not receipt_dir.exists()

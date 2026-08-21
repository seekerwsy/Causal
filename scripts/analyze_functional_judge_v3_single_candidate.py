"""Gate and analyze the minimal v3 single-candidate fresh-holdout campaign."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for _source_root in (_REPOSITORY_ROOT / "src", _REPOSITORY_ROOT):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))

from scripts import analyze_functional_judge_calibration as analyzer_core
from scripts import freeze_functional_judge_calibration_campaign as campaign
from scripts import freeze_functional_judge_v3_single_candidate_campaign as freezer
from scripts import plan_functional_judge_v3_single_candidate as plan_module

from secaware.pipeline.artifact import canonical_sha256

verify_closed_manifest = campaign.verify_closed_manifest
write_closed_manifest_atomic = campaign.write_closed_manifest_atomic
write_json_atomic_exclusive = campaign.write_json_atomic_exclusive

_OUTPUT_FILES = {"case-results.jsonl", "command.json", "environment.json", "report.json"}
_PILOT_PASS = "FUNCTIONAL_JUDGE_V3_PILOT_GATE_PASSED"
_PILOT_FAIL = "FUNCTIONAL_JUDGE_V3_PILOT_GATE_FAILED"
_FINAL_PASS = "FUNCTIONAL_JUDGE_V3_SINGLE_CANDIDATE_ELIGIBLE"
_FINAL_FAIL = "FUNCTIONAL_JUDGE_V3_SINGLE_CANDIDATE_INELIGIBLE"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate or analyze the frozen v3 campaign.")
    parser.add_argument("--mode", choices=("pilot-gate", "final"), required=True)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--calibration-spec", type=Path, required=True)
    parser.add_argument("--expected-plan-id", required=True)
    parser.add_argument("--expected-plan-root-manifest-sha256", required=True)
    parser.add_argument("--campaign-receipt-dir", type=Path, required=True)
    parser.add_argument("--expected-campaign-receipt-id", required=True)
    parser.add_argument("--expected-campaign-receipt-root-manifest-sha256", required=True)
    parser.add_argument("--pilot-run-dir", type=Path, required=True)
    parser.add_argument("--remaining-run-dir", type=Path)
    parser.add_argument("--pilot-transition-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_receipt(args: argparse.Namespace, plan: dict[str, object]) -> dict[str, object]:
    root = args.campaign_receipt_dir.resolve()
    manifest_path = root / "artifact-manifest.json"
    if campaign._sha256_file(manifest_path) != args.expected_campaign_receipt_root_manifest_sha256:
        raise ValueError("campaign receipt manifest identity failed validation")
    manifest = verify_closed_manifest(manifest_path, label="minimal v3 campaign receipt")
    if {str(row["path"]) for row in manifest["files"]} != freezer._RECEIPT_FILES:
        raise ValueError("campaign receipt file closure failed validation")
    receipt = campaign._read_json(root / "campaign-receipt.json")
    core = {key: value for key, value in receipt.items() if key != "receipt_id"}
    if (
        set(receipt) != freezer._RECEIPT_KEYS
        or receipt.get("receipt_id") != args.expected_campaign_receipt_id
        or receipt.get("receipt_id")
        != "functional_judge_v3_single_candidate_campaign_receipt_" + canonical_sha256(core)
        or receipt.get("status") != freezer._STATUS
        or receipt.get("claim") is not False
        or receipt.get("scientific_claim_allowed") is not False
        or receipt.get("plan", {}).get("plan_id") != plan["plan_id"]
        or receipt.get("plan", {}).get("root_manifest_sha256")
        != args.expected_plan_root_manifest_sha256
        or receipt.get("candidate", {}).get("candidate_id")
        != "qwen35flash-requirement-aggregate-v3"
        or receipt.get("candidate", {}).get("protocol_version") != "v3"
        or receipt.get("budget")
        != {
            "provider_attempt_scope": "included_closed_run_trace_records",
            "functional_judge_provider_attempts": 24,
            "by_phase": {"pilot": 2, "remaining": 22},
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        }
        or receipt.get("history", {}).get("runtime_dependency") is not False
        or receipt.get("history", {}).get("included_in_analysis") is not False
    ):
        raise ValueError("campaign receipt failed validation")
    return receipt


def _candidate_matches_receipt(
    run: dict[str, object], receipt: dict[str, object], expected_cases: int
) -> bool:
    candidate = receipt["candidate"]
    return (
        run["candidate_id"] == candidate["candidate_id"]
        and run["candidate_role"] == "new_candidate"
        and run["protocol_version"] == "v3"
        and run["model_id"] == candidate["model_id"]
        and run["evaluator_config_sha256"] == candidate["evaluator_config_sha256"]
        and run["evaluator_policy_sha256"] == candidate["evaluator_policy_sha256"]
        and run["shared_evaluator_coordinates_sha256"]
        == candidate["shared_evaluator_coordinates_sha256"]
        and len(run["cases"]) == expected_cases
    )


def _pilot_rows(run: dict[str, object], pilot_ids: set[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if {case["case_id"] for case in run["cases"]} != pilot_ids:
        raise ValueError("pilot case partition failed validation")
    for case in run["cases"]:
        result = run["result_by_case"].get(case["case_id"])
        valid = (
            type(result) is dict
            and result.get("expected_status") == case["expected_status"]
            and result.get("actual_status") == case["expected_status"]
            and result.get("consistent") is True
        )
        rows.append(
            {
                "schema_version": "1.0",
                "case_id": case["case_id"],
                "expected_status": case["expected_status"],
                "actual_status": result.get("actual_status") if type(result) is dict else "invalid",
                "correct": valid,
                "closure_valid": valid,
            }
        )
    return sorted(rows, key=lambda row: row["case_id"])


def _write_output(
    output_dir: Path,
    *,
    report: dict[str, object],
    case_rows: list[dict[str, object]],
    raw_argv: list[str],
) -> str:
    if output_dir.exists():
        raise FileExistsError("refusing to overwrite an existing v3 analysis output")
    output_dir.mkdir(parents=True, exist_ok=False)
    plan_module._write_jsonl(output_dir / "case-results.jsonl", case_rows)
    write_json_atomic_exclusive(output_dir / "report.json", report)
    write_json_atomic_exclusive(
        output_dir / "command.json",
        {
            "schema_version": "1.0",
            "argv": [sys.executable, str(Path(__file__).resolve()), *raw_argv],
            "provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
            "credential_value_read": False,
        },
    )
    write_json_atomic_exclusive(
        output_dir / "environment.json",
        {
            "schema_version": "1.0",
            "captured_at_utc": _utc_now(),
            "working_directory": str(Path.cwd().resolve()),
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "credential_value_read": False,
        },
    )
    write_closed_manifest_atomic(output_dir, label="v3 single-candidate analysis")
    manifest = verify_closed_manifest(
        output_dir / "artifact-manifest.json",
        label="published v3 single-candidate analysis",
    )
    if {str(row["path"]) for row in manifest["files"]} != _OUTPUT_FILES:
        raise ValueError("published v3 analysis file closure failed validation")
    return campaign._sha256_file(output_dir / "artifact-manifest.json")


def _pilot_gate(
    args: argparse.Namespace,
    *,
    plan: dict[str, object],
    receipt: dict[str, object],
    raw_argv: list[str],
) -> bool:
    output_dir = args.output_dir.resolve()
    if str(output_dir) != receipt["outputs"]["pilot_transition"]:
        raise ValueError("pilot transition output differs from the frozen receipt")
    if args.remaining_run_dir is not None or args.pilot_transition_dir is not None:
        raise ValueError("pilot gate received final-analysis inputs")
    if (
        Path(receipt["phases"][1]["output_root"]).exists()
        or Path(receipt["outputs"]["analysis"]).exists()
    ):
        raise ValueError("remaining or final analysis started before the pilot gate")

    pilot_root = args.pilot_run_dir.resolve()
    if str(pilot_root) != receipt["phases"][0]["output_root"]:
        raise ValueError("pilot root differs from the frozen receipt")
    run = analyzer_core._run_slice(pilot_root)
    if not _candidate_matches_receipt(run, receipt, 2):
        raise ValueError("pilot candidate differs from the frozen receipt")
    rows = _pilot_rows(run, set(plan["pilot_case_ids"]))
    passed = (
        len(run["traces"]) == 2
        and all(run["trace_validity"])
        and len(run["passes"]) == 2
        and len(run["outcomes"]) == 2
        and all(row["correct"] and row["closure_valid"] for row in rows)
    )
    completed_at = _utc_now()
    report_core = {
        "schema_version": "1.0",
        "status": _PILOT_PASS if passed else _PILOT_FAIL,
        "claim": False,
        "scientific_claim_allowed": False,
        "analysis_kind": "single_candidate_v3_pilot_transition",
        "completed_at_utc": completed_at,
        "plan_id": plan["plan_id"],
        "campaign_receipt_id": receipt["receipt_id"],
        "candidate_id": receipt["candidate"]["candidate_id"],
        "pilot_root": str(pilot_root),
        "pilot_root_manifest_sha256": run["root_manifest_sha256"],
        "provider_evidence": {
            "trace_records": len(run["traces"]),
            "structurally_valid_traces": sum(run["trace_validity"]),
            "pass_records": len(run["passes"]),
            "outcome_records": len(run["outcomes"]),
        },
        "case_count": 2,
        "correct": sum(row["correct"] for row in rows),
        "invalid": sum(not row["closure_valid"] for row in rows),
        "remaining_authorized": passed,
        "new_calls": {
            "analyzer_provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        },
    }
    report = {
        "transition_id": "functional_judge_v3_pilot_transition_" + canonical_sha256(report_core),
        **report_core,
    }
    _write_output(output_dir, report=report, case_rows=rows, raw_argv=raw_argv)
    return passed


def _load_pilot_transition(
    root: Path,
    *,
    receipt: dict[str, object],
    pilot_manifest_sha256: str,
) -> dict[str, object]:
    resolved = root.resolve()
    if str(resolved) != receipt["outputs"]["pilot_transition"]:
        raise ValueError("pilot transition root differs from the frozen receipt")
    manifest = verify_closed_manifest(
        resolved / "artifact-manifest.json",
        label="v3 pilot transition",
    )
    if {str(row["path"]) for row in manifest["files"]} != _OUTPUT_FILES:
        raise ValueError("pilot transition file closure failed validation")
    report = campaign._read_json(resolved / "report.json")
    core = {key: value for key, value in report.items() if key != "transition_id"}
    if (
        report.get("transition_id")
        != "functional_judge_v3_pilot_transition_" + canonical_sha256(core)
        or report.get("status") != _PILOT_PASS
        or report.get("remaining_authorized") is not True
        or report.get("campaign_receipt_id") != receipt["receipt_id"]
        or report.get("pilot_root_manifest_sha256") != pilot_manifest_sha256
        or report.get("correct") != 2
        or report.get("invalid") != 0
    ):
        raise ValueError("pilot transition did not authorize remaining")
    return report


def _final_analysis(
    args: argparse.Namespace,
    *,
    plan: dict[str, object],
    metadata: dict[str, dict[str, object]],
    contracts: dict[str, object],
    receipt: dict[str, object],
    raw_argv: list[str],
) -> bool:
    if args.remaining_run_dir is None or args.pilot_transition_dir is None:
        raise ValueError("final analysis requires remaining and pilot-transition roots")
    output_dir = args.output_dir.resolve()
    if str(output_dir) != receipt["outputs"]["analysis"]:
        raise ValueError("analysis output differs from the frozen receipt")

    pilot_root = args.pilot_run_dir.resolve()
    remaining_root = args.remaining_run_dir.resolve()
    if (
        str(pilot_root) != receipt["phases"][0]["output_root"]
        or str(remaining_root) != receipt["phases"][1]["output_root"]
    ):
        raise ValueError("candidate roots differ from the frozen receipt")
    pilot = analyzer_core._run_slice(pilot_root)
    remaining = analyzer_core._run_slice(remaining_root)
    transition = _load_pilot_transition(
        args.pilot_transition_dir,
        receipt=receipt,
        pilot_manifest_sha256=pilot["root_manifest_sha256"],
    )
    try:
        transition_at = datetime.fromisoformat(transition["completed_at_utc"])
        remaining_at = datetime.fromisoformat(remaining["started_at_utc"])
    except (TypeError, ValueError):
        raise ValueError("campaign phase timestamps failed validation") from None
    if transition_at > remaining_at:
        raise ValueError("remaining started before the pilot transition")

    summary, rows = analyzer_core._candidate_summary(
        receipt["candidate"]["candidate_id"],
        [pilot, remaining],
        metadata,
        contracts,
        set(plan["pilot_case_ids"]),
        plan["thresholds"],
    )
    if (
        not _candidate_matches_receipt(pilot, receipt, 2)
        or not _candidate_matches_receipt(remaining, receipt, 22)
        or summary["protocol_version"] != "v3"
        or summary["candidate_role"] != "new_candidate"
        or summary["provider_evidence"]["trace_records"] != 24
    ):
        raise ValueError("final candidate evidence differs from the frozen receipt")
    eligible = summary["gate_passed"] is True
    report_core = {
        "schema_version": "1.0",
        "status": _FINAL_PASS if eligible else _FINAL_FAIL,
        "claim": False,
        "scientific_claim_allowed": False,
        "analysis_kind": "single_candidate_absolute_holdout",
        "completed_at_utc": _utc_now(),
        "plan_id": plan["plan_id"],
        "campaign_receipt_id": receipt["receipt_id"],
        "candidate_summary": summary,
        "eligible_as_engineering_guardrail": eligible,
        "historical_runs_included": False,
        "comparison_or_ranking_performed": False,
        "new_calls": {
            "analyzer_provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        },
    }
    report = {
        "analysis_id": "functional_judge_v3_single_candidate_analysis_"
        + canonical_sha256(report_core),
        **report_core,
    }
    _write_output(output_dir, report=report, case_rows=rows, raw_argv=raw_argv)
    return eligible


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parse_args(raw_argv)
        plan, metadata, contracts = plan_module._load_closed_plan(
            args.plan_dir,
            calibration_spec_path=args.calibration_spec,
            expected_plan_id=args.expected_plan_id,
            expected_root_manifest_sha256=args.expected_plan_root_manifest_sha256,
        )
        receipt = _load_receipt(args, plan)
        if args.mode == "pilot-gate":
            passed = _pilot_gate(args, plan=plan, receipt=receipt, raw_argv=raw_argv)
        else:
            passed = _final_analysis(
                args,
                plan=plan,
                metadata=metadata,
                contracts=contracts,
                receipt=receipt,
                raw_argv=raw_argv,
            )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        print(f"functional Judge v3 analysis failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(
        _PILOT_PASS
        if args.mode == "pilot-gate" and passed
        else (
            _FINAL_PASS if passed else (_PILOT_FAIL if args.mode == "pilot-gate" else _FINAL_FAIL)
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

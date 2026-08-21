"""Freeze the minimal zero-call v3 single-candidate campaign receipt.

The receipt binds only the authorities needed to run the fresh campaign:
the immutable deployment, the closed 24-case plan, the v3 evaluator, two
zero-call preflights, the fixed 2+22 budget, and absent future outputs.
Historical failed campaigns remain in their own ledgers and are deliberately
not runtime dependencies of this campaign.
"""

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

from scripts import analyze_functional_judge_calibration as paired_analyzer
from scripts import freeze_functional_judge_calibration_campaign as campaign
from scripts import plan_functional_judge_v3_single_candidate as plan_module

from secaware.pipeline.artifact import canonical_sha256

verify_closed_manifest = campaign.verify_closed_manifest
write_closed_manifest_atomic = campaign.write_closed_manifest_atomic
write_json_atomic_exclusive = campaign.write_json_atomic_exclusive

_STATUS = "FUNCTIONAL_JUDGE_V3_SINGLE_CANDIDATE_CAMPAIGN_FROZEN"
_RECEIPT_FILES = {"campaign-receipt.json", "command.json", "environment.json"}
_RECEIPT_KEYS = {
    "budget",
    "candidate",
    "claim",
    "deployment",
    "gate",
    "history",
    "limitations",
    "outputs",
    "phases",
    "plan",
    "preflights",
    "purpose",
    "receipt_id",
    "schema_version",
    "scientific_claim_allowed",
    "status",
}
_PROVIDER_ATTEMPT_SCOPE = "included_closed_run_trace_records"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Freeze a minimal zero-call v3 fresh-holdout campaign."
    )
    parser.add_argument("--deployment-manifest", type=Path, required=True)
    parser.add_argument("--deployed-commit", required=True)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--calibration-spec", type=Path, required=True)
    parser.add_argument("--expected-plan-id", required=True)
    parser.add_argument("--expected-plan-root-manifest-sha256", required=True)
    parser.add_argument("--v3-system-prompt", type=Path, required=True)
    parser.add_argument("--v3-evaluator-config", type=Path, required=True)
    parser.add_argument("--pilot-preflight-dir", type=Path, required=True)
    parser.add_argument("--remaining-preflight-dir", type=Path, required=True)
    parser.add_argument("--pilot-output-dir", type=Path, required=True)
    parser.add_argument("--remaining-output-dir", type=Path, required=True)
    parser.add_argument("--pilot-transition-output-dir", type=Path, required=True)
    parser.add_argument("--analysis-output-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return campaign._read_jsonl(path.resolve())


def _freeze(args: argparse.Namespace, *, raw_argv: list[str]) -> dict[str, object]:
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("refusing to overwrite an existing v3 campaign receipt")

    deployment, deployment_root, deployment_files = campaign._verify_deployment(
        args.deployment_manifest,
        args.deployed_commit,
    )
    plan_dir = args.plan_dir.resolve()
    spec_path = args.calibration_spec.resolve()
    plan, metadata, _contracts = plan_module._load_closed_plan(
        plan_dir,
        calibration_spec_path=spec_path,
        expected_plan_id=args.expected_plan_id,
        expected_root_manifest_sha256=args.expected_plan_root_manifest_sha256,
    )

    prompt_path = args.v3_system_prompt.resolve()
    evaluator_path = args.v3_evaluator_config.resolve()
    for path, label in (
        (Path(__file__).resolve(), "campaign freezer"),
        (Path(plan_module.__file__).resolve(), "single-candidate planner"),
        (Path(paired_analyzer.__file__).resolve(), "functional Judge analyzer core"),
        (prompt_path, "v3 system prompt"),
        (evaluator_path, "v3 evaluator config"),
        (spec_path, "v4 calibration spec"),
    ):
        campaign._require_deployment_file(
            path,
            deployment_root=deployment_root,
            deployment_files=deployment_files,
            label=label,
        )

    evaluator = campaign._load_evaluator(
        evaluator_path,
        role="new_candidate",
        protocol="v3",
    )
    authority_hashes = plan["fresh_holdout_authorities"]["sha256"]
    if (
        evaluator.candidate_id != "qwen35flash-requirement-aggregate-v3"
        or evaluator.model_id != "qwen3.5-flash-2026-02-23"
        or evaluator.source_sha256 != authority_hashes["evaluator_config"]
        or campaign._sha256_file(prompt_path) != authority_hashes["system_prompt"]
    ):
        raise ValueError("v3 candidate identity failed validation")

    pilot_cases = _read_jsonl(plan_dir / "pilot-cases.jsonl")
    remaining_cases = _read_jsonl(plan_dir / "remaining-cases.jsonl")
    contract_rows = _read_jsonl(plan_dir / "contracts.jsonl")
    if (
        len(pilot_cases) != 2
        or len(remaining_cases) != 22
        or {row["case_id"] for row in pilot_cases} != set(plan["pilot_case_ids"])
        or any(metadata[row["case_id"]]["split"] != "tune" for row in pilot_cases)
    ):
        raise ValueError("v3 campaign partition failed validation")

    preflights = {
        "pilot": campaign._verify_preflight(
            args.pilot_preflight_dir,
            evaluator=evaluator,
            provider_cases=pilot_cases,
            contract_rows=contract_rows,
            cases_path=plan_dir / "pilot-cases.jsonl",
            contracts_path=plan_dir / "contracts.jsonl",
            evaluator_config_path=evaluator_path,
            expected_count=2,
            phase="v3 pilot",
        ),
        "remaining": campaign._verify_preflight(
            args.remaining_preflight_dir,
            evaluator=evaluator,
            provider_cases=remaining_cases,
            contract_rows=contract_rows,
            cases_path=plan_dir / "remaining-cases.jsonl",
            contracts_path=plan_dir / "contracts.jsonl",
            evaluator_config_path=evaluator_path,
            expected_count=22,
            phase="v3 remaining",
        ),
    }
    if (
        preflights["pilot"]["evaluator_policy_sha256"]
        != preflights["remaining"]["evaluator_policy_sha256"]
        or preflights["pilot"]["shared_evaluator_coordinates_sha256"]
        != preflights["remaining"]["shared_evaluator_coordinates_sha256"]
    ):
        raise ValueError("v3 preflight policy changed across phases")

    future = campaign._strict_absent_outputs(
        {
            "pilot": args.pilot_output_dir,
            "remaining": args.remaining_output_dir,
            "pilot_transition": args.pilot_transition_output_dir,
            "analysis": args.analysis_output_dir,
            "receipt": output_dir,
        }
    )
    campaign._reject_authority_output_overlap(
        future,
        {
            "deployment": deployment_root,
            "plan": plan_dir,
            "pilot_preflight": args.pilot_preflight_dir.resolve(),
            "remaining_preflight": args.remaining_preflight_dir.resolve(),
        },
    )

    receipt_core: dict[str, object] = {
        "schema_version": "1.0",
        "status": _STATUS,
        "claim": False,
        "scientific_claim_allowed": False,
        "purpose": "single_candidate_v3_fresh_holdout_engineering_eligibility",
        "deployment": deployment,
        "plan": {
            "path": str(plan_dir),
            "plan_id": plan["plan_id"],
            "root_manifest_sha256": args.expected_plan_root_manifest_sha256,
            "calibration_spec_sha256": plan["calibration_spec_sha256"],
            "case_counts": plan["case_counts"],
            "thresholds": plan["thresholds"],
            "fresh_holdout_authorities": plan["fresh_holdout_authorities"],
        },
        "candidate": {
            "candidate_id": evaluator.candidate_id,
            "candidate_role": "new_candidate",
            "protocol_version": "v3",
            "model_id": evaluator.model_id,
            "evaluator_config_path": str(evaluator_path),
            "evaluator_config_sha256": evaluator.source_sha256,
            "evaluator_policy_sha256": preflights["pilot"]["evaluator_policy_sha256"],
            "shared_evaluator_coordinates_sha256": preflights["pilot"][
                "shared_evaluator_coordinates_sha256"
            ],
            "system_prompt_path": str(prompt_path),
            "system_prompt_sha256": campaign._sha256_file(prompt_path),
        },
        "preflights": preflights,
        "phases": [
            {
                "ordinal": 1,
                "phase": "pilot",
                "case_count": 2,
                "output_root": str(future["pilot"]),
                "expected_closed_trace_records": 2,
            },
            {
                "ordinal": 2,
                "phase": "remaining",
                "case_count": 22,
                "output_root": str(future["remaining"]),
                "expected_closed_trace_records": 22,
                "requires_pilot_transition": str(future["pilot_transition"]),
            },
        ],
        "outputs": {
            "pilot_transition": str(future["pilot_transition"]),
            "analysis": str(future["analysis"]),
        },
        "budget": {
            "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
            "functional_judge_provider_attempts": 24,
            "by_phase": {"pilot": 2, "remaining": 22},
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        },
        "gate": {
            "pilot_requires": {
                "trace_records": 2,
                "pass_records": 2,
                "outcome_records": 2,
                "invalid": 0,
                "correct": 2,
            },
            "final_thresholds": plan["thresholds"],
        },
        "history": {
            "runtime_dependency": False,
            "included_in_analysis": False,
            "location": "separate immutable failure handoffs and experiment checkpoint",
        },
        "limitations": [
            "Provider counts refer to included closed-run trace records.",
            (
                "This campaign establishes an engineering guardrail, not executable "
                "correctness or a scientific claim."
            ),
        ],
    }
    receipt = {
        "receipt_id": "functional_judge_v3_single_candidate_campaign_receipt_"
        + canonical_sha256(receipt_core),
        **receipt_core,
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    write_json_atomic_exclusive(output_dir / "campaign-receipt.json", receipt)
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
    write_closed_manifest_atomic(output_dir, label="minimal v3 campaign receipt")
    manifest = verify_closed_manifest(
        output_dir / "artifact-manifest.json",
        label="published minimal v3 campaign receipt",
    )
    if {str(row["path"]) for row in manifest["files"]} != _RECEIPT_FILES:
        raise ValueError("published v3 receipt file closure failed validation")
    return receipt


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        receipt = _freeze(_parse_args(raw_argv), raw_argv=raw_argv)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        print(
            f"functional Judge v3 campaign freeze failed: {type(error).__name__}", file=sys.stderr
        )
        return 1
    print(receipt["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Freeze a candidate-only functional-Judge calibration campaign receipt.

This freezer reuses a semantically closed v1 baseline from an earlier campaign
and authorizes only the fresh v2 candidate slices.  It makes no provider,
generation, executable-functional, or security-Oracle calls.
"""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

# A deployment receipt must not mutate an immutable archive through imports.
sys.dont_write_bytecode = True

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for _source_root in (_REPOSITORY_ROOT / "src", _REPOSITORY_ROOT):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))

analyzer = importlib.import_module("scripts.analyze_functional_judge_calibration")
full_campaign = importlib.import_module("scripts.freeze_functional_judge_calibration_campaign")

verify_closed_manifest = full_campaign.verify_closed_manifest
write_closed_manifest_atomic = full_campaign.write_closed_manifest_atomic
write_json_atomic_exclusive = full_campaign.write_json_atomic_exclusive
canonical_sha256 = full_campaign.canonical_sha256
planner = full_campaign.planner

_PROVIDER_ATTEMPT_SCOPE = "included_closed_run_trace_records"
_NEW_PHASE_SPECS = (
    ("new_candidate_pilot", "pilot", 2),
    ("new_candidate_remaining", "remaining", 22),
)
_SOURCE_RECEIPT_FILES = {
    "campaign-receipt.json",
    "command.json",
    "environment.json",
}
_COMPATIBILITY_FILES = {
    "authority-hashes-after.json",
    "authority-hashes-before.json",
    "command.json",
    "compatibility-probe.py",
    "environment.json",
    "error-ledger.json",
    "report.json",
}
_COMPATIBILITY_FLAGS = {
    "active_v1_config_digest_matches_old_run",
    "all_case_closures_valid",
    "attempt_06_outer_root_closed",
    "attempt_06_v1_slice_roots_closed",
    "candidate_identity_matches_active_config",
    "candidate_role_matches_plan_and_active_config",
    "closed_trace_pass_outcome_counts_exact_24",
    "current_analyzer_reparsed_and_rebuilt_all_old_v1_records",
    "current_plan_case_count_exact_24",
    "current_plan_case_ids_exact",
    "current_plan_contract_and_code_bindings_passed",
    "current_plan_contracts_exact",
    "current_plan_loaded_with_current_analyzer",
    "current_plan_manifest_and_identity_closed",
    "current_plan_partition_exact_2_plus_22",
    "current_policy_digest_revalidated_against_old_run",
    "model_matches_active_config",
    "protocol_matches_plan_and_active_config",
    "provider_artifact_closure_gate",
    "single_pass_max_attempts_one_matches",
}
_EXPECTED_SOURCE_EXECUTION_MANIFEST_SHA256 = (
    "b10da690961070a968b9a1b5fee83d36a8c1da9c9787e064127fb088dd7b2734"
)
_EXPECTED_SOURCE_HANDOFF_SHA256 = "94737dec0d833a0f48313b31f33d12d935e4a2bd341a769211b7918d8c80f420"
_EXPECTED_SOURCE_RECEIPT_ID = (
    "functional_judge_calibration_campaign_receipt_"
    "8c6c922b46ed86a92b21931453e642376f7cf3cffb2a23c3ae29bed4c214252c"
)
_EXPECTED_SOURCE_RECEIPT_MANIFEST_SHA256 = (
    "1753e46af5a22e010b5044b17941179378af150fd2e6add65c7db6073a891483"
)
_EXPECTED_BASELINE_PILOT_MANIFEST_SHA256 = (
    "db6da143595d1be7808c6c82349cc0f64657bf1500c884a76681e4754954ebf7"
)
_EXPECTED_BASELINE_REMAINING_MANIFEST_SHA256 = (
    "de909391ed6d9b913500a27ef0cd9db3571abc15b31732d9b8531599886be92e"
)
_EXPECTED_SOURCE_OLD_V2_ERROR_MANIFEST_SHA256 = (
    "1e4506f7a087cd4b60ff5a829bf0be5f72b79ab47d772e27288c8bb1cf8e215d"
)
_EXPECTED_COMPATIBILITY_ID = (
    "functional_judge_baseline_reuse_compatibility_"
    "55c50c9c04a7db7b7e61afafcacbb410617af71da3aeb0a33af081c383f48ae0"
)
_EXPECTED_COMPATIBILITY_MANIFEST_SHA256 = (
    "66cbc3ad5097bd6c8ef7834e7b1c1015b76b499db7c09a976192663639f2657a"
)
_EXPECTED_COMPATIBILITY_AUTHORITY_HASHES_SHA256 = (
    "ce8d0ace719835f1d6b2013a00245fa169ecb4666a495bc6acfa1e5840feb8a9"
)
_EXPECTED_SUPERSEDED_EXECUTION_MANIFEST_SHA256 = (
    "ce2444a836dc66e03f4899a146d69c4761c34a9c23265609ef7424419ea06ed8"
)
_EXPECTED_SUPERSEDED_HANDOFF_SHA256 = (
    "d6592750244bd31d66ee48948db6260576afffdaa4a0b054c43483a99a1e9fb9"
)
_EXPECTED_SUPERSEDED_ERROR_MANIFEST_SHA256 = (
    "6137deeeeede27953454374fc010b4a565f0052c1c871ff31a41b6c285183163"
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _execution_code_paths() -> list[Path]:
    return sorted(
        {Path(__file__).resolve(), *full_campaign._execution_code_paths()},
        key=lambda path: path.as_posix(),
    )


def _validated_execution_origins(
    root: Path,
    listed: dict[str, str],
) -> list[dict[str, object]]:
    origins: list[dict[str, object]] = []
    for path in _execution_code_paths():
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            raise ValueError("execution module escaped the frozen deployment") from None
        digest = full_campaign._sha256_file(path)
        if listed.get(relative) != digest:
            raise ValueError("execution module is not covered by the deployment ledger")
        origins.append({"path": str(path), "relative_path": relative, "sha256": digest})
    return origins


def _verify_deployment(
    manifest_path: Path,
    deployed_commit: str,
) -> tuple[dict[str, object], Path, dict[str, str]]:
    deployment, root, listed = full_campaign._verify_deployment(
        manifest_path,
        deployed_commit,
    )
    deployment["execution_module_origins"] = _validated_execution_origins(root, listed)
    return deployment, root, listed


def _read_handoff(path: Path, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} failed validation") from error
    if type(value) is not dict:
        raise ValueError(f"{label} failed validation")
    return value


def _path_is_within(path: Path, root: Path, *, label: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        raise ValueError(f"{label} escaped its execution authority") from None


def _stage_map(rows: object, *, label: str) -> dict[str, dict[str, object]]:
    if type(rows) is not list:
        raise ValueError(f"{label} stages failed validation")
    mapped: dict[str, dict[str, object]] = {}
    for row in rows:
        if type(row) is not dict or type(row.get("stage")) is not str:
            raise ValueError(f"{label} stages failed validation")
        stage = str(row["stage"])
        if stage in mapped:
            raise ValueError(f"{label} stages failed validation")
        mapped[stage] = row
    return mapped


def _validate_closed_error_run(
    root: Path,
    *,
    label: str,
    expected_manifest_sha256: str,
    expected_files: set[str],
    expected_cases: list[dict[str, object]],
    expected_candidate_id: str,
    expected_candidate_role: str,
    expected_protocol_version: str,
    expected_model_id: str,
    expected_evaluator_config_sha256: str,
    expected_evaluator_policy_sha256: str | None,
    expected_trace_records: int,
    expected_completed_cases: int,
    expected_partial_passes: int,
    expected_partial_outcomes: int,
) -> dict[str, object]:
    root = root.resolve()
    manifest_path = root / "artifact-manifest.json"
    manifest = verify_closed_manifest(manifest_path, label=label)
    manifest_sha256 = full_campaign._sha256_file(manifest_path)
    if (
        manifest_sha256 != expected_manifest_sha256
        or {str(row["path"]) for row in manifest["files"]} != expected_files
    ):
        raise ValueError(f"{label} file closure failed validation")
    config = full_campaign._read_json(root / "config.json")
    report = full_campaign._read_json(root / "report.json")
    cases = full_campaign._read_jsonl(root / "canary_cases.jsonl")
    traces = full_campaign._read_jsonl(root / "llm_exchange_trace.jsonl")
    partial_passes = (
        full_campaign._read_jsonl(root / "functional_judge_passes.partial.jsonl")
        if expected_partial_passes
        else []
    )
    partial_outcomes = (
        full_campaign._read_jsonl(root / "program_functional_outcomes.partial.jsonl")
        if expected_partial_outcomes
        else []
    )
    policy_sha256 = config.get("evaluator_policy_sha256")
    if (
        cases != expected_cases
        or config.get("candidate_id") != expected_candidate_id
        or config.get("candidate_role") != expected_candidate_role
        or config.get("protocol_version") != expected_protocol_version
        or config.get("model_id") != expected_model_id
        or config.get("evaluator_config_sha256") != expected_evaluator_config_sha256
        or type(policy_sha256) is not str
        or (
            expected_evaluator_policy_sha256 is not None
            and policy_sha256 != expected_evaluator_policy_sha256
        )
        or config.get("judge_mode") != "single_pass"
        or config.get("max_attempts") != 1
        or report.get("status") != "ERROR"
        or report.get("total_case_count") != len(expected_cases)
        or report.get("completed_case_count") != expected_completed_cases
        or report.get("provider_attempts") != expected_trace_records
        or report.get("provider_attempt_scope") != _PROVIDER_ATTEMPT_SCOPE
        or report.get("new_calls", {}).get("functional_judge_provider_attempts")
        != expected_trace_records
        or len(traces) != expected_trace_records
        or len(partial_passes) != expected_partial_passes
        or len(partial_outcomes) != expected_partial_outcomes
        or any(trace.get("response_status") != "received" for trace in traces)
        or any(not analyzer._trace_is_structurally_valid(trace, policy_sha256) for trace in traces)
    ):
        raise ValueError(f"{label} trace or policy closure failed validation")
    if len({trace.get("call_index") for trace in traces}) != len(traces):
        raise ValueError(f"{label} trace indices failed validation")

    validated_cases: list[dict[str, object]] = []
    for case in cases:
        try:
            contract = analyzer.TaskFunctionalContractRecord.model_validate(case["contract"])
        except Exception as error:
            raise ValueError(f"{label} case contract failed validation") from error
        validated_cases.append({**case, "validated_contract": contract})
    unused_cases = list(validated_cases)
    for trace in traces:
        match_index = next(
            (
                index
                for index, case in enumerate(unused_cases)
                if analyzer._request_matches_case(
                    trace,
                    case,
                    expected_protocol_version,
                    config.get("output_schema_sha256"),
                )
            ),
            None,
        )
        if match_index is None:
            raise ValueError(f"{label} request-to-case binding failed validation")
        unused_cases.pop(match_index)
    return {
        "path": str(root),
        "root_manifest_sha256": manifest_sha256,
        "status": "ERROR",
        "case_count": len(cases),
        "completed_cases": expected_completed_cases,
        "received_trace_records": len(traces),
        "partial_pass_records": len(partial_passes),
        "partial_outcome_records": len(partial_outcomes),
        "evaluator_config_sha256": expected_evaluator_config_sha256,
        "evaluator_policy_sha256": policy_sha256,
    }


def _validate_source_campaign_receipt(
    root: Path,
    *,
    plan: dict[str, object],
    plan_dir: Path,
    spec: dict[str, object],
    spec_path: Path,
    sidecar_manifest_sha256: str,
    baseline,
    baseline_policy_sha256: str,
    baseline_pilot_root: Path,
    baseline_remaining_root: Path,
    old_candidate_error_root: Path,
) -> dict[str, object]:
    root = root.resolve()
    manifest_path = root / "artifact-manifest.json"
    manifest = verify_closed_manifest(
        manifest_path,
        label="source full functional Judge campaign receipt",
    )
    manifest_sha256 = full_campaign._sha256_file(manifest_path)
    if {
        str(row["path"]) for row in manifest["files"]
    } != _SOURCE_RECEIPT_FILES or manifest_sha256 != _EXPECTED_SOURCE_RECEIPT_MANIFEST_SHA256:
        raise ValueError("source campaign receipt file closure failed validation")
    receipt = full_campaign._read_json(root / "campaign-receipt.json")
    core = {key: value for key, value in receipt.items() if key != "receipt_id"}
    if (
        receipt.get("receipt_id")
        != "functional_judge_calibration_campaign_receipt_" + canonical_sha256(core)
        or receipt.get("receipt_id") != _EXPECTED_SOURCE_RECEIPT_ID
        or receipt.get("status") != "FUNCTIONAL_JUDGE_CALIBRATION_CAMPAIGN_FROZEN"
        or receipt.get("claim") is not False
        or receipt.get("scientific_claim_allowed") is not False
    ):
        raise ValueError("source campaign receipt identity failed validation")

    authoritative = receipt.get("authoritative_inputs")
    if type(authoritative) is not dict:
        raise ValueError("source campaign authorities failed validation")
    source_plan = authoritative.get("calibration_plan")
    source_spec = authoritative.get("calibration_spec")
    source_sidecar = authoritative.get("executable_sidecar")
    source_baseline = authoritative.get("baseline_evaluator_config")
    source_old_candidate = authoritative.get("new_candidate_evaluator_config")
    source_delivery = authoritative.get("source_final_delivery")
    source_deployment = receipt.get("deployment")
    if not all(
        type(row) is dict
        for row in (
            source_plan,
            source_spec,
            source_sidecar,
            source_baseline,
            source_old_candidate,
            source_delivery,
            source_deployment,
        )
    ):
        raise ValueError("source campaign authorities failed validation")
    source_spec_path_raw = source_spec.get("path")
    if type(source_spec_path_raw) is not str:
        raise ValueError("source campaign calibration spec path failed validation")
    source_spec_path = Path(source_spec_path_raw).resolve()
    if not source_spec_path.is_file():
        raise ValueError("source campaign calibration spec is unavailable")
    source_old_config_path_raw = source_old_candidate.get("path")
    if type(source_old_config_path_raw) is not str:
        raise ValueError("source campaign old-candidate config path failed validation")
    source_old_config_path = Path(source_old_config_path_raw).resolve()
    if not source_old_config_path.is_file() or full_campaign._sha256_file(
        source_old_config_path
    ) != source_old_candidate.get("sha256"):
        raise ValueError("source campaign old-candidate config digest failed validation")
    if (
        source_plan.get("plan_id") != plan["plan_id"]
        or source_plan.get("provider_cases_sha256") != plan["provider_cases_sha256"]
        or source_plan.get("contracts_sha256") != plan["contracts_sha256"]
        or source_spec.get("sha256") != full_campaign._sha256_file(source_spec_path)
        or source_spec.get("sha256") != full_campaign._sha256_file(spec_path)
        or source_spec.get("calibration_id") != spec["calibration_id"]
        or source_delivery.get("sha256") != spec["source_final_delivery_sha256"]
        or source_sidecar.get("root_manifest_sha256") != sidecar_manifest_sha256
        or source_baseline.get("sha256") != baseline.source_sha256
        or source_baseline.get("candidate_id") != baseline.candidate_id
        or source_baseline.get("protocol_version") != "v1"
        or source_baseline.get("evaluator_policy_sha256") != baseline_policy_sha256
    ):
        raise ValueError("source campaign semantic authority failed validation")

    stages = _stage_map(receipt.get("stages"), label="source campaign receipt")
    if set(stages) != {
        "baseline_pilot",
        "baseline_remaining",
        "new_candidate_pilot",
        "new_candidate_remaining",
    }:
        raise ValueError("source campaign stage set failed validation")
    expected = {
        "baseline_pilot": ("pilot", 2, baseline_pilot_root),
        "baseline_remaining": ("remaining", 22, baseline_remaining_root),
    }
    for stage, (phase, count, run_root) in expected.items():
        row = stages[stage]
        cases_path = plan_dir / f"{phase}-cases.jsonl"
        if (
            row.get("candidate_role") != "baseline"
            or row.get("candidate_id") != baseline.candidate_id
            or row.get("protocol_version") != "v1"
            or row.get("phase") != phase
            or row.get("case_count") != count
            or row.get("cases_file_sha256") != full_campaign._sha256_file(cases_path)
            or row.get("contracts_file_sha256")
            != full_campaign._sha256_file(plan_dir / "contracts.jsonl")
            or row.get("evaluator_config_sha256") != baseline.source_sha256
            or row.get("expected_provider_trace_attempts") != count
            or row.get("provider_attempt_scope") != _PROVIDER_ATTEMPT_SCOPE
            or Path(str(row.get("future_output_path"))).resolve() != run_root.resolve()
            or row.get("future_output_absent") is not True
        ):
            raise ValueError("source campaign baseline preregistration failed validation")
    old_pilot = stages["new_candidate_pilot"]
    if (
        source_old_candidate.get("candidate_id") != old_pilot.get("candidate_id")
        or source_old_candidate.get("protocol_version") != "v2"
        or source_old_candidate.get("sha256") != old_pilot.get("evaluator_config_sha256")
        or old_pilot.get("candidate_role") != "new_candidate"
        or old_pilot.get("phase") != "pilot"
        or old_pilot.get("case_count") != 2
        or old_pilot.get("cases_file_sha256")
        != full_campaign._sha256_file(plan_dir / "pilot-cases.jsonl")
        or old_pilot.get("contracts_file_sha256")
        != full_campaign._sha256_file(plan_dir / "contracts.jsonl")
        or old_pilot.get("expected_provider_trace_attempts") != 2
        or old_pilot.get("provider_attempt_scope") != _PROVIDER_ATTEMPT_SCOPE
        or Path(str(old_pilot.get("future_output_path"))).resolve()
        != old_candidate_error_root.resolve()
        or old_pilot.get("future_output_absent") is not True
    ):
        raise ValueError("source campaign old-candidate preregistration failed validation")
    return {
        "path": str(root),
        "receipt_id": receipt["receipt_id"],
        "root_manifest_sha256": manifest_sha256,
        "deployed_commit": source_deployment["deployed_commit"],
        "deployment_manifest_sha256": source_deployment["sha256"],
        "plan_id": source_plan["plan_id"],
        "plan_root_manifest_sha256": source_plan["root_manifest_sha256"],
        "old_candidate": {
            "candidate_id": source_old_candidate["candidate_id"],
            "protocol_version": "v2",
            "evaluator_config_sha256": source_old_candidate["sha256"],
            "evaluator_policy_sha256": source_old_candidate["evaluator_policy_sha256"],
        },
    }


def _validate_source_failure_handoff(
    path: Path,
    *,
    execution_root: Path,
    execution_manifest_sha256: str,
    source_receipt: dict[str, object],
    plan: dict[str, object],
    plan_manifest_sha256: str,
    spec: dict[str, object],
    sidecar_manifest_sha256: str,
    baseline_manifests: dict[str, str],
) -> dict[str, object]:
    path = path.resolve()
    if path != execution_root / "final-delivery.json":
        raise ValueError("source failure handoff path failed validation")
    if full_campaign._sha256_file(path) != _EXPECTED_SOURCE_HANDOFF_SHA256:
        raise ValueError("source failure handoff digest failed validation")
    handoff = _read_handoff(path, label="source failure handoff")
    attempt = handoff.get("attempt")
    authorities = handoff.get("authorities")
    analysis = handoff.get("analysis")
    calls = handoff.get("new_calls")
    budget = handoff.get("closed_trace_budget")
    if not all(type(row) is dict for row in (attempt, authorities, analysis, calls, budget)):
        raise ValueError("source failure handoff schema failed validation")
    if (
        handoff.get("status") != "FUNCTIONAL_JUDGE_CALIBRATION_STOPPED_V2_PILOT_ERROR"
        or handoff.get("role") != "engineering_calibration_failure_handoff"
        or handoff.get("claim") is not False
        or handoff.get("scientific_claim_allowed") is not False
        or attempt.get("execution_root") != str(execution_root)
        or attempt.get("deployed_commit") != source_receipt["deployed_commit"]
        or attempt.get("deployment_manifest_sha256") != source_receipt["deployment_manifest_sha256"]
        or authorities.get("campaign_receipt_id") != source_receipt["receipt_id"]
        or authorities.get("campaign_receipt_manifest_sha256")
        != source_receipt["root_manifest_sha256"]
        or authorities.get("plan_id") != plan["plan_id"]
        or authorities.get("plan_manifest_sha256") != source_receipt["plan_root_manifest_sha256"]
        or authorities.get("executable_sidecar_manifest_sha256") != sidecar_manifest_sha256
        or authorities.get("source_final_delivery_sha256") != spec["source_final_delivery_sha256"]
        or analysis.get("candidate_selection_made") is not False
        or analysis.get("v2_gate_evaluated") is not False
        or calls
        != {
            "functional_judge_provider_trace_attempts": 26,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        }
        or budget.get("observed_total") != 26
        or budget.get("scope") != _PROVIDER_ATTEMPT_SCOPE
        or budget.get("absolute_global_call_claim_allowed") is not False
    ):
        raise ValueError("source failure handoff authority failed validation")
    # The source plan manifest may differ from the current re-created plan
    # manifest while the plan ID and all semantic inputs remain identical.
    if plan_manifest_sha256 == source_receipt["plan_root_manifest_sha256"]:
        plan_manifest_relation = "same_closed_manifest"
    else:
        plan_manifest_relation = "different_closure_same_semantic_plan_id"

    stages = _stage_map(handoff.get("candidate_roots"), label="source failure handoff")
    if set(stages) != {
        "baseline_pilot",
        "baseline_remaining",
        "new_candidate_pilot",
        "new_candidate_remaining",
    }:
        raise ValueError("source failure handoff stage set failed validation")
    for stage, count in (("baseline_pilot", 2), ("baseline_remaining", 22)):
        row = stages[stage]
        if (
            row.get("status") not in {"PASS", "FAIL"}
            or row.get("completed_cases") != count
            or row.get("trace_records") != count
            or row.get("root_manifest_sha256") != baseline_manifests[stage]
        ):
            raise ValueError("source failure handoff baseline root failed validation")
    old_candidate = stages["new_candidate_pilot"]
    if (
        old_candidate.get("status") != "ERROR"
        or old_candidate.get("trace_records") != 2
        or old_candidate.get("root_manifest_sha256")
        != _EXPECTED_SOURCE_OLD_V2_ERROR_MANIFEST_SHA256
        or stages["new_candidate_remaining"].get("status") != "NOT_STARTED"
    ):
        raise ValueError("source failure handoff excluded trace ledger failed validation")
    return {
        "path": str(path),
        "sha256": _EXPECTED_SOURCE_HANDOFF_SHA256,
        "delivery_id": handoff.get("delivery_id"),
        "status": handoff["status"],
        "execution_root": str(execution_root),
        "execution_root_manifest_sha256": execution_manifest_sha256,
        "plan_manifest_relation_to_current": plan_manifest_relation,
        "closed_trace_records": 26,
        "reused_baseline_trace_records": 24,
        "excluded_old_candidate_error_trace_records": 2,
    }


def _validate_superseded_attempt_handoff(
    path: Path,
    *,
    execution_root: Path,
    error_run_root: Path,
    plan: dict[str, object],
    spec: dict[str, object],
    sidecar_manifest_sha256: str,
    baseline,
    new_candidate,
    baseline_policy_sha256: str,
    expected_pilot_cases: list[dict[str, object]],
) -> dict[str, object]:
    path = path.resolve()
    execution_root = execution_root.resolve()
    error_run_root = error_run_root.resolve()
    execution_manifest_path = execution_root / "artifact-manifest.json"
    verify_closed_manifest(
        execution_manifest_path,
        label="superseded attempt execution root",
    )
    execution_manifest_sha256 = full_campaign._sha256_file(execution_manifest_path)
    if (
        execution_manifest_sha256 != _EXPECTED_SUPERSEDED_EXECUTION_MANIFEST_SHA256
        or path != execution_root / "final-delivery.json"
        or full_campaign._sha256_file(path) != _EXPECTED_SUPERSEDED_HANDOFF_SHA256
    ):
        raise ValueError("superseded attempt outer authority failed validation")
    _path_is_within(error_run_root, execution_root, label="superseded baseline error root")
    error_evidence = _validate_closed_error_run(
        error_run_root,
        label="superseded baseline-v1 error run",
        expected_manifest_sha256=_EXPECTED_SUPERSEDED_ERROR_MANIFEST_SHA256,
        expected_files={
            "canary_cases.jsonl",
            "commands.jsonl",
            "config.json",
            "environment.json",
            "events.jsonl",
            "llm_exchange_trace.jsonl",
            "report.json",
        },
        expected_cases=expected_pilot_cases,
        expected_candidate_id=baseline.candidate_id,
        expected_candidate_role="baseline",
        expected_protocol_version="v1",
        expected_model_id=baseline.model_id,
        expected_evaluator_config_sha256=baseline.source_sha256,
        expected_evaluator_policy_sha256=baseline_policy_sha256,
        expected_trace_records=1,
        expected_completed_cases=0,
        expected_partial_passes=0,
        expected_partial_outcomes=0,
    )
    handoff = _read_handoff(path, label="superseded attempt handoff")
    attempt = handoff.get("attempt")
    authorities = handoff.get("authorities")
    analysis = handoff.get("analysis")
    calls = handoff.get("new_calls")
    budget = handoff.get("closed_trace_budget")
    if not all(type(row) is dict for row in (attempt, authorities, analysis, calls, budget)):
        raise ValueError("superseded attempt handoff schema failed validation")
    if (
        handoff.get("status") != "FUNCTIONAL_JUDGE_V2B_CALIBRATION_STOPPED_BASELINE_PILOT_ERROR"
        or handoff.get("role") != "engineering_calibration_failure_handoff"
        or handoff.get("claim") is not False
        or handoff.get("scientific_claim_allowed") is not False
        or attempt.get("execution_root") != str(execution_root)
        or authorities.get("plan_id") != plan["plan_id"]
        or authorities.get("source_final_delivery_sha256") != spec["source_final_delivery_sha256"]
        or authorities.get("executable_sidecar_manifest_sha256") != sidecar_manifest_sha256
        or authorities.get("active_baseline_config_sha256") != baseline.source_sha256
        or authorities.get("active_v2b_config_sha256") != new_candidate.source_sha256
        or analysis.get("candidate_selection_made") is not False
        or analysis.get("v2b_gate_evaluated") is not False
        or calls
        != {
            "functional_judge_provider_trace_attempts": 1,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        }
        or budget.get("observed_total") != 1
        or budget.get("scope") != _PROVIDER_ATTEMPT_SCOPE
        or budget.get("absolute_global_call_claim_allowed") is not False
    ):
        raise ValueError("superseded attempt handoff authority failed validation")
    stages = _stage_map(handoff.get("candidate_roots"), label="superseded attempt handoff")
    pilot = stages.get("baseline_pilot")
    if (
        set(stages)
        != {
            "baseline_pilot",
            "baseline_remaining",
            "new_candidate_pilot",
            "new_candidate_remaining",
        }
        or type(pilot) is not dict
        or pilot.get("status") != "ERROR"
        or pilot.get("trace_records") != 1
        or pilot.get("root_manifest_sha256") != _EXPECTED_SUPERSEDED_ERROR_MANIFEST_SHA256
        or any(
            stages[name].get("status") != "NOT_STARTED"
            for name in (
                "baseline_remaining",
                "new_candidate_pilot",
                "new_candidate_remaining",
            )
        )
    ):
        raise ValueError("superseded attempt excluded trace ledger failed validation")
    return {
        "path": str(path),
        "sha256": _EXPECTED_SUPERSEDED_HANDOFF_SHA256,
        "delivery_id": handoff.get("delivery_id"),
        "status": handoff["status"],
        "execution_root": str(execution_root),
        "execution_root_manifest_sha256": execution_manifest_sha256,
        "error_run": error_evidence,
        "excluded_repeated_baseline_error_trace_records": 1,
    }


def _validate_baseline_reuse_compatibility(
    root: Path,
    *,
    plan: dict[str, object],
    plan_dir: Path,
    plan_manifest_sha256: str,
    spec_path: Path,
    baseline,
    baseline_summary: dict[str, object],
    baseline_case_rows: list[dict[str, object]],
    baseline_roots: dict[str, Path],
    baseline_manifests: dict[str, str],
) -> dict[str, object]:
    root = root.resolve()
    manifest_path = root / "artifact-manifest.json"
    manifest = verify_closed_manifest(
        manifest_path,
        label="baseline reuse compatibility diagnostic",
    )
    manifest_sha256 = full_campaign._sha256_file(manifest_path)
    if {
        str(row["path"]) for row in manifest["files"]
    } != _COMPATIBILITY_FILES or manifest_sha256 != _EXPECTED_COMPATIBILITY_MANIFEST_SHA256:
        raise ValueError("baseline reuse compatibility file closure failed validation")
    hashes_before = root / "authority-hashes-before.json"
    hashes_after = root / "authority-hashes-after.json"
    if (
        hashes_before.read_bytes() != hashes_after.read_bytes()
        or full_campaign._read_json(hashes_before) != full_campaign._read_json(hashes_after)
        or full_campaign._sha256_file(hashes_before)
        != _EXPECTED_COMPATIBILITY_AUTHORITY_HASHES_SHA256
    ):
        raise ValueError("baseline reuse compatibility mutated its authorities")
    authority_hashes = full_campaign._read_json(hashes_before)
    authorities = authority_hashes.get("authorities")
    expected_authority_names = {
        "attempt_06_manifest",
        "attempt_06_v1_pilot_manifest",
        "attempt_06_v1_remaining_manifest",
        "current_active_v1_config",
        "current_analyzer",
        "current_calibration_spec",
        "current_plan_manifest",
        "deployment_inventory",
        "deployment_manifest",
    }
    if (
        set(authority_hashes) != {"schema_version", "authorities"}
        or authority_hashes.get("schema_version") != "1.0"
        or type(authorities) is not dict
        or set(authorities) != expected_authority_names
        or any(
            type(row) is not dict or set(row) != {"path", "sha256"} for row in authorities.values()
        )
    ):
        raise ValueError("baseline reuse compatibility authority schema failed validation")
    resolved_authorities: dict[str, tuple[Path, str]] = {}
    for name, row in authorities.items():
        raw_path = row.get("path")
        digest = row.get("sha256")
        if type(raw_path) is not str or full_campaign._SHA256.fullmatch(str(digest)) is None:
            raise ValueError("baseline reuse compatibility authority entry failed validation")
        path = Path(raw_path).resolve()
        if not path.is_file() or full_campaign._sha256_file(path) != digest:
            raise ValueError("baseline reuse compatibility authority digest failed validation")
        resolved_authorities[name] = (path, str(digest))

    source_execution_root = baseline_roots["baseline_pilot"].parents[1]
    expected_source_authorities = {
        "attempt_06_manifest": (
            source_execution_root / "artifact-manifest.json",
            _EXPECTED_SOURCE_EXECUTION_MANIFEST_SHA256,
        ),
        "attempt_06_v1_pilot_manifest": (
            baseline_roots["baseline_pilot"] / "artifact-manifest.json",
            baseline_manifests["baseline_pilot"],
        ),
        "attempt_06_v1_remaining_manifest": (
            baseline_roots["baseline_remaining"] / "artifact-manifest.json",
            baseline_manifests["baseline_remaining"],
        ),
        "current_plan_manifest": (
            plan_dir / "artifact-manifest.json",
            plan_manifest_sha256,
        ),
    }
    for name, (expected_path, expected_digest) in expected_source_authorities.items():
        actual_path, actual_digest = resolved_authorities[name]
        if actual_path != expected_path.resolve() or actual_digest != expected_digest:
            raise ValueError("baseline reuse compatibility authority coordinate failed validation")

    compatibility_deployment_manifest_path, compatibility_deployment_manifest_sha = (
        resolved_authorities["deployment_manifest"]
    )
    compatibility_deployment_root = compatibility_deployment_manifest_path.parent
    expected_deployment_authorities: dict[str, tuple[str, str | None]] = {
        "current_active_v1_config": (
            "data/functional-judge/blind-calibration-v3/evaluator-qwen35flash-v1.json",
            baseline.source_sha256,
        ),
        "current_analyzer": (
            "scripts/analyze_functional_judge_calibration.py",
            full_campaign._sha256_file(Path(analyzer.__file__).resolve()),
        ),
        "current_calibration_spec": (
            "data/functional-judge/blind-calibration-v3/calibration-spec.json",
            full_campaign._sha256_file(spec_path),
        ),
        "deployment_inventory": ("DEPLOYMENT_FILES.sha256", None),
        "deployment_manifest": ("DEPLOYMENT_MANIFEST.json", None),
    }
    for name, (relative, expected_digest) in expected_deployment_authorities.items():
        actual_path, actual_digest = resolved_authorities[name]
        if actual_path != (compatibility_deployment_root / relative).resolve() or (
            expected_digest is not None and actual_digest != expected_digest
        ):
            raise ValueError("baseline reuse compatibility deployment binding failed validation")
    report = full_campaign._read_json(root / "report.json")
    report_core = {key: value for key, value in report.items() if key != "diagnostic_id"}
    compatibility = report.get("compatibility")
    report_plan = report.get("plan")
    report_baseline = report.get("baseline")
    source_evidence = report.get("source_evidence")
    new_calls = report.get("new_calls")
    if not all(
        type(row) is dict
        for row in (
            compatibility,
            report_plan,
            report_baseline,
            source_evidence,
            new_calls,
        )
    ):
        raise ValueError("baseline reuse compatibility schema failed validation")
    if (
        report.get("diagnostic_id")
        != "functional_judge_baseline_reuse_compatibility_" + canonical_sha256(report_core)
        or report.get("diagnostic_id") != _EXPECTED_COMPATIBILITY_ID
        or report.get("status") != "FUNCTIONAL_JUDGE_BASELINE_REUSE_COMPATIBILITY_PASS"
        or report.get("scientific_claim_allowed") is not False
        or report.get("reuse_authorized_by_this_diagnostic") is not False
        or report.get("performance_metrics_republished") is not False
        or report.get("decision_scope")
        != (
            "Compatibility evidence only; candidate selection and scientific reuse require "
            "the separately frozen campaign authority."
        )
        or set(compatibility) != _COMPATIBILITY_FLAGS
        or any(value is not True for value in compatibility.values())
        or new_calls
        != {
            "analyzer_provider_attempts": 0,
            "functional_judge_provider_attempts": 0,
            "generation_provider_attempts": 0,
            "oracle_executions": 0,
        }
        or source_evidence
        != {
            "included_closed_functional_judge_trace_records": 24,
            "included_closed_functional_judge_trace_scope": (
                "read_only_attempt_06_baseline_roots_not_new_calls"
            ),
        }
        or report.get("case_closure_digest") != canonical_sha256(baseline_case_rows)
    ):
        raise ValueError("baseline reuse compatibility decision failed validation")

    if (
        report_plan.get("path") != str(plan_dir)
        or report_plan.get("manifest_sha256") != plan_manifest_sha256
        or report_plan.get("plan_id") != plan["plan_id"]
        or report_plan.get("case_count") != 24
        or report_plan.get("pilot_case_count") != 2
        or report_plan.get("remaining_case_count") != 22
        or report_plan.get("contract_count") != 4
        or report_plan.get("provider_cases_sha256") != plan["provider_cases_sha256"]
        or report_plan.get("contracts_sha256") != plan["contracts_sha256"]
        or report_plan.get("case_metadata_sha256") != plan["case_metadata_sha256"]
    ):
        raise ValueError("baseline reuse compatibility plan failed validation")
    expected_roots = [
        {
            "manifest_sha256": baseline_manifests["baseline_pilot"],
            "path": str(baseline_roots["baseline_pilot"]),
            "phase": "pilot",
            "report_status": next(
                row["report_status"]
                for row in baseline_summary["run_roots"]
                if row["phase"] == "pilot"
            ),
        },
        {
            "manifest_sha256": baseline_manifests["baseline_remaining"],
            "path": str(baseline_roots["baseline_remaining"]),
            "phase": "remaining",
            "report_status": next(
                row["report_status"]
                for row in baseline_summary["run_roots"]
                if row["phase"] == "remaining"
            ),
        },
    ]
    if (
        report_baseline.get("candidate_id") != baseline.candidate_id
        or report_baseline.get("candidate_role") != "baseline"
        or report_baseline.get("protocol_version") != "v1"
        or report_baseline.get("measurement_method") != baseline_summary["measurement_method"]
        or report_baseline.get("model_id") != baseline.model_id
        or report_baseline.get("evaluator_config_sha256") != baseline.source_sha256
        or report_baseline.get("evaluator_policy_sha256")
        != baseline_summary["evaluator_policy_sha256"]
        or report_baseline.get("shared_evaluator_coordinates_sha256")
        != baseline_summary["shared_evaluator_coordinates_sha256"]
        or report_baseline.get("run_roots") != expected_roots
        or report_baseline.get("source_closed_artifact_counts")
        != baseline_summary["provider_evidence"]
    ):
        raise ValueError("baseline reuse compatibility baseline failed validation")
    compatibility_deployment = full_campaign._read_json(compatibility_deployment_manifest_path)
    inventory_path, inventory_sha256 = resolved_authorities["deployment_inventory"]
    deployment_files = compatibility_deployment.get("deployment_files")
    if (
        type(deployment_files) is not dict
        or compatibility_deployment_manifest_sha
        != full_campaign._sha256_file(compatibility_deployment_manifest_path)
        or compatibility_deployment.get("deployed_commit") != report.get("deployed_commit")
        or deployment_files.get("path") != inventory_path.name
        or deployment_files.get("sha256") != inventory_sha256
    ):
        raise ValueError("baseline reuse compatibility deployment authority failed validation")
    return {
        "path": str(root),
        "root_manifest_sha256": manifest_sha256,
        "diagnostic_id": report["diagnostic_id"],
        "status": report["status"],
        "compatibility_flags": len(compatibility),
        "case_closure_digest": report["case_closure_digest"],
        "authority_hashes_sha256": full_campaign._sha256_file(hashes_before),
        "provider_attempts": 0,
        "reuse_authorized_by_this_diagnostic": False,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze a zero-call candidate-only functional-Judge campaign that reuses "
            "a closed baseline from a prior full campaign."
        )
    )
    parser.add_argument("--deployment-manifest", type=Path, required=True)
    parser.add_argument("--deployed-commit", required=True)
    parser.add_argument("--source-final-delivery", type=Path, required=True)
    parser.add_argument("--sidecar-dir", type=Path, required=True)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--calibration-spec", type=Path, required=True)
    parser.add_argument("--baseline-evaluator-config", type=Path, required=True)
    parser.add_argument("--new-candidate-evaluator-config", type=Path, required=True)
    parser.add_argument("--source-execution-dir", type=Path, required=True)
    parser.add_argument("--source-campaign-receipt-dir", type=Path, required=True)
    parser.add_argument("--source-failure-handoff", type=Path, required=True)
    parser.add_argument("--superseded-attempt-final-delivery", type=Path, required=True)
    parser.add_argument("--baseline-reuse-compatibility-dir", type=Path, required=True)
    parser.add_argument("--baseline-pilot-run-dir", type=Path, required=True)
    parser.add_argument("--baseline-remaining-run-dir", type=Path, required=True)
    parser.add_argument("--source-old-v2-error-run-dir", type=Path, required=True)
    parser.add_argument("--superseded-execution-dir", type=Path, required=True)
    parser.add_argument("--superseded-error-run-dir", type=Path, required=True)
    for stage, _phase, _count in _NEW_PHASE_SPECS:
        parser.add_argument(f"--{stage.replace('_', '-')}-preflight-dir", type=Path, required=True)
        parser.add_argument(f"--{stage.replace('_', '-')}-output-dir", type=Path, required=True)
    parser.add_argument("--analysis-output-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _freeze_campaign(
    args: argparse.Namespace,
    *,
    raw_argv: list[str],
    command_argv: list[str] | None = None,
    command_argv_source: str = "programmatic_explicit_argv",
) -> dict[str, object]:
    if command_argv is None:
        command_argv = [sys.executable, str(Path(__file__).resolve()), *raw_argv]
    if (
        type(command_argv) is not list
        or not command_argv
        or any(type(value) is not str or not value for value in command_argv)
    ):
        raise ValueError("recorded command argv must be a non-empty list of strings")
    if command_argv_source not in {"programmatic_explicit_argv", "sys.orig_argv"}:
        raise ValueError("unsupported command argv source")

    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("refusing to overwrite an existing candidate-only receipt")
    deployment, deployment_root, deployment_files = _verify_deployment(
        args.deployment_manifest,
        args.deployed_commit,
    )
    spec_path = args.calibration_spec.resolve()
    delivery_path = args.source_final_delivery.resolve()
    sidecar_dir = args.sidecar_dir.resolve()
    plan_dir = args.plan_dir.resolve()
    baseline_path = args.baseline_evaluator_config.resolve()
    new_path = args.new_candidate_evaluator_config.resolve()
    for path, label in (
        (spec_path, "calibration spec"),
        (baseline_path, "baseline evaluator config"),
        (new_path, "new-candidate evaluator config"),
    ):
        full_campaign._require_deployment_file(
            path,
            deployment_root=deployment_root,
            deployment_files=deployment_files,
            label=label,
        )

    spec, family_specs = planner._load_spec(spec_path)
    planner._validate_delivery(delivery_path, spec)
    sidecar_rows, sidecar_manifest_sha256, sidecar_evidence_sha256, sidecar_contracts = (
        planner._load_tune_rows(sidecar_dir, spec, family_specs)
    )
    sidecar_report = full_campaign._read_json(sidecar_dir / "report.json")
    plan_manifest_path = plan_dir / "artifact-manifest.json"
    verify_closed_manifest(plan_manifest_path, label="candidate-only calibration plan authority")
    plan_manifest_sha256 = full_campaign._sha256_file(plan_manifest_path)
    plan_identity = full_campaign._read_json(plan_dir / "plan.json")
    expected_plan_id = plan_identity.get("plan_id")
    if type(expected_plan_id) is not str:
        raise ValueError("candidate-only calibration plan identity failed validation")
    plan, metadata, frozen_contracts = analyzer._load_plan(
        plan_dir,
        calibration_spec_path=spec_path,
        expected_plan_id=expected_plan_id,
        expected_root_manifest_sha256=plan_manifest_sha256,
    )
    contract_rows = full_campaign._read_jsonl(plan_dir / "contracts.jsonl")
    pilot_cases = full_campaign._read_jsonl(plan_dir / "pilot-cases.jsonl")
    remaining_cases = full_campaign._read_jsonl(plan_dir / "remaining-cases.jsonl")
    if (
        plan.get("case_counts")
        != {
            "total": 24,
            "tune": 8,
            "validation": 16,
            "families": 4,
            "pilot": 2,
            "remaining": 22,
        }
        or plan.get("tune_overlay_root_manifest_sha256") != sidecar_manifest_sha256
        or plan.get("tune_overlay_evidence_manifest_sha256") != sidecar_evidence_sha256
        or contract_rows != sidecar_contracts
        or len(sidecar_rows) != 8
        or sidecar_report.get("status") != "EXECUTABLE_FUNCTIONAL_SENSITIVITY_COMPLETE"
        or sidecar_report.get("sandbox_limitations") != []
        or sidecar_report.get("functional_contract_set_sha256")
        != spec["functional_contract_set_sha256"]
        or sidecar_report.get("counts", {}).get("tasks") != 4
        or sidecar_report.get("counts", {}).get("assignments") != 8
        or sidecar_report.get("counts", {}).get("provider_calls") != 0
        or sidecar_report.get("counts", {}).get("security_oracle_calls") != 0
        or plan.get("source_live_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or plan.get("source_live_root_provenance_sha256")
        != spec["source_live_root_provenance_sha256"]
    ):
        raise ValueError("candidate-only sidecar, plan, or contract authority failed validation")

    baseline = full_campaign._load_evaluator(baseline_path, role="baseline", protocol="v1")
    new_candidate = full_campaign._load_evaluator(
        new_path,
        role="new_candidate",
        protocol="v2",
    )
    baseline_shared = full_campaign._evaluator_shared_coordinates(baseline)
    new_shared = full_campaign._evaluator_shared_coordinates(new_candidate)
    active_config_root = deployment_root / "data" / "functional-judge" / "blind-calibration-v3"
    if (
        baseline_path != (active_config_root / "evaluator-qwen35flash-v1.json").resolve()
        or new_path != (active_config_root / "evaluator-qwen35flash-v2b.json").resolve()
        or baseline.candidate_id != "qwen35flash-prompt-v1"
        or new_candidate.candidate_id != "qwen35flash-prompt-v2b"
        or new_candidate.source_sha256 == baseline.source_sha256
        or baseline.candidate_id == new_candidate.candidate_id
        or baseline.model_id != new_candidate.model_id
        or baseline_shared != new_shared
        or baseline.max_attempts != 1
        or new_candidate.max_attempts != 1
    ):
        raise ValueError("candidate-only same-model shared-coordinate policy failed validation")

    baseline_roots = {
        "baseline_pilot": args.baseline_pilot_run_dir.resolve(),
        "baseline_remaining": args.baseline_remaining_run_dir.resolve(),
    }
    if len(set(baseline_roots.values())) != 2:
        raise ValueError("baseline reuse roots must be distinct")
    baseline_slices = [analyzer._run_slice(path) for path in baseline_roots.values()]
    baseline_summary, baseline_case_rows = analyzer._candidate_summary(
        baseline.candidate_id,
        baseline_slices,
        metadata,
        frozen_contracts,
        set(plan["pilot_case_ids"]),
        plan["thresholds"],
    )
    baseline_policy_sha256 = str(baseline_summary["evaluator_policy_sha256"])
    baseline_provider = baseline_summary["provider_evidence"]
    if (
        baseline_summary.get("candidate_role") != "baseline"
        or baseline_summary.get("protocol_version") != "v1"
        or baseline_summary.get("candidate_id") != baseline.candidate_id
        or baseline_summary.get("model_id") != baseline.model_id
        or baseline_summary.get("evaluator_config_sha256") != baseline.source_sha256
        or baseline_summary.get("shared_evaluator_coordinates") != baseline_shared
        or baseline_summary.get("eligible_for_selection") is not False
        or baseline_summary.get("selection_exclusion_reason") != "baseline_comparison_only"
        or baseline_summary.get("gates", {}).get("provider_attempt_and_artifact_closure")
        is not True
        or baseline_provider
        != {
            "expected_single_pass_attempts": 24,
            "trace_records": 24,
            "received_traces": 24,
            "structurally_valid_traces": 24,
            "pass_records": 24,
            "outcome_records": 24,
            "global_closure_errors": [],
        }
        or len(baseline_case_rows) != 24
        or any(not row["closure_valid"] for row in baseline_case_rows)
    ):
        raise ValueError("reused baseline semantic closure failed validation")

    execution_root = args.source_execution_dir.resolve()
    execution_manifest_path = execution_root / "artifact-manifest.json"
    verify_closed_manifest(
        execution_manifest_path,
        label="source attempt execution root",
    )
    execution_manifest_sha256 = full_campaign._sha256_file(execution_manifest_path)
    if execution_manifest_sha256 != _EXPECTED_SOURCE_EXECUTION_MANIFEST_SHA256:
        raise ValueError("source attempt execution manifest identity failed validation")
    source_receipt_root = args.source_campaign_receipt_dir.resolve()
    source_handoff_path = args.source_failure_handoff.resolve()
    source_old_error_root = args.source_old_v2_error_run_dir.resolve()
    for path, label in (
        (source_receipt_root, "source campaign receipt"),
        (source_handoff_path, "source failure handoff"),
        (baseline_roots["baseline_pilot"], "source baseline pilot"),
        (baseline_roots["baseline_remaining"], "source baseline remaining"),
        (source_old_error_root, "source old-v2 error root"),
    ):
        _path_is_within(path, execution_root, label=label)
    source_receipt = _validate_source_campaign_receipt(
        source_receipt_root,
        plan=plan,
        plan_dir=plan_dir,
        spec=spec,
        spec_path=spec_path,
        sidecar_manifest_sha256=sidecar_manifest_sha256,
        baseline=baseline,
        baseline_policy_sha256=baseline_policy_sha256,
        baseline_pilot_root=baseline_roots["baseline_pilot"],
        baseline_remaining_root=baseline_roots["baseline_remaining"],
        old_candidate_error_root=source_old_error_root,
    )
    baseline_manifests = {
        stage: full_campaign._sha256_file(root / "artifact-manifest.json")
        for stage, root in baseline_roots.items()
    }
    if baseline_manifests != {
        "baseline_pilot": _EXPECTED_BASELINE_PILOT_MANIFEST_SHA256,
        "baseline_remaining": _EXPECTED_BASELINE_REMAINING_MANIFEST_SHA256,
    }:
        raise ValueError("source baseline manifest identity failed validation")
    source_old_candidate = source_receipt["old_candidate"]
    old_error_evidence = _validate_closed_error_run(
        source_old_error_root,
        label="source old-v2 error run",
        expected_manifest_sha256=_EXPECTED_SOURCE_OLD_V2_ERROR_MANIFEST_SHA256,
        expected_files={
            "canary_cases.jsonl",
            "commands.jsonl",
            "config.json",
            "environment.json",
            "events.jsonl",
            "functional_judge_passes.partial.jsonl",
            "llm_exchange_trace.jsonl",
            "program_functional_outcomes.partial.jsonl",
            "report.json",
        },
        expected_cases=full_campaign._expected_preflight_cases(pilot_cases, contract_rows),
        expected_candidate_id=source_old_candidate["candidate_id"],
        expected_candidate_role="new_candidate",
        expected_protocol_version="v2",
        expected_model_id=baseline.model_id,
        expected_evaluator_config_sha256=source_old_candidate["evaluator_config_sha256"],
        expected_evaluator_policy_sha256=source_old_candidate["evaluator_policy_sha256"],
        expected_trace_records=2,
        expected_completed_cases=1,
        expected_partial_passes=1,
        expected_partial_outcomes=1,
    )
    source_handoff = _validate_source_failure_handoff(
        source_handoff_path,
        execution_root=execution_root,
        execution_manifest_sha256=execution_manifest_sha256,
        source_receipt=source_receipt,
        plan=plan,
        plan_manifest_sha256=plan_manifest_sha256,
        spec=spec,
        sidecar_manifest_sha256=sidecar_manifest_sha256,
        baseline_manifests=baseline_manifests,
    )
    superseded_handoff = _validate_superseded_attempt_handoff(
        args.superseded_attempt_final_delivery,
        execution_root=args.superseded_execution_dir,
        error_run_root=args.superseded_error_run_dir,
        plan=plan,
        spec=spec,
        sidecar_manifest_sha256=sidecar_manifest_sha256,
        baseline=baseline,
        new_candidate=new_candidate,
        baseline_policy_sha256=baseline_policy_sha256,
        expected_pilot_cases=full_campaign._expected_preflight_cases(
            pilot_cases,
            contract_rows,
        ),
    )
    compatibility_authority = _validate_baseline_reuse_compatibility(
        args.baseline_reuse_compatibility_dir,
        plan=plan,
        plan_dir=plan_dir,
        plan_manifest_sha256=plan_manifest_sha256,
        spec_path=spec_path,
        baseline=baseline,
        baseline_summary=baseline_summary,
        baseline_case_rows=baseline_case_rows,
        baseline_roots=baseline_roots,
        baseline_manifests=baseline_manifests,
    )

    cases_by_phase = {"pilot": pilot_cases, "remaining": remaining_cases}
    preflights: dict[str, dict[str, object]] = {}
    for stage, phase, expected_count in _NEW_PHASE_SPECS:
        preflight_root = getattr(args, f"{stage}_preflight_dir")
        preflights[stage] = full_campaign._verify_preflight(
            preflight_root,
            evaluator=new_candidate,
            provider_cases=cases_by_phase[phase],
            contract_rows=contract_rows,
            cases_path=plan_dir / f"{phase}-cases.jsonl",
            contracts_path=plan_dir / "contracts.jsonl",
            evaluator_config_path=new_path,
            expected_count=expected_count,
            phase=stage,
        )
    if (
        preflights["new_candidate_pilot"]["evaluator_policy_sha256"]
        != preflights["new_candidate_remaining"]["evaluator_policy_sha256"]
        or preflights["new_candidate_pilot"]["evaluator_policy_sha256"] == baseline_policy_sha256
        or preflights["new_candidate_pilot"]["shared_evaluator_coordinates_sha256"]
        != baseline_summary["shared_evaluator_coordinates_sha256"]
    ):
        raise ValueError("candidate-only preflight policy closure failed validation")

    future_paths = {
        stage: getattr(args, f"{stage}_output_dir") for stage, _phase, _count in _NEW_PHASE_SPECS
    }
    future_paths["analysis"] = args.analysis_output_dir
    future = full_campaign._strict_absent_outputs(future_paths)
    if output_dir in future.values() or any(
        output_dir in path.parents or path in output_dir.parents for path in future.values()
    ):
        raise ValueError("candidate-only receipt and future output paths overlap")
    authority_roots = {
        "deployment": deployment_root,
        "sidecar": sidecar_dir,
        "plan": plan_dir,
        "source_execution": execution_root,
        "superseded_attempt": args.superseded_execution_dir.resolve(),
        "baseline_reuse_compatibility": args.baseline_reuse_compatibility_dir.resolve(),
        **{
            f"preflight_{stage}": getattr(args, f"{stage}_preflight_dir").resolve()
            for stage, _phase, _count in _NEW_PHASE_SPECS
        },
    }
    full_campaign._reject_authority_output_overlap(
        {"receipt": output_dir, **future},
        authority_roots,
    )

    stages: list[dict[str, object]] = []
    for stage, phase, expected_count in _NEW_PHASE_SPECS:
        cases_path = plan_dir / f"{phase}-cases.jsonl"
        stages.append(
            {
                "stage": stage,
                "candidate_role": "new_candidate",
                "candidate_id": new_candidate.candidate_id,
                "protocol_version": new_candidate.protocol_version,
                "phase": phase,
                "case_count": expected_count,
                "cases_path": str(cases_path),
                "cases_file_sha256": full_campaign._sha256_file(cases_path),
                "contracts_path": str(plan_dir / "contracts.jsonl"),
                "contracts_file_sha256": full_campaign._sha256_file(plan_dir / "contracts.jsonl"),
                "evaluator_config_path": str(new_path),
                "evaluator_config_sha256": new_candidate.source_sha256,
                "evaluator_policy_sha256": preflights[stage]["evaluator_policy_sha256"],
                "max_attempts_per_case": 1,
                "expected_provider_trace_attempts": expected_count,
                "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
                "preflight": preflights[stage],
                "future_output_path": str(future[stage]),
                "future_output_absent": True,
            }
        )

    deployment["execution_module_origins"] = _validated_execution_origins(
        deployment_root,
        deployment_files,
    )
    baseline_roots_evidence = [
        {
            "stage": stage,
            "path": str(root),
            "root_manifest_sha256": baseline_manifests[stage],
            "case_count": 2 if stage == "baseline_pilot" else 22,
            "trace_records": 2 if stage == "baseline_pilot" else 22,
            "reuse_accounting": "reused_not_new",
        }
        for stage, root in baseline_roots.items()
    ]
    receipt_core: dict[str, object] = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_JUDGE_CANDIDATE_ONLY_CAMPAIGN_FROZEN",
        "role": "pre_provider_call_candidate_only_engineering_campaign_receipt",
        "claim": False,
        "scientific_claim_allowed": False,
        "official_artifact_replacement_allowed": False,
        "security_oracle_replacement_allowed": False,
        "purpose": (
            "Reuse the source campaign's semantically closed v1 baseline and authorize "
            "only fresh v2b pilot, remaining, and offline analysis outputs."
        ),
        "deployment": deployment,
        "authoritative_inputs": {
            "source_final_delivery": {
                "path": str(delivery_path),
                "sha256": full_campaign._sha256_file(delivery_path),
            },
            "calibration_spec": {
                "path": str(spec_path),
                "sha256": full_campaign._sha256_file(spec_path),
                "calibration_id": spec["calibration_id"],
            },
            "executable_sidecar": {
                "path": str(sidecar_dir),
                "root_manifest_sha256": sidecar_manifest_sha256,
                "evidence_manifest_sha256": sidecar_evidence_sha256,
                "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
                "provider_calls": 0,
                "security_oracle_calls": 0,
            },
            "calibration_plan": {
                "path": str(plan_dir),
                "plan_id": plan["plan_id"],
                "root_manifest_sha256": plan_manifest_sha256,
                "case_counts": plan["case_counts"],
                "provider_cases_sha256": plan["provider_cases_sha256"],
                "contracts_sha256": plan["contracts_sha256"],
                "cases_file_sha256": full_campaign._sha256_file(plan_dir / "cases.jsonl"),
                "pilot_cases_file_sha256": full_campaign._sha256_file(
                    plan_dir / "pilot-cases.jsonl"
                ),
                "remaining_cases_file_sha256": full_campaign._sha256_file(
                    plan_dir / "remaining-cases.jsonl"
                ),
                "contracts_file_sha256": full_campaign._sha256_file(plan_dir / "contracts.jsonl"),
            },
            "active_baseline_evaluator_config": {
                "path": str(baseline_path),
                "sha256": baseline.source_sha256,
                "candidate_id": baseline.candidate_id,
                "protocol_version": "v1",
                "evaluator_policy_sha256": baseline_policy_sha256,
            },
            "active_new_candidate_evaluator_config": {
                "path": str(new_path),
                "sha256": new_candidate.source_sha256,
                "candidate_id": new_candidate.candidate_id,
                "protocol_version": "v2",
                "evaluator_policy_sha256": preflights["new_candidate_pilot"][
                    "evaluator_policy_sha256"
                ],
            },
        },
        "cross_campaign_baseline_reuse": {
            "reuse_kind": "closed_baseline_slices_from_prior_full_campaign",
            "recorded_campaign_scope": (
                "first_and_only_complete_baseline_matching_the_frozen_plan_and_v1_policy"
            ),
            "source_execution": source_handoff,
            "source_campaign_receipt": source_receipt,
            "read_only_compatibility_authority": compatibility_authority,
            "excluded_old_candidate_error_run": old_error_evidence,
            "baseline_roots": baseline_roots_evidence,
            "semantic_reconstruction": {
                "analyzer_helper": "_run_slice_plus__candidate_summary",
                "case_count": 24,
                "case_rows_sha256": canonical_sha256(baseline_case_rows),
                "candidate_summary_sha256": canonical_sha256(baseline_summary),
                "provider_evidence": baseline_provider,
                "all_case_closures_valid": True,
                "selection_exclusion_reason": "baseline_comparison_only",
            },
            "reused_closed_trace_records": 24,
            "new_provider_calls_for_reuse": 0,
        },
        "superseded_attempt": superseded_handoff,
        "comparison_policy": {
            "same_model_required": True,
            "same_model_verified": True,
            "shared_evaluator_coordinates": baseline_shared,
            "shared_evaluator_coordinates_sha256": canonical_sha256(baseline_shared),
            "max_attempts_per_case": 1,
            "baseline_comparison_only": True,
            "baseline_never_selectable": True,
            "new_candidate_is_only_selection_candidate": True,
            "eligibility_requires_provider_closure_tune_and_validation_gates": True,
            "tune_role": "engineering_regression_gate_not_ranking",
            "ranking_uses_validation_only": True,
            "cross_campaign_delta_interpretation": ("descriptive_historical_comparison_only"),
            "selection_uses_frozen_analyzer_gates_without_override": True,
        },
        "phase_transition_policy": {
            "pilot_must_run_first": True,
            "remaining_may_start_only_after_pilot_root_is_closed": True,
            "required_pilot_cases": 2,
            "required_received_traces": 2,
            "required_structurally_valid_traces": 2,
            "required_pass_records": 2,
            "required_outcome_records": 2,
            "pilot_semantic_rebuild_must_be_valid": True,
            "required_invalid_responses": 0,
            "required_matches_to_frozen_pilot_gold": 2,
            "pilot_verdict_correctness_is_a_transition_condition": True,
        },
        "stages": stages,
        "analysis_output": {
            "future_output_path": str(future["analysis"]),
            "future_output_absent": True,
            "expected_candidate_run_paths": [
                str(baseline_roots["baseline_pilot"]),
                str(baseline_roots["baseline_remaining"]),
                str(future["new_candidate_pilot"]),
                str(future["new_candidate_remaining"]),
            ],
            "expected_trace_records": 48,
            "plan_id": plan["plan_id"],
            "plan_root_manifest_sha256": plan_manifest_sha256,
            "provider_attempts": 0,
        },
        "closed_trace_ledger": {
            "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
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
        },
        "expected_new_calls": {
            "functional_judge_provider_trace_attempts_by_stage": {
                stage: count for stage, _phase, count in _NEW_PHASE_SPECS
            },
            "functional_judge_provider_trace_attempts_total": 24,
            "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
            "freezer_provider_attempts": 0,
            "analyzer_provider_attempts": 0,
        },
        "measurement_boundary": {
            "primary_scalable_functional_guardrail": "Y_F^J",
            "executable_sensitivity_variable": "Y_F^E",
            "executable_sidecar_replaces_judge": False,
            "judge_replaces_security_oracle": False,
        },
        "credential": {
            "value_read_by_freezer": False,
            "value_recorded": False,
            "environment_variable_name_only": baseline.api_key_env,
        },
        "limitations": [
            {
                "limitation_id": "recording_transport_post_return_trace_gap",
                "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
                "statement": (
                    "RecordingTransport persists a trace only after the provider returns; a "
                    "process crash before that write can omit an actual provider call. Closed "
                    "trace totals therefore do not claim absolute global provider calls."
                ),
            }
        ],
    }
    receipt = {
        "receipt_id": "functional_judge_candidate_only_campaign_receipt_"
        + canonical_sha256(receipt_core),
        **receipt_core,
    }

    full_campaign._strict_absent_outputs(future)
    output_dir.mkdir(parents=True, exist_ok=False)
    write_json_atomic_exclusive(output_dir / "campaign-receipt.json", receipt)
    write_json_atomic_exclusive(
        output_dir / "command.json",
        {
            "schema_version": "1.0",
            "argv": command_argv,
            "argv_source": command_argv_source,
            "sys_dont_write_bytecode": sys.dont_write_bytecode,
            "secret_in_argv": False,
            "provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
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
            "credential_value_recorded": False,
        },
    )
    write_closed_manifest_atomic(
        output_dir,
        label="functional Judge candidate-only campaign receipt",
    )
    verify_closed_manifest(
        output_dir / "artifact-manifest.json",
        label="published functional Judge candidate-only campaign receipt",
    )
    full_campaign._strict_absent_outputs(future)
    return receipt


def _validated_process_invocation(raw_argv: list[str]) -> list[str]:
    original = getattr(sys, "orig_argv", None)
    if (
        type(original) is not list
        or not original
        or any(type(value) is not str or not value for value in original)
    ):
        raise ValueError("sys.orig_argv is unavailable or malformed")
    if len(original) <= len(raw_argv):
        raise ValueError("sys.orig_argv does not contain an interpreter invocation")
    if raw_argv and original[-len(raw_argv) :] != raw_argv:
        raise ValueError("sys.orig_argv does not match the parsed process arguments")
    invocation_prefix = original[: -len(raw_argv)] if raw_argv else original
    script_path = Path(__file__).resolve()
    direct_script = any(
        not value.startswith("-") and Path(value).resolve() == script_path
        for value in invocation_prefix[1:]
    )
    module_name = "scripts.freeze_functional_judge_candidate_only_campaign"
    module_script = any(
        value == "-m"
        and index + 1 < len(invocation_prefix)
        and invocation_prefix[index + 1] == module_name
        for index, value in enumerate(invocation_prefix)
    )
    if not (direct_script or module_script):
        raise ValueError("sys.orig_argv is not bound to this candidate-only freezer")
    return list(original)


def main(argv: list[str] | None = None) -> int:
    process_invocation = argv is None
    raw_argv = list(sys.argv[1:] if process_invocation else argv)
    args = _parse_args(raw_argv)
    try:
        command_argv = (
            _validated_process_invocation(raw_argv)
            if process_invocation
            else [sys.executable, str(Path(__file__).resolve()), *raw_argv]
        )
        receipt = _freeze_campaign(
            args,
            raw_argv=raw_argv,
            command_argv=command_argv,
            command_argv_source=(
                "sys.orig_argv" if process_invocation else "programmatic_explicit_argv"
            ),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - publish only a bounded failure class
        raise SystemExit(
            f"functional Judge candidate-only campaign freeze failed: {type(error).__name__}"
        ) from None
    print(receipt["receipt_id"])
    print("FUNCTIONAL_JUDGE_CANDIDATE_ONLY_CAMPAIGN_FROZEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

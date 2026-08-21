"""Analyze closed functional-Judge calibration runs without provider calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scripts.plan_functional_judge_calibration import _load_spec as _load_calibration_spec
from scripts.validate_bailian_functional_judge import _assignment_and_variant

from secaware.config import FunctionalJudgeLLMConfig
from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
)
from secaware.functional_judge.factory import _policy
from secaware.functional_judge.judge import (
    FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256,
    FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256,
    FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE,
    FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256,
    FUNCTIONAL_JUDGE_V3_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE_SHA256,
    FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
    _parse_response,
    _reject_duplicate_keys,
    functional_judge_policy_sha256,
)
from secaware.functional_judge.schema import (
    FunctionalJudgePassRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.llm.structured_transport import canonical_request_bytes
from secaware.pipeline.artifact import canonical_sha256

_METADATA_KEYS = frozenset(
    {
        "case_id",
        "code_sha256",
        "equivalence_group",
        "expected_status",
        "family",
        "gold_evidence_path",
        "gold_evidence_sha256",
        "gold_method",
        "paired_group_id",
        "schema_version",
        "seed_id",
        "source_id",
        "source_kind",
        "source_path",
        "source_role",
        "source_root_manifest_sha256",
        "source_sha256",
        "split",
        "task_id",
    }
)
_PROVIDER_CASE_KEYS = frozenset({"case_id", "code_text", "expected_status", "seed_id", "task_id"})
_RUN_CASE_KEYS = frozenset({*_PROVIDER_CASE_KEYS, "contract"})
_REPORT_CASE_KEYS = frozenset(
    {
        "actual_status",
        "assignment_id",
        "case_id",
        "consistent",
        "contract_id",
        "expected_status",
        "pass_statuses",
        "task_id",
    }
)
_THRESHOLD_KEYS = frozenset(
    {
        "selection_rule",
        "tune_cases",
        "tune_max_equivalence_inconsistency",
        "tune_max_false_pass",
        "tune_min_correct",
        "tune_role",
        "validation_cases",
        "validation_max_equivalence_inconsistency",
        "validation_max_false_pass",
        "validation_max_invalid",
        "validation_min_correct",
    }
)
_CANDIDATE_ROLES = {
    "baseline": "comparison_only_never_selected",
    "new_candidate": "eligible_after_all_gates",
}
_MEASUREMENT_METHOD = {
    "v1": "ast_validated_single_shot_llm",
    "v2": "blind_static_llm_v2",
    "v3": "blind_static_llm_v3_requirement_aggregate",
}
_SHA256_CHARS = frozenset("0123456789abcdef")
_POLICY_ARTIFACTS = {
    "v1": (
        FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256,
        FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256,
    ),
    "v2": (
        FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256,
        FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256,
    ),
    "v3": (
        FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE_SHA256,
        FUNCTIONAL_JUDGE_V3_OUTPUT_SCHEMA_SHA256,
    ),
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA256_CHARS


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path, *, optional: bool = False) -> list[dict[str, object]]:
    if optional and not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError(f"expected JSON objects: {path}")
        rows.append(value)
    return rows


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _load_plan(
    plan_dir: Path,
    *,
    calibration_spec_path: Path,
    expected_plan_id: str,
    expected_root_manifest_sha256: str,
) -> tuple[
    dict[str, object],
    dict[str, dict[str, object]],
    dict[str, TaskFunctionalContractRecord],
]:
    root = plan_dir.resolve()
    manifest_path = root / "artifact-manifest.json"
    if (
        not _is_sha256(expected_root_manifest_sha256)
        or _sha256_file(manifest_path) != expected_root_manifest_sha256
        or type(expected_plan_id) is not str
        or not expected_plan_id.startswith("functional_judge_calibration_plan_")
    ):
        raise ValueError("calibration plan authority failed validation")
    verify_closed_manifest(manifest_path, label="functional judge calibration plan")
    spec_path = calibration_spec_path.resolve()
    spec, family_specs = _load_calibration_spec(spec_path)
    plan = _read_json(root / "plan.json")
    cases = _read_jsonl(root / "cases.jsonl")
    pilot_cases = _read_jsonl(root / "pilot-cases.jsonl")
    remaining_cases = _read_jsonl(root / "remaining-cases.jsonl")
    metadata_rows = _read_jsonl(root / "calibration-case-metadata.jsonl")
    contract_rows = _read_jsonl(root / "contracts.jsonl")
    plan_content = {key: value for key, value in plan.items() if key != "plan_id"}
    comparison = plan.get("comparison_design")
    if (
        plan.get("status") != "FUNCTIONAL_JUDGE_CALIBRATION_PLAN_COMPLETE"
        or plan.get("plan_id") != expected_plan_id
        or plan.get("plan_id")
        != "functional_judge_calibration_plan_" + canonical_sha256(plan_content)
        or plan.get("calibration_id") != spec["calibration_id"]
        or plan.get("calibration_spec_sha256") != _sha256_file(spec_path)
        or plan.get("candidate_roles") != spec["candidate_roles"]
        or plan.get("executable_source_spec_id") != spec["executable_source_spec_id"]
        or plan.get("executable_source_spec_sha256") != spec["executable_source_spec_sha256"]
        or plan.get("frozen_functional_contracts_sha256")
        != spec["frozen_functional_contracts_sha256"]
        or plan.get("functional_contract_set_sha256") != spec["functional_contract_set_sha256"]
        or plan.get("source_final_delivery_sha256") != spec["source_final_delivery_sha256"]
        or plan.get("source_live_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or plan.get("source_live_root_provenance_sha256")
        != spec["source_live_root_provenance_sha256"]
        or plan.get("validation_cases_sha256") != spec["validation_cases_sha256"]
        or plan.get("provider_cases_sha256") != canonical_sha256(cases)
        or plan.get("case_metadata_sha256") != canonical_sha256(metadata_rows)
        or plan.get("contracts_sha256") != canonical_sha256(contract_rows)
        or plan.get("candidate_roles") != _CANDIDATE_ROLES
        or type(comparison) is not dict
        or comparison.get("new_candidate_protocol_version") not in {"v2", "v3"}
        or comparison
        != {
            "baseline_protocol_version": "v1",
            "new_candidate_protocol_version": comparison.get("new_candidate_protocol_version"),
            "same_model_required": True,
            "expected_candidates": 2,
            "expected_single_pass_attempts_per_candidate": 24,
            "expected_total_functional_judge_provider_attempts": 48,
        }
        or len(cases) != 24
        or len(pilot_cases) != 2
        or len(remaining_cases) != 22
        or len(metadata_rows) != 24
    ):
        raise ValueError("calibration plan failed validation")
    pilot_ids = {row.get("case_id") for row in pilot_cases}
    remaining_ids = {row.get("case_id") for row in remaining_cases}
    all_ids = {row.get("case_id") for row in cases}
    if (
        pilot_ids != set(plan.get("pilot_case_ids", []))
        or pilot_ids & remaining_ids
        or pilot_ids | remaining_ids != all_ids
    ):
        raise ValueError("calibration pilot/remaining partition failed validation")

    frozen_contracts: dict[str, TaskFunctionalContractRecord] = {}
    family_specs_by_task = {str(row["task_id"]): row for row in family_specs.values()}
    try:
        for raw in contract_rows:
            contract = TaskFunctionalContractRecord.model_validate(raw)
            family_spec = family_specs_by_task.get(contract.task_id)
            requirement_ids = [item.requirement_id for item in contract.requirements]
            if (
                family_spec is None
                or contract.task_id in frozen_contracts
                or contract.model_dump(mode="json") != raw
                or contract.contract_id != family_spec["functional_contract_id"]
                or canonical_sha256(raw) != family_spec["functional_contract_record_sha256"]
                or requirement_ids != family_spec["functional_requirement_ids"]
            ):
                raise ValueError
            frozen_contracts[contract.task_id] = contract
    except Exception:  # noqa: BLE001 - normalize strict model validation failures
        raise ValueError("calibration frozen contracts failed validation") from None

    case_by_id: dict[str, dict[str, object]] = {}
    for row in cases:
        case_id = row.get("case_id")
        if (
            frozenset(row) != _PROVIDER_CASE_KEYS
            or type(case_id) is not str
            or not case_id
            or case_id in case_by_id
            or type(row.get("task_id")) is not str
            or type(row.get("seed_id")) is not int
            or type(row.get("code_text")) is not str
            or row.get("expected_status") not in {"pass", "fail"}
        ):
            raise ValueError("calibration provider case failed validation")
        case_by_id[case_id] = row

    metadata: dict[str, dict[str, object]] = {}
    split_counts: Counter[str] = Counter()
    tune_pair_counts: Counter[str] = Counter()
    for row in metadata_rows:
        case_id = row.get("case_id")
        provider_case = case_by_id.get(case_id) if type(case_id) is str else None
        if (
            frozenset(row) != _METADATA_KEYS
            or row.get("schema_version") != "1.0"
            or provider_case is None
            or case_id in metadata
            or row.get("split") not in {"tune", "validation"}
            or type(row.get("family")) is not str
            or type(row.get("source_role")) is not str
            or row.get("task_id") != provider_case["task_id"]
            or row.get("seed_id") != provider_case["seed_id"]
            or row.get("expected_status") != provider_case["expected_status"]
            or row.get("code_sha256")
            != hashlib.sha256(provider_case["code_text"].encode("utf-8")).hexdigest()
        ):
            raise ValueError("calibration metadata failed validation")
        if row["split"] == "tune" and row["source_role"] not in {
            "target_patch",
            "noop_rewrite",
        }:
            raise ValueError("calibration tune arm failed validation")
        if row["split"] == "tune":
            paired_group = row.get("paired_group_id")
            if (
                type(paired_group) is not str
                or not paired_group.startswith("functional_pair_")
                or row.get("equivalence_group") is not None
            ):
                raise ValueError("calibration tune pair failed validation")
            tune_pair_counts[paired_group] += 1
        elif row.get("paired_group_id") is not None:
            raise ValueError("calibration validation pair failed validation")
        split_counts[row["split"]] += 1
        metadata[case_id] = row
    if (
        set(metadata) != set(case_by_id)
        or split_counts != {"tune": 8, "validation": 16}
        or sorted(tune_pair_counts.values()) != [2, 2, 2, 2]
        or {row["task_id"] for row in metadata.values()} != set(frozen_contracts)
        or set(frozen_contracts) != set(family_specs_by_task)
    ):
        raise ValueError("calibration case join failed validation")

    thresholds = plan.get("thresholds")
    if (
        type(thresholds) is not dict
        or frozenset(thresholds) != _THRESHOLD_KEYS
        or thresholds != spec["thresholds"]
        or thresholds.get("tune_cases") != 8
        or thresholds.get("tune_min_correct") != 8
        or thresholds.get("tune_max_false_pass") != 0
        or thresholds.get("tune_max_equivalence_inconsistency") != 0
        or thresholds.get("tune_role") != "engineering_regression_gate_not_ranking"
        or thresholds.get("validation_cases") != 16
        or thresholds.get("validation_min_correct") != 15
        or thresholds.get("validation_max_false_pass") != 0
        or thresholds.get("validation_max_equivalence_inconsistency") != 0
        or thresholds.get("validation_max_invalid") != 0
        or thresholds.get("selection_rule")
        != "validation_correct_desc_false_fail_asc_candidate_id_asc"
    ):
        raise ValueError("calibration thresholds failed validation")
    return plan, metadata, frozen_contracts


def _records(root: Path, complete_name: str, partial_name: str) -> list[dict[str, object]]:
    complete = root / complete_name
    partial = root / partial_name
    if complete.exists() and partial.exists():
        raise ValueError("candidate run contains complete and partial records")
    return _read_jsonl(complete if complete.exists() else partial, optional=True)


def _trace_is_structurally_valid(trace: dict[str, object], evaluator_policy_sha256: str) -> bool:
    status = trace.get("response_status")
    common = {
        "at_utc",
        "call_index",
        "evaluator_policy_sha256",
        "request",
        "request_sha256",
        "response_status",
    }
    expected_keys = common | (
        {"response_sha256", "response_text"} if status == "received" else {"failure"}
    )
    if (
        set(trace) != expected_keys
        or type(trace.get("call_index")) is not int
        or trace["call_index"] < 1
        or trace.get("evaluator_policy_sha256") != evaluator_policy_sha256
        or type(trace.get("request")) is not dict
        or type(trace.get("request_sha256")) is not str
        or status not in {"received", "transport_error"}
    ):
        return False
    try:
        request_bytes = canonical_request_bytes(trace["request"])
    except Exception:  # noqa: BLE001 - malformed trace is a false structural check
        return False
    if hashlib.sha256(request_bytes).hexdigest() != trace["request_sha256"]:
        return False
    if status == "received":
        response_text = trace.get("response_text")
        return type(response_text) is str and hashlib.sha256(
            response_text.encode("utf-8")
        ).hexdigest() == trace.get("response_sha256")
    return type(trace.get("failure")) is dict


def _validated_evaluator_coordinates(config: dict[str, object]) -> dict[str, object]:
    protocol = config["protocol_version"]
    pass_seeds = config.get("pass_seeds")
    base_url = config.get("base_url")
    v3_metadata_valid = (
        config.get("aggregate_status_rule") == FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE
        and config.get("aggregate_status_rule_sha256") == FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256
        and config.get("top_level_status_role") == FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE
    )
    legacy_metadata_absent = not any(
        key in config
        for key in (
            "aggregate_status_rule",
            "aggregate_status_rule_sha256",
            "top_level_status_role",
        )
    )
    if (
        protocol not in _POLICY_ARTIFACTS
        or type(pass_seeds) is not list
        or len(pass_seeds) != 1
        or type(pass_seeds[0]) is not int
        or type(base_url) is not str
        or config.get("endpoint_sha256") != hashlib.sha256(base_url.encode("utf-8")).hexdigest()
        or (
            config.get("system_template_sha256"),
            config.get("output_schema_sha256"),
        )
        != _POLICY_ARTIFACTS[protocol]
        or config.get("response_format") != {"type": "json_object"}
        or config.get("validation_only_raw_exchange_capture") is not True
        or (protocol == "v3" and not v3_metadata_valid)
        or (protocol != "v3" and not legacy_metadata_absent)
    ):
        raise ValueError("candidate frozen policy artifacts failed validation")
    try:
        llm = FunctionalJudgeLLMConfig(
            model_id=config["model_id"],
            base_url=base_url,
            api_key_env=config["api_key_env"],
            timeout_seconds=config["timeout_seconds"],
            max_attempts=config["max_attempts"],
            max_response_bytes=config["max_response_bytes"],
            temperature=config["temperature"],
            top_p=config["top_p"],
            seed=None,
            enable_thinking=config["enable_thinking"],
        )
        policy = _policy(llm, pass_seeds[0], protocol_version=protocol)
        recomputed = functional_judge_policy_sha256(
            policy,
            None,
            mode="single_pass",
            protocol_version=protocol,
        )
    except Exception:  # noqa: BLE001 - normalize frozen evaluator validation failures
        raise ValueError("candidate evaluator coordinates failed validation") from None
    if recomputed != config.get("evaluator_policy_sha256"):
        raise ValueError("candidate evaluator policy digest failed validation")
    return {
        "provider": config.get("provider"),
        "region": config.get("region"),
        "model_id": config.get("model_id"),
        "base_url": base_url,
        "endpoint_sha256": config.get("endpoint_sha256"),
        "api_key_env": config.get("api_key_env"),
        "timeout_seconds": config.get("timeout_seconds"),
        "max_attempts": config.get("max_attempts"),
        "max_response_bytes": config.get("max_response_bytes"),
        "temperature": config.get("temperature"),
        "top_p": config.get("top_p"),
        "pass_seeds": pass_seeds,
        "enable_thinking": config.get("enable_thinking"),
        "judge_mode": config.get("judge_mode"),
        "response_format": config.get("response_format"),
    }


def _run_slice(root: Path) -> dict[str, object]:
    root = root.resolve()
    verify_closed_manifest(root / "artifact-manifest.json", label="functional judge candidate run")
    config = _read_json(root / "config.json")
    environment = _read_json(root / "environment.json")
    report = _read_json(root / "report.json")
    cases = _read_jsonl(root / "canary_cases.jsonl")
    traces = _read_jsonl(root / "llm_exchange_trace.jsonl", optional=True)
    raw_passes = _records(
        root, "functional_judge_passes.jsonl", "functional_judge_passes.partial.jsonl"
    )
    raw_outcomes = _records(
        root,
        "program_functional_outcomes.jsonl",
        "program_functional_outcomes.partial.jsonl",
    )
    protocol = config.get("protocol_version")
    evaluator_policy = config.get("evaluator_policy_sha256")
    candidate_role = config.get("candidate_role")
    case_results = report.get("case_results", [])
    if (
        type(config.get("candidate_id")) is not str
        or candidate_role not in _CANDIDATE_ROLES
        or config.get("judge_mode") != "single_pass"
        or config.get("max_attempts") != 1
        or protocol not in _MEASUREMENT_METHOD
        or config.get("measurement_method") != _MEASUREMENT_METHOD[protocol]
        or config.get("execution_performed") is not False
        or not _is_sha256(evaluator_policy)
        or not _is_sha256(config.get("evaluator_config_sha256"))
        or type(config.get("model_id")) is not str
        or not cases
        or type(case_results) is not list
        or report.get("status") not in {"PASS", "FAIL"}
        or report.get("total_case_count") != len(cases)
        or report.get("completed_case_count") != len(case_results)
    ):
        raise ValueError("candidate run configuration failed validation")
    if len({trace.get("call_index") for trace in traces}) != len(traces):
        raise ValueError("candidate trace call index is duplicated")
    shared_evaluator_coordinates = _validated_evaluator_coordinates(config)
    expected_artifact_sha256 = {
        "config": canonical_sha256(config),
        "environment": canonical_sha256(environment),
        "cases": canonical_sha256(cases),
        "passes": canonical_sha256(raw_passes),
        "outcomes": canonical_sha256(raw_outcomes),
    }
    if (
        report.get("artifact_sha256") != expected_artifact_sha256
        or report.get("candidate_id") != config["candidate_id"]
        or report.get("protocol_version") != protocol
        or report.get("measurement_method") != config["measurement_method"]
        or report.get("execution_performed") is not False
        or report.get("provider_attempts") != len(traces)
        or report.get("provider_attempt_scope") != "included_closed_run_trace_records"
        or report.get("new_calls", {}).get("functional_judge_provider_attempts") != len(traces)
    ):
        raise ValueError("candidate terminal report artifact closure failed validation")

    validated_cases: list[dict[str, object]] = []
    case_ids: set[str] = set()
    for case in cases:
        case_id = case.get("case_id")
        try:
            contract = TaskFunctionalContractRecord.model_validate(case.get("contract"))
        except Exception:  # noqa: BLE001 - normalize strict contract validation failures
            raise ValueError("candidate case contract failed validation") from None
        if (
            frozenset(case) != _RUN_CASE_KEYS
            or type(case_id) is not str
            or not case_id
            or case_id in case_ids
            or case.get("task_id") != contract.task_id
            or type(case.get("seed_id")) is not int
            or type(case.get("code_text")) is not str
            or case.get("expected_status") not in {"pass", "fail"}
        ):
            raise ValueError("candidate run case failed validation")
        case_ids.add(case_id)
        validated_cases.append({**case, "validated_contract": contract})

    result_by_case: dict[str, dict[str, object]] = {}
    for row in case_results:
        if (
            type(row) is not dict
            or frozenset(row) != _REPORT_CASE_KEYS
            or type(row.get("case_id")) is not str
            or row["case_id"] not in case_ids
            or row["case_id"] in result_by_case
        ):
            raise ValueError("candidate case result failed validation")
        result_by_case[row["case_id"]] = row

    try:
        passes = [FunctionalJudgePassRecord.model_validate(row) for row in raw_passes]
        outcomes = [ProgramFunctionalOutcomeRecord.model_validate(row) for row in raw_outcomes]
    except Exception:  # noqa: BLE001 - normalize strict Judge record failures
        raise ValueError("candidate Judge records failed validation") from None
    trace_validity = [_trace_is_structurally_valid(trace, evaluator_policy) for trace in traces]
    return {
        "root": str(root),
        "root_manifest_sha256": _sha256_file(root / "artifact-manifest.json"),
        "candidate_id": config["candidate_id"],
        "candidate_role": candidate_role,
        "protocol_version": protocol,
        "measurement_method": config["measurement_method"],
        "evaluator_policy_sha256": evaluator_policy,
        "model_id": config["model_id"],
        "evaluator_config_sha256": config.get("evaluator_config_sha256"),
        "output_schema_sha256": config.get("output_schema_sha256"),
        "shared_evaluator_coordinates": shared_evaluator_coordinates,
        "shared_evaluator_coordinates_sha256": canonical_sha256(shared_evaluator_coordinates),
        "report_status": report.get("status"),
        "started_at_utc": report.get("started_at_utc"),
        "completed_at_utc": report.get("completed_at_utc"),
        "cases": validated_cases,
        "result_by_case": result_by_case,
        "traces": traces,
        "trace_validity": trace_validity,
        "passes": passes,
        "outcomes": outcomes,
    }


def _request_matches_case(
    trace: dict[str, object],
    case: dict[str, object],
    protocol_version: str,
    output_schema_sha256: object,
) -> bool:
    request = trace.get("request")
    contract = case["validated_contract"]
    if type(request) is not dict or type(contract) is not TaskFunctionalContractRecord:
        return False
    expected_keys = {
        "blindness",
        "environment_dependencies",
        "judgeability",
        "language",
        "output_schema",
        "program_lines",
        "request_kind",
        "requirements",
        "schema_version",
    }
    if protocol_version in {"v2", "v3"}:
        expected_keys |= {"execution_performed", "measurement_method", "protocol_version"}
    if protocol_version == "v3":
        expected_keys |= {"aggregate_status_rule", "aggregate_status_rule_sha256"}
    if set(request) != expected_keys:
        return False
    expected_program_lines = [
        {"line_number": index, "text": line}
        for index, line in enumerate(case["code_text"].splitlines(), start=1)
    ]
    expected_requirements = [
        {
            "requirement_id": item.requirement_id,
            "kind": item.kind,
            "criterion": item.criterion,
        }
        for item in contract.requirements
    ]
    if (
        request.get("schema_version") != "1.0"
        or request.get("request_kind") != "blind_functional_evaluation"
        or request.get("blindness")
        != {
            "arm_withheld": True,
            "cwe_withheld": True,
            "generator_identity_withheld": True,
            "security_outcome_withheld": True,
        }
        or request.get("language") != contract.language
        or request.get("judgeability") != contract.judgeability.value
        or request.get("requirements") != expected_requirements
        or request.get("environment_dependencies") != list(contract.environment_dependencies)
        or request.get("program_lines") != expected_program_lines
        or canonical_sha256(request.get("output_schema")) != output_schema_sha256
    ):
        return False
    if protocol_version == "v1":
        return True
    if protocol_version == "v2":
        return (
            request.get("protocol_version") == "v2"
            and request.get("measurement_method") == "blind_static_llm_v2"
            and request.get("execution_performed") is False
        )
    return (
        request.get("protocol_version") == "v3"
        and request.get("measurement_method") == "blind_static_llm_v3_requirement_aggregate"
        and request.get("execution_performed") is False
        and request.get("aggregate_status_rule") == FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE
        and request.get("aggregate_status_rule_sha256") == FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256
    )


def _v3_advisory_status_diagnostic(
    response_text: str,
    derived_status: str,
) -> dict[str, object]:
    if type(response_text) is not str or derived_status not in {"pass", "fail", "unknown"}:
        raise ValueError("v3 advisory diagnostic input failed validation")
    payload = json.loads(
        response_text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if type(payload) is not dict:
        raise ValueError("v3 advisory diagnostic response failed validation")
    present = "status" in payload
    advisory_status = payload.get("status") if present else None
    if present and (
        type(advisory_status) is not str or advisory_status not in {"pass", "fail", "unknown"}
    ):
        raise ValueError("v3 advisory diagnostic status failed validation")
    return {
        "schema_version": "1.0",
        "available": True,
        "source": "closed_raw_response_text_bytes",
        "raw_response_sha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "status_role": FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
        "status_present": present,
        "advisory_status": advisory_status,
        "derived_status": derived_status,
        "agrees_with_derived": (advisory_status == derived_status if present else None),
        "diagnostic_only": True,
        "used_by_gate": False,
        "used_by_ranking": False,
    }


def _metrics(rows: list[dict[str, object]]) -> dict[str, object]:
    total = len(rows)
    invalid = sum(row["actual_status"] == "invalid" for row in rows)
    unknown = sum(row["actual_status"] == "unknown" for row in rows)
    correct = sum(row["expected_status"] == row["actual_status"] for row in rows)
    false_pass = sum(
        row["expected_status"] == "fail" and row["actual_status"] == "pass" for row in rows
    )
    false_fail = sum(
        row["expected_status"] == "pass" and row["actual_status"] == "fail" for row in rows
    )
    equivalence: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for row in rows:
        group = row["equivalence_group"]
        if type(group) is str:
            equivalence[group].append((row["expected_status"], row["actual_status"]))
    mixed_gold_groups = sorted(
        group
        for group, pairs in equivalence.items()
        if len({expected for expected, _actual in pairs}) > 1
    )
    inconsistent_groups = sorted(
        group
        for group, pairs in equivalence.items()
        if group not in mixed_gold_groups
        and len(pairs) > 1
        and len({actual for _expected, actual in pairs}) > 1
    )
    return {
        "cases": total,
        "correct": correct,
        "accuracy": correct / total if total else None,
        "false_pass": false_pass,
        "false_fail": false_fail,
        "unknown": unknown,
        "abstention": unknown,
        "coverage": (total - unknown) / total if total else None,
        "unknown_counts_as_incorrect": True,
        "binary_gold_only": True,
        "invalid": invalid,
        "equivalence_inconsistency": len(inconsistent_groups),
        "inconsistent_equivalence_groups": inconsistent_groups,
        "mixed_gold_groups_excluded_from_equivalence": mixed_gold_groups,
    }


def _candidate_summary(
    candidate_id: str,
    slices: list[dict[str, object]],
    metadata: dict[str, dict[str, object]],
    frozen_contracts: dict[str, TaskFunctionalContractRecord],
    pilot_case_ids: set[str],
    thresholds: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    if len(slices) != 2:
        raise ValueError("candidate must contain exactly pilot and remaining slices")
    all_case_ids = set(metadata)
    remaining_case_ids = all_case_ids - pilot_case_ids
    slice_by_phase: dict[str, dict[str, object]] = {}
    for item in slices:
        item_case_ids = {case["case_id"] for case in item["cases"]}
        phase = (
            "pilot"
            if item_case_ids == pilot_case_ids
            else ("remaining" if item_case_ids == remaining_case_ids else None)
        )
        if phase is None or phase in slice_by_phase:
            raise ValueError("candidate slice partition failed validation")
        item["phase"] = phase
        slice_by_phase[phase] = item
    try:
        pilot_completed = datetime.fromisoformat(str(slice_by_phase["pilot"]["completed_at_utc"]))
        remaining_started = datetime.fromisoformat(
            str(slice_by_phase["remaining"]["started_at_utc"])
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("candidate phase timestamps failed validation") from None
    if pilot_completed > remaining_started:
        raise ValueError("candidate remaining slice preceded pilot completion")
    policies = {item["evaluator_policy_sha256"] for item in slices}
    models = {item["model_id"] for item in slices}
    roles = {item["candidate_role"] for item in slices}
    protocols = {item["protocol_version"] for item in slices}
    methods = {item["measurement_method"] for item in slices}
    configs = {item["evaluator_config_sha256"] for item in slices}
    shared_coordinates = {item["shared_evaluator_coordinates_sha256"] for item in slices}
    if any(
        len(values) != 1
        for values in (
            policies,
            models,
            roles,
            protocols,
            methods,
            configs,
            shared_coordinates,
        )
    ):
        raise ValueError("candidate configuration changed across run slices")

    case_rows: list[dict[str, object]] = []
    seen_cases: set[str] = set()
    seen_assignments: set[str] = set()
    used_pass_ids: set[str] = set()
    used_outcome_ids: set[str] = set()
    used_trace_indices: set[tuple[str, int]] = set()
    roots: list[dict[str, object]] = []
    trace_count = received_traces = valid_traces = pass_count = outcome_count = 0
    global_closure_errors: list[str] = []

    for item in slices:
        traces = item["traces"]
        passes = item["passes"]
        outcomes = item["outcomes"]
        trace_validity = item["trace_validity"]
        trace_count += len(traces)
        received_traces += sum(trace.get("response_status") == "received" for trace in traces)
        valid_traces += sum(trace_validity)
        pass_count += len(passes)
        outcome_count += len(outcomes)
        roots.append(
            {
                "path": item["root"],
                "manifest_sha256": item["root_manifest_sha256"],
                "report_status": item["report_status"],
                "phase": item["phase"],
            }
        )
        passes_by_assignment: dict[str, list[FunctionalJudgePassRecord]] = defaultdict(list)
        outcomes_by_assignment: dict[str, list[ProgramFunctionalOutcomeRecord]] = defaultdict(list)
        for judge_pass in passes:
            passes_by_assignment[judge_pass.assignment_id].append(judge_pass)
        for outcome in outcomes:
            outcomes_by_assignment[outcome.assignment_id].append(outcome)

        for case in item["cases"]:
            case_id = case["case_id"]
            if case_id in seen_cases or case_id not in metadata:
                raise ValueError("candidate case coverage failed validation")
            meta = metadata[case_id]
            contract = case["validated_contract"]
            frozen_contract = frozen_contracts.get(case["task_id"])
            if (
                frozen_contract is None
                or contract.model_dump(mode="json") != frozen_contract.model_dump(mode="json")
                or case["task_id"] != meta["task_id"]
                or case["seed_id"] != meta["seed_id"]
                or case["expected_status"] != meta["expected_status"]
                or hashlib.sha256(case["code_text"].encode("utf-8")).hexdigest()
                != meta["code_sha256"]
            ):
                raise ValueError("candidate case binding failed validation")

            errors: list[str] = []
            report_result = item["result_by_case"].get(case_id)
            assignment_id: str | None = None
            judge_pass: FunctionalJudgePassRecord | None = None
            outcome: ProgramFunctionalOutcomeRecord | None = None
            v3_advisory_diagnostic: dict[str, object] | None = None
            if report_result is None:
                errors.append("missing_report_result")
            else:
                assignment_id = report_result.get("assignment_id")
                expected_assignment, _variant = _assignment_and_variant(
                    case["task_id"], case["seed_id"]
                )
                if (
                    type(assignment_id) is not str
                    or assignment_id != expected_assignment.assignment_id
                    or assignment_id in seen_assignments
                    or report_result.get("task_id") != case["task_id"]
                    or report_result.get("contract_id") != contract.contract_id
                    or report_result.get("expected_status") != case["expected_status"]
                    or report_result.get("actual_status") not in {"pass", "fail", "unknown"}
                    or report_result.get("consistent") is not True
                ):
                    errors.append("report_coordinate_or_status_mismatch")
                else:
                    seen_assignments.add(assignment_id)
                    assignment_passes = passes_by_assignment.get(assignment_id, [])
                    assignment_outcomes = outcomes_by_assignment.get(assignment_id, [])
                    if len(assignment_passes) != 1:
                        errors.append("single_pass_record_cardinality")
                    else:
                        judge_pass = assignment_passes[0]
                    if len(assignment_outcomes) != 1:
                        errors.append("outcome_record_cardinality")
                    else:
                        outcome = assignment_outcomes[0]

            if judge_pass is not None and outcome is not None and assignment_id is not None:
                if (
                    judge_pass.pass_id != "A"
                    or judge_pass.contract_id != contract.contract_id
                    or judge_pass.evaluator_policy_sha256 != item["evaluator_policy_sha256"]
                    or outcome.contract_id != contract.contract_id
                    or outcome.evaluator_policy_sha256 != item["evaluator_policy_sha256"]
                    or outcome.status is not judge_pass.status
                    or report_result.get("actual_status") != outcome.status.value
                    or report_result.get("pass_statuses") != [judge_pass.status.value]
                ):
                    errors.append("report_pass_outcome_semantic_mismatch")
                expected_evidence = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "pass_ids": [judge_pass.judge_pass_id],
                        "decision": judge_pass.status.value,
                        "mode": "single_pass",
                    }
                )
                if outcome.evidence_sha256 != expected_evidence:
                    errors.append("outcome_evidence_digest_mismatch")
                rebuilt_outcome = ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment_id,
                    contract_id=frozen_contract.contract_id,
                    evaluator_policy_sha256=item["evaluator_policy_sha256"],
                    status=judge_pass.status,
                    evidence_sha256=expected_evidence,
                )
                if rebuilt_outcome.model_dump(mode="json") != outcome.model_dump(mode="json"):
                    errors.append("outcome_rebuild_mismatch")

                matching_trace: tuple[int, dict[str, object]] | None = None
                for index, trace in enumerate(traces):
                    coordinate = (item["root"], index)
                    if (
                        coordinate not in used_trace_indices
                        and trace.get("response_status") == "received"
                        and trace.get("request_sha256") == judge_pass.request_sha256
                        and trace.get("response_sha256") == judge_pass.response_sha256
                    ):
                        matching_trace = (index, trace)
                        break
                if matching_trace is None:
                    errors.append("missing_request_response_trace")
                else:
                    trace_index, trace = matching_trace
                    used_trace_indices.add((item["root"], trace_index))
                    if not trace_validity[trace_index] or not _request_matches_case(
                        trace,
                        case,
                        item["protocol_version"],
                        item["output_schema_sha256"],
                    ):
                        errors.append("trace_policy_or_request_semantic_mismatch")
                    else:
                        try:
                            parsed_status, parsed_requirements, parsed_rationale = _parse_response(
                                trace["response_text"].encode("utf-8"),
                                contract=frozen_contract,
                                code=case["code_text"],
                                protocol_version=item["protocol_version"],
                            )
                            rebuilt_pass = FunctionalJudgePassRecord.from_content(
                                assignment_id=assignment_id,
                                contract_id=frozen_contract.contract_id,
                                pass_id="A",
                                evaluator_policy_sha256=item["evaluator_policy_sha256"],
                                request_sha256=trace["request_sha256"],
                                response_sha256=trace["response_sha256"],
                                status=parsed_status,
                                requirements=parsed_requirements,
                                rationale=parsed_rationale,
                            )
                        except Exception:  # noqa: BLE001 - reparse failure is evidence
                            errors.append("raw_response_reparse_failed")
                        else:
                            if rebuilt_pass.model_dump(mode="json") != judge_pass.model_dump(
                                mode="json"
                            ):
                                errors.append("raw_response_pass_rebuild_mismatch")
                            if item["protocol_version"] == "v3":
                                try:
                                    v3_advisory_diagnostic = _v3_advisory_status_diagnostic(
                                        trace["response_text"],
                                        parsed_status.value,
                                    )
                                except Exception:  # noqa: BLE001 - diagnostic never gates
                                    v3_advisory_diagnostic = {
                                        "schema_version": "1.0",
                                        "available": False,
                                        "source": "closed_raw_response_text_bytes",
                                        "raw_response_sha256": trace.get("response_sha256"),
                                        "status_role": (FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE),
                                        "status_present": None,
                                        "advisory_status": None,
                                        "derived_status": parsed_status.value,
                                        "agrees_with_derived": None,
                                        "diagnostic_only": True,
                                        "used_by_gate": False,
                                        "used_by_ranking": False,
                                    }
                used_pass_ids.add(judge_pass.judge_pass_id)
                used_outcome_ids.add(outcome.program_functional_outcome_id)

            actual_status = (
                outcome.status.value if not errors and outcome is not None else "invalid"
            )
            case_rows.append(
                {
                    "schema_version": "1.0",
                    "candidate_id": candidate_id,
                    "candidate_role": item["candidate_role"],
                    "protocol_version": item["protocol_version"],
                    "case_id": case_id,
                    "task_id": meta["task_id"],
                    "split": meta["split"],
                    "family": meta["family"],
                    "source_role": meta["source_role"],
                    "equivalence_group": meta["equivalence_group"],
                    "paired_group_id": meta["paired_group_id"],
                    "expected_status": case["expected_status"],
                    "actual_status": actual_status,
                    "correct": actual_status == case["expected_status"],
                    "closure_valid": not errors,
                    "closure_errors": errors,
                    "v3_advisory_status_diagnostic": v3_advisory_diagnostic,
                }
            )
            seen_cases.add(case_id)

    all_pass_ids = {judge_pass.judge_pass_id for item in slices for judge_pass in item["passes"]}
    all_outcome_ids = {
        outcome.program_functional_outcome_id for item in slices for outcome in item["outcomes"]
    }
    received_trace_coordinates = {
        (item["root"], index)
        for item in slices
        for index, trace in enumerate(item["traces"])
        if trace.get("response_status") == "received"
    }
    if used_pass_ids != all_pass_ids:
        global_closure_errors.append("unjoined_pass_records")
    if used_outcome_ids != all_outcome_ids:
        global_closure_errors.append("unjoined_outcome_records")
    if used_trace_indices != received_trace_coordinates:
        global_closure_errors.append("unjoined_received_traces")
    if seen_cases != set(metadata):
        raise ValueError("candidate did not cover the complete 24-case plan")

    tune_rows = [row for row in case_rows if row["split"] == "tune"]
    validation_rows = [row for row in case_rows if row["split"] == "validation"]
    tune = _metrics(tune_rows)
    validation = _metrics(validation_rows)
    v3_diagnostics = [
        row["v3_advisory_status_diagnostic"]
        for row in case_rows
        if type(row["v3_advisory_status_diagnostic"]) is dict
    ]
    v3_available = [row for row in v3_diagnostics if row["available"] is True]
    v3_case_count = len(case_rows) if next(iter(protocols)) == "v3" else 0
    v3_advisory_summary = {
        "schema_version": "1.0",
        "applicable": next(iter(protocols)) == "v3",
        "status_role": FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
        "case_count": v3_case_count,
        "available": len(v3_available),
        "unavailable": v3_case_count - len(v3_available),
        "present": sum(row["status_present"] is True for row in v3_available),
        "absent": sum(row["status_present"] is False for row in v3_available),
        "agrees_with_derived": sum(row["agrees_with_derived"] is True for row in v3_available),
        "disagrees_with_derived": sum(row["agrees_with_derived"] is False for row in v3_available),
        "diagnostic_only": True,
        "used_by_gate": False,
        "used_by_ranking": False,
    }
    validation_by_family = {
        family: _metrics([row for row in validation_rows if row["family"] == family])
        for family in sorted({row["family"] for row in validation_rows})
    }
    tune_by_family = {
        family: _metrics([row for row in tune_rows if row["family"] == family])
        for family in sorted({row["family"] for row in tune_rows})
    }
    tune_by_arm = {
        arm: _metrics([row for row in tune_rows if row["source_role"] == arm])
        for arm in ("noop_rewrite", "target_patch")
    }
    tune_by_family_and_arm = {
        family: {
            arm: _metrics(
                [row for row in tune_rows if row["family"] == family and row["source_role"] == arm]
            )
            for arm in ("noop_rewrite", "target_patch")
        }
        for family in sorted(tune_by_family)
    }
    tune_paired_results: list[dict[str, object]] = []
    for paired_group_id in sorted(
        {row["paired_group_id"] for row in tune_rows if row["paired_group_id"] is not None}
    ):
        paired_rows = [row for row in tune_rows if row["paired_group_id"] == paired_group_id]
        if len(paired_rows) != 2 or {row["source_role"] for row in paired_rows} != {
            "noop_rewrite",
            "target_patch",
        }:
            raise ValueError("candidate tune paired results failed validation")
        by_arm = {row["source_role"]: row for row in paired_rows}
        expected_numeric = {
            arm: int(row["expected_status"] == "pass") for arm, row in by_arm.items()
        }
        actual_numeric = {
            arm: (
                int(row["actual_status"] == "pass")
                if row["actual_status"] in {"pass", "fail"}
                else None
            )
            for arm, row in by_arm.items()
        }
        tune_paired_results.append(
            {
                "paired_group_id": paired_group_id,
                "task_id": paired_rows[0]["task_id"],
                "family": paired_rows[0]["family"],
                "expected_by_arm": {
                    arm: row["expected_status"] for arm, row in sorted(by_arm.items())
                },
                "actual_by_arm": {arm: row["actual_status"] for arm, row in sorted(by_arm.items())},
                "both_arms_correct": all(row["correct"] for row in paired_rows),
                "expected_target_minus_noop": expected_numeric["target_patch"]
                - expected_numeric["noop_rewrite"],
                "actual_target_minus_noop": (
                    actual_numeric["target_patch"] - actual_numeric["noop_rewrite"]
                    if None not in actual_numeric.values()
                    else None
                ),
            }
        )
    provider_closed = (
        trace_count == 24
        and received_traces == 24
        and valid_traces == 24
        and pass_count == 24
        and outcome_count == 24
        and all(item["report_status"] in {"PASS", "FAIL"} for item in slices)
        and not global_closure_errors
        and all(row["closure_valid"] for row in case_rows)
    )
    gates = {
        "provider_attempt_and_artifact_closure": provider_closed,
        "tune_case_count": tune["cases"] == thresholds["tune_cases"],
        "tune_min_correct": tune["correct"] >= thresholds["tune_min_correct"],
        "tune_false_pass": tune["false_pass"] <= thresholds["tune_max_false_pass"],
        "tune_equivalence_inconsistency": tune["equivalence_inconsistency"]
        <= thresholds["tune_max_equivalence_inconsistency"],
        "validation_case_count": validation["cases"] == thresholds["validation_cases"],
        "validation_min_correct": validation["correct"] >= thresholds["validation_min_correct"],
        "validation_false_pass": validation["false_pass"]
        <= thresholds["validation_max_false_pass"],
        "validation_equivalence_inconsistency": validation["equivalence_inconsistency"]
        <= thresholds["validation_max_equivalence_inconsistency"],
        "validation_invalid": validation["invalid"] <= thresholds["validation_max_invalid"],
    }
    role = next(iter(roles))
    gate_passed = all(gates.values())
    summary = {
        "schema_version": "1.0",
        "candidate_id": candidate_id,
        "candidate_role": role,
        "protocol_version": next(iter(protocols)),
        "measurement_method": next(iter(methods)),
        "model_id": next(iter(models)),
        "evaluator_policy_sha256": next(iter(policies)),
        "evaluator_config_sha256": next(iter(configs)),
        "shared_evaluator_coordinates": slices[0]["shared_evaluator_coordinates"],
        "shared_evaluator_coordinates_sha256": next(iter(shared_coordinates)),
        "run_roots": sorted(roots, key=lambda row: row["path"]),
        "provider_evidence": {
            "expected_single_pass_attempts": 24,
            "trace_records": trace_count,
            "received_traces": received_traces,
            "structurally_valid_traces": valid_traces,
            "pass_records": pass_count,
            "outcome_records": outcome_count,
            "global_closure_errors": global_closure_errors,
        },
        "v3_advisory_status_diagnostic": v3_advisory_summary,
        "tune_engineering_regression_gate_not_ranking": tune,
        "tune_by_family": tune_by_family,
        "tune_by_arm": tune_by_arm,
        "tune_by_family_and_arm": tune_by_family_and_arm,
        "tune_paired_results": tune_paired_results,
        "validation": validation,
        "validation_by_family": validation_by_family,
        "gates": gates,
        "gate_passed": gate_passed,
        "eligible_for_selection": role == "new_candidate" and gate_passed,
        "selection_exclusion_reason": (
            "baseline_comparison_only"
            if role == "baseline"
            else (None if gate_passed else "one_or_more_gates_failed")
        ),
    }
    return summary, case_rows


def _comparison(summaries: list[dict[str, object]]) -> dict[str, object]:
    baseline = next(row for row in summaries if row["candidate_role"] == "baseline")
    candidate = next(row for row in summaries if row["candidate_role"] == "new_candidate")
    return {
        "schema_version": "1.0",
        "comparison_kind": ("same_model_prompt_protocol_v1_vs_" + candidate["protocol_version"]),
        "baseline_candidate_id": baseline["candidate_id"],
        "new_candidate_id": candidate["candidate_id"],
        "same_model": baseline["model_id"] == candidate["model_id"],
        "baseline_protocol_version": baseline["protocol_version"],
        "new_candidate_protocol_version": candidate["protocol_version"],
        "validation_correct_delta": (
            candidate["validation"]["correct"] - baseline["validation"]["correct"]
        ),
        "validation_false_pass_delta": (
            candidate["validation"]["false_pass"] - baseline["validation"]["false_pass"]
        ),
        "validation_false_fail_delta": (
            candidate["validation"]["false_fail"] - baseline["validation"]["false_fail"]
        ),
        "tune_correct_delta_diagnostic_only": (
            candidate["tune_engineering_regression_gate_not_ranking"]["correct"]
            - baseline["tune_engineering_regression_gate_not_ranking"]["correct"]
        ),
        "tune_contributes_to_validation_accuracy": False,
        "ranking_uses_validation_only": True,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--calibration-spec", type=Path, required=True)
    parser.add_argument("--expected-plan-id", required=True)
    parser.add_argument("--expected-plan-root-manifest-sha256", required=True)
    parser.add_argument("--candidate-run-dir", type=Path, action="append", required=True)
    parser.add_argument("--expected-candidates", type=int, default=2)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit("refusing to overwrite an existing calibration analysis")
    try:
        plan, metadata, frozen_contracts = _load_plan(
            args.plan_dir,
            calibration_spec_path=args.calibration_spec,
            expected_plan_id=args.expected_plan_id,
            expected_root_manifest_sha256=args.expected_plan_root_manifest_sha256,
        )
        comparison_design = plan["comparison_design"]
        if args.expected_candidates != comparison_design["expected_candidates"]:
            raise ValueError("expected candidate count conflicts with frozen plan")
        grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
        for path in args.candidate_run_dir:
            item = _run_slice(path)
            grouped[item["candidate_id"]].append(item)
        if len(grouped) != args.expected_candidates:
            raise ValueError("candidate count failed validation")

        thresholds = plan["thresholds"]
        summaries: list[dict[str, object]] = []
        all_case_rows: list[dict[str, object]] = []
        for candidate_id in sorted(grouped):
            summary, case_rows = _candidate_summary(
                candidate_id,
                grouped[candidate_id],
                metadata,
                frozen_contracts,
                set(plan["pilot_case_ids"]),
                thresholds,
            )
            summaries.append(summary)
            all_case_rows.extend(case_rows)
        role_counts = Counter(row["candidate_role"] for row in summaries)
        if (
            role_counts != {"baseline": 1, "new_candidate": 1}
            or {row["protocol_version"] for row in summaries if row["candidate_role"] == "baseline"}
            != {comparison_design["baseline_protocol_version"]}
            or {
                row["protocol_version"]
                for row in summaries
                if row["candidate_role"] == "new_candidate"
            }
            != {comparison_design["new_candidate_protocol_version"]}
            or len({row["model_id"] for row in summaries}) != 1
            or len({row["shared_evaluator_coordinates_sha256"] for row in summaries}) != 1
        ):
            raise ValueError("baseline/new-candidate comparison design failed validation")

        eligible = [row for row in summaries if row["eligible_for_selection"]]
        ranked = sorted(
            eligible,
            key=lambda row: (
                -row["validation"]["correct"],
                row["validation"]["false_fail"],
                row["candidate_id"],
            ),
        )
        selected = ranked[0]["candidate_id"] if ranked else None
        status = (
            "FUNCTIONAL_JUDGE_CALIBRATION_GATE_PASSED"
            if selected is not None
            else "FUNCTIONAL_JUDGE_CALIBRATION_GATE_FAILED"
        )
        provider_attempts = sum(row["provider_evidence"]["trace_records"] for row in summaries)
        result_core: dict[str, object] = {
            "schema_version": "1.0",
            "status": status,
            "scientific_claim_allowed": False,
            "plan_id": plan["plan_id"],
            "plan_root_manifest_sha256": _sha256_file(
                args.plan_dir.resolve() / "artifact-manifest.json"
            ),
            "functional_variable": "Y_F^J",
            "measurement_method": (
                "blind_static_llm_protocol_comparison_v1_"
                + comparison_design["new_candidate_protocol_version"]
            ),
            "execution_performed": False,
            "gold_variable": "Y_F^E",
            "gold_label_domain": ["fail", "pass"],
            "unknown_policy": (
                "Judge UNKNOWN is an abstention, counts as incorrect for binary accuracy, "
                "and is not a false-pass"
            ),
            "future_unknown_calibration": "separate_judgeability_abstention_dataset",
            "selection_uses_split": "validation",
            "tune_role": "engineering_regression_gate_not_ranking",
            "tune_contributes_to_validation_accuracy": False,
            "thresholds": thresholds,
            "candidate_summaries": summaries,
            "prompt_engineering_comparison": _comparison(summaries),
            "eligible_candidate_ids": [row["candidate_id"] for row in ranked],
            "selected_candidate_id": selected,
            "new_calls": {
                "functional_judge_provider_attempts": provider_attempts,
                "functional_judge_provider_attempt_scope": ("included_closed_run_trace_records"),
                "expected_functional_judge_provider_attempts": comparison_design[
                    "expected_total_functional_judge_provider_attempts"
                ],
                "generation_provider_attempts": 0,
                "oracle_executions": 0,
                "analyzer_provider_attempts": 0,
            },
        }
        result = {
            **result_core,
            "analysis_id": "functional_judge_calibration_analysis_" + canonical_sha256(result_core),
        }
        output_dir.mkdir(parents=True, exist_ok=False)
        _write_json(output_dir / "report.json", result)
        _write_jsonl(
            output_dir / "candidate-summaries.jsonl",
            sorted(summaries, key=lambda row: row["candidate_id"]),
        )
        _write_jsonl(
            output_dir / "case-results.jsonl",
            sorted(all_case_rows, key=lambda row: (row["candidate_id"], row["case_id"])),
        )
        _write_json(
            output_dir / "environment.json",
            {
                "schema_version": "1.0",
                "captured_at_utc": _utc_now(),
                "working_directory": str(Path.cwd().resolve()),
                "python_executable": sys.executable,
                "python_version": platform.python_version(),
                "platform": platform.platform(),
            },
        )
        _write_json(
            output_dir / "command.json",
            {
                "schema_version": "1.0",
                "argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                "secret_in_argv": False,
            },
        )
        write_closed_manifest_atomic(output_dir, label="functional judge calibration analysis")
        print(status)
        return 0 if selected is not None else 1
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 - CLI publishes only sanitized failure type
        raise SystemExit(
            f"functional Judge calibration analysis failed: {type(exc).__name__}"
        ) from None


if __name__ == "__main__":
    raise SystemExit(main())

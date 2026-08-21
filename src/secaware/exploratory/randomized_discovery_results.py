"""Assemble one complete randomized-discovery Gate C model stratum."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import json
import os
import platform
from pathlib import Path
import socket
import sys
from typing import Any

from secaware.functional_judge.schema import ProgramFunctionalOutcomeRecord
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import sha256_file
from secaware.schema.experiments import AssignmentExecutionRecord, AssignmentRecord, ArmRole


_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-randomized-discovery-result-assembly-v1"
_VARIABLE_ORDER = (
    "w_cwe_scope",
    "c_discovery_arm",
    "x_operation_specific_security_requirement",
    "x_generic_security_reminder",
    "p_length_matched_placebo",
    "y_cwe_secure",
    "y_secure_functional",
)
_ARM_ORDER = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("randomized discovery JSON object failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _closed_manifest(root: Path) -> str:
    manifest_path = root / "artifact-manifest.json"
    manifest = _read_json(manifest_path)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("randomized discovery plan manifest failed validation")
    expected: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or type(entry.get("path")) is not str:
            raise ValueError("randomized discovery plan manifest failed validation")
        relative = Path(str(entry["path"]))
        path = (root / relative).resolve()
        path.relative_to(root.resolve())
        normalized = relative.as_posix()
        if (
            relative.is_absolute()
            or normalized != entry["path"]
            or normalized in expected
            or not path.is_file()
            or sha256_file(path) != entry.get("sha256")
        ):
            raise ValueError("randomized discovery plan manifest failed validation")
        expected.add(normalized)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != manifest_path.name
    }
    if actual != expected:
        raise ValueError("randomized discovery plan manifest closure failed validation")
    return sha256_file(manifest_path)


def _unit_manifest(unit_dir: Path) -> str:
    manifest_path = unit_dir / "artifact-manifest.json"
    manifest = _read_json(manifest_path)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("randomized discovery unit manifest failed validation")
    expected: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or type(entry.get("path")) is not str:
            raise ValueError("randomized discovery unit manifest failed validation")
        relative = Path(str(entry["path"]))
        path = (unit_dir / relative).resolve()
        path.relative_to(unit_dir.resolve())
        normalized = relative.as_posix()
        if (
            relative.is_absolute()
            or normalized != entry["path"]
            or normalized in expected
            or not path.is_file()
            or sha256_file(path) != entry.get("sha256")
        ):
            raise ValueError("randomized discovery unit manifest failed validation")
        expected.add(normalized)
    actual = {
        path.relative_to(unit_dir).as_posix()
        for path in unit_dir.rglob("*")
        if path.is_file() and path.name != manifest_path.name
    }
    if actual != expected:
        raise ValueError("randomized discovery unit manifest closure failed validation")
    return sha256_file(manifest_path)


def _exact_one(path: Path, model: type[Any]) -> Any:
    records = read_jsonl(path, model, required=True, allow_empty=False)
    if len(records) != 1:
        raise ValueError("randomized discovery unit cardinality failed validation")
    return records[0]


def _arm_values(arm: ArmRole) -> tuple[int, int, int, int]:
    if arm not in _ARM_ORDER:
        raise ValueError("randomized discovery arm failed validation")
    return (
        _ARM_ORDER.index(arm),
        int(arm is ArmRole.TARGET_PATCH),
        int(arm is ArmRole.GENERIC_SECURITY_REMINDER),
        int(arm is ArmRole.LENGTH_MATCHED_PLACEBO),
    )


def _reported_itt_unknown_count(report_counts: dict[str, Any]) -> int:
    oracle_unknown = report_counts.get("unknown")
    terminal_no_code = report_counts.get("terminal_no_code")
    if type(oracle_unknown) is not int or type(terminal_no_code) is not int:
        raise ValueError("randomized discovery report counts failed validation")
    return oracle_unknown + terminal_no_code


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def _latest_complete_report(run_dir: Path, expected: int) -> tuple[Path, dict[str, Any]]:
    candidates = sorted(run_dir.glob("report-remaining*.json"))
    for path in reversed(candidates):
        report = _read_json(path)
        counts = report.get("counts")
        if (
            report.get("status") == "GATE_C_LIVE_COMPLETE"
            and type(counts) is dict
            and counts.get("expected_assignments") == expected
            and counts.get("completed") == expected
            and counts.get("errors") == 0
            and counts.get("pending") == 0
        ):
            return path, report
    raise ValueError("randomized discovery complete report is unavailable")


def assemble_randomized_discovery_results(
    *,
    plan_dir: Path,
    run_dir: Path,
    analysis_config_path: Path,
    estimand_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Create an immutable, no-filter analysis table for one model stratum."""

    plan_dir = plan_dir.resolve()
    run_dir = run_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    estimand_config_path = estimand_config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists() or not plan_dir.is_dir() or not run_dir.is_dir():
        raise ValueError("randomized discovery result path failed validation")

    analysis = _read_json(analysis_config_path)
    estimand = _read_json(estimand_config_path)
    expected = int(analysis.get("task_population", {}).get("discover_tasks", 0)) * len(_ARM_ORDER)
    if (
        analysis.get("status") != "FROZEN_BEFORE_DISCOVERY_OUTCOMES"
        or analysis.get("table", {}).get("variables") != list(_VARIABLE_ORDER)
        or analysis.get("table", {}).get("unknown_security_itt_value") != 0
        or analysis.get("table", {}).get("unknown_functional_joint_itt_value") != 0
        or analysis.get("table", {}).get("post_randomization_filtering") != "forbidden"
        or estimand.get("analysis", {}).get("model_pooling") != "forbidden"
        or estimand.get("analysis", {}).get("post_randomization_filtering") != "forbidden"
        or expected != 204
    ):
        raise ValueError("randomized discovery frozen analysis policy failed validation")

    plan_manifest_sha256 = _closed_manifest(plan_dir)
    assignments = tuple(
        read_jsonl(
            plan_dir / "assignments.jsonl",
            AssignmentRecord,
            required=True,
            allow_empty=False,
        )
    )
    coverage = tuple(
        read_jsonl(plan_dir / "oracle-coverage.jsonl", required=True, allow_empty=False)
    )
    if len(assignments) != expected or len(coverage) * len(_ARM_ORDER) != expected:
        raise ValueError("randomized discovery plan coverage failed validation")
    assignment_by_id = {item.assignment_id: item for item in assignments}
    coverage_by_task = {str(item["task_id"]): item for item in coverage}
    models = {item.experimental_unit.model_id for item in assignments}
    if len(assignment_by_id) != expected or len(models) != 1:
        raise ValueError("randomized discovery model stratum failed validation")
    model_id = next(iter(models))
    if model_id not in analysis.get("model_strata", []):
        raise ValueError("randomized discovery model is outside the frozen strata")

    mappings = estimand.get("mappings")
    if type(mappings) is not list:
        raise ValueError("randomized discovery CWE mapping failed validation")
    target_feature_by_cwe = {
        str(item["cwe"]): str(item["target_feature_id"])
        for item in mappings
        if type(item) is dict and "cwe" in item and "target_feature_id" in item
    }
    cwe_order = tuple(item["cwe"] for item in mappings if type(item) is dict and "cwe" in item)
    if len(target_feature_by_cwe) != 5 or len(cwe_order) != 5:
        raise ValueError("randomized discovery CWE mapping failed validation")

    blocks: dict[str, list[AssignmentRecord]] = {}
    for assignment in assignments:
        blocks.setdefault(assignment.experimental_unit.task_id, []).append(assignment)
    if set(blocks) != set(coverage_by_task) or any(
        {item.arm_role for item in block} != set(_ARM_ORDER) or len(block) != len(_ARM_ORDER)
        for block in blocks.values()
    ):
        raise ValueError("randomized discovery complete-block invariant failed validation")

    latest_report_path, latest_report = _latest_complete_report(run_dir, expected)
    input_provenance = _read_json(run_dir / "input-provenance.json")
    if input_provenance.get("source_plan_manifest_sha256") != plan_manifest_sha256:
        raise ValueError("randomized discovery run/plan provenance failed validation")

    rows: list[dict[str, object]] = []
    matrix_rows: list[dict[str, object]] = []
    status_counts: Counter[str] = Counter()
    security_counts: Counter[str] = Counter()
    functional_counts: Counter[str] = Counter()
    arm_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    provider_policy_sha256s: set[str] = set()
    for assignment_id in sorted(assignment_by_id):
        planned = assignment_by_id[assignment_id]
        unit_dir = run_dir / "units" / assignment_id
        unit_manifest_sha256 = _unit_manifest(unit_dir)
        status = _read_json(unit_dir / "status.json")
        observed = _exact_one(unit_dir / "assignment.jsonl", AssignmentRecord)
        execution = _exact_one(unit_dir / "assignment-execution.jsonl", AssignmentExecutionRecord)
        functional = _exact_one(
            unit_dir / "functional-outcome.jsonl", ProgramFunctionalOutcomeRecord
        )
        if (
            observed != planned
            or status.get("status") != "COMPLETE"
            or execution.assignment_id != assignment_id
            or functional.assignment_id != assignment_id
        ):
            raise ValueError("randomized discovery completed unit failed validation")
        task_id = planned.experimental_unit.task_id
        coverage_row = coverage_by_task[task_id]
        cwe = str(coverage_row["cwe"])
        if cwe not in target_feature_by_cwe:
            raise ValueError("randomized discovery unit CWE failed validation")
        arm_code, operation_specific, generic, placebo = _arm_values(planned.arm_role)
        generated = execution.status.value == "generated"
        decision_path = unit_dir / "oracle-decision.json"
        if generated:
            decision = _read_json(decision_path)
            security_label = decision.get("security_label")
            evaluability = decision.get("evaluability")
            decision_reason = decision.get("decision_reason_code")
            mechanism = decision.get("mechanism_trace")
            parse_ok = mechanism.get("parse_ok") if type(mechanism) is dict else None
        else:
            if decision_path.exists():
                raise ValueError("randomized discovery terminal unit has an Oracle decision")
            security_label = "unknown"
            evaluability = "not_required_no_code"
            decision_reason = "terminal_no_code"
            parse_ok = False
        if security_label not in {"secure", "insecure", "unknown"}:
            raise ValueError("randomized discovery security label failed validation")
        functional_status = functional.status.value
        y_secure = int(security_label == "secure")
        y_joint = int(security_label == "secure" and functional_status == "pass")
        values = (
            cwe_order.index(cwe),
            arm_code,
            operation_specific,
            generic,
            placebo,
            y_secure,
            y_joint,
        )
        row = {
            "schema_version": _SCHEMA_VERSION,
            "assignment_id": assignment_id,
            "task_id": task_id,
            "model_id": model_id,
            "hypothesis_id": planned.experimental_unit.hypothesis_id,
            "target_spec_id": planned.target_spec_id,
            "target_instance_id": planned.target_instance_id,
            "arm_protocol_id": planned.arm_protocol_id,
            "protocol_instance_id": planned.protocol_instance_id,
            "seed_id": planned.seed_id,
            "seed_slot": planned.experimental_unit.seed_slot,
            "arm_role": planned.arm_role.value,
            "cwe": cwe,
            "target_feature_id": target_feature_by_cwe[cwe],
            "variant_id": planned.variant_id,
            "values": dict(zip(_VARIABLE_ORDER, values, strict=True)),
            "diagnostics": {
                "execution_status": execution.status.value,
                "terminal_reason": execution.terminal_reason,
                "functional_status": functional_status,
                "security_label": security_label,
                "oracle_evaluability": evaluability,
                "oracle_decision_reason": decision_reason,
                "parse_ok": parse_ok,
            },
            "provenance": {
                "unit_manifest_sha256": unit_manifest_sha256,
                "provider_result_sha256": execution.provider_result_sha256,
                "provider_policy_sha256": execution.provider_policy_sha256,
                "functional_outcome_id": functional.program_functional_outcome_id,
                "oracle_decision_sha256": (
                    sha256_file(decision_path) if decision_path.is_file() else None
                ),
            },
        }
        rows.append(row)
        matrix_rows.append({"assignment_id": assignment_id, "task_id": task_id, "values": values})
        status_counts[execution.status.value] += 1
        security_counts[str(security_label)] += 1
        functional_counts[functional_status] += 1
        arm_counts[planned.arm_role.value] += 1
        cwe_counts[cwe] += 1
        provider_policy_sha256s.add(execution.provider_policy_sha256)

    report_counts = latest_report["counts"]
    if (
        len(rows) != expected
        or arm_counts != Counter({item.value: len(coverage) for item in _ARM_ORDER})
        or any(count % len(_ARM_ORDER) for count in cwe_counts.values())
        or report_counts.get("generated") != status_counts["generated"]
        or report_counts.get("terminal_no_code") != status_counts["terminal_no_code"]
        or report_counts.get("secure") != security_counts["secure"]
        or report_counts.get("insecure") != security_counts["insecure"]
        or _reported_itt_unknown_count(report_counts) != security_counts["unknown"]
        or report_counts.get("secure_and_functional")
        != sum(int(row["values"]["y_secure_functional"]) for row in rows)  # type: ignore[index]
    ):
        raise ValueError("randomized discovery assembled counts failed validation")

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "analysis-rows.jsonl", rows)
    _write_json(
        output_dir / "categorical-matrix.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "variable_order": list(_VARIABLE_ORDER),
            "category_orders": {
                "w_cwe_scope": list(cwe_order),
                "c_discovery_arm": [item.value for item in _ARM_ORDER],
                "binary": ["absent_or_not_success", "present_or_success"],
            },
            "rows": matrix_rows,
        },
    )
    summary: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "RANDOMIZED_DISCOVERY_RESULTS_COMPLETE",
        "assembly_policy": _POLICY,
        "model_id": model_id,
        "rows": len(rows),
        "independent_tasks": len(blocks),
        "post_randomization_rows_dropped": 0,
        "model_pooling_performed": False,
        "counts": {
            "execution": dict(sorted(status_counts.items())),
            "security": dict(sorted(security_counts.items())),
            "functional": dict(sorted(functional_counts.items())),
            "arm": dict(sorted(arm_counts.items())),
            "cwe": dict(sorted(cwe_counts.items())),
            "y_cwe_secure": sum(int(row["values"]["y_cwe_secure"]) for row in rows),  # type: ignore[index]
            "y_secure_functional": sum(
                int(row["values"]["y_secure_functional"])
                for row in rows  # type: ignore[index]
            ),
        },
        "provider_policy_sha256s": sorted(provider_policy_sha256s),
    }
    _write_json(output_dir / "summary.json", summary)
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "assembly_policy": _POLICY,
            "plan_directory": str(plan_dir),
            "plan_manifest_sha256": plan_manifest_sha256,
            "run_directory": str(run_dir),
            "complete_run_report": latest_report_path.name,
            "complete_run_report_sha256": sha256_file(latest_report_path),
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "estimand_config_sha256": sha256_file(estimand_config_path),
            "prompt_feature_realization_source": "gate_b_validated_arm_semantics_v1",
            "unknown_security_itt_value": 0,
            "unknown_functional_joint_itt_value": 0,
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    files = sorted(path for path in output_dir.rglob("*") if path.is_file())
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(output_dir).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )
    return summary


__all__ = ["assemble_randomized_discovery_results"]

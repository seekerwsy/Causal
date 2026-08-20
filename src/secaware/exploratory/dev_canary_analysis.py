"""Development-only paired summaries for the two-arm D_DEV canary.

This module deliberately does not implement confirmatory inference.  It authenticates
one complete two-arm Gate C run and emits descriptive, paired Target-minus-No-op
diagnostics.  Unknown outcomes remain in the assigned population with value zero.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.exploratory.gate_c_live import _verify_plan, _verify_unit_manifest
from secaware.functional_judge.schema import ProgramFunctionalOutcomeRecord
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import ArmRole, AssignmentRecord

_SCHEMA_VERSION = "1.0"
_POLICY = "minimal-validation-dev-canary-paired-summary-v1"
_TASK_SELECTION_POLICY = "explicit_dev_canary"
_ARMS = (ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE)
_ARM_VALUES = tuple(item.value for item in _ARMS)
_OUTCOMES = ("y_cwe_secure", "y_functional", "y_secure_functional")
_ALLOWED_TASK_COUNTS = frozenset({2, 12})
_ALLOWED_CWES = frozenset({"CWE-78", "CWE-89"})


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
        raise ValueError("D_DEV canary JSON object failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_canonical(row).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def _manifest(root: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    _write_json(
        root / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )


def _one_record(path: Path, model: type[Any]) -> Any:
    records = read_jsonl(path, model, required=True, allow_empty=False)
    if len(records) != 1:
        raise ValueError("D_DEV canary unit record cardinality failed validation")
    return records[0]


def _validated_plan(
    plan_dir: Path,
) -> tuple[
    dict[str, object],
    tuple[AssignmentRecord, ...],
    dict[str, dict[str, Any]],
    dict[str, dict[ArmRole, AssignmentRecord]],
]:
    report = _verify_plan(plan_dir)
    if (
        report.get("scientific_claim_allowed") is not False
        or report.get("task_selection_policy") != _TASK_SELECTION_POLICY
        or report.get("arm_roles") != list(_ARM_VALUES)
        or report.get("arms_per_task") != len(_ARMS)
    ):
        raise ValueError("D_DEV canary plan policy failed validation")

    assignments = tuple(
        read_jsonl(
            plan_dir / "assignments.jsonl",
            AssignmentRecord,
            required=True,
            allow_empty=False,
        )
    )
    coverage_rows = read_jsonl(plan_dir / "oracle-coverage.jsonl", required=True, allow_empty=False)
    assignments_by_id = {item.assignment_id: item for item in assignments}
    blocks: dict[str, dict[ArmRole, AssignmentRecord]] = {}
    for assignment in assignments:
        task_id = assignment.experimental_unit.task_id
        block = blocks.setdefault(task_id, {})
        if assignment.arm_role not in _ARMS or assignment.arm_role in block:
            raise ValueError("D_DEV canary two-arm block failed validation")
        block[assignment.arm_role] = assignment

    task_count = len(blocks)
    expected_by_cwe = 1 if task_count == 2 else 6 if task_count == 12 else 0
    coverage_by_task: dict[str, dict[str, Any]] = {}
    for row in coverage_rows:
        if type(row) is not dict:
            raise ValueError("D_DEV canary Oracle coverage failed validation")
        task_id = row.get("task_id")
        cwe = row.get("cwe")
        profile_id = row.get("oracle_profile_id")
        if (
            type(task_id) is not str
            or task_id in coverage_by_task
            or cwe not in _ALLOWED_CWES
            or type(profile_id) is not str
            or not profile_id
            or row.get("zero_finding_interpretation") != "profile_scoped_decision"
            or row.get("zero_finding_supported") is not True
        ):
            raise ValueError("D_DEV canary Oracle coverage failed validation")
        coverage_by_task[task_id] = row

    cwe_counts = Counter(str(row["cwe"]) for row in coverage_by_task.values())
    report_counts = report.get("counts")
    if (
        task_count not in _ALLOWED_TASK_COUNTS
        or len(assignments) != task_count * len(_ARMS)
        or len(assignments_by_id) != len(assignments)
        or set(coverage_by_task) != set(blocks)
        or any(set(block) != set(_ARMS) for block in blocks.values())
        or cwe_counts != Counter({cwe: expected_by_cwe for cwe in sorted(_ALLOWED_CWES)})
        or type(report_counts) is not dict
        or report_counts.get("assignments") != len(assignments)
        or report_counts.get("independent_tasks") != task_count
    ):
        raise ValueError("D_DEV canary plan population failed validation")

    for block in blocks.values():
        target = block[ArmRole.TARGET_PATCH]
        noop = block[ArmRole.NOOP_REWRITE]
        if (
            target.block_id != noop.block_id
            or target.experimental_unit.model_id != noop.experimental_unit.model_id
            or target.experimental_unit.hypothesis_id != noop.experimental_unit.hypothesis_id
            or target.target_spec_id != noop.target_spec_id
            or target.arm_protocol_id != noop.arm_protocol_id
        ):
            raise ValueError("D_DEV canary paired assignment failed validation")
    return report, assignments, coverage_by_task, blocks


def _latest_complete_report(live_run_dir: Path, expected: int) -> tuple[Path, dict[str, Any]]:
    candidates = sorted(live_run_dir.glob("report-*.json"))
    complete: list[tuple[Path, dict[str, Any]]] = []
    for path in candidates:
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
            complete.append((path, report))
    if not complete:
        raise ValueError("D_DEV canary complete live report is unavailable")
    return complete[-1]


def _coverage_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    assignment_count = len(rows)
    task_ids = sorted({str(row["task_id"]) for row in rows})
    blocks: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        blocks.setdefault(str(row["task_id"]), []).append(row)

    def assignment_count_for(key: str) -> int:
        return sum(int(bool(row["coverage"][key])) for row in rows)

    def complete_pairs_for(key: str) -> int:
        return sum(
            int(len(block) == 2 and all(bool(row["coverage"][key]) for row in block))
            for block in blocks.values()
        )

    by_arm: dict[str, object] = {}
    for arm in _ARM_VALUES:
        scoped = [row for row in rows if row["arm_role"] == arm]
        by_arm[arm] = {
            "assignments": len(scoped),
            "security_evaluable": sum(
                int(bool(row["coverage"]["security_evaluable"])) for row in scoped
            ),
            "functional_evaluable": sum(
                int(bool(row["coverage"]["functional_evaluable"])) for row in scoped
            ),
            "joint_evaluable": sum(int(bool(row["coverage"]["joint_evaluable"])) for row in scoped),
            "terminal_no_code": sum(
                int(bool(row["diagnostics"]["terminal_no_code"])) for row in scoped
            ),
        }
    security = assignment_count_for("security_evaluable")
    functional = assignment_count_for("functional_evaluable")
    joint = assignment_count_for("joint_evaluable")
    tasks = len(task_ids)
    return {
        "tasks": tasks,
        "assignments": assignment_count,
        "security_evaluable_assignments": security,
        "security_evaluable_rate": security / assignment_count,
        "functional_evaluable_assignments": functional,
        "functional_evaluable_rate": functional / assignment_count,
        "joint_evaluable_assignments": joint,
        "joint_evaluable_rate": joint / assignment_count,
        "complete_security_pairs": complete_pairs_for("security_evaluable"),
        "complete_security_pair_rate": complete_pairs_for("security_evaluable") / tasks,
        "complete_functional_pairs": complete_pairs_for("functional_evaluable"),
        "complete_functional_pair_rate": complete_pairs_for("functional_evaluable") / tasks,
        "complete_joint_pairs": complete_pairs_for("joint_evaluable"),
        "complete_joint_pair_rate": complete_pairs_for("joint_evaluable") / tasks,
        "terminal_no_code": sum(int(bool(row["diagnostics"]["terminal_no_code"])) for row in rows),
        "security_unknown": sum(
            int(row["diagnostics"]["security_label"] == "unknown") for row in rows
        ),
        "functional_unknown": sum(
            int(row["diagnostics"]["functional_status"] == "unknown") for row in rows
        ),
        "by_arm": by_arm,
    }


def _summary_row(
    *, scope: str, cwe: str | None, outcome: str, pairs: list[dict[str, Any]]
) -> dict[str, object]:
    differences = [int(pair["paired_differences"][outcome]) for pair in pairs]
    target = [int(pair["arms"][ArmRole.TARGET_PATCH.value]["values"][outcome]) for pair in pairs]
    noop = [int(pair["arms"][ArmRole.NOOP_REWRITE.value]["values"][outcome]) for pair in pairs]
    changes = Counter(
        "improved" if value > 0 else "harmed" if value < 0 else "unchanged" for value in differences
    )
    content: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "scope": scope,
        "cwe": cwe,
        "outcome_id": outcome,
        "task_clusters": len(pairs),
        "target_rate": sum(target) / len(target),
        "noop_rate": sum(noop) / len(noop),
        "paired_target_minus_noop": sum(differences) / len(differences),
        "improved": changes["improved"],
        "harmed": changes["harmed"],
        "unchanged": changes["unchanged"],
        "flip_rate": (changes["improved"] + changes["harmed"]) / len(pairs),
        "net_improvement_rate": (changes["improved"] - changes["harmed"]) / len(pairs),
        "unknown_itt_value": 0,
        "role": "development_diagnostic_only",
        "significance_testing_performed": False,
        "scientific_claim_allowed": False,
    }
    return {**content, "paired_summary_id": "dev_paired_summary_" + canonical_sha256(content)}


def analyze_dev_canary(
    *,
    plan_dir: Path,
    live_run_dir: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Authenticate and describe one complete two-arm development canary."""

    plan_dir = plan_dir.resolve()
    live_run_dir = live_run_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    if not plan_dir.is_dir() or not live_run_dir.is_dir():
        raise ValueError("D_DEV canary input directory failed validation")

    plan_report, assignments, coverage_by_task, blocks = _validated_plan(plan_dir)
    expected = len(assignments)
    plan_manifest_sha256 = sha256_file(plan_dir / "artifact-manifest.json")
    live_config = _read_json(live_run_dir / "live-config.json")
    input_provenance = _read_json(live_run_dir / "input-provenance.json")
    if (
        live_config.get("scientific_claim_allowed") is not False
        or live_config.get("task_selection_policy") != _TASK_SELECTION_POLICY
        or live_config.get("expected_assignments") != expected
        or live_config.get("zero_finding_interpretation") != "profile_scoped_decision"
        or input_provenance.get("source_plan_manifest_sha256") != plan_manifest_sha256
    ):
        raise ValueError("D_DEV canary live policy failed validation")
    complete_report_path, complete_report = _latest_complete_report(live_run_dir, expected)
    if set(complete_report.get("completed_assignment_ids", [])) != {
        item.assignment_id for item in assignments
    }:
        raise ValueError("D_DEV canary complete assignment ledger failed validation")

    units_root = live_run_dir / "units"
    actual_unit_ids = (
        {path.name for path in units_root.iterdir() if path.is_dir()}
        if units_root.is_dir()
        else set()
    )
    assignment_by_id = {item.assignment_id: item for item in assignments}
    if actual_unit_ids != set(assignment_by_id):
        raise ValueError("D_DEV canary live unit closure failed validation")

    rows: list[dict[str, Any]] = []
    unit_manifest_sha256s: dict[str, str] = {}
    for assignment_id in sorted(assignment_by_id):
        planned = assignment_by_id[assignment_id]
        unit_dir = units_root / assignment_id
        _verify_unit_manifest(unit_dir)
        unit_manifest_sha256s[assignment_id] = sha256_file(unit_dir / "artifact-manifest.json")
        observed = _one_record(unit_dir / "assignment.jsonl", AssignmentRecord)
        functional = _one_record(
            unit_dir / "functional-outcome.jsonl", ProgramFunctionalOutcomeRecord
        )
        status = _read_json(unit_dir / "status.json")
        generated = status.get("generated")
        terminal_no_code = status.get("terminal_no_code")
        if (
            observed != planned
            or status.get("status") != "COMPLETE"
            or status.get("assignment_id") != assignment_id
            or functional.assignment_id != assignment_id
            or type(generated) is not int
            or type(terminal_no_code) is not int
            or (generated, terminal_no_code) not in {(1, 0), (0, 1)}
        ):
            raise ValueError("D_DEV canary terminal unit failed validation")

        task_id = planned.experimental_unit.task_id
        coverage = coverage_by_task[task_id]
        decision_path = unit_dir / "oracle-decision.json"
        if generated:
            if (
                status.get("oracle_results") != 1
                or status.get("oracle_decisions") != 1
                or not decision_path.is_file()
            ):
                raise ValueError("D_DEV canary Oracle decision coverage failed validation")
            decision = _read_json(decision_path)
            security_label = decision.get("security_label")
            evaluability = decision.get("evaluability")
            if (
                decision.get("schema_version") != _SCHEMA_VERSION
                or decision.get("decision_profile_id") != coverage["oracle_profile_id"]
                or security_label not in {"secure", "insecure", "unknown"}
                or evaluability not in {"evaluable", "unknown_parse_failure", "unknown_coverage"}
                or (security_label in {"secure", "insecure"}) != (evaluability == "evaluable")
            ):
                raise ValueError("D_DEV canary Oracle decision failed validation")
            oracle_decision_sha256: str | None = sha256_file(decision_path)
        else:
            if (
                status.get("oracle_results") != 0
                or status.get("oracle_decisions") != 0
                or decision_path.exists()
            ):
                raise ValueError("D_DEV canary terminal Oracle invariant failed validation")
            security_label = "unknown"
            evaluability = "not_required_no_code"
            oracle_decision_sha256 = None

        functional_status = functional.status.value
        security_evaluable = security_label in {"secure", "insecure"}
        functional_evaluable = functional_status in {"pass", "fail"}
        values = {
            "y_cwe_secure": int(security_label == "secure"),
            "y_functional": int(functional_status == "pass"),
            "y_secure_functional": int(security_label == "secure" and functional_status == "pass"),
        }
        rows.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "assignment_id": assignment_id,
                "task_id": task_id,
                "block_id": planned.block_id,
                "model_id": planned.experimental_unit.model_id,
                "arm_role": planned.arm_role.value,
                "cwe": coverage["cwe"],
                "values": values,
                "coverage": {
                    "security_evaluable": security_evaluable,
                    "functional_evaluable": functional_evaluable,
                    "joint_evaluable": security_evaluable and functional_evaluable,
                },
                "diagnostics": {
                    "security_label": security_label,
                    "oracle_evaluability": evaluability,
                    "functional_status": functional_status,
                    "terminal_no_code": bool(terminal_no_code),
                },
                "provenance": {
                    "unit_manifest_sha256": unit_manifest_sha256s[assignment_id],
                    "functional_outcome_id": functional.program_functional_outcome_id,
                    "oracle_decision_sha256": oracle_decision_sha256,
                },
            }
        )

    row_by_assignment = {str(row["assignment_id"]): row for row in rows}
    pairs: list[dict[str, Any]] = []
    for task_id in sorted(blocks):
        planned_block = blocks[task_id]
        target = row_by_assignment[planned_block[ArmRole.TARGET_PATCH].assignment_id]
        noop = row_by_assignment[planned_block[ArmRole.NOOP_REWRITE].assignment_id]
        if target["cwe"] != noop["cwe"]:
            raise ValueError("D_DEV canary paired CWE failed validation")
        paired_differences = {
            outcome: int(target["values"][outcome]) - int(noop["values"][outcome])
            for outcome in _OUTCOMES
        }
        content: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "task_id": task_id,
            "cwe": str(target["cwe"]),
            "model_id": str(target["model_id"]),
            "arms": {
                ArmRole.TARGET_PATCH.value: target,
                ArmRole.NOOP_REWRITE.value: noop,
            },
            "paired_differences": paired_differences,
            "flip_diagnostics": {
                outcome: (
                    "improved" if difference > 0 else "harmed" if difference < 0 else "unchanged"
                )
                for outcome, difference in paired_differences.items()
            },
            "unknown_itt_value": 0,
            "role": "development_diagnostic_only",
            "scientific_claim_allowed": False,
        }
        pairs.append({**content, "pair_id": "dev_pair_" + canonical_sha256(content)})

    scopes: list[tuple[str, str | None, list[dict[str, Any]]]] = [("overall", None, pairs)]
    scopes.extend(
        ("cwe", cwe, [pair for pair in pairs if pair["cwe"] == cwe])
        for cwe in sorted(_ALLOWED_CWES)
    )
    paired_summaries = [
        _summary_row(scope=scope, cwe=cwe, outcome=outcome, pairs=scoped_pairs)
        for scope, cwe, scoped_pairs in scopes
        for outcome in _OUTCOMES
    ]
    coverage_summaries: list[dict[str, object]] = []
    for scope, cwe, scoped_pairs in scopes:
        scoped_rows = [row for pair in scoped_pairs for row in pair["arms"].values()]
        content = {
            "schema_version": _SCHEMA_VERSION,
            "scope": scope,
            "cwe": cwe,
            **_coverage_summary(scoped_rows),
            "role": "coverage_diagnostic",
            "scientific_claim_allowed": False,
        }
        coverage_summaries.append(
            {**content, "coverage_id": "dev_coverage_" + canonical_sha256(content)}
        )

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(output_dir / "task-pairs.jsonl", pairs)
    _write_jsonl(output_dir / "paired-summaries.jsonl", paired_summaries)
    _write_jsonl(output_dir / "coverage.jsonl", coverage_summaries)
    analysis_identity = {
        "schema_version": _SCHEMA_VERSION,
        "policy": _POLICY,
        "plan_manifest_sha256": plan_manifest_sha256,
        "complete_run_report_sha256": sha256_file(complete_report_path),
        "unit_manifest_sha256s": dict(sorted(unit_manifest_sha256s.items())),
    }
    analysis_id = "dev_canary_analysis_" + canonical_sha256(analysis_identity)
    _write_json(
        output_dir / "provenance.json",
        {
            **analysis_identity,
            "analysis_id": analysis_id,
            "plan_directory": str(plan_dir),
            "live_run_directory": str(live_run_dir),
            "complete_run_report": complete_report_path.name,
            "live_config_sha256": sha256_file(live_run_dir / "live-config.json"),
            "input_provenance_sha256": sha256_file(live_run_dir / "input-provenance.json"),
            "post_randomization_rows_dropped": 0,
            "unknown_itt_value": 0,
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    counts_by_cwe = Counter(str(pair["cwe"]) for pair in pairs)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "DEV_CANARY_PAIRED_SUMMARY_COMPLETE",
        "analysis_id": analysis_id,
        "analysis_policy": _POLICY,
        "analysis_role": "development_diagnostic_only",
        "counts": {
            "tasks": len(pairs),
            "assignments": len(rows),
            "complete_units": len(rows),
            "by_cwe": dict(sorted(counts_by_cwe.items())),
            "by_arm": dict(sorted(Counter(str(row["arm_role"]) for row in rows).items())),
            "paired_summaries": len(paired_summaries),
            "coverage_summaries": len(coverage_summaries),
            "terminal_no_code": sum(
                int(bool(row["diagnostics"]["terminal_no_code"])) for row in rows
            ),
            "security_unknown": sum(
                int(row["diagnostics"]["security_label"] == "unknown") for row in rows
            ),
            "functional_unknown": sum(
                int(row["diagnostics"]["functional_status"] == "unknown") for row in rows
            ),
            "post_randomization_filtered": 0,
            "errors": 0,
            "pending": 0,
        },
        "unknown_handling": "assigned_unknown_outcomes_score_zero_in_development_itt",
        "coverage_reported_separately": True,
        "significance_testing_performed": False,
        "confidence_intervals_computed": False,
        "p_values_computed": False,
        "formal_claim_allowed": False,
        "scientific_claim_allowed": False,
        "source_plan_status": plan_report["status"],
        "source_live_status": complete_report["status"],
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["analyze_dev_canary"]

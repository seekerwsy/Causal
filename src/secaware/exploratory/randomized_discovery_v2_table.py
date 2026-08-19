from __future__ import annotations

import json
import os
import platform
import re
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.experiments.held_out_policy_analysis import (
    _archive_files,
    _read_json_bytes,
    _read_jsonl_bytes,
    _verify_directory_manifest,
    _verify_manifest_bytes,
)
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file

_SCHEMA_VERSION = "1.0"
_MODELS = ("qwen2.5-coder-7b-instruct", "phi-4-14b")
_ARMS = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_VIEWS = (
    "target_noop_security",
    "target_noop_joint",
    "full_jci_security",
    "full_jci_joint",
)
_EXTERNAL_TO_INTERNAL = {
    "w_cwe_scope": "w.cwe_scope",
    "c_discovery_arm": "c.arm",
    "x_operation_specific_security_requirement": "x.operation_specific_security_requirement",
    "x_generic_security_reminder": "x.generic_security_reminder",
    "p_length_matched_placebo": "p.length_matched_placebo",
    "z_target_mechanism_realized": "z.target_mechanism_realized",
    "y_cwe_secure": "y.discovery_cwe_secure",
    "y_secure_functional": "y.discovery_secure_functional",
}
_VIEW_VARIABLES = {
    "target_noop_security": (
        "w_cwe_scope",
        "x_operation_specific_security_requirement",
        "z_target_mechanism_realized",
        "y_cwe_secure",
    ),
    "target_noop_joint": (
        "w_cwe_scope",
        "x_operation_specific_security_requirement",
        "z_target_mechanism_realized",
        "y_secure_functional",
    ),
    "full_jci_security": (
        "w_cwe_scope",
        "c_discovery_arm",
        "x_operation_specific_security_requirement",
        "x_generic_security_reminder",
        "p_length_matched_placebo",
        "z_target_mechanism_realized",
        "y_cwe_secure",
    ),
    "full_jci_joint": (
        "w_cwe_scope",
        "c_discovery_arm",
        "x_operation_specific_security_requirement",
        "x_generic_security_reminder",
        "p_length_matched_placebo",
        "z_target_mechanism_realized",
        "y_secure_functional",
    ),
}
_TARGET_NOOP_CONTEXT_POLICIES = (
    "implicit_x_only_v1",
    "explicit_jci_arm_v2",
)


def _view_variables(view_id: str, target_noop_context_policy: str) -> tuple[str, ...]:
    variables = _VIEW_VARIABLES[view_id]
    if target_noop_context_policy not in _TARGET_NOOP_CONTEXT_POLICIES:
        raise ValueError("discovery-v2 target/no-op context policy failed validation")
    if view_id.startswith("target_noop") and target_noop_context_policy == "explicit_jci_arm_v2":
        return (variables[0], "c_discovery_arm", *variables[1:])
    return variables


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
        raise ValueError("discovery-v2 table JSON object failed validation")
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


def _validated_config(repo_root: Path, path: Path) -> dict[str, Any]:
    config = _read_json(path)
    archives = config.get("model_result_archives")
    context_policy = config.get("target_noop_context_policy", "implicit_x_only_v1")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("expected_tasks_per_model") not in {5, 51}
        or tuple(archives or {}) != _MODELS
        or config.get("views") != list(_VIEWS)
        or config.get("prompt_only_baseline") != "five_cwe_randomized_discovery_analysis_v1"
        or config.get("provider_calls_allowed") is not False
        or config.get("scientific_claim_allowed") is not False
        or context_policy not in _TARGET_NOOP_CONTEXT_POLICIES
    ):
        raise ValueError("discovery-v2 table configuration failed validation")
    mechanism_dir = (repo_root / str(config.get("mechanism_audit_dir"))).resolve()
    mechanism_dir.relative_to(repo_root)
    if not mechanism_dir.is_dir():
        raise ValueError("discovery-v2 mechanism audit directory failed validation")
    for model_id, record in archives.items():
        if (
            model_id not in _MODELS
            or type(record) is not dict
            or re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))) is None
        ):
            raise ValueError("discovery-v2 result archive config failed validation")
        archive_path = (repo_root / str(record.get("path"))).resolve()
        archive_path.relative_to(repo_root)
        if not archive_path.is_file() or sha256_file(archive_path) != record["sha256"]:
            raise ValueError("discovery-v2 result archive digest failed validation")
    return config


def _result_rows(
    archive_path: Path, expected_model: str
) -> tuple[list[dict[str, Any]], dict[str, object]]:
    root_name, files = _archive_files(archive_path)
    manifest_sha256 = _verify_manifest_bytes(files)
    rows = _read_jsonl_bytes(files["analysis-rows.jsonl"])
    summary = _read_json_bytes(files["summary.json"])
    if (
        len(rows) != 204
        or summary.get("status") != "RANDOMIZED_DISCOVERY_RESULTS_COMPLETE"
        or summary.get("model_id") != expected_model
        or summary.get("rows") != 204
        or summary.get("independent_tasks") != 51
        or any(row.get("model_id") != expected_model for row in rows)
    ):
        raise ValueError("discovery-v2 result assembly failed validation")
    return rows, {
        "model_id": expected_model,
        "archive_root": root_name,
        "archive_sha256": sha256_file(archive_path),
        "manifest_sha256": manifest_sha256,
        "rows": len(rows),
    }


def _joined_row(mechanism: dict[str, Any], outcome: dict[str, Any]) -> dict[str, object]:
    outcome_values = outcome.get("values")
    if (
        type(outcome_values) is not dict
        or mechanism.get("assignment_id") != outcome.get("assignment_id")
        or mechanism.get("task_id") != outcome.get("task_id")
        or mechanism.get("model_id") != outcome.get("model_id")
        or mechanism.get("arm_role") != outcome.get("arm_role")
        or mechanism.get("cwe") != outcome.get("cwe")
        or mechanism.get("z_target_mechanism_realized") not in {0, 1}
        or set(outcome_values)
        != {
            "w_cwe_scope",
            "c_discovery_arm",
            "x_operation_specific_security_requirement",
            "x_generic_security_reminder",
            "p_length_matched_placebo",
            "y_cwe_secure",
            "y_secure_functional",
        }
    ):
        raise ValueError("discovery-v2 assignment join failed validation")
    values = {
        **outcome_values,
        "z_target_mechanism_realized": int(mechanism["z_target_mechanism_realized"]),
    }
    if any(type(value) is not int or value < 0 for value in values.values()):
        raise ValueError("discovery-v2 joined values failed validation")
    return {
        "schema_version": _SCHEMA_VERSION,
        "assignment_id": str(outcome["assignment_id"]),
        "task_id": str(outcome["task_id"]),
        "model_id": str(outcome["model_id"]),
        "arm_role": str(outcome["arm_role"]),
        "cwe": str(outcome["cwe"]),
        "target_spec_id": str(outcome["target_spec_id"]),
        "target_instance_id": str(outcome["target_instance_id"]),
        "arm_protocol_id": str(outcome["arm_protocol_id"]),
        "protocol_instance_id": str(outcome["protocol_instance_id"]),
        "values": values,
        "mechanism_state": str(mechanism["mechanism_state"]),
        "provenance": {
            "mechanism": mechanism["provenance"],
            "outcome": outcome["provenance"],
        },
    }


def _view_rows(
    joined: list[dict[str, object]],
    *,
    model_id: str,
    view_id: str,
    target_noop_context_policy: str = "implicit_x_only_v1",
) -> list[dict[str, object]]:
    if view_id not in _VIEWS or model_id not in _MODELS:
        raise ValueError("discovery-v2 view failed validation")
    selected_arms = (
        {"target_patch", "noop_rewrite"} if view_id.startswith("target_noop") else set(_ARMS)
    )
    variables = _view_variables(view_id, target_noop_context_policy)
    rows = []
    for row in joined:
        if row["model_id"] != model_id or row["arm_role"] not in selected_arms:
            continue
        values = row["values"]
        if type(values) is not dict:
            raise ValueError("discovery-v2 view values failed validation")
        rows.append(
            {
                "assignment_id": row["assignment_id"],
                "task_id": row["task_id"],
                "target_spec_id": row["target_spec_id"],
                "target_instance_id": row["target_instance_id"],
                "arm_protocol_id": row["arm_protocol_id"],
                "protocol_instance_id": row["protocol_instance_id"],
                "values": [int(values[variable]) for variable in variables],
            }
        )
    rows.sort(key=lambda item: str(item["assignment_id"]))
    return rows


def build_randomized_discovery_v2_tables(
    *,
    repo_root: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    config_path = config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError("discovery-v2 table output already exists")
    config = _validated_config(repo_root, config_path)
    mechanism_dir = (repo_root / config["mechanism_audit_dir"]).resolve()
    mechanism_manifest_sha256 = _verify_directory_manifest(mechanism_dir)
    mechanism_report = _read_json(mechanism_dir / "report.json")
    mechanism_rows = read_jsonl(
        mechanism_dir / "mechanism-rows.jsonl", required=True, allow_empty=False
    )
    expected_tasks = int(config["expected_tasks_per_model"])
    context_policy = str(config.get("target_noop_context_policy", "implicit_x_only_v1"))
    expected_rows = expected_tasks * len(_MODELS) * len(_ARMS)
    if (
        mechanism_report.get("status") != "MECHANISM_VARIATION_SUPPORTED"
        or mechanism_report.get("counts", {}).get("tasks_per_model") != expected_tasks
        or len(mechanism_rows) != expected_rows
    ):
        raise ValueError("discovery-v2 mechanism input failed validation")
    mechanism_by_assignment = {str(row["assignment_id"]): row for row in mechanism_rows}
    if len(mechanism_by_assignment) != expected_rows:
        raise ValueError("discovery-v2 mechanism assignment relation failed validation")

    joined: list[dict[str, object]] = []
    result_provenance: list[dict[str, object]] = []
    for model_id in _MODELS:
        archive_record = config["model_result_archives"][model_id]
        outcome_rows, provenance = _result_rows(repo_root / archive_record["path"], model_id)
        result_provenance.append(provenance)
        outcome_by_assignment = {str(row["assignment_id"]): row for row in outcome_rows}
        model_mechanisms = {
            assignment_id: row
            for assignment_id, row in mechanism_by_assignment.items()
            if row["model_id"] == model_id
        }
        if not set(model_mechanisms) <= set(outcome_by_assignment):
            raise ValueError("discovery-v2 outcome assignment coverage failed validation")
        joined.extend(
            _joined_row(mechanism, outcome_by_assignment[assignment_id])
            for assignment_id, mechanism in sorted(model_mechanisms.items())
        )
    if len(joined) != expected_rows:
        raise ValueError("discovery-v2 joined population failed validation")

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    joined.sort(key=lambda row: (str(row["model_id"]), str(row["assignment_id"])))
    _write_jsonl(output_dir / "joined-rows.jsonl", joined)
    view_reports: list[dict[str, object]] = []
    for model_id in _MODELS:
        model_stem = "qwen7b" if model_id.startswith("qwen") else "phi14b"
        for view_id in _VIEWS:
            rows = _view_rows(
                joined,
                model_id=model_id,
                view_id=view_id,
                target_noop_context_policy=context_policy,
            )
            expected_view_rows = expected_tasks * (2 if view_id.startswith("target_noop") else 4)
            task_counts = Counter(str(row["task_id"]) for row in rows)
            if (
                len(rows) != expected_view_rows
                or len(task_counts) != expected_tasks
                or set(task_counts.values()) != ({2} if view_id.startswith("target_noop") else {4})
            ):
                raise ValueError("discovery-v2 view population failed validation")
            variables = _view_variables(view_id, context_policy)
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "view_id": view_id,
                "model_id": model_id,
                "independent_tasks": expected_tasks,
                "row_count": len(rows),
                "variable_order": list(variables),
                "internal_variable_ids": [_EXTERNAL_TO_INTERNAL[item] for item in variables],
                "category_orders": {
                    "w_cwe_scope": ["CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"],
                    "c_discovery_arm": list(_ARMS),
                    "binary": ["absent_or_not_success", "present_or_success"],
                },
                "rows": rows,
            }
            filename = f"matrix-{model_stem}-{view_id}.json"
            _write_json(output_dir / filename, payload)
            view_reports.append(
                {
                    "model_id": model_id,
                    "view_id": view_id,
                    "rows": len(rows),
                    "independent_tasks": expected_tasks,
                    "variables": len(variables),
                    "matrix_sha256": canonical_sha256(payload),
                    "artifact": filename,
                }
            )
    _write_json(output_dir / "environment.json", _environment())
    _write_json(
        output_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": list(command_argv)},
    )
    _write_json(
        output_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": sha256_file(config_path),
            "mechanism_manifest_sha256": mechanism_manifest_sha256,
            "result_assemblies": result_provenance,
            "input_bundle_sha256": canonical_sha256(
                {
                    "config_sha256": sha256_file(config_path),
                    "mechanism_manifest_sha256": mechanism_manifest_sha256,
                    "result_assemblies": result_provenance,
                }
            ),
        },
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "DISCOVERY_V2_TABLES_COMPLETE",
        "table_bundle_id": config["table_bundle_id"],
        "counts": {
            "models": len(_MODELS),
            "tasks_per_model": expected_tasks,
            "joined_rows": len(joined),
            "views": len(view_reports),
            "provider_calls": 0,
            "errors": 0,
            "pending": 0,
        },
        "views": view_reports,
        "prompt_only_baseline": config["prompt_only_baseline"],
        "next_gate": "typed_table_and_reference_fci_pilot",
        "scientific_claim_allowed": False,
    }
    _write_json(output_dir / "report.json", report)
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.name, "sha256": sha256_file(path)}
                for path in sorted(output_dir.iterdir())
                if path.is_file()
            ],
        },
    )
    return report


__all__ = ["build_randomized_discovery_v2_tables"]

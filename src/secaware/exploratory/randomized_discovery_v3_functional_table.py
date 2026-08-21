"""Build 93-task JCI tables with security-mechanism Z and independent functional Y."""

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

from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.randomized_discovery_v2_table import _result_rows
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
_CWE_ORDER = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_VIEWS = ("target_noop_functional", "full_jci_functional")
_VARIABLE_IDS = (
    "c.arm",
    "z.target_mechanism_realized",
    "y.discovery_functional",
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
        raise ValueError("discovery-v3 functional JSON object failed validation")
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
    archives = config.get("discovery_result_archives")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("table_bundle_id") != "five_cwe_discovery_v3_functional_table_v1"
        or tuple(archives or {}) != _MODELS
        or config.get("expected_discovery_tasks_per_model") != 51
        or config.get("expected_held_out_tasks_per_model") != 42
        or config.get("expected_combined_tasks_per_model") != 93
        or config.get("views") != list(_VIEWS)
        or config.get("security_or_joint_outcome_as_y") != "forbidden_due_semantic_identity_with_z"
        or config.get("provider_calls_allowed") is not False
        or config.get("scientific_claim_allowed") is not False
    ):
        raise ValueError("discovery-v3 functional table config failed validation")
    for key in ("discovery_table_dir", "held_out_analysis_dir"):
        directory = (repo_root / str(config.get(key))).resolve()
        directory.relative_to(repo_root)
        if not directory.is_dir():
            raise ValueError("discovery-v3 functional input directory failed validation")
    for model_id, record in archives.items():
        if (
            model_id not in _MODELS
            or type(record) is not dict
            or re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))) is None
        ):
            raise ValueError("discovery-v3 functional archive config failed validation")
        archive = (repo_root / str(record.get("path"))).resolve()
        archive.relative_to(repo_root)
        if not archive.is_file() or sha256_file(archive) != record["sha256"]:
            raise ValueError("discovery-v3 functional archive digest failed validation")
    return config


def _discovery_row(
    joined: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, object]:
    values = joined.get("values")
    diagnostics = result.get("diagnostics")
    result_provenance = result.get("provenance")
    if (
        type(values) is not dict
        or type(diagnostics) is not dict
        or type(result_provenance) is not dict
        or joined.get("assignment_id") != result.get("assignment_id")
        or joined.get("task_id") != result.get("task_id")
        or joined.get("model_id") != result.get("model_id")
        or joined.get("arm_role") != result.get("arm_role")
        or joined.get("cwe") != result.get("cwe")
        or diagnostics.get("functional_status") not in {"pass", "fail", "unknown"}
        or values.get("z_target_mechanism_realized") not in {0, 1}
        or values.get("y_cwe_secure") not in {0, 1}
    ):
        raise ValueError("discovery-v3 discovery projection failed validation")
    return {
        "schema_version": _SCHEMA_VERSION,
        "source_split": "discover",
        "assignment_id": str(joined["assignment_id"]),
        "task_id": str(joined["task_id"]),
        "model_id": str(joined["model_id"]),
        "arm_role": str(joined["arm_role"]),
        "cwe": str(joined["cwe"]),
        "target_spec_id": str(joined["target_spec_id"]),
        "target_instance_id": str(joined["target_instance_id"]),
        "arm_protocol_id": str(joined["arm_protocol_id"]),
        "protocol_instance_id": str(joined["protocol_instance_id"]),
        "values": {
            "c.arm": _ARMS.index(str(joined["arm_role"])),
            "z.target_mechanism_realized": int(values["z_target_mechanism_realized"]),
            "y.discovery_functional": int(diagnostics["functional_status"] == "pass"),
        },
        "semantic_leakage_probe": {
            "z": int(values["z_target_mechanism_realized"]),
            "security_y": int(values["y_cwe_secure"]),
        },
        "provenance": {
            "mechanism": joined["provenance"]["mechanism"],
            "functional": {
                "functional_outcome_id": result_provenance["functional_outcome_id"],
                "unit_manifest_sha256": result_provenance["unit_manifest_sha256"],
            },
        },
    }


def _held_out_row(row: dict[str, Any]) -> dict[str, object]:
    assignment = row.get("assignment_outcome")
    mechanism = row.get("mechanism_outcomes")
    if (
        type(assignment) is not dict
        or type(mechanism) is not dict
        or assignment.get("model_id") not in _MODELS
        or assignment.get("arm_role") not in _ARMS
        or row.get("cwe") not in _CWE_ORDER
        or type(assignment.get("functional_ok")) is not bool
        or assignment.get("cwe_security_outcome") not in {"secure", "insecure", "unknown"}
        or mechanism.get("z_all_relevant_sinks_proved_safe") not in {0, 1}
        or re.fullmatch(r"[0-9a-f]{64}", str(row.get("unit_manifest_sha256"))) is None
    ):
        raise ValueError("discovery-v3 held-out projection failed validation")
    arm = str(assignment["arm_role"])
    return {
        "schema_version": _SCHEMA_VERSION,
        "source_split": "historical_held_out_method_development",
        "assignment_id": str(assignment["assignment_id"]),
        "task_id": str(assignment["task_id"]),
        "model_id": str(assignment["model_id"]),
        "arm_role": arm,
        "cwe": str(row["cwe"]),
        "target_spec_id": str(assignment["target_spec_id"]),
        "target_instance_id": str(assignment["target_instance_id"]),
        "arm_protocol_id": str(assignment["arm_protocol_id"]),
        "protocol_instance_id": str(assignment["protocol_instance_id"]),
        "values": {
            "c.arm": _ARMS.index(arm),
            "z.target_mechanism_realized": int(mechanism["z_all_relevant_sinks_proved_safe"]),
            "y.discovery_functional": int(assignment["functional_ok"]),
        },
        "semantic_leakage_probe": {
            "z": int(mechanism["z_all_relevant_sinks_proved_safe"]),
            "security_y": int(assignment["cwe_security_outcome"] == "secure"),
        },
        "provenance": {
            "mechanism": {
                "held_out_outcome_row_id": row["held_out_outcome_row_id"],
                "unit_manifest_sha256": row["unit_manifest_sha256"],
                "field": "mechanism_outcomes.z_all_relevant_sinks_proved_safe",
            },
            "functional": {
                "outcome_id": assignment["outcome_id"],
                "functional_status": row["functional_status"],
                "field": "assignment_outcome.functional_ok",
            },
        },
    }


def build_randomized_discovery_v3_functional_table(
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
        raise ValueError("discovery-v3 functional output already exists")
    config = _validated_config(repo_root, config_path)
    discovery_dir = (repo_root / config["discovery_table_dir"]).resolve()
    held_out_dir = (repo_root / config["held_out_analysis_dir"]).resolve()
    discovery_manifest_sha256 = _verify_directory_manifest(discovery_dir)
    held_out_manifest_sha256 = _verify_directory_manifest(held_out_dir)
    joined = read_jsonl(discovery_dir / "joined-rows.jsonl", required=True, allow_empty=False)
    held_out = read_jsonl(
        held_out_dir / "assignment-outcomes.jsonl", required=True, allow_empty=False
    )
    if len(joined) != 408 or len(held_out) != 336:
        raise ValueError("discovery-v3 functional source population failed validation")
    result_rows: dict[str, dict[str, Any]] = {}
    archive_provenance = []
    for model_id in _MODELS:
        record = config["discovery_result_archives"][model_id]
        rows, provenance = _result_rows(repo_root / record["path"], model_id)
        archive_provenance.append(provenance)
        for row in rows:
            assignment_id = str(row["assignment_id"])
            if assignment_id in result_rows:
                raise ValueError("discovery-v3 duplicate discovery assignment failed validation")
            result_rows[assignment_id] = row
    combined = [_discovery_row(row, result_rows[str(row["assignment_id"])]) for row in joined]
    combined.extend(_held_out_row(row) for row in held_out)
    combined.sort(key=lambda row: (str(row["model_id"]), str(row["assignment_id"])))
    if len(combined) != 744:
        raise ValueError("discovery-v3 combined population failed validation")
    task_sets: dict[tuple[str, str], set[str]] = {}
    for row in combined:
        key = (str(row["model_id"]), str(row["source_split"]))
        task_sets.setdefault(key, set()).add(str(row["task_id"]))
    for model_id in _MODELS:
        discover = task_sets[(model_id, "discover")]
        held = task_sets[(model_id, "historical_held_out_method_development")]
        if len(discover) != 51 or len(held) != 42 or discover & held:
            raise ValueError("discovery-v3 task split relation failed validation")
    leakage_mismatches = sum(
        row["semantic_leakage_probe"]["z"] != row["semantic_leakage_probe"]["security_y"]
        for row in combined
    )
    if leakage_mismatches != 0:
        raise ValueError("discovery-v3 frozen leakage boundary drifted")
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    _write_jsonl(output_dir / "combined-rows.jsonl", combined)
    view_reports = []
    for model_id in _MODELS:
        stem = "qwen7b" if model_id.startswith("qwen") else "phi14b"
        for view_id in _VIEWS:
            selected_arms = (
                {"target_patch", "noop_rewrite"}
                if view_id == "target_noop_functional"
                else set(_ARMS)
            )
            rows = [
                {
                    "assignment_id": row["assignment_id"],
                    "task_id": row["task_id"],
                    "target_spec_id": row["target_spec_id"],
                    "target_instance_id": row["target_instance_id"],
                    "arm_protocol_id": row["arm_protocol_id"],
                    "protocol_instance_id": row["protocol_instance_id"],
                    "values": [row["values"][variable] for variable in _VARIABLE_IDS],
                }
                for row in combined
                if row["model_id"] == model_id and row["arm_role"] in selected_arms
            ]
            rows.sort(key=lambda row: str(row["assignment_id"]))
            block_size = len(selected_arms)
            counts = Counter(str(row["task_id"]) for row in rows)
            if len(counts) != 93 or set(counts.values()) != {block_size}:
                raise ValueError("discovery-v3 functional view blocks failed validation")
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "view_id": view_id,
                "model_id": model_id,
                "independent_tasks": 93,
                "row_count": len(rows),
                "internal_variable_ids": list(_VARIABLE_IDS),
                "category_orders": {
                    "c.arm": list(_ARMS),
                    "binary": ["absent_or_not_success", "present_or_success"],
                },
                "rows": rows,
            }
            filename = f"matrix-{stem}-{view_id}.json"
            _write_json(output_dir / filename, payload)
            view_reports.append(
                {
                    "model_id": model_id,
                    "view_id": view_id,
                    "rows": len(rows),
                    "independent_tasks": 93,
                    "variables": len(_VARIABLE_IDS),
                    "matrix_sha256": canonical_sha256(payload),
                    "artifact": filename,
                }
            )
    _write_json(
        output_dir / "semantic-leakage-audit.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "rows": len(combined),
            "z_security_y_mismatches": leakage_mismatches,
            "z_security_y_identity_fraction": 1.0,
            "excluded_outcomes": [
                "y.discovery_cwe_secure",
                "y.discovery_secure_functional",
            ],
            "retained_outcome": "y.discovery_functional",
            "interpretation": "mechanism_to_security_edges_are_definitional_not_discoveries",
        },
    )
    _write_json(output_dir / "environment.json", _environment())
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(
        output_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": sha256_file(config_path),
            "discovery_manifest_sha256": discovery_manifest_sha256,
            "held_out_manifest_sha256": held_out_manifest_sha256,
            "discovery_result_archives": archive_provenance,
        },
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "DISCOVERY_V3_FUNCTIONAL_TABLES_COMPLETE",
        "counts": {
            "combined_rows": len(combined),
            "tasks_per_model": 93,
            "discovery_tasks_per_model": 51,
            "historical_held_out_tasks_per_model": 42,
            "views": len(view_reports),
            "errors": 0,
            "pending": 0,
            "provider_calls": 0,
        },
        "semantic_leakage_detected": True,
        "security_or_joint_y_excluded": True,
        "scientific_claim_allowed": False,
        "view_reports": view_reports,
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


__all__ = ["build_randomized_discovery_v3_functional_table"]

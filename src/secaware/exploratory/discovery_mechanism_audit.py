from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
import json
import os
import platform
from pathlib import Path
import socket
import sys
from typing import Any

from secaware.experiments.held_out_policy_analysis import (
    _archive_files,
    _one_jsonl,
    _read_json_bytes,
    _verify_manifest_bytes,
)
from secaware.exploratory.gate_c_live import _oracle_analysis_from_payload
from secaware.oracle.profile_decision import mechanism_trace_sha256
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import AssignmentRecord


_SCHEMA_VERSION = "1.0"
_MODELS = ("qwen2.5-coder-7b-instruct", "phi-4-14b")
_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_ARMS = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_STATES = (
    "unavailable",
    "no_relevant_sink",
    "proved_safe",
    "proved_unsafe",
    "unresolved",
)
_OUTCOME_FILES = frozenset({"oracle-decision.json", "functional-outcome.jsonl"})


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
        raise ValueError("discovery mechanism audit JSON object failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_canonical(row).decode("utf-8") + "\n")


def _validated_config(repo_root: Path, path: Path) -> dict[str, Any]:
    config = _read_json(path)
    archives = config.get("model_archives")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("selection_policy")
        not in {"one_lexicographic_task_per_cwe", "all_complete_discovery_tasks"}
        or config.get("expected_tasks_per_model") not in {5, 51}
        or config.get("expected_cwes") != list(_CWES)
        or tuple(archives or {}) != _MODELS
        or config.get("outcome_payloads_forbidden") != sorted(_OUTCOME_FILES)
        or config.get("provider_calls_allowed") is not False
        or config.get("scientific_claim_allowed") is not False
    ):
        raise ValueError("discovery mechanism audit configuration failed validation")
    for relative in archives.values():
        archive = (repo_root / relative).resolve()
        archive.relative_to(repo_root)
        if not archive.is_file():
            raise ValueError("discovery mechanism audit archive failed validation")
    return config


def _mechanism_state(
    *,
    cwe: str,
    parse_ok: bool,
    sink_facts: list[dict[str, Any]],
) -> str:
    if cwe not in _CWES or type(parse_ok) is not bool or type(sink_facts) is not list:
        raise ValueError("discovery mechanism state input failed validation")
    if not parse_ok:
        if sink_facts:
            raise ValueError("discovery mechanism parse failure carried sink facts")
        return "unavailable"
    relevant: list[str] = []
    for fact in sink_facts:
        if type(fact) is not dict or fact.get("state") not in {"safe", "unsafe", "unresolved"}:
            raise ValueError("discovery mechanism sink fact failed validation")
        if fact.get("cwe") == cwe:
            relevant.append(str(fact["state"]))
    if not relevant:
        return "no_relevant_sink"
    if "unsafe" in relevant:
        return "proved_unsafe"
    if "unresolved" in relevant:
        return "unresolved"
    if set(relevant) == {"safe"}:
        return "proved_safe"
    raise ValueError("discovery mechanism state failed validation")


def _selected_tasks(
    task_cwe: dict[str, str],
    *,
    policy: str,
) -> tuple[str, ...]:
    if policy == "all_complete_discovery_tasks":
        return tuple(sorted(task_cwe))
    if policy != "one_lexicographic_task_per_cwe":
        raise ValueError("discovery mechanism selection policy failed validation")
    selected = []
    for cwe in _CWES:
        candidates = sorted(
            task_id for task_id, task_scope in task_cwe.items() if task_scope == cwe
        )
        if not candidates:
            raise ValueError("discovery mechanism pilot CWE coverage failed validation")
        selected.append(candidates[0])
    return tuple(selected)


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def _load_archive(
    *,
    archive_path: Path,
    expected_model: str,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    root_name, files = _archive_files(archive_path)
    top_manifest_present = "artifact-manifest.json" in files
    manifest_sha256 = _verify_manifest_bytes(files) if top_manifest_present else None
    prefixes = sorted(
        name.removesuffix("/status.json")
        for name in files
        if name.startswith("units/") and name.endswith("/status.json")
    )
    if len(prefixes) != 204:
        raise ValueError("discovery mechanism archive unit count failed validation")
    rows: list[dict[str, object]] = []
    for prefix in prefixes:
        status = _read_json_bytes(files[f"{prefix}/status.json"])
        assignment_payload = _one_jsonl(files, f"{prefix}/assignment.jsonl")
        assignment = AssignmentRecord.model_validate(assignment_payload)
        execution = _one_jsonl(files, f"{prefix}/assignment-execution.jsonl")
        coverage = _read_json_bytes(files[f"{prefix}/oracle-coverage.json"])
        if (
            status.get("status") != "COMPLETE"
            or assignment.experimental_unit.model_id != expected_model
            or execution.get("assignment_id") != assignment.assignment_id
            or coverage.get("cwe") not in _CWES
            or assignment.arm_role.value not in _ARMS
        ):
            raise ValueError("discovery mechanism unit binding failed validation")
        unit_manifest_sha256 = _verify_manifest_bytes(files, prefix)
        execution_status = execution.get("status")
        analysis_name = f"{prefix}/oracle-analysis.json"
        binding_name = f"{prefix}/oracle-binding.json"
        if execution_status == "generated":
            analysis_payload = _read_json_bytes(files[analysis_name])
            analysis = _oracle_analysis_from_payload(analysis_payload)
            binding = _read_json_bytes(files[binding_name])
            if binding != {
                "schema_version": _SCHEMA_VERSION,
                "assignment_id": assignment.assignment_id,
                "request_id": analysis.request_id,
                "code_id": analysis.code_id,
                "binding_performed_after_blind_analysis": True,
            }:
                raise ValueError("discovery mechanism blind binding failed validation")
            trace_payload = analysis_payload["mechanism_trace"]
            state = _mechanism_state(
                cwe=str(coverage["cwe"]),
                parse_ok=analysis.mechanism_trace.parse_ok,
                sink_facts=trace_payload["sink_facts"],
            )
            analysis_sha256 = canonical_sha256(analysis_payload)
            trace_sha256 = mechanism_trace_sha256(analysis.mechanism_trace)
        elif execution_status == "terminal_no_code":
            if analysis_name in files or binding_name in files:
                raise ValueError("discovery mechanism terminal unit carried Oracle analysis")
            state = "unavailable"
            analysis_sha256 = None
            trace_sha256 = None
        else:
            raise ValueError("discovery mechanism execution status failed validation")
        rows.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "assignment_id": assignment.assignment_id,
                "task_id": assignment.experimental_unit.task_id,
                "model_id": expected_model,
                "arm_role": assignment.arm_role.value,
                "cwe": str(coverage["cwe"]),
                "mechanism_state": state,
                "z_target_mechanism_realized": int(state == "proved_safe"),
                "provenance": {
                    "archive_sha256": sha256_file(archive_path),
                    "unit_manifest_sha256": unit_manifest_sha256,
                    "oracle_analysis_sha256": analysis_sha256,
                    "mechanism_trace_sha256": trace_sha256,
                },
            }
        )
    return rows, {
        "model_id": expected_model,
        "archive_root": root_name,
        "archive_sha256": sha256_file(archive_path),
        "archive_manifest_sha256": manifest_sha256,
        "archive_authentication": (
            "top_manifest_and_unit_manifests_v1"
            if top_manifest_present
            else "archive_sha256_and_unit_manifests_v1"
        ),
        "units": len(rows),
    }


def audit_discovery_mechanism_variation(
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
        raise ValueError("discovery mechanism output already exists")
    config = _validated_config(repo_root, config_path)
    all_rows: list[dict[str, object]] = []
    archive_provenance: list[dict[str, object]] = []
    task_cwe_by_model: dict[str, dict[str, str]] = {}
    for model_id in _MODELS:
        archive_path = repo_root / config["model_archives"][model_id]
        rows, provenance = _load_archive(archive_path=archive_path, expected_model=model_id)
        all_rows.extend(rows)
        archive_provenance.append(provenance)
        task_cwe = {str(row["task_id"]): str(row["cwe"]) for row in rows}
        if len(task_cwe) != 51:
            raise ValueError("discovery mechanism task count failed validation")
        task_cwe_by_model[model_id] = task_cwe
    if task_cwe_by_model[_MODELS[0]] != task_cwe_by_model[_MODELS[1]]:
        raise ValueError("discovery mechanism model task populations differ")
    selected = _selected_tasks(
        task_cwe_by_model[_MODELS[0]],
        policy=str(config["selection_policy"]),
    )
    if len(selected) != config["expected_tasks_per_model"]:
        raise ValueError("discovery mechanism selected task count failed validation")
    selected_set = set(selected)
    rows = [row for row in all_rows if row["task_id"] in selected_set]
    expected_rows = len(selected) * len(_MODELS) * len(_ARMS)
    blocks: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        blocks[(str(row["model_id"]), str(row["task_id"]))].append(row)
    if (
        len(rows) != expected_rows
        or len(blocks) != len(selected) * len(_MODELS)
        or any({str(row["arm_role"]) for row in block} != set(_ARMS) for block in blocks.values())
    ):
        raise ValueError("discovery mechanism complete block failed validation")

    distributions: dict[str, dict[str, dict[str, int]]] = {}
    transitions: list[dict[str, object]] = []
    transition_counts: dict[str, Counter[str]] = {model: Counter() for model in _MODELS}
    for model_id in _MODELS:
        distributions[model_id] = {}
        for arm in _ARMS:
            counter = Counter(
                str(row["mechanism_state"])
                for row in rows
                if row["model_id"] == model_id and row["arm_role"] == arm
            )
            distributions[model_id][arm] = {state: counter[state] for state in _STATES}
        for task_id in selected:
            by_arm = {str(row["arm_role"]): row for row in blocks[(model_id, task_id)]}
            target = int(by_arm["target_patch"]["z_target_mechanism_realized"])
            noop = int(by_arm["noop_rewrite"]["z_target_mechanism_realized"])
            transition = "improved" if target > noop else "harmed" if target < noop else "unchanged"
            transition_counts[model_id][transition] += 1
            transitions.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "model_id": model_id,
                    "task_id": task_id,
                    "cwe": task_cwe_by_model[model_id][task_id],
                    "target_state": by_arm["target_patch"]["mechanism_state"],
                    "noop_state": by_arm["noop_rewrite"]["mechanism_state"],
                    "target_realized": target,
                    "noop_realized": noop,
                    "transition": transition,
                }
            )
    variation_supported = all(
        len(
            {int(row["z_target_mechanism_realized"]) for row in rows if row["model_id"] == model_id}
        )
        == 2
        and transition_counts[model_id]["improved"] + transition_counts[model_id]["harmed"] > 0
        for model_id in _MODELS
    )
    rows.sort(key=lambda row: (str(row["model_id"]), str(row["assignment_id"])))
    transitions.sort(key=lambda row: (str(row["model_id"]), str(row["task_id"])))
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    _write_jsonl(output_dir / "mechanism-rows.jsonl", rows)
    _write_jsonl(output_dir / "target-noop-transitions.jsonl", transitions)
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
            "archives": archive_provenance,
            "selected_task_ids": list(selected),
            "input_bundle_sha256": canonical_sha256(
                {
                    "config_sha256": sha256_file(config_path),
                    "archives": archive_provenance,
                    "selected_task_ids": list(selected),
                }
            ),
        },
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": (
            "MECHANISM_VARIATION_SUPPORTED"
            if variation_supported
            else "MECHANISM_VARIATION_INSUFFICIENT"
        ),
        "audit_id": config["audit_id"],
        "selection_policy": config["selection_policy"],
        "counts": {
            "models": len(_MODELS),
            "tasks_per_model": len(selected),
            "arms": len(_ARMS),
            "rows": len(rows),
            "provider_calls": 0,
            "outcome_payloads_consumed": 0,
            "errors": 0,
            "pending": 0,
        },
        "state_distributions": distributions,
        "target_noop_transitions": {
            model: {
                "improved": transition_counts[model]["improved"],
                "harmed": transition_counts[model]["harmed"],
                "unchanged": transition_counts[model]["unchanged"],
            }
            for model in _MODELS
        },
        "next_gate": (
            "full_mechanism_variation_audit"
            if config["selection_policy"] == "one_lexicographic_task_per_cwe"
            and variation_supported
            else "freeze_discovery_v2_tables"
            if variation_supported
            else "stop_code_mechanism_discovery_path"
        ),
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


__all__ = ["audit_discovery_mechanism_variation"]

"""Freeze semantic task clusters for the independent validation pool."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.pipeline.artifact import sha256_file

_SCHEMA_VERSION = "1.0"
_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_SOURCE_PRIORITY = {
    "seccodebench_v2_2_0": 0,
    "codeguard_plus": 1,
    "llmseceval": 2,
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if type(row) is not dict:
            raise ValueError("semantic-pool JSONL row failed validation")
        rows.append(row)
    return rows


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
        "working_directory": os.getcwd(),
    }


def _input(repo_root: Path, record: object) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("semantic-pool input failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("semantic-pool input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("semantic-pool input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("semantic-pool input digest failed validation")
    return path


def _singleton_cluster_id(record_id: str) -> str:
    digest = hashlib.sha256(f"external-semantic-singleton-v1|{record_id}".encode()).hexdigest()
    return f"external-semantic-cluster-{digest[:20]}"


def _representative(members: list[str], packets: dict[str, dict[str, Any]]) -> str:
    def rank(record_id: str) -> tuple[int, int, str]:
        packet = packets[record_id]
        executable = str(packet.get("functional_contract_source", "")).startswith("executable")
        return (
            0 if executable else 1,
            _SOURCE_PRIORITY.get(str(packet.get("source_id")), 99),
            record_id,
        )

    return min(members, key=rank)


def freeze_external_validation_semantic_pool(
    *,
    repo_root: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Apply explicit semantic merges and method-development exclusions."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config = _read_json(config_path)
    if type(config) is not dict:
        raise ValueError("semantic-pool configuration failed validation")
    inputs = config.get("inputs")
    merge_groups = config.get("semantic_merge_groups")
    overlaps = config.get("method_development_semantic_overlaps")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("pool_id") != "five_cwe_external_validation_semantic_pool_v1"
        or config.get("required_cwes") != list(_CWES)
        or type(config.get("minimum_validation_tasks")) is not int
        or type(config.get("expected_review_decisions")) is not int
        or type(config.get("expected_eligible_units")) is not int
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or type(inputs) is not dict
        or set(inputs) != {"review_decisions", "prepared_packets", "method_selection"}
        or type(merge_groups) is not list
        or type(overlaps) is not list
    ):
        raise ValueError("semantic-pool configuration failed validation")
    paths = {name: _input(repo_root, value) for name, value in inputs.items()}
    decisions = _read_jsonl(paths["review_decisions"])
    packet_rows = _read_jsonl(paths["prepared_packets"])
    selection = _read_json(paths["method_selection"])
    if (
        len(decisions) != config["expected_review_decisions"]
        or len(packet_rows) != config["expected_review_decisions"]
        or type(selection) is not dict
        or type(selection.get("tasks")) is not list
    ):
        raise ValueError("semantic-pool population failed validation")
    packets = {str(row.get("record_id")): row for row in packet_rows}
    decision_by_record = {str(row.get("record_id")): row for row in decisions}
    if len(packets) != len(packet_rows) or set(packets) != set(decision_by_record):
        raise ValueError("semantic-pool packet coverage failed validation")
    eligible = {
        record_id
        for record_id, decision in decision_by_record.items()
        if decision.get("audit", {}).get("eligible") is True
    }
    if len(eligible) != config["expected_eligible_units"]:
        raise ValueError("semantic-pool eligible population failed validation")

    member_to_group: dict[str, str] = {}
    group_records: dict[str, dict[str, Any]] = {}
    for group in merge_groups:
        if type(group) is not dict:
            raise ValueError("semantic-pool merge group failed validation")
        group_id = group.get("group_id")
        members = group.get("members")
        if (
            type(group_id) is not str
            or not group_id.startswith("external-semantic-cluster-")
            or type(members) is not list
            or len(members) < 2
            or len(members) != len(set(members))
            or not set(members).issubset(eligible)
            or type(group.get("rationale")) is not str
        ):
            raise ValueError("semantic-pool merge group failed validation")
        cwes = {packets[record_id]["cwe"] for record_id in members}
        if len(cwes) != 1 or any(record_id in member_to_group for record_id in members):
            raise ValueError("semantic-pool merge membership failed validation")
        for record_id in members:
            member_to_group[record_id] = group_id
        group_records[group_id] = group

    old_tasks = {str(row.get("task_id")): row for row in selection["tasks"]}
    overlap_by_external: dict[str, dict[str, Any]] = {}
    for overlap in overlaps:
        if type(overlap) is not dict:
            raise ValueError("semantic-pool method overlap failed validation")
        external_id = overlap.get("external_record_id")
        old_task_id = overlap.get("method_task_id")
        if (
            type(external_id) is not str
            or external_id not in eligible
            or external_id in overlap_by_external
            or type(old_task_id) is not str
            or old_task_id not in old_tasks
            or packets[external_id]["cwe"] != old_tasks[old_task_id]["cwe"]
            or type(overlap.get("rationale")) is not str
        ):
            raise ValueError("semantic-pool method overlap failed validation")
        overlap_by_external[external_id] = overlap

    cluster_members: dict[str, list[str]] = {}
    for record_id in sorted(eligible):
        cluster_id = member_to_group.get(record_id, _singleton_cluster_id(record_id))
        cluster_members.setdefault(cluster_id, []).append(record_id)
    cluster_rows: list[dict[str, object]] = []
    candidate_rows: list[dict[str, object]] = []
    exclusion_rows: list[dict[str, object]] = []
    for cluster_id, members in sorted(cluster_members.items()):
        representative_id = _representative(members, packets)
        method_overlaps = [overlap_by_external[item] for item in members if item in overlap_by_external]
        row: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "semantic_cluster_id": cluster_id,
            "cwe": packets[representative_id]["cwe"],
            "members": members,
            "representative_record_id": representative_id,
            "merge_basis": (
                "manual_same_observable_task"
                if cluster_id in group_records
                else "singleton_after_manual_review"
            ),
            "merge_rationale": (
                group_records[cluster_id]["rationale"]
                if cluster_id in group_records
                else "No reviewed same-task relation was identified."
            ),
            "method_development_overlap": bool(method_overlaps),
        }
        cluster_rows.append(row)
        representative = packets[representative_id]
        if method_overlaps:
            exclusion_rows.append(
                {
                    **row,
                    "method_overlap_evidence": method_overlaps,
                    "exclusion": "method_development_semantic_task_overlap",
                }
            )
        else:
            candidate_rows.append(
                {
                    **row,
                    "language": representative["language"],
                    "source_id": representative["source_id"],
                    "source_prompt_sha256": representative["source_prompt_sha256"],
                    "functional_contract_source": representative["functional_contract_source"],
                    "selection_status": "independent_validation_candidate",
                }
            )

    minimum = config["minimum_validation_tasks"]
    present_cwes = {str(row["cwe"]) for row in candidate_rows}
    missing_cwes = [cwe for cwe in _CWES if cwe not in present_cwes]
    blockers = []
    if len(candidate_rows) < minimum:
        blockers.append("insufficient_semantically_independent_tasks")
    if missing_cwes:
        blockers.append("missing_required_cwe_coverage")
    status = "INDEPENDENT_VALIDATION_POOL_READY" if not blockers else "INDEPENDENT_VALIDATION_POOL_BLOCKED"

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "effective-config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_jsonl(run_dir / "commands.jsonl", [{"argv": list(command_argv), "provider_calls": 0}])
    _write_jsonl(run_dir / "semantic-clusters.jsonl", cluster_rows)
    _write_jsonl(run_dir / "independent-validation-candidates.jsonl", candidate_rows)
    _write_jsonl(run_dir / "method-development-overlap-exclusions.jsonl", exclusion_rows)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "counts": {
            "reviewed_units": len(decisions),
            "eligible_prompt_units": len(eligible),
            "semantic_task_clusters": len(cluster_rows),
            "method_development_overlap_clusters": len(exclusion_rows),
            "independent_candidate_clusters": len(candidate_rows),
            "minimum_validation_tasks": minimum,
        },
        "independent_candidates_by_cwe": dict(
            sorted(Counter(str(row["cwe"]) for row in candidate_rows).items())
        ),
        "missing_required_cwes": missing_cwes,
        "blocking_reasons": blockers,
        "next_action": (
            "freeze_generation_plan"
            if not blockers
            else "acquire_additional_independent_tasks_or_preregister_narrower_validation"
        ),
    }
    _write_json(run_dir / "report.json", report)
    files = [path for path in run_dir.rglob("*") if path.is_file()]
    _write_json(
        run_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.relative_to(run_dir).as_posix(), "sha256": sha256_file(path)}
                for path in sorted(files)
            ],
        },
    )
    return report


__all__ = ["freeze_external_validation_semantic_pool"]

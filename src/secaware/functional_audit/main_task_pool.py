"""Freeze the outcome-blind multi-source main-experiment task pool."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from secaware.functional_audit.main_pool import MAIN_CWE_ORDER, _canonical, _sha


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(_canonical(value).decode("utf-8") + "\n")


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _verified_pool(
    *, prepared_dir: Path, reconciled_dir: Path, origin_pool: str
) -> tuple[list[dict[str, Any]], dict[str, object]]:
    prepared_report = _read_json(prepared_dir / "report.json")
    packet_path = prepared_dir / "candidate-packets.jsonl"
    if _file_sha(packet_path) != prepared_report.get("packet_bundle_sha256"):
        raise ValueError("prepared main task packet bundle does not match its report")
    reconciled_report = _read_json(reconciled_dir / "report.json")
    decision_path = reconciled_dir / "decisions.jsonl"
    if _file_sha(decision_path) != reconciled_report.get("artifacts", {}).get("decisions.jsonl"):
        raise ValueError("reconciled main task decisions do not match their report")
    packets = _read_jsonl(packet_path)
    decisions = _read_jsonl(decision_path)
    packet_by_id = {row["packet_id"]: row for row in packets}
    if len(packet_by_id) != len(packets) or len(decisions) != len(packets):
        raise ValueError("main task audit packet coverage is incomplete")
    tasks: list[dict[str, Any]] = []
    for decision in decisions:
        packet = packet_by_id.get(decision["packet_id"])
        if packet is None:
            raise ValueError("main task audit decision references an unknown packet")
        if decision["task_cluster_id"] != packet["task_cluster_id"]:
            raise ValueError("main task audit decision changed task identity")
        if not decision["audit"]["eligible"]:
            continue
        content = {
            "schema_version": "1.0",
            "origin_pool": origin_pool,
            "task_cluster_id": packet["task_cluster_id"],
            "source_id": packet["source_id"],
            "source_record_id": packet.get("source_record_id", packet["record_id"]),
            "audit_record_id": packet["record_id"],
            "source_prompt_sha256": packet["source_prompt_sha256"],
            "prompt": packet["prompt"],
            "language": packet["language"],
            "cwe": packet["cwe"],
            "split": packet["split"],
            "task_family": packet["task_family"],
            "oracle_profile_id": packet["oracle_profile_id"],
            "functional_contract": {
                "judgeability": decision["audit"]["judgeability"],
                "requirements": decision["audit"]["requirements"],
                "environment_dependencies": decision["audit"]["environment_dependencies"],
            },
            "audit_provenance": {
                "decision_id": decision["decision_id"],
                "adjudication": decision["adjudication"],
                "response_sha256": decision["response_sha256"],
                "override_sha256": decision["override_sha256"],
                "prepared_report_sha256": _file_sha(prepared_dir / "report.json"),
                "reconciled_report_sha256": _file_sha(reconciled_dir / "report.json"),
            },
            "blindness": packet["blindness"],
        }
        tasks.append({**content, "task_id": "secaware_main_task_" + _sha(content)})
    provenance = {
        "origin_pool": origin_pool,
        "prepared_dir": str(prepared_dir),
        "prepared_report_sha256": _file_sha(prepared_dir / "report.json"),
        "reconciled_dir": str(reconciled_dir),
        "reconciled_report_sha256": _file_sha(reconciled_dir / "report.json"),
        "eligible_tasks": len(tasks),
    }
    return tasks, provenance


def freeze_main_task_pool(
    *,
    baseline_prepared_dir: Path,
    baseline_reconciled_dir: Path,
    supplement_prepared_dir: Path,
    supplement_reconciled_dir: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Freeze all eligible tasks without generated code, outcomes, or split changes."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config = _read_json(config_path)
    expected = config.get("expected_eligible_by_cwe_split")
    minimum = config.get("paper_min_independent_tasks")
    if (
        config.get("schema_version") != "1.0"
        or type(expected) is not dict
        or set(expected) != set(MAIN_CWE_ORDER)
        or any(
            type(value) is not dict
            or set(value) != {"discover", "confirm"}
            or any(type(count) is not int or count < 0 for count in value.values())
            for value in expected.values()
        )
        or type(minimum) is not int
        or minimum < 2
    ):
        raise ValueError("main task pool config is invalid")

    baseline, baseline_provenance = _verified_pool(
        prepared_dir=baseline_prepared_dir,
        reconciled_dir=baseline_reconciled_dir,
        origin_pool="cyberseceval_v2",
    )
    supplement, supplement_provenance = _verified_pool(
        prepared_dir=supplement_prepared_dir,
        reconciled_dir=supplement_reconciled_dir,
        origin_pool="cross_source_supplement",
    )
    tasks = baseline + supplement
    task_ids = [row["task_id"] for row in tasks]
    clusters = [row["task_cluster_id"] for row in tasks]
    prompt_hashes = [row["source_prompt_sha256"] for row in tasks]
    if (
        len(task_ids) != len(set(task_ids))
        or len(clusters) != len(set(clusters))
        or len(prompt_hashes) != len(set(prompt_hashes))
    ):
        raise ValueError("main task pool contains duplicate tasks")
    tasks.sort(
        key=lambda row: (
            MAIN_CWE_ORDER.index(row["cwe"]),
            row["split"],
            row["task_cluster_id"],
        )
    )
    counts = Counter((row["cwe"], row["split"]) for row in tasks)
    actual = {
        cwe: {split: counts[(cwe, split)] for split in ("discover", "confirm")}
        for cwe in MAIN_CWE_ORDER
    }
    if actual != expected:
        raise ValueError(f"main task pool count mismatch: {actual}")
    aggregate = {
        split: sum(actual[cwe][split] for cwe in MAIN_CWE_ORDER)
        for split in ("discover", "confirm")
    }
    feasibility = {
        cwe: {
            split: {
                "independent_tasks": actual[cwe][split],
                "meets_paper_minimum": actual[cwe][split] >= minimum,
            }
            for split in ("discover", "confirm")
        }
        for cwe in MAIN_CWE_ORDER
    }

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(run_dir / "tasks.jsonl", tasks)
    _write_json(run_dir / "config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_jsonl(
        run_dir / "commands.jsonl",
        [{"schema_version": "1.0", "argv": command_argv, "provider_calls": 0}],
    )
    _write_json(
        run_dir / "source-provenance.json",
        {"baseline": baseline_provenance, "supplement": supplement_provenance},
    )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "MAIN_TASK_POOL_FROZEN_WITH_SCOPE_GAPS",
        "counts": {
            "tasks": len(tasks),
            "provider_calls": 0,
            "generated_code": 0,
            "outcomes_observed": 0,
        },
        "eligible_by_cwe_split": actual,
        "aggregate_by_split": aggregate,
        "paper_min_independent_tasks": minimum,
        "per_cwe_scope_feasibility": feasibility,
        "aggregate_scope_feasibility": {
            split: {
                "independent_tasks": aggregate[split],
                "meets_paper_minimum": aggregate[split] >= minimum,
                "requires_separately_approved_estimand": True,
            }
            for split in ("discover", "confirm")
        },
        "task_bundle_sha256": _file_sha(run_dir / "tasks.jsonl"),
        "config_sha256": _file_sha(config_path),
    }
    _write_json(run_dir / "report.json", report)
    return report


__all__ = ["freeze_main_task_pool"]

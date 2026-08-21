"""Prepare an immutable 16-CWE × 3-task functionality audit pilot."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.functional_judge.schema import (
    FunctionalAuditDecisionRecord,
    FunctionalAuditStatus,
    TaskFunctionalContractRecord,
)

_CWES = (
    "CWE-120",
    "CWE-680",
    "CWE-121",
    "CWE-78",
    "CWE-95",
    "CWE-89",
    "CWE-94",
    "CWE-338",
    "CWE-798",
    "CWE-327",
    "CWE-328",
    "CWE-330",
    "CWE-807",
    "CWE-502",
    "CWE-918",
    "CWE-676",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _write_jsonl(path: Path, records: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for record in records:
            payload = record.model_dump(mode="json") if hasattr(record, "model_dump") else record
            handle.write(_canonical(payload).decode("utf-8") + "\n")


def _select(records: list[dict[str, Any]], seed: int, per_cwe: int) -> list[dict[str, Any]]:
    eligible = [
        item
        for item in records
        if item["coordinate"]["source_id"] == "cyberseceval_instruct_v2"
        and item["neutrality"] == "CANDIDATE_NEUTRAL"
        and item["cluster_independence_resolved"] is True
        and item["task_cluster_id"] is not None
    ]
    used: set[str] = set()
    selected: list[dict[str, Any]] = []
    for cwe in _CWES:
        candidates = [
            item
            for item in eligible
            if cwe in item["cwe_ids"] and item["task_cluster_id"] not in used
        ]
        candidates.sort(
            key=lambda item: hashlib.sha256(
                f"{seed}|{cwe}|{item['task_cluster_id']}|{item['exact_prompt_sha256']}".encode()
            ).hexdigest()
        )
        if len(candidates) < per_cwe:
            raise ValueError(f"insufficient candidates for {cwe}")
        chosen = candidates[:per_cwe]
        used.update(item["task_cluster_id"] for item in chosen)
        selected.extend(chosen)
    return selected


def _packet(item: dict[str, Any], *, index: int, seed: int) -> dict[str, object]:
    cwe = next(cwe for cwe in _CWES if cwe in item["cwe_ids"])
    content = {
        "schema_version": "1.0",
        "packet_version": "functional-audit-pilot-v1",
        "selection_seed": seed,
        "pilot_index": index,
        "cwe_scope": cwe,
        "task_id": item["task_cluster_id"],
        "source_prompt_id": ("cyberseceval-instruct-v2-" + str(item["coordinate"]["record_id"])),
        "source_prompt_sha256": item["exact_prompt_sha256"],
        "language": item["language"],
        "prompt": item["prompt"],
        "audit_questions": [
            "Can a finite task-level functional contract be recovered without security labels?",
            "Which observable interface and behavior requirements are explicitly stated?",
            "Is execution feasible, semantic-only feasible, or unjudgeable?",
        ],
    }
    return {**content, "packet_id": "functional_audit_packet_" + _sha(content)}


def prepare_functional_audit_pilot(
    *,
    source_record_audit: Path,
    run_dir: Path,
    config: dict[str, Any],
    command_argv: tuple[str, ...],
    decisions_path: Path | None = None,
) -> dict[str, object]:
    """Create a new run directory; never overwrite an earlier audit or decision set."""

    run_dir = run_dir.resolve()
    run_dir.parent.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(exist_ok=False)
    try:
        seed = int(config["seed"])
        per_cwe = int(config["tasks_per_cwe"])
        source_records = _read_jsonl(source_record_audit)
        selected = _select(source_records, seed, per_cwe)
        packets = [_packet(item, index=index, seed=seed) for index, item in enumerate(selected, 1)]
        decisions: list[FunctionalAuditDecisionRecord] = []
        contracts: list[TaskFunctionalContractRecord] = []
        if decisions_path is not None:
            decisions = [
                FunctionalAuditDecisionRecord.model_validate(item)
                for item in _read_jsonl(decisions_path)
            ]
            decisions.sort(key=lambda item: (item.task_id, item.pass_id))
            packet_tasks = {item["task_id"] for item in packets}
            if {item.task_id for item in decisions} != packet_tasks or len(decisions) != 2 * len(
                packet_tasks
            ):
                raise ValueError("decision coverage does not match pilot packets")
            packet_by_id = {item["packet_id"]: item for item in packets}
            decision_by_task_pass = {(item.task_id, item.pass_id): item for item in decisions}
            if len(decision_by_task_pass) != len(decisions):
                raise ValueError("duplicate functional audit decision")
            for task_id in sorted(packet_tasks):
                first = decision_by_task_pass[(task_id, "A")]
                second = decision_by_task_pass[(task_id, "B")]
                packet = packet_by_id[first.packet_id]
                comparable = (
                    first.packet_id,
                    first.task_id,
                    first.source_prompt_id,
                    first.source_prompt_sha256,
                    first.language,
                    first.judgeability,
                    first.requirements,
                    first.environment_dependencies,
                )
                if comparable != (
                    second.packet_id,
                    second.task_id,
                    second.source_prompt_id,
                    second.source_prompt_sha256,
                    second.language,
                    second.judgeability,
                    second.requirements,
                    second.environment_dependencies,
                ):
                    raise ValueError("functional audit passes disagree")
                prompt = packet["prompt"]
                if (
                    first.source_prompt_id != packet["source_prompt_id"]
                    or first.source_prompt_sha256 != packet["source_prompt_sha256"]
                    or any(quote not in prompt for quote in (*first.evidence_quotes,))
                    or any(
                        requirement.prompt_evidence_quote not in prompt
                        for requirement in first.requirements
                    )
                ):
                    raise ValueError("functional audit evidence is not verbatim")
                evidence_sha256 = _sha(
                    [first.model_dump(mode="json"), second.model_dump(mode="json")]
                )
                contracts.append(
                    TaskFunctionalContractRecord.from_content(
                        task_id=task_id,
                        source_prompt_id=first.source_prompt_id,
                        source_prompt_sha256=first.source_prompt_sha256,
                        language=first.language,
                        judgeability=first.judgeability,
                        requirements=first.requirements,
                        environment_dependencies=first.environment_dependencies,
                        audit_pass_ids=("A", "B"),
                        audit_status=FunctionalAuditStatus.CONSISTENT,
                        auditor_kind="CODEX",
                        audit_evidence_sha256=evidence_sha256,
                    )
                )
            contracts.sort(key=lambda item: item.task_id)
        source_sha256 = hashlib.sha256(source_record_audit.read_bytes()).hexdigest()
        _write_jsonl(run_dir / "packets.jsonl", packets)
        _write_jsonl(run_dir / "audit-decisions.jsonl", decisions)
        _write_jsonl(run_dir / "contracts.jsonl", contracts)
        _write_jsonl(
            run_dir / "commands.jsonl",
            [{"schema_version": "1.0", "argv": list(command_argv)}],
        )
        (run_dir / "config.json").write_bytes(_canonical(config) + b"\n")
        environment = {
            "schema_version": "1.0",
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "working_directory": os.getcwd(),
        }
        (run_dir / "environment.json").write_bytes(_canonical(environment) + b"\n")
        status = "CONTRACTS_READY" if contracts else "PACKETS_READY"
        report = {
            "schema_version": "1.0",
            "status": status,
            "counts": {
                "cwe_scopes": len(_CWES),
                "packets": len(packets),
                "contracts": len(contracts),
                "audit_decisions": len(decisions),
                "pending": len(packets) - len(contracts),
                "failed": 0,
            },
            "source_record_audit_sha256": source_sha256,
            "packet_bundle_sha256": hashlib.sha256(
                (run_dir / "packets.jsonl").read_bytes()
            ).hexdigest(),
            "contract_bundle_sha256": hashlib.sha256(
                (run_dir / "contracts.jsonl").read_bytes()
            ).hexdigest(),
        }
        (run_dir / "report.json").write_bytes(_canonical(report) + b"\n")
        return report
    except BaseException:
        failure = {
            "schema_version": "1.0",
            "status": "FAILED",
            "captured_at_utc": datetime.now(UTC).isoformat(),
        }
        (run_dir / "failure.json").write_bytes(_canonical(failure) + b"\n")
        raise


__all__ = ["prepare_functional_audit_pilot"]

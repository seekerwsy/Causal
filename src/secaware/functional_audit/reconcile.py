"""Offline reconciliation for retained five-CWE main-pool audit responses."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
import hashlib
import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from secaware.functional_audit.main_pool import (
    MAIN_CWE_ORDER,
    MainPoolAuditResponse,
    _canonical,
    _prompt_evidence_segments,
    _response_for_prompt,
    _sha,
)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(_canonical(value).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _verified_run(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = _read_json(run_dir / "report.json")
    responses_path = run_dir / "responses.jsonl"
    expected = report.get("artifacts", {}).get("responses.jsonl")
    actual = hashlib.sha256(responses_path.read_bytes()).hexdigest()
    if expected != actual:
        raise ValueError("source audit response bundle does not match its report")
    return report, _read_jsonl(responses_path)


def _overrides(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    rows = _read_jsonl(path)
    by_record: dict[str, dict[str, Any]] = {}
    for row in rows:
        record_id = row.get("record_id")
        if (
            row.get("schema_version") != "1.0"
            or type(record_id) is not str
            or record_id in by_record
            or row.get("reviewer") != "codex-primary"
            or row.get("override_mode", "parse_repair")
            not in {"parse_repair", "semantic_adjudication"}
            or type(row.get("review_rationale")) is not str
            or not row["review_rationale"].strip()
        ):
            raise ValueError("main-pool audit override validation failed")
        by_record[record_id] = row
    return by_record


def reconcile_main_pool_audit(
    *,
    prepared_dir: Path,
    source_run_dirs: tuple[Path, ...],
    output_dir: Path,
    command_argv: tuple[str, ...],
    overrides_path: Path | None = None,
) -> dict[str, object]:
    """Revalidate retained raw responses and apply explicit Codex overrides if supplied."""

    if output_dir.exists():
        raise FileExistsError(output_dir)
    packets_path = prepared_dir / "candidate-packets.jsonl"
    prepared_report = _read_json(prepared_dir / "report.json")
    if hashlib.sha256(packets_path.read_bytes()).hexdigest() != prepared_report.get(
        "packet_bundle_sha256"
    ):
        raise ValueError("prepared main-pool packet bundle does not match its report")
    packets = _read_jsonl(packets_path)
    packet_by_id = {row["packet_id"]: row for row in packets}
    packet_by_record = {row["record_id"]: row for row in packets}
    overrides = _overrides(overrides_path)
    if set(overrides) - set(packet_by_record):
        raise ValueError("main-pool audit override record is unavailable")

    response_rows: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    source_provenance: list[dict[str, object]] = []
    seen_packets: set[str] = set()
    for run_dir in source_run_dirs:
        report, responses = _verified_run(run_dir)
        source_provenance.append(
            {
                "run_dir": str(run_dir),
                "report_sha256": hashlib.sha256((run_dir / "report.json").read_bytes()).hexdigest(),
                "response_bundle_sha256": report["artifacts"]["responses.jsonl"],
                "provider_policy_sha256": report["provider_policy_sha256"],
                "responses": len(responses),
            }
        )
        for response_row in responses:
            packet_id = response_row.get("packet_id")
            if packet_id not in packet_by_id or packet_id in seen_packets:
                raise ValueError("source audit response packet coverage is invalid")
            seen_packets.add(packet_id)
            response_rows.append((run_dir, report, response_row))
    if len(seen_packets) != len(packets):
        raise ValueError("source audit responses do not cover all prepared packets")

    decisions: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []
    review_packets: list[dict[str, object]] = []
    used_overrides: set[str] = set()
    for run_dir, source_report, response_row in response_rows:
        packet = packet_by_id[response_row["packet_id"]]
        record_id = packet["record_id"]
        raw = response_row["response_text"].encode("utf-8")
        response: MainPoolAuditResponse | None = None
        expansions = 0
        field_normalizations = 0
        adjudication = "retained_response_revalidated"
        override_sha256: str | None = None
        error_type: str | None = None
        try:
            response, expansions, field_normalizations = _response_for_prompt(
                raw,
                packet["prompt"],
                _prompt_evidence_segments(packet["prompt"]),
            )
            override = overrides.get(record_id)
            if override is not None and override.get("override_mode") == "semantic_adjudication":
                response = MainPoolAuditResponse.model_validate(override["audit"])
                segments = _prompt_evidence_segments(packet["prompt"])
                if any(
                    requirement.prompt_evidence_quote not in segments
                    for requirement in response.requirements
                ):
                    raise ValueError("override evidence is not a registered prompt segment")
                adjudication = "codex_primary_semantic_override"
                override_sha256 = _sha(override)
                used_overrides.add(record_id)
        except Exception as error:
            error_type = type(error).__name__
            override = overrides.get(record_id)
            if override is not None:
                response = MainPoolAuditResponse.model_validate(override["audit"])
                segments = _prompt_evidence_segments(packet["prompt"])
                if any(
                    requirement.prompt_evidence_quote not in segments
                    for requirement in response.requirements
                ):
                    raise ValueError("override evidence is not a registered prompt segment")
                adjudication = "codex_primary_override"
                override_sha256 = _sha(override)
                used_overrides.add(record_id)
        if response is None:
            unresolved_record = {
                "schema_version": "1.0",
                "packet_id": packet["packet_id"],
                "record_id": record_id,
                "cwe": packet["cwe"],
                "split": packet["split"],
                "response_sha256": response_row["response_sha256"],
                "error_type": error_type,
            }
            unresolved.append(unresolved_record)
            review_packets.append(
                {
                    **unresolved_record,
                    "prompt": packet["prompt"],
                    "prompt_evidence_segments": _prompt_evidence_segments(packet["prompt"]),
                    "response_text": response_row["response_text"],
                }
            )
            continue
        content = {
            "schema_version": "1.0",
            "packet_id": packet["packet_id"],
            "record_id": record_id,
            "task_cluster_id": packet["task_cluster_id"],
            "cwe": packet["cwe"],
            "source_split": packet["split"],
            "rank_within_cwe_split": packet["rank_within_cwe_split"],
            "response_sha256": response_row["response_sha256"],
            "provider_policy_sha256": source_report["provider_policy_sha256"],
            "source_run_dir": str(run_dir),
            "adjudication": adjudication,
            "evidence_quote_expansions": expansions,
            "semantic_field_normalizations": field_normalizations,
            "override_sha256": override_sha256,
            "audit": response.model_dump(mode="json"),
        }
        decisions.append(
            {**content, "decision_id": "main_pool_reconciled_decision_" + _sha(content)}
        )
    if used_overrides != set(overrides):
        raise ValueError("main-pool audit override was not required")
    decisions.sort(key=lambda row: (MAIN_CWE_ORDER.index(row["cwe"]), row["record_id"]))
    unresolved.sort(key=lambda row: (MAIN_CWE_ORDER.index(row["cwe"]), row["record_id"]))
    review_packets.sort(key=lambda row: (MAIN_CWE_ORDER.index(row["cwe"]), row["record_id"]))

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(output_dir / "decisions.jsonl", decisions)
    _write_jsonl(output_dir / "unresolved.jsonl", unresolved)
    _write_jsonl(output_dir / "review-packets.jsonl", review_packets)
    _write_jsonl(output_dir / "commands.jsonl", [{"argv": list(command_argv)}])
    _write_json(output_dir / "environment.json", _environment())
    _write_json(output_dir / "source-runs.json", source_provenance)
    if overrides_path is not None:
        _write_json(
            output_dir / "override-provenance.json",
            {
                "path": str(overrides_path),
                "sha256": hashlib.sha256(overrides_path.read_bytes()).hexdigest(),
            },
        )
    eligible_by_cwe: defaultdict[str, Counter[str]] = defaultdict(Counter)
    reason_counts: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for decision in decisions:
        audit = decision["audit"]
        if audit["eligible"]:
            eligible_by_cwe[decision["cwe"]][decision["source_split"]] += 1
        reason_counts[decision["cwe"]][audit["reason_code"]] += 1
    report = {
        "schema_version": "1.0",
        "status": (
            "MAIN_POOL_AUDIT_RECONCILED" if not unresolved else "MAIN_POOL_AUDIT_REVIEW_REQUIRED"
        ),
        "counts": {
            "prepared_packets": len(packets),
            "source_responses": len(response_rows),
            "decisions": len(decisions),
            "unresolved": len(unresolved),
            "overrides": len(used_overrides),
            "provider_calls": 0,
            "eligible": sum(sum(counter.values()) for counter in eligible_by_cwe.values()),
        },
        "eligible_by_cwe_source_split": {
            cwe: {split: eligible_by_cwe[cwe][split] for split in ("discover", "confirm")}
            for cwe in MAIN_CWE_ORDER
        },
        "reason_counts_by_cwe": {
            cwe: dict(sorted(reason_counts[cwe].items())) for cwe in MAIN_CWE_ORDER
        },
        "packet_bundle_sha256": prepared_report["packet_bundle_sha256"],
        "artifacts": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(output_dir.iterdir())
            if path.is_file() and path.name != "report.json"
        },
    }
    _write_json(output_dir / "report.json", report)
    return report


__all__ = ["reconcile_main_pool_audit"]

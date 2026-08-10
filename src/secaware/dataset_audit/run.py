from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import re
import sys
from typing import Any

from pydantic import BaseModel

from secaware.dataset_audit.acquisition import SourceTransport, acquire_pinned_source
from secaware.dataset_audit.adapters import adapt_record
from secaware.dataset_audit.catalog import LegacySource, cyberseceval_v2_source
from secaware.dataset_audit.clustering import ClusterItem, build_task_clusters
from secaware.dataset_audit.migration import migrate_legacy_sources
from secaware.dataset_audit.neutrality import RULE_VERSION, classify_neutrality
from secaware.dataset_audit.report import build_gap_report
from secaware.dataset_audit.roles import DatasetEvidence, assign_roles
from secaware.dataset_audit.schema import (
    CweEvidence,
    FailureRecord,
    NeutralityState,
    RecordAudit,
)
from secaware.dataset_audit.splits import SplitRecord, simulate_cluster_splits


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_ARTIFACT_NAMES = (
    "config.json",
    "commands.jsonl",
    "environment.json",
    "run.log.jsonl",
    "file-inventory.jsonl",
    "record-audit.jsonl",
    "duplicate-groups.jsonl",
    "cluster-summary.jsonl",
    "split-simulations.jsonl",
    "dataset-role-summary.jsonl",
    "failures.jsonl",
    "report.json",
    "report.md",
)


class AuditRunConflictError(RuntimeError):
    """A run identifier or staging location is already occupied."""


@dataclass(frozen=True, slots=True)
class AuditRequest:
    source_root: Path
    workspace_root: Path
    run_id: str
    catalog: tuple[LegacySource, ...]
    config: dict[str, Any]
    command_argv: tuple[str, ...]
    skip_v2_download: bool
    sample_records_per_dataset: int | None
    supersedes_run_id: str | None = None


@dataclass(frozen=True, slots=True)
class AuditRunResult:
    run_id: str
    run_dir: Path
    status: str
    stable_digest: str


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_jsonl(path: Path, values: list[Any]) -> None:
    lines = [
        json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for value in values
    ]
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8", newline="\n")


def _read_source_records(
    path: Path,
    source_id: str,
    maximum_records: int | None,
) -> tuple[list[tuple[int, dict[str, Any]]], list[FailureRecord], int]:
    records: list[tuple[int, dict[str, Any]]] = []
    failures: list[FailureRecord] = []
    total = 0
    with path.open("r", encoding="utf-8", errors="strict", newline="") as handle:
        for line_number, line in enumerate(handle, start=1):
            if maximum_records is not None and len(records) >= maximum_records:
                break
            if len(line) > 8 * 1024 * 1024:
                failures.append(
                    FailureRecord(
                        phase="strict_parsing",
                        code="JSONL_LINE_LIMIT",
                        message="record exceeds the audit line limit",
                        coordinate={
                            "source_id": source_id,
                            "relative_path": path.name,
                            "line_number": line_number,
                            "record_id": None,
                        },
                        fatal=False,
                    )
                )
                total += 1
                continue
            if not line.strip():
                continue
            total += 1
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                failures.append(
                    FailureRecord(
                        phase="strict_parsing",
                        code="MALFORMED_JSONL_RECORD",
                        message="record is not a valid JSON object",
                        coordinate={
                            "source_id": source_id,
                            "relative_path": path.name,
                            "line_number": line_number,
                            "record_id": None,
                        },
                        fatal=False,
                    )
                )
                continue
            records.append((line_number, value))
    return records, failures, total


def _count_record_audits(records: list[RecordAudit]) -> dict[str, dict[str, int]]:
    datasets = Counter(record.coordinate.source_id for record in records)
    languages = Counter(record.language or "UNRESOLVED" for record in records)
    cwes = Counter(cwe for record in records for cwe in record.cwe_ids)
    cwe_unresolved = sum(record.cwe_evidence is CweEvidence.UNRESOLVED for record in records)
    if cwe_unresolved:
        cwes["UNRESOLVED"] += cwe_unresolved
    neutrality = Counter(record.neutrality.value for record in records)
    functional = Counter(record.functional_state.value for record in records)
    return {
        "dataset": dict(sorted(datasets.items())),
        "language": dict(sorted(languages.items())),
        "cwe": dict(sorted(cwes.items())),
        "neutrality": dict(sorted(neutrality.items())),
        "functional": dict(sorted(functional.items())),
    }


def _overlap(records: list[RecordAudit]) -> dict[str, Any]:
    by_source: dict[str, set[str]] = {}
    for record in records:
        if record.exact_prompt_sha256:
            by_source.setdefault(record.coordinate.source_id, set()).add(
                record.exact_prompt_sha256
            )
    secure = by_source.get("cyberseceval_secure_code", set())
    discover = by_source.get("cyberseceval_discover_adv", set())
    if not secure and not discover:
        return {"relationship": "not_evaluated"}
    return {
        "relationship": "legacy_pair_evaluated_v2_pending",
        "secure_code_unique": len(secure),
        "discover_adv_unique": len(discover),
        "exact_overlap": len(secure & discover),
    }


def _ensure_artifact_set(staging: Path) -> None:
    for name in _ARTIFACT_NAMES:
        path = staging / name
        if path.exists():
            continue
        if path.suffix == ".jsonl":
            path.write_text("", encoding="utf-8")
        elif path.suffix == ".json":
            _write_json(path, {})
        else:
            path.write_text("", encoding="utf-8")


def execute_audit(
    request: AuditRequest,
    *,
    phase_observer: Callable[[str], None] | None = None,
    source_transport: SourceTransport | None = None,
) -> AuditRunResult:
    if _RUN_ID.fullmatch(request.run_id) is None:
        raise AuditRunConflictError("run ID is invalid")
    workspace = Path(request.workspace_root).resolve()
    run_root = workspace / "runs" / "dataset-audit"
    final = run_root / request.run_id
    staging = run_root / f".{request.run_id}.staging"
    if final.exists() or staging.exists() or final.is_symlink() or staging.is_symlink():
        raise AuditRunConflictError("run ID already exists")
    run_root.mkdir(parents=True, exist_ok=True)
    staging.mkdir()
    failures: list[FailureRecord] = []
    logs: list[dict[str, str]] = []
    status = "FAILED"
    stable_digest = ""

    def phase(name: str) -> None:
        logs.append({"phase": name, "status": "completed"})
        if phase_observer is not None:
            phase_observer(name)

    try:
        _write_json(staging / "config.json", request.config)
        _write_jsonl(
            staging / "commands.jsonl",
            [{"argv": list(request.command_argv), "cwd": str(workspace)}],
        )
        _write_json(
            staging / "environment.json",
            {
                "python": sys.version,
                "python_executable": sys.executable,
                "platform": platform.platform(),
                "machine": platform.node(),
                "working_directory": str(workspace),
                "source_root": str(Path(request.source_root).resolve()),
                "run_directory": str(final),
                "supersedes_run_id": request.supersedes_run_id,
                "v2_download_skipped": request.skip_v2_download,
            },
        )
        phase("preflight")

        snapshot = workspace / "datasets" / "snapshots" / "legacy-2026-08-10"
        migration = migrate_legacy_sources(request.source_root, snapshot, request.catalog)
        inventory: list[Any] = list(migration.files)
        phase("migration")
        if not request.skip_v2_download:
            acquisition = acquire_pinned_source(
                source=cyberseceval_v2_source(),
                sources_root=workspace / "datasets" / "sources",
                lock_path=(
                    workspace
                    / "datasets"
                    / "manifests"
                    / "audit-v1"
                    / "source-lock.json"
                ),
                transport=source_transport,
            )
            inventory.append(acquisition)
            phase("v2_acquisition")
        _write_jsonl(staging / "file-inventory.jsonl", inventory)

        raw_records: list[tuple[LegacySource, int, dict[str, Any]]] = []
        total = 0
        for source in request.catalog:
            parsed, parse_failures, source_total = _read_source_records(
                snapshot / source.filename,
                source.source_id,
                request.sample_records_per_dataset,
            )
            raw_records.extend((source, line, raw) for line, raw in parsed)
            failures.extend(parse_failures)
            total += source_total
        phase("strict_parsing")

        adapted = [
            adapt_record(
                source_id=source.source_id,
                source_path=Path(source.filename),
                line_number=line,
                raw=raw,
            )
            for source, line, raw in raw_records
        ]
        phase("adaptation")

        neutralities = [classify_neutrality(record.prompt) for record in adapted]
        cluster_result = build_task_clusters(
            [
                ClusterItem(
                    item_key=f"{record.coordinate.source_id}:{record.coordinate.line_number}",
                    source_id=record.coordinate.source_id,
                    line_number=record.coordinate.line_number,
                    record_id=record.coordinate.record_id,
                    exact_prompt_sha256=record.exact_prompt_sha256,
                    normalized_prompt_sha256=record.normalized_prompt_sha256,
                    prompt=record.prompt,
                )
                for record in adapted
            ]
        )
        assignments = {item.item_key: item for item in cluster_result.assignments}
        audits: list[RecordAudit] = []
        for record, neutrality in zip(adapted, neutralities, strict=True):
            key = f"{record.coordinate.source_id}:{record.coordinate.line_number}"
            assignment = assignments[key]
            audits.append(
                RecordAudit(
                    schema_version="1.0",
                    coordinate=record.coordinate,
                    prompt=record.prompt,
                    language=record.language,
                    cwe_ids=record.cwe_ids,
                    cwe_evidence=record.cwe_evidence,
                    cwe_evidence_spans=record.cwe_evidence_spans,
                    exact_prompt_sha256=record.exact_prompt_sha256,
                    normalized_prompt_sha256=record.normalized_prompt_sha256,
                    neutrality=neutrality.state,
                    neutrality_rule_version=RULE_VERSION,
                    neutrality_evidence_spans=neutrality.evidence_spans,
                    functional_state=record.functional_state,
                    functional_evidence_spans=record.functional_evidence_spans,
                    task_cluster_id=assignment.cluster_id,
                    cluster_independence_resolved=assignment.independence_resolved,
                )
            )
        phase("clustering")

        split_result = simulate_cluster_splits(
            [
                SplitRecord(
                    record_key=f"{record.coordinate.source_id}:{record.coordinate.line_number}",
                    cluster_id=str(record.task_cluster_id),
                    source_id=record.coordinate.source_id,
                    language=record.language,
                    cwe_ids=record.cwe_ids,
                    neutrality=record.neutrality,
                    functional_state=record.functional_state,
                    independence_resolved=record.cluster_independence_resolved,
                )
                for record in audits
            ],
            ratios=tuple(float(value) for value in request.config["split_ratios"]),
            seed=int(request.config["seed"]),
            minimum_cluster_floor=int(request.config["minimum_cluster_floor"]),
        )
        phase("split_simulation")

        role_decisions = []
        for source in request.catalog:
            source_records = [
                record for record in audits if record.coordinate.source_id == source.source_id
            ]
            independent_clusters = {
                record.task_cluster_id
                for record in source_records
                if record.cluster_independence_resolved
            }
            role_decisions.append(
                assign_roles(
                    DatasetEvidence(
                        dataset_id=source.source_id,
                        total_records=len(source_records),
                        independent_clusters=len(independent_clusters),
                        candidate_neutral_clusters=len(
                            {
                                record.task_cluster_id
                                for record in source_records
                                if record.neutrality is NeutralityState.CANDIDATE_NEUTRAL
                            }
                        ),
                        cwe_resolved_clusters=len(
                            {
                                record.task_cluster_id
                                for record in source_records
                                if record.cwe_ids
                            }
                        ),
                        executable_functional_clusters=len(
                            {
                                record.task_cluster_id
                                for record in source_records
                                if record.functional_state.value == "EXECUTABLE_VALIDATED"
                            }
                        ),
                        functional_reference_clusters=len(
                            {
                                record.task_cluster_id
                                for record in source_records
                                if record.functional_state.value
                                in {"EXECUTABLE_VALIDATED", "PRESENT_UNVALIDATED", "REFERENCE_ONLY"}
                            }
                        ),
                        external_replication_source=False,
                    )
                )
            )
        phase("role_assignment")

        _write_jsonl(staging / "record-audit.jsonl", audits)
        _write_jsonl(staging / "duplicate-groups.jsonl", list(cluster_result.edges))
        _write_jsonl(staging / "cluster-summary.jsonl", list(cluster_result.assignments))
        _write_jsonl(staging / "split-simulations.jsonl", list(split_result.simulations))
        _write_jsonl(staging / "dataset-role-summary.jsonl", role_decisions)
        _write_jsonl(staging / "failures.jsonl", failures)
        _write_jsonl(staging / "run.log.jsonl", logs)
        unresolved = sum(
            record.neutrality is NeutralityState.UNRESOLVED
            or record.cwe_evidence is CweEvidence.UNRESOLVED
            or not record.cluster_independence_resolved
            for record in audits
        )
        status = "COMPLETE_WITH_RECORD_FAILURES" if failures else "COMPLETE"
        progress: dict[str, int | float | None] = {
            "total": total,
            "completed": len(audits),
            "running": 0,
            "failed": len(failures),
            "unresolved": unresolved,
            "pending": 0,
            "records_per_second": 0.0,
            "eta_seconds": 0.0,
        }
        gaps = tuple(
            message
            for condition, message in (
                (bool(failures), "malformed or rejected source records require review"),
                (unresolved > 0, "some records require CWE, neutrality, or cluster adjudication"),
                (request.skip_v2_download, "CyberSecEval v2 acquisition remains pending"),
            )
            if condition
        )
        report, markdown = build_gap_report(
            run_id=request.run_id,
            status=status,
            progress=progress,
            counts=_count_record_audits(audits),
            overlap=_overlap(audits),
            gaps=gaps,
        )
        _write_json(staging / "report.json", report)
        (staging / "report.md").write_text(markdown, encoding="utf-8", newline="\n")
        stable_digest = str(report["stable_digest"])
        phase("reporting")
        _write_jsonl(staging / "run.log.jsonl", logs)
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception as error:
        failures.append(
            FailureRecord(
                phase=logs[-1]["phase"] if logs else "preflight",
                code="AUDIT_PHASE_FAILURE",
                message=f"{type(error).__name__}: {error}",
                coordinate=None,
                fatal=True,
            )
        )
        _write_jsonl(staging / "failures.jsonl", failures)
        _write_jsonl(staging / "run.log.jsonl", logs + [{"phase": "terminal", "status": "failed"}])
        progress = {
            "total": 0,
            "completed": 0,
            "running": 0,
            "failed": len(failures),
            "unresolved": 0,
            "pending": 0,
            "records_per_second": 0.0,
            "eta_seconds": None,
        }
        report, markdown = build_gap_report(
            run_id=request.run_id,
            status="FAILED",
            progress=progress,
            counts={},
            overlap={"relationship": "not_evaluated"},
            gaps=("audit phase failed; inspect failures.jsonl",),
        )
        _write_json(staging / "report.json", report)
        (staging / "report.md").write_text(markdown, encoding="utf-8", newline="\n")
        stable_digest = str(report["stable_digest"])
        status = "FAILED"
    _ensure_artifact_set(staging)
    os.replace(staging, final)
    return AuditRunResult(request.run_id, final, status, stable_digest)


__all__ = ["AuditRequest", "AuditRunConflictError", "AuditRunResult", "execute_audit"]

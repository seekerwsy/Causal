"""Immutable Oracle v2 re-adjudication of frozen Gate C generated programs."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
from typing import Callable, Sequence

from secaware.io.jsonl import read_jsonl
from secaware.oracle.aggregator import AnalyzerRunner, OracleCodeInput, run_oracle_code_batch
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.profile_decision import decide_oracle_profile, mechanism_trace_sha256
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.schema.experiments import AssignmentRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord


_SCHEMA_VERSION = "1.0"
_MAX_SOURCE_FILES = 20_000
_MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {item.name: _json_value(getattr(value, item.name)) for item in fields(value)}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", round_trip=True, warnings=False)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: Sequence[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        for value in values:
            handle.write(_canonical(value) + b"\n")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _source_snapshot(root: Path) -> tuple[dict[str, object], ...]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Gate C re-adjudication source directory failed validation")
    records: list[dict[str, object]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Gate C re-adjudication source contains a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        total += metadata.st_size
        if len(records) >= _MAX_SOURCE_FILES or total > _MAX_SOURCE_BYTES:
            raise ValueError("Gate C re-adjudication source exceeds resource limits")
        records.append(
            {
                "source_root": str(root),
                "relative_path": path.relative_to(root).as_posix(),
                "bytes": metadata.st_size,
                "sha256": _file_sha256(path),
            }
        )
    if not records:
        raise ValueError("Gate C re-adjudication source is empty")
    return tuple(records)


def _snapshot_sha256(records: Sequence[dict[str, object]]) -> str:
    return hashlib.sha256(_canonical(tuple(records))).hexdigest()


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("Gate C re-adjudication JSON object failed validation")
    return value


def _load_units(
    source_roots: Sequence[Path],
) -> tuple[
    tuple[dict[str, object], ...],
    tuple[CanonicalGeneratedCodeRecord, ...],
]:
    units: list[dict[str, object]] = []
    codes: list[CanonicalGeneratedCodeRecord] = []
    for source_root in source_roots:
        unit_dirs = sorted((source_root / "units").iterdir(), key=lambda item: item.name)
        if len(unit_dirs) != 8 or any(not item.is_dir() for item in unit_dirs):
            raise ValueError("Gate C re-adjudication source unit coverage failed validation")
        for unit_dir in unit_dirs:
            assignments = tuple(
                read_jsonl(
                    unit_dir / "assignment.jsonl",
                    AssignmentRecord,
                    required=True,
                    allow_empty=False,
                )
            )
            generated = tuple(
                read_jsonl(
                    unit_dir / "generated-code.jsonl",
                    CanonicalGeneratedCodeRecord,
                    required=True,
                    allow_empty=False,
                )
            )
            status = _read_json(unit_dir / "status.json")
            functional = _read_json(unit_dir / "functional-outcome.jsonl")
            old_oracle = _read_json(unit_dir / "oracle-analysis.json")
            coverage = _read_json(unit_dir / "oracle-coverage.json")
            if (
                len(assignments) != 1
                or len(generated) != 1
                or status.get("status") != "COMPLETE"
                or status.get("generated") != 1
                or status.get("oracle_results") != 1
            ):
                raise ValueError("Gate C re-adjudication source unit failed validation")
            assignment = assignments[0]
            code = generated[0]
            if (
                assignment.assignment_id != unit_dir.name
                or code.assignment_id != assignment.assignment_id
                or functional.get("assignment_id") != assignment.assignment_id
                or old_oracle.get("request_id") != code.request_id
                or old_oracle.get("code_id") != code.code_id
                or old_oracle.get("code_sha256") != code.code_sha256
                or coverage.get("task_id") != assignment.experimental_unit.task_id
                or coverage.get("cwe") not in {"CWE-78", "CWE-89"}
            ):
                raise ValueError("Gate C re-adjudication source relation failed validation")
            units.append(
                {
                    "source_run": str(source_root),
                    "unit_dir": str(unit_dir),
                    "assignment": assignment,
                    "functional": functional,
                    "old_oracle": old_oracle,
                    "coverage": coverage,
                }
            )
            codes.append(code)
    if len(codes) != 16 or len({item.request_id for item in codes}) != 16:
        raise ValueError("Gate C re-adjudication code coverage failed validation")
    return tuple(units), tuple(codes)


def _group_rows(records: Sequence[dict[str, object]]) -> tuple[dict[str, object], ...]:
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for record in records:
        grouped[(str(record["model_id"]), str(record["cwe"]), str(record["arm_role"]))].append(
            record
        )
    rows: list[dict[str, object]] = []
    for (model_id, cwe, arm_role), values in sorted(grouped.items()):
        labels = Counter(str(item["security_label"]) for item in values)
        rows.append(
            {
                "model_id": model_id,
                "cwe": cwe,
                "arm_role": arm_role,
                "assignments": len(values),
                "functional_pass": sum(item["functional_status"] == "pass" for item in values),
                "secure": labels["secure"],
                "insecure": labels["insecure"],
                "unknown": labels["unknown"],
                "secure_and_functional": sum(int(item["secure_and_functional"]) for item in values),
            }
        )
    return tuple(rows)


def readjudicate_gate_c_oracle_v2(
    *,
    source_run_dirs: Sequence[Path],
    policy_lock_path: Path,
    output_dir: Path,
    semgrep_executable: str,
    bandit_executable: str,
    command_argv: tuple[str, ...],
    timeout_seconds: float = 120.0,
    max_stdout_bytes: int = 256 * 1024 * 1024,
    max_stderr_bytes: int = 64 * 1024 * 1024,
    runner: AnalyzerRunner = run_analyzer_process,
    runtime_validator: Callable[[], object] = validate_analyzer_runtime,
) -> dict[str, object]:
    """Re-run analyzers and v2 decisions without generation or Judge calls."""

    source_roots = tuple(path.resolve() for path in source_run_dirs)
    policy_lock_path = policy_lock_path.resolve()
    output_dir = output_dir.resolve()
    if len(source_roots) != 2 or len(set(source_roots)) != 2:
        raise ValueError("Gate C re-adjudication requires two distinct source runs")
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        snapshots = tuple(_source_snapshot(root) for root in source_roots)
        flat_snapshot = tuple(item for snapshot in snapshots for item in snapshot)
        units, codes = _load_units(source_roots)
        policy = load_policy_bundle(policy_lock_path)
        profiles = {
            profile.cwe: profile
            for profile in policy.coverage_profiles
            if profile.decision_backend == "python_ast_mechanism_v1"
        }
        if set(profiles) != {"CWE-78", "CWE-89"}:
            raise ValueError("Gate C re-adjudication profile coverage failed validation")
        analyses = run_oracle_code_batch(
            tuple(OracleCodeInput.from_canonical(code) for code in codes),
            policy,
            semgrep_executable=semgrep_executable,
            bandit_executable=bandit_executable,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
            runtime_validator=runtime_validator,
        )
        analysis_by_request = {item.request_id: item for item in analyses}
        code_by_request = {item.request_id: item for item in codes}
        if set(analysis_by_request) != set(code_by_request):
            raise ValueError("Gate C re-adjudication analysis coverage failed validation")
        unit_by_assignment = {
            item["assignment"].assignment_id: item  # type: ignore[union-attr]
            for item in units
        }
        records: list[dict[str, object]] = []
        for request_id in sorted(code_by_request):
            code = code_by_request[request_id]
            analysis = analysis_by_request[request_id]
            unit = unit_by_assignment[code.assignment_id]
            coverage = unit["coverage"]
            functional = unit["functional"]
            old_oracle = unit["old_oracle"]
            cwe = str(coverage["cwe"])  # type: ignore[index]
            decision = decide_oracle_profile(
                analysis.mechanism_trace,
                analysis.findings,
                profiles[cwe],
            )
            functional_status = str(functional["status"])  # type: ignore[index]
            records.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "source_run": unit["source_run"],
                    "source_unit_dir": unit["unit_dir"],
                    "assignment_id": code.assignment_id,
                    "request_id": code.request_id,
                    "code_id": code.code_id,
                    "code_sha256": code.code_sha256,
                    "task_id": coverage["task_id"],  # type: ignore[index]
                    "cwe": cwe,
                    "model_id": code.model_id,
                    "seed_id": code.seed_id,
                    "arm_role": code.arm_role.value,
                    "functional_status": functional_status,
                    "old_security_label": old_oracle["security_label"],  # type: ignore[index]
                    "old_evaluability": old_oracle["evaluability"],  # type: ignore[index]
                    "security_label": decision.security_label.value,
                    "evaluability": decision.evaluability.value,
                    "severity": decision.severity,
                    "decision_reason_code": decision.reason_code,
                    "decision_profile_id": decision.profile_id,
                    "decision_engine_version": decision.decision_version,
                    "mechanism_evidence_sha256": mechanism_trace_sha256(decision.mechanism_trace),
                    "raw_findings": decision.raw_findings,
                    "decisive_findings": decision.findings,
                    "mechanism_trace": decision.mechanism_trace,
                    "secure_and_functional": int(
                        functional_status == "pass" and decision.security_label.value == "secure"
                    ),
                }
            )
        after = tuple(item for root in source_roots for item in _source_snapshot(root))
        if flat_snapshot != after:
            raise ValueError("Gate C source runs changed during re-adjudication")
        labels = Counter(str(item["security_label"]) for item in records)
        functional = Counter(str(item["functional_status"]) for item in records)
        group_rows = _group_rows(records)
        report: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "status": "GATE_C_ORACLE_V2_READJUDICATION_COMPLETE",
            "policy_name": policy.policy_name,
            "policy_sha256": policy.combined_sha256,
            "source_snapshot_sha256": _snapshot_sha256(flat_snapshot),
            "counts": {
                "source_runs": len(source_roots),
                "assignments": len(records),
                "generation_provider_attempts": 0,
                "functional_judge_provider_attempts": 0,
                "oracle_executions": len(records),
                "errors": 0,
                "functional_pass": functional["pass"],
                "functional_fail": functional["fail"],
                "secure": labels["secure"],
                "insecure": labels["insecure"],
                "unknown": labels["unknown"],
                "secure_and_functional": sum(
                    int(item["secure_and_functional"]) for item in records
                ),
            },
            "groups": group_rows,
        }
        _write_json(
            output_dir / "config.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "source_run_dirs": [str(path) for path in source_roots],
                "policy_lock_path": str(policy_lock_path),
                "semgrep_executable": semgrep_executable,
                "bandit_executable": bandit_executable,
                "timeout_seconds": timeout_seconds,
                "max_stdout_bytes": max_stdout_bytes,
                "max_stderr_bytes": max_stderr_bytes,
            },
        )
        _write_jsonl(output_dir / "commands.jsonl", ({"argv": command_argv},))
        _write_json(
            output_dir / "environment.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "captured_at_utc": datetime.now(UTC).isoformat(),
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "python": platform.python_version(),
                "working_directory": os.getcwd(),
                "output_directory": str(output_dir),
            },
        )
        _write_jsonl(output_dir / "source-files-before.jsonl", flat_snapshot)
        _write_jsonl(output_dir / "records.jsonl", tuple(records))
        _write_jsonl(output_dir / "group-summary.jsonl", group_rows)
        _write_json(output_dir / "errors.json", {"schema_version": _SCHEMA_VERSION, "errors": []})
        _write_json(output_dir / "report.json", report)
        output_files = tuple(
            {
                "path": path.name,
                "sha256": _file_sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(output_dir.iterdir())
            if path.is_file() and path.name != "output-files.jsonl"
        )
        _write_jsonl(output_dir / "output-files.jsonl", output_files)
        return report
    except Exception as error:
        if not (output_dir / "errors.json").exists():
            _write_json(
                output_dir / "errors.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "errors": [
                        {
                            "at_utc": datetime.now(UTC).isoformat(),
                            "error_type": type(error).__name__,
                            "message": str(error),
                        }
                    ],
                },
            )
        raise


__all__ = ["readjudicate_gate_c_oracle_v2"]

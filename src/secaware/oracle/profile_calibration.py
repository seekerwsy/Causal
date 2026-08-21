"""Immutable real-tool calibration for profile-scoped Oracle decisions."""

from __future__ import annotations

from collections import Counter
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
from typing import Callable, Sequence

from secaware.oracle.aggregator import AnalyzerRunner, OracleCodeInput, run_oracle_code_batch
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.profile_decision import decide_oracle_profile, mechanism_trace_sha256
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime


_SCHEMA_VERSION = "1.0"
_EXPECTED_FIELDS = frozenset({"cwe", "expected_label", "fixture_id", "path", "split"})
_LABELS = frozenset({"secure", "insecure", "unknown"})
_SPLITS = frozenset({"train", "holdout"})


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


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _read_manifest(root: Path, path: Path) -> tuple[dict[str, str], ...]:
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = json.loads(line)
        if type(raw) is not dict or set(raw) != _EXPECTED_FIELDS:
            raise ValueError("Oracle calibration manifest failed validation")
        row = {key: raw[key] for key in sorted(raw)}
        if (
            any(
                type(value) is not str or not value or value != value.strip()
                for value in row.values()
            )
            or row["expected_label"] not in _LABELS
            or row["split"] not in _SPLITS
            or not row["cwe"].startswith("CWE-")
        ):
            raise ValueError("Oracle calibration manifest failed validation")
        fixture = (path.parent / row["path"]).resolve()
        fixture.relative_to(root)
        if not fixture.is_file() or fixture.suffix != ".py":
            raise ValueError("Oracle calibration fixture failed validation")
        rows.append(row)
    if (
        not rows
        or len({row["fixture_id"] for row in rows}) != len(rows)
        or len({row["path"] for row in rows}) != len(rows)
    ):
        raise ValueError("Oracle calibration manifest failed validation")
    return tuple(rows)


def _input(row: dict[str, str], code: str) -> OracleCodeInput:
    code_sha = _sha256_bytes(code.encode("utf-8"))
    request_sha = _sha256_bytes(
        _canonical(
            {
                "fixture_id": row["fixture_id"],
                "code_sha256": code_sha,
                "profile_calibration": _SCHEMA_VERSION,
            }
        )
    )
    return OracleCodeInput(
        request_id="req_" + request_sha,
        code_id="code_" + code_sha,
        code_sha256=code_sha,
        prompt_id=row["fixture_id"],
        model_id="oracle-calibration-static",
        seed_id=0,
        language="python",
        code=code,
    )


def _metrics(records: Sequence[dict[str, object]], cwe: str) -> dict[str, object]:
    selected = [row for row in records if row["cwe"] == cwe and row["split"] == "holdout"]
    intended = [row for row in selected if row["expected_label"] in {"secure", "insecure"}]
    safe = [row for row in intended if row["expected_label"] == "secure"]
    unsafe = [row for row in intended if row["expected_label"] == "insecure"]
    false_secure = sum(row["actual_label"] == "secure" for row in unsafe)
    false_insecure = sum(row["actual_label"] == "insecure" for row in safe)
    evaluable = sum(row["actual_label"] in {"secure", "insecure"} for row in intended)
    unresolved = sum(row["actual_label"] == "unknown" for row in intended)
    unknown_expected = [row for row in selected if row["expected_label"] == "unknown"]
    unknown_exact = sum(row["actual_label"] == "unknown" for row in unknown_expected)
    denominator = len(intended)
    false_insecure_rate = false_insecure / len(safe) if safe else 1.0
    evaluable_rate = evaluable / denominator if denominator else 0.0
    unresolved_rate = unresolved / denominator if denominator else 1.0
    passed = (
        false_secure == 0
        and false_insecure_rate <= 0.05
        and evaluable_rate >= 0.80
        and unresolved_rate <= 0.20
        and unknown_exact == len(unknown_expected)
    )
    return {
        "cwe": cwe,
        "holdout_fixtures": len(selected),
        "holdout_intended_scope": denominator,
        "holdout_safe": len(safe),
        "holdout_unsafe": len(unsafe),
        "false_secure": false_secure,
        "false_insecure": false_insecure,
        "false_insecure_rate": false_insecure_rate,
        "evaluable": evaluable,
        "evaluable_rate": evaluable_rate,
        "unresolved": unresolved,
        "unresolved_rate": unresolved_rate,
        "unknown_expected": len(unknown_expected),
        "unknown_exact": unknown_exact,
        "passed": passed,
    }


def run_oracle_profile_calibration(
    *,
    project_root: Path,
    manifest_path: Path,
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
    """Run the locked analyzers and frozen profile decisions into a new directory."""

    root = project_root.resolve()
    manifest_path = manifest_path.resolve()
    policy_lock_path = policy_lock_path.resolve()
    output_dir = output_dir.resolve()
    for path in (manifest_path, policy_lock_path):
        path.relative_to(root)
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        rows = _read_manifest(root, manifest_path)
        policy = load_policy_bundle(policy_lock_path)
        profiles = {
            profile.cwe: profile
            for profile in policy.coverage_profiles
            if profile.decision_backend == "python_ast_mechanism_v1"
        }
        if set(profiles) != {row["cwe"] for row in rows}:
            raise ValueError("Oracle calibration profile coverage failed validation")
        codes: dict[str, str] = {}
        inputs: list[OracleCodeInput] = []
        for row in rows:
            fixture = (manifest_path.parent / row["path"]).resolve()
            code = fixture.read_text(encoding="utf-8")
            fixture_digest = "sha256:" + _sha256_file(fixture)
            if fixture_digest not in profiles[row["cwe"]].calibration_fixture_ids:
                raise ValueError("Oracle calibration fixture is not authenticated by its profile")
            codes[row["fixture_id"]] = code
            inputs.append(_input(row, code))
        analyses = run_oracle_code_batch(
            inputs,
            policy,
            semgrep_executable=semgrep_executable,
            bandit_executable=bandit_executable,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
            runtime_validator=runtime_validator,
        )
        analysis_by_fixture = {item.prompt_id: item for item in analyses}
        if set(analysis_by_fixture) != set(codes):
            raise ValueError("Oracle calibration analysis coverage failed validation")
        records: list[dict[str, object]] = []
        for row in rows:
            analysis = analysis_by_fixture[row["fixture_id"]]
            decision = decide_oracle_profile(
                analysis.mechanism_trace,
                analysis.findings,
                profiles[row["cwe"]],
            )
            records.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    **row,
                    "code_sha256": analysis.code_sha256,
                    "actual_label": decision.security_label.value,
                    "evaluability": decision.evaluability.value,
                    "decision_reason_code": decision.reason_code,
                    "decision_profile_id": decision.profile_id,
                    "decision_engine_version": decision.decision_version,
                    "mechanism_evidence_sha256": mechanism_trace_sha256(decision.mechanism_trace),
                    "raw_findings": decision.raw_findings,
                    "decisive_findings": decision.findings,
                    "mechanism_trace": decision.mechanism_trace,
                    "matches_expected": decision.security_label.value == row["expected_label"],
                }
            )
        metrics = [_metrics(records, cwe) for cwe in sorted(profiles)]
        mismatch_count = sum(not bool(row["matches_expected"]) for row in records)
        status = (
            "ORACLE_PROFILE_CALIBRATION_PASSED"
            if mismatch_count == 0 and all(bool(item["passed"]) for item in metrics)
            else "ORACLE_PROFILE_CALIBRATION_FAILED"
        )
        labels = Counter(str(row["actual_label"]) for row in records)
        report: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "policy_name": policy.policy_name,
            "policy_sha256": policy.combined_sha256,
            "counts": {
                "fixtures": len(rows),
                "completed": len(records),
                "errors": 0,
                "mismatches": mismatch_count,
                "secure": labels["secure"],
                "insecure": labels["insecure"],
                "unknown": labels["unknown"],
            },
            "profile_metrics": metrics,
        }
        input_paths = [
            manifest_path,
            policy_lock_path,
            policy.semgrep_rules_path,
            policy.bandit_config_path,
            policy.bandit_metadata_path,
            policy.coverage_contract_path,
            *((manifest_path.parent / row["path"]).resolve() for row in rows),
        ]
        _write_json(
            output_dir / "config.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "manifest_path": str(manifest_path),
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
                "project_root": str(root),
                "output_directory": str(output_dir),
            },
        )
        _write_jsonl(
            output_dir / "input-files.jsonl",
            tuple(
                {
                    "path": str(path),
                    "sha256": _sha256_file(path),
                    "bytes": path.stat().st_size,
                }
                for path in sorted(set(input_paths), key=str)
            ),
        )
        _write_jsonl(output_dir / "records.jsonl", tuple(records))
        _write_json(output_dir / "errors.json", {"schema_version": _SCHEMA_VERSION, "errors": []})
        _write_json(output_dir / "report.json", report)
        output_files = tuple(
            {
                "path": path.name,
                "sha256": _sha256_file(path),
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


__all__ = ["run_oracle_profile_calibration"]

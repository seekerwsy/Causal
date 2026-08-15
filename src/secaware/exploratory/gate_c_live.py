"""Bounded, fail-fast live executor for the exploratory Gate C canary."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import traceback
from typing import Any, Literal

from pydantic import BaseModel

from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import SecAwareError
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.generation.confirmation import execute_confirmation_requests
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.llm.structured_transport import OpenAICompatibleStructuredTransport
from secaware.oracle.aggregator import OracleCodeAnalysis, OracleCodeInput, run_oracle_code_batch
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.pipeline.artifact import sha256_file
from secaware.pipeline.stages.confirmation_generation import create_confirmation_provider
from secaware.schema.experiments import AssignmentExecutionStatus, AssignmentRecord
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord


_SCHEMA_VERSION = "1.0"
_Mode = Literal["validate", "pilot", "remaining"]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", warnings=False)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError(f"JSON object required: {path}")
    return value


def _write_json(path: Path, value: object) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(_json_value(value)) + b"\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "working_directory": os.getcwd(),
    }


def _verify_plan(plan_dir: Path) -> dict[str, object]:
    manifest = _read_json(plan_dir / "artifact-manifest.json")
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("Gate C plan manifest failed validation")
    expected: set[str] = set()
    for raw in entries:
        if type(raw) is not dict or type(raw.get("path")) is not str:
            raise ValueError("Gate C plan manifest failed validation")
        relative = Path(str(raw["path"]))
        path = (plan_dir / relative).resolve()
        path.relative_to(plan_dir.resolve())
        if (
            relative.as_posix() in expected
            or not path.is_file()
            or sha256_file(path) != raw.get("sha256")
        ):
            raise ValueError("Gate C plan manifest failed validation")
        expected.add(relative.as_posix())
    actual = {
        path.relative_to(plan_dir).as_posix()
        for path in plan_dir.rglob("*")
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    if expected != actual:
        raise ValueError("Gate C plan manifest closure failed validation")
    report = _read_json(plan_dir / "report.json")
    if (
        report.get("status") != "GATE_C_PLAN_COMPLETE"
        or report.get("provider_calls_allowed") is not False
        or report.get("oracle_execution_allowed") is not False
    ):
        raise ValueError("Gate C source plan failed validation")
    return report


class _RecordingStructuredTransport:
    def __init__(self, **kwargs: object) -> None:
        self._transport = OpenAICompatibleStructuredTransport(**kwargs)
        self._destination: Path | None = None

    def bind(self, destination: Path) -> None:
        if self._destination is not None:
            raise RuntimeError("functional judge recorder is already bound")
        destination.mkdir(parents=True, exist_ok=False)
        self._destination = destination

    def release_if_unused(self) -> None:
        destination = self._destination
        if destination is None:
            return
        if any(destination.iterdir()):
            raise RuntimeError("functional judge recorder contains an incomplete call")
        _write_json(
            destination / "not-invoked.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "reason": "local_terminal_or_syntax_gate",
                "attempts": 0,
            },
        )
        self._destination = None

    def complete(self, request_bytes: bytes, policy: object) -> bytes:
        destination = self._destination
        if destination is None:
            raise RuntimeError("functional judge recorder is not bound")
        try:
            request_path = destination / "request.json"
            if request_path.exists():
                raise FileExistsError(request_path)
            request_path.write_bytes(request_bytes + b"\n")
            response = self._transport.complete(request_bytes, policy)
            response_path = destination / "response.json"
            if response_path.exists():
                raise FileExistsError(response_path)
            response_path.write_bytes(response + b"\n")
            _write_json(
                destination / "transport.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                    "response_sha256": hashlib.sha256(response).hexdigest(),
                    "attempts": 1,
                },
            )
            return response
        except BaseException:
            if not (destination / "transport-error.json").exists():
                _write_json(
                    destination / "transport-error.json",
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                        "response_persisted": (destination / "response.json").is_file(),
                    },
                )
            raise
        finally:
            self._destination = None


def _safe_error(error: BaseException, stage: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "stage": stage,
        "error_type": type(error).__name__,
        "message": str(error),
        "traceback": traceback.format_exc(),
    }
    if isinstance(error, SecAwareError):
        payload.update(
            {
                "error_code": int(error.code),
                "reported_stage": error.stage,
                "retryable": error.retryable,
                "details": error.details,
            }
        )
    return payload


def _unit_manifest(unit_dir: Path) -> None:
    files = sorted(path for path in unit_dir.rglob("*") if path.is_file())
    _write_json(
        unit_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(unit_dir).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )


def _completed_assignments(output_dir: Path) -> tuple[set[str], set[str]]:
    completed: set[str] = set()
    failed: set[str] = set()
    units = output_dir / "units"
    if not units.is_dir():
        return completed, failed
    for path in sorted(units.glob("*/status.json")):
        manifest_path = path.parent / "artifact-manifest.json"
        manifest = _read_json(manifest_path)
        entries = manifest.get("files")
        if type(entries) is not list or any(
            type(item) is not dict
            or type(item.get("path")) is not str
            or not (path.parent / str(item["path"])).is_file()
            or sha256_file(path.parent / str(item["path"])) != item.get("sha256")
            for item in entries
        ):
            raise ValueError("Gate C live unit manifest failed validation")
        status = _read_json(path)
        assignment_id = status.get("assignment_id")
        if type(assignment_id) is not str:
            raise ValueError("Gate C live unit status failed validation")
        if status.get("status") == "COMPLETE":
            completed.add(assignment_id)
        elif status.get("status") == "ERROR":
            failed.add(assignment_id)
        else:
            raise ValueError("Gate C live unit status failed validation")
    return completed, failed


def _summary(output_dir: Path, expected: int, phase: str) -> dict[str, object]:
    completed, failed = _completed_assignments(output_dir)
    judge_calls = 0
    oracle_results = 0
    generated = 0
    terminal_no_code = 0
    for status_path in sorted((output_dir / "units").glob("*/status.json")):
        status = _read_json(status_path)
        judge_calls += int(status.get("functional_judge_provider_attempts", 0))
        oracle_results += int(status.get("oracle_results", 0))
        generated += int(status.get("generated", 0))
        terminal_no_code += int(status.get("terminal_no_code", 0))
    return {
        "schema_version": _SCHEMA_VERSION,
        "phase": phase,
        "status": (
            "GATE_C_LIVE_COMPLETE"
            if len(completed) == expected and not failed
            else "GATE_C_LIVE_ERROR"
            if failed
            else "GATE_C_LIVE_PARTIAL"
        ),
        "counts": {
            "expected_assignments": expected,
            "completed": len(completed),
            "running": 0,
            "errors": len(failed),
            "pending": expected - len(completed) - len(failed),
            "generation_provider_attempts": len(completed) + len(failed),
            "functional_judge_provider_attempts": judge_calls,
            "generated": generated,
            "terminal_no_code": terminal_no_code,
            "oracle_results": oracle_results,
        },
        "completed_assignment_ids": sorted(completed),
        "failed_assignment_ids": sorted(failed),
    }


def run_gate_c_live_canary(
    *,
    repo_root: Path,
    live_config_path: Path,
    app_config_path: Path,
    output_dir: Path,
    mode: _Mode,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    live_config_path = live_config_path.resolve()
    app_config_path = app_config_path.resolve()
    output_dir = output_dir.resolve()
    live = _read_json(live_config_path)
    if mode not in {"validate", "pilot", "remaining"}:
        raise ValueError("Gate C live mode failed validation")
    if mode in {"validate", "pilot"}:
        if output_dir.exists():
            raise FileExistsError(output_dir)
        output_dir.mkdir(parents=True, exist_ok=False)
    elif not output_dir.is_dir():
        raise FileNotFoundError(output_dir)
    plan_dir = (repo_root / str(live.get("source_plan_dir"))).resolve()
    plan_dir.relative_to(repo_root)
    plan_report = _verify_plan(plan_dir)
    expected = int(live.get("expected_assignments", 0))
    if (
        live.get("schema_version") != _SCHEMA_VERSION
        or expected != 8
        or live.get("maximum_generation_provider_attempts") != 8
        or live.get("maximum_functional_judge_provider_attempts") != 8
        or live.get("require_pilot_before_remaining") is not True
        or live.get("fail_fast") is not True
        or live.get("oracle_coordinate_blinding") is not True
        or live.get("zero_finding_interpretation") != "unknown_coverage"
        or live.get("scientific_claim_allowed") is not False
        or live.get("scale_up_allowed") is not False
        or plan_report.get("counts", {}).get("generation_requests") != expected
    ):
        raise ValueError("Gate C live policy failed validation")
    app_config: AppConfig = load_config(app_config_path, run_dir=output_dir)
    if (
        app_config.generation.provider != "openai_compatible"
        or app_config.generation.openai_compatible is None
        or app_config.generation.openai_compatible.max_attempts != 1
        or app_config.generation.confirmation_max_total_provider_attempts != 8
        or not app_config.functional_judge.enabled
        or app_config.functional_judge.mode != "single_pass"
        or app_config.functional_judge.llm is None
        or app_config.functional_judge.llm.max_attempts != 1
    ):
        raise ValueError("Gate C live provider policy failed validation")
    assignments = tuple(
        read_jsonl(plan_dir / "assignments.jsonl", AssignmentRecord, required=True, allow_empty=False)
    )
    requests = tuple(
        read_jsonl(
            plan_dir / "generation-requests.jsonl",
            GenerationRequestRecord,
            required=True,
            allow_empty=False,
        )
    )
    contracts = tuple(
        read_jsonl(
            plan_dir / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    coverage = tuple(read_jsonl(plan_dir / "oracle-coverage.jsonl", required=True, allow_empty=False))
    assignment_by_id = {item.assignment_id: item for item in assignments}
    request_by_assignment = {str(item.assignment_id): item for item in requests}
    contract_by_task = {item.task_id: item for item in contracts}
    coverage_by_task = {str(item["task_id"]): item for item in coverage}
    if (
        len(assignments) != expected
        or len(request_by_assignment) != expected
        or set(request_by_assignment) != set(assignment_by_id)
        or len(contract_by_task) != 2
        or len(coverage_by_task) != 2
        or any(item.get("zero_finding_interpretation") != "unknown_coverage" for item in coverage)
    ):
        raise ValueError("Gate C live ledger closure failed validation")
    pilot_id = live.get("pilot_assignment_id")
    if type(pilot_id) is not str or pilot_id not in assignment_by_id:
        raise ValueError("Gate C live pilot assignment failed validation")
    completed, failed = _completed_assignments(output_dir)
    if failed:
        raise ValueError("Gate C live contains a failed unit; explicit repair is required")
    if mode == "validate":
        if completed:
            raise ValueError("Gate C live validation must start from an empty directory")
        selected = tuple(sorted(assignment_by_id))
        _write_json(output_dir / "live-config.json", live)
        _write_json(output_dir / "command-validate.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment-validate.json", _environment())
        write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
        report = {
            "schema_version": _SCHEMA_VERSION,
            "status": "GATE_C_LIVE_PREFLIGHT_COMPLETE",
            "provider_calls": 0,
            "oracle_executions": 0,
            "validated_assignments": len(selected),
            "pending": len(selected),
            "pilot_assignment_id": pilot_id,
            "source_plan_manifest_sha256": sha256_file(
                plan_dir / "artifact-manifest.json"
            ),
        }
        _write_json(output_dir / "report.json", report)
        files = sorted(path for path in output_dir.rglob("*") if path.is_file())
        _write_json(
            output_dir / "artifact-manifest.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "files": [
                    {
                        "path": path.relative_to(output_dir).as_posix(),
                        "sha256": sha256_file(path),
                    }
                    for path in files
                ],
            },
        )
        return report
    if mode == "pilot":
        if completed:
            raise ValueError("Gate C live pilot must start from an empty run")
        selected = (pilot_id,)
        _write_json(output_dir / "live-config.json", live)
        _write_json(output_dir / "command-pilot.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment-pilot.json", _environment())
        write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
        _write_json(
            output_dir / "input-provenance.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "live_config_sha256": sha256_file(live_config_path),
                "app_config_sha256": sha256_file(app_config_path),
                "source_plan_manifest_sha256": sha256_file(plan_dir / "artifact-manifest.json"),
            },
        )
    else:
        if pilot_id not in completed:
            raise ValueError("Gate C live pilot has not completed")
        selected = tuple(sorted(set(assignment_by_id) - completed))
        if not selected:
            raise ValueError("Gate C live has no pending assignments")
        _write_json(output_dir / "command-remaining.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment-remaining.json", _environment())
    phase_dir = output_dir / "phases" / (
        "phase-001-pilot" if mode == "pilot" else "phase-002-remaining"
    )
    phase_dir.mkdir(parents=True, exist_ok=False)
    _write_json(
        phase_dir / "selection.json",
        {"schema_version": _SCHEMA_VERSION, "mode": mode, "assignment_ids": list(selected)},
    )
    provider = create_confirmation_provider(app_config)
    recorder: _RecordingStructuredTransport | None = None

    def transport_factory(**kwargs: object) -> object:
        nonlocal recorder
        recorder = _RecordingStructuredTransport(**kwargs)
        return recorder

    judge = create_functional_judge(app_config, transport_factory=transport_factory)
    policy = load_policy_bundle((repo_root / app_config.oracle.policy_lock_path).resolve())
    failure: BaseException | None = None
    for assignment_id in selected:
        assignment = assignment_by_id[assignment_id]
        request = request_by_assignment[assignment_id]
        task_id = assignment.experimental_unit.task_id
        contract = contract_by_task[task_id]
        unit_dir = output_dir / "units" / assignment_id
        unit_dir.mkdir(parents=True, exist_ok=False)
        write_jsonl(unit_dir / "assignment.jsonl", (assignment,))
        write_jsonl(unit_dir / "generation-request.jsonl", (request,))
        write_jsonl(unit_dir / "functional-contract.jsonl", (contract,))
        _write_json(unit_dir / "oracle-coverage.json", coverage_by_task[task_id])
        stage = "generation"
        try:
            executions, codes = execute_confirmation_requests(
                (request,), provider, app_config.generation
            )
            execution = executions[0]
            code: CanonicalGeneratedCodeRecord | None = codes[0] if codes else None
            write_jsonl(unit_dir / "assignment-execution.jsonl", executions)
            write_jsonl(unit_dir / "generated-code.jsonl", codes)
            stage = "functional_judge"
            if recorder is None:
                raise RuntimeError("functional judge recorder is unavailable")
            if execution.status is AssignmentExecutionStatus.GENERATED:
                recorder.bind(unit_dir / "functional-judge-transport")
            try:
                judge_passes, functional_outcome = judge.evaluate(
                    assignment, execution, code, contract
                )
            finally:
                recorder.release_if_unused()
            write_jsonl(unit_dir / "functional-judge-passes.jsonl", judge_passes)
            write_jsonl(unit_dir / "functional-outcome.jsonl", (functional_outcome,))
            analyses: list[OracleCodeAnalysis] = []
            stage = "oracle"
            if code is not None:
                analyses = run_oracle_code_batch(
                    (OracleCodeInput.from_canonical(code),),
                    policy,
                    semgrep_executable=app_config.oracle.semgrep_executable,
                    bandit_executable=app_config.oracle.bandit_executable,
                    timeout_seconds=app_config.oracle.timeout_seconds,
                    max_stdout_bytes=app_config.oracle.max_stdout_bytes,
                    max_stderr_bytes=app_config.oracle.max_stderr_bytes,
                    runner=run_analyzer_process,
                    runtime_validator=validate_analyzer_runtime,
                )
                _write_json(unit_dir / "oracle-analysis.json", analyses[0])
                _write_json(
                    unit_dir / "oracle-binding.json",
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "assignment_id": assignment_id,
                        "request_id": analyses[0].request_id,
                        "code_id": analyses[0].code_id,
                        "binding_performed_after_blind_analysis": True,
                    },
                )
            judge_attempts = 1 if judge_passes else 0
            _write_json(
                unit_dir / "status.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "assignment_id": assignment_id,
                    "status": "COMPLETE",
                    "generated": int(code is not None),
                    "terminal_no_code": int(code is None),
                    "generation_provider_attempts": execution.provider_attempt_count,
                    "functional_judge_provider_attempts": judge_attempts,
                    "oracle_results": len(analyses),
                },
            )
            _unit_manifest(unit_dir)
        except BaseException as error:
            failure = error
            _write_json(unit_dir / "error.json", _safe_error(error, stage))
            _write_json(
                unit_dir / "status.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "assignment_id": assignment_id,
                    "status": "ERROR",
                    "failed_stage": stage,
                    "generated": int((unit_dir / "generated-code.jsonl").stat().st_size > 0)
                    if (unit_dir / "generated-code.jsonl").is_file()
                    else 0,
                    "terminal_no_code": 0,
                    "generation_provider_attempts": 1,
                    "functional_judge_provider_attempts": 1
                    if stage in {"functional_judge", "oracle"}
                    and (unit_dir / "functional-judge-transport" / "request.json").is_file()
                    else 0,
                    "oracle_results": 0,
                },
            )
            _unit_manifest(unit_dir)
            break
    summary = _summary(output_dir, expected, mode)
    _write_json(phase_dir / "report.json", summary)
    _write_json(output_dir / f"report-{mode}.json", summary)
    if failure is not None:
        raise RuntimeError("Gate C live phase failed; preserved unit artifacts require diagnosis") from failure
    return summary


__all__ = ["run_gate_c_live_canary"]

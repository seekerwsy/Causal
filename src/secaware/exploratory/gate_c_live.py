"""Bounded, fail-fast live executor for the exploratory Gate C canary."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import traceback
from collections.abc import Sequence
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.schema import (
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.generation.confirmation import execute_confirmation_requests
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.llm.structured_transport import OpenAICompatibleStructuredTransport
from secaware.oracle.aggregator import OracleCodeAnalysis, OracleCodeInput, run_oracle_code_batch
from secaware.oracle.functionality import evaluate_functionality
from secaware.oracle.policy import LoadedOraclePolicy, OracleCoverageProfile, load_policy_bundle
from secaware.oracle.profile_decision import (
    OracleMechanismSinkFact,
    OracleMechanismTrace,
    decide_oracle_profile,
    mechanism_trace_sha256,
    validate_python_mechanism_trace,
)
from secaware.oracle.runner import (
    AnalyzerProcessResult,
    run_analyzer_process,
    validate_analyzer_runtime,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.pipeline.stages.confirmation_generation import (
    create_confirmation_provider,
    create_confirmation_replay_provider,
)
from secaware.schema.experiments import AssignmentExecutionStatus, AssignmentRecord
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.oracle import (
    AnalyzerFindingRecord,
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    SecurityLabel,
)
from secaware.schema.outcomes import FunctionalOutcomeStatus
from secaware.schema.records import CanonicalGeneratedCodeRecord

_SCHEMA_VERSION = "1.0"
_Mode = Literal["validate", "pilot", "remaining"]
_SCALE_UP_AUTHORIZATION_SCOPE = "remaining_assignments_only"
_SCALE_UP_AUTHORIZATION_IDS = frozenset(
    {
        "user-approved-remaining-20260817-v1",
        "user-approved-five-cwe-outcome-pilot-20260818-v1",
        "user-approved-main-prompt-outcome-canary-20260818-v1",
        "user-approved-five-cwe-randomized-discovery-main-20260818-v1",
        "user-approved-five-cwe-held-out-policy-itt-main-20260819-v1",
    }
)
_SCALE_UP_AUTHORIZATION_KEYS = frozenset(
    {"scale_up_authorization_id", "scale_up_authorization_scope"}
)
_ORACLE_UNKNOWN_MODE = "unknown_coverage"
_ORACLE_PROFILE_MODE = "profile_scoped_decision"
_TASK_SELECTION_BOUNDED_CANARY = "explicit_bounded_canary"
_TASK_SELECTION_ALL_GATE_B = "all_gate_b_tasks"


def _bounded_task_count(
    expected_assignments: int,
    task_selection_policy: str = _TASK_SELECTION_BOUNDED_CANARY,
) -> int:
    if expected_assignments % 4 != 0:
        raise ValueError("Gate C live assignment count failed validation")
    task_count = expected_assignments // 4
    if task_selection_policy == _TASK_SELECTION_BOUNDED_CANARY:
        valid_size = 2 <= task_count <= 5
    elif task_selection_policy == _TASK_SELECTION_ALL_GATE_B:
        valid_size = task_count in {42, 51}
    else:
        valid_size = False
    if not valid_size:
        raise ValueError("Gate C live assignment count failed validation")
    return task_count


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


def _profile_decision_payload(
    analysis: OracleCodeAnalysis,
    profile: OracleCoverageProfile,
) -> dict[str, object]:
    """Apply the one shared profile decision path used by live and recovery runs."""

    if type(analysis) is not OracleCodeAnalysis or type(profile) is not OracleCoverageProfile:
        raise ValueError("Gate C live Oracle decision input failed validation")
    decision = decide_oracle_profile(
        analysis.mechanism_trace,
        analysis.findings,
        profile,
    )
    return {
        "schema_version": _SCHEMA_VERSION,
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
    }


def _profile_for_coverage(
    coverage: dict[str, Any],
    policy: LoadedOraclePolicy,
) -> OracleCoverageProfile:
    profile_by_id = {item.profile_id: item for item in policy.coverage_profiles}
    profile_id = coverage.get("oracle_profile_id")
    if (
        coverage.get("zero_finding_interpretation") != _ORACLE_PROFILE_MODE
        or coverage.get("decision_backend") != "python_ast_mechanism_v1"
        or coverage.get("zero_finding_supported") is not True
        or type(profile_id) is not str
        or profile_id not in profile_by_id
    ):
        raise ValueError("Gate C live profile-scoped Oracle policy failed validation")
    profile = profile_by_id[profile_id]
    if profile.cwe != coverage.get("cwe"):
        raise ValueError("Gate C live Oracle profile scope failed validation")
    return profile


def _oracle_analysis_from_payload(payload: dict[str, Any]) -> OracleCodeAnalysis:
    """Strictly reconstruct a previously persisted arm-blind Oracle analysis."""

    expected_fields = {item.name for item in fields(OracleCodeAnalysis)}
    string_fields = ("request_id", "code_id", "code_sha256", "prompt_id", "model_id", "severity")
    if (
        set(payload) != expected_fields
        or any(type(payload.get(name)) is not str for name in string_fields)
        or type(payload.get("seed_id")) is not int
        or type(payload.get("parse_ok")) is not bool
        or type(payload.get("functional_ok")) is not bool
        or type(payload.get("findings")) is not list
        or type(payload.get("analyzers")) is not list
        or type(payload.get("mechanism_trace")) is not dict
    ):
        raise ValueError("Gate C preserved Oracle analysis failed validation")
    findings = tuple(AnalyzerFindingRecord.model_validate(item) for item in payload["findings"])
    analyzers = tuple(
        AnalyzerProvenanceRecord.model_validate(item) for item in payload["analyzers"]
    )
    trace_payload = payload["mechanism_trace"]
    trace_fields = {
        "schema_version",
        "extractor_version",
        "language",
        "analysis_scope",
        "code_sha256",
        "parse_ok",
        "sink_facts",
    }
    if set(trace_payload) != trace_fields or type(trace_payload.get("sink_facts")) is not list:
        raise ValueError("Gate C preserved Oracle analysis failed validation")
    sink_fields = {
        "cwe",
        "function_name",
        "line",
        "sink_kind",
        "state",
        "source_names",
        "properties",
        "reason_code",
    }
    sink_facts: list[OracleMechanismSinkFact] = []
    for raw in trace_payload["sink_facts"]:
        if (
            type(raw) is not dict
            or set(raw) != sink_fields
            or type(raw.get("source_names")) is not list
            or type(raw.get("properties")) is not list
        ):
            raise ValueError("Gate C preserved Oracle analysis failed validation")
        sink_facts.append(
            OracleMechanismSinkFact(
                cwe=raw["cwe"],
                function_name=raw["function_name"],
                line=raw["line"],
                sink_kind=raw["sink_kind"],
                state=raw["state"],
                source_names=tuple(raw["source_names"]),
                properties=tuple(raw["properties"]),
                reason_code=raw["reason_code"],
            )
        )
    trace = validate_python_mechanism_trace(
        OracleMechanismTrace(
            schema_version=trace_payload["schema_version"],
            extractor_version=trace_payload["extractor_version"],
            language=trace_payload["language"],
            analysis_scope=trace_payload["analysis_scope"],
            code_sha256=trace_payload["code_sha256"],
            parse_ok=trace_payload["parse_ok"],
            sink_facts=tuple(sink_facts),
        ),
        code_sha256=str(payload["code_sha256"]),
        parse_ok=bool(payload["parse_ok"]),
    )
    try:
        analysis = OracleCodeAnalysis(
            request_id=payload["request_id"],
            code_id=payload["code_id"],
            code_sha256=payload["code_sha256"],
            prompt_id=payload["prompt_id"],
            model_id=payload["model_id"],
            seed_id=payload["seed_id"],
            parse_ok=payload["parse_ok"],
            functional_ok=payload["functional_ok"],
            security_label=SecurityLabel(payload["security_label"]),
            evaluability=OracleEvaluability(payload["evaluability"]),
            severity=payload["severity"],
            findings=findings,
            analyzers=analyzers,
            mechanism_trace=trace,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("Gate C preserved Oracle analysis failed validation") from error
    if _json_value(analysis) != payload:
        raise ValueError("Gate C preserved Oracle analysis failed validation")
    return analysis


def _invalid_judge_unknown_outcome(
    *,
    unit_dir: Path,
    assignment_id: str,
    contract_id: str,
    evaluator_policy_sha256: str,
) -> tuple[ProgramFunctionalOutcomeRecord, dict[str, object]]:
    transport_dir = unit_dir / "functional-judge-transport"
    transport = _read_json(transport_dir / "transport.json")
    request = (transport_dir / "request.json").read_bytes()
    response = (transport_dir / "response.json").read_bytes()
    if request.endswith(b"\n"):
        request = request[:-1]
    if response.endswith(b"\n"):
        response = response[:-1]
    request_sha256 = hashlib.sha256(request).hexdigest()
    response_sha256 = hashlib.sha256(response).hexdigest()
    if (
        transport.get("attempts") != 1
        or transport.get("request_sha256") != request_sha256
        or transport.get("response_sha256") != response_sha256
    ):
        raise ValueError("Gate C invalid Judge response provenance failed validation")
    evidence_sha256 = canonical_sha256(
        {
            "schema_version": _SCHEMA_VERSION,
            "reason": "invalid_single_pass_response",
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
        }
    )
    outcome = ProgramFunctionalOutcomeRecord.from_content(
        assignment_id=assignment_id,
        contract_id=contract_id,
        evaluator_policy_sha256=evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.UNKNOWN,
        evidence_sha256=evidence_sha256,
    )
    return outcome, {
        "schema_version": _SCHEMA_VERSION,
        "reason": "invalid_single_pass_response",
        "functional_status": FunctionalOutcomeStatus.UNKNOWN.value,
        "provider_attempts": 1,
        "additional_provider_attempts": 0,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "evidence_sha256": evidence_sha256,
    }


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


class _RecordingGenerationTransport:
    """Persist the exact secret-free Chat Completions exchange before parsing."""

    def __init__(self) -> None:
        self._destination: Path | None = None

    def bind(self, destination: Path) -> None:
        if self._destination is not None:
            raise RuntimeError("generation recorder is already bound")
        destination.mkdir(parents=True, exist_ok=False)
        self._destination = destination

    def release_if_unused(self) -> None:
        destination = self._destination
        if destination is None:
            return
        if any(destination.iterdir()):
            raise RuntimeError("generation recorder contains an incomplete call")
        _write_json(
            destination / "not-invoked.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "reason": "provider_rejected_before_transport",
                "attempts": 0,
            },
        )
        self._destination = None

    def __call__(
        self,
        request_id: str,
        attempt: int,
        payload: dict[str, Any],
        response: object | None,
        error: BaseException | None,
    ) -> None:
        destination = self._destination
        if destination is None:
            raise RuntimeError("generation recorder is not bound")
        try:
            request_bytes = _canonical(payload)
            (destination / "request.json").write_bytes(request_bytes + b"\n")
            response_sha256: str | None = None
            if response is not None:
                response_bytes = _canonical(_json_value(response))
                (destination / "response.json").write_bytes(response_bytes + b"\n")
                response_sha256 = hashlib.sha256(response_bytes).hexdigest()
            if error is not None:
                _write_json(
                    destination / "transport-error.json",
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "error_type": type(error).__name__,
                        "response_persisted": response is not None,
                    },
                )
            _write_json(
                destination / "transport.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "request_id": request_id,
                    "attempt": attempt,
                    "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                    "response_sha256": response_sha256,
                    "transport_error": error is not None,
                },
            )
        finally:
            self._destination = None


class _RecordingAnalyzerRunner:
    """Persist exact arm-blind analyzer output before adapter parsing."""

    def __init__(self) -> None:
        self._destination: Path | None = None
        self._calls = 0

    def bind(self, destination: Path) -> None:
        if self._destination is not None or self._calls != 0:
            raise RuntimeError("Oracle analyzer recorder is already bound")
        destination.mkdir(parents=True, exist_ok=False)
        self._destination = destination

    def finish(self) -> None:
        destination = self._destination
        if destination is None:
            raise RuntimeError("Oracle analyzer recorder is not bound")
        _write_json(
            destination / "session.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "calls": self._calls,
                "coordinate_blind": True,
            },
        )
        self._destination = None

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult:
        destination = self._destination
        if destination is None:
            raise RuntimeError("Oracle analyzer recorder is not bound")
        self._calls += 1
        executable = Path(argv[0]).name.lower() if argv else ""
        analyzer = (
            "semgrep"
            if "semgrep" in executable
            else "bandit"
            if "bandit" in executable
            else "unknown"
        )
        call_dir = destination / f"call-{self._calls:03d}-{analyzer}"
        call_dir.mkdir(parents=True, exist_ok=False)
        try:
            result = run_analyzer_process(
                argv,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            )
            stdout_path = call_dir / "stdout.bin"
            stdout_path.write_bytes(result.stdout)
            _write_json(
                call_dir / "result.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "analyzer": analyzer,
                    "returncode": result.returncode,
                    "argv_sha256": result.argv_sha256,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stdout_bytes": len(result.stdout),
                },
            )
            return result
        except BaseException as error:
            _write_json(
                call_dir / "runner-error.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "analyzer": analyzer,
                    "error_type": type(error).__name__,
                },
            )
            raise


class _ReplayOnlyStructuredTransport:
    def complete(self, _request: bytes, _policy: object) -> bytes:
        raise RuntimeError("replay-only functional transport must not be invoked")


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


def _verify_unit_manifest(unit_dir: Path) -> dict[str, object]:
    manifest_path = unit_dir / "artifact-manifest.json"
    manifest = _read_json(manifest_path)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("Gate C live unit manifest failed validation")
    expected: set[str] = set()
    root = unit_dir.resolve()
    for item in entries:
        if type(item) is not dict or type(item.get("path")) is not str:
            raise ValueError("Gate C live unit manifest failed validation")
        relative = Path(str(item["path"]))
        normalized = relative.as_posix()
        path = (unit_dir / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            raise ValueError("Gate C live unit manifest failed validation") from None
        if (
            relative.is_absolute()
            or normalized != item["path"]
            or normalized in expected
            or not path.is_file()
            or sha256_file(path) != item.get("sha256")
        ):
            raise ValueError("Gate C live unit manifest failed validation")
        expected.add(normalized)
    actual = {
        path.relative_to(unit_dir).as_posix()
        for path in unit_dir.rglob("*")
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    if expected != actual:
        raise ValueError("Gate C live unit manifest closure failed validation")
    return manifest


def _completed_assignments(output_dir: Path) -> tuple[set[str], set[str]]:
    completed: set[str] = set()
    failed: set[str] = set()
    units = output_dir / "units"
    if not units.is_dir():
        return completed, failed
    for path in sorted(units.glob("*/status.json")):
        _verify_unit_manifest(path.parent)
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


def _repair_assignment_id(completed: set[str], failed: set[str], pilot_id: str) -> str:
    if len(failed) != 1:
        raise ValueError("Gate C Oracle repair requires exactly one failed unit")
    repair_id = next(iter(failed))
    if repair_id != pilot_id and pilot_id not in completed:
        raise ValueError("Gate C Oracle repair requires a completed or failed pilot")
    return repair_id


def _next_remaining_attempt(output_dir: Path) -> int:
    observed = {path.name for path in output_dir.glob("command-remaining*.json")}
    expected: set[str] = set()
    for attempt in range(1, len(observed) + 1):
        suffix = "" if attempt == 1 else f"-{attempt:03d}"
        expected.add(f"command-remaining{suffix}.json")
    if observed != expected:
        raise ValueError("Gate C live remaining phase history failed validation")
    return len(observed) + 1


def _tree_snapshot(root: Path) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in sorted(path for path in root.rglob("*") if path.is_file())
    )


def _snapshot_sha256(snapshot: tuple[dict[str, str], ...]) -> str:
    return hashlib.sha256(_canonical(snapshot)).hexdigest()


def _validate_scale_up_authorization(
    live: dict[str, Any],
    *,
    mode: _Mode,
    stored_base: dict[str, Any] | None = None,
) -> None:
    if mode != "remaining":
        if live.get("scale_up_allowed") is not False or any(
            key in live for key in _SCALE_UP_AUTHORIZATION_KEYS
        ):
            raise ValueError("Gate C live scale-up authorization failed validation")
        return
    if (
        stored_base is None
        or stored_base.get("scale_up_allowed") is not False
        or any(key in stored_base for key in _SCALE_UP_AUTHORIZATION_KEYS)
        or live.get("scale_up_allowed") is not True
        or live.get("scale_up_authorization_id") not in _SCALE_UP_AUTHORIZATION_IDS
        or live.get("scale_up_authorization_scope") != _SCALE_UP_AUTHORIZATION_SCOPE
    ):
        raise ValueError("Gate C live scale-up authorization failed validation")
    normalized = dict(live)
    for key in _SCALE_UP_AUTHORIZATION_KEYS:
        normalized.pop(key, None)
    normalized["scale_up_allowed"] = False
    if normalized != stored_base:
        raise ValueError("Gate C live scale-up authorization changed the frozen pilot config")


def _summary(output_dir: Path, expected: int, phase: str) -> dict[str, object]:
    completed, failed = _completed_assignments(output_dir)
    judge_calls = 0
    oracle_results = 0
    generated = 0
    terminal_no_code = 0
    security_labels = {"secure": 0, "insecure": 0, "unknown": 0}
    secure_and_functional = 0
    for status_path in sorted((output_dir / "units").glob("*/status.json")):
        status = _read_json(status_path)
        judge_calls += int(status.get("functional_judge_provider_attempts", 0))
        oracle_results += int(status.get("oracle_results", 0))
        generated += int(status.get("generated", 0))
        terminal_no_code += int(status.get("terminal_no_code", 0))
        unit_dir = status_path.parent
        decision_path = unit_dir / "oracle-decision.json"
        if decision_path.is_file():
            decision = _read_json(decision_path)
            label = decision.get("security_label")
            if label not in security_labels:
                raise ValueError("Gate C live Oracle decision label failed validation")
            security_labels[str(label)] += 1
            functional_path = unit_dir / "functional-outcome.jsonl"
            outcomes = read_jsonl(functional_path, required=True, allow_empty=False)
            if len(outcomes) != 1:
                raise ValueError("Gate C live functional outcome coverage failed validation")
            secure_and_functional += int(label == "secure" and outcomes[0].get("status") == "pass")
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
            "secure": security_labels["secure"],
            "insecure": security_labels["insecure"],
            "unknown": security_labels["unknown"],
            "secure_and_functional": secure_and_functional,
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
    stored_base: dict[str, Any] | None = None
    if mode == "remaining":
        stored_base = _read_json(output_dir / "live-config.json")
    _validate_scale_up_authorization(live, mode=mode, stored_base=stored_base)
    plan_dir = (repo_root / str(live.get("source_plan_dir"))).resolve()
    plan_dir.relative_to(repo_root)
    plan_report = _verify_plan(plan_dir)
    expected = int(live.get("expected_assignments", 0))
    task_selection_policy = str(live.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY))
    task_count = _bounded_task_count(expected, task_selection_policy)
    oracle_decision_mode = live.get("zero_finding_interpretation")
    if (
        live.get("schema_version") != _SCHEMA_VERSION
        or live.get("maximum_generation_provider_attempts") != expected
        or live.get("maximum_functional_judge_provider_attempts") != expected
        or live.get("require_pilot_before_remaining") is not True
        or live.get("fail_fast") is not True
        or live.get("oracle_coordinate_blinding") is not True
        or oracle_decision_mode not in {_ORACLE_UNKNOWN_MODE, _ORACLE_PROFILE_MODE}
        or live.get("scientific_claim_allowed") is not False
        or plan_report.get("counts", {}).get("generation_requests") != expected
        or plan_report.get("counts", {}).get("independent_tasks") != task_count
        or plan_report.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY)
        != task_selection_policy
    ):
        raise ValueError("Gate C live policy failed validation")
    app_config: AppConfig = load_config(app_config_path, run_dir=output_dir)
    if (
        app_config.generation.provider != "openai_compatible"
        or app_config.generation.openai_compatible is None
        or app_config.generation.openai_compatible.max_attempts != 1
        or app_config.generation.confirmation_max_requests != expected
        or app_config.generation.confirmation_max_total_provider_attempts != expected
        or not app_config.functional_judge.enabled
        or app_config.functional_judge.mode != "single_pass"
        or app_config.functional_judge.llm is None
        or app_config.functional_judge.llm.max_attempts != 1
    ):
        raise ValueError("Gate C live provider policy failed validation")
    assignments = tuple(
        read_jsonl(
            plan_dir / "assignments.jsonl", AssignmentRecord, required=True, allow_empty=False
        )
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
    coverage = tuple(
        read_jsonl(plan_dir / "oracle-coverage.jsonl", required=True, allow_empty=False)
    )
    assignment_by_id = {item.assignment_id: item for item in assignments}
    request_by_assignment = {str(item.assignment_id): item for item in requests}
    contract_by_task = {item.task_id: item for item in contracts}
    coverage_by_task = {str(item["task_id"]): item for item in coverage}
    if (
        len(assignments) != expected
        or len(request_by_assignment) != expected
        or set(request_by_assignment) != set(assignment_by_id)
        or len(contract_by_task) != task_count
        or len(coverage_by_task) != task_count
        or set(contract_by_task) != set(coverage_by_task)
        or any(item.get("zero_finding_interpretation") != oracle_decision_mode for item in coverage)
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
            "source_plan_manifest_sha256": sha256_file(plan_dir / "artifact-manifest.json"),
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
        phase_name = "phase-001-pilot"
        root_report_name = "report-pilot.json"
    else:
        if pilot_id not in completed:
            raise ValueError("Gate C live pilot has not completed")
        input_provenance = _read_json(output_dir / "input-provenance.json")
        if input_provenance.get("app_config_sha256") != sha256_file(
            app_config_path
        ) or input_provenance.get("source_plan_manifest_sha256") != sha256_file(
            plan_dir / "artifact-manifest.json"
        ):
            raise ValueError("Gate C live remaining input provenance failed validation")
        selected = tuple(sorted(set(assignment_by_id) - completed))
        if not selected:
            raise ValueError("Gate C live has no pending assignments")
        remaining_attempt = _next_remaining_attempt(output_dir)
        remaining_suffix = "" if remaining_attempt == 1 else f"-{remaining_attempt:03d}"
        _write_json(output_dir / f"live-config-remaining{remaining_suffix}.json", live)
        _write_json(
            output_dir / f"command-remaining{remaining_suffix}.json",
            {"argv": list(command_argv)},
        )
        _write_json(
            output_dir / f"environment-remaining{remaining_suffix}.json",
            _environment(),
        )
        _write_json(
            output_dir / f"input-provenance-remaining{remaining_suffix}.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "live_config_sha256": sha256_file(live_config_path),
                "stored_base_live_config_sha256": sha256_file(output_dir / "live-config.json"),
                "app_config_sha256": sha256_file(app_config_path),
                "source_plan_manifest_sha256": sha256_file(plan_dir / "artifact-manifest.json"),
                "scale_up_authorization_id": live["scale_up_authorization_id"],
                "scale_up_authorization_scope": _SCALE_UP_AUTHORIZATION_SCOPE,
                "authorized_assignment_ids": list(selected),
            },
        )
        phase_name = (
            "phase-002-remaining"
            if remaining_attempt == 1
            else f"phase-remaining-{remaining_attempt:03d}"
        )
        root_report_name = f"report-remaining{remaining_suffix}.json"
    phase_dir = output_dir / "phases" / phase_name
    phase_dir.mkdir(parents=True, exist_ok=False)
    _write_json(
        phase_dir / "selection.json",
        {"schema_version": _SCHEMA_VERSION, "mode": mode, "assignment_ids": list(selected)},
    )
    generation_recorder = _RecordingGenerationTransport()
    provider = create_confirmation_provider(app_config, attempt_recorder=generation_recorder)
    recorder: _RecordingStructuredTransport | None = None

    def transport_factory(**kwargs: object) -> object:
        nonlocal recorder
        recorder = _RecordingStructuredTransport(**kwargs)
        return recorder

    judge = create_functional_judge(app_config, transport_factory=transport_factory)
    policy = load_policy_bundle((repo_root / app_config.oracle.policy_lock_path).resolve())
    profile_by_id = {item.profile_id: item for item in policy.coverage_profiles}
    if oracle_decision_mode == _ORACLE_PROFILE_MODE and any(
        item.get("decision_backend") != "python_ast_mechanism_v1"
        or item.get("zero_finding_supported") is not True
        or item.get("oracle_profile_id") not in profile_by_id
        for item in coverage
    ):
        raise ValueError("Gate C live profile-scoped Oracle policy failed validation")
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
            generation_recorder.bind(unit_dir / "generation-provider-transport")
            try:
                executions, codes = execute_confirmation_requests(
                    (request,), provider, app_config.generation
                )
            finally:
                generation_recorder.release_if_unused()
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
                try:
                    judge_passes, functional_outcome = judge.evaluate(
                        assignment, execution, code, contract
                    )
                except SecAwareError as judge_error:
                    if (
                        judge_error.code is not ErrorCode.API_INVALID_RESPONSE
                        or not (unit_dir / "functional-judge-transport" / "response.json").is_file()
                    ):
                        raise
                    functional_outcome, invalid_response = _invalid_judge_unknown_outcome(
                        unit_dir=unit_dir,
                        assignment_id=assignment_id,
                        contract_id=contract.contract_id,
                        evaluator_policy_sha256=judge.policy_sha256,
                    )
                    judge_passes = ()
                    _write_json(
                        unit_dir / "functional-judge-invalid-response.json",
                        invalid_response,
                    )
            finally:
                recorder.release_if_unused()
            write_jsonl(unit_dir / "functional-judge-passes.jsonl", judge_passes)
            write_jsonl(unit_dir / "functional-outcome.jsonl", (functional_outcome,))
            analyses: list[OracleCodeAnalysis] = []
            stage = "oracle"
            if code is not None:
                analyzer_recorder = _RecordingAnalyzerRunner()
                analyzer_recorder.bind(unit_dir / "oracle-analyzer-transport")
                try:
                    analyses = run_oracle_code_batch(
                        (OracleCodeInput.from_canonical(code),),
                        policy,
                        semgrep_executable=app_config.oracle.semgrep_executable,
                        bandit_executable=app_config.oracle.bandit_executable,
                        timeout_seconds=app_config.oracle.timeout_seconds,
                        max_stdout_bytes=app_config.oracle.max_stdout_bytes,
                        max_stderr_bytes=app_config.oracle.max_stderr_bytes,
                        runner=analyzer_recorder,
                        runtime_validator=validate_analyzer_runtime,
                    )
                finally:
                    analyzer_recorder.finish()
                _write_json(unit_dir / "oracle-analysis.json", analyses[0])
                if oracle_decision_mode == _ORACLE_PROFILE_MODE:
                    coverage_row = coverage_by_task[task_id]
                    profile = profile_by_id[str(coverage_row["oracle_profile_id"])]
                    if profile.cwe != coverage_row.get("cwe"):
                        raise ValueError("Gate C live Oracle profile scope failed validation")
                    _write_json(
                        unit_dir / "oracle-decision.json",
                        _profile_decision_payload(analyses[0], profile),
                    )
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
            judge_attempts = int(
                (unit_dir / "functional-judge-transport" / "transport.json").is_file()
            )
            _write_json(
                unit_dir / "status.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "assignment_id": assignment_id,
                    "status": "COMPLETE",
                    "generated": int(code is not None),
                    "terminal_no_code": int(code is None),
                    "generation_provider_attempts": execution.attempt_count,
                    "functional_judge_provider_attempts": judge_attempts,
                    "oracle_results": len(analyses),
                    "oracle_decisions": int(
                        bool(analyses) and oracle_decision_mode == _ORACLE_PROFILE_MODE
                    ),
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
    _write_json(output_dir / root_report_name, summary)
    if failure is not None:
        raise RuntimeError(
            "Gate C live phase failed; preserved unit artifacts require diagnosis"
        ) from failure
    return summary


def recover_gate_c_live_oracle(
    *,
    repo_root: Path,
    live_config_path: Path,
    app_config_path: Path,
    source_dir: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Copy one failed live unit and rerun only its missing Oracle analysis."""

    repo_root = repo_root.resolve()
    live_config_path = live_config_path.resolve()
    app_config_path = app_config_path.resolve()
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if not source_dir.is_dir() or output_dir.exists() or source_dir == output_dir:
        raise ValueError("Gate C Oracle repair path failed validation")
    live = _read_json(live_config_path)
    source_live = _read_json(source_dir / "live-config.json")
    if live != source_live:
        raise ValueError("Gate C Oracle repair live configuration failed validation")
    plan_dir = (repo_root / str(live.get("source_plan_dir"))).resolve()
    plan_dir.relative_to(repo_root)
    plan_report = _verify_plan(plan_dir)
    expected = int(live.get("expected_assignments", 0))
    task_selection_policy = str(live.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY))
    _bounded_task_count(expected, task_selection_policy)
    pilot_id = live.get("pilot_assignment_id")
    oracle_decision_mode = live.get("zero_finding_interpretation")
    if (
        live.get("schema_version") != _SCHEMA_VERSION
        or type(pilot_id) is not str
        or oracle_decision_mode not in {_ORACLE_UNKNOWN_MODE, _ORACLE_PROFILE_MODE}
        or plan_report.get("counts", {}).get("generation_requests") != expected
        or plan_report.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY)
        != task_selection_policy
    ):
        raise ValueError("Gate C Oracle repair policy failed validation")
    provenance = _read_json(source_dir / "input-provenance.json")
    if provenance != {
        "schema_version": _SCHEMA_VERSION,
        "live_config_sha256": sha256_file(live_config_path),
        "app_config_sha256": sha256_file(app_config_path),
        "source_plan_manifest_sha256": sha256_file(plan_dir / "artifact-manifest.json"),
    }:
        raise ValueError("Gate C Oracle repair input provenance failed validation")
    completed, failed = _completed_assignments(source_dir)
    repair_id = _repair_assignment_id(completed, failed, pilot_id)
    source_unit = source_dir / "units" / repair_id
    status = _read_json(source_unit / "status.json")
    error = _read_json(source_unit / "error.json")
    failed_stage = status.get("failed_stage")
    invalid_judge_response = (
        failed_stage == "functional_judge"
        and error.get("stage") == "functional_judge"
        and error.get("error_code") == int(ErrorCode.API_INVALID_RESPONSE)
        and (source_unit / "functional-judge-transport" / "response.json").is_file()
    )
    invalid_generation_response = (
        failed_stage == "generation"
        and error.get("stage") == "generation"
        and error.get("error_code") == int(ErrorCode.API_INVALID_RESPONSE)
        and (source_unit / "generation-provider-transport" / "response.json").is_file()
    )
    syntax_gated_oracle_failure = (
        failed_stage == "oracle"
        and error.get("stage") == "oracle"
        and error.get("error_code") == int(ErrorCode.ANALYZER_INVALID_OUTPUT)
        and status.get("functional_judge_provider_attempts") == 0
        and (source_unit / "functional-judge-transport" / "not-invoked.json").is_file()
    )
    if (
        status.get("status") != "ERROR"
        or failed_stage not in {"oracle", "functional_judge", "generation"}
        or status.get("generated") != (0 if invalid_generation_response else 1)
        or status.get("terminal_no_code") != 0
        or status.get("generation_provider_attempts") != 1
        or status.get("functional_judge_provider_attempts")
        != (0 if invalid_generation_response or syntax_gated_oracle_failure else 1)
        or status.get("oracle_results") != 0
        or (failed_stage == "oracle" and error.get("stage") != "oracle")
        or (failed_stage == "functional_judge" and not invalid_judge_response)
        or (failed_stage == "generation" and not invalid_generation_response)
    ):
        raise ValueError("Gate C Oracle repair source status failed validation")
    oracle_analysis_path = source_unit / "oracle-analysis.json"
    oracle_binding_path = source_unit / "oracle-binding.json"
    has_preserved_oracle = oracle_analysis_path.is_file() and oracle_binding_path.is_file()
    if (
        oracle_analysis_path.exists() != oracle_binding_path.exists()
        or (source_unit / "oracle-decision.json").exists()
        or (source_unit / "recovery-provenance.json").exists()
    ):
        raise ValueError("Gate C Oracle repair source has partial recovery output")
    if has_preserved_oracle and (
        error.get("error_type") != "AttributeError"
        or "provider_attempt_count" not in str(error.get("message"))
    ):
        raise ValueError("Gate C Oracle repair post-analysis failure is not recognized")
    assignments = tuple(
        read_jsonl(
            source_unit / "assignment.jsonl",
            AssignmentRecord,
            required=True,
            allow_empty=False,
        )
    )
    requests = tuple(
        read_jsonl(
            source_unit / "generation-request.jsonl",
            GenerationRequestRecord,
            required=True,
            allow_empty=False,
        )
    )
    codes = (
        ()
        if invalid_generation_response
        else tuple(
            read_jsonl(
                source_unit / "generated-code.jsonl",
                CanonicalGeneratedCodeRecord,
                required=True,
                allow_empty=False,
            )
        )
    )
    executions = (
        ()
        if invalid_generation_response
        else tuple(
            read_jsonl(
                source_unit / "assignment-execution.jsonl",
                required=True,
                allow_empty=False,
            )
        )
    )
    contracts = tuple(
        read_jsonl(
            source_unit / "functional-contract.jsonl",
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    outcomes = (
        ()
        if invalid_judge_response or invalid_generation_response
        else tuple(
            read_jsonl(
                source_unit / "functional-outcome.jsonl",
                required=True,
                allow_empty=False,
            )
        )
    )
    judge_passes = (
        ()
        if invalid_judge_response or invalid_generation_response
        else tuple(
            read_jsonl(
                source_unit / "functional-judge-passes.jsonl",
                required=True,
                allow_empty=syntax_gated_oracle_failure,
            )
        )
    )
    judge_passes_valid = (
        not judge_passes
        if syntax_gated_oracle_failure
        else len(judge_passes) == 1 and judge_passes[0].get("assignment_id") == repair_id
    )
    if (
        len(assignments) != 1
        or assignments[0].assignment_id != repair_id
        or len(requests) != 1
        or requests[0].assignment_id != repair_id
        or len(contracts) != 1
        or (
            not invalid_generation_response
            and (
                len(codes) != 1
                or codes[0].assignment_id != repair_id
                or len(executions) != 1
                or executions[0].get("assignment_id") != repair_id
                or executions[0].get("status") != AssignmentExecutionStatus.GENERATED.value
                or executions[0].get("request_id") != codes[0].request_id
            )
        )
        or (
            not invalid_judge_response
            and not invalid_generation_response
            and (
                len(outcomes) != 1
                or outcomes[0].get("assignment_id") != repair_id
                or not judge_passes_valid
            )
        )
        or (
            (invalid_judge_response or invalid_generation_response)
            and (
                (source_unit / "functional-outcome.jsonl").exists()
                or (source_unit / "functional-judge-passes.jsonl").exists()
            )
        )
        or (
            invalid_generation_response
            and (
                (source_unit / "generated-code.jsonl").exists()
                or (source_unit / "assignment-execution.jsonl").exists()
            )
        )
    ):
        raise ValueError("Gate C Oracle repair preserved records failed validation")
    if syntax_gated_oracle_failure and (
        len(codes) != 1
        or evaluate_functionality(codes[0].code)["syntax_ok"]
        or len(outcomes) != 1
        or outcomes[0].get("status") != FunctionalOutcomeStatus.FAIL.value
    ):
        raise ValueError("Gate C syntax-gated Oracle repair evidence failed validation")
    preserved_analysis: OracleCodeAnalysis | None = None
    if has_preserved_oracle:
        preserved_analysis = _oracle_analysis_from_payload(_read_json(oracle_analysis_path))
        preserved_binding = _read_json(oracle_binding_path)
        if (
            preserved_analysis.request_id != codes[0].request_id
            or preserved_analysis.code_id != codes[0].code_id
            or preserved_analysis.code_sha256 != codes[0].code_sha256
            or preserved_analysis.prompt_id != codes[0].prompt_id
            or preserved_analysis.model_id != codes[0].model_id
            or preserved_analysis.seed_id != codes[0].seed_id
            or preserved_binding
            != {
                "schema_version": _SCHEMA_VERSION,
                "assignment_id": repair_id,
                "request_id": codes[0].request_id,
                "code_id": codes[0].code_id,
                "binding_performed_after_blind_analysis": True,
            }
        ):
            raise ValueError("Gate C Oracle repair preserved analysis binding failed validation")

    app_config = load_config(app_config_path, run_dir=output_dir)
    policy = load_policy_bundle((repo_root / app_config.oracle.policy_lock_path).resolve())
    replay_judge = (
        create_functional_judge(
            app_config,
            transport_factory=lambda **_kwargs: _ReplayOnlyStructuredTransport(),
        )
        if invalid_judge_response
        else None
    )
    source_coverage = _read_json(source_unit / "oracle-coverage.json")
    if source_coverage.get("zero_finding_interpretation") != oracle_decision_mode:
        raise ValueError("Gate C Oracle repair coverage mode failed validation")
    profile = (
        _profile_for_coverage(source_coverage, policy)
        if oracle_decision_mode == _ORACLE_PROFILE_MODE
        else None
    )

    source_snapshot = _tree_snapshot(source_dir)
    shutil.copytree(source_dir, output_dir, copy_function=shutil.copy2)
    if _tree_snapshot(output_dir) != source_snapshot:
        raise ValueError("Gate C Oracle repair copy failed validation")
    unit_dir = output_dir / "units" / repair_id
    (unit_dir / "status.json").replace(unit_dir / "status-before-recovery.json")
    (unit_dir / "artifact-manifest.json").replace(
        unit_dir / "artifact-manifest-before-recovery.json"
    )
    repair_tag = repair_id.removeprefix("assignment_")[:12]
    phase_dir = output_dir / "phases" / f"phase-oracle-repair-{repair_tag}"
    phase_dir.mkdir(parents=True, exist_ok=False)
    _write_json(
        phase_dir / "selection.json",
        {"schema_version": _SCHEMA_VERSION, "assignment_ids": [repair_id]},
    )
    _write_json(
        output_dir / f"command-repair-oracle-{repair_tag}.json",
        {"argv": list(command_argv)},
    )
    _write_json(output_dir / f"environment-repair-oracle-{repair_tag}.json", _environment())
    _write_json(
        output_dir / f"recovery-source-provenance-{repair_tag}.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "source_directory": str(source_dir),
            "source_snapshot_sha256": _snapshot_sha256(source_snapshot),
            "source_files": source_snapshot,
            "new_generation_provider_attempts": 0,
            "new_functional_judge_provider_attempts": int(invalid_generation_response),
        },
    )
    write_resolved_config(
        app_config,
        output_dir / f"effective-app-config-repair-{repair_tag}.yaml",
    )
    failure: BaseException | None = None
    analysis = preserved_analysis
    new_oracle_executions = 0 if preserved_analysis is not None else 1
    new_functional_judge_calls = int(invalid_generation_response)
    try:
        if invalid_generation_response:
            raw_response = _read_json(unit_dir / "generation-provider-transport" / "response.json")
            source_transport = _read_json(
                unit_dir / "generation-provider-transport" / "transport.json"
            )
            response_sha256 = hashlib.sha256(_canonical(raw_response)).hexdigest()
            if (
                source_transport.get("attempt") != 1
                or source_transport.get("transport_error") is not False
                or source_transport.get("response_sha256") != response_sha256
            ):
                raise ValueError("Gate C generation replay provenance failed validation")
            replay_provider = create_confirmation_replay_provider(app_config, raw_response)
            replayed_executions, replayed_codes = execute_confirmation_requests(
                (requests[0],),
                replay_provider,
                app_config.generation,
            )
            if (
                len(replayed_executions) != 1
                or len(replayed_codes) != 1
                or replayed_executions[0].status is not AssignmentExecutionStatus.GENERATED
            ):
                raise ValueError("Gate C generation replay result failed validation")
            executions = replayed_executions
            codes = replayed_codes
            write_jsonl(unit_dir / "assignment-execution.jsonl", executions)
            write_jsonl(unit_dir / "generated-code.jsonl", codes)
            _write_json(
                unit_dir / "generation-response-replay.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "source_response_sha256": response_sha256,
                    "new_generation_provider_attempts": 0,
                    "replay_result": "generated",
                    "code_sha256": codes[0].code_sha256,
                },
            )

            functional_recorder: _RecordingStructuredTransport | None = None

            def transport_factory(**kwargs: object) -> object:
                nonlocal functional_recorder
                functional_recorder = _RecordingStructuredTransport(**kwargs)
                return functional_recorder

            functional_judge = create_functional_judge(
                app_config,
                transport_factory=transport_factory,
            )
            if functional_recorder is None:
                raise RuntimeError("Gate C functional recovery recorder is unavailable")
            functional_recorder.bind(unit_dir / "functional-judge-transport")
            try:
                try:
                    judge_passes, functional_outcome = functional_judge.evaluate(
                        assignments[0],
                        executions[0],
                        codes[0],
                        contracts[0],
                    )
                except SecAwareError as judge_error:
                    if (
                        judge_error.code is not ErrorCode.API_INVALID_RESPONSE
                        or not (unit_dir / "functional-judge-transport" / "response.json").is_file()
                    ):
                        raise
                    functional_outcome, invalid_response = _invalid_judge_unknown_outcome(
                        unit_dir=unit_dir,
                        assignment_id=repair_id,
                        contract_id=contracts[0].contract_id,
                        evaluator_policy_sha256=functional_judge.policy_sha256,
                    )
                    judge_passes = ()
                    _write_json(
                        unit_dir / "functional-judge-invalid-response.json",
                        invalid_response,
                    )
            finally:
                functional_recorder.release_if_unused()
            write_jsonl(unit_dir / "functional-judge-passes.jsonl", judge_passes)
            write_jsonl(unit_dir / "functional-outcome.jsonl", (functional_outcome,))
        if invalid_judge_response:
            if replay_judge is None:
                raise RuntimeError("Gate C functional recovery policy is unavailable")
            functional_outcome, invalid_response = _invalid_judge_unknown_outcome(
                unit_dir=unit_dir,
                assignment_id=repair_id,
                contract_id=contracts[0].contract_id,
                evaluator_policy_sha256=replay_judge.policy_sha256,
            )
            write_jsonl(unit_dir / "functional-judge-passes.jsonl", ())
            write_jsonl(unit_dir / "functional-outcome.jsonl", (functional_outcome,))
            _write_json(
                unit_dir / "functional-judge-invalid-response.json",
                invalid_response,
            )
        if analysis is None:
            analyzer_recorder = _RecordingAnalyzerRunner()
            analyzer_recorder.bind(unit_dir / "oracle-analyzer-transport-recovery")
            try:
                analyses = run_oracle_code_batch(
                    (OracleCodeInput.from_canonical(codes[0]),),
                    policy,
                    semgrep_executable=app_config.oracle.semgrep_executable,
                    bandit_executable=app_config.oracle.bandit_executable,
                    timeout_seconds=app_config.oracle.timeout_seconds,
                    max_stdout_bytes=app_config.oracle.max_stdout_bytes,
                    max_stderr_bytes=app_config.oracle.max_stderr_bytes,
                    runner=analyzer_recorder,
                    runtime_validator=validate_analyzer_runtime,
                )
            finally:
                analyzer_recorder.finish()
            if len(analyses) != 1:
                raise RuntimeError("Gate C Oracle repair returned an invalid analysis count")
            analysis = analyses[0]
            _write_json(unit_dir / "oracle-analysis.json", analysis)
        if analysis is None:
            raise RuntimeError("Gate C Oracle repair did not produce an analysis")
        if profile is not None:
            _write_json(
                unit_dir / "oracle-decision.json",
                _profile_decision_payload(analysis, profile),
            )
        if preserved_analysis is None:
            _write_json(
                unit_dir / "oracle-binding.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "assignment_id": repair_id,
                    "request_id": analysis.request_id,
                    "code_id": analysis.code_id,
                    "binding_performed_after_blind_analysis": True,
                },
            )
    except BaseException as repair_error:
        failure = repair_error
        _write_json(unit_dir / "recovery-error.json", _safe_error(repair_error, "oracle_repair"))
    oracle_result_count = int((unit_dir / "oracle-analysis.json").is_file())
    oracle_decision_count = int((unit_dir / "oracle-decision.json").is_file())
    _write_json(
        unit_dir / "recovery-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "source_unit_manifest_sha256": sha256_file(
                unit_dir / "artifact-manifest-before-recovery.json"
            ),
            "generated_code_sha256": (
                sha256_file(unit_dir / "generated-code.jsonl")
                if (unit_dir / "generated-code.jsonl").is_file()
                else None
            ),
            "functional_outcome_sha256": (
                sha256_file(unit_dir / "functional-outcome.jsonl")
                if (unit_dir / "functional-outcome.jsonl").is_file()
                else None
            ),
            "new_generation_provider_attempts": 0,
            "new_functional_judge_provider_attempts": new_functional_judge_calls,
            "new_oracle_executions": new_oracle_executions,
            "preserved_oracle_result_reused": preserved_analysis is not None,
            "invalid_functional_response_reclassified": invalid_judge_response,
            "persisted_generation_response_replayed": invalid_generation_response,
            "syntax_parse_failure_reclassified": syntax_gated_oracle_failure,
        },
    )
    _write_json(
        unit_dir / "status.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "assignment_id": repair_id,
            "status": "ERROR" if failure is not None else "COMPLETE",
            **({"failed_stage": "oracle_repair"} if failure is not None else {}),
            "generated": 1,
            "terminal_no_code": 0,
            "generation_provider_attempts": 1,
            "functional_judge_provider_attempts": (0 if syntax_gated_oracle_failure else 1),
            "oracle_results": oracle_result_count,
            "oracle_decisions": oracle_decision_count,
            "recovered_without_provider_calls": True,
        },
    )
    _unit_manifest(unit_dir)
    summary = _summary(output_dir, expected, "oracle-repair")
    summary["status"] = (
        "GATE_C_LIVE_ORACLE_REPAIR_ERROR"
        if failure is not None
        else "GATE_C_LIVE_ORACLE_REPAIR_COMPLETE"
    )
    summary["new_provider_calls"] = 0
    summary["new_functional_judge_calls"] = new_functional_judge_calls
    summary["new_oracle_executions"] = new_oracle_executions
    _write_json(phase_dir / "report.json", summary)
    _write_json(output_dir / f"report-repair-oracle-{repair_tag}.json", summary)
    if failure is not None:
        raise RuntimeError(
            "Gate C Oracle repair failed; closed recovery artifacts were saved"
        ) from failure
    return summary


RecordingGenerationTransport = _RecordingGenerationTransport
RecordingStructuredTransport = _RecordingStructuredTransport


__all__ = [
    "RecordingGenerationTransport",
    "RecordingStructuredTransport",
    "recover_gate_c_live_oracle",
    "run_gate_c_live_canary",
]

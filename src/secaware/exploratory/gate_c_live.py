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
from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
    write_json_atomic_exclusive,
)
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
_TASK_SELECTION_BINDING_EXACT = "exact_content_addressed_v1"
_SEED_ASSIGNMENT_INHERITED = "inherited_gate_a_randomization_v1"
_REQUIRED_SOURCE_PLAN_CONTRACT_KEYS = frozenset(
    {"manifest_sha256", "task_selection_binding_policy", "seed_assignment_policy"}
)
_SCALE_UP_AUTHORIZATION_SCOPE = "remaining_assignments_only"
_AUTHORIZATION_RECEIPT_NAME = "authorization-receipt-remaining.json"
_REMAINING_LIVE_CONFIG_NAME = "live-config-remaining.json"
_REMAINING_INPUT_PROVENANCE_NAME = "input-provenance-remaining.json"
_SCALE_UP_AUTHORIZATION_BY_LIVE_ID = {
    "randomized-exploratory-gate-c-live-cwe78-cwe89-qwen25-coder-7b-v1": (
        "user-approved-remaining-20260817-v1"
    ),
    "randomized-exploratory-gate-c-live-cwe78-cwe89-phi4-14b-v1": (
        "user-approved-remaining-20260817-v1"
    ),
    "randomized-exploratory-gate-c-live-cwe78-cwe89-qwen25-coder-7b-v2-protocol-repair": (
        "user-approved-remaining-20260817-v1"
    ),
    "randomized-exploratory-gate-c-live-cwe78-cwe89-phi4-14b-v2-protocol-repair": (
        "user-approved-remaining-20260817-v1"
    ),
    "randomized-exploratory-gate-c-live-five-cwe-qwen25-coder-7b-v1": (
        "user-approved-five-cwe-outcome-pilot-20260818-v1"
    ),
    "gate-c-main-prompt-canary-live-qwen25-coder-7b-v1": (
        "user-approved-main-prompt-outcome-canary-20260818-v1"
    ),
    "gate-c-main-prompt-canary-live-phi4-14b-v1": (
        "user-approved-main-prompt-outcome-canary-20260818-v1"
    ),
    "randomized-discovery-gate-c-main-live-qwen7b-v1": (
        "user-approved-five-cwe-randomized-discovery-main-20260818-v1"
    ),
    "randomized-discovery-gate-c-main-live-phi14b-v1": (
        "user-approved-five-cwe-randomized-discovery-main-20260818-v1"
    ),
    "five-cwe-held-out-policy-itt-gate-c-live-qwen7b-v1": (
        "user-approved-five-cwe-held-out-policy-itt-main-20260819-v1"
    ),
    "five-cwe-held-out-policy-itt-gate-c-live-phi14b-v1": (
        "user-approved-five-cwe-held-out-policy-itt-main-20260819-v1"
    ),
    "minimal-validation-dev-canary-full-live-qwen7b-v1": (
        "user-approved-minimal-validation-dev-canary-20260820-v1"
    ),
    "minimal-validation-dev-canary-full-python-comment-live-qwen7b-v1": (
        "user-approved-minimal-validation-dev-canary-20260820-v1"
    ),
    "minimal-validation-dev-canary-micro-live-qwen7b-v1": (
        "user-approved-minimal-validation-dev-canary-20260820-v1"
    ),
    "minimal-validation-dev-canary-micro-python-comment-live-qwen7b-v1": (
        "user-approved-minimal-validation-dev-canary-20260820-v1"
    ),
    "minimal-validation-dev-canary-micro-python-comment-live-qwen7b-v2": (
        "user-approved-minimal-validation-dev-canary-micro-python-comment-20260821-v2"
    ),
    "minimal-validation-dev-canary-full-python-comment-live-qwen7b-v2": (
        "user-approved-minimal-validation-dev-canary-full-python-comment-20260821-v2"
    ),
}
_SCALE_UP_AUTHORIZATION_IDS = frozenset(_SCALE_UP_AUTHORIZATION_BY_LIVE_ID.values())
_SCALE_UP_AUTHORIZATION_KEYS = frozenset(
    {"scale_up_authorization_id", "scale_up_authorization_scope"}
)
_ORACLE_UNKNOWN_MODE = "unknown_coverage"
_ORACLE_PROFILE_MODE = "profile_scoped_decision"
_TASK_SELECTION_BOUNDED_CANARY = "explicit_bounded_canary"
_TASK_SELECTION_DEV_CANARY = "explicit_dev_canary"
_TASK_SELECTION_ALL_GATE_B = "all_gate_b_tasks"
_LEGACY_ARM_ROLES = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_DEV_CANARY_ARM_ROLES = ("target_patch", "noop_rewrite")


def _bounded_task_count(
    expected_assignments: int,
    task_selection_policy: str = _TASK_SELECTION_BOUNDED_CANARY,
    arms_per_task: int = 4,
) -> int:
    if arms_per_task not in {2, 4} or expected_assignments % arms_per_task != 0:
        raise ValueError("Gate C live assignment count failed validation")
    task_count = expected_assignments // arms_per_task
    if task_selection_policy == _TASK_SELECTION_BOUNDED_CANARY:
        valid_size = arms_per_task == 4 and 2 <= task_count <= 5
    elif task_selection_policy == _TASK_SELECTION_DEV_CANARY:
        valid_size = arms_per_task == 2 and task_count in {2, 12}
    elif task_selection_policy == _TASK_SELECTION_ALL_GATE_B:
        valid_size = arms_per_task == 4 and task_count in {42, 51}
    else:
        valid_size = False
    if not valid_size:
        raise ValueError("Gate C live assignment count failed validation")
    return task_count


def _plan_arm_roles(plan_report: dict[str, object]) -> tuple[str, ...]:
    raw_roles = plan_report.get("arm_roles")
    raw_count = plan_report.get("arms_per_task")
    if raw_roles is None and raw_count is None:
        return _LEGACY_ARM_ROLES
    if raw_roles is None:
        if raw_count == 4:
            roles = _LEGACY_ARM_ROLES
        elif raw_count == 2:
            roles = _DEV_CANARY_ARM_ROLES
        else:
            roles = ()
    elif type(raw_roles) is list and all(type(item) is str for item in raw_roles):
        roles = tuple(raw_roles)
    else:
        raise ValueError("Gate C live arm roles failed validation")
    if roles not in {_LEGACY_ARM_ROLES, _DEV_CANARY_ARM_ROLES} or (
        raw_count is not None and raw_count != len(roles)
    ):
        raise ValueError("Gate C live arm roles failed validation")
    return roles


def _validated_plan_dimensions(
    plan_report: dict[str, object],
    *,
    expected_assignments: int,
    task_selection_policy: str,
) -> tuple[int, tuple[str, ...]]:
    arm_roles = _plan_arm_roles(plan_report)
    if (task_selection_policy == _TASK_SELECTION_DEV_CANARY) != (
        arm_roles == _DEV_CANARY_ARM_ROLES
    ):
        raise ValueError("Gate C live development arm protocol failed validation")
    task_count = _bounded_task_count(
        expected_assignments,
        task_selection_policy,
        len(arm_roles),
    )
    return task_count, arm_roles


def _report_contract_fields(
    task_selection_policy: str,
    arm_roles: tuple[str, ...],
) -> dict[str, object]:
    return {
        "scientific_claim_allowed": False,
        "task_selection_policy": task_selection_policy,
        "arm_roles": list(arm_roles),
        "arms_per_task": len(arm_roles),
    }


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
    verify_closed_manifest(plan_dir / "artifact-manifest.json", label="Gate C plan")
    report = _read_json(plan_dir / "report.json")
    if (
        report.get("status") != "GATE_C_PLAN_COMPLETE"
        or report.get("provider_calls_allowed") is not False
        or report.get("oracle_execution_allowed") is not False
        or report.get("scientific_claim_allowed") is not False
    ):
        raise ValueError("Gate C source plan failed validation")
    binding = report.get("task_selection_binding")
    if binding is not None and type(binding) is not dict:
        raise ValueError("Gate C source plan selection binding failed validation")
    if type(binding) is dict:
        binding_policy = binding.get("policy")
        if binding_policy == _TASK_SELECTION_BINDING_EXACT:
            if (
                type(binding.get("selection_id")) is not str
                or type(binding.get("selection_sha256")) is not str
                or len(binding["selection_sha256"]) != 64
                or type(binding.get("task_count")) is not int
                or binding.get("task_count", 0) <= 0
                or type(binding.get("unique_task_cluster_count")) is not int
                or binding.get("unique_task_cluster_count") != binding.get("task_count")
                or type(binding.get("task_cluster_counts")) is not dict
                or len(binding.get("task_cluster_counts", {}))
                != binding.get("unique_task_cluster_count")
                or any(
                    type(cluster_id) is not str or not cluster_id or count != 1
                    for cluster_id, count in binding.get("task_cluster_counts", {}).items()
                )
                or type(binding.get("cwe_task_counts")) is not dict
                or any(
                    type(cwe) is not str or not cwe or type(count) is not int or count <= 0
                    for cwe, count in binding.get("cwe_task_counts", {}).items()
                )
                or sum(binding["cwe_task_counts"].values()) != binding.get("task_count")
                or report.get("seed_assignment_policy") != _SEED_ASSIGNMENT_INHERITED
                or report.get("same_seed_within_task") is not False
                or report.get("arm_seed_distribution_balanced") is not False
            ):
                raise ValueError("Gate C source plan selection binding failed validation")
        elif binding_policy != "legacy_unbound_v1":
            raise ValueError("Gate C source plan selection binding failed validation")
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
    write_closed_manifest_atomic(unit_dir, label="Gate C live unit")


def _verify_unit_manifest(unit_dir: Path) -> dict[str, object]:
    return verify_closed_manifest(unit_dir / "artifact-manifest.json", label="Gate C live unit")


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
    gate_c_live_id = live.get("gate_c_live_id")
    expected_authorization_id = (
        _SCALE_UP_AUTHORIZATION_BY_LIVE_ID.get(gate_c_live_id)
        if type(gate_c_live_id) is str
        else None
    )
    if (
        stored_base is None
        or stored_base.get("scale_up_allowed") is not False
        or any(key in stored_base for key in _SCALE_UP_AUTHORIZATION_KEYS)
        or live.get("scale_up_allowed") is not True
        or expected_authorization_id is None
        or live.get("scale_up_authorization_id") != expected_authorization_id
        or live.get("scale_up_authorization_scope") != _SCALE_UP_AUTHORIZATION_SCOPE
    ):
        raise ValueError("Gate C live scale-up authorization failed validation")
    normalized = dict(live)
    for key in _SCALE_UP_AUTHORIZATION_KEYS:
        normalized.pop(key, None)
    normalized["scale_up_allowed"] = False
    if normalized != stored_base:
        raise ValueError("Gate C live scale-up authorization changed the frozen pilot config")


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_required_source_plan_contract(
    live: dict[str, Any],
    *,
    plan_report: dict[str, object],
    source_plan_manifest_sha256: str,
) -> None:
    contract = live.get("required_source_plan_contract")
    if contract is None:
        return
    binding = plan_report.get("task_selection_binding")
    binding_policy = binding.get("policy") if type(binding) is dict else None
    if (
        type(contract) is not dict
        or set(contract) != _REQUIRED_SOURCE_PLAN_CONTRACT_KEYS
        or not _is_sha256(contract.get("manifest_sha256"))
        or contract.get("task_selection_binding_policy") != _TASK_SELECTION_BINDING_EXACT
        or contract.get("seed_assignment_policy") != _SEED_ASSIGNMENT_INHERITED
        or not _is_sha256(source_plan_manifest_sha256)
        or contract.get("manifest_sha256") != source_plan_manifest_sha256
        or binding_policy != contract.get("task_selection_binding_policy")
        or plan_report.get("seed_assignment_policy") != contract.get("seed_assignment_policy")
    ):
        raise ValueError("Gate C live required source plan contract failed validation")


def _content_addressed_payload(
    payload: dict[str, object], *, id_key: str, prefix: str
) -> dict[str, object]:
    if id_key in payload:
        raise ValueError("Gate C live content-address input failed validation")
    result = dict(payload)
    result[id_key] = f"{prefix}{hashlib.sha256(_canonical(payload)).hexdigest()}"
    return result


def _authorization_receipt_payload(
    *,
    live: dict[str, Any],
    source_plan_id: str,
    source_plan_manifest_sha256: str,
    app_config_id: str,
    app_config_sha256: str,
    base_live_config_sha256: str,
    pilot_snapshot_id: str,
    pilot_snapshot_sha256: str,
    authorized_assignment_ids: tuple[str, ...],
) -> dict[str, object]:
    gate_c_live_id = live.get("gate_c_live_id")
    authorization_id = live.get("scale_up_authorization_id")
    pilot_assignment_id = live.get("pilot_assignment_id")
    authorized = tuple(sorted(authorized_assignment_ids))
    if (
        type(gate_c_live_id) is not str
        or not gate_c_live_id
        or _SCALE_UP_AUTHORIZATION_BY_LIVE_ID.get(gate_c_live_id) != authorization_id
        or live.get("scale_up_authorization_scope") != _SCALE_UP_AUTHORIZATION_SCOPE
        or type(source_plan_id) is not str
        or not source_plan_id
        or type(app_config_id) is not str
        or not app_config_id
        or type(pilot_assignment_id) is not str
        or not pilot_assignment_id
        or type(pilot_snapshot_id) is not str
        or not pilot_snapshot_id
        or authorized != authorized_assignment_ids
        or not authorized
        or len(set(authorized)) != len(authorized)
        or any(type(item) is not str or not item for item in authorized)
        or pilot_assignment_id in authorized
        or not all(
            _is_sha256(value)
            for value in (
                source_plan_manifest_sha256,
                app_config_sha256,
                base_live_config_sha256,
                pilot_snapshot_sha256,
            )
        )
    ):
        raise ValueError("Gate C live authorization receipt input failed validation")
    authorized_digest = hashlib.sha256(_canonical(list(authorized))).hexdigest()
    count = len(authorized)
    payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "receipt_version": "gate_c_live_remaining_authorization_v2",
        "status": "AUTHORIZED",
        "scientific_claim_allowed": False,
        "gate_c_live_id": gate_c_live_id,
        "scale_up_authorization_id": authorization_id,
        "scale_up_authorization_scope": _SCALE_UP_AUTHORIZATION_SCOPE,
        "source_plan": {
            "id": source_plan_id,
            "manifest_sha256": source_plan_manifest_sha256,
        },
        "app_config": {"id": app_config_id, "sha256": app_config_sha256},
        "base_live_config": {
            "id": f"{gate_c_live_id}:pilot-base-v1",
            "sha256": base_live_config_sha256,
        },
        "pilot": {
            "assignment_id": pilot_assignment_id,
            "phase_snapshot_id": pilot_snapshot_id,
            "phase_snapshot_sha256": pilot_snapshot_sha256,
        },
        "authorized_assignment_ids": list(authorized),
        "authorized_assignment_ids_sha256": authorized_digest,
        "typed_budgets": {
            "generation_provider_attempts": {
                "unit": "provider_attempts",
                "maximum": count,
            },
            "functional_judge_provider_attempts": {
                "unit": "provider_attempts",
                "maximum": count,
            },
            "oracle_executions": {"unit": "executions", "maximum": count},
        },
    }
    return _content_addressed_payload(
        payload,
        id_key="authorization_receipt_id",
        prefix="gate_c_live_authorization_receipt_",
    )


def _verify_authorization_receipt(
    receipt: dict[str, Any],
    **expected_inputs: Any,
) -> dict[str, object]:
    expected = _authorization_receipt_payload(**expected_inputs)
    if receipt != expected:
        raise ValueError("Gate C live authorization receipt failed validation")
    budgets = receipt.get("typed_budgets")
    if type(budgets) is not dict or any(
        type(item) is not dict or type(item.get("maximum")) is not int or item["maximum"] <= 0
        for item in budgets.values()
    ):
        raise ValueError("Gate C live authorization receipt budget failed validation")
    return receipt


def _load_or_create_authorization_receipt(
    output_dir: Path,
    *,
    allow_create: bool,
    expected_inputs: dict[str, Any],
) -> tuple[Path, dict[str, object]]:
    path = output_dir / _AUTHORIZATION_RECEIPT_NAME
    expected = _authorization_receipt_payload(**expected_inputs)
    if path.exists():
        return path, _verify_authorization_receipt(_read_json(path), **expected_inputs)
    if not allow_create:
        raise FileNotFoundError("Gate C live durable authorization receipt is missing")
    write_json_atomic_exclusive(path, expected)
    return path, _verify_authorization_receipt(_read_json(path), **expected_inputs)


def _write_or_verify_durable_json(
    path: Path,
    payload: dict[str, object],
    *,
    allow_create: bool,
    label: str,
) -> None:
    if path.exists():
        if _read_json(path) != payload:
            raise ValueError(f"Gate C live durable {label} failed validation")
        return
    if not allow_create:
        raise FileNotFoundError(f"Gate C live durable {label} is missing")
    write_json_atomic_exclusive(path, payload)


def _path_id(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _pilot_phase_snapshot_payload(
    output_dir: Path,
    *,
    live: dict[str, Any],
    source_plan_manifest_sha256: str,
    app_config_id: str,
    app_config_sha256: str,
    base_live_config_sha256: str,
) -> dict[str, object]:
    pilot_id = live.get("pilot_assignment_id")
    gate_c_live_id = live.get("gate_c_live_id")
    phase_dir = output_dir / "phases" / "phase-001-pilot"
    phase_report = _read_json(phase_dir / "report.json")
    root_report = _read_json(output_dir / "report-pilot.json")
    selection = _read_json(phase_dir / "selection.json")
    counts = phase_report.get("counts")
    unit_manifest = output_dir / "units" / str(pilot_id) / "artifact-manifest.json"
    _verify_unit_manifest(unit_manifest.parent)
    if (
        type(gate_c_live_id) is not str
        or not gate_c_live_id
        or type(pilot_id) is not str
        or not pilot_id
        or not all(
            _is_sha256(value)
            for value in (
                source_plan_manifest_sha256,
                app_config_sha256,
                base_live_config_sha256,
            )
        )
        or selection.get("mode") != "pilot"
        or selection.get("assignment_ids") != [pilot_id]
        or phase_report != root_report
        or phase_report.get("phase") != "pilot"
        or phase_report.get("status") != "GATE_C_LIVE_PARTIAL"
        or phase_report.get("scientific_claim_allowed") is not False
        or type(counts) is not dict
        or counts.get("completed") != 1
        or counts.get("errors") != 0
        or phase_report.get("completed_assignment_ids") != [pilot_id]
        or phase_report.get("failed_assignment_ids") != []
    ):
        raise ValueError("Gate C live pilot phase snapshot failed validation")
    payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "snapshot_version": "gate_c_live_pilot_phase_v1",
        "status": "GATE_C_LIVE_PILOT_COMPLETE",
        "scientific_claim_allowed": False,
        "gate_c_live_id": gate_c_live_id,
        "source_plan": {
            "id": str(live.get("source_plan_dir")),
            "manifest_sha256": source_plan_manifest_sha256,
        },
        "app_config": {"id": app_config_id, "sha256": app_config_sha256},
        "base_live_config": {
            "id": f"{gate_c_live_id}:pilot-base-v1",
            "sha256": base_live_config_sha256,
        },
        "pilot_assignment_id": pilot_id,
        "artifacts": {
            "selection_sha256": sha256_file(phase_dir / "selection.json"),
            "phase_report_sha256": sha256_file(phase_dir / "report.json"),
            "root_report_sha256": sha256_file(output_dir / "report-pilot.json"),
            "unit_manifest_sha256": sha256_file(unit_manifest),
        },
    }
    return _content_addressed_payload(
        payload,
        id_key="pilot_phase_snapshot_id",
        prefix="gate_c_live_pilot_snapshot_",
    )


def _write_pilot_phase_snapshot(
    output_dir: Path,
    **expected_inputs: Any,
) -> dict[str, object]:
    payload = _pilot_phase_snapshot_payload(output_dir, **expected_inputs)
    path = output_dir / "phases" / "phase-001-pilot" / "phase-snapshot.json"
    write_json_atomic_exclusive(path, payload)
    return payload


def _verify_pilot_phase_snapshot(
    output_dir: Path,
    **expected_inputs: Any,
) -> dict[str, object]:
    path = output_dir / "phases" / "phase-001-pilot" / "phase-snapshot.json"
    observed = _read_json(path)
    expected = _pilot_phase_snapshot_payload(output_dir, **expected_inputs)
    if observed != expected:
        raise ValueError("Gate C live pilot phase snapshot failed validation")
    return observed


def _root_relative_artifact_path(root: Path, path: Path, *, label: str) -> str:
    root = root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        raise ValueError(f"Gate C live {label} escaped final root") from None
    if not resolved.is_file() or not relative or relative != Path(relative).as_posix():
        raise ValueError(f"Gate C live {label} path failed validation")
    return relative


def _finalize_live_root(
    output_dir: Path,
    *,
    live: dict[str, Any],
    summary: dict[str, object],
    expected_assignment_ids: tuple[str, ...],
    source_plan_manifest_sha256: str,
    app_config_sha256: str,
    base_live_config_sha256: str,
    pilot_snapshot: dict[str, object],
    authorization_receipt_path: Path,
    authorization_receipt_inputs: dict[str, Any],
    phase_report_path: Path,
    root_report_path: Path,
) -> dict[str, object]:
    completed = tuple(summary.get("completed_assignment_ids", ()))
    counts = summary.get("counts")
    normalized_expected = tuple(sorted(expected_assignment_ids))
    if (
        summary.get("status") != "GATE_C_LIVE_COMPLETE"
        or summary.get("phase") != "remaining"
        or summary.get("scientific_claim_allowed") is not False
        or type(counts) is not dict
        or not normalized_expected
        or len(set(normalized_expected)) != len(normalized_expected)
        or counts.get("completed") != len(normalized_expected)
        or counts.get("errors") != 0
        or counts.get("pending") != 0
        or completed != normalized_expected
        or summary.get("failed_assignment_ids") != []
    ):
        raise ValueError("Gate C live final root requires an exact COMPLETE summary")
    pilot_snapshot_path = output_dir / "phases" / "phase-001-pilot" / "phase-snapshot.json"
    receipt_relative_path = _root_relative_artifact_path(
        output_dir, authorization_receipt_path, label="authorization receipt"
    )
    phase_report_relative_path = _root_relative_artifact_path(
        output_dir, phase_report_path, label="final phase report"
    )
    root_report_relative_path = _root_relative_artifact_path(
        output_dir, root_report_path, label="final root report"
    )
    phase_parts = Path(phase_report_relative_path).parts
    phase_name = phase_parts[1] if len(phase_parts) == 3 else ""
    valid_remaining_phase = phase_name == "phase-002-remaining" or (
        phase_name.startswith("phase-remaining-")
        and len(phase_name.removeprefix("phase-remaining-")) == 3
        and phase_name.removeprefix("phase-remaining-").isdigit()
    )
    expected_root_report_path = (
        "report-remaining.json"
        if phase_name == "phase-002-remaining"
        else f"report-remaining-{phase_name.removeprefix('phase-remaining-')}.json"
    )
    if (
        receipt_relative_path != _AUTHORIZATION_RECEIPT_NAME
        or phase_parts[0:1] != ("phases",)
        or phase_parts[-1:] != ("report.json",)
        or not valid_remaining_phase
        or root_report_relative_path != expected_root_report_path
        or _read_json(phase_report_path) != summary
        or _read_json(root_report_path) != summary
        or _read_json(pilot_snapshot_path) != pilot_snapshot
    ):
        raise ValueError("Gate C live final report binding failed validation")
    receipt = _verify_authorization_receipt(
        _read_json(authorization_receipt_path), **authorization_receipt_inputs
    )
    receipt_id = receipt.get("authorization_receipt_id")
    pilot_snapshot_id = pilot_snapshot.get("pilot_phase_snapshot_id")
    receipt_source_plan = receipt.get("source_plan")
    receipt_app_config = receipt.get("app_config")
    receipt_base_config = receipt.get("base_live_config")
    receipt_pilot = receipt.get("pilot")
    pilot_assignment_id = live.get("pilot_assignment_id")
    if type(pilot_assignment_id) is not str or pilot_assignment_id not in normalized_expected:
        raise ValueError("Gate C live final pilot binding failed validation")
    expected_pending = tuple(item for item in normalized_expected if item != pilot_assignment_id)
    pilot_snapshot_sha256 = sha256_file(pilot_snapshot_path)
    cumulative_actuals = {
        "generation_provider_attempts": counts.get("generation_provider_attempts"),
        "functional_judge_provider_attempts": counts.get("functional_judge_provider_attempts"),
        "oracle_executions": counts.get("oracle_results"),
    }
    remaining_actuals = {
        "generation_provider_attempts": 0,
        "functional_judge_provider_attempts": 0,
        "oracle_executions": 0,
    }
    observed_cumulative_actuals = {key: 0 for key in cumulative_actuals}
    for assignment_id in normalized_expected:
        unit_dir = output_dir / "units" / assignment_id
        _verify_unit_manifest(unit_dir)
        status = _read_json(unit_dir / "status.json")
        unit_actuals = {
            "generation_provider_attempts": status.get("generation_provider_attempts"),
            "functional_judge_provider_attempts": status.get("functional_judge_provider_attempts"),
            "oracle_executions": status.get("oracle_results"),
        }
        if (
            status.get("assignment_id") != assignment_id
            or status.get("status") != "COMPLETE"
            or any(type(value) is not int or value < 0 for value in unit_actuals.values())
        ):
            raise ValueError("Gate C live typed actual failed validation")
        for key, value in unit_actuals.items():
            observed_cumulative_actuals[key] += value
            if assignment_id in expected_pending:
                remaining_actuals[key] += value
    typed_budgets = receipt.get("typed_budgets")
    if (
        type(receipt_id) is not str
        or not receipt_id
        or type(pilot_snapshot_id) is not str
        or not pilot_snapshot_id
        or receipt.get("gate_c_live_id") != live.get("gate_c_live_id")
        or type(receipt_source_plan) is not dict
        or receipt_source_plan.get("manifest_sha256") != source_plan_manifest_sha256
        or type(receipt_app_config) is not dict
        or receipt_app_config.get("sha256") != app_config_sha256
        or type(receipt_base_config) is not dict
        or receipt_base_config.get("sha256") != base_live_config_sha256
        or type(receipt_pilot) is not dict
        or receipt_pilot.get("assignment_id") != pilot_assignment_id
        or receipt_pilot.get("phase_snapshot_id") != pilot_snapshot_id
        or receipt_pilot.get("phase_snapshot_sha256") != pilot_snapshot_sha256
        or tuple(receipt.get("authorized_assignment_ids", ())) != expected_pending
        or type(typed_budgets) is not dict
        or any(type(value) is not int or value < 0 for value in cumulative_actuals.values())
        or observed_cumulative_actuals != cumulative_actuals
        or any(
            type(typed_budgets.get(key)) is not dict
            or remaining_actuals[key] > typed_budgets[key].get("maximum", -1)
            for key in remaining_actuals
        )
        or not all(
            _is_sha256(value)
            for value in (
                source_plan_manifest_sha256,
                app_config_sha256,
                base_live_config_sha256,
            )
        )
    ):
        raise ValueError("Gate C live final root provenance failed validation")
    provenance_payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "provenance_version": "gate_c_live_final_root_v2",
        "status": "GATE_C_LIVE_ROOT_READY",
        "completion_marker": "artifact-manifest.json",
        "scientific_claim_allowed": False,
        "gate_c_live_id": live["gate_c_live_id"],
        "source_plan_manifest_sha256": source_plan_manifest_sha256,
        "app_config_sha256": app_config_sha256,
        "base_live_config_sha256": base_live_config_sha256,
        "pilot_phase_snapshot_id": pilot_snapshot_id,
        "pilot_phase_snapshot_sha256": pilot_snapshot_sha256,
        "authorization_receipt_id": receipt_id,
        "authorization_receipt_path": receipt_relative_path,
        "authorization_receipt_sha256": sha256_file(authorization_receipt_path),
        "final_phase_report_path": phase_report_relative_path,
        "final_phase_report_sha256": sha256_file(phase_report_path),
        "root_report_sha256": sha256_file(root_report_path),
        "completed_assignment_ids": list(completed),
        "completed_assignment_ids_sha256": hashlib.sha256(_canonical(list(completed))).hexdigest(),
        "typed_remaining_actuals": remaining_actuals,
        "typed_cumulative_actuals": cumulative_actuals,
    }
    provenance = _content_addressed_payload(
        provenance_payload,
        id_key="root_provenance_id",
        prefix="gate_c_live_root_provenance_",
    )
    provenance_path = output_dir / "root-provenance.json"
    if provenance_path.exists():
        if _read_json(provenance_path) != provenance:
            raise ValueError("Gate C live existing root provenance failed validation")
    else:
        write_json_atomic_exclusive(provenance_path, provenance)
    return write_closed_manifest_atomic(output_dir, label="Gate C live final root")


def _summary(
    output_dir: Path,
    expected: int,
    phase: str,
    *,
    task_selection_policy: str,
    arm_roles: tuple[str, ...],
) -> dict[str, object]:
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
        **_report_contract_fields(task_selection_policy, arm_roles),
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
    source_plan_manifest_sha256 = sha256_file(plan_dir / "artifact-manifest.json")
    _validate_required_source_plan_contract(
        live,
        plan_report=plan_report,
        source_plan_manifest_sha256=source_plan_manifest_sha256,
    )
    app_config_id = _path_id(repo_root, app_config_path)
    app_config_sha256 = sha256_file(app_config_path)
    expected = int(live.get("expected_assignments", 0))
    task_selection_policy = str(live.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY))
    task_count, arm_roles = _validated_plan_dimensions(
        plan_report,
        expected_assignments=expected,
        task_selection_policy=task_selection_policy,
    )
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
            **_report_contract_fields(task_selection_policy, arm_roles),
            "provider_calls": 0,
            "oracle_executions": 0,
            "validated_assignments": len(selected),
            "pending": len(selected),
            "pilot_assignment_id": pilot_id,
            "source_plan_manifest_sha256": source_plan_manifest_sha256,
        }
        _write_json(output_dir / "report.json", report)
        write_closed_manifest_atomic(output_dir, label="Gate C live preflight")
        return report
    pilot_snapshot: dict[str, object] | None = None
    authorization_receipt_path: Path | None = None
    authorization_receipt_inputs: dict[str, Any] | None = None
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
                "app_config_sha256": app_config_sha256,
                "source_plan_manifest_sha256": source_plan_manifest_sha256,
            },
        )
        phase_name = "phase-001-pilot"
        root_report_name = "report-pilot.json"
    else:
        if pilot_id not in completed:
            raise ValueError("Gate C live pilot has not completed")
        input_provenance = _read_json(output_dir / "input-provenance.json")
        base_live_config_sha256 = sha256_file(output_dir / "live-config.json")
        if (
            input_provenance.get("app_config_sha256") != app_config_sha256
            or input_provenance.get("source_plan_manifest_sha256") != source_plan_manifest_sha256
        ):
            raise ValueError("Gate C live remaining input provenance failed validation")
        pilot_snapshot = _verify_pilot_phase_snapshot(
            output_dir,
            live=stored_base,
            source_plan_manifest_sha256=source_plan_manifest_sha256,
            app_config_id=app_config_id,
            app_config_sha256=app_config_sha256,
            base_live_config_sha256=base_live_config_sha256,
        )
        authorized_assignment_ids = tuple(sorted(set(assignment_by_id) - {pilot_id}))
        selected = tuple(sorted(set(assignment_by_id) - completed))
        if not selected or not set(selected).issubset(authorized_assignment_ids):
            raise ValueError("Gate C live has no pending assignments")
        remaining_attempt = _next_remaining_attempt(output_dir)
        remaining_suffix = "" if remaining_attempt == 1 else f"-{remaining_attempt:03d}"
        receipt_inputs: dict[str, Any] = {
            "live": live,
            "source_plan_id": str(live["source_plan_dir"]),
            "source_plan_manifest_sha256": source_plan_manifest_sha256,
            "app_config_id": app_config_id,
            "app_config_sha256": app_config_sha256,
            "base_live_config_sha256": base_live_config_sha256,
            "pilot_snapshot_id": str(pilot_snapshot["pilot_phase_snapshot_id"]),
            "pilot_snapshot_sha256": sha256_file(
                output_dir / "phases" / "phase-001-pilot" / "phase-snapshot.json"
            ),
            "authorized_assignment_ids": authorized_assignment_ids,
        }
        authorization_receipt_inputs = receipt_inputs
        authorization_receipt_path, receipt = _load_or_create_authorization_receipt(
            output_dir,
            allow_create=remaining_attempt == 1,
            expected_inputs=receipt_inputs,
        )
        _write_or_verify_durable_json(
            output_dir / _REMAINING_LIVE_CONFIG_NAME,
            live,
            allow_create=remaining_attempt == 1,
            label="remaining live config",
        )
        remaining_input_provenance: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "live_config_sha256": sha256_file(live_config_path),
            "stored_base_live_config_sha256": base_live_config_sha256,
            "app_config_sha256": app_config_sha256,
            "source_plan_manifest_sha256": source_plan_manifest_sha256,
            "scale_up_authorization_id": live["scale_up_authorization_id"],
            "scale_up_authorization_scope": _SCALE_UP_AUTHORIZATION_SCOPE,
            "authorization_receipt_id": receipt["authorization_receipt_id"],
            "authorization_receipt_path": _AUTHORIZATION_RECEIPT_NAME,
            "authorization_receipt_sha256": sha256_file(authorization_receipt_path),
            "authorized_assignment_ids": list(authorized_assignment_ids),
        }
        _write_or_verify_durable_json(
            output_dir / _REMAINING_INPUT_PROVENANCE_NAME,
            remaining_input_provenance,
            allow_create=remaining_attempt == 1,
            label="remaining input provenance",
        )
        _write_json(
            output_dir / f"command-remaining{remaining_suffix}.json",
            {"argv": list(command_argv)},
        )
        _write_json(
            output_dir / f"environment-remaining{remaining_suffix}.json",
            _environment(),
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
    summary = _summary(
        output_dir,
        expected,
        mode,
        task_selection_policy=task_selection_policy,
        arm_roles=arm_roles,
    )
    _write_json(phase_dir / "report.json", summary)
    if mode == "pilot" or failure is None:
        _write_json(output_dir / root_report_name, summary)
    if failure is not None:
        raise RuntimeError(
            "Gate C live phase failed; preserved unit artifacts require diagnosis"
        ) from failure
    if mode == "pilot":
        _write_pilot_phase_snapshot(
            output_dir,
            live=live,
            source_plan_manifest_sha256=source_plan_manifest_sha256,
            app_config_id=app_config_id,
            app_config_sha256=app_config_sha256,
            base_live_config_sha256=sha256_file(output_dir / "live-config.json"),
        )
    else:
        if (
            pilot_snapshot is None
            or authorization_receipt_path is None
            or authorization_receipt_inputs is None
        ):
            raise RuntimeError("Gate C live finalization inputs are unavailable")
        _finalize_live_root(
            output_dir,
            live=live,
            summary=summary,
            expected_assignment_ids=tuple(sorted(assignment_by_id)),
            source_plan_manifest_sha256=source_plan_manifest_sha256,
            app_config_sha256=app_config_sha256,
            base_live_config_sha256=sha256_file(output_dir / "live-config.json"),
            pilot_snapshot=pilot_snapshot,
            authorization_receipt_path=authorization_receipt_path,
            authorization_receipt_inputs=authorization_receipt_inputs,
            phase_report_path=phase_dir / "report.json",
            root_report_path=output_dir / root_report_name,
        )
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
    source_plan_manifest_sha256 = sha256_file(plan_dir / "artifact-manifest.json")
    _validate_required_source_plan_contract(
        live,
        plan_report=plan_report,
        source_plan_manifest_sha256=source_plan_manifest_sha256,
    )
    expected = int(live.get("expected_assignments", 0))
    task_selection_policy = str(live.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY))
    _, arm_roles = _validated_plan_dimensions(
        plan_report,
        expected_assignments=expected,
        task_selection_policy=task_selection_policy,
    )
    pilot_id = live.get("pilot_assignment_id")
    oracle_decision_mode = live.get("zero_finding_interpretation")
    if (
        live.get("schema_version") != _SCHEMA_VERSION
        or live.get("scientific_claim_allowed") is not False
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
        "source_plan_manifest_sha256": source_plan_manifest_sha256,
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
    summary = _summary(
        output_dir,
        expected,
        "oracle-repair",
        task_selection_policy=task_selection_policy,
        arm_roles=arm_roles,
    )
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

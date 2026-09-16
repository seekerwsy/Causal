"""Independent external measurements with total assignment accounting."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from prompt_mechanism_study.artifact_io import (
    json_object,
    require_sha256 as _digest,
)
from prompt_mechanism_study.functional_judge import (
    JudgeGateError,
    build_review_request,
    code_syntax_valid,
    functional_source_scope,
    syntax_parser_identity,
    validate_review_response,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique
from prompt_mechanism_study.security_profiles import evaluate_security_profile


class MeasurementExecutionError(ValueError):
    """A generation or evaluator response violated the frozen measurement contract."""


class CodeStatus(StrEnum):
    VALID = "valid"
    NO_CODE = "no_code"
    INVALID = "invalid"


class OracleStatus(StrEnum):
    SECURE = "secure"
    INSECURE = "insecure"
    UNKNOWN = "unknown"
    NOT_RUN = "not_run"


class FunctionalStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_RUN = "not_run"


@dataclass(frozen=True, slots=True)
class Measurement:
    assignment_id: str
    code_status: CodeStatus
    oracle_status: OracleStatus
    functional_status: FunctionalStatus
    generator_evidence_sha256: str
    code_sha256: str | None = None
    oracle_evidence_sha256: str | None = None
    functional_evidence_sha256: str | None = None
    terminal_reason: str | None = None

    def __post_init__(self) -> None:
        require_text(self.assignment_id, "assignment_id")
        if type(self.code_status) is not CodeStatus:
            raise TypeError("code_status must be a CodeStatus")
        if type(self.oracle_status) is not OracleStatus:
            raise TypeError("oracle_status must be an OracleStatus")
        if type(self.functional_status) is not FunctionalStatus:
            raise TypeError("functional_status must be a FunctionalStatus")
        _digest(self.generator_evidence_sha256, "generator_evidence_sha256")
        if self.code_status is CodeStatus.VALID:
            _digest(self.code_sha256, "valid code_sha256")
            _digest(self.oracle_evidence_sha256, "oracle_evidence_sha256")
            _digest(self.functional_evidence_sha256, "functional_evidence_sha256")
            if self.oracle_status is OracleStatus.NOT_RUN:
                raise ValueError("valid code requires an Oracle result")
            if self.functional_status is FunctionalStatus.NOT_RUN:
                raise ValueError("valid code requires a functional result")
            if self.terminal_reason is not None:
                raise ValueError("valid code cannot have a terminal reason")
        else:
            if self.oracle_status is not OracleStatus.NOT_RUN:
                raise ValueError("terminal code cannot have an Oracle label")
            if self.functional_status is not FunctionalStatus.NOT_RUN:
                raise ValueError("terminal code cannot have a functional label")
            require_text(self.terminal_reason, "terminal_reason")
            if self.code_sha256 is not None:
                _digest(self.code_sha256, "code_sha256")
            if (
                self.oracle_evidence_sha256 is not None
                or self.functional_evidence_sha256 is not None
            ):
                raise ValueError("a non-run evaluator cannot have evidence")

    @property
    def measurement_id(self) -> str:
        return content_id("measurement_", self)


@dataclass(frozen=True, slots=True)
class InfrastructureFailure:
    assignment_id: str
    producer: str
    reason: str

    def __post_init__(self) -> None:
        require_text(self.assignment_id, "assignment_id")
        require_text(self.producer, "producer")
        require_text(self.reason, "reason")


@dataclass(frozen=True, slots=True)
class MeasurementLedger:
    study_id: str
    randomization_id: str
    adapter_bundle_id: str
    measurements: tuple[Measurement, ...]

    def __post_init__(self) -> None:
        require_text(self.study_id, "study_id")
        require_text(self.randomization_id, "randomization_id")
        require_text(self.adapter_bundle_id, "adapter_bundle_id")
        require_unique(
            (item.assignment_id for item in self.measurements), "measurement assignments"
        )

    @property
    def ledger_id(self) -> str:
        return content_id("ledger_", self)


def measure_generated_code(
    *,
    assignment_id: str,
    generation_request: Mapping[str, Any],
    generation_evaluator: Mapping[str, Any],
    generation_prompt: str,
    source_task_prompt: str,
    functional_contract: Mapping[str, Any],
    functional_evaluator: Mapping[str, Any],
    functional_prompt: str,
    security_profile_id: str,
    complete: Callable[[dict[str, Any], Mapping[str, Any], str], bytes],
    security_evaluate: Callable[[str, str], Mapping[str, Any]] = evaluate_security_profile,
    security_replay: Callable[[str, str], Mapping[str, Any]] | None = None,
) -> tuple[Measurement, dict[str, Any]]:
    """Execute the one active generated-code measurement sequence."""

    request = dict(generation_request)
    language = functional_contract.get("language", request.get("language", "python"))
    if not isinstance(language, str) or not language:
        raise MeasurementExecutionError("functional contract language is invalid")
    if request.get("language", language) != language:
        raise MeasurementExecutionError("generation and measurement languages differ")
    if not isinstance(security_profile_id, str) or not security_profile_id.startswith(language + "."):
        raise MeasurementExecutionError("security profile language differs from the task")
    if ("source_prompt_sha256" in functional_contract
            and functional_contract["source_prompt_sha256"] != content_hash(source_task_prompt)):
        raise MeasurementExecutionError("functional contract is bound to a different source prompt")
    parser_identity = syntax_parser_identity(language)
    functional_scope = functional_source_scope(functional_contract)
    raw = complete(request, generation_evaluator, generation_prompt)
    if not isinstance(raw, bytes):
        raise MeasurementExecutionError("generation provider response is not bytes")
    response = _json_object(raw, "generation response")
    if set(response) != {"code"} or not isinstance(response["code"], str):
        raise MeasurementExecutionError("generation response schema drift")
    code = response["code"]
    generator_digest = hashlib.sha256(raw).hexdigest()
    syntax_valid = code_syntax_valid(code, language)
    evidence: dict[str, Any] = {
        "generation_request": request,
        "generation_response": raw.decode("utf-8"),
        "generation_response_sha256": generator_digest,
        "code": code,
        "syntax_valid": syntax_valid,
        "syntax_parser": parser_identity,
        "functional_source_scope": functional_scope,
        "functional_review_policy": "judge_all_syntax_valid_source_scopes",
        "security": None,
        "functional_request": None,
        "functional_response": None,
        "functional_response_sha256": None,
        "functional_validated": None,
    }
    if not code.strip() or not syntax_valid:
        status = CodeStatus.NO_CODE if not code.strip() else CodeStatus.INVALID
        return (
            Measurement(
                assignment_id,
                status,
                OracleStatus.NOT_RUN,
                FunctionalStatus.NOT_RUN,
                generator_digest,
                content_hash(code) if code else None,
                terminal_reason=status.value,
            ),
            evidence,
        )

    security = security_evaluate(code, security_profile_id)
    if not isinstance(security, Mapping) or security.get("security_label") not in {
        "secure",
        "insecure",
        "unknown",
    }:
        raise MeasurementExecutionError("security Oracle response schema drift")
    security = dict(security)
    if security_replay is not None and security != security_replay(
        code,
        security_profile_id,
    ):
        raise MeasurementExecutionError(
            "security Oracle response does not replay from the frozen local profile"
        )
    requirements = _mapping_list(
        functional_contract.get("requirements", []),
        "functional requirements",
    )
    dependencies = _string_list(
        functional_contract.get("environment_dependencies", []),
        "functional environment dependencies",
    )
    if not functional_contract.get("parent_contract_applies_to_current_input", True):
        # A restored source is reviewed directly, without its former input's summary.
        requirements, dependencies = [], []
    functional_request = build_review_request(
        code,
        source_task_prompt,
        requirements=requirements,
        environment_dependencies=dependencies,
        language=language,
        source_scope=functional_scope,
    )
    functional_raw = None
    functional_failure = None
    try:
        functional_raw = complete(functional_request, functional_evaluator, functional_prompt)
        if not isinstance(functional_raw, bytes):
            functional_raw = None
            raise MeasurementExecutionError("functional provider response is not bytes")
        functional = validate_review_response(functional_raw, code)
    except (JudgeGateError, MeasurementExecutionError) as error:
        # A failed secondary evaluator cannot erase the independently measured
        # primary security endpoint. Keep functionality/joint unknown, with the
        # exact failure and any raw response, rather than filtering the assignment.
        functional_failure = {"error_type": type(error).__name__, "error_message": str(error)}
        functional = {"status": "unknown", "reason": "functional_evaluator_failed",
                      "failure": functional_failure}
    functional_digest = (hashlib.sha256(functional_raw).hexdigest() if functional_raw is not None
                         else content_hash(functional_failure))
    evidence.update(
        {
            "security": security,
            "functional_request": functional_request,
            "functional_response": functional_raw.decode("utf-8") if functional_raw is not None else None,
            "functional_response_sha256": functional_digest if functional_raw is not None else None,
            "functional_validated": functional,
        }
    )
    if functional_failure is not None:
        evidence["functional_failure"] = functional_failure
    return (
        Measurement(
            assignment_id,
            CodeStatus.VALID,
            OracleStatus(security["security_label"]),
            FunctionalStatus(functional["status"]),
            generator_digest,
            content_hash(code),
            content_hash(security),
            functional_digest,
        ),
        evidence,
    )


def close_target_measurements(
    assignments: Iterable[object],
    measurements: Iterable[Measurement],
    *,
    study_id: str,
    randomization_id: str,
    adapter_bundle_id: str,
    infrastructure_failures: Iterable[InfrastructureFailure] = (),
) -> MeasurementLedger:
    """Close target assigned arms through the shared measurement contract."""

    failures = tuple(infrastructure_failures)
    if failures:
        raise ValueError("infrastructure failures require repair or replay before analysis")
    frozen_assignments = tuple(assignments)
    if any(
        not isinstance(getattr(item, "assignment_id", None), str)
        or not item.assignment_id
        for item in frozen_assignments
    ):
        raise TypeError("target assignments must expose non-empty assignment identities")
    expected = {item.assignment_id for item in frozen_assignments}
    if len(expected) != len(frozen_assignments):
        raise ValueError("target assignment identities must be unique")
    return _close_measurement_ledger(
        expected,
        measurements,
        study_id,
        randomization_id,
        adapter_bundle_id,
    )


def _close_measurement_ledger(
    expected: set[str],
    measurements: Iterable[Measurement],
    study_id: str,
    randomization_id: str,
    adapter_bundle_id: str,
) -> MeasurementLedger:
    require_text(study_id, "measurement study_id")
    require_text(randomization_id, "measurement randomization_id")
    require_text(adapter_bundle_id, "measurement adapter_bundle_id")
    frozen = tuple(sorted(measurements, key=lambda item: item.assignment_id))
    if any(type(item) is not Measurement for item in frozen):
        raise TypeError("measurements must contain Measurement values")
    observed = tuple(item.assignment_id for item in frozen)
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("measurements must close every randomized assignment exactly once")
    return MeasurementLedger(
        study_id,
        randomization_id,
        adapter_bundle_id,
        frozen,
    )


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return json_object(raw)
    except ValueError:
        raise MeasurementExecutionError(f"{label} is invalid JSON") from None


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise MeasurementExecutionError(f"{label} must be a list of non-empty strings")
    return value


def _mapping_list(value: Any, label: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise MeasurementExecutionError(f"{label} must be a list of objects")
    return value


__all__ = [
    "CodeStatus",
    "FunctionalStatus",
    "InfrastructureFailure",
    "Measurement",
    "MeasurementExecutionError",
    "MeasurementLedger",
    "OracleStatus",
    "close_target_measurements",
    "measure_generated_code",
]

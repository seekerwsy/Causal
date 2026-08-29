"""Independent external measurements with total assignment accounting."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from prompt_mechanism_study.adapters import AdapterBundle
from prompt_mechanism_study.artifact_io import (
    json_object,
    require_sha256 as _digest,
)
from prompt_mechanism_study.functional_judge import (
    build_review_request,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.randomization import (
    FactorialRandomization,
    SuccessorRandomization,
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
    raw = complete(request, generation_evaluator, generation_prompt)
    if not isinstance(raw, bytes):
        raise MeasurementExecutionError("generation provider response is not bytes")
    response = _json_object(raw, "generation response")
    if set(response) != {"code"} or not isinstance(response["code"], str):
        raise MeasurementExecutionError("generation response schema drift")
    code = response["code"]
    generator_digest = hashlib.sha256(raw).hexdigest()
    language = functional_contract.get("language", request.get("language", "python"))
    if not isinstance(language, str) or not language:
        raise MeasurementExecutionError("functional contract language is invalid")
    syntax_valid = language == "python" and python_syntax_valid(code)
    evidence: dict[str, Any] = {
        "generation_request": request,
        "generation_response": raw.decode("utf-8"),
        "generation_response_sha256": generator_digest,
        "code": code,
        "syntax_valid": syntax_valid,
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
        functional_contract.get("requirements"),
        "functional requirements",
    )
    dependencies = _string_list(
        functional_contract.get("environment_dependencies"),
        "functional environment dependencies",
    )
    functional_request = build_review_request(
        code,
        source_task_prompt,
        requirements=requirements,
        environment_dependencies=dependencies,
        language=language,
    )
    functional_raw = complete(
        functional_request,
        functional_evaluator,
        functional_prompt,
    )
    if not isinstance(functional_raw, bytes):
        raise MeasurementExecutionError("functional provider response is not bytes")
    functional = validate_review_response(functional_raw, code)
    functional_digest = hashlib.sha256(functional_raw).hexdigest()
    evidence.update(
        {
            "security": security,
            "functional_request": functional_request,
            "functional_response": functional_raw.decode("utf-8"),
            "functional_response_sha256": functional_digest,
            "functional_validated": functional,
        }
    )
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


def close_measurements(
    randomization: SuccessorRandomization | FactorialRandomization,
    adapters: AdapterBundle,
    measurements: Iterable[Measurement],
    *,
    study_id: str,
    infrastructure_failures: Iterable[InfrastructureFailure] = (),
) -> MeasurementLedger:
    failures = tuple(infrastructure_failures)
    if failures:
        raise ValueError("infrastructure failures require repair or replay before analysis")
    frozen = tuple(sorted(measurements, key=lambda item: item.assignment_id))
    observed = tuple(item.assignment_id for item in frozen)
    expected = {item.assignment_id for item in randomization.assignments}
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("measurements must close every randomized assignment exactly once")
    return MeasurementLedger(
        study_id,
        randomization.randomization_id,
        adapters.adapter_bundle_id,
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
    "close_measurements",
    "measure_generated_code",
]

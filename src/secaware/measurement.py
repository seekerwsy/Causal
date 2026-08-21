"""Independent external measurements with total assignment accounting."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from secaware.adapters import AdapterBundle
from secaware.randomization import Randomization
from secaware.records import content_id, require_text, require_unique


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


def close_measurements(
    randomization: Randomization,
    adapters: AdapterBundle,
    measurements: Iterable[Measurement],
    *,
    study_id: str,
    infrastructure_failures: Iterable[InfrastructureFailure] = (),
) -> MeasurementLedger:
    failures = tuple(infrastructure_failures)
    if failures:
        raise ValueError("infrastructure failures require repair or replay before analysis")
    frozen = tuple(sorted(tuple(measurements), key=lambda item: item.assignment_id))
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


def _digest(value: str | None, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


__all__ = [
    "CodeStatus",
    "FunctionalStatus",
    "InfrastructureFailure",
    "Measurement",
    "MeasurementLedger",
    "OracleStatus",
    "close_measurements",
]

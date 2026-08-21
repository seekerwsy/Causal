"""Independent security/functionality measurements and total accounting."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from secaware.randomization import Randomization
from secaware.records import content_id, require_text, require_unique


class SecurityLabel(StrEnum):
    SECURE = "secure"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


class FunctionalLabel(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Measurement:
    assignment_id: str
    security: SecurityLabel
    functionality: FunctionalLabel

    def __post_init__(self) -> None:
        require_text(self.assignment_id, "assignment_id")
        if type(self.security) is not SecurityLabel:
            raise TypeError("security must be a SecurityLabel")
        if type(self.functionality) is not FunctionalLabel:
            raise TypeError("functionality must be a FunctionalLabel")

    @property
    def measurement_id(self) -> str:
        return content_id("measurement_", self)


@dataclass(frozen=True, slots=True)
class TerminalFailure:
    assignment_id: str
    stage: str

    def __post_init__(self) -> None:
        require_text(self.assignment_id, "assignment_id")
        require_text(self.stage, "stage")


@dataclass(frozen=True, slots=True)
class MeasurementLedger:
    randomization_id: str
    measurements: tuple[Measurement, ...]
    failures: tuple[TerminalFailure, ...]

    def __post_init__(self) -> None:
        require_text(self.randomization_id, "randomization_id")
        ids = tuple(item.assignment_id for item in self.measurements) + tuple(
            item.assignment_id for item in self.failures
        )
        require_unique(ids, "ledger assignment ids")

    @property
    def ledger_id(self) -> str:
        return content_id("ledger_", self)


def close_measurements(
    randomization: Randomization,
    measurements: Iterable[Measurement],
    failures: Iterable[TerminalFailure] = (),
) -> MeasurementLedger:
    """Require one terminal record for every randomized assignment."""

    frozen_measurements = tuple(sorted(measurements, key=lambda item: item.assignment_id))
    frozen_failures = tuple(sorted(failures, key=lambda item: item.assignment_id))
    observed = {item.assignment_id for item in frozen_measurements} | {
        item.assignment_id for item in frozen_failures
    }
    expected = {item.assignment_id for item in randomization.assignments}
    if observed != expected:
        raise ValueError("measurement ledger must close every randomized assignment")
    return MeasurementLedger(
        randomization.randomization_id,
        frozen_measurements,
        frozen_failures,
    )


__all__ = [
    "FunctionalLabel",
    "Measurement",
    "MeasurementLedger",
    "SecurityLabel",
    "TerminalFailure",
    "close_measurements",
]

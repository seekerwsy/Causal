"""Deterministic outcome projection with explicit unknown states."""

from __future__ import annotations

from dataclasses import dataclass

from secaware.measurement import (
    FunctionalLabel,
    MeasurementLedger,
    SecurityLabel,
)
from secaware.records import content_id


@dataclass(frozen=True, slots=True)
class Outcome:
    assignment_id: str
    security: int | None
    functionality: int | None
    joint: int | None
    terminal_failure: bool

    @property
    def outcome_id(self) -> str:
        return content_id("outcome_", self)


def derive_outcomes(ledger: MeasurementLedger) -> tuple[Outcome, ...]:
    outcomes = [
        Outcome(
            assignment_id=item.assignment_id,
            security=_binary(item.security, SecurityLabel.SECURE, SecurityLabel.INSECURE),
            functionality=_binary(
                item.functionality,
                FunctionalLabel.PASS,
                FunctionalLabel.FAIL,
            ),
            joint=_joint(item.security, item.functionality),
            terminal_failure=False,
        )
        for item in ledger.measurements
    ]
    outcomes.extend(Outcome(item.assignment_id, None, None, None, True) for item in ledger.failures)
    return tuple(sorted(outcomes, key=lambda item: item.assignment_id))


def _binary(value: object, positive: object, negative: object) -> int | None:
    if value is positive:
        return 1
    if value is negative:
        return 0
    return None


def _joint(security: SecurityLabel, functionality: FunctionalLabel) -> int | None:
    if security is SecurityLabel.INSECURE or functionality is FunctionalLabel.FAIL:
        return 0
    if security is SecurityLabel.SECURE and functionality is FunctionalLabel.PASS:
        return 1
    return None


__all__ = ["Outcome", "derive_outcomes"]

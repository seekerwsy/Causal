"""Total outcome decomposition for code, Oracle, functionality, and joint yield."""

from __future__ import annotations

from dataclasses import dataclass

from secaware.measurement import (
    CodeStatus,
    FunctionalStatus,
    MeasurementLedger,
    OracleStatus,
)
from secaware.records import content_id


@dataclass(frozen=True, slots=True)
class Outcome:
    assignment_id: str
    code_valid: int
    oracle_evaluable: int
    secure_yield: int
    latent_secure_upper: int
    functionality: int | None
    joint: int | None
    latent_joint_upper: int
    terminal_status: str | None

    @property
    def outcome_id(self) -> str:
        return content_id("outcome_", self)


def derive_outcomes(ledger: MeasurementLedger) -> tuple[Outcome, ...]:
    return tuple(
        sorted(
            (_outcome(item) for item in ledger.measurements),
            key=lambda item: item.assignment_id,
        )
    )


def _outcome(item: object) -> Outcome:
    code_status = item.code_status
    if code_status is not CodeStatus.VALID:
        return Outcome(
            item.assignment_id,
            code_valid=0,
            oracle_evaluable=0,
            secure_yield=0,
            latent_secure_upper=0,
            functionality=0,
            joint=0,
            latent_joint_upper=0,
            terminal_status=code_status.value,
        )

    oracle = item.oracle_status
    evaluable = int(oracle in {OracleStatus.SECURE, OracleStatus.INSECURE})
    secure = int(oracle is OracleStatus.SECURE)
    latent_upper = int(oracle in {OracleStatus.SECURE, OracleStatus.UNKNOWN})
    functionality = _functional(item.functional_status)
    if oracle is OracleStatus.INSECURE or functionality == 0:
        joint = 0
    elif oracle is OracleStatus.UNKNOWN or functionality is None:
        joint = None
    else:
        joint = 1
    latent_joint_upper = int(latent_upper == 1 and functionality != 0)
    return Outcome(
        item.assignment_id,
        code_valid=1,
        oracle_evaluable=evaluable,
        secure_yield=secure,
        latent_secure_upper=latent_upper,
        functionality=functionality,
        joint=joint,
        latent_joint_upper=latent_joint_upper,
        terminal_status=None,
    )


def _functional(status: FunctionalStatus) -> int | None:
    if status is FunctionalStatus.PASS:
        return 1
    if status is FunctionalStatus.FAIL:
        return 0
    return None


__all__ = ["Outcome", "derive_outcomes"]

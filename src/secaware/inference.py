"""Transparent ITT estimates and worst-case unknown bounds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence

from secaware.intervention import Arm
from secaware.outcomes import Outcome
from secaware.randomization import Randomization
from secaware.records import content_id


Dimension = Literal["security", "functionality", "joint"]


@dataclass(frozen=True, slots=True)
class ArmSummary:
    arm: Arm
    total: int
    observed: int
    successes: int
    unknown: int
    mean: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class ITTEstimate:
    dimension: Dimension
    target: ArmSummary
    control: ArmSummary
    difference: float | None
    lower: float
    upper: float

    @property
    def estimate_id(self) -> str:
        return content_id("itt_", self)


def estimate_itt(
    randomization: Randomization,
    outcomes: Sequence[Outcome],
    *,
    dimension: Dimension = "security",
    target_arm: Arm = Arm.TARGET,
    control_arm: Arm = Arm.NOOP,
) -> ITTEstimate:
    """Estimate target-minus-control without deleting unknown or failed units."""

    by_id = {outcome.assignment_id: outcome for outcome in outcomes}
    expected = {assignment.assignment_id for assignment in randomization.assignments}
    if len(by_id) != len(outcomes) or set(by_id) != expected:
        raise ValueError("outcomes must cover the complete randomized assignment set")
    target = _summarize(randomization, by_id, target_arm, dimension)
    control = _summarize(randomization, by_id, control_arm, dimension)
    difference = None if target.mean is None or control.mean is None else target.mean - control.mean
    return ITTEstimate(
        dimension=dimension,
        target=target,
        control=control,
        difference=difference,
        lower=target.lower - control.upper,
        upper=target.upper - control.lower,
    )


def _summarize(
    randomization: Randomization,
    outcomes: dict[str, Outcome],
    arm: Arm,
    dimension: Dimension,
) -> ArmSummary:
    values = [
        getattr(outcomes[item.assignment_id], dimension)
        for item in randomization.assignments
        if item.arm is arm
    ]
    if not values:
        raise ValueError("requested arm has no assignments")
    known = [value for value in values if value is not None]
    successes = sum(known)
    unknown = len(values) - len(known)
    total = len(values)
    return ArmSummary(
        arm=arm,
        total=total,
        observed=len(known),
        successes=successes,
        unknown=unknown,
        mean=(successes / total if unknown == 0 else None),
        lower=successes / total,
        upper=(successes + unknown) / total,
    )


__all__ = ["ArmSummary", "Dimension", "ITTEstimate", "estimate_itt"]

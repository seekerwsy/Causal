"""Frozen four-arm intervention specifications."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from secaware.records import content_id, require_text
from secaware.representation import Candidate


class Arm(StrEnum):
    TARGET = "target"
    NOOP = "noop"
    PLACEBO = "placebo"
    GENERIC = "generic"


ARM_ORDER = (Arm.TARGET, Arm.NOOP, Arm.PLACEBO, Arm.GENERIC)


@dataclass(frozen=True, slots=True)
class ArmText:
    arm: Arm
    text: str

    def __post_init__(self) -> None:
        if type(self.arm) is not Arm:
            raise TypeError("arm must be an Arm")
        require_text(self.text, "arm text")


@dataclass(frozen=True, slots=True)
class InterventionBundle:
    candidate_id: str
    task_id: str
    arms: tuple[ArmText, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        require_text(self.task_id, "task_id")
        if tuple(item.arm for item in self.arms) != ARM_ORDER:
            raise ValueError("intervention must contain the four arms in canonical order")

    @property
    def intervention_id(self) -> str:
        return content_id("intervention_", self)


def freeze_intervention(
    candidate: Candidate,
    arm_texts: Mapping[Arm, str],
) -> InterventionBundle:
    if set(arm_texts) != set(ARM_ORDER):
        raise ValueError("all and only the four registered arms are required")
    arms = tuple(ArmText(arm, arm_texts[arm]) for arm in ARM_ORDER)
    return InterventionBundle(candidate.candidate_id, candidate.task_id, arms)


__all__ = ["ARM_ORDER", "Arm", "ArmText", "InterventionBundle", "freeze_intervention"]

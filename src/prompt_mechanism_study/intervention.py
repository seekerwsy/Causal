"""Context-conditioned four-arm, multi-realization intervention policies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique
from prompt_mechanism_study.representation import Candidate, Operation


class Arm(StrEnum):
    TARGET = "target"
    NOOP = "noop"
    PLACEBO = "placebo"
    GENERIC = "generic"


ARM_ORDER = (Arm.TARGET, Arm.NOOP, Arm.PLACEBO, Arm.GENERIC)


@dataclass(frozen=True, slots=True)
class ArmDefinition:
    arm: Arm
    semantic_role: str

    def __post_init__(self) -> None:
        if type(self.arm) is not Arm:
            raise TypeError("arm must be an Arm")
        require_text(self.semantic_role, "semantic_role")


@dataclass(frozen=True, slots=True)
class ArmProtocol:
    operation: Operation
    definitions: tuple[ArmDefinition, ...]

    def __post_init__(self) -> None:
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if tuple(item.arm for item in self.definitions) != ARM_ORDER:
            raise ValueError("arm protocol must contain four canonical arms")
        if tuple(item.semantic_role for item in self.definitions) != _roles(self.operation):
            raise ValueError("arm semantics do not match the candidate operation")

    @property
    def arm_protocol_id(self) -> str:
        return content_id("arm_protocol_", self)


@dataclass(frozen=True, slots=True)
class RealizationSpec:
    label: str
    weight: int
    executor_adapter_id: str

    def __post_init__(self) -> None:
        require_text(self.label, "realization label")
        require_text(self.executor_adapter_id, "executor_adapter_id")
        if type(self.weight) is not int or self.weight <= 0:
            raise ValueError("realization weight must be a positive integer")

    @property
    def realization_id(self) -> str:
        return content_id("realization_", self)


@dataclass(frozen=True, slots=True)
class VariantValidation:
    context_invariant: bool
    task_invariant: bool
    non_target_invariant: bool
    allowed_delta: bool
    controls_matched: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        if not all(
            type(value) is bool
            for value in (
                self.context_invariant,
                self.task_invariant,
                self.non_target_invariant,
                self.allowed_delta,
                self.controls_matched,
            )
        ):
            raise TypeError("validation flags must be booleans")
        if len(self.evidence_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.evidence_sha256
        ):
            raise ValueError("validation evidence must be a lowercase SHA-256 digest")
        if not self.passed:
            raise ValueError("only fully validated bundles may enter randomization")

    @property
    def passed(self) -> bool:
        return (
            self.context_invariant
            and self.task_invariant
            and self.non_target_invariant
            and self.allowed_delta
            and self.controls_matched
        )


@dataclass(frozen=True, slots=True)
class ArmVariant:
    arm: Arm
    text: str

    def __post_init__(self) -> None:
        if type(self.arm) is not Arm:
            raise TypeError("arm must be an Arm")
        require_text(self.text, "variant text")

    @property
    def variant_sha256(self) -> str:
        return content_hash(self.text)


@dataclass(frozen=True, slots=True)
class TaskRealizationBundle:
    candidate_id: str
    task_id: str
    semantic_cluster_id: str
    realization_id: str
    arm_protocol_id: str
    variants: tuple[ArmVariant, ...]
    validation: VariantValidation

    def __post_init__(self) -> None:
        for name in (
            "candidate_id",
            "task_id",
            "semantic_cluster_id",
            "realization_id",
            "arm_protocol_id",
        ):
            require_text(getattr(self, name), name)
        if tuple(item.arm for item in self.variants) != ARM_ORDER:
            raise ValueError("bundle must contain four variants in canonical order")

    @property
    def task_bundle_id(self) -> str:
        return content_id("task_bundle_", self)

    def variant(self, arm: Arm) -> ArmVariant:
        return self.variants[ARM_ORDER.index(arm)]


@dataclass(frozen=True, slots=True)
class InterventionPolicy:
    candidate_id: str
    protocol: ArmProtocol
    realizations: tuple[RealizationSpec, ...]
    bundles: tuple[TaskRealizationBundle, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        if not self.realizations or not self.bundles:
            raise ValueError("policy requires realizations and task bundles")
        require_unique((item.realization_id for item in self.realizations), "realization ids")
        require_unique((item.task_bundle_id for item in self.bundles), "task bundle ids")
        realization_ids = {item.realization_id for item in self.realizations}
        for bundle in self.bundles:
            if (
                bundle.candidate_id != self.candidate_id
                or bundle.arm_protocol_id != self.protocol.arm_protocol_id
                or bundle.realization_id not in realization_ids
            ):
                raise ValueError("task bundle drifts from its intervention policy")
        if (
            tuple(sorted(self.realizations, key=lambda item: item.realization_id))
            != self.realizations
        ):
            raise ValueError("realizations must use canonical order")
        if tuple(sorted(self.bundles, key=lambda item: item.task_bundle_id)) != self.bundles:
            raise ValueError("task bundles must use canonical order")

    @property
    def policy_id(self) -> str:
        return content_id("policy_", self)

    def realization_weight(self, realization_id: str) -> int:
        return next(
            item.weight for item in self.realizations if item.realization_id == realization_id
        )


def arm_protocol(operation: Operation) -> ArmProtocol:
    return ArmProtocol(
        operation,
        tuple(
            ArmDefinition(arm, role) for arm, role in zip(ARM_ORDER, _roles(operation), strict=True)
        ),
    )


def freeze_bundle(
    candidate: Candidate,
    *,
    task_id: str,
    semantic_cluster_id: str,
    realization: RealizationSpec,
    arm_texts: Mapping[Arm, str],
    validation: VariantValidation,
) -> TaskRealizationBundle:
    if set(arm_texts) != set(ARM_ORDER):
        raise ValueError("all and only four registered arms are required")
    protocol = arm_protocol(candidate.operation)
    return TaskRealizationBundle(
        candidate.candidate_id,
        task_id,
        semantic_cluster_id,
        realization.realization_id,
        protocol.arm_protocol_id,
        tuple(ArmVariant(arm, arm_texts[arm]) for arm in ARM_ORDER),
        validation,
    )


def freeze_policy(
    candidate: Candidate,
    realizations: tuple[RealizationSpec, ...],
    bundles: tuple[TaskRealizationBundle, ...],
) -> InterventionPolicy:
    return InterventionPolicy(
        candidate.candidate_id,
        arm_protocol(candidate.operation),
        tuple(sorted(realizations, key=lambda item: item.realization_id)),
        tuple(sorted(bundles, key=lambda item: item.task_bundle_id)),
    )


def _roles(operation: Operation) -> tuple[str, ...]:
    if operation is Operation.ADD:
        return (
            "target_patch",
            "noop_rewrite",
            "length_matched_placebo",
            "generic_security_reminder",
        )
    return (
        "target_remove",
        "noop_retain",
        "length_matched_sham_edit",
        "generic_security_replacement",
    )


__all__ = [
    "ARM_ORDER",
    "Arm",
    "ArmDefinition",
    "ArmProtocol",
    "ArmVariant",
    "InterventionPolicy",
    "RealizationSpec",
    "TaskRealizationBundle",
    "VariantValidation",
    "arm_protocol",
    "freeze_bundle",
    "freeze_policy",
]

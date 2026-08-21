"""LLM-realized prompt interventions with outcome-blind semantic validation."""

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
APPEND_SEPARATOR = "\n\n"


class SemanticVerdict(StrEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class InterventionSpec:
    candidate_id: str
    mechanism: str
    operation: Operation
    arm_instructions: tuple[tuple[Arm, str], ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        require_text(self.mechanism, "mechanism")
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if tuple(arm for arm, _ in self.arm_instructions) != ARM_ORDER:
            raise ValueError("intervention spec must contain four canonical arms")
        for _, instruction in self.arm_instructions:
            require_text(instruction, "arm instruction")

    @property
    def intervention_spec_id(self) -> str:
        return content_id("intervention_spec_", self)

    def instruction(self, arm: Arm) -> str:
        return self.arm_instructions[ARM_ORDER.index(arm)][1]


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
class InterventionExecution:
    intervention_text: str
    executor_adapter_id: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        require_text(self.intervention_text, "intervention_text")
        require_text(self.executor_adapter_id, "executor_adapter_id")
        _require_digest(self.evidence_sha256, "executor evidence")


@dataclass(frozen=True, slots=True)
class SemanticValidation:
    task_preserved: SemanticVerdict
    contract_satisfied: SemanticVerdict
    unintended_changes: SemanticVerdict
    contradiction: SemanticVerdict
    validator_adapter_id: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "task_preserved",
            "contract_satisfied",
            "unintended_changes",
            "contradiction",
        ):
            if type(getattr(self, name)) is not SemanticVerdict:
                raise TypeError(f"{name} must be a SemanticVerdict")
        require_text(self.validator_adapter_id, "validator_adapter_id")
        _require_digest(self.evidence_sha256, "validator evidence")

    @property
    def passed(self) -> bool:
        return (
            self.task_preserved is SemanticVerdict.YES
            and self.contract_satisfied is SemanticVerdict.YES
            and self.unintended_changes is SemanticVerdict.NO
            and self.contradiction is SemanticVerdict.NO
        )


@dataclass(frozen=True, slots=True)
class ArmVariant:
    arm: Arm
    execution: InterventionExecution
    prompt_text: str
    validation: SemanticValidation

    def __post_init__(self) -> None:
        if type(self.arm) is not Arm:
            raise TypeError("arm must be an Arm")
        require_text(self.prompt_text, "prompt_text")
        if not self.validation.passed:
            raise ValueError("only semantically validated variants may enter randomization")

    @property
    def variant_sha256(self) -> str:
        return content_hash(self.prompt_text)


@dataclass(frozen=True, slots=True)
class TaskRealizationBundle:
    candidate_id: str
    task_id: str
    semantic_cluster_id: str
    realization_id: str
    intervention_spec_id: str
    source_prompt_sha256: str
    variants: tuple[ArmVariant, ...]

    def __post_init__(self) -> None:
        for name in (
            "candidate_id",
            "task_id",
            "semantic_cluster_id",
            "realization_id",
            "intervention_spec_id",
        ):
            require_text(getattr(self, name), name)
        _require_digest(self.source_prompt_sha256, "source prompt")
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
    spec: InterventionSpec
    realizations: tuple[RealizationSpec, ...]
    bundles: tuple[TaskRealizationBundle, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        if self.spec.candidate_id != self.candidate_id:
            raise ValueError("intervention spec does not bind the policy candidate")
        if not self.realizations or not self.bundles:
            raise ValueError("policy requires realizations and task bundles")
        require_unique((item.realization_id for item in self.realizations), "realization ids")
        require_unique((item.task_bundle_id for item in self.bundles), "task bundle ids")
        realization_ids = {item.realization_id for item in self.realizations}
        for bundle in self.bundles:
            if (
                bundle.candidate_id != self.candidate_id
                or bundle.intervention_spec_id != self.spec.intervention_spec_id
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


def intervention_spec(
    candidate: Candidate,
    arm_instructions: Mapping[Arm, str],
) -> InterventionSpec:
    if set(arm_instructions) != set(ARM_ORDER):
        raise ValueError("all and only four registered arm instructions are required")
    return InterventionSpec(
        candidate.candidate_id,
        candidate.actionable_feature_id,
        candidate.operation,
        tuple((arm, arm_instructions[arm]) for arm in ARM_ORDER),
    )


def freeze_bundle(
    candidate: Candidate,
    *,
    spec: InterventionSpec,
    task_id: str,
    semantic_cluster_id: str,
    source_prompt: str,
    realization: RealizationSpec,
    executions: Mapping[Arm, InterventionExecution],
    validations: Mapping[Arm, SemanticValidation],
) -> TaskRealizationBundle:
    if any(set(values) != set(ARM_ORDER) for values in (executions, validations)):
        raise ValueError("all and only four registered arms are required")
    if spec.candidate_id != candidate.candidate_id or spec.operation is not candidate.operation:
        raise ValueError("intervention spec drifts from its candidate")
    require_text(source_prompt, "source_prompt")
    variants = []
    for arm in ARM_ORDER:
        execution = executions[arm]
        if execution.executor_adapter_id != realization.executor_adapter_id:
            raise ValueError("intervention execution adapter drift")
        prompt_text = assemble_prompt(source_prompt, execution.intervention_text)
        variants.append(
            ArmVariant(
                arm,
                execution,
                prompt_text,
                validations[arm],
            )
        )
    return TaskRealizationBundle(
        candidate.candidate_id,
        task_id,
        semantic_cluster_id,
        realization.realization_id,
        spec.intervention_spec_id,
        content_hash(source_prompt),
        tuple(variants),
    )


def assemble_prompt(source_prompt: str, intervention_text: str) -> str:
    """Apply the sole active edit rule; language semantics remain an LLM concern."""

    require_text(source_prompt, "source_prompt")
    require_text(intervention_text, "intervention_text")
    return source_prompt + APPEND_SEPARATOR + intervention_text


def freeze_policy(
    candidate: Candidate,
    spec: InterventionSpec,
    realizations: tuple[RealizationSpec, ...],
    bundles: tuple[TaskRealizationBundle, ...],
) -> InterventionPolicy:
    return InterventionPolicy(
        candidate.candidate_id,
        spec,
        tuple(sorted(realizations, key=lambda item: item.realization_id)),
        tuple(sorted(bundles, key=lambda item: item.task_bundle_id)),
    )


def _require_digest(value: str, name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


__all__ = [
    "ARM_ORDER",
    "APPEND_SEPARATOR",
    "Arm",
    "ArmVariant",
    "InterventionExecution",
    "InterventionPolicy",
    "InterventionSpec",
    "RealizationSpec",
    "TaskRealizationBundle",
    "SemanticValidation",
    "SemanticVerdict",
    "assemble_prompt",
    "freeze_bundle",
    "freeze_policy",
    "intervention_spec",
]

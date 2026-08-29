"""Replayable complete-block assignment for successor and factorial policies."""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.intervention import (
    FACTORIAL_CELL_ORDER,
    SUCCESSOR_ARM_ROLE_ORDER,
    FactorialCell,
    FactorialPolicy,
    FactorialTaskBundle,
    InterventionPolicyV2,
    PolicyArmRoleV2,
    TaskRealizationBundleV2,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique


@dataclass(frozen=True, slots=True)
class SuccessorBlockKey:
    """Canonical v2 complete-block key from the successor protocol."""

    task_unit_id: str
    task_instance_id: str
    hypothesis_id: str
    target_spec_id: str
    realization_spec_id: str
    task_realization_bundle_id: str
    model_id: str
    arm_protocol_id: str

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            require_text(getattr(self, name), name)

    @property
    def block_id(self) -> str:
        return content_id("successor_block_v2_", self)


@dataclass(frozen=True, slots=True)
class SuccessorAssignment:
    block: SuccessorBlockKey
    request_randomness_slot: int
    arm_role: PolicyArmRoleV2
    arm_label: str
    variant_sha256: str
    provider_seed: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.request_randomness_slot) is not int
            or self.request_randomness_slot < 0
        ):
            raise ValueError("request_randomness_slot must be a non-negative integer")
        if type(self.arm_role) is not PolicyArmRoleV2:
            raise TypeError("arm_role must be a PolicyArmRoleV2")
        require_text(self.arm_label, "arm_label")
        _require_digest(self.variant_sha256, "variant_sha256")
        if self.provider_seed is not None and (
            type(self.provider_seed) is not int or self.provider_seed < 0
        ):
            raise ValueError("provider_seed must be null or non-negative")

    @property
    def assignment_id(self) -> str:
        return content_id("successor_assignment_v2_", self)


@dataclass(frozen=True, slots=True)
class SuccessorRandomization:
    population_id: str
    selection_id: str
    seed: int
    models: tuple[str, ...]
    request_randomness_slots: tuple[int, ...]
    assignments: tuple[SuccessorAssignment, ...]

    def __post_init__(self) -> None:
        require_text(self.population_id, "population_id")
        require_text(self.selection_id, "selection_id")
        if type(self.seed) is not int:
            raise TypeError("seed must be an integer")
        if not require_unique(self.models, "models"):
            raise ValueError("models cannot be empty")
        if not require_unique(self.request_randomness_slots, "request randomness slots"):
            raise ValueError("request randomness slots cannot be empty")
        require_unique((item.assignment_id for item in self.assignments), "assignment ids")

    @property
    def randomization_id(self) -> str:
        return content_id("successor_randomization_v2_", self)


@dataclass(frozen=True, slots=True)
class FactorialBlockKey:
    task_unit_id: str
    task_instance_id: str
    pair_id: str
    pair_context_query_id: str
    joint_realization_id: str
    factorial_task_bundle_id: str
    model_id: str
    factorial_protocol_id: str

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            require_text(getattr(self, name), name)

    @property
    def block_id(self) -> str:
        return content_id("factorial_block_", self)


@dataclass(frozen=True, slots=True)
class FactorialAssignment:
    block: FactorialBlockKey
    request_slot: int
    cell: FactorialCell
    variant_sha256: str
    provider_seed: int | None = None

    def __post_init__(self) -> None:
        if type(self.request_slot) is not int or self.request_slot < 0:
            raise ValueError("request_slot must be a non-negative integer")
        if type(self.cell) is not FactorialCell:
            raise TypeError("cell must be a FactorialCell")
        _require_digest(self.variant_sha256, "variant_sha256")
        if self.provider_seed is not None and (
            type(self.provider_seed) is not int or self.provider_seed < 0
        ):
            raise ValueError("provider_seed must be null or non-negative")

    @property
    def assignment_id(self) -> str:
        return content_id("factorial_assignment_", self)


@dataclass(frozen=True, slots=True)
class FactorialRandomization:
    population_id: str
    selection_id: str
    seed: int
    models: tuple[str, ...]
    slots: tuple[int, ...]
    assignments: tuple[FactorialAssignment, ...]

    def __post_init__(self) -> None:
        require_text(self.population_id, "population_id")
        require_text(self.selection_id, "selection_id")
        if type(self.seed) is not int:
            raise TypeError("seed must be an integer")
        if not require_unique(self.models, "models"):
            raise ValueError("models cannot be empty")
        if not require_unique(self.slots, "slots"):
            raise ValueError("slots cannot be empty")
        require_unique((item.assignment_id for item in self.assignments), "assignment ids")

    @property
    def randomization_id(self) -> str:
        return content_id("factorial_randomization_", self)


def randomize_successor(
    policies: Iterable[InterventionPolicyV2],
    *,
    population_id: str,
    selection_id: str,
    models: Iterable[str],
    request_randomness_slots: Iterable[int],
    seed: int,
    provider_seed: int | None = None,
) -> SuccessorRandomization:
    """Assign all four successor roles inside every complete frozen block."""

    frozen_policies = tuple(
        sorted(policies, key=lambda item: item.intervention_policy_id)
    )
    frozen_models = require_unique(tuple(models), "models")
    frozen_slots = require_unique(
        tuple(request_randomness_slots), "request randomness slots"
    )
    if not frozen_policies or not frozen_models or not frozen_slots:
        raise ValueError("successor policies, models, and request slots cannot be empty")
    if len(frozen_slots) % len(SUCCESSOR_ARM_ROLE_ORDER):
        raise ValueError("request slots must form complete four-arm blocks")
    if any(type(slot) is not int or slot < 0 for slot in frozen_slots):
        raise ValueError("request randomness slots must be non-negative integers")
    if provider_seed is not None and (type(provider_seed) is not int or provider_seed < 0):
        raise ValueError("provider_seed must be null or non-negative")

    assignments: list[SuccessorAssignment] = []
    for policy in frozen_policies:
        protocol = policy.realization_policy.arm_protocol
        for bundle in policy.bundles:
            for model_id in frozen_models:
                block = _successor_block(policy, bundle, model_id)
                roles = list(SUCCESSOR_ARM_ROLE_ORDER) * (
                    len(frozen_slots) // len(SUCCESSOR_ARM_ROLE_ORDER)
                )
                block_seed = int(
                    content_hash({"seed": seed, "block_id": block.block_id})[:16],
                    16,
                )
                random.Random(block_seed).shuffle(roles)
                assignments.extend(
                    SuccessorAssignment(
                        block,
                        slot,
                        role,
                        protocol.label(role),
                        bundle.variant(role).variant_sha256,
                        None
                        if provider_seed is None
                        else int(
                            content_hash(
                                {
                                    "provider_seed": provider_seed,
                                    "block_id": block.block_id,
                                    "request_randomness_slot": slot,
                                    "arm_role": role,
                                }
                            )[:8],
                            16,
                        )
                        & 0x7FFFFFFF,
                    )
                    for slot, role in zip(frozen_slots, roles, strict=True)
                )
    result = SuccessorRandomization(
        population_id,
        selection_id,
        seed,
        frozen_models,
        frozen_slots,
        tuple(assignments),
    )
    verify_successor_randomization(result, frozen_policies)
    return result


def verify_successor_randomization(
    result: SuccessorRandomization,
    policies: Iterable[InterventionPolicyV2],
) -> None:
    expected = {
        _successor_block(policy, bundle, model_id).block_id: (
            _successor_block(policy, bundle, model_id),
            policy,
            bundle,
        )
        for policy in policies
        for bundle in policy.bundles
        for model_id in result.models
    }
    if {item.block.block_id for item in result.assignments} != set(expected):
        raise ValueError("successor randomization block support drift")
    for block_id, (expected_block, policy, bundle) in expected.items():
        block = [item for item in result.assignments if item.block.block_id == block_id]
        if len(block) != len(result.request_randomness_slots) or {
            item.request_randomness_slot for item in block
        } != set(result.request_randomness_slots):
            raise ValueError("successor randomization slot support drift")
        counts = Counter(item.arm_role for item in block)
        if set(counts) != set(SUCCESSOR_ARM_ROLE_ORDER) or len(set(counts.values())) != 1:
            raise ValueError("successor arms are not balanced inside a complete block")
        protocol = policy.realization_policy.arm_protocol
        if any(
            item.block != expected_block
            or item.arm_label != protocol.label(item.arm_role)
            or item.variant_sha256 != bundle.variant(item.arm_role).variant_sha256
            for item in block
        ):
            raise ValueError("successor assignment block, arm, or variant binding drift")


def randomize_factorial(
    policies: Iterable[FactorialPolicy],
    *,
    population_id: str,
    selection_id: str,
    models: Iterable[str],
    slots: Iterable[int],
    seed: int,
    provider_seed: int | None = None,
) -> FactorialRandomization:
    frozen_policies = tuple(sorted(policies, key=lambda item: item.policy_id))
    frozen_models = require_unique(tuple(models), "models")
    frozen_slots = require_unique(tuple(slots), "slots")
    if not frozen_policies or not frozen_models or not frozen_slots:
        raise ValueError("factorial policies, models, and slots cannot be empty")
    if len(frozen_slots) % len(FACTORIAL_CELL_ORDER):
        raise ValueError("slots must form complete A00/A10/A01/A11 blocks")
    if any(type(slot) is not int or slot < 0 for slot in frozen_slots):
        raise ValueError("slots must be non-negative integers")
    if provider_seed is not None and (type(provider_seed) is not int or provider_seed < 0):
        raise ValueError("provider_seed must be null or non-negative")
    assignments: list[FactorialAssignment] = []
    for policy in frozen_policies:
        for bundle in policy.bundles:
            for model_id in frozen_models:
                block = _factorial_block(policy, bundle, model_id)
                cells = list(FACTORIAL_CELL_ORDER) * (
                    len(frozen_slots) // len(FACTORIAL_CELL_ORDER)
                )
                block_seed = int(
                    content_hash({"seed": seed, "block_id": block.block_id})[:16], 16
                )
                random.Random(block_seed).shuffle(cells)
                assignments.extend(
                    FactorialAssignment(
                        block,
                        slot,
                        cell,
                        bundle.variant(cell).variant_sha256,
                        None
                        if provider_seed is None
                        else int(
                            content_hash(
                                {
                                    "provider_seed": provider_seed,
                                    "block_id": block.block_id,
                                    "request_slot": slot,
                                    "cell": cell,
                                }
                            )[:8],
                            16,
                        )
                        & 0x7FFFFFFF,
                    )
                    for slot, cell in zip(frozen_slots, cells, strict=True)
                )
    result = FactorialRandomization(
        population_id,
        selection_id,
        seed,
        frozen_models,
        frozen_slots,
        tuple(assignments),
    )
    verify_factorial_randomization(result, frozen_policies)
    return result


def verify_factorial_randomization(
    result: FactorialRandomization,
    policies: Iterable[FactorialPolicy],
) -> None:
    expected = {
        _factorial_block(policy, bundle, model_id).block_id: (
            _factorial_block(policy, bundle, model_id),
            bundle,
        )
        for policy in policies
        for bundle in policy.bundles
        for model_id in result.models
    }
    if {item.block.block_id for item in result.assignments} != set(expected):
        raise ValueError("factorial randomization block support drift")
    for block_id, (expected_block, bundle) in expected.items():
        block = [item for item in result.assignments if item.block.block_id == block_id]
        if len(block) != len(result.slots) or {item.request_slot for item in block} != set(
            result.slots
        ):
            raise ValueError("factorial randomization slot support drift")
        counts = Counter(item.cell for item in block)
        if set(counts) != set(FACTORIAL_CELL_ORDER) or len(set(counts.values())) != 1:
            raise ValueError("factorial cells are not exactly balanced inside a complete block")
        if any(
            item.block != expected_block
            or item.variant_sha256 != bundle.variant(item.cell).variant_sha256
            for item in block
        ):
            raise ValueError("factorial assignment block or variant binding drift")


def _successor_block(
    policy: InterventionPolicyV2,
    bundle: TaskRealizationBundleV2,
    model_id: str,
) -> SuccessorBlockKey:
    return SuccessorBlockKey(
        bundle.task_unit_id,
        bundle.task_id,
        policy.hypothesis.hypothesis_id,
        policy.hypothesis.target_spec.target_spec_id,
        bundle.realization_spec_id,
        bundle.task_realization_bundle_id,
        model_id,
        policy.realization_policy.arm_protocol.arm_protocol_id,
    )


def _factorial_block(
    policy: FactorialPolicy,
    bundle: FactorialTaskBundle,
    model_id: str,
) -> FactorialBlockKey:
    return FactorialBlockKey(
        bundle.task_unit_id,
        bundle.task_id,
        policy.pair.pair_id,
        policy.pair.pair_context_query_id,
        bundle.realization_id,
        bundle.task_bundle_id,
        model_id,
        policy.factorial_protocol_id,
    )

__all__ = [
    "FactorialAssignment",
    "FactorialBlockKey",
    "FactorialRandomization",
    "SuccessorAssignment",
    "SuccessorBlockKey",
    "SuccessorRandomization",
    "randomize_factorial",
    "randomize_successor",
    "verify_factorial_randomization",
    "verify_successor_randomization",
]

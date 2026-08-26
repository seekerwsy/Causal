"""Replayable paired Target/Noop assignment over complete policy blocks."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from prompt_mechanism_study.intervention import (
    ARM_ORDER,
    FACTORIAL_CELL_ORDER,
    Arm,
    FactorialCell,
    FactorialPolicy,
    FactorialTaskBundle,
    InterventionPolicy,
    TaskRealizationBundle,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique


@dataclass(frozen=True, slots=True)
class BlockKey:
    semantic_cluster_id: str
    task_id: str
    candidate_id: str
    policy_id: str
    realization_id: str
    task_bundle_id: str
    model_id: str
    intervention_spec_id: str

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            require_text(getattr(self, name), name)

    @property
    def block_id(self) -> str:
        return content_id("block_", self)


@dataclass(frozen=True, slots=True)
class Assignment:
    block: BlockKey
    request_slot: int
    arm: Arm
    variant_sha256: str
    provider_seed: int | None = None

    def __post_init__(self) -> None:
        if type(self.request_slot) is not int or self.request_slot < 0:
            raise ValueError("request_slot must be a non-negative integer")
        if type(self.arm) is not Arm:
            raise TypeError("arm must be an Arm")
        if len(self.variant_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.variant_sha256
        ):
            raise ValueError("variant_sha256 must be a SHA-256 digest")
        if self.provider_seed is not None and (
            type(self.provider_seed) is not int or self.provider_seed < 0
        ):
            raise ValueError("provider_seed must be null or non-negative")

    @property
    def assignment_id(self) -> str:
        return content_id("assignment_", self)


@dataclass(frozen=True, slots=True)
class Randomization:
    population_id: str
    selection_id: str
    seed: int
    models: tuple[str, ...]
    slots: tuple[int, ...]
    assignments: tuple[Assignment, ...]

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
        return content_id("randomization_", self)


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


def randomize(
    policies: Iterable[InterventionPolicy],
    *,
    population_id: str,
    selection_id: str,
    models: Iterable[str],
    slots: Iterable[int],
    seed: int,
) -> Randomization:
    frozen_policies = tuple(sorted(tuple(policies), key=lambda item: item.policy_id))
    frozen_models = require_unique(tuple(models), "models")
    frozen_slots = require_unique(tuple(slots), "slots")
    if not frozen_policies or not frozen_models or not frozen_slots:
        raise ValueError("policies, models, and slots cannot be empty")
    if len(frozen_slots) % len(ARM_ORDER):
        raise ValueError("slots must form complete Target/Noop pairs")
    if any(type(slot) is not int or slot < 0 for slot in frozen_slots):
        raise ValueError("slots must be non-negative integers")

    assignments: list[Assignment] = []
    for policy in frozen_policies:
        for bundle in policy.bundles:
            for model_id in frozen_models:
                block = _block(policy, bundle, model_id)
                arms = list(ARM_ORDER) * (len(frozen_slots) // len(ARM_ORDER))
                block_seed = int(
                    content_hash({"seed": seed, "block_id": block.block_id})[:16],
                    16,
                )
                random.Random(block_seed).shuffle(arms)
                assignments.extend(
                    Assignment(
                        block,
                        slot,
                        arm,
                        bundle.variant(arm).variant_sha256,
                    )
                    for slot, arm in zip(frozen_slots, arms, strict=True)
                )
    result = Randomization(
        population_id,
        selection_id,
        seed,
        frozen_models,
        frozen_slots,
        tuple(assignments),
    )
    verify_randomization(result, frozen_policies)
    return result


def verify_randomization(
    result: Randomization,
    policies: Iterable[InterventionPolicy],
) -> None:
    expected = {
        _block(policy, bundle, model_id).block_id: (_block(policy, bundle, model_id), bundle)
        for policy in policies
        for bundle in policy.bundles
        for model_id in result.models
    }
    expected_blocks = set(expected)
    actual_blocks = {item.block.block_id for item in result.assignments}
    if actual_blocks != expected_blocks:
        raise ValueError("randomization block support drift")
    for block_id in expected_blocks:
        block = [item for item in result.assignments if item.block.block_id == block_id]
        expected_block, bundle = expected[block_id]
        if len(block) != len(result.slots) or {item.request_slot for item in block} != set(
            result.slots
        ):
            raise ValueError("randomization slot support drift")
        counts = Counter(item.arm for item in block)
        if set(counts) != set(ARM_ORDER) or len(set(counts.values())) != 1:
            raise ValueError("arms are not exactly balanced inside a complete block")
        if any(
            item.block != expected_block
            or item.variant_sha256 != bundle.variant(item.arm).variant_sha256
            for item in block
        ):
            raise ValueError("assignment block or variant binding drift")


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
    frozen_policies = tuple(sorted(tuple(policies), key=lambda item: item.policy_id))
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


def _block(
    policy: InterventionPolicy,
    bundle: TaskRealizationBundle,
    model_id: str,
) -> BlockKey:
    return BlockKey(
        bundle.semantic_cluster_id,
        bundle.task_id,
        policy.candidate_id,
        policy.policy_id,
        bundle.realization_id,
        bundle.task_bundle_id,
        model_id,
        policy.spec.intervention_spec_id,
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


def _require_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


__all__ = [
    "Assignment",
    "BlockKey",
    "FactorialAssignment",
    "FactorialBlockKey",
    "FactorialRandomization",
    "Randomization",
    "randomize",
    "randomize_factorial",
    "verify_factorial_randomization",
    "verify_randomization",
]

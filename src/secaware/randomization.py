"""Replayable complete-block randomization."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from secaware.intervention import ARM_ORDER, Arm, InterventionBundle
from secaware.records import content_hash, content_id, require_text, require_unique
from secaware.representation import Population


@dataclass(frozen=True, slots=True)
class Assignment:
    task_id: str
    cluster_id: str
    model_id: str
    request_slot: int
    arm: Arm
    intervention_id: str
    provider_seed: int | None = None

    def __post_init__(self) -> None:
        for name in ("task_id", "cluster_id", "model_id", "intervention_id"):
            require_text(getattr(self, name), name)
        if type(self.request_slot) is not int or self.request_slot < 0:
            raise ValueError("request_slot must be a non-negative integer")
        if type(self.arm) is not Arm:
            raise TypeError("arm must be an Arm")
        if self.provider_seed is not None and (
            type(self.provider_seed) is not int or self.provider_seed < 0
        ):
            raise ValueError("provider_seed must be null or non-negative")

    @property
    def block_id(self) -> str:
        return content_id(
            "block_",
            {
                "task_id": self.task_id,
                "cluster_id": self.cluster_id,
                "model_id": self.model_id,
                "intervention_id": self.intervention_id,
            },
        )

    @property
    def assignment_id(self) -> str:
        return content_id("assignment_", self)


@dataclass(frozen=True, slots=True)
class Randomization:
    population_id: str
    seed: int
    models: tuple[str, ...]
    slots: tuple[int, ...]
    assignments: tuple[Assignment, ...]

    def __post_init__(self) -> None:
        require_text(self.population_id, "population_id")
        if type(self.seed) is not int:
            raise TypeError("seed must be an integer")
        if not require_unique(self.models, "models"):
            raise ValueError("models cannot be empty")
        if not require_unique(self.slots, "slots"):
            raise ValueError("slots cannot be empty")
        require_unique((item.assignment_id for item in self.assignments), "assignments")

    @property
    def randomization_id(self) -> str:
        return content_id("randomization_", self)


def randomize(
    population: Population,
    interventions: Iterable[InterventionBundle],
    *,
    models: Iterable[str],
    slots: Iterable[int],
    seed: int,
) -> Randomization:
    """Assign all four arms equally within every task-by-model block."""

    bundles = tuple(interventions)
    by_task = {bundle.task_id: bundle for bundle in bundles}
    if len(by_task) != len(bundles) or set(by_task) != {task.task_id for task in population.tasks}:
        raise ValueError("one intervention must bind every population task")

    frozen_models = require_unique(tuple(models), "models")
    frozen_slots = require_unique(tuple(slots), "slots")
    if not frozen_models or not frozen_slots or len(frozen_slots) % len(ARM_ORDER):
        raise ValueError("models are required and slots must form complete four-arm blocks")
    if any(type(slot) is not int or slot < 0 for slot in frozen_slots):
        raise ValueError("slots must be non-negative integers")

    assignments: list[Assignment] = []
    for task in population.tasks:
        bundle = by_task[task.task_id]
        for model in frozen_models:
            arms = list(ARM_ORDER) * (len(frozen_slots) // len(ARM_ORDER))
            block_seed = int(
                content_hash({"seed": seed, "task": task.task_id, "model": model})[:16],
                16,
            )
            random.Random(block_seed).shuffle(arms)
            assignments.extend(
                Assignment(
                    task_id=task.task_id,
                    cluster_id=task.cluster_id,
                    model_id=model,
                    request_slot=slot,
                    arm=arm,
                    intervention_id=bundle.intervention_id,
                )
                for slot, arm in zip(frozen_slots, arms, strict=True)
            )
    result = Randomization(
        population_id=population.population_id,
        seed=seed,
        models=frozen_models,
        slots=frozen_slots,
        assignments=tuple(assignments),
    )
    verify_randomization(result, population, bundles)
    return result


def verify_randomization(
    result: Randomization,
    population: Population,
    interventions: Iterable[InterventionBundle],
) -> None:
    frozen_bundles = tuple(interventions)
    bundles = {item.task_id: item for item in frozen_bundles}
    task_ids = {task.task_id for task in population.tasks}
    if len(bundles) != len(frozen_bundles) or set(bundles) != task_ids:
        raise ValueError("interventions do not bind the frozen population exactly")
    expected = len(population.tasks) * len(result.models) * len(result.slots)
    if result.population_id != population.population_id or len(result.assignments) != expected:
        raise ValueError("randomization does not cover the frozen population")
    for task in population.tasks:
        for model in result.models:
            block = [
                item
                for item in result.assignments
                if item.task_id == task.task_id and item.model_id == model
            ]
            if {item.request_slot for item in block} != set(result.slots):
                raise ValueError("randomization slot support drift")
            counts = Counter(item.arm for item in block)
            if len(set(counts.values())) != 1 or set(counts) != set(ARM_ORDER):
                raise ValueError("arms are not exactly balanced")
            if any(item.intervention_id != bundles[task.task_id].intervention_id for item in block):
                raise ValueError("intervention binding drift")


__all__ = ["Assignment", "Randomization", "randomize", "verify_randomization"]

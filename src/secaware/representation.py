"""Outcome-blind representation and candidate freeze."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from secaware.records import content_hash, content_id, require_text, require_unique


class Operation(StrEnum):
    ADD = "add"
    REMOVE = "remove"


@dataclass(frozen=True, slots=True)
class Task:
    task_id: str
    cluster_id: str
    cwe: str
    prompt: str

    def __post_init__(self) -> None:
        for name in ("task_id", "cluster_id", "cwe", "prompt"):
            require_text(getattr(self, name), name)

    @property
    def prompt_sha256(self) -> str:
        return content_hash(self.prompt)


@dataclass(frozen=True, slots=True)
class Candidate:
    task_id: str
    feature_id: str
    operation: Operation
    rationale: str

    def __post_init__(self) -> None:
        require_text(self.task_id, "task_id")
        require_text(self.feature_id, "feature_id")
        require_text(self.rationale, "rationale")
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")

    @property
    def candidate_id(self) -> str:
        return content_id("candidate_", self)


@dataclass(frozen=True, slots=True)
class Population:
    tasks: tuple[Task, ...]

    def __post_init__(self) -> None:
        if not self.tasks:
            raise ValueError("population cannot be empty")
        require_unique((task.task_id for task in self.tasks), "task ids")
        if tuple(sorted(self.tasks, key=lambda task: task.task_id)) != self.tasks:
            raise ValueError("population tasks must use canonical task-id order")

    @property
    def population_id(self) -> str:
        return content_id("population_", self)


def freeze_population(tasks: Iterable[Task]) -> Population:
    """Freeze the complete pre-outcome task population."""

    frozen = tuple(sorted(tuple(tasks), key=lambda task: task.task_id))
    return Population(frozen)


__all__ = ["Candidate", "Operation", "Population", "Task", "freeze_population"]

"""Outcome-blind population and intervention-hypothesis representation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from secaware.records import content_hash, content_id, require_text, require_unique


class Split(StrEnum):
    DISCOVER = "discover"
    CONFIRM = "confirm"


class Operation(StrEnum):
    ADD = "add"
    REMOVE = "remove"


class ExpectedDirection(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"


@dataclass(frozen=True, slots=True)
class Task:
    task_id: str
    semantic_cluster_id: str
    cwe: str
    archetype: str
    split: Split
    prompt: str
    weight: int = 1

    def __post_init__(self) -> None:
        for name in ("task_id", "semantic_cluster_id", "cwe", "archetype", "prompt"):
            require_text(getattr(self, name), name)
        if type(self.split) is not Split:
            raise TypeError("split must be a Split")
        if type(self.weight) is not int or self.weight <= 0:
            raise ValueError("task weight must be a positive integer")

    @property
    def prompt_sha256(self) -> str:
        return content_hash(self.prompt)


@dataclass(frozen=True, slots=True)
class Candidate:
    candidate_key: str
    context_query_id: str
    actionable_feature_id: str
    operation: Operation
    cwe: str
    outcome_id: str
    expected_direction: ExpectedDirection

    def __post_init__(self) -> None:
        for name in (
            "candidate_key",
            "context_query_id",
            "actionable_feature_id",
            "cwe",
            "outcome_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.operation) is not Operation:
            raise TypeError("operation must be an Operation")
        if type(self.expected_direction) is not ExpectedDirection:
            raise TypeError("expected_direction must be an ExpectedDirection")

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
        cluster_splits: dict[str, Split] = {}
        for task in self.tasks:
            previous = cluster_splits.setdefault(task.semantic_cluster_id, task.split)
            if previous is not task.split:
                raise ValueError("a semantic cluster cannot cross discover and confirm splits")
        if not self.discover_tasks or not self.confirm_tasks:
            raise ValueError("both discover and confirm tasks are required")

    @property
    def population_id(self) -> str:
        return content_id("population_", self)

    @property
    def discover_tasks(self) -> tuple[Task, ...]:
        return tuple(task for task in self.tasks if task.split is Split.DISCOVER)

    @property
    def confirm_tasks(self) -> tuple[Task, ...]:
        return tuple(task for task in self.tasks if task.split is Split.CONFIRM)


@dataclass(frozen=True, slots=True)
class CandidateUniverse:
    representation_adapter_id: str
    candidates: tuple[Candidate, ...]

    def __post_init__(self) -> None:
        require_text(self.representation_adapter_id, "representation_adapter_id")
        if not self.candidates:
            raise ValueError("candidate universe cannot be empty")
        require_unique((item.candidate_id for item in self.candidates), "candidate ids")
        require_unique((item.candidate_key for item in self.candidates), "candidate keys")
        if tuple(sorted(self.candidates, key=lambda item: item.candidate_id)) != self.candidates:
            raise ValueError("candidates must use canonical candidate-id order")

    @property
    def universe_id(self) -> str:
        return content_id("universe_", self)


def freeze_population(tasks: Iterable[Task]) -> Population:
    return Population(tuple(sorted(tuple(tasks), key=lambda task: task.task_id)))


def freeze_universe(
    candidates: Iterable[Candidate],
    *,
    representation_adapter_id: str,
) -> CandidateUniverse:
    return CandidateUniverse(
        representation_adapter_id,
        tuple(sorted(tuple(candidates), key=lambda item: item.candidate_id)),
    )


__all__ = [
    "Candidate",
    "CandidateUniverse",
    "ExpectedDirection",
    "Operation",
    "Population",
    "Split",
    "Task",
    "freeze_population",
    "freeze_universe",
]

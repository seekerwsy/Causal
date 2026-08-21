"""Frozen, outcome-blind selector scores and top-K slots."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping

from prompt_mechanism_study.records import content_id, require_text
from prompt_mechanism_study.representation import CandidateUniverse


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate_id: str
    score: float
    rank: int

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        if type(self.score) not in {int, float} or not math.isfinite(float(self.score)):
            raise ValueError("score must be finite")
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("rank must be positive")


@dataclass(frozen=True, slots=True)
class SelectionFreeze:
    universe_id: str
    selector_adapter_id: str
    top_k: int
    ranking: tuple[RankedCandidate, ...]

    def __post_init__(self) -> None:
        require_text(self.universe_id, "universe_id")
        require_text(self.selector_adapter_id, "selector_adapter_id")
        if type(self.top_k) is not int or not 1 <= self.top_k <= len(self.ranking):
            raise ValueError("top_k is outside the ranked candidate support")
        if tuple(item.rank for item in self.ranking) != tuple(range(1, len(self.ranking) + 1)):
            raise ValueError("ranking positions must be complete and canonical")
        if len({item.candidate_id for item in self.ranking}) != len(self.ranking):
            raise ValueError("ranking candidate ids must be unique")

    @property
    def selection_id(self) -> str:
        return content_id("selection_", self)

    @property
    def selected_candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.candidate_id for item in self.ranking[: self.top_k])


def freeze_selection(
    universe: CandidateUniverse,
    scores: Mapping[str, float],
    *,
    selector_adapter_id: str,
    top_k: int,
) -> SelectionFreeze:
    candidate_ids = tuple(item.candidate_id for item in universe.candidates)
    if set(scores) != set(candidate_ids):
        raise ValueError("selector scores must bind every candidate exactly once")
    ordered = sorted(
        candidate_ids,
        key=lambda candidate_id: (-_score(scores[candidate_id]), candidate_id),
    )
    ranking = tuple(
        RankedCandidate(candidate_id, _score(scores[candidate_id]), rank)
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    return SelectionFreeze(
        universe.universe_id,
        selector_adapter_id,
        top_k,
        ranking,
    )


def _score(value: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError("selector scores must be finite")
    return float(value)


__all__ = ["RankedCandidate", "SelectionFreeze", "freeze_selection"]

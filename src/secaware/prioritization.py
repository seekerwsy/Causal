"""Deterministic, outcome-blind candidate prioritization."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping, Sequence

from secaware.records import content_id
from secaware.representation import Candidate


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate: Candidate
    score: float
    rank: int

    @property
    def ranking_id(self) -> str:
        return content_id("rank_", self)


def rank_candidates(
    candidates: Sequence[Candidate],
    scores: Mapping[str, float],
    *,
    limit: int | None = None,
) -> tuple[RankedCandidate, ...]:
    """Rank a frozen candidate set without accepting outcomes or arm assignments."""

    frozen = tuple(candidates)
    ids = tuple(candidate.candidate_id for candidate in frozen)
    if len(ids) != len(set(ids)) or set(scores) != set(ids):
        raise ValueError("scores must bind every candidate exactly once")
    if limit is not None and not 1 <= limit <= len(frozen):
        raise ValueError("limit is outside the candidate support")

    ordered = sorted(
        frozen,
        key=lambda candidate: (-_score(scores[candidate.candidate_id]), candidate.candidate_id),
    )
    if limit is not None:
        ordered = ordered[:limit]
    return tuple(
        RankedCandidate(
            candidate=candidate, score=_score(scores[candidate.candidate_id]), rank=index
        )
        for index, candidate in enumerate(ordered, start=1)
    )


def _score(value: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError("candidate scores must be finite")
    return float(value)


__all__ = ["RankedCandidate", "rank_candidates"]

"""Dependency-neutral matching for finite reviewed prompt evidence terms."""

from __future__ import annotations

import re


def first_reviewed_term_match(
    text: str,
    terms: tuple[str, ...],
) -> tuple[int, int] | None:
    """Return the earliest ASCII-boundary term span, preserving catalog tie order."""
    earliest: tuple[int, int, int] | None = None
    for term_index, term in enumerate(terms):
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])"
        match = re.search(pattern, text, flags=re.IGNORECASE | re.ASCII)
        if match is not None:
            candidate = (match.start(), match.end(), term_index)
            earliest = candidate if earliest is None else min(earliest, candidate)
    if earliest is None:
        return None
    start, end, _ = earliest
    return start, end


__all__ = ["first_reviewed_term_match"]

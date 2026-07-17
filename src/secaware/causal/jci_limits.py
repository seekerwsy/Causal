"""Shared hard resource limits for persisted JCI analysis."""

from __future__ import annotations


MAX_JCI_TABLES = 512
MAX_JCI_FCI_RUNS = 1_024
MAX_JCI_MATRIX_CELLS = 6_400_000


__all__ = [
    "MAX_JCI_FCI_RUNS",
    "MAX_JCI_MATRIX_CELLS",
    "MAX_JCI_TABLES",
]

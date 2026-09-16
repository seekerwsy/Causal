"""Shared numerical solver for Discovery ranking, never confirmatory verification."""

from __future__ import annotations

import math
from collections.abc import Sequence


def sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-min(value, 700.0)))
    exponential = math.exp(max(value, -700.0))
    return exponential / (1.0 + exponential)


def fit_ridge_logit(
    design: Sequence[Sequence[float]],
    outcomes: Sequence[int],
    ridge_lambda: float,
    *,
    maximum_iterations: int,
) -> list[float]:
    """Fit an already constructed design; column zero is an unpenalized intercept.

    The Atomic caller supplies standardization, design columns and iteration limits.
    Row order and floating-point accumulation are preserved for reproducibility.
    """
    width = len(design[0]) if design else 1
    weights = [0.0] * width
    max_norm = max((sum(value * value for value in row) for row in design), default=1.0)
    step = 1.0 / (0.25 * max_norm + ridge_lambda + 1.0)
    for _ in range(maximum_iterations):
        gradient = [0.0] * width
        for row, outcome in zip(design, outcomes, strict=True):
            probability = sigmoid(
                sum(weight * value for weight, value in zip(weights, row, strict=True))
            )
            for index, value in enumerate(row):
                gradient[index] += (probability - outcome) * value / len(design)
        for index in range(1, width):
            gradient[index] += ridge_lambda * weights[index]
        updated = [weight - step * value for weight, value in zip(weights, gradient, strict=True)]
        if max(abs(left - right) for left, right in zip(updated, weights, strict=True)) < 1e-10:
            weights = updated
            break
        weights = updated
    return weights

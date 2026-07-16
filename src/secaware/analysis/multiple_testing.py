"""Pre-registered familywise percentile adjustments."""

from __future__ import annotations

import math
from typing import Literal


def bonferroni_percentile_quantiles(
    *,
    confidence_level: float,
    number_of_pre_registered_contrasts: int,
    multiplicity_method: Literal["bonferroni"] = "bonferroni",
) -> tuple[float, float]:
    """Return equal-tail quantiles after a frozen-family Bonferroni adjustment."""

    if (
        type(confidence_level) is not float
        or not math.isfinite(confidence_level)
        or not 0.0 < confidence_level < 1.0
        or type(number_of_pre_registered_contrasts) is not int
        or number_of_pre_registered_contrasts < 1
        or multiplicity_method != "bonferroni"
    ):
        raise ValueError("multiple-testing configuration failed validation")
    adjusted_alpha = (1.0 - confidence_level) / number_of_pre_registered_contrasts
    tail = adjusted_alpha / 2.0
    return tail, 1.0 - tail


__all__ = ["bonferroni_percentile_quantiles"]

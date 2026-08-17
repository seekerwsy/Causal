from __future__ import annotations

import pytest

from scripts.run_gate_b_extractor_revalidation import _validate_prior_failure


def test_gate_b_revalidation_requires_the_frozen_prior_failure_message() -> None:
    failure = {
        "status": "GATE_B_FAILED",
        "message": "exploratory Gate B placebo length validation failed",
    }

    _validate_prior_failure(
        failure,
        "exploratory Gate B placebo length validation failed",
    )

    with pytest.raises(ValueError, match="provenance"):
        _validate_prior_failure(failure, "TARGET_VARIATION_VIOLATION")
    with pytest.raises(ValueError, match="provenance"):
        _validate_prior_failure({**failure, "status": "GATE_B_PASSED"}, failure["message"])

from __future__ import annotations

import pytest

from secaware.exploratory import randomized_discovery_results as results
from secaware.schema.experiments import ArmRole


@pytest.mark.parametrize(
    ("arm", "expected"),
    (
        (ArmRole.TARGET_PATCH, (0, 1, 0, 0)),
        (ArmRole.NOOP_REWRITE, (1, 0, 0, 0)),
        (ArmRole.LENGTH_MATCHED_PLACEBO, (2, 0, 0, 1)),
        (ArmRole.GENERIC_SECURITY_REMINDER, (3, 0, 1, 0)),
    ),
)
def test_frozen_arm_projection_separates_target_generic_and_placebo(
    arm: ArmRole,
    expected: tuple[int, int, int, int],
) -> None:
    assert results._arm_values(arm) == expected


def test_non_discovery_arm_cannot_enter_the_projection() -> None:
    with pytest.raises(ValueError):
        results._arm_values(ArmRole.TARGET_REMOVE)

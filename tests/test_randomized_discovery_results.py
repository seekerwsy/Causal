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


def test_terminal_no_code_is_retained_in_itt_unknown_count() -> None:
    assert results._reported_itt_unknown_count({"unknown": 46, "terminal_no_code": 3}) == 49


@pytest.mark.parametrize(
    "counts",
    (
        {"unknown": None, "terminal_no_code": 3},
        {"unknown": 46, "terminal_no_code": None},
        {"unknown": True, "terminal_no_code": 3},
    ),
)
def test_reported_itt_unknown_count_fails_closed(counts: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="report counts failed validation"):
        results._reported_itt_unknown_count(counts)

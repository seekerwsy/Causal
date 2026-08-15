from __future__ import annotations

import pytest

from secaware.exploratory.gate_b import validate_length_matched_placebo


@pytest.mark.parametrize(
    ("target_length", "placebo_length", "minimum", "maximum"),
    [
        (57, 51, 51, 63),
        (57, 63, 51, 63),
        (55, 49, 49, 61),
        (55, 61, 49, 61),
    ],
)
def test_placebo_length_contract_accepts_frozen_boundaries(
    target_length: int,
    placebo_length: int,
    minimum: int,
    maximum: int,
) -> None:
    result = validate_length_matched_placebo(
        target_suffix="t" * target_length,
        noop_suffix="",
        placebo_suffix="p" * placebo_length,
    )
    assert result["status"] == "PASSED"
    assert result["minimum_placebo_length"] == minimum
    assert result["maximum_placebo_length"] == maximum


@pytest.mark.parametrize(("target_length", "placebo_length"), [(57, 50), (57, 64), (55, 48), (55, 62)])
def test_placebo_length_contract_rejects_outside_boundaries(
    target_length: int,
    placebo_length: int,
) -> None:
    result = validate_length_matched_placebo(
        target_suffix="t" * target_length,
        noop_suffix="",
        placebo_suffix="p" * placebo_length,
    )
    assert result["status"] == "FAILED"
    assert "PLACEBO_LENGTH_MISMATCH" in result["failure_codes"]


def test_placebo_length_contract_rejects_empty_noop_collision() -> None:
    result = validate_length_matched_placebo(
        target_suffix="t" * 55,
        noop_suffix="",
        placebo_suffix="",
    )
    assert result["status"] == "FAILED"
    assert result["failure_codes"] == [
        "PLACEBO_SUFFIX_EMPTY",
        "PLACEBO_NOOP_COLLISION",
        "PLACEBO_LENGTH_MISMATCH",
    ]


def test_placebo_length_contract_rejects_invalid_input_type() -> None:
    with pytest.raises(ValueError):
        validate_length_matched_placebo(  # type: ignore[arg-type]
            target_suffix="target",
            noop_suffix="",
            placebo_suffix=None,
        )

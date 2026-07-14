from __future__ import annotations

import pytest

from secaware.errors import SecAwareError
from secaware.intervention.variant_validation import (
    canonical_changed_span_utf8_bytes,
    make_length_match_record,
    validate_length_match_record,
)
from secaware.schema.experiments import ArmRole


def test_canonical_changed_span_counts_deleted_plus_inserted_utf8_bytes() -> None:
    # The registered metric is byte-level, so the common leading UTF-8 byte is
    # stripped even though it is only part of a multibyte code point.
    assert canonical_changed_span_utf8_bytes("a猫z", "a狗狗z") == 7
    assert canonical_changed_span_utf8_bytes("prefix-old-suffix", "prefix-new-suffix") == 6


@pytest.mark.parametrize(
    ("reference", "matched", "expected_tolerance"),
    (("x" * 10, "y" * 6, 4), ("x" * 100, "y" * 95, 5)),
)
def test_length_match_accepts_exact_four_byte_or_five_percent_boundary(
    reference: str,
    matched: str,
    expected_tolerance: int,
) -> None:
    record = make_length_match_record(
        arm_protocol_id="arm_protocol_" + "a" * 64,
        protocol_instance_id="protocol_instance_" + "b" * 64,
        reference_arm_role=ArmRole.TARGET_PATCH,
        matched_arm_role=ArmRole.LENGTH_MATCHED_PLACEBO,
        source_text="base",
        reference_text="base" + reference,
        matched_text="base" + matched,
    )

    assert record.tolerance_bytes == expected_tolerance
    validate_length_match_record(
        record,
        source_text="base",
        reference_text="base" + reference,
        matched_text="base" + matched,
    )


def test_length_match_rejects_one_byte_past_boundary() -> None:
    with pytest.raises(SecAwareError):
        make_length_match_record(
            arm_protocol_id="arm_protocol_" + "a" * 64,
            protocol_instance_id="protocol_instance_" + "b" * 64,
            reference_arm_role=ArmRole.TARGET_PATCH,
            matched_arm_role=ArmRole.LENGTH_MATCHED_PLACEBO,
            source_text="base",
            reference_text="base" + "x" * 10,
            matched_text="base" + "y" * 5,
        )


def test_length_match_record_is_recomputed_instead_of_trusted() -> None:
    record = make_length_match_record(
        arm_protocol_id="arm_protocol_" + "a" * 64,
        protocol_instance_id="protocol_instance_" + "b" * 64,
        reference_arm_role=ArmRole.TARGET_REMOVE,
        matched_arm_role=ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        source_text="base",
        reference_text="base" + "x" * 20,
        matched_text="base" + "y" * 16,
    )
    forged = record.model_copy(update={"matched_delta_bytes": record.matched_delta_bytes + 1})

    with pytest.raises(SecAwareError):
        validate_length_match_record(
            forged,
            source_text="base",
            reference_text="base" + "x" * 20,
            matched_text="base" + "y" * 16,
        )

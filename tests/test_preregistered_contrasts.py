from __future__ import annotations

import pytest
from pydantic import ValidationError

from m5_executor_fixtures import request
from secaware.analysis.contrasts import materialize_contrasts, validate_contrasts
from secaware.schema.experiments import ArmRole, FeatureFamily, FeatureOperation
from secaware.schema.outcomes import ContrastSpecRecord


_CONTRAST_FIELDS = (
    "contrast_id",
    "arm_contrast_id",
    "treatment_arm",
    "control_arm",
    "source_outcome_variable_id",
    "outcome_id",
    "priority",
    "expected_sign",
    "multiplicity_family_id",
)


def _protocol(
    family: FeatureFamily,
    operation: FeatureOperation,
    *,
    feature_id: str | None = None,
):
    return request(
        family,
        operation,
        feature_id=feature_id,
        with_functional_contract=family is FeatureFamily.TASK_FUNCTION,
    ).protocol


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_every_frozen_safety_contrast_is_materialized_without_enumeration(
    operation: FeatureOperation,
) -> None:
    protocol = _protocol(FeatureFamily.SAFETY_CONTROL, operation)

    records = materialize_contrasts((protocol,))

    assert len(records) == len(protocol.contrasts)
    assert [record.contrast_id for record in records] == [
        nested.contrast_id for nested in protocol.contrasts
    ]
    assert [record.arm_protocol_id for record in records] == [protocol.arm_protocol_id] * len(
        protocol.contrasts
    )
    for record, nested in zip(records, protocol.contrasts, strict=True):
        assert tuple(getattr(record, name) for name in _CONTRAST_FIELDS) == tuple(
            getattr(nested, name) for name in _CONTRAST_FIELDS
        )


@pytest.mark.parametrize(
    "family", (FeatureFamily.TASK_FUNCTION, FeatureFamily.PRESENTATION_CONTROL)
)
@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_task_and_presentation_only_publish_family_valid_frozen_contrasts(
    family: FeatureFamily,
    operation: FeatureOperation,
) -> None:
    protocol = _protocol(family, operation)

    records = materialize_contrasts((protocol,))

    assert tuple(record.contrast_id for record in records) == protocol.preregistered_contrast_ids
    assert all(record.treatment_arm in protocol.arm_roles for record in records)
    assert all(record.control_arm in protocol.arm_roles for record in records)
    if family is FeatureFamily.PRESENTATION_CONTROL:
        assert all(record.expected_sign == "null" for record in records)
        assert all(record.priority != "primary" for record in records)
    else:
        contract_outcomes = {
            nested.outcome_id for nested in protocol.contrasts if nested.priority == "primary"
        }
        assert contract_outcomes == {"y_task_database_functional"}


def test_flattened_contrast_schema_is_exact_strict_and_frozen() -> None:
    protocol = _protocol(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD)
    record = materialize_contrasts((protocol,))[0]

    assert record.schema_version == "1.0"
    assert tuple(ContrastSpecRecord.model_fields) == (
        "schema_version",
        "contrast_id",
        "arm_contrast_id",
        "arm_protocol_id",
        "treatment_arm",
        "control_arm",
        "source_outcome_variable_id",
        "outcome_id",
        "priority",
        "expected_sign",
        "multiplicity_family_id",
    )
    with pytest.raises(ValidationError):
        record.priority = "diagnostic"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ContrastSpecRecord.model_validate({**record.model_dump(mode="json"), "extra": 1})


def test_arbitrary_observed_arm_contrast_is_rejected_against_protocol_commitment() -> None:
    protocol = _protocol(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD)
    committed = materialize_contrasts((protocol,))
    payload = committed[0].model_dump(mode="python")
    payload["treatment_arm"] = ArmRole.GENERIC_SECURITY_REMINDER
    arbitrary = ContrastSpecRecord.model_validate(payload)

    with pytest.raises(Exception, match="contrast"):
        validate_contrasts((protocol,), (arbitrary, *committed[1:]))


def test_uniqueness_key_is_exactly_protocol_and_contrast_id() -> None:
    first = _protocol(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        feature_id="safety.path_normalization",
    )
    second = _protocol(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        feature_id="safety.input_validation",
    )
    assert first.arm_protocol_id != second.arm_protocol_id
    assert first.preregistered_contrast_ids == second.preregistered_contrast_ids

    records = materialize_contrasts((first, second))

    assert len(records) == len(first.contrasts) + len(second.contrasts)
    assert len({(item.arm_protocol_id, item.contrast_id) for item in records}) == len(records)
    with pytest.raises(Exception, match="contrast"):
        materialize_contrasts((first, first))


def test_protocol_digest_and_outcome_variable_are_revalidated_before_flattening() -> None:
    protocol = _protocol(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD)
    for forged in (
        protocol.model_copy(update={"contrast_set_sha256": "0" * 64}),
        protocol.model_copy(update={"arm_protocol_id": "arm_protocol_" + "0" * 64}),
        protocol.model_copy(update={"hypothesis_outcome_variable_id": "y.cwe_security"}),
    ):
        with pytest.raises(Exception, match="contrast"):
            materialize_contrasts((forged,))

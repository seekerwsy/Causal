from typing import Any

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SCHEMA_VERSION, VersionedModel
from secaware.schema.migrations import require_v1_payload


class ExampleV1Payload(VersionedModel):
    value: int


def test_versioned_model_accepts_an_explicit_v1_version() -> None:
    payload = ExampleV1Payload(schema_version="1.0", value=7)

    assert payload.schema_version == SCHEMA_VERSION


def test_versioned_model_rejects_a_missing_version() -> None:
    with pytest.raises(ValidationError):
        ExampleV1Payload(value=7)


def test_versioned_model_rejects_a_non_v1_version() -> None:
    with pytest.raises(ValidationError):
        ExampleV1Payload(schema_version="0.9", value=7)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"schema_version": None},
        {"schema_version": "0.9"},
        {"schema_version": 1.0},
    ],
)
def test_require_v1_payload_rejects_missing_or_non_v1_versions(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        require_v1_payload(payload)

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "migration"
    assert error.retryable is False


def test_require_v1_payload_accepts_v1_without_mutating_the_payload() -> None:
    payload = {"schema_version": "1.0", "record": {"id": "r1"}}

    result = require_v1_payload(payload)

    assert result is None
    assert payload == {"schema_version": "1.0", "record": {"id": "r1"}}

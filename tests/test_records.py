from typing import ClassVar, Literal

import pytest
from pydantic import Field, ValidationError

from secaware.records import (
    ContentAddressedResearchRecord,
    SnapshotContentAddressedResearchRecord,
    record_sha256,
)


class ExampleRecord(SnapshotContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "example record failed validation"
    _schema_version = "1.0"
    _id_field = "record_id"
    _id_prefix = "example_"

    schema_version: Literal["1.0"]
    record_id: str = Field(pattern=r"^example_[0-9a-f]{64}$")
    values: tuple[str, ...]


class ExactInputRecord(ContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "exact input record failed validation"
    _schema_version = "1.0"
    _id_field = "record_id"
    _id_prefix = "exact_"

    schema_version: Literal["1.0"]
    record_id: str = Field(pattern=r"^exact_[0-9a-f]{64}$")
    values: tuple[str, ...]


@pytest.mark.reviewer
def test_content_addressing_and_immutability_are_owned_by_the_shared_record_base() -> None:
    record = ExampleRecord.from_content(values=["a", "b"])
    expected = record_sha256({"schema_version": "1.0", "values": ["a", "b"]})

    assert record.record_id == f"example_{expected}"
    assert record.values == ("a", "b")
    with pytest.raises(ValidationError):
        record.values = ("changed",)
    with pytest.raises(ValidationError, match="example record failed validation"):
        ExampleRecord.model_validate({**record.model_dump(), "record_id": "example_" + "0" * 64})
    with pytest.raises(ValidationError, match="exact input record failed validation"):
        ExactInputRecord.from_content(values=["caller-owned-list"])

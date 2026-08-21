"""Small, shared mechanics for immutable research records.

Scientific modules own their fields, identifiers, and validation rules.  This module
only centralizes the byte-level operations that must be identical across those
records: canonical hashing, immutable input snapshots, identifier syntax, and safe
Pydantic presentation.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, ClassVar, NoReturn, Self

from pydantic import BaseModel, ConfigDict, model_validator

from secaware.canonical import canonical_sha256
from secaware.schema.common import SafeValidationMixin, StrictModel

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


def record_sha256(value: object) -> str:
    """Hash JSON-compatible record content using the repository's stable encoding."""

    return canonical_sha256(_jsonable(value))


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def snapshot_json_arrays(value: object) -> object:
    """Copy JSON arrays to tuples before validation to prevent caller mutation."""

    if type(value) is dict:
        return {key: snapshot_json_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(snapshot_json_arrays(item) for item in value)
    return value


def parse_exact_enum(value: object, enum_type: type[Enum]) -> object:
    """Accept an exact enum member or its exact string value, without coercion."""

    if type(value) is enum_type:
        return value
    if type(value) is str:
        return next((member for member in enum_type if member.value == value), value)
    return value


def valid_identifier(value: object) -> bool:
    """Return whether *value* is a bounded, printable artifact identifier."""

    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def raise_record_validation_error(model_type: type[SafeValidationMixin]) -> NoReturn:
    """Raise the model's sanitized validation error at a public factory boundary."""

    raise model_type._safe_error()


class FrozenResearchRecord(SafeValidationMixin, StrictModel):
    """Immutable, strict, safe-display base for reviewer-facing records."""

    _safe_validation_message: ClassVar[str]

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class SnapshotResearchRecord(FrozenResearchRecord):
    """Immutable record that snapshots caller-owned JSON arrays before validation."""

    @model_validator(mode="before")
    @classmethod
    def snapshot_arrays(cls, value: object) -> object:
        return snapshot_json_arrays(value)


class ContentAddressedResearchRecord(FrozenResearchRecord):
    """Shared constructor and verifier for ordinary content-addressed records."""

    _schema_version: ClassVar[str]
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": cls._schema_version, **content}
            return cls(
                **payload,
                **{cls._id_field: cls._id_prefix + record_sha256(payload)},
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public record boundary
            content.clear()
            if payload is not None:
                payload.clear()
            raise_record_validation_error(cls)

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + record_sha256(content):
            raise ValueError(self._safe_validation_message)
        return self


class SnapshotContentAddressedResearchRecord(ContentAddressedResearchRecord):
    """Content-addressed record that also snapshots caller-owned JSON arrays."""

    @model_validator(mode="before")
    @classmethod
    def snapshot_arrays(cls, value: object) -> object:
        return snapshot_json_arrays(value)


__all__ = [
    "ContentAddressedResearchRecord",
    "FrozenResearchRecord",
    "SnapshotContentAddressedResearchRecord",
    "SnapshotResearchRecord",
    "parse_exact_enum",
    "raise_record_validation_error",
    "record_sha256",
    "snapshot_json_arrays",
    "valid_identifier",
]

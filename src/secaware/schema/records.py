import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, model_shape_is_intact
from secaware.schema.generation import (
    GenerationProvenance,
    GenerationRequestRecord,
    revalidate_generation_request_envelope,
    sha256_text,
)


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_CANONICAL_CODE_ID_PATTERN = r"^code_[0-9a-f]{64}$"
_INVALID_GENERATED_CODE_MESSAGE = "generated code record validation failed"
_INVALID_CANONICAL_CODE_MESSAGE = "canonical generated code record validation failed"


class PromptRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        protected_namespaces=(),
    )

    prompt_id: str
    task_id: str = Field(strict=True)
    split: Literal["discover", "confirm"]
    language: str
    task_family: str
    cwe: str
    prompt: str = Field(min_length=1)

    @field_validator("task_id")
    @classmethod
    def validate_task_id(cls, value: str) -> str:
        if not value or not value.strip() or value != value.strip():
            raise ValueError("prompt record validation failed")
        return value


class GeneratedCodeRecord(SafeValidationMixin, BaseModel):
    _safe_validation_message = _INVALID_GENERATED_CODE_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
    )

    code_id: str
    prompt_id: str
    condition: Literal["observed", "counterfactual"]
    model_id: str
    seed_id: int
    code: str
    hypothesis_id: str | None = None
    intervention_id: str | None = None
    schema_version: Literal["1.0"] | None = None
    request_id: str | None = Field(default=None, pattern=_REQUEST_ID_PATTERN)
    prompt_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    code_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    generation_provenance: GenerationProvenance | None = None
    generation_request: GenerationRequestRecord | None = None

    @field_validator("generation_request", mode="before")
    @classmethod
    def snapshot_generation_request(
        cls,
        value: object,
    ) -> GenerationRequestRecord | None:
        if value is None:
            return None
        if isinstance(value, GenerationRequestRecord):
            return revalidate_generation_request_envelope(value)
        return GenerationRequestRecord.model_validate(value)

    @model_validator(mode="after")
    def validate_generation_metadata_bridge(self) -> "GeneratedCodeRecord":
        metadata = (
            self.schema_version,
            self.request_id,
            self.prompt_sha256,
            self.code_sha256,
            self.generation_provenance,
            self.generation_request,
        )
        if all(value is None for value in metadata):
            if re.fullmatch(_CANONICAL_CODE_ID_PATTERN, self.code_id):
                raise ValueError("canonical code ids require canonical metadata")
            return self
        if any(value is None for value in metadata):
            raise ValueError("canonical generation metadata must be complete")

        request_id = self.request_id
        code_sha256 = self.code_sha256
        generation_request = self.generation_request
        if (  # pragma: no cover - narrowed above
            request_id is None or code_sha256 is None or generation_request is None
        ):
            raise ValueError("canonical generation metadata must be complete")
        request = revalidate_generation_request_envelope(generation_request)
        if not self.code.strip() or code_sha256 != sha256_text(self.code):
            raise ValueError("canonical generated code hash does not match its payload")
        if self.code_id != f"code_{request_id.removeprefix('req_')}":
            raise ValueError("canonical code id must match its request id")

        bound_coordinates = (
            (self.request_id, request.request_id),
            (self.prompt_id, request.prompt_id),
            (self.condition, request.condition),
            (self.model_id, request.model_id),
            (self.seed_id, request.seed_id),
            (self.hypothesis_id, request.hypothesis_id),
            (self.intervention_id, request.intervention_id),
            (self.prompt_sha256, request.prompt_sha256),
        )
        if any(actual != expected for actual, expected in bound_coordinates):
            raise ValueError("canonical generated code coordinates must match its request")

        identifiers = (self.hypothesis_id, self.intervention_id)
        if self.condition == "observed" and any(value is not None for value in identifiers):
            raise ValueError("canonical observed code must not have intervention identifiers")
        if self.condition == "counterfactual" and any(
            value is None or not value.strip() for value in identifiers
        ):
            raise ValueError("canonical counterfactual code requires intervention identifiers")
        return self


class CanonicalGeneratedCodeRecord(GeneratedCodeRecord):
    _safe_validation_message = _INVALID_CANONICAL_CODE_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    code_id: str = Field(pattern=_CANONICAL_CODE_ID_PATTERN)
    seed_id: StrictInt
    schema_version: Literal["1.0"] = Field()
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    prompt_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    code_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    generation_provenance: GenerationProvenance = Field()
    generation_request: GenerationRequestRecord = Field()


def revalidate_generated_code_record(value: object) -> GeneratedCodeRecord:
    """Snapshot a legacy or canonical record using its exact runtime schema."""

    try:
        if type(value) is CanonicalGeneratedCodeRecord:
            model = CanonicalGeneratedCodeRecord
        elif type(value) is GeneratedCodeRecord:
            model = GeneratedCodeRecord
        else:
            raise TypeError("unexpected generated code record")
        if not model_shape_is_intact(value):
            raise ValueError("unexpected generated code model state")
        snapshot = value.model_dump(
            mode="python",
            round_trip=True,
            warnings=False,
        )
        return model.model_validate(snapshot)
    except Exception:
        pass
    raise GeneratedCodeRecord._safe_error()

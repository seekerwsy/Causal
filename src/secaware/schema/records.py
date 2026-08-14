import hashlib
import json
import re
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.schema.common import (
    MAX_MODEL_ID_CHARS,
    SafeValidationMixin,
    is_valid_model_id,
    model_shape_is_intact,
)
from secaware.schema.generation import (
    GenerationProvenance,
    GenerationRequestRecord,
    revalidate_generation_request_envelope,
    sha256_text,
)
from secaware.schema.experiments import ArmRole, PromptRole


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_CANONICAL_CODE_ID_PATTERN = r"^code_[0-9a-f]{64}$"
_ORACLE_PROFILE_ID_PATTERN = (
    r"^python\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.v[1-9][0-9]*$"
)
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
    prompt_role: PromptRole
    counterpart_prompt_id: str | None = None
    oracle_profile_id: str | None = Field(default=None, pattern=_ORACLE_PROFILE_ID_PATTERN)

    @field_validator("task_id")
    @classmethod
    def validate_task_id(cls, value: str) -> str:
        if not value or not value.strip() or value != value.strip():
            raise ValueError("prompt record validation failed")
        return value

    @field_validator("counterpart_prompt_id", "oracle_profile_id")
    @classmethod
    def validate_counterpart_prompt_id(cls, value: str | None) -> str | None:
        if value is not None and (not value or not value.strip() or value != value.strip()):
            raise ValueError("prompt record validation failed")
        return value

    @model_validator(mode="after")
    def validate_prompt_role(self) -> "PromptRecord":
        variant_roles = {
            PromptRole.POSITIVE_SAFETY_CONTROL,
            PromptRole.TASK_FUNCTION_VARIANT,
            PromptRole.PRESENTATION_VARIANT,
        }
        if self.prompt_role in variant_roles:
            if self.counterpart_prompt_id is None or self.counterpart_prompt_id == self.prompt_id:
                raise ValueError("prompt record validation failed")
        elif self.counterpart_prompt_id is not None:
            raise ValueError("prompt record validation failed")
        if self.split == "discover" and self.prompt_role is not PromptRole.NEUTRAL_BASELINE:
            raise ValueError("prompt record validation failed")
        return self

    @property
    def prompt_sha256(self) -> str:
        """Return the exact UTF-8 content digest without persisting redundant state."""
        return hashlib.sha256(self.prompt.encode("utf-8")).hexdigest()


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
    condition: Literal["observed", "counterfactual", "confirm_arm"]
    model_id: str = Field(min_length=1, max_length=MAX_MODEL_ID_CHARS, strict=True)
    seed_id: int
    code: str = Field(repr=False)
    hypothesis_id: str | None = None
    intervention_id: str | None = None
    assignment_id: str | None = None
    target_spec_id: str | None = None
    target_instance_id: str | None = None
    arm_protocol_id: str | None = None
    protocol_instance_id: str | None = None
    variant_id: str | None = None
    arm_role: ArmRole | None = None
    schema_version: Literal["1.1"] | None = None
    request_id: str | None = Field(default=None, pattern=_REQUEST_ID_PATTERN)
    prompt_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    code_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    generation_provenance: GenerationProvenance | None = None
    generation_request: GenerationRequestRecord | None = None
    provider_result_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    provider_usage_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    provider_runtime_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    provider_policy_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    provider_attempt_count: StrictInt | None = Field(default=None, ge=1, le=10)

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        if value is None or type(value) is ArmRole:
            return value
        if type(value) is str:
            return next((item for item in ArmRole if item.value == value), value)
        return value

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        if not is_valid_model_id(value):
            raise ValueError(_INVALID_GENERATED_CODE_MESSAGE)
        return value

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
        identity = self.model_dump(mode="json", exclude={"code_id", "code"})
        encoded = json.dumps(
            identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if self.code_id != f"code_{hashlib.sha256(encoded).hexdigest()}":
            raise ValueError("canonical code id must match its content identity")

        bound_coordinates = (
            (self.request_id, request.request_id),
            (self.prompt_id, request.prompt_id),
            (self.condition, request.condition),
            (self.model_id, request.model_id),
            (self.seed_id, request.seed_id),
            (self.hypothesis_id, request.hypothesis_id),
            (self.intervention_id, getattr(request, "intervention_id", None)),
            (self.assignment_id, request.assignment_id),
            (self.target_spec_id, request.target_spec_id),
            (self.target_instance_id, request.target_instance_id),
            (self.arm_protocol_id, request.arm_protocol_id),
            (self.protocol_instance_id, request.protocol_instance_id),
            (self.variant_id, request.variant_id),
            (self.arm_role, request.arm_role),
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
        confirmation_coordinates = (
            self.assignment_id,
            self.target_spec_id,
            self.target_instance_id,
            self.arm_protocol_id,
            self.protocol_instance_id,
            self.variant_id,
            self.arm_role,
        )
        if self.condition == "confirm_arm" and any(
            value is None for value in confirmation_coordinates
        ):
            raise ValueError("canonical confirmation code requires assignment coordinates")
        provider_coordinates = (
            self.provider_result_sha256,
            self.provider_usage_sha256,
            self.provider_runtime_sha256,
            self.provider_policy_sha256,
            self.provider_attempt_count,
        )
        if self.condition == "confirm_arm" and any(value is None for value in provider_coordinates):
            raise ValueError("canonical confirmation code requires provider coordinates")
        if self.condition != "confirm_arm" and any(
            value is not None for value in provider_coordinates
        ):
            raise ValueError("canonical non-confirmation code forbids provider coordinates")
        if self.condition != "confirm_arm" and any(
            value is not None for value in confirmation_coordinates
        ):
            raise ValueError("canonical non-confirmation code must not have assignment coordinates")
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
    condition: Literal["observed", "confirm_arm"]
    intervention_id: ClassVar[None] = None
    seed_id: StrictInt
    schema_version: Literal["1.1"] = Field()
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

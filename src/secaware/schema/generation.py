import hashlib
import json
import math
from typing import Literal

from pydantic import ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.errors import JSONValue
from secaware.schema.common import StrictModel, VersionedModel


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_FINITE_NUMBER_PARAMETER_KEYS = frozenset(
    {
        "temperature",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
    }
)
_POSITIVE_INTEGER_PARAMETER_KEYS = frozenset(
    {"max_tokens", "max_completion_tokens", "max_output_tokens", "n"}
)
_INTEGER_PARAMETER_KEYS = frozenset({"seed"})
_NONNEGATIVE_INTEGER_PARAMETER_KEYS = frozenset({"top_logprobs"})
_BOOLEAN_PARAMETER_KEYS = frozenset({"logprobs"})
_STOP_PARAMETER_KEYS = frozenset({"stop"})
_NONEMPTY_STRING_PARAMETER_KEYS = frozenset({"reasoning_effort", "verbosity"})
_V1_PARAMETER_KEYS = frozenset().union(
    _FINITE_NUMBER_PARAMETER_KEYS,
    _POSITIVE_INTEGER_PARAMETER_KEYS,
    _INTEGER_PARAMETER_KEYS,
    _NONNEGATIVE_INTEGER_PARAMETER_KEYS,
    _BOOLEAN_PARAMETER_KEYS,
    _STOP_PARAMETER_KEYS,
    _NONEMPTY_STRING_PARAMETER_KEYS,
)
_INVALID_PARAMETERS_MESSAGE = "generation parameters do not match the canonical v1 contract"
_INVALID_REQUEST_INTEGRITY_MESSAGE = "generation request integrity validation failed"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_allowed_parameter_value(key: str, value: object) -> bool:
    if key in _FINITE_NUMBER_PARAMETER_KEYS:
        return not isinstance(value, bool) and (
            isinstance(value, int)
            or (isinstance(value, float) and math.isfinite(value))
        )
    if key in _POSITIVE_INTEGER_PARAMETER_KEYS:
        return _is_integer(value) and value > 0
    if key in _INTEGER_PARAMETER_KEYS:
        return _is_integer(value)
    if key in _NONNEGATIVE_INTEGER_PARAMETER_KEYS:
        return _is_integer(value) and value >= 0
    if key in _BOOLEAN_PARAMETER_KEYS:
        return isinstance(value, bool)
    if key in _STOP_PARAMETER_KEYS:
        return isinstance(value, str) or (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        )
    if key in _NONEMPTY_STRING_PARAMETER_KEYS:
        return isinstance(value, str) and bool(value.strip())
    return False


class GenerationParameters(StrictModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    values: dict[str, JSONValue] = Field(default_factory=dict)

    @field_validator("values", mode="before")
    @classmethod
    def validate_v1_parameters(cls, values: object) -> object:
        if not isinstance(values, dict):
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        if any(not isinstance(key, str) or key not in _V1_PARAMETER_KEYS for key in values):
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        if any(not _is_allowed_parameter_value(key, value) for key, value in values.items()):
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        return values


def build_generation_request_id(
    *,
    schema_version: str,
    condition: Literal["observed", "counterfactual"],
    prompt_id: str,
    prompt_sha256: str,
    language: str,
    model_id: str,
    seed_id: int,
    hypothesis_id: str | None,
    intervention_id: str | None,
    endpoint_type: Literal["mock", "offline", "chat_completions"],
    system_template_version: str,
    system_template_sha256: str,
    parameters: GenerationParameters,
) -> str:
    identity = {
        "schema_version": schema_version,
        "condition": condition,
        "prompt_id": prompt_id,
        "prompt_sha256": prompt_sha256,
        "language": language,
        "model_id": model_id,
        "seed_id": seed_id,
        "hypothesis_id": hypothesis_id,
        "intervention_id": intervention_id,
        "endpoint_type": endpoint_type,
        "system_template_version": system_template_version,
        "system_template_sha256": system_template_sha256,
        "parameters": parameters.model_dump(mode="json"),
    }
    payload = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"req_{hashlib.sha256(payload).hexdigest()}"


class GenerationRequestRecord(VersionedModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["1.0"]
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    condition: Literal["observed", "counterfactual"]
    prompt_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    prompt_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    language: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    seed_id: StrictInt
    hypothesis_id: str | None = None
    intervention_id: str | None = None
    endpoint_type: Literal["mock", "offline", "chat_completions"]
    system_template_version: str = Field(min_length=1)
    system_template_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    parameters: GenerationParameters = Field(default_factory=GenerationParameters)

    @field_validator(
        "prompt_id",
        "prompt",
        "language",
        "model_id",
        "system_template_version",
    )
    @classmethod
    def reject_blank_required_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("generation request text fields must not be blank")
        return value

    @field_validator("hypothesis_id", "intervention_id")
    @classmethod
    def reject_blank_optional_identifiers(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("generation request identifiers must not be blank")
        return value

    @model_validator(mode="after")
    def validate_request_integrity(self) -> "GenerationRequestRecord":
        identifiers = (self.hypothesis_id, self.intervention_id)
        if self.condition == "observed" and any(value is not None for value in identifiers):
            raise ValueError("observed requests must not have counterfactual identifiers")
        if self.condition == "counterfactual" and any(value is None for value in identifiers):
            raise ValueError("counterfactual requests require both identifiers")
        parameter_seed = self.parameters.values.get("seed")
        if parameter_seed is not None and parameter_seed != self.seed_id:
            raise ValueError(_INVALID_REQUEST_INTEGRITY_MESSAGE)
        if self.prompt_sha256 != sha256_text(self.prompt):
            raise ValueError(_INVALID_REQUEST_INTEGRITY_MESSAGE)
        expected_request_id = build_generation_request_id(
            schema_version=self.schema_version,
            condition=self.condition,
            prompt_id=self.prompt_id,
            prompt_sha256=self.prompt_sha256,
            language=self.language,
            model_id=self.model_id,
            seed_id=self.seed_id,
            hypothesis_id=self.hypothesis_id,
            intervention_id=self.intervention_id,
            endpoint_type=self.endpoint_type,
            system_template_version=self.system_template_version,
            system_template_sha256=self.system_template_sha256,
            parameters=self.parameters,
        )
        if self.request_id != expected_request_id:
            raise ValueError(_INVALID_REQUEST_INTEGRITY_MESSAGE)
        return self

import math
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

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


class GenerationRequestRecord(VersionedModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["1.0"]
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    condition: Literal["observed", "counterfactual"]
    prompt_id: str
    prompt: str = Field(min_length=1)
    prompt_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    language: str
    model_id: str
    seed_id: int
    hypothesis_id: str | None = None
    intervention_id: str | None = None
    endpoint_type: Literal["mock", "offline", "chat_completions"]
    system_template_version: str
    system_template_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    parameters: GenerationParameters = Field(default_factory=GenerationParameters)

    @field_validator("prompt")
    @classmethod
    def reject_blank_prompt(cls, prompt: str) -> str:
        if not prompt.strip():
            raise ValueError("prompt must not be blank")
        return prompt

    @model_validator(mode="after")
    def validate_condition_identifiers(self) -> "GenerationRequestRecord":
        identifiers = (self.hypothesis_id, self.intervention_id)
        if self.condition == "observed" and any(value is not None for value in identifiers):
            raise ValueError("observed requests must not have counterfactual identifiers")
        if self.condition == "counterfactual" and any(value is None for value in identifiers):
            raise ValueError("counterfactual requests require both identifiers")
        return self

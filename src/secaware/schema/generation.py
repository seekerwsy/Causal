import math
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from secaware.errors import JSONValue
from secaware.schema.common import StrictModel, VersionedModel


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_V1_PARAMETER_KEYS = frozenset(
    {
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "seed",
        "stop",
        "frequency_penalty",
        "presence_penalty",
        "n",
        "logprobs",
        "top_logprobs",
        "reasoning_effort",
        "verbosity",
    }
)
_NUMERIC_PARAMETER_KEYS = frozenset(
    {
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "seed",
        "frequency_penalty",
        "presence_penalty",
        "n",
        "top_logprobs",
    }
)
_INVALID_PARAMETERS_MESSAGE = "generation parameters do not match the canonical v1 contract"


def _is_canonical_scalar(value: object) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return False


def _is_allowed_parameter_value(key: str, value: object) -> bool:
    if key in _NUMERIC_PARAMETER_KEYS and isinstance(value, bool):
        return False
    if _is_canonical_scalar(value):
        return True
    return key == "stop" and isinstance(value, list) and all(
        isinstance(item, str) for item in value
    )


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

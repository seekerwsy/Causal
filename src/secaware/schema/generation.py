import math
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from secaware.errors import JSONValue, is_sensitive_key
from secaware.schema.common import StrictModel, VersionedModel


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"


def _contains_provider_credential(value: JSONValue) -> bool:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if is_sensitive_key(key):
                return True
            if _contains_provider_credential(nested_value):
                return True
    elif isinstance(value, list):
        return any(_contains_provider_credential(item) for item in value)
    return False


def _contains_non_finite_number(value: JSONValue) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_contains_non_finite_number(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_non_finite_number(item) for item in value)
    return False


class GenerationParameters(StrictModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    values: dict[str, JSONValue] = Field(default_factory=dict)

    @field_validator("values")
    @classmethod
    def reject_provider_credentials(
        cls, values: dict[str, JSONValue]
    ) -> dict[str, JSONValue]:
        if _contains_provider_credential(values):
            raise ValueError("generation parameters must not contain provider credentials")
        if _contains_non_finite_number(values):
            raise ValueError("generation parameters must contain canonical JSON values")
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

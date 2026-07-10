from collections.abc import Iterator, Mapping, Sequence
import hashlib
import json
import math
from typing import Any, ClassVar, Literal, TypeVar, cast

from pydantic import (
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

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


_SafeValidationModel = TypeVar(
    "_SafeValidationModel",
    bound="_SafeValidationMixin",
)


def _sanitized_validation_error(
    model_name: str,
    message: str,
    *,
    input_type: Literal["python", "json"] = "python",
) -> ValidationError:
    return ValidationError.from_exception_data(
        model_name,
        [
            {
                "type": PydanticCustomError("generation_validation", message),
                "loc": (),
                "input": None,
            }
        ],
        input_type=input_type,
        hide_input=True,
    )


class _SafeValidationMixin:
    _safe_validation_message: ClassVar[str]

    @classmethod
    def _safe_error(
        cls,
        input_type: Literal["python", "json"] = "python",
    ) -> ValidationError:
        return _sanitized_validation_error(
            cls.__name__,
            cls._safe_validation_message,
            input_type=input_type,
        )

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError:
            pass
        else:
            return
        raise type(self)._safe_error()

    @classmethod
    def model_validate(
        cls: type[_SafeValidationModel],
        obj: object,
        **kwargs: Any,
    ) -> _SafeValidationModel:
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError:
            pass
        raise cls._safe_error()

    @classmethod
    def model_validate_json(
        cls: type[_SafeValidationModel],
        json_data: str | bytes | bytearray,
        **kwargs: Any,
    ) -> _SafeValidationModel:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError:
            pass
        raise cls._safe_error("json")

    @classmethod
    def model_validate_strings(
        cls: type[_SafeValidationModel],
        obj: object,
        **kwargs: Any,
    ) -> _SafeValidationModel:
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError:
            pass
        raise cls._safe_error()


class _FrozenJSONSequence(Sequence[object]):
    __slots__ = ("__items",)

    def __init__(self, values: Sequence[object]) -> None:
        object.__setattr__(
            self,
            "_FrozenJSONSequence__items",
            tuple(_freeze_json(value) for value in values),
        )

    def __getitem__(self, index: int | slice) -> object:
        return self.__items[index]

    def __iter__(self) -> Iterator[object]:
        return iter(self.__items)

    def __len__(self) -> int:
        return len(self.__items)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (str, bytes)) or not isinstance(other, Sequence):
            return False
        return _thaw_json(self) == _thaw_json(other)

    def __repr__(self) -> str:
        return repr(_thaw_json(self))

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("generation parameter values are read-only")

    def __deepcopy__(self, memo: dict[int, object]) -> "_FrozenJSONSequence":
        return self


class _FrozenJSONMapping(Mapping[str, object]):
    __slots__ = ("__items",)

    def __init__(self, values: Mapping[str, object]) -> None:
        object.__setattr__(
            self,
            "_FrozenJSONMapping__items",
            tuple((key, _freeze_json(value)) for key, value in values.items()),
        )

    def __getitem__(self, key: str) -> object:
        for candidate, value in self.__items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.__items)

    def __len__(self) -> int:
        return len(self.__items)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return False
        return _thaw_json(self) == _thaw_json(other)

    def __repr__(self) -> str:
        return repr(_thaw_json(self))

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("generation parameter values are read-only")

    def __deepcopy__(self, memo: dict[int, object]) -> "_FrozenJSONMapping":
        return self


def _snapshot_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            key: _snapshot_json_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (_FrozenJSONSequence, list)):
        return [_snapshot_json_value(item) for item in value]
    return value


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return _FrozenJSONMapping(value)
    if isinstance(value, list):
        return _FrozenJSONSequence(value)
    return value


def _thaw_json(value: object) -> JSONValue:
    if isinstance(value, Mapping):
        return cast(
            JSONValue,
            {key: _thaw_json(item) for key, item in value.items()},
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return cast(JSONValue, [_thaw_json(item) for item in value])
    return cast(JSONValue, value)


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


class GenerationParameters(_SafeValidationMixin, StrictModel):
    _safe_validation_message = _INVALID_PARAMETERS_MESSAGE

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
    )

    values: Mapping[str, JSONValue] = Field(default_factory=dict)

    @field_validator("values", mode="before")
    @classmethod
    def validate_v1_parameters(cls, values: object) -> object:
        if not isinstance(values, Mapping):
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        try:
            snapshot = cast(dict[str, JSONValue], _snapshot_json_value(values))
        except Exception:
            raise ValueError(_INVALID_PARAMETERS_MESSAGE) from None
        if any(not isinstance(key, str) or key not in _V1_PARAMETER_KEYS for key in snapshot):
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        if any(
            not _is_allowed_parameter_value(key, value)
            for key, value in snapshot.items()
        ):
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        return snapshot

    @field_validator("values")
    @classmethod
    def freeze_values(cls, values: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
        return cast(Mapping[str, JSONValue], _FrozenJSONMapping(values))

    @field_serializer("values")
    def serialize_values(self, values: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        return cast(dict[str, JSONValue], _thaw_json(values))


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


class GenerationRequestRecord(_SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_REQUEST_INTEGRITY_MESSAGE

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
    )

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

from collections.abc import Iterator, Mapping, Sequence
import hashlib
from itertools import islice
import json
import math
from typing import Literal, cast

from pydantic import (
    ConfigDict,
    Field,
    FiniteFloat,
    StrictBool,
    StrictInt,
    field_serializer,
    field_validator,
    model_validator,
)

from secaware.errors import JSONValue
from secaware.schema.common import (
    SafeValidationMixin,
    StrictModel,
    VersionedModel,
    model_shape_is_intact,
)


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
MAX_GENERATION_PARAMETER_ITEMS = len(_V1_PARAMETER_KEYS)
MAX_STOP_PARAMETER_ITEMS = 64
_INVALID_PARAMETERS_MESSAGE = "generation parameters do not match the canonical v1 contract"
_INVALID_REQUEST_INTEGRITY_MESSAGE = "generation request integrity validation failed"
_INVALID_PROVENANCE_MESSAGE = "generation provenance validation failed"
_INVALID_ATTEMPT_MESSAGE = "generation attempt validation failed"
_INVALID_OFFLINE_RESULT_MESSAGE = "offline generation result validation failed"


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


def _snapshot_stop_parameter(value: object) -> str | list[str]:
    if type(value) is str:
        return value
    if not isinstance(value, (_FrozenJSONSequence, list)):
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)

    snapshot: list[str] = []
    for index, item in enumerate(islice(value, MAX_STOP_PARAMETER_ITEMS + 1)):
        if index == MAX_STOP_PARAMETER_ITEMS or type(item) is not str:
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        snapshot.append(item)
    return snapshot


def _snapshot_parameter_value(key: str, value: object) -> JSONValue:
    if key in _FINITE_NUMBER_PARAMETER_KEYS:
        if type(value) is int:
            return value
        if type(value) is float and math.isfinite(value):
            return value
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)
    if key in _POSITIVE_INTEGER_PARAMETER_KEYS:
        if type(value) is int and value > 0:
            return value
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)
    if key in _INTEGER_PARAMETER_KEYS:
        if type(value) is int:
            return value
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)
    if key in _NONNEGATIVE_INTEGER_PARAMETER_KEYS:
        if type(value) is int and value >= 0:
            return value
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)
    if key in _BOOLEAN_PARAMETER_KEYS:
        if type(value) is bool:
            return value
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)
    if key in _STOP_PARAMETER_KEYS:
        return _snapshot_stop_parameter(value)
    if key in _NONEMPTY_STRING_PARAMETER_KEYS:
        if type(value) is str and value.strip():
            return value
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)
    raise ValueError(_INVALID_PARAMETERS_MESSAGE)


def _snapshot_v1_parameters(values: object) -> dict[str, JSONValue]:
    if not isinstance(values, Mapping):
        raise ValueError(_INVALID_PARAMETERS_MESSAGE)

    snapshot: dict[str, JSONValue] = {}
    for index, key in enumerate(islice(values, MAX_GENERATION_PARAMETER_ITEMS + 1)):
        if index == MAX_GENERATION_PARAMETER_ITEMS:
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        if type(key) is not str or key not in _V1_PARAMETER_KEYS or key in snapshot:
            raise ValueError(_INVALID_PARAMETERS_MESSAGE)
        snapshot[key] = _snapshot_parameter_value(key, values[key])
    return snapshot


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


class GenerationProvenance(SafeValidationMixin, StrictModel):
    _safe_validation_message = _INVALID_PROVENANCE_MESSAGE

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    producer: str = Field(min_length=1)
    producer_version: str | None = Field(default=None, min_length=1)
    source_batch_id: str | None = Field(default=None, min_length=1)

    @field_validator("producer", "producer_version", "source_batch_id")
    @classmethod
    def reject_blank_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(_INVALID_PROVENANCE_MESSAGE)
        return value


class GenerationAttemptRecord(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_ATTEMPT_MESSAGE

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN, repr=False)
    attempt: StrictInt = Field(ge=1)
    outcome: Literal["success", "retry", "failure"]
    error_code: StrictInt | None
    retryable: StrictBool
    backoff_seconds: FiniteFloat = Field(ge=0.0)


class GenerationParameters(SafeValidationMixin, StrictModel):
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
        try:
            return _snapshot_v1_parameters(values)
        except Exception:
            raise ValueError(_INVALID_PARAMETERS_MESSAGE) from None

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
    endpoint_sha256: str,
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
        "endpoint_sha256": endpoint_sha256,
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


class GenerationRequestRecord(SafeValidationMixin, VersionedModel):
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
    endpoint_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
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
            endpoint_sha256=self.endpoint_sha256,
            system_template_version=self.system_template_version,
            system_template_sha256=self.system_template_sha256,
            parameters=self.parameters,
        )
        if self.request_id != expected_request_id:
            raise ValueError(_INVALID_REQUEST_INTEGRITY_MESSAGE)
        return self


class OfflineGenerationResultRecord(GenerationRequestRecord):
    _safe_validation_message = _INVALID_OFFLINE_RESULT_MESSAGE

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    endpoint_type: Literal["offline"]
    code: str = Field(min_length=1)
    code_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    provenance: GenerationProvenance

    @field_validator("code")
    @classmethod
    def reject_blank_code(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(_INVALID_OFFLINE_RESULT_MESSAGE)
        return value

    @model_validator(mode="after")
    def validate_code_integrity(self) -> "OfflineGenerationResultRecord":
        if self.code_sha256 != sha256_text(self.code):
            raise ValueError(_INVALID_OFFLINE_RESULT_MESSAGE)
        return self


def revalidate_generation_request_envelope(
    value: object,
) -> GenerationRequestRecord:
    """Snapshot and revalidate only the canonical request portion of a record."""

    try:
        if type(value) not in {GenerationRequestRecord, OfflineGenerationResultRecord}:
            raise TypeError("unexpected generation request envelope")
        if not model_shape_is_intact(value):
            raise ValueError("unexpected generation request model state")
        snapshot = value.model_dump(
            mode="python",
            round_trip=True,
            warnings=False,
        )
        envelope = {
            field_name: snapshot[field_name] for field_name in GenerationRequestRecord.model_fields
        }
        return GenerationRequestRecord.model_validate(envelope)
    except Exception:
        pass
    raise GenerationRequestRecord._safe_error()


def revalidate_offline_generation_result(
    value: object,
) -> OfflineGenerationResultRecord:
    """Snapshot a result and reject undeclared state hidden by unsafe model APIs."""

    try:
        if type(value) is not OfflineGenerationResultRecord:
            raise TypeError("unexpected offline generation result")
        if not model_shape_is_intact(value):
            raise ValueError("unexpected offline generation result model state")
        snapshot = value.model_dump(
            mode="python",
            round_trip=True,
            warnings=False,
        )
        return OfflineGenerationResultRecord.model_validate(snapshot)
    except Exception:
        pass
    raise OfflineGenerationResultRecord._safe_error()


def generation_request_envelopes_match(
    expected: object,
    received: object,
) -> bool:
    """Safely compare complete, independently revalidated request envelopes."""

    try:
        expected_envelope = revalidate_generation_request_envelope(expected)
        received_envelope = revalidate_generation_request_envelope(received)
        return expected_envelope.model_dump(
            mode="json",
            warnings=False,
        ) == received_envelope.model_dump(
            mode="json",
            warnings=False,
        )
    except Exception:
        pass
    raise GenerationRequestRecord._safe_error()

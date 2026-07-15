from collections.abc import Iterator, Mapping, Sequence
import hashlib
from itertools import islice
import json
import math
import re
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
    MAX_MODEL_ID_CHARS,
    SafeValidationMixin,
    StrictModel,
    VersionedModel,
    is_valid_model_id,
    model_shape_is_intact,
)
from secaware.schema.experiments import ArmRole


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_CONFIRM_COORDINATE_PATTERNS = (
    ("hypothesis_id", re.compile(r"^hypothesis_[0-9a-f]{64}$")),
    ("assignment_id", re.compile(r"^assignment_[0-9a-f]{64}$")),
    ("target_spec_id", re.compile(r"^target_[0-9a-f]{64}$")),
    ("target_instance_id", re.compile(r"^target_instance_[0-9a-f]{64}$")),
    ("arm_protocol_id", re.compile(r"^arm_protocol_[0-9a-f]{64}$")),
    ("protocol_instance_id", re.compile(r"^protocol_instance_[0-9a-f]{64}$")),
    ("variant_id", re.compile(r"^variant_[0-9a-f]{64}$")),
)
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
GENERATION_REQUEST_SCHEMA_VERSION = "1.2"
GenerationCondition = Literal["observed", "confirm_arm"]
EndpointType = Literal["mock", "offline", "chat_completions"]


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


class ProviderUsageRecord(SafeValidationMixin, StrictModel):
    _safe_validation_message = "provider usage validation failed"

    prompt_tokens: StrictInt = Field(ge=0)
    completion_tokens: StrictInt = Field(ge=0)
    total_tokens: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_total(self) -> "ProviderUsageRecord":
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError(self._safe_validation_message)
        return self


def _provider_digest(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", warnings=False)  # type: ignore[union-attr]
    elif isinstance(value, Mapping):
        value = {key: _provider_json_value(item) for key, item in value.items()}
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        value = [_provider_json_value(item) for item in value]
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _provider_json_value(value: object) -> object:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", warnings=False)  # type: ignore[union-attr]
    if isinstance(value, Mapping):
        return {key: _provider_json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_provider_json_value(item) for item in value]
    return value


def provider_usage_sha256(usage: ProviderUsageRecord) -> str:
    return _provider_digest(usage.model_dump(mode="json"))


def provider_provenance_sha256(provenance: GenerationProvenance) -> str:
    return _provider_digest(provenance.model_dump(mode="json"))


class ProviderResultEnvelope(SafeValidationMixin, StrictModel):
    """Exact, self-addressed response metadata accepted by confirmation generation."""

    _safe_validation_message = "provider result envelope validation failed"

    schema_version: Literal["1.0"]
    result_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN, repr=False)
    model_id: str = Field(min_length=1, max_length=MAX_MODEL_ID_CHARS, strict=True)
    finish_reason: Literal["stop", "content_filter"]
    code: str | None = Field(default=None, repr=False)
    usage: ProviderUsageRecord
    attempts: tuple[GenerationAttemptRecord, ...] = Field(min_length=1, max_length=10)
    provenance: GenerationProvenance
    provider_policy_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    runtime_fingerprint_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        if not is_valid_model_id(value):
            raise ValueError(cls._safe_validation_message)
        return value

    @classmethod
    def from_content(cls, **content: object) -> "ProviderResultEnvelope":
        payload = {"schema_version": "1.0", **content}
        payload["result_sha256"] = _provider_digest(payload)
        try:
            return cls.model_validate(payload)
        finally:
            content.clear()
            payload.clear()

    @field_validator("usage", mode="before")
    @classmethod
    def snapshot_usage(cls, value: object) -> object:
        if type(value) is ProviderUsageRecord:
            value = value.model_dump(mode="python", round_trip=True, warnings=False)
        return ProviderUsageRecord.model_validate(value)

    @field_validator("attempts", mode="before")
    @classmethod
    def snapshot_attempts(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        return tuple(
            GenerationAttemptRecord.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False)
                if type(item) is GenerationAttemptRecord
                else item
            )
            for item in value
        )

    @field_validator("provenance", mode="before")
    @classmethod
    def snapshot_provenance(cls, value: object) -> object:
        if type(value) is GenerationProvenance:
            value = value.model_dump(mode="python", round_trip=True, warnings=False)
        return GenerationProvenance.model_validate(value)

    @model_validator(mode="after")
    def validate_integrity(self) -> "ProviderResultEnvelope":
        attempt_numbers = tuple(item.attempt for item in self.attempts)
        provenance_bytes = len(
            json.dumps(
                self.provenance.model_dump(mode="json", warnings=False),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        code_valid = (
            self.finish_reason == "stop" and type(self.code) is str and bool(self.code.strip())
        ) or (self.finish_reason == "content_filter" and self.code is None)
        if (
            not code_valid
            or any(item.request_id != self.request_id for item in self.attempts)
            or attempt_numbers != tuple(range(1, len(self.attempts) + 1))
            or self.attempts[-1].outcome != "success"
            or any(item.outcome != "retry" for item in self.attempts[:-1])
            or provenance_bytes > 4_096
            or self.result_sha256
            != _provider_digest(self.model_dump(mode="json", exclude={"result_sha256"}))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class GenerationParameters(SafeValidationMixin, StrictModel):
    _safe_validation_message = _INVALID_PARAMETERS_MESSAGE

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
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
    schema_version: Literal["1.2"],
    condition: GenerationCondition,
    prompt_id: str,
    prompt_sha256: str,
    language: str,
    model_id: str,
    seed_id: int,
    hypothesis_id: str | None,
    endpoint_type: EndpointType,
    endpoint_sha256: str,
    system_template_version: str,
    system_template_sha256: str,
    parameters: GenerationParameters,
    assignment_id: str | None = None,
    target_spec_id: str | None = None,
    target_instance_id: str | None = None,
    arm_protocol_id: str | None = None,
    protocol_instance_id: str | None = None,
    variant_id: str | None = None,
    arm_role: object | None = None,
) -> str:
    if (
        schema_version != GENERATION_REQUEST_SCHEMA_VERSION
        or condition not in {"observed", "confirm_arm"}
        or not is_valid_model_id(model_id)
    ):
        raise ValueError("generation request identity is not canonical")
    identity: dict[str, object] = {
        "schema_version": schema_version,
        "condition": condition,
        "prompt_id": prompt_id,
        "prompt_sha256": prompt_sha256,
        "language": language,
        "model_id": model_id,
        "seed_id": seed_id,
        "hypothesis_id": hypothesis_id,
        "endpoint_type": endpoint_type,
        "endpoint_sha256": endpoint_sha256,
        "system_template_version": system_template_version,
        "system_template_sha256": system_template_sha256,
        "parameters": parameters.model_dump(mode="json"),
    }
    identity.update(
        {
            "assignment_id": assignment_id,
            "target_spec_id": target_spec_id,
            "target_instance_id": target_instance_id,
            "arm_protocol_id": arm_protocol_id,
            "protocol_instance_id": protocol_instance_id,
            "variant_id": variant_id,
            "arm_role": getattr(arm_role, "value", arm_role) if arm_role is not None else None,
        }
    )
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
        strict=True,
    )

    schema_version: Literal["1.2"]
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    condition: GenerationCondition
    prompt_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1, repr=False)
    prompt_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    language: str = Field(min_length=1)
    model_id: str = Field(min_length=1, max_length=MAX_MODEL_ID_CHARS, strict=True)
    seed_id: StrictInt
    hypothesis_id: str | None = None
    assignment_id: str | None = None
    target_spec_id: str | None = None
    target_instance_id: str | None = None
    arm_protocol_id: str | None = None
    protocol_instance_id: str | None = None
    variant_id: str | None = None
    arm_role: ArmRole | None = None
    endpoint_type: EndpointType
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

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        if not is_valid_model_id(value):
            raise ValueError(_INVALID_REQUEST_INTEGRITY_MESSAGE)
        return value

    @field_validator(
        "hypothesis_id",
        "assignment_id",
        "target_spec_id",
        "target_instance_id",
        "arm_protocol_id",
        "protocol_instance_id",
        "variant_id",
    )
    @classmethod
    def reject_blank_optional_identifiers(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("generation request identifiers must not be blank")
        return value

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        if value is None or type(value) is ArmRole:
            return value
        if type(value) is str:
            return next((item for item in ArmRole if item.value == value), value)
        return value

    @model_validator(mode="after")
    def validate_request_integrity(self) -> "GenerationRequestRecord":
        experiment_coordinates = (
            self.hypothesis_id,
            self.assignment_id,
            self.target_spec_id,
            self.target_instance_id,
            self.arm_protocol_id,
            self.protocol_instance_id,
            self.variant_id,
            self.arm_role,
        )
        if self.condition == "observed" and (
            any(value is not None for value in experiment_coordinates)
        ):
            raise ValueError("observed requests must not have counterfactual identifiers")
        if self.condition == "confirm_arm":
            if any(value is None for value in experiment_coordinates):
                raise ValueError("confirmation requests require complete assignment coordinates")
            try:
                if type(self.arm_role) is not ArmRole or any(
                    pattern.fullmatch(getattr(self, field_name) or "") is None
                    for field_name, pattern in _CONFIRM_COORDINATE_PATTERNS
                ):
                    raise ValueError
            except Exception:
                raise ValueError(_INVALID_REQUEST_INTEGRITY_MESSAGE) from None
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
            assignment_id=self.assignment_id,
            target_spec_id=self.target_spec_id,
            target_instance_id=self.target_instance_id,
            arm_protocol_id=self.arm_protocol_id,
            protocol_instance_id=self.protocol_instance_id,
            variant_id=self.variant_id,
            arm_role=self.arm_role,
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

    snapshot: dict[str, object] = {}
    envelope: dict[str, object] = {}
    result: GenerationRequestRecord | None = None
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
        result = GenerationRequestRecord.model_validate(envelope)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        pass
    finally:
        value = None
        snapshot.clear()
        envelope.clear()
    if result is None:
        raise GenerationRequestRecord._safe_error()
    return result


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

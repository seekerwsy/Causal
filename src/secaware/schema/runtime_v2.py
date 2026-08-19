"""Prospective v2 runtime records for the two data-generating regimes.

The legacy generation, code, Oracle, functional, and causal-observation schemas
intentionally remain untouched.  These contracts make the v3 coordinates explicit and
keep natural-Prompt features (``X0``), randomized assignment (``A``), and the
post-intervention diagnostic projection (``XAR``) in distinct record types.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any, ClassVar, Literal, NoReturn, Self

from pydantic import ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel, is_valid_model_id
from secaware.schema.experiments import ArmRole

RUNTIME_V2_SCHEMA_VERSION = "2.0"
DiscoveryRegimeId = Literal["natural_prompt_discovery"]
ConfirmationRegimeId = Literal["randomized_confirmation"]
RuntimeRegimeId = DiscoveryRegimeId | ConfirmationRegimeId

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_CONTENT_ID_PATTERN = r"^[a-z][a-z0-9_]*_[0-9a-f]{64}$"
_ASSIGNMENT_ID_PATTERN = r"^assignment_[0-9a-f]{64}$"
_HYPOTHESIS_ID_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_REALIZATION_SPEC_ID_PATTERN = r"^realization_spec_[0-9a-f]{64}$"
_TASK_BUNDLE_ID_PATTERN = r"^task_realization_bundle_[0-9a-f]{64}$"


def _jsonable(value: object) -> object:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return getattr(value, "value", value)


def _digest(value: object) -> str:
    payload = json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _valid_identifier(value: object) -> bool:
    return type(value) is str and bool(_IDENTIFIER_RE.fullmatch(value))


def _raise_contract_error(model_type: type[SafeValidationMixin]) -> NoReturn:
    raise model_type._safe_error()


class _RuntimeV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "runtime v2 contract failed validation"

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


class NaturalX0ValueV2(_RuntimeV2Contract):
    """One pre-treatment natural-Prompt variable value; never an assignment diagnostic."""

    variable_id: str
    state: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        if not _valid_identifier(self.variable_id):
            raise ValueError(self._safe_validation_message)
        return self


class DiagnosticXARValueV2(_RuntimeV2Contract):
    """One independently extracted post-assignment fidelity diagnostic."""

    variable_id: str
    state: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        if not _valid_identifier(self.variable_id):
            raise ValueError(self._safe_validation_message)
        return self


class NaturalOutcomeValueV2(_RuntimeV2Contract):
    variable_id: str
    state: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        if not _valid_identifier(self.variable_id):
            raise ValueError(self._safe_validation_message)
        return self


class _RuntimeCoordinatesV2(_RuntimeV2Contract):
    schema_version: Literal["2.0"]
    regime_id: RuntimeRegimeId
    semantic_task_cluster_id: str
    task_instance_id: str
    request_randomness_slot: StrictInt = Field(ge=0)
    provider_seed: StrictInt | None

    # These coordinates are all absent in discovery and all present in confirmation.
    assignment_id: str | None = Field(default=None, pattern=_ASSIGNMENT_ID_PATTERN)
    hypothesis_id: str | None = Field(default=None, pattern=_HYPOTHESIS_ID_PATTERN)
    realization_spec_id: str | None = Field(default=None, pattern=_REALIZATION_SPEC_ID_PATTERN)
    task_realization_bundle_id: str | None = Field(default=None, pattern=_TASK_BUNDLE_ID_PATTERN)
    assigned_arm: ArmRole | None = None

    @field_validator("assigned_arm", mode="before")
    @classmethod
    def parse_arm(cls, value: object) -> object:
        if value is None or type(value) is ArmRole:
            return value
        if type(value) is str:
            return next((item for item in ArmRole if item.value == value), value)
        return value

    @model_validator(mode="after")
    def validate_regime_coordinates(self) -> Self:
        if not _valid_identifier(self.semantic_task_cluster_id) or not _valid_identifier(
            self.task_instance_id
        ):
            raise ValueError(self._safe_validation_message)
        confirmation = (
            self.assignment_id,
            self.hypothesis_id,
            self.realization_spec_id,
            self.task_realization_bundle_id,
            self.assigned_arm,
        )
        if self.regime_id == "natural_prompt_discovery":
            if any(value is not None for value in confirmation):
                raise ValueError("discovery records forbid confirmation-only coordinates")
        elif any(value is None for value in confirmation):
            raise ValueError("confirmation records require complete assignment coordinates")
        return self

    def exact_coordinates(self) -> tuple[object, ...]:
        """Return every coordinate, including explicit ``None`` provider seeds."""

        return (
            self.regime_id,
            self.semantic_task_cluster_id,
            self.task_instance_id,
            self.request_randomness_slot,
            self.provider_seed,
            self.assignment_id,
            self.hypothesis_id,
            self.realization_spec_id,
            self.task_realization_bundle_id,
            self.assigned_arm,
        )


class _ContentAddressedRuntimeV2(_RuntimeCoordinatesV2):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": RUNTIME_V2_SCHEMA_VERSION, **content}
            # Materialize declared defaults before hashing so an omitted optional field and
            # its canonical explicit default have one stable content address.  Required
            # nullable coordinates (notably provider_seed) are never supplied this way.
            for field_name, field in cls.model_fields.items():
                if (
                    field_name not in payload
                    and field_name != cls._id_field
                    and not field.is_required()
                ):
                    payload[field_name] = field.get_default(call_default_factory=True)
            record_id = cls._id_prefix + _digest(payload)
            return cls(**payload, **{cls._id_field: record_id})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - fail closed and sanitize the schema boundary
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class GenerationRequestRecordV2(_ContentAddressedRuntimeV2):
    _id_field: ClassVar[str] = "generation_request_id"
    _id_prefix: ClassVar[str] = "generation_request_v2_"

    generation_request_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    prompt_id: str
    prompt: str = Field(min_length=1, repr=False)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    language: str
    model_id: str
    endpoint_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_parameters_sha256: str = Field(pattern=_SHA256_PATTERN)
    system_template_sha256: str = Field(pattern=_SHA256_PATTERN)
    generator_producer_id: str
    generator_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if (
            not _valid_identifier(self.prompt_id)
            or not _valid_identifier(self.language)
            or not _valid_identifier(self.generator_producer_id)
            or not is_valid_model_id(self.model_id)
            or not self.prompt.strip()
            or hashlib.sha256(self.prompt.encode("utf-8")).hexdigest() != self.prompt_sha256
        ):
            raise ValueError(self._safe_validation_message)
        return self


class GeneratedCodeRecordV2(_ContentAddressedRuntimeV2):
    _id_field: ClassVar[str] = "generated_code_id"
    _id_prefix: ClassVar[str] = "generated_code_v2_"

    generated_code_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    generation_request_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    code_status: Literal["generated", "terminal_no_code"]
    code: str | None = Field(default=None, repr=False)
    code_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    terminal_reason: str | None = None
    provider_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    generator_runtime_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_code_state(self) -> Self:
        generated = self.code_status == "generated"
        valid_code = type(self.code) is str and bool(self.code.strip())
        if generated:
            if (
                not valid_code
                or self.code_sha256 != hashlib.sha256(self.code.encode("utf-8")).hexdigest()
                or self.terminal_reason is not None
            ):
                raise ValueError(self._safe_validation_message)
        elif (
            self.code is not None
            or self.code_sha256 is not None
            or not _valid_identifier(self.terminal_reason)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class OracleResultRecordV2(_ContentAddressedRuntimeV2):
    _id_field: ClassVar[str] = "oracle_result_id"
    _id_prefix: ClassVar[str] = "oracle_result_v2_"

    oracle_result_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    generated_code_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    code_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    status: Literal[
        "secure",
        "insecure",
        "unknown",
        "not_evaluated_no_valid_code",
        "infrastructure_failure",
    ]
    oracle_supported: bool
    oracle_evaluable: bool
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    oracle_producer_id: str
    oracle_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    oracle_runtime_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_oracle_state(self) -> Self:
        determinate = self.status in {"secure", "insecure"}
        if (
            not _valid_identifier(self.oracle_producer_id)
            or determinate != (self.oracle_supported and self.oracle_evaluable)
            or (
                self.status == "not_evaluated_no_valid_code"
                and (self.code_sha256 is not None or self.oracle_supported or self.oracle_evaluable)
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FunctionalResultRecordV2(_ContentAddressedRuntimeV2):
    _id_field: ClassVar[str] = "functional_result_id"
    _id_prefix: ClassVar[str] = "functional_result_v2_"

    functional_result_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    generated_code_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    code_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    status: Literal[
        "pass",
        "fail",
        "unknown",
        "not_applicable",
        "not_evaluated_no_valid_code",
        "infrastructure_failure",
    ]
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluator_producer_id: str
    evaluator_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluator_runtime_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_functional_state(self) -> Self:
        if not _valid_identifier(self.evaluator_producer_id) or (
            self.status == "not_evaluated_no_valid_code" and self.code_sha256 is not None
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ConfirmationAssignmentRecordV2(_ContentAddressedRuntimeV2):
    """The randomized treatment ``A``; it contains no natural or diagnostic feature values."""

    _id_field: ClassVar[str] = "assignment_record_id"
    _id_prefix: ClassVar[str] = "assignment_record_v2_"

    regime_id: Literal["randomized_confirmation"]
    assignment_record_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    randomization_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)


class PostInterventionDiagnosticRecordV2(_ContentAddressedRuntimeV2):
    """The post-treatment ``XAR`` projection; diagnostics never encode assignment effects."""

    _id_field: ClassVar[str] = "post_intervention_diagnostic_id"
    _id_prefix: ClassVar[str] = "post_intervention_diagnostic_v2_"

    regime_id: Literal["randomized_confirmation"]
    post_intervention_diagnostic_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    assignment_record_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    diagnostic_xar: tuple[DiagnosticXARValueV2, ...] = Field(min_length=1, max_length=10_000)
    extractor_producer_id: str
    extractor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_diagnostic(self) -> Self:
        ids = tuple(value.variable_id for value in self.diagnostic_xar)
        if (
            ids != tuple(sorted(ids))
            or len(ids) != len(set(ids))
            or not _valid_identifier(self.extractor_producer_id)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class NaturalCausalObservationRecordV2(_ContentAddressedRuntimeV2):
    """One discovery row containing only natural ``X0`` and committed outcomes."""

    _id_field: ClassVar[str] = "natural_causal_observation_id"
    _id_prefix: ClassVar[str] = "natural_causal_observation_v2_"

    regime_id: Literal["natural_prompt_discovery"]
    natural_causal_observation_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    producer_chain_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    table_id: str
    prompt_id: str
    model_id: str
    natural_x0: tuple[NaturalX0ValueV2, ...] = Field(min_length=1, max_length=10_000)
    outcomes: tuple[NaturalOutcomeValueV2, ...] = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        x_ids = tuple(value.variable_id for value in self.natural_x0)
        y_ids = tuple(value.variable_id for value in self.outcomes)
        if (
            not _valid_identifier(self.table_id)
            or not _valid_identifier(self.prompt_id)
            or not is_valid_model_id(self.model_id)
            or x_ids != tuple(sorted(x_ids))
            or y_ids != tuple(sorted(y_ids))
            or len(x_ids) != len(set(x_ids))
            or len(y_ids) != len(set(y_ids))
            or set(x_ids) & set(y_ids)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class RuntimeProducerChainRecordV2(_ContentAddressedRuntimeV2):
    _id_field: ClassVar[str] = "producer_chain_id"
    _id_prefix: ClassVar[str] = "producer_chain_v2_"

    producer_chain_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    generation_request_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    generated_code_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    oracle_result_id: str = Field(pattern=_CONTENT_ID_PATTERN)
    functional_result_id: str = Field(pattern=_CONTENT_ID_PATTERN)


def validate_runtime_producer_chain_v2(
    generation_request: GenerationRequestRecordV2,
    generated_code: GeneratedCodeRecordV2,
    oracle_result: OracleResultRecordV2,
    functional_result: FunctionalResultRecordV2,
) -> RuntimeProducerChainRecordV2:
    """Validate exact producer references and every runtime coordinate.

    Equality deliberately includes ``provider_seed`` even when it is ``None``; the
    independently recorded ``request_randomness_slot`` therefore cannot disappear or be
    substituted by a provider seed downstream.
    """

    try:
        request = GenerationRequestRecordV2.model_validate(generation_request, strict=True)
        code = GeneratedCodeRecordV2.model_validate(generated_code, strict=True)
        oracle = OracleResultRecordV2.model_validate(oracle_result, strict=True)
        functional = FunctionalResultRecordV2.model_validate(functional_result, strict=True)
        records: Sequence[_RuntimeCoordinatesV2] = (code, oracle, functional)
        if any(item.exact_coordinates() != request.exact_coordinates() for item in records):
            raise ValueError("runtime producer-chain coordinates do not join exactly")
        if (
            code.generation_request_id != request.generation_request_id
            or oracle.generated_code_id != code.generated_code_id
            or functional.generated_code_id != code.generated_code_id
            or oracle.code_sha256 != code.code_sha256
            or functional.code_sha256 != code.code_sha256
        ):
            raise ValueError("runtime producer-chain references do not join exactly")
        return RuntimeProducerChainRecordV2.from_content(
            regime_id=request.regime_id,
            semantic_task_cluster_id=request.semantic_task_cluster_id,
            task_instance_id=request.task_instance_id,
            request_randomness_slot=request.request_randomness_slot,
            provider_seed=request.provider_seed,
            assignment_id=request.assignment_id,
            hypothesis_id=request.hypothesis_id,
            realization_spec_id=request.realization_spec_id,
            task_realization_bundle_id=request.task_realization_bundle_id,
            assigned_arm=request.assigned_arm,
            generation_request_id=request.generation_request_id,
            generated_code_id=code.generated_code_id,
            oracle_result_id=oracle.oracle_result_id,
            functional_result_id=functional.functional_result_id,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        raise ValueError("runtime v2 producer chain failed exact join validation") from error


__all__ = [
    "RUNTIME_V2_SCHEMA_VERSION",
    "ConfirmationAssignmentRecordV2",
    "DiagnosticXARValueV2",
    "FunctionalResultRecordV2",
    "GeneratedCodeRecordV2",
    "GenerationRequestRecordV2",
    "NaturalCausalObservationRecordV2",
    "NaturalOutcomeValueV2",
    "NaturalX0ValueV2",
    "OracleResultRecordV2",
    "PostInterventionDiagnosticRecordV2",
    "RuntimeProducerChainRecordV2",
    "validate_runtime_producer_chain_v2",
]

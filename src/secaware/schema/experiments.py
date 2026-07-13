"""Strict immutable contracts for pre-randomization confirmation protocols."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
import hashlib
import json
import re
from typing import Any, ClassVar, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.features import FeatureFamily, FeatureOperation, FeatureState


_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_HYPOTHESIS_ID_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_TARGET_ID_PATTERN = r"^target_[0-9a-f]{64}$"
_TARGET_INSTANCE_ID_PATTERN = r"^target_instance_[0-9a-f]{64}$"
_PROTOCOL_ID_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_PROTOCOL_INSTANCE_ID_PATTERN = r"^protocol_instance_[0-9a-f]{64}$"
_CONTRACT_ID_PATTERN = r"^functional_contract_[0-9a-f]{64}$"
_MULTIPLICITY_ID_RE = re.compile(r"^multiplicity_[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_OUTCOME_ID_RE = re.compile(r"^y_[a-z0-9][a-z0-9_]{0,126}$")
_OUTCOME_VARIABLE_RE = re.compile(r"^y\.[a-z0-9][a-z0-9_.-]{0,126}$")
_FAMILY_ORDER = {family: index for index, family in enumerate(FeatureFamily)}
_STATE_ORDER = {state: index for index, state in enumerate(FeatureState)}
_RESERVED_FUNCTIONAL_OUTCOMES = frozenset(
    {
        "y_secure_functional",
        "y_cwe_secure",
        "y_cwe_insecure",
        "y_cwe_unknown",
        "y_oracle_evaluable",
        "y_parse_ok",
        "y_functional_ok",
    }
)

# M4B intentionally observes every intervenable Prompt feature, including the
# generic reminder. M5 applies this narrower, immutable target gate: the reminder
# remains available as a randomized arm control but can never become the target.
CONFIRMATION_CONTROL_ONLY_FEATURE_IDS = ("safety.generic_security_reminder",)
CONFIRMATION_TARGET_FEATURE_IDS = (
    "task.input_consumption",
    "task.file_read",
    "task.database_query",
    "task.process_launch",
    "task.privileged_action",
    "task.object_deserialization",
    "safety.input_validation",
    "safety.path_normalization",
    "safety.sql_parameterization",
    "safety.safe_subprocess",
    "safety.authorization_check",
    "safety.safe_deserialization",
    "presentation.noop_rewrite",
    "presentation.length_matched_placebo",
    "presentation.sham_edit",
    "presentation.matched_control",
)


def is_confirmation_target_feature(
    feature_id: object,
    operation: object,
) -> bool:
    """Return whether one exact catalog operation may be an M5 target."""
    return (
        type(feature_id) is str
        and type(operation) is FeatureOperation
        and feature_id in CONFIRMATION_TARGET_FEATURE_IDS
        and operation in (FeatureOperation.ADD, FeatureOperation.REMOVE)
    )


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _content(model: StrictModel, *derived_fields: str) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude=set(derived_fields))


def _snapshot_json_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_json_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_json_arrays(item) for item in value)
    return value


def _exact_enum(value: object, enum_type: type[Enum]) -> object:
    if isinstance(value, enum_type):
        return value
    if type(value) is str:
        for member in enum_type:
            if value == member.value:
                return member
    return value


def _valid_identifier(value: str) -> bool:
    return (
        bool(_IDENTIFIER_RE.fullmatch(value))
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _raise_contract_validation_error(
    model_type: type[SafeValidationMixin],
) -> NoReturn:
    """Raise from a frame that never receives raw contract values."""
    raise model_type._safe_error()


class _ExperimentContract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "experiment contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_json_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ExperimentVersionedContract(_ExperimentContract):
    schema_version: Literal["1.0"]


class PromptRole(str, Enum):
    NEUTRAL_BASELINE = "neutral_baseline"
    POSITIVE_SAFETY_CONTROL = "positive_safety_control"
    TASK_FUNCTION_BASELINE = "task_function_baseline"
    TASK_FUNCTION_VARIANT = "task_function_variant"
    PRESENTATION_BASELINE = "presentation_baseline"
    PRESENTATION_VARIANT = "presentation_variant"


class InterventionMode(str, Enum):
    TEXT_NATIVE = "text_native"
    GRAPH_NATIVE = "graph_native"


class InterventionExecutorKind(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"


class ArmRole(str, Enum):
    TARGET_PATCH = "target_patch"
    NOOP_REWRITE = "noop_rewrite"
    LENGTH_MATCHED_PLACEBO = "length_matched_placebo"
    GENERIC_SECURITY_REMINDER = "generic_security_reminder"
    TARGET_REMOVE = "target_remove"
    NOOP_RETAIN = "noop_retain"
    LENGTH_MATCHED_SHAM_EDIT = "length_matched_sham_edit"
    GENERIC_SECURITY_REPLACEMENT = "generic_security_replacement"
    TASK_TARGET = "task_target"
    TASK_NOOP = "task_noop"
    TASK_LENGTH_PLACEBO = "task_length_placebo"
    TASK_GENERIC_CONTROL = "task_generic_control"
    PRESENTATION_TARGET = "presentation_target"
    PRESENTATION_NOOP = "presentation_noop"
    PRESENTATION_MATCHED_CONTROL = "presentation_matched_control"


class TargetSpecRecord(_ExperimentVersionedContract):
    schema_version: Literal["1.0"]
    target_spec_id: str = Field(pattern=_TARGET_ID_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_ID_PATTERN)
    frozen_hypothesis_sha256: str = Field(pattern=_SHA256_PATTERN)
    feature_family: FeatureFamily
    feature_id: str
    operation: FeatureOperation
    hypothesis_outcome_variable_id: str
    hypothesis_outcome_estimand_id: str
    expected_hypothesis_contrast_sign: Literal["positive", "negative", "null", "two_sided"]

    @field_validator("feature_family", mode="before")
    @classmethod
    def parse_family(cls, value: object) -> object:
        return _exact_enum(value, FeatureFamily)

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            result = cls(**payload, target_spec_id=f"target_{_digest(payload)}")
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            content = None
            if payload is not None:
                payload.clear()
            payload = None
            result = None
            _raise_contract_validation_error(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        prefix = {
            FeatureFamily.TASK_FUNCTION: "task.",
            FeatureFamily.SAFETY_CONTROL: "safety.",
            FeatureFamily.PRESENTATION_CONTROL: "presentation.",
        }[self.feature_family]
        expected_estimand = {
            "y.secure_functional": "y_secure_functional",
            "y.cwe_security": "y_cwe_secure",
        }.get(self.hypothesis_outcome_variable_id)
        expected = _digest(_content(self, "target_spec_id"))
        if (
            not _valid_identifier(self.feature_id)
            or not self.feature_id.startswith(prefix)
            or not is_confirmation_target_feature(self.feature_id, self.operation)
            or expected_estimand != self.hypothesis_outcome_estimand_id
            or self.target_spec_id != f"target_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class TargetInstanceRecord(_ExperimentVersionedContract):
    schema_version: Literal["1.0"]
    target_instance_id: str = Field(pattern=_TARGET_INSTANCE_ID_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_ID_PATTERN)
    task_id: str
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    counterpart_prompt_id: str | None
    counterpart_prompt_sha256: str | None
    source_prompt_role: PromptRole
    counterpart_required: bool

    @field_validator("source_prompt_role", mode="before")
    @classmethod
    def parse_prompt_role(cls, value: object) -> object:
        return _exact_enum(value, PromptRole)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            result = cls(
                **payload,
                target_instance_id=f"target_instance_{_digest(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            content = None
            if payload is not None:
                payload.clear()
            payload = None
            result = None
            _raise_contract_validation_error(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        has_counterpart = (
            self.counterpart_prompt_id is not None and self.counterpart_prompt_sha256 is not None
        )
        expected = _digest(_content(self, "target_instance_id"))
        if (
            not _valid_identifier(self.task_id)
            or not _valid_identifier(self.source_prompt_id)
            or (
                self.counterpart_prompt_id is not None
                and not _valid_identifier(self.counterpart_prompt_id)
            )
            or (self.counterpart_prompt_id is None) != (self.counterpart_prompt_sha256 is None)
            or has_counterpart != self.counterpart_required
            or self.target_instance_id != f"target_instance_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FeatureTransition(_ExperimentContract):
    feature_id: str
    from_states: tuple[FeatureState, ...]
    to_states: tuple[FeatureState, ...]

    @field_validator("from_states", "to_states", mode="before")
    @classmethod
    def parse_states(cls, value: object) -> object:
        snapshot = _snapshot_json_arrays(value)
        if type(snapshot) is not tuple:
            return snapshot
        return tuple(_exact_enum(item, FeatureState) for item in snapshot)

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        allowed_states = {FeatureState.ABSENT, FeatureState.PRESENT}
        if (
            not _valid_identifier(self.feature_id)
            or not self.from_states
            or not self.to_states
            or set(self.from_states) - allowed_states
            or set(self.to_states) - allowed_states
            or set(self.from_states) & set(self.to_states)
            or len(self.from_states) != len(set(self.from_states))
            or len(self.to_states) != len(set(self.to_states))
            or self.from_states
            != tuple(sorted(self.from_states, key=lambda item: _STATE_ORDER[item]))
            or self.to_states != tuple(sorted(self.to_states, key=lambda item: _STATE_ORDER[item]))
        ):
            raise ValueError(self._safe_validation_message)
        try:
            from secaware.tsg.feature_catalog import prompt_feature_spec

            spec = prompt_feature_spec(self.feature_id)
            if not spec.intervenable:
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ValueError(self._safe_validation_message) from None
        return self


class AllowedDeltaRecord(_ExperimentContract):
    allowed_transitions: tuple[FeatureTransition, ...]
    fixed_families: tuple[FeatureFamily, ...]
    fixed_feature_ids: tuple[str, ...]

    @field_validator("fixed_families", mode="before")
    @classmethod
    def parse_families(cls, value: object) -> object:
        snapshot = _snapshot_json_arrays(value)
        if type(snapshot) is not tuple:
            return snapshot
        return tuple(_exact_enum(item, FeatureFamily) for item in snapshot)

    @model_validator(mode="after")
    def validate_delta(self) -> Self:
        transition_ids = tuple(item.feature_id for item in self.allowed_transitions)
        if (
            transition_ids != tuple(sorted(transition_ids))
            or len(transition_ids) != len(set(transition_ids))
            or self.fixed_families
            != tuple(sorted(self.fixed_families, key=lambda item: _FAMILY_ORDER[item]))
            or len(self.fixed_families) != len(set(self.fixed_families))
            or self.fixed_feature_ids != tuple(sorted(self.fixed_feature_ids))
            or len(self.fixed_feature_ids) != len(set(self.fixed_feature_ids))
            or set(transition_ids) & set(self.fixed_feature_ids)
        ):
            raise ValueError(self._safe_validation_message)
        try:
            from secaware.tsg.feature_catalog import prompt_feature_spec

            transition_specs = tuple(prompt_feature_spec(item) for item in transition_ids)
            fixed_specs = tuple(prompt_feature_spec(item) for item in self.fixed_feature_ids)
            if any(item.feature_family in self.fixed_families for item in transition_specs) or any(
                item.feature_family in self.fixed_families for item in fixed_specs
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ValueError(self._safe_validation_message) from None
        return self


class ArmSpecRecord(_ExperimentContract):
    role: ArmRole
    allowed_delta: AllowedDeltaRecord

    @field_validator("role", mode="before")
    @classmethod
    def parse_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)


class PreRegisteredContrastSpec(_ExperimentContract):
    contrast_id: str
    arm_contrast_id: str
    treatment_arm: ArmRole
    control_arm: ArmRole
    source_outcome_variable_id: str
    outcome_id: str
    priority: Literal["primary", "secondary", "diagnostic"]
    expected_sign: Literal["positive", "negative", "null", "two_sided"]
    multiplicity_family_id: str

    @field_validator("treatment_arm", "control_arm", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @model_validator(mode="after")
    def validate_contrast(self) -> Self:
        if (
            not _valid_identifier(self.contrast_id)
            or not _valid_identifier(self.arm_contrast_id)
            or self.contrast_id != f"{self.arm_contrast_id}.{self.outcome_id}"
            or self.treatment_arm is self.control_arm
            or _OUTCOME_VARIABLE_RE.fullmatch(self.source_outcome_variable_id) is None
            or _OUTCOME_ID_RE.fullmatch(self.outcome_id) is None
            or _MULTIPLICITY_ID_RE.fullmatch(self.multiplicity_family_id) is None
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ConfirmationProtocolRecord(_ExperimentVersionedContract):
    schema_version: Literal["1.0"]
    arm_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_ID_PATTERN)
    frozen_hypothesis_sha256: str = Field(pattern=_SHA256_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_ID_PATTERN)
    feature_family: FeatureFamily
    operation: FeatureOperation
    arms: tuple[ArmSpecRecord, ...]
    hypothesis_outcome_variable_id: str
    hypothesis_outcome_estimand_id: str
    expected_hypothesis_contrast_sign: Literal["positive", "negative", "null", "two_sided"]
    contrasts: tuple[PreRegisteredContrastSpec, ...]
    contrast_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    functional_outcome_contract_id: str | None = Field(
        default=None,
        pattern=_CONTRACT_ID_PATTERN,
    )

    @field_validator("feature_family", mode="before")
    @classmethod
    def parse_family(cls, value: object) -> object:
        return _exact_enum(value, FeatureFamily)

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        return _exact_enum(value, FeatureOperation)

    @property
    def arm_roles(self) -> tuple[ArmRole, ...]:
        return tuple(arm.role for arm in self.arms)

    @property
    def preregistered_contrast_ids(self) -> tuple[str, ...]:
        return tuple(item.contrast_id for item in self.contrasts)

    @staticmethod
    def contrast_digest(contrasts: tuple[PreRegisteredContrastSpec, ...]) -> str:
        return _digest(
            {
                "schema_version": "1.0",
                "contrast_catalog_id": "confirmation-contrast-catalog-v1",
                "contrasts": contrasts,
            }
        )

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        complete: dict[str, Any] | None = None
        contrasts: tuple[object, ...] = ()
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            contrasts = tuple(payload["contrasts"])
            contrast_set_sha256 = cls.contrast_digest(contrasts)
            complete = {**payload, "contrast_set_sha256": contrast_set_sha256}
            result = cls(
                **complete,
                arm_protocol_id=f"arm_protocol_{_digest(complete)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            content = None
            if payload is not None:
                payload.clear()
            payload = None
            if complete is not None:
                complete.clear()
            complete = None
            contrasts = ()
            result = None
            _raise_contract_validation_error(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected_contrast_sha256 = self.contrast_digest(self.contrasts)
        expected_protocol_sha256 = _digest(_content(self, "arm_protocol_id"))
        role_ids = self.arm_roles
        contrast_ids = self.preregistered_contrast_ids
        if (
            not self.arms
            or not self.contrasts
            or len(role_ids) != len(set(role_ids))
            or len(contrast_ids) != len(set(contrast_ids))
            or any(
                contrast.treatment_arm not in role_ids or contrast.control_arm not in role_ids
                for contrast in self.contrasts
            )
            or self.contrast_set_sha256 != expected_contrast_sha256
            or self.arm_protocol_id != f"arm_protocol_{expected_protocol_sha256}"
        ):
            raise ValueError(self._safe_validation_message)
        try:
            from secaware.intervention.arm_catalog import _validate_materialized_protocol

            _validate_materialized_protocol(self)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ValueError(self._safe_validation_message) from None
        return self


class ConfirmationProtocolInstanceRecord(_ExperimentVersionedContract):
    schema_version: Literal["1.0"]
    protocol_instance_id: str = Field(pattern=_PROTOCOL_INSTANCE_ID_PATTERN)
    arm_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    target_instance_id: str = Field(pattern=_TARGET_INSTANCE_ID_PATTERN)
    task_id: str
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    counterpart_prompt_id: str | None
    counterpart_prompt_sha256: str | None

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            result = cls(
                **payload,
                protocol_instance_id=f"protocol_instance_{_digest(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            content = None
            if payload is not None:
                payload.clear()
            payload = None
            result = None
            _raise_contract_validation_error(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "protocol_instance_id"))
        if (
            not _valid_identifier(self.task_id)
            or not _valid_identifier(self.source_prompt_id)
            or (
                self.counterpart_prompt_id is not None
                and not _valid_identifier(self.counterpart_prompt_id)
            )
            or (self.counterpart_prompt_id is None) != (self.counterpart_prompt_sha256 is None)
            or self.protocol_instance_id != f"protocol_instance_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FunctionalOutcomeContractRecord(_ExperimentVersionedContract):
    schema_version: Literal["1.0"]
    contract_id: str = Field(pattern=_CONTRACT_ID_PATTERN)
    task_feature_id: str
    outcome_id: str
    expected_add_sign: Literal["positive", "negative", "two_sided"]
    expected_remove_sign: Literal["positive", "negative", "two_sided"]
    generic_control_feature_id: str | None
    evaluator_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            result = cls(
                **payload,
                contract_id=f"functional_contract_{_digest(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            content = None
            if payload is not None:
                payload.clear()
            payload = None
            result = None
            _raise_contract_validation_error(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "contract_id"))
        try:
            from secaware.tsg.feature_catalog import prompt_feature_spec

            target = prompt_feature_spec(self.task_feature_id)
            generic = (
                prompt_feature_spec(self.generic_control_feature_id)
                if self.generic_control_feature_id is not None
                else None
            )
            if (
                target.feature_family is not FeatureFamily.TASK_FUNCTION
                or not target.intervenable
                or (
                    generic is not None
                    and (
                        generic.feature_family is not FeatureFamily.TASK_FUNCTION
                        or not generic.intervenable
                        or generic.feature_id == target.feature_id
                    )
                )
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ValueError(self._safe_validation_message) from None
        if (
            _OUTCOME_ID_RE.fullmatch(self.outcome_id) is None
            or self.outcome_id in _RESERVED_FUNCTIONAL_OUTCOMES
            or self.contract_id != f"functional_contract_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "AllowedDeltaRecord",
    "ArmRole",
    "ArmSpecRecord",
    "CONFIRMATION_CONTROL_ONLY_FEATURE_IDS",
    "CONFIRMATION_TARGET_FEATURE_IDS",
    "ConfirmationProtocolInstanceRecord",
    "ConfirmationProtocolRecord",
    "FeatureTransition",
    "FunctionalOutcomeContractRecord",
    "InterventionExecutorKind",
    "InterventionMode",
    "is_confirmation_target_feature",
    "PreRegisteredContrastSpec",
    "PromptRole",
    "TargetInstanceRecord",
    "TargetSpecRecord",
]

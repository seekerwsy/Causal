"""Strict, text-free contracts for assignment-bound outcome publication."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Any, ClassVar, Literal, NoReturn, Self

from pydantic import ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from secaware.schema.common import MAX_MODEL_ID_CHARS, SafeValidationMixin, VersionedModel
from secaware.schema.experiments import ArmRole, AssignmentExecutionStatus


_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ASSIGNMENT_ID_PATTERN = r"^assignment_[0-9a-f]{64}$"
_OUTCOME_ID_PATTERN = r"^assignment_outcome_[0-9a-f]{64}$"
_FUNCTIONAL_OUTCOME_ID_PATTERN = r"^functional_outcome_[0-9a-f]{64}$"
_HYPOTHESIS_ID_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_TARGET_ID_PATTERN = r"^target_[0-9a-f]{64}$"
_TARGET_INSTANCE_ID_PATTERN = r"^target_instance_[0-9a-f]{64}$"
_PROTOCOL_ID_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_PROTOCOL_INSTANCE_ID_PATTERN = r"^protocol_instance_[0-9a-f]{64}$"
_VARIANT_ID_PATTERN = r"^variant_[0-9a-f]{64}$"
_FUNCTIONAL_CONTRACT_ID_PATTERN = r"^functional_contract_[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class CWESecurityOutcome(str, Enum):
    SECURE = "secure"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


class AssignmentEvaluability(str, Enum):
    EVALUABLE = "evaluable"
    UNKNOWN_PARSE_FAILURE = "unknown_parse_failure"
    NOT_REQUIRED_NO_CODE = "not_required_no_code"


class FunctionalOutcomeStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _content(record: VersionedModel, derived_id: str) -> dict[str, object]:
    return record.model_dump(mode="json", exclude={derived_id})


def _exact_enum(value: object, enum_type: type[Enum]) -> object:
    if type(value) is enum_type:
        return value
    if type(value) is str:
        return next((member for member in enum_type if member.value == value), value)
    return value


def _raise_safe(model: type[SafeValidationMixin]) -> NoReturn:
    raise model._safe_error()


class _OutcomeContract(SafeValidationMixin, VersionedModel):
    _safe_validation_message: ClassVar[str] = "outcome contract failed validation"

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


class AssignmentOutcomeRecord(_OutcomeContract):
    """One exact conservative primary outcome per randomized assignment."""

    schema_version: Literal["1.0"]
    outcome_id: str = Field(pattern=_OUTCOME_ID_PATTERN)
    assignment_id: str = Field(pattern=_ASSIGNMENT_ID_PATTERN)
    task_id: str
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_ID_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_ID_PATTERN)
    target_instance_id: str = Field(pattern=_TARGET_INSTANCE_ID_PATTERN)
    arm_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    protocol_instance_id: str = Field(pattern=_PROTOCOL_INSTANCE_ID_PATTERN)
    variant_id: str = Field(pattern=_VARIANT_ID_PATTERN)
    arm_role: ArmRole
    model_id: str = Field(min_length=1, max_length=MAX_MODEL_ID_CHARS)
    seed_id: StrictInt
    execution_status: AssignmentExecutionStatus
    secure_functional_success: StrictInt = Field(ge=0, le=1)
    cwe_security_outcome: CWESecurityOutcome
    oracle_evaluability: AssignmentEvaluability
    parse_ok: StrictBool
    functional_ok: StrictBool
    target_changed: StrictBool | None
    semantic_compliance: StrictBool | None
    source_digests_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "arm_role",
        "execution_status",
        "cwe_security_outcome",
        "oracle_evaluability",
        mode="before",
    )
    @classmethod
    def parse_enums(cls, value: object, info: object) -> object:
        enum_type = {
            "arm_role": ArmRole,
            "execution_status": AssignmentExecutionStatus,
            "cwe_security_outcome": CWESecurityOutcome,
            "oracle_evaluability": AssignmentEvaluability,
        }[info.field_name]  # type: ignore[attr-defined]
        return _exact_enum(value, enum_type)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            result = cls(
                **payload,
                outcome_id=f"assignment_outcome_{_canonical_sha256(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_safe(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        if (
            _IDENTIFIER_PATTERN.fullmatch(self.task_id) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.model_id) is None
            or self.task_id != self.task_id.strip()
            or self.model_id != self.model_id.strip()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in self.task_id)
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in self.model_id)
        ):
            raise ValueError(self._safe_validation_message)

        terminal = self.execution_status is AssignmentExecutionStatus.TERMINAL_NO_CODE
        if terminal:
            coherent = (
                self.secure_functional_success == 0
                and self.cwe_security_outcome is CWESecurityOutcome.UNKNOWN
                and self.oracle_evaluability is AssignmentEvaluability.NOT_REQUIRED_NO_CODE
                and not self.parse_ok
                and not self.functional_ok
            )
        elif self.oracle_evaluability is AssignmentEvaluability.UNKNOWN_PARSE_FAILURE:
            coherent = (
                self.secure_functional_success == 0
                and self.cwe_security_outcome is CWESecurityOutcome.UNKNOWN
                and not self.parse_ok
                and not self.functional_ok
            )
        else:
            expected_primary = int(
                self.parse_ok
                and self.functional_ok
                and self.cwe_security_outcome is CWESecurityOutcome.SECURE
            )
            coherent = (
                self.oracle_evaluability is AssignmentEvaluability.EVALUABLE
                and self.parse_ok
                and self.cwe_security_outcome is not CWESecurityOutcome.UNKNOWN
                and (not self.functional_ok or self.parse_ok)
                and self.secure_functional_success == expected_primary
            )
        if (
            not coherent
            or self.outcome_id
            != f"assignment_outcome_{_canonical_sha256(_content(self, 'outcome_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FunctionalOutcomeRecord(_OutcomeContract):
    """Independent assignment-bound result from one pre-registered evaluator."""

    schema_version: Literal["1.0"]
    functional_outcome_id: str = Field(pattern=_FUNCTIONAL_OUTCOME_ID_PATTERN)
    assignment_id: str = Field(pattern=_ASSIGNMENT_ID_PATTERN)
    contract_id: str = Field(pattern=_FUNCTIONAL_CONTRACT_ID_PATTERN)
    evaluator_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: FunctionalOutcomeStatus
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, value: object) -> object:
        return _exact_enum(value, FunctionalOutcomeStatus)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            payload = {"schema_version": "1.0", **content}
            result = cls(
                **payload,
                functional_outcome_id=f"functional_outcome_{_canonical_sha256(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_safe(cls)
        return result

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.functional_outcome_id != (
            "functional_outcome_" + _canonical_sha256(_content(self, "functional_outcome_id"))
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "AssignmentEvaluability",
    "AssignmentOutcomeRecord",
    "CWESecurityOutcome",
    "FunctionalOutcomeRecord",
    "FunctionalOutcomeStatus",
]

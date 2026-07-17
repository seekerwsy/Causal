"""Strict, text-free contracts for assignment-bound outcome publication."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
import hashlib
import json
import math
import re
from typing import Any, ClassVar, Literal, NoReturn, Self

from pydantic import ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from secaware.schema.common import (
    MAX_MODEL_ID_CHARS,
    SafeValidationMixin,
    StrictModel,
    VersionedModel,
)
from secaware.schema.causal import EndpointMark, PAGRecord, PAGRunKind, jci_row_id_from_content
from secaware.schema.experiments import ArmRole, AssignmentExecutionStatus


_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ASSIGNMENT_ID_PATTERN = r"^assignment_[0-9a-f]{64}$"
_OUTCOME_ID_PATTERN = r"^assignment_outcome_[0-9a-f]{64}$"
_TABLE_ID_PATTERN = r"^table_[0-9a-f]{64}$"
_ROW_ID_PATTERN = r"^row_[0-9a-f]{64}$"
_FUNCTIONAL_OUTCOME_ID_PATTERN = r"^functional_outcome_[0-9a-f]{64}$"
_ITT_EFFECT_ID_PATTERN = r"^itt_effect_[0-9a-f]{64}$"
_EFFECT_DRAW_ID_PATTERN = r"^effect_bootstrap_draw_[0-9a-f]{64}$"
_ANALYSIS_FAILURE_ID_PATTERN = r"^analysis_failure_[0-9a-f]{64}$"
_JCI_DELTA_ID_PATTERN = r"^jci_delta_[0-9a-f]{64}$"
_PAG_ID_PATTERN = r"^pag_[0-9a-f]{64}$"
_HYPOTHESIS_ID_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_TARGET_ID_PATTERN = r"^target_[0-9a-f]{64}$"
_TARGET_INSTANCE_ID_PATTERN = r"^target_instance_[0-9a-f]{64}$"
_PROTOCOL_ID_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_PROTOCOL_INSTANCE_ID_PATTERN = r"^protocol_instance_[0-9a-f]{64}$"
_VARIANT_ID_PATTERN = r"^variant_[0-9a-f]{64}$"
_FUNCTIONAL_CONTRACT_ID_PATTERN = r"^functional_contract_[0-9a-f]{64}$"
_MULTIPLICITY_ID_PATTERN = r"^multiplicity_[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_CAUSAL_VARIABLE_PATTERN = re.compile(r"^[wxyc]\.[a-z0-9][a-z0-9_.-]{0,126}$")
_MAX_PAG_EDGE_CHANGES = 64 * 63 // 2
_RFCI_BACKEND = "py_tetrad_rfci_v1"
_RFCI_PY_TETRAD_COMMIT = "a30707264aa4363a23ac5f136a70bbdd62212f07"
_RFCI_JPYPE_VERSION = "1.7.1"
_RFCI_TETRAD_JAR_SHA256 = "3c898047c26a909495925d3e50264150f58ee57cd5b48d95683c45e3ab0e17f4"

_OUTCOME_SOURCES = {
    "y_secure_functional": "y.secure_functional",
    "y_cwe_secure": "y.cwe_security",
    "y_cwe_insecure": "y.cwe_security",
    "y_cwe_unknown": "y.cwe_security",
    "y_oracle_evaluable": "y.oracle_evaluable",
    "y_parse_ok": "y.parse_ok",
    "y_functional_ok": "y.functional_ok",
}


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


class AnalysisStage(str, Enum):
    EFFECTS = "effects"
    JCI = "jci"
    RFCI = "rfci"


class AnalysisFailureReason(str, Enum):
    INSUFFICIENT_SUPPORT = "insufficient_support"
    BOOTSTRAP_FAILURE = "bootstrap_failure"
    DEGENERATE_GSQ_SUPPORT = "degenerate_gsq_support"
    BACKEND_TIMEOUT = "backend_timeout"
    BACKEND_FAILURE = "backend_failure"


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


class RFCICapabilityRecord(_OutcomeContract):
    """Bounded, import-free availability evidence for optional py-tetrad RFCI."""

    schema_version: Literal["1.0"]
    available: StrictBool
    status: Literal["disabled", "available", "unavailable"]
    requires_java: Literal[True] = True
    python_version: str = Field(min_length=3, max_length=64, pattern=r"^[0-9]+(?:\.[0-9]+){1,3}$")
    java_major: StrictInt | None = Field(default=None, ge=1, le=999)
    jpype_version: str | None = Field(default=None, min_length=1, max_length=64)
    py_tetrad_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    tetrad_jar_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    reason_code: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        available_status = self.status == "available"
        if self.available != available_status:
            raise ValueError(self._safe_validation_message)
        if available_status:
            if (
                self.reason_code is not None
                or self.java_major is None
                or self.java_major < 21
                or self.jpype_version is None
                or self.py_tetrad_commit is None
                or self.tetrad_jar_sha256 is None
            ):
                raise ValueError(self._safe_validation_message)
        elif self.reason_code is None:
            raise ValueError(self._safe_validation_message)
        if self.status == "disabled" and (
            self.reason_code != "disabled"
            or self.java_major is not None
            or self.jpype_version is not None
            or self.py_tetrad_commit is not None
            or self.tetrad_jar_sha256 is not None
        ):
            raise ValueError(self._safe_validation_message)
        return self


class RFCISensitivityResult(SafeValidationMixin, StrictModel):
    """Persistable RFCI outcome bound to the exact capability evidence checked."""

    _safe_validation_message: ClassVar[str] = "RFCI sensitivity result failed validation"
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    capability: RFCICapabilityRecord
    pag: PAGRecord | None

    @model_validator(mode="after")
    def validate_capability_binding(self) -> Self:
        if self.capability.available:
            if (
                self.pag is None
                or self.pag.run_kind is not PAGRunKind.RFCI_SENSITIVITY
                or self.pag.backend != _RFCI_BACKEND
                or self.pag.backend_version != _RFCI_PY_TETRAD_COMMIT
                or self.capability.py_tetrad_commit != _RFCI_PY_TETRAD_COMMIT
                or self.capability.jpype_version != _RFCI_JPYPE_VERSION
                or self.capability.tetrad_jar_sha256 != _RFCI_TETRAD_JAR_SHA256
                or self.capability.java_major is None
                or self.capability.java_major < 21
            ):
                raise ValueError(self._safe_validation_message)
        elif self.pag is not None:
            raise ValueError(self._safe_validation_message)
        return self

    def __repr__(self) -> str:
        return "RFCISensitivityResult()"

    def __str__(self) -> str:
        return "RFCISensitivityResult()"


class ContrastSpecRecord(_OutcomeContract):
    """One flattened contrast authenticated by its content-addressed protocol."""

    schema_version: Literal["1.0"]
    contrast_id: str
    arm_contrast_id: str
    arm_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    treatment_arm: ArmRole
    control_arm: ArmRole
    source_outcome_variable_id: str
    outcome_id: str
    priority: Literal["primary", "secondary", "diagnostic"]
    expected_sign: Literal["positive", "negative", "null", "two_sided"]
    multiplicity_family_id: str = Field(pattern=_MULTIPLICITY_ID_PATTERN)

    @field_validator("treatment_arm", "control_arm", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @model_validator(mode="after")
    def validate_coordinates(self) -> Self:
        expected_source = _OUTCOME_SOURCES.get(
            self.outcome_id,
            self.outcome_id.replace("y_", "y.", 1),
        )
        if (
            _IDENTIFIER_PATTERN.fullmatch(self.contrast_id) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.arm_contrast_id) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.source_outcome_variable_id) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.outcome_id) is None
            or not self.outcome_id.startswith("y_")
            or self.contrast_id != f"{self.arm_contrast_id}.{self.outcome_id}"
            or self.treatment_arm is self.control_arm
            or self.source_outcome_variable_id != expected_source
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ITTEffectRecord(_OutcomeContract):
    """One content-addressed semantic-protocol randomized ITT estimate."""

    schema_version: Literal["1.0"]
    effect_id: str = Field(pattern=_ITT_EFFECT_ID_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_ID_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_ID_PATTERN)
    arm_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    model_id: str = Field(min_length=1, max_length=MAX_MODEL_ID_CHARS)
    contrast_id: str
    outcome_id: str
    treatment_n: StrictInt = Field(ge=1)
    control_n: StrictInt = Field(ge=1)
    independent_task_n: StrictInt = Field(ge=2)
    risk_difference: float = Field(ge=-1.0, le=1.0, allow_inf_nan=False)
    ci_low: float = Field(ge=-1.0, le=1.0, allow_inf_nan=False)
    ci_high: float = Field(ge=-1.0, le=1.0, allow_inf_nan=False)
    sensitivity_low: float = Field(ge=-1.0, le=1.0, allow_inf_nan=False)
    sensitivity_high: float = Field(ge=-1.0, le=1.0, allow_inf_nan=False)
    status: Literal[
        "confirmed_expected_direction",
        "opposite_direction",
        "inconclusive",
        "negative_control_consistent",
        "negative_control_shift",
        "unsupported",
        "unsupported_missing_functional_outcome",
    ]
    assignment_universe_sha256: str = Field(pattern=_SHA256_PATTERN)
    target_instance_universe_sha256: str = Field(pattern=_SHA256_PATTERN)
    bootstrap_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            for field in (
                "risk_difference",
                "ci_low",
                "ci_high",
                "sensitivity_low",
                "sensitivity_high",
            ):
                value = content.get(field)
                if type(value) in {float, int} and type(value) is not bool and value == 0:
                    content[field] = 0.0
            payload = {"schema_version": "1.0", **content}
            result = cls(
                **payload,
                effect_id=f"itt_effect_{_canonical_sha256(payload)}",
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
        numeric = (
            self.risk_difference,
            self.ci_low,
            self.ci_high,
            self.sensitivity_low,
            self.sensitivity_high,
        )
        if (
            not all(math.isfinite(value) for value in numeric)
            or any(value == 0.0 and math.copysign(1.0, value) < 0.0 for value in numeric)
            or self.ci_low > self.ci_high
            or self.sensitivity_low > self.risk_difference
            or self.risk_difference > self.sensitivity_high
            or _IDENTIFIER_PATTERN.fullmatch(self.model_id) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.contrast_id) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.outcome_id) is None
            or self.effect_id != f"itt_effect_{_canonical_sha256(_content(self, 'effect_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class EffectBootstrapDrawRecord(_OutcomeContract):
    """One persisted task-cluster draw bound to its completed ITT effect."""

    _safe_validation_message: ClassVar[str] = "effect bootstrap draw failed validation"

    schema_version: Literal["1.0"]
    draw_id: str = Field(pattern=_EFFECT_DRAW_ID_PATTERN)
    effect_id: str = Field(pattern=_ITT_EFFECT_ID_PATTERN)
    replicate_index: StrictInt = Field(ge=0, le=9_999)
    sampled_task_ids: tuple[str, ...] = Field(min_length=1, max_length=100_000)
    estimate: float = Field(ge=-1.0, le=1.0, allow_inf_nan=False)
    assignment_universe_sha256: str = Field(pattern=_SHA256_PATTERN)
    bootstrap_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("sampled_task_ids", mode="before")
    @classmethod
    def snapshot_sampled_task_ids(cls, value: object) -> object:
        if type(value) not in {list, tuple}:
            return value
        return tuple(value)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if content.get("estimate") == 0 and type(content.get("estimate")) is not bool:
                content["estimate"] = 0.0
            payload = {"schema_version": "1.0", **content}
            return cls(
                **payload,
                draw_id=f"effect_bootstrap_draw_{_canonical_sha256(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_safe(cls)

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        if (
            not math.isfinite(self.estimate)
            or (self.estimate == 0.0 and math.copysign(1.0, self.estimate) < 0.0)
            or any(
                _IDENTIFIER_PATTERN.fullmatch(task_id) is None
                or task_id != task_id.strip()
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in task_id)
                for task_id in self.sampled_task_ids
            )
            or self.draw_id
            != f"effect_bootstrap_draw_{_canonical_sha256(_content(self, 'draw_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class AnalysisFailureRecord(_OutcomeContract):
    """Generic content-addressed failure for bounded optional analyses."""

    _safe_validation_message: ClassVar[str] = "analysis failure failed validation"

    schema_version: Literal["1.0"]
    failure_id: str = Field(pattern=_ANALYSIS_FAILURE_ID_PATTERN)
    stage: AnalysisStage
    subject_id: str
    reason_code: AnalysisFailureReason
    config_sha256: str = Field(pattern=_SHA256_PATTERN)
    input_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("stage", mode="before")
    @classmethod
    def parse_stage(cls, value: object) -> object:
        return _exact_enum(value, AnalysisStage)

    @field_validator("reason_code", mode="before")
    @classmethod
    def parse_reason(cls, value: object) -> object:
        return _exact_enum(value, AnalysisFailureReason)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            payload = {"schema_version": "1.0", **content}
            return cls(
                **payload,
                failure_id=f"analysis_failure_{_canonical_sha256(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_safe(cls)

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        allowed = {
            AnalysisStage.EFFECTS: {
                AnalysisFailureReason.INSUFFICIENT_SUPPORT,
                AnalysisFailureReason.BOOTSTRAP_FAILURE,
            },
            AnalysisStage.JCI: {
                AnalysisFailureReason.INSUFFICIENT_SUPPORT,
                AnalysisFailureReason.DEGENERATE_GSQ_SUPPORT,
                AnalysisFailureReason.BACKEND_TIMEOUT,
                AnalysisFailureReason.BACKEND_FAILURE,
            },
            AnalysisStage.RFCI: {
                AnalysisFailureReason.BACKEND_TIMEOUT,
                AnalysisFailureReason.BACKEND_FAILURE,
            },
        }
        if (
            _IDENTIFIER_PATTERN.fullmatch(self.subject_id) is None
            or self.reason_code not in allowed[self.stage]
            or self.failure_id
            != f"analysis_failure_{_canonical_sha256(_content(self, 'failure_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


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


class JCIObservationRecord(_OutcomeContract):
    """One assignment-bound categorical row in a JCI causal table."""

    _safe_validation_message: ClassVar[str] = "JCI observation failed validation"

    schema_version: Literal["1.0"]
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    row_id: str = Field(pattern=_ROW_ID_PATTERN)
    assignment_id: str = Field(pattern=_ASSIGNMENT_ID_PATTERN)
    task_id: str
    target_spec_id: str = Field(pattern=_TARGET_ID_PATTERN)
    target_instance_id: str = Field(pattern=_TARGET_INSTANCE_ID_PATTERN)
    arm_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    protocol_instance_id: str = Field(pattern=_PROTOCOL_INSTANCE_ID_PATTERN)
    values: tuple[StrictInt, ...] = Field(min_length=2, max_length=64)

    @field_validator("values", mode="before")
    @classmethod
    def snapshot_values(cls, value: object) -> object:
        if type(value) not in {list, tuple}:
            return value
        return tuple(value)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            payload = {"schema_version": "1.0", **content}
            row_id = jci_row_id_from_content(
                assignment_id=payload["assignment_id"],
                task_id=payload["task_id"],
                target_spec_id=payload["target_spec_id"],
                target_instance_id=payload["target_instance_id"],
                arm_protocol_id=payload["arm_protocol_id"],
                protocol_instance_id=payload["protocol_instance_id"],
                values=payload["values"],
            )
            return cls(**payload, row_id=row_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_safe(cls)

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = jci_row_id_from_content(
            assignment_id=self.assignment_id,
            task_id=self.task_id,
            target_spec_id=self.target_spec_id,
            target_instance_id=self.target_instance_id,
            arm_protocol_id=self.arm_protocol_id,
            protocol_instance_id=self.protocol_instance_id,
            values=self.values,
        )
        if (
            _IDENTIFIER_PATTERN.fullmatch(self.task_id) is None
            or any(value < 0 for value in self.values)
            or self.row_id != expected
        ):
            raise ValueError(self._safe_validation_message)
        return self


class EndpointChangeRecord(SafeValidationMixin, StrictModel):
    """One canonical edge-pair difference without per-assumption attribution."""

    _safe_validation_message: ClassVar[str] = "JCI endpoint change failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    left: str
    right: str
    raw_left_mark: EndpointMark | None
    raw_right_mark: EndpointMark | None
    constrained_left_mark: EndpointMark | None
    constrained_right_mark: EndpointMark | None
    change_kind: Literal["edge_added", "edge_removed", "marks_changed"]

    @field_validator(
        "raw_left_mark",
        "raw_right_mark",
        "constrained_left_mark",
        "constrained_right_mark",
        mode="before",
    )
    @classmethod
    def parse_endpoint_mark(cls, value: object) -> object:
        return None if value is None else _exact_enum(value, EndpointMark)

    @model_validator(mode="before")
    @classmethod
    def canonicalize_endpoints(cls, value: object) -> object:
        if isinstance(value, cls) or not isinstance(value, Mapping):
            return value
        payload = dict(value)
        left = payload.get("left")
        right = payload.get("right")
        if isinstance(left, str) and isinstance(right, str) and right < left:
            payload["left"], payload["right"] = right, left
            for prefix in ("raw", "constrained"):
                payload[f"{prefix}_left_mark"], payload[f"{prefix}_right_mark"] = (
                    payload.get(f"{prefix}_right_mark"),
                    payload.get(f"{prefix}_left_mark"),
                )
        return payload

    @model_validator(mode="after")
    def validate_change(self) -> Self:
        raw = (self.raw_left_mark, self.raw_right_mark)
        constrained = (self.constrained_left_mark, self.constrained_right_mark)
        raw_present = all(mark is not None for mark in raw)
        constrained_present = all(mark is not None for mark in constrained)
        coherent = (
            (
                self.change_kind == "edge_added"
                and not raw_present
                and raw == (None, None)
                and constrained_present
            )
            or (
                self.change_kind == "edge_removed"
                and raw_present
                and not constrained_present
                and constrained == (None, None)
            )
            or (
                self.change_kind == "marks_changed"
                and raw_present
                and constrained_present
                and raw != constrained
            )
        )
        if (
            _CAUSAL_VARIABLE_PATTERN.fullmatch(self.left) is None
            or _CAUSAL_VARIABLE_PATTERN.fullmatch(self.right) is None
            or self.left >= self.right
            or not coherent
        ):
            raise ValueError(self._safe_validation_message)
        return self


class JCIOrientationDeltaRecord(_OutcomeContract):
    """Content-addressed PAG delta attributed only to a complete assumption set."""

    _safe_validation_message: ClassVar[str] = "JCI orientation delta failed validation"

    schema_version: Literal["1.0"]
    delta_id: str = Field(pattern=_JCI_DELTA_ID_PATTERN)
    raw_pag_id: str = Field(pattern=_PAG_ID_PATTERN)
    constrained_pag_id: str = Field(pattern=_PAG_ID_PATTERN)
    assumption_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    assumption_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    per_assumption_attribution: Literal[False] = False
    changes: tuple[EndpointChangeRecord, ...] = Field(max_length=_MAX_PAG_EDGE_CHANGES)

    @field_validator("assumption_ids", "changes", mode="before")
    @classmethod
    def snapshot_sequence_fields(cls, value: object) -> object:
        if type(value) not in {list, tuple}:
            return value
        return tuple(value)

    @classmethod
    def from_content(
        cls,
        *,
        raw_pag_id: str,
        constrained_pag_id: str,
        assumption_ids: Sequence[str],
        changes: Sequence[EndpointChangeRecord],
    ) -> Self:
        payload: dict[str, Any] | None = None
        result: Self | None = None
        failed = False
        try:
            if not 1 <= len(assumption_ids) <= 8 or len(changes) > _MAX_PAG_EDGE_CHANGES:
                raise ValueError
            assumptions = tuple(sorted(assumption_ids))
            ordered_changes = tuple(sorted(changes, key=lambda item: (item.left, item.right)))
            payload = {
                "schema_version": "1.0",
                "raw_pag_id": raw_pag_id,
                "constrained_pag_id": constrained_pag_id,
                "assumption_ids": assumptions,
                "assumption_set_sha256": _canonical_sha256(assumptions),
                "per_assumption_attribution": False,
                "changes": ordered_changes,
            }
            digest_payload = {
                **payload,
                "changes": tuple(item.model_dump(mode="json") for item in ordered_changes),
            }
            result = cls(
                **payload,
                delta_id=f"jci_delta_{_canonical_sha256(digest_payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed = True
        if failed:
            if payload is not None:
                payload.clear()
            _raise_safe(cls)
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        pairs = tuple((item.left, item.right) for item in self.changes)
        expected = _canonical_sha256(_content(self, "delta_id"))
        if (
            self.raw_pag_id == self.constrained_pag_id
            or self.assumption_ids != tuple(sorted(self.assumption_ids))
            or len(self.assumption_ids) != len(set(self.assumption_ids))
            or any(_IDENTIFIER_PATTERN.fullmatch(item) is None for item in self.assumption_ids)
            or self.assumption_set_sha256 != _canonical_sha256(self.assumption_ids)
            or pairs != tuple(sorted(pairs))
            or len(pairs) != len(set(pairs))
            or self.delta_id != f"jci_delta_{expected}"
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
    "AnalysisFailureReason",
    "AnalysisFailureRecord",
    "AnalysisStage",
    "AssignmentEvaluability",
    "AssignmentOutcomeRecord",
    "ContrastSpecRecord",
    "CWESecurityOutcome",
    "EffectBootstrapDrawRecord",
    "EndpointChangeRecord",
    "FunctionalOutcomeRecord",
    "FunctionalOutcomeStatus",
    "ITTEffectRecord",
    "JCIOrientationDeltaRecord",
    "JCIObservationRecord",
    "RFCICapabilityRecord",
    "RFCISensitivityResult",
]

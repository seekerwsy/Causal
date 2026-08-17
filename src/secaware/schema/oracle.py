from enum import Enum
from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from secaware.schema.common import (
    MAX_MODEL_ID_CHARS,
    SafeValidationMixin,
    VersionedModel,
    is_valid_model_id,
    model_shape_is_intact,
)
from secaware.schema.experiments import ArmRole


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_CANONICAL_CODE_ID_PATTERN = r"^code_[0-9a-f]{64}$"
_HYPOTHESIS_ID_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_ASSIGNMENT_ID_PATTERN = r"^assignment_[0-9a-f]{64}$"
_TARGET_ID_PATTERN = r"^target_[0-9a-f]{64}$"
_TARGET_INSTANCE_ID_PATTERN = r"^target_instance_[0-9a-f]{64}$"
_PROTOCOL_ID_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_PROTOCOL_INSTANCE_ID_PATTERN = r"^protocol_instance_[0-9a-f]{64}$"
_VARIANT_ID_PATTERN = r"^variant_[0-9a-f]{64}$"
_PROFILE_ID_PATTERN = r"^python\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.v[1-9][0-9]*$"
_INVALID_FINDING_MESSAGE = "analyzer finding validation failed"
_INVALID_PROVENANCE_MESSAGE = "analyzer provenance validation failed"
_INVALID_ORACLE_MESSAGE = "oracle record validation failed"


class SecurityLabel(str, Enum):
    SECURE = "secure"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


class OracleEvaluability(str, Enum):
    EVALUABLE = "evaluable"
    UNKNOWN_PARSE_FAILURE = "unknown_parse_failure"
    UNKNOWN_COVERAGE = "unknown_coverage"


class AnalyzerFindingRecord(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_FINDING_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    analyzer: Literal["semgrep", "bandit"] = Field(repr=False)
    rule_id: str = Field(min_length=1, max_length=256, repr=False)
    cwe: str = Field(min_length=1, max_length=32, repr=False)
    severity: Literal["low", "medium", "high"] = Field(repr=False)
    confidence: Literal["low", "medium", "high", "not_provided"] = Field(repr=False)
    line: StrictInt = Field(ge=1, repr=False)
    column: StrictInt = Field(ge=1, repr=False)
    end_line: StrictInt = Field(ge=1, repr=False)
    end_column: StrictInt = Field(ge=1, repr=False)
    message: str = Field(min_length=1, max_length=4096, repr=False)

    @field_validator("rule_id", "cwe", "message")
    @classmethod
    def reject_noncanonical_text(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(_INVALID_FINDING_MESSAGE)
        return value

    @model_validator(mode="after")
    def validate_source_range(self) -> "AnalyzerFindingRecord":
        if (self.end_line, self.end_column) < (self.line, self.column):
            raise ValueError(_INVALID_FINDING_MESSAGE)
        return self


class AnalyzerProvenanceRecord(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_PROVENANCE_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    analyzer: Literal["semgrep", "bandit"]
    version: str = Field(min_length=1, max_length=128)
    policy_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)

    @field_validator("version")
    @classmethod
    def reject_noncanonical_version(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(_INVALID_PROVENANCE_MESSAGE)
        return value


FindingRecord = AnalyzerFindingRecord


def _snapshot_findings(value: object) -> tuple[AnalyzerFindingRecord, ...]:
    if type(value) not in {list, tuple}:
        raise TypeError(_INVALID_ORACLE_MESSAGE)
    snapshots: list[AnalyzerFindingRecord] = []
    for item in value:
        if isinstance(item, AnalyzerFindingRecord):
            if type(item) is not AnalyzerFindingRecord or not model_shape_is_intact(item):
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            item = item.model_dump(mode="python", round_trip=True, warnings=False)
        snapshots.append(AnalyzerFindingRecord.model_validate(item))
    return tuple(snapshots)


def _snapshot_analyzers(value: object) -> tuple[AnalyzerProvenanceRecord, ...]:
    if type(value) not in {list, tuple}:
        raise TypeError(_INVALID_ORACLE_MESSAGE)
    snapshots: list[AnalyzerProvenanceRecord] = []
    for item in value:
        if isinstance(item, AnalyzerProvenanceRecord):
            if type(item) is not AnalyzerProvenanceRecord or not model_shape_is_intact(item):
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            item = item.model_dump(mode="python", round_trip=True, warnings=False)
        snapshots.append(AnalyzerProvenanceRecord.model_validate(item))
    return tuple(snapshots)


def _is_completed_unknown(record: "OracleRecord") -> bool:
    """Authenticate conservative terminal states without inventing secure labels."""

    return (
        (
            (
                record.evaluability is OracleEvaluability.UNKNOWN_PARSE_FAILURE
                and not record.parse_ok
                and not record.functional_ok
            )
            or (record.evaluability is OracleEvaluability.UNKNOWN_COVERAGE and record.parse_ok)
        )
        and record.severity == "none"
        and not record.findings
    )


class OracleRecord(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_ORACLE_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.2", "1.3"]
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    code_id: str = Field(pattern=_CANONICAL_CODE_ID_PATTERN)
    code_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    prompt_id: str = Field(min_length=1, max_length=1024)
    condition: Literal["observed", "confirm_arm"]
    model_id: str = Field(min_length=1, max_length=MAX_MODEL_ID_CHARS, strict=True)
    seed_id: StrictInt
    hypothesis_id: str | None = Field(default=None, pattern=_HYPOTHESIS_ID_PATTERN)
    assignment_id: str | None = Field(default=None, pattern=_ASSIGNMENT_ID_PATTERN)
    target_spec_id: str | None = Field(default=None, pattern=_TARGET_ID_PATTERN)
    target_instance_id: str | None = Field(default=None, pattern=_TARGET_INSTANCE_ID_PATTERN)
    arm_protocol_id: str | None = Field(default=None, pattern=_PROTOCOL_ID_PATTERN)
    protocol_instance_id: str | None = Field(default=None, pattern=_PROTOCOL_INSTANCE_ID_PATTERN)
    variant_id: str | None = Field(default=None, pattern=_VARIANT_ID_PATTERN)
    arm_role: ArmRole | None = None
    parse_ok: StrictBool
    functional_ok: StrictBool
    security_label: SecurityLabel
    evaluability: OracleEvaluability
    severity: Literal["none", "low", "medium", "high"]
    findings: tuple[AnalyzerFindingRecord, ...] = Field(default_factory=tuple)
    raw_findings: tuple[AnalyzerFindingRecord, ...] = Field(default_factory=tuple)
    analyzers: tuple[AnalyzerProvenanceRecord, ...]
    decision_profile_id: str | None = Field(default=None, pattern=_PROFILE_ID_PATTERN)
    decision_engine_version: str | None = Field(default=None, min_length=1, max_length=128)
    decision_reason_code: str | None = Field(default=None, min_length=1, max_length=128)
    mechanism_evidence_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)

    @field_validator("prompt_id")
    @classmethod
    def reject_blank_prompt_id(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        return value

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        if not is_valid_model_id(value):
            raise ValueError(_INVALID_ORACLE_MESSAGE)
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
        if value is not None and (not value.strip() or value != value.strip()):
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        return value

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        if value is None or type(value) is ArmRole:
            return value
        if type(value) is str:
            return next((item for item in ArmRole if item.value == value), value)
        return value

    @field_validator("security_label", mode="before")
    @classmethod
    def parse_security_label(cls, value: object) -> SecurityLabel:
        if type(value) is SecurityLabel:
            return value
        if type(value) is str:
            return SecurityLabel(value)
        raise TypeError(_INVALID_ORACLE_MESSAGE)

    @field_validator("evaluability", mode="before")
    @classmethod
    def parse_evaluability(cls, value: object) -> OracleEvaluability:
        if type(value) is OracleEvaluability:
            return value
        if type(value) is str:
            return OracleEvaluability(value)
        raise TypeError(_INVALID_ORACLE_MESSAGE)

    @field_validator("findings", mode="before")
    @classmethod
    def snapshot_findings(cls, value: object) -> tuple[AnalyzerFindingRecord, ...]:
        return _snapshot_findings(value)

    @field_validator("raw_findings", mode="before")
    @classmethod
    def snapshot_raw_findings(cls, value: object) -> tuple[AnalyzerFindingRecord, ...]:
        return _snapshot_findings(value)

    @field_validator("analyzers", mode="before")
    @classmethod
    def snapshot_analyzers(
        cls,
        value: object,
    ) -> tuple[AnalyzerProvenanceRecord, ...]:
        return _snapshot_analyzers(value)

    @classmethod
    def migrate_persisted_payload(cls, value: object) -> object:
        """Migrate valid observed v1.0/v1.1 payloads at the JSONL boundary only."""
        if type(value) is not dict or value.get("schema_version") not in {"1.0", "1.1"}:
            return value
        snapshot = dict(value)
        legacy_version = snapshot.get("schema_version")
        confirmation_fields = (
            "hypothesis_id",
            "assignment_id",
            "target_spec_id",
            "target_instance_id",
            "arm_protocol_id",
            "protocol_instance_id",
            "variant_id",
            "arm_role",
        )
        if (
            snapshot.get("condition") != "observed"
            or snapshot.get("intervention_id") is not None
            or any(snapshot.get(field) is not None for field in confirmation_fields)
            or (legacy_version == "1.0" and "evaluability" in snapshot)
            or (legacy_version == "1.1" and "evaluability" not in snapshot)
        ):
            return value
        if legacy_version == "1.0" and snapshot.get("parse_ok") is False:
            if (
                snapshot.get("functional_ok") is not False
                or snapshot.get("security_label") != SecurityLabel.SECURE.value
                or snapshot.get("severity") != "none"
                or type(snapshot.get("findings")) not in {list, tuple}
                or len(snapshot["findings"]) != 0
            ):
                return value
            snapshot["security_label"] = SecurityLabel.UNKNOWN
            snapshot["evaluability"] = OracleEvaluability.UNKNOWN_PARSE_FAILURE
        elif legacy_version == "1.0":
            snapshot["evaluability"] = OracleEvaluability.EVALUABLE
        snapshot["schema_version"] = "1.2"
        snapshot.pop("intervention_id", None)
        for field in confirmation_fields:
            snapshot.setdefault(field, None)
        return cls.model_validate(snapshot)

    @model_validator(mode="after")
    def validate_integrity(self) -> "OracleRecord":
        identifiers = (
            self.hypothesis_id,
            self.assignment_id,
            self.target_spec_id,
            self.target_instance_id,
            self.arm_protocol_id,
            self.protocol_instance_id,
            self.variant_id,
            self.arm_role,
        )
        if self.condition == "observed" and any(value is not None for value in identifiers):
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        if self.condition == "confirm_arm" and any(value is None for value in identifiers):
            raise ValueError(_INVALID_ORACLE_MESSAGE)

        if self.functional_ok and not self.parse_ok:
            raise ValueError(_INVALID_ORACLE_MESSAGE)

        decision_fields = (
            self.decision_profile_id,
            self.decision_engine_version,
            self.decision_reason_code,
            self.mechanism_evidence_sha256,
        )
        if self.schema_version == "1.2":
            if any(value is not None for value in decision_fields) or self.raw_findings:
                raise ValueError(_INVALID_ORACLE_MESSAGE)
        else:
            if any(value is None for value in decision_fields):
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            raw_keys = {
                (
                    item.analyzer,
                    item.rule_id,
                    item.line,
                    item.column,
                    item.end_line,
                    item.end_column,
                )
                for item in self.raw_findings
            }
            if any(
                (
                    item.analyzer,
                    item.rule_id,
                    item.line,
                    item.column,
                    item.end_line,
                    item.end_column,
                )
                not in raw_keys
                for item in self.findings
            ):
                raise ValueError(_INVALID_ORACLE_MESSAGE)

        analyzer_names = tuple(item.analyzer for item in self.analyzers)
        if len(analyzer_names) != 2 or set(analyzer_names) != {"semgrep", "bandit"}:
            raise ValueError(_INVALID_ORACLE_MESSAGE)

        if self.security_label is SecurityLabel.UNKNOWN:
            if not _is_completed_unknown(self):
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            return self
        if self.evaluability is not OracleEvaluability.EVALUABLE or not self.parse_ok:
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        if self.security_label is SecurityLabel.SECURE:
            if self.findings or self.severity != "none":
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            return self

        if not self.findings:
            if (
                self.schema_version != "1.3"
                or self.decision_reason_code != "proved_unsafe_sink"
                or self.severity == "none"
            ):
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            return self
        severity_rank = {"low": 1, "medium": 2, "high": 3}
        aggregate = max(self.findings, key=lambda item: severity_rank[item.severity]).severity
        if self.severity != aggregate:
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        return self


__all__ = [
    "AnalyzerFindingRecord",
    "AnalyzerProvenanceRecord",
    "FindingRecord",
    "OracleEvaluability",
    "OracleRecord",
    "SecurityLabel",
]

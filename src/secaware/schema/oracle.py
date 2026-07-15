from enum import Enum
from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from secaware.schema.common import (
    SafeValidationMixin,
    VersionedModel,
    model_shape_is_intact,
)


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"
_CANONICAL_CODE_ID_PATTERN = r"^code_[0-9a-f]{64}$"
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

    schema_version: Literal["1.1"]
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    code_id: str = Field(pattern=_CANONICAL_CODE_ID_PATTERN)
    code_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    prompt_id: str = Field(min_length=1, max_length=1024)
    condition: Literal["observed", "counterfactual"]
    model_id: str = Field(min_length=1, max_length=1024)
    seed_id: StrictInt
    hypothesis_id: str | None = Field(default=None, max_length=1024)
    intervention_id: str | None = Field(default=None, max_length=1024)
    parse_ok: StrictBool
    functional_ok: StrictBool
    security_label: SecurityLabel
    evaluability: OracleEvaluability
    severity: Literal["none", "low", "medium", "high"]
    findings: tuple[AnalyzerFindingRecord, ...] = Field(default_factory=tuple)
    analyzers: tuple[AnalyzerProvenanceRecord, ...]

    @field_validator("prompt_id", "model_id")
    @classmethod
    def reject_blank_pairing_coordinates(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        return value

    @field_validator("hypothesis_id", "intervention_id")
    @classmethod
    def reject_blank_optional_identifiers(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or value != value.strip()):
            raise ValueError(_INVALID_ORACLE_MESSAGE)
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

    @field_validator("analyzers", mode="before")
    @classmethod
    def snapshot_analyzers(
        cls,
        value: object,
    ) -> tuple[AnalyzerProvenanceRecord, ...]:
        return _snapshot_analyzers(value)

    @classmethod
    def migrate_persisted_payload(cls, value: object) -> object:
        """Migrate one valid observed v1.0 payload at the JSONL read boundary only."""
        if type(value) is not dict or value.get("schema_version") != "1.0":
            return value
        snapshot = dict(value)
        if snapshot.get("condition") != "observed" or "evaluability" in snapshot:
            return value
        snapshot["schema_version"] = "1.1"
        if snapshot.get("parse_ok") is False:
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
        else:
            snapshot["evaluability"] = OracleEvaluability.EVALUABLE
        return cls.model_validate(snapshot)

    @model_validator(mode="after")
    def validate_integrity(self) -> "OracleRecord":
        identifiers = (self.hypothesis_id, self.intervention_id)
        if self.condition == "observed" and any(value is not None for value in identifiers):
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        if self.condition == "counterfactual" and any(value is None for value in identifiers):
            raise ValueError(_INVALID_ORACLE_MESSAGE)

        if self.functional_ok and not self.parse_ok:
            raise ValueError(_INVALID_ORACLE_MESSAGE)

        analyzer_names = tuple(item.analyzer for item in self.analyzers)
        if len(analyzer_names) != 2 or set(analyzer_names) != {"semgrep", "bandit"}:
            raise ValueError(_INVALID_ORACLE_MESSAGE)

        if self.security_label is SecurityLabel.UNKNOWN:
            if (
                self.evaluability is not OracleEvaluability.UNKNOWN_PARSE_FAILURE
                or self.parse_ok
                or self.functional_ok
                or self.severity != "none"
                or self.findings
            ):
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            return self
        if self.evaluability is not OracleEvaluability.EVALUABLE or not self.parse_ok:
            raise ValueError(_INVALID_ORACLE_MESSAGE)
        if self.security_label is SecurityLabel.SECURE:
            if self.findings or self.severity != "none":
                raise ValueError(_INVALID_ORACLE_MESSAGE)
            return self

        if not self.findings:
            raise ValueError(_INVALID_ORACLE_MESSAGE)
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

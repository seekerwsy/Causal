from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _PersistedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CweEvidence(str, Enum):
    EXPLICIT_FIELD = "EXPLICIT_FIELD"
    SOURCE_ID_PARSE = "SOURCE_ID_PARSE"
    SOURCE_MAPPING = "SOURCE_MAPPING"
    CONFLICTING = "CONFLICTING"
    UNRESOLVED = "UNRESOLVED"


class NeutralityState(str, Enum):
    OBVIOUS_CONFLICT = "OBVIOUS_CONFLICT"
    CANDIDATE_NEUTRAL = "CANDIDATE_NEUTRAL"
    UNRESOLVED = "UNRESOLVED"


class FunctionalState(str, Enum):
    EXECUTABLE_VALIDATED = "EXECUTABLE_VALIDATED"
    PRESENT_UNVALIDATED = "PRESENT_UNVALIDATED"
    REFERENCE_ONLY = "REFERENCE_ONLY"
    ABSENT = "ABSENT"
    CONFLICTING = "CONFLICTING"
    UNRESOLVED = "UNRESOLVED"


class DatasetRole(str, Enum):
    PAPER_PRIMARY_CANDIDATE = "PAPER_PRIMARY_CANDIDATE"
    SECURITY_ONLY_SECONDARY_CANDIDATE = "SECURITY_ONLY_SECONDARY_CANDIDATE"
    FUNCTIONAL_CALIBRATION = "FUNCTIONAL_CALIBRATION"
    ORACLE_CALIBRATION = "ORACLE_CALIBRATION"
    EXTRACTOR_OR_TSG_EVALUATION = "EXTRACTOR_OR_TSG_EVALUATION"
    EXTERNAL_REPLICATION_CANDIDATE = "EXTERNAL_REPLICATION_CANDIDATE"
    PENDING_CONTRACT_OR_ADJUDICATION = "PENDING_CONTRACT_OR_ADJUDICATION"
    UNUSABLE_UNDER_CURRENT_SCOPE = "UNUSABLE_UNDER_CURRENT_SCOPE"


class EvidenceSpan(_PersistedModel):
    field: str = Field(min_length=1)
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    text: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)


class SourceCoordinate(_PersistedModel):
    source_id: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    record_id: str | None = None


class AdaptedRecord(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    coordinate: SourceCoordinate
    prompt: str | None
    language: str | None
    cwe_ids: tuple[str, ...]
    cwe_evidence: CweEvidence
    cwe_evidence_spans: tuple[EvidenceSpan, ...] = ()
    exact_prompt_sha256: str | None
    normalized_prompt_sha256: str | None
    functional_state: FunctionalState
    functional_evidence_spans: tuple[EvidenceSpan, ...] = ()


class RecordAudit(_PersistedModel):
    schema_version: Literal["1.0"]
    coordinate: SourceCoordinate
    prompt: str | None
    language: str | None
    cwe_ids: tuple[str, ...]
    cwe_evidence: CweEvidence
    cwe_evidence_spans: tuple[EvidenceSpan, ...] = ()
    exact_prompt_sha256: str | None
    normalized_prompt_sha256: str | None
    neutrality: NeutralityState
    neutrality_rule_version: str
    neutrality_evidence_spans: tuple[EvidenceSpan, ...] = ()
    functional_state: FunctionalState
    functional_evidence_spans: tuple[EvidenceSpan, ...] = ()
    duplicate_group_id: str | None = None
    task_cluster_id: str | None = None
    cluster_independence_resolved: bool = False
    roles: tuple[DatasetRole, ...] = ()


class FailureRecord(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    phase: str = Field(min_length=1)
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    coordinate: SourceCoordinate | None = None
    fatal: bool


class ProgressCounts(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    total: int = Field(ge=0)
    completed: int = Field(ge=0)
    running: int = Field(ge=0)
    failed: int = Field(ge=0)
    unresolved: int = Field(ge=0)
    pending: int = Field(ge=0)
    records_per_second: float = Field(ge=0)
    eta_seconds: float | None = Field(default=None, ge=0)

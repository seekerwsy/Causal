"""Strict contracts for pre-treatment functionality audits and blind judge passes."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel, VersionedModel
from secaware.schema.outcomes import FunctionalOutcomeStatus

_SHA256 = r"^[0-9a-f]{64}$"
_CONTRACT_ID = r"^functional_contract_[0-9a-f]{64}$"
_ASSIGNMENT_ID = r"^assignment_[0-9a-f]{64}$"
_PASS_ID = r"^functional_judge_pass_[0-9a-f]{64}$"
_PROGRAM_OUTCOME_ID = r"^program_functional_outcome_[0-9a-f]{64}$"
_AUDIT_DECISION_ID = r"^functional_audit_decision_[0-9a-f]{64}$"
_PACKET_ID = r"^functional_audit_packet_[0-9a-f]{64}$"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            default=lambda item: (
                item.model_dump(mode="json") if isinstance(item, BaseModel) else str(item)
            ),
        ).encode("utf-8")
    ).hexdigest()


def _content(record: VersionedModel, field: str) -> dict[str, object]:
    return record.model_dump(mode="json", exclude={field})


def _enum(value: object, enum_type: type[Enum]) -> object:
    if type(value) is enum_type:
        return value
    if type(value) is str:
        return next((item for item in enum_type if item.value == value), value)
    return value


class FunctionalJudgeability(str, Enum):
    EXECUTABLE = "executable"
    SEMANTIC_ONLY = "semantic_only"
    UNJUDGEABLE = "unjudgeable"


class FunctionalAuditStatus(str, Enum):
    CONSISTENT = "consistent"
    RESOLVED = "resolved"


class RequirementVerdict(str, Enum):
    MET = "met"
    NOT_MET = "not_met"
    UNKNOWN = "unknown"


class _Contract(SafeValidationMixin, VersionedModel):
    _safe_validation_message: ClassVar[str] = "functional evaluation contract failed validation"
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class FunctionalRequirementRecord(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    requirement_id: str = Field(pattern=r"^req_[a-z0-9_]{1,64}$")
    kind: Literal[
        "interface",
        "behavior",
        "input_output",
        "side_effect",
        "error_handling",
        "environment",
    ]
    criterion: str = Field(min_length=1, max_length=4000)
    prompt_evidence_quote: str = Field(min_length=1, max_length=4000)

    @model_validator(mode="after")
    def validate_text(self) -> Self:
        if (
            self.criterion != self.criterion.strip()
            or self.prompt_evidence_quote != self.prompt_evidence_quote.strip()
        ):
            raise ValueError("functional requirement failed validation")
        return self


class FunctionalAuditDecisionRecord(_Contract):
    """One content-addressed Codex pass over a blinded pre-treatment task packet."""

    schema_version: Literal["1.0"]
    decision_id: str = Field(pattern=_AUDIT_DECISION_ID)
    packet_id: str = Field(pattern=_PACKET_ID)
    task_id: str
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=_SHA256)
    pass_id: Literal["A", "B"]
    language: str = Field(min_length=1, max_length=128)
    judgeability: FunctionalJudgeability
    requirements: tuple[FunctionalRequirementRecord, ...] = Field(max_length=32)
    environment_dependencies: tuple[str, ...] = Field(default=(), max_length=32)
    confidence: Literal["HIGH", "LOW"]
    evidence_quotes: tuple[str, ...] = Field(min_length=1, max_length=16)
    rationale: str = Field(min_length=1, max_length=4000)
    rubric_version: Literal["functional-contract-audit-v1"]
    auditor_kind: Literal["CODEX"]
    auditor_id: Literal["codex-primary"]

    @field_validator("judgeability", mode="before")
    @classmethod
    def parse_judgeability(cls, value: object) -> object:
        return _enum(value, FunctionalJudgeability)

    @field_validator("requirements", "environment_dependencies", "evidence_quotes", mode="before")
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, object] = {"schema_version": "1.0", **content}
        try:
            return cls(
                **payload,
                decision_id=f"functional_audit_decision_{_digest(payload)}",
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        requirement_ids = tuple(item.requirement_id for item in self.requirements)
        if (
            _IDENTIFIER.fullmatch(self.task_id) is None
            or _IDENTIFIER.fullmatch(self.source_prompt_id) is None
            or self.language != self.language.strip()
            or requirement_ids != tuple(sorted(requirement_ids))
            or len(requirement_ids) != len(set(requirement_ids))
            or (self.judgeability is FunctionalJudgeability.UNJUDGEABLE) != (not self.requirements)
            or self.environment_dependencies != tuple(sorted(self.environment_dependencies))
            or len(self.environment_dependencies) != len(set(self.environment_dependencies))
            or any(not item.strip() for item in self.evidence_quotes)
            or self.rationale != self.rationale.strip()
            or self.decision_id
            != f"functional_audit_decision_{_digest(_content(self, 'decision_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class TaskFunctionalContractRecord(_Contract):
    """One source-prompt-bound definition of functional success, frozen pre-treatment."""

    schema_version: Literal["1.0"]
    contract_id: str = Field(pattern=_CONTRACT_ID)
    task_id: str
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=_SHA256)
    language: str = Field(min_length=1, max_length=128)
    judgeability: FunctionalJudgeability
    requirements: tuple[FunctionalRequirementRecord, ...] = Field(max_length=32)
    environment_dependencies: tuple[str, ...] = Field(default=(), max_length=32)
    audit_pass_ids: tuple[Literal["A", "B"], ...] = Field(min_length=1, max_length=2)
    audit_status: FunctionalAuditStatus
    auditor_kind: Literal["CODEX"]
    audit_evidence_sha256: str = Field(pattern=_SHA256)

    @field_validator("judgeability", mode="before")
    @classmethod
    def parse_judgeability(cls, value: object) -> object:
        return _enum(value, FunctionalJudgeability)

    @field_validator("audit_status", mode="before")
    @classmethod
    def parse_audit_status(cls, value: object) -> object:
        return _enum(value, FunctionalAuditStatus)

    @field_validator("requirements", "environment_dependencies", "audit_pass_ids", mode="before")
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, object] = {"schema_version": "1.0", **content}
        try:
            return cls(**payload, contract_id=f"functional_contract_{_digest(payload)}")
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        requirement_ids = tuple(item.requirement_id for item in self.requirements)
        if (
            _IDENTIFIER.fullmatch(self.task_id) is None
            or _IDENTIFIER.fullmatch(self.source_prompt_id) is None
            or self.language != self.language.strip()
            or self.audit_pass_ids not in {("A",), ("A", "B")}
            or (
                self.audit_pass_ids == ("A",)
                and self.audit_status is not FunctionalAuditStatus.RESOLVED
            )
            or requirement_ids != tuple(sorted(requirement_ids))
            or len(requirement_ids) != len(set(requirement_ids))
            or self.environment_dependencies != tuple(sorted(self.environment_dependencies))
            or len(self.environment_dependencies) != len(set(self.environment_dependencies))
            or (self.judgeability is FunctionalJudgeability.UNJUDGEABLE) != (not self.requirements)
            or self.contract_id != f"functional_contract_{_digest(_content(self, 'contract_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FunctionalRequirementDecision(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    requirement_id: str = Field(pattern=r"^req_[a-z0-9_]{1,64}$")
    verdict: RequirementVerdict
    code_evidence: tuple[str, ...] = Field(default=(), max_length=32)
    counterexample: str | None = Field(default=None, max_length=4000)

    @field_validator("code_evidence", mode="before")
    @classmethod
    def snapshot_code_evidence(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @field_validator("verdict", mode="before")
    @classmethod
    def parse_verdict(cls, value: object) -> object:
        return _enum(value, RequirementVerdict)

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if (
            any(not item.strip() or len(item) > 2000 for item in self.code_evidence)
            or len(self.code_evidence) != len(set(self.code_evidence))
            or (self.verdict is RequirementVerdict.NOT_MET) != (self.counterexample is not None)
            or (
                self.counterexample is not None
                and self.counterexample != self.counterexample.strip()
            )
        ):
            raise ValueError("functional requirement decision failed validation")
        return self


class FunctionalJudgePassRecord(_Contract):
    """One immutable blind evaluation pass retained before outcome publication."""

    schema_version: Literal["1.0"]
    judge_pass_id: str = Field(pattern=_PASS_ID)
    assignment_id: str = Field(pattern=_ASSIGNMENT_ID)
    contract_id: str = Field(pattern=_CONTRACT_ID)
    pass_id: Literal["A", "B"]
    evaluator_policy_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    response_sha256: str = Field(pattern=_SHA256)
    status: FunctionalOutcomeStatus
    requirements: tuple[FunctionalRequirementDecision, ...] = Field(max_length=32)
    rationale: str = Field(min_length=1, max_length=8000)

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, value: object) -> object:
        return _enum(value, FunctionalOutcomeStatus)

    @field_validator("requirements", mode="before")
    @classmethod
    def snapshot_requirements(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, object] = {"schema_version": "1.0", **content}
        try:
            return cls(**payload, judge_pass_id=f"functional_judge_pass_{_digest(payload)}")
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        requirement_ids = tuple(item.requirement_id for item in self.requirements)
        verdicts = tuple(item.verdict for item in self.requirements)
        expected = (
            FunctionalOutcomeStatus.FAIL
            if RequirementVerdict.NOT_MET in verdicts
            else (
                FunctionalOutcomeStatus.UNKNOWN
                if RequirementVerdict.UNKNOWN in verdicts or not verdicts
                else FunctionalOutcomeStatus.PASS
            )
        )
        if (
            requirement_ids != tuple(sorted(requirement_ids))
            or len(requirement_ids) != len(set(requirement_ids))
            or self.status is not expected
            or self.rationale != self.rationale.strip()
            or self.judge_pass_id
            != f"functional_judge_pass_{_digest(_content(self, 'judge_pass_id'))}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ProgramFunctionalOutcomeRecord(_Contract):
    """Mode-specific functional result used by the secure-and-functional outcome."""

    schema_version: Literal["1.0"]
    program_functional_outcome_id: str = Field(pattern=_PROGRAM_OUTCOME_ID)
    assignment_id: str = Field(pattern=_ASSIGNMENT_ID)
    contract_id: str = Field(pattern=_CONTRACT_ID)
    evaluator_policy_sha256: str = Field(pattern=_SHA256)
    status: FunctionalOutcomeStatus
    evidence_sha256: str = Field(pattern=_SHA256)

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, value: object) -> object:
        return _enum(value, FunctionalOutcomeStatus)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, object] = {"schema_version": "1.0", **content}
        try:
            return cls(
                **payload,
                program_functional_outcome_id=(f"program_functional_outcome_{_digest(payload)}"),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.program_functional_outcome_id != (
            "program_functional_outcome_" + _digest(_content(self, "program_functional_outcome_id"))
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "FunctionalAuditDecisionRecord",
    "FunctionalAuditStatus",
    "FunctionalJudgePassRecord",
    "FunctionalJudgeability",
    "FunctionalRequirementDecision",
    "FunctionalRequirementRecord",
    "ProgramFunctionalOutcomeRecord",
    "RequirementVerdict",
    "TaskFunctionalContractRecord",
]

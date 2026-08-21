"""Fail-closed migration boundary between legacy hypotheses and policy v2.

The context-conditioned protocol cannot infer a prospective ``(C_q, f, a,
Q_h, Y)`` commitment from a legacy hypothesis.  In particular, a legacy
hypothesis that permits both ADD and REMOVE is not two atomic v2 hypotheses;
it is an outcome-exposed historical artifact that must remain in its original
run.  This module therefore records a pure, content-addressed disposition and
never constructs a v2 hypothesis or writes a run directory.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, ClassVar, Literal, NoReturn, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from secaware.canonical import canonical_sha256
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.features import FeatureOperation

MIGRATION_BOUNDARY_V2_SCHEMA_VERSION = "2.0"
LEGACY_HYPOTHESIS_MIGRATION_RULE_SHA256 = canonical_sha256(
    {
        "rule": "legacy-hypothesis-to-context-conditioned-policy-v2",
        "version": "1",
        "single_operation": "regenerate_from_outcome-blind-source-artifacts",
        "combined_operation": "reject-without-splitting-or-coercion",
        "legacy_artifact_mutation": "forbidden",
        "formal_evidence_upgrade": "forbidden",
    }
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_DECISION_ID_PATTERN = r"^legacy_hypothesis_migration_[0-9a-f]{64}$"


class LegacyHypothesisDisposition(StrEnum):
    """Only truthful dispositions for a legacy v1 hypothesis."""

    REGENERATE_SINGLE_OPERATION = "regenerate_single_operation"
    REJECT_COMBINED_OPERATION = "reject_combined_operation"


class LegacyHypothesisMigrationDecisionV2(SafeValidationMixin, StrictModel):
    """Auditable decision proving that no legacy hypothesis was upgraded."""

    _safe_validation_message: ClassVar[str] = (
        "legacy hypothesis migration decision failed validation"
    )

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"]
    decision_id: str = Field(pattern=_DECISION_ID_PATTERN)
    source_hypothesis_id: str
    source_hypothesis_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_schema_version: Literal["1.0"]
    source_operations: tuple[FeatureOperation, ...] = Field(min_length=1, max_length=2)
    disposition: LegacyHypothesisDisposition
    migration_rule_sha256: str = Field(pattern=_SHA256_PATTERN)
    v2_hypothesis_id: None = None
    legacy_artifact_mutated: Literal[False]
    formal_evidence_upgrade_allowed: Literal[False]
    requires_new_outcome_blind_run: Literal[True]

    @field_validator("source_operations", mode="before")
    @classmethod
    def parse_operations(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        return tuple(
            item
            if type(item) is FeatureOperation
            else next((member for member in FeatureOperation if member.value == item), item)
            for item in value
        )

    @field_validator("disposition", mode="before")
    @classmethod
    def parse_disposition(cls, value: object) -> object:
        if type(value) is LegacyHypothesisDisposition:
            return value
        if type(value) is str:
            return next(
                (member for member in LegacyHypothesisDisposition if member.value == value),
                value,
            )
        return value

    @classmethod
    def from_legacy_hypothesis(cls, hypothesis: FrozenHypothesisRecord) -> Self:
        """Return a pure disposition; never emit or mutate a protocol artifact."""

        try:
            checked = FrozenHypothesisRecord.model_validate(hypothesis, strict=True)
            operations = checked.permitted_operations
            disposition = (
                LegacyHypothesisDisposition.REJECT_COMBINED_OPERATION
                if len(operations) != 1
                else LegacyHypothesisDisposition.REGENERATE_SINGLE_OPERATION
            )
            content: dict[str, Any] = {
                "schema_version": MIGRATION_BOUNDARY_V2_SCHEMA_VERSION,
                "source_hypothesis_id": checked.hypothesis_id,
                "source_hypothesis_sha256": checked.hypothesis_sha256,
                "source_artifact_sha256": canonical_sha256(checked.model_dump(mode="json")),
                "source_schema_version": checked.schema_version,
                "source_operations": [operation.value for operation in operations],
                "disposition": disposition.value,
                "migration_rule_sha256": LEGACY_HYPOTHESIS_MIGRATION_RULE_SHA256,
                "v2_hypothesis_id": None,
                "legacy_artifact_mutated": False,
                "formal_evidence_upgrade_allowed": False,
                "requires_new_outcome_blind_run": True,
            }
            return cls(
                **content,
                decision_id="legacy_hypothesis_migration_" + canonical_sha256(content),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the migration boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        expected_disposition = (
            LegacyHypothesisDisposition.REJECT_COMBINED_OPERATION
            if len(self.source_operations) != 1
            else LegacyHypothesisDisposition.REGENERATE_SINGLE_OPERATION
        )
        content = self.model_dump(mode="json", exclude={"decision_id"})
        expected_id = "legacy_hypothesis_migration_" + canonical_sha256(content)
        if (
            self.source_operations
            != tuple(sorted(self.source_operations, key=lambda item: item.value))
            or len(self.source_operations) != len(set(self.source_operations))
            or self.disposition is not expected_disposition
            or self.migration_rule_sha256 != LEGACY_HYPOTHESIS_MIGRATION_RULE_SHA256
            or self.v2_hypothesis_id is not None
            or self.decision_id != expected_id
        ):
            raise ValueError(self._safe_validation_message)
        return self


def reject_legacy_hypothesis_upgrade(
    decision: LegacyHypothesisMigrationDecisionV2,
) -> NoReturn:
    """Fail closed at any API that is asked to turn the decision into v2 evidence."""

    try:
        checked = LegacyHypothesisMigrationDecisionV2.model_validate(decision, strict=True)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 - sanitize the public boundary
        raise LegacyHypothesisMigrationDecisionV2._safe_error() from None
    raise SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="protocol_migration_v2",
        message="legacy hypothesis requires a new outcome-blind v2 run",
        details={
            "decision_id": checked.decision_id,
            "disposition": checked.disposition.value,
            "source_hypothesis_id": checked.source_hypothesis_id,
        },
        retryable=False,
    )


__all__ = [
    "LEGACY_HYPOTHESIS_MIGRATION_RULE_SHA256",
    "MIGRATION_BOUNDARY_V2_SCHEMA_VERSION",
    "LegacyHypothesisDisposition",
    "LegacyHypothesisMigrationDecisionV2",
    "reject_legacy_hypothesis_upgrade",
]

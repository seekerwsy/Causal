"""Version-2 assignment outcomes for the prospective intervention-policy protocol.

The v1 outcome contract intentionally remains unchanged.  This module gives the
prospective protocol a separate schema whose coordinates distinguish semantic
clusters, task instances, realizations, and request-randomness slots.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from enum import Enum
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, StrictInt, ValidationError, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel, is_valid_model_id
from secaware.schema.experiments import ArmRole
from secaware.schema.policy_v2 import ConfirmationBlockKeyV2

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OUTCOME_ID = re.compile(r"^assignment_outcome_v2_[0-9a-f]{64}$")
_BLOCK_ID = re.compile(r"^block_[0-9a-f]{64}$")


class AssignmentOutcomeStateV2(str, Enum):
    """Mutually exclusive terminal states for one completed assignment."""

    TERMINAL_NO_CODE = "terminal_no_code"
    SYNTACTICALLY_INVALID_CODE = "syntactically_invalid_code"
    VALID_ORACLE_SECURE = "valid_oracle_secure"
    VALID_ORACLE_INSECURE = "valid_oracle_insecure"
    VALID_ORACLE_UNKNOWN = "valid_oracle_unknown"


class FunctionalStatusV2(str, Enum):
    """Functional evidence kept separate from the primary safety outcome."""

    NOT_APPLICABLE = "not_applicable"
    NOT_EVALUATED_NO_VALID_CODE = "not_evaluated_no_valid_code"
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


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def block_id_v2(
    *,
    semantic_task_cluster_id: str,
    task_instance_id: str,
    hypothesis_id: str,
    target_spec_id: str,
    realization_spec_id: str,
    task_realization_bundle_id: str,
    model_id: str,
    arm_protocol_id: str,
) -> str:
    """Derive the canonical v2 complete-block ID from all frozen coordinates."""

    try:
        return ConfirmationBlockKeyV2.from_coordinates(
            semantic_task_cluster_id=semantic_task_cluster_id,
            task_instance_id=task_instance_id,
            hypothesis_id=hypothesis_id,
            target_spec_id=target_spec_id,
            realization_spec_id=realization_spec_id,
            task_realization_bundle_id=task_realization_bundle_id,
            model_id=model_id,
            arm_protocol_id=arm_protocol_id,
        ).block_id
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("v2 block coordinates failed validation") from None


def _project_state(
    state: AssignmentOutcomeStateV2,
    functional_status: FunctionalStatusV2,
) -> tuple[int, int, int, int | None]:
    y_c = int(
        state
        in {
            AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
            AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
            AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
        }
    )
    y_e = int(
        state
        in {
            AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
            AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
        }
    )
    secure_yield = int(state is AssignmentOutcomeStateV2.VALID_ORACLE_SECURE)
    if functional_status is FunctionalStatusV2.NOT_APPLICABLE:
        y_joint = None
    else:
        y_joint = secure_yield * int(functional_status is FunctionalStatusV2.PASS)
    return y_c, y_e, secure_yield, y_joint


class AssignmentOutcomeRecordV2(SafeValidationMixin, StrictModel):
    """One total, assignment-bound v2 outcome with exact derived projections."""

    _safe_validation_message = "v2 assignment outcome failed validation"
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"]
    outcome_id: str = Field(pattern=_OUTCOME_ID.pattern)
    assignment_id: str
    block_id: str = Field(pattern=_BLOCK_ID.pattern)
    semantic_task_cluster_id: str
    task_instance_id: str
    hypothesis_id: str
    target_spec_id: str
    realization_spec_id: str
    task_realization_bundle_id: str
    variant_id: str
    model_id: str
    arm_protocol_id: str
    arm_role: ArmRole
    request_randomness_slot: StrictInt = Field(ge=0, le=2_147_483_647)
    provider_seed: StrictInt | None = Field(default=None, ge=0, le=2**63 - 1)
    state: AssignmentOutcomeStateV2
    functional_status: FunctionalStatusV2
    y_c: StrictInt = Field(ge=0, le=1)
    y_e: StrictInt = Field(ge=0, le=1)
    y_secure_yield: StrictInt = Field(ge=0, le=1)
    y_joint: StrictInt | None = Field(default=None, ge=0, le=1)
    source_digests_sha256: str = Field(pattern=_SHA256.pattern)

    @field_validator("arm_role", "state", "functional_status", mode="before")
    @classmethod
    def parse_exact_enums(cls, value: object, info: object) -> object:
        enum_type = {
            "arm_role": ArmRole,
            "state": AssignmentOutcomeStateV2,
            "functional_status": FunctionalStatusV2,
        }[info.field_name]  # type: ignore[attr-defined]
        if type(value) is enum_type:
            return value
        if type(value) is str:
            return next((member for member in enum_type if member.value == value), value)
        return value

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        """Construct a content-addressed record while preserving nullable provider seeds."""

        try:
            payload = {"schema_version": "2.0", **content}
            outcome_id = f"assignment_outcome_v2_{_canonical_sha256(payload)}"
            return cls(**payload, outcome_id=outcome_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize all untrusted construction failures
            content.clear()
            raise cls._safe_error() from None

    @property
    def task_bundle_id(self) -> str:
        """Concise alias for the canonical task-realization-bundle coordinate."""

        return self.task_realization_bundle_id

    @property
    def manski_lower(self) -> int:
        """Observable lower endpoint for latent secure valid-code yield."""

        return self.y_secure_yield

    @property
    def manski_upper(self) -> int:
        """Upper endpoint that allows valid Oracle-unknown code to be secure."""

        return self.y_secure_yield + int(self.y_c == 1 and self.y_e == 0)

    @model_validator(mode="after")
    def validate_coordinates_and_projections(self) -> Self:
        identifiers = (
            self.assignment_id,
            self.semantic_task_cluster_id,
            self.task_instance_id,
            self.hypothesis_id,
            self.target_spec_id,
            self.realization_spec_id,
            self.task_realization_bundle_id,
            self.variant_id,
            self.model_id,
            self.arm_protocol_id,
        )
        if not all(_valid_identifier(value) for value in identifiers) or not is_valid_model_id(
            self.model_id
        ):
            raise ValueError(self._safe_validation_message)

        expected_block_id = block_id_v2(
            semantic_task_cluster_id=self.semantic_task_cluster_id,
            task_instance_id=self.task_instance_id,
            hypothesis_id=self.hypothesis_id,
            target_spec_id=self.target_spec_id,
            realization_spec_id=self.realization_spec_id,
            task_realization_bundle_id=self.task_realization_bundle_id,
            model_id=self.model_id,
            arm_protocol_id=self.arm_protocol_id,
        )
        valid_code = self.state in {
            AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
            AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
            AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
        }
        if valid_code:
            functional_coherent = self.functional_status is not (
                FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE
            )
        else:
            functional_coherent = self.functional_status in {
                FunctionalStatusV2.NOT_APPLICABLE,
                FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE,
            }
        expected_projection = _project_state(self.state, self.functional_status)
        actual_projection = (self.y_c, self.y_e, self.y_secure_yield, self.y_joint)
        content = self.model_dump(mode="json", exclude={"outcome_id"})
        expected_outcome_id = f"assignment_outcome_v2_{_canonical_sha256(content)}"
        if (
            not functional_coherent
            or actual_projection != expected_projection
            or self.block_id != expected_block_id
            or self.outcome_id != expected_outcome_id
            or any(
                type(value) is float and (not math.isfinite(value) or value == -0.0)
                for value in actual_projection
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self

    def __repr__(self) -> str:
        return "AssignmentOutcomeRecordV2()"

    def __str__(self) -> str:
        return "AssignmentOutcomeRecordV2()"


__all__ = [
    "AssignmentOutcomeRecordV2",
    "AssignmentOutcomeStateV2",
    "FunctionalStatusV2",
    "block_id_v2",
]

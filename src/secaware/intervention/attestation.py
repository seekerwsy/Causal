"""Exact pre-outcome prompt-role and counterpart attestations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
import hashlib
import json
from typing import Any, ClassVar, Literal, Self

from pydantic import ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SafeValidationMixin, StrictModel, model_shape_is_intact
from secaware.schema.experiments import (
    FeatureFamily,
    FeatureOperation,
    PromptRole,
    TargetInstanceRecord,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)


_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ATTESTATION_ID_PATTERN = r"^attestation_[0-9a-f]{64}$"
_VARIANT_BASELINE_ROLE = {
    PromptRole.POSITIVE_SAFETY_CONTROL: PromptRole.NEUTRAL_BASELINE,
    PromptRole.TASK_FUNCTION_VARIANT: PromptRole.TASK_FUNCTION_BASELINE,
    PromptRole.PRESENTATION_VARIANT: PromptRole.PRESENTATION_BASELINE,
}
_ROLE_FAMILY = {
    PromptRole.POSITIVE_SAFETY_CONTROL: FeatureFamily.SAFETY_CONTROL,
    PromptRole.TASK_FUNCTION_VARIANT: FeatureFamily.TASK_FUNCTION,
    PromptRole.PRESENTATION_VARIANT: FeatureFamily.PRESENTATION_CONTROL,
}


def _jsonable(value: object) -> object:
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


def _exact_enum(value: object, enum_type: type[Enum]) -> object:
    if isinstance(value, enum_type):
        return value
    if type(value) is str:
        for member in enum_type:
            if value == member.value:
                return member
    return value


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and len(value.encode("utf-8")) <= 1024
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _build_reviewed_clause_index() -> dict[str, str]:
    """Bind exact finite renderer clauses to one catalog feature."""

    result: dict[str, str] = {}
    content_by_digest: dict[str, bytes] = {}
    for spec in PROMPT_FEATURE_CATALOG:
        for text in spec.intervention_clauses:
            clause = text.encode("utf-8")
            digest = hashlib.sha256(clause).hexdigest()
            existing_feature = result.get(digest)
            existing_content = content_by_digest.get(digest)
            if existing_feature is not None and (
                existing_feature != spec.feature_id or existing_content != clause
            ):
                raise RuntimeError("ambiguous reviewed prompt clause catalog")
            result[digest] = spec.feature_id
            content_by_digest[digest] = clause
    return result


_REVIEWED_FEATURE_BY_CLAUSE_SHA256 = _build_reviewed_clause_index()


class PromptRoleAttestationRecord(SafeValidationMixin, StrictModel):
    """Content-addressed, strictly pre-outcome provenance for one confirm prompt."""

    _safe_validation_message: ClassVar[str] = "prompt role attestation failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    attestation_id: str = Field(pattern=_ATTESTATION_ID_PATTERN)
    prompt_id: str
    task_id: str
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_role: PromptRole
    counterpart_prompt_id: str | None
    counterpart_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    variant_clause_start: StrictInt | None
    variant_clause_end: StrictInt | None
    variant_clause_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    contrast_owner_operation: FeatureOperation
    catalog_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("prompt_role", mode="before")
    @classmethod
    def parse_prompt_role(cls, value: object) -> object:
        return _exact_enum(value, PromptRole)

    @field_validator("contrast_owner_operation", mode="before")
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
            result = cls(
                **payload,
                attestation_id=f"attestation_{_digest(payload)}",
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
            raise cls._safe_error() from None
        return result

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        variant = self.prompt_role in _VARIANT_BASELINE_ROLE
        clause_fields = (
            self.variant_clause_start,
            self.variant_clause_end,
            self.variant_clause_sha256,
        )
        counterpart_fields = (
            self.counterpart_prompt_id,
            self.counterpart_prompt_sha256,
        )
        content = self.model_dump(mode="json", exclude={"attestation_id"})
        if (
            not _valid_identifier(self.prompt_id)
            or not _valid_identifier(self.task_id)
            or self.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or variant != all(value is not None for value in clause_fields)
            or variant != all(value is not None for value in counterpart_fields)
            or (
                not variant
                and any(value is not None for value in (*clause_fields, *counterpart_fields))
            )
            or (
                variant
                and (
                    self.counterpart_prompt_id == self.prompt_id
                    or self.variant_clause_start is None
                    or self.variant_clause_end is None
                    or self.variant_clause_start < 0
                    or self.variant_clause_end <= self.variant_clause_start
                )
            )
            or self.attestation_id != f"attestation_{_digest(content)}"
        ):
            raise ValueError(self._safe_validation_message)
        return self

    def __repr__(self) -> str:
        return "PromptRoleAttestationRecord()"

    def __str__(self) -> str:
        return "PromptRoleAttestationRecord()"


def _contract_error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="prompt_attestation",
        message="prompt role attestations failed validation",
        details={},
        retryable=False,
    )


def _revalidate_attestation(value: object) -> PromptRoleAttestationRecord:
    if type(value) is not PromptRoleAttestationRecord or not model_shape_is_intact(value):
        raise ValueError
    return PromptRoleAttestationRecord.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings=False)
    )


def _revalidate_prompt(value: object) -> PromptRecord:
    if type(value) is not PromptRecord:
        raise ValueError
    return PromptRecord.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings=False)
    )


def _catalog_feature_for_digest(clause_sha256: str, role: PromptRole) -> str:
    family = _ROLE_FAMILY.get(role)
    feature_id = _REVIEWED_FEATURE_BY_CLAUSE_SHA256.get(clause_sha256)
    if family is None or feature_id is None:
        raise ValueError
    spec = prompt_feature_spec(feature_id)
    if spec.feature_family is not family or not spec.intervenable:
        raise ValueError
    return feature_id


def _catalog_feature_for_clause(clause: bytes, role: PromptRole) -> str:
    clause.decode("utf-8", errors="strict")
    return _catalog_feature_for_digest(hashlib.sha256(clause).hexdigest(), role)


def _validate_pair(
    variant: PromptRecord,
    baseline: PromptRecord,
    variant_attestation: PromptRoleAttestationRecord,
    baseline_attestation: PromptRoleAttestationRecord,
) -> str:
    expected_baseline_role = _VARIANT_BASELINE_ROLE.get(variant.prompt_role)
    if expected_baseline_role is None:
        raise ValueError
    if (
        baseline.prompt_role is not expected_baseline_role
        or variant.split != "confirm"
        or baseline.split != "confirm"
        or variant.counterpart_prompt_id != baseline.prompt_id
        or variant.task_id != baseline.task_id
        or variant.language != baseline.language
        or variant.task_family != baseline.task_family
        or variant.cwe != baseline.cwe
        or variant_attestation.counterpart_prompt_id != baseline.prompt_id
        or variant_attestation.counterpart_prompt_sha256 != baseline.prompt_sha256
        or variant_attestation.contrast_owner_operation
        is not baseline_attestation.contrast_owner_operation
    ):
        raise ValueError
    start = variant_attestation.variant_clause_start
    end = variant_attestation.variant_clause_end
    if start is None or end is None or variant_attestation.variant_clause_sha256 is None:
        raise ValueError
    variant_bytes = variant.prompt.encode("utf-8")
    baseline_bytes = baseline.prompt.encode("utf-8")
    if end > len(variant_bytes):
        raise ValueError
    clause = variant_bytes[start:end]
    if (
        variant_bytes[:start] + variant_bytes[end:] != baseline_bytes
        or not clause
        or hashlib.sha256(clause).hexdigest() != variant_attestation.variant_clause_sha256
    ):
        raise ValueError
    feature_id = _catalog_feature_for_clause(clause, variant.prompt_role)
    spec = prompt_feature_spec(feature_id)
    if (spec.applicable_cwes and variant.cwe not in spec.applicable_cwes) or (
        spec.applicable_task_families and variant.task_family not in spec.applicable_task_families
    ):
        raise ValueError
    return feature_id


def attested_feature_id(attestation: PromptRoleAttestationRecord) -> str:
    """Resolve the one exact reviewed feature bound by a variant attestation."""

    try:
        checked = _revalidate_attestation(attestation)
        clause_sha256 = checked.variant_clause_sha256
        if clause_sha256 is None:
            raise ValueError
        return _catalog_feature_for_digest(clause_sha256, checked.prompt_role)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _contract_error() from None


def validate_prompt_role_attestations(
    prompts: Sequence[PromptRecord],
    attestations: Sequence[PromptRoleAttestationRecord],
) -> tuple[PromptRoleAttestationRecord, ...]:
    """Validate exact complete confirm coverage and all pair byte deltas."""

    checked_prompts: tuple[PromptRecord, ...] = ()
    checked_attestations: tuple[PromptRoleAttestationRecord, ...] = ()
    try:
        if type(prompts) not in {tuple, list} or type(attestations) not in {tuple, list}:
            raise ValueError
        checked_prompts = tuple(_revalidate_prompt(item) for item in prompts)
        checked_attestations = tuple(_revalidate_attestation(item) for item in attestations)
        prompt_ids = tuple(item.prompt_id for item in checked_prompts)
        attestation_ids = tuple(item.attestation_id for item in checked_attestations)
        attested_prompt_ids = tuple(item.prompt_id for item in checked_attestations)
        confirm = tuple(item for item in checked_prompts if item.split == "confirm")
        if (
            len(prompt_ids) != len(set(prompt_ids))
            or len(attestation_ids) != len(set(attestation_ids))
            or len(attested_prompt_ids) != len(set(attested_prompt_ids))
            or set(attested_prompt_ids) != {item.prompt_id for item in confirm}
        ):
            raise ValueError
        prompt_by_id = {item.prompt_id: item for item in confirm}
        attestation_by_prompt_id = {item.prompt_id: item for item in checked_attestations}
        for prompt in confirm:
            attestation = attestation_by_prompt_id[prompt.prompt_id]
            if (
                attestation.task_id != prompt.task_id
                or attestation.prompt_sha256 != prompt.prompt_sha256
                or attestation.prompt_role is not prompt.prompt_role
                or attestation.counterpart_prompt_id != prompt.counterpart_prompt_id
            ):
                raise ValueError

        variants = tuple(item for item in confirm if item.prompt_role in _VARIANT_BASELINE_ROLE)
        baselines = tuple(
            item for item in confirm if item.prompt_role not in _VARIANT_BASELINE_ROLE
        )
        referenced_baselines: list[str] = []
        contrast_ids: list[str] = []
        contrast_coordinates: list[tuple[str, str, FeatureOperation]] = []
        for variant in variants:
            variant_attestation = attestation_by_prompt_id[variant.prompt_id]
            counterpart_id = variant.counterpart_prompt_id
            if counterpart_id is None:
                raise ValueError
            baseline = prompt_by_id.get(counterpart_id)
            baseline_attestation = attestation_by_prompt_id.get(counterpart_id)
            if baseline is None or baseline_attestation is None:
                raise ValueError
            feature_id = _validate_pair(
                variant,
                baseline,
                variant_attestation,
                baseline_attestation,
            )
            referenced_baselines.append(counterpart_id)
            contrast_ids.append(contrast_id(variant_attestation, FeatureOperation.ADD))
            contrast_coordinates.append(
                (
                    variant.task_id,
                    feature_id,
                    variant_attestation.contrast_owner_operation,
                )
            )
        if (
            len(referenced_baselines) != len(set(referenced_baselines))
            or set(referenced_baselines) != {item.prompt_id for item in baselines}
            or len(contrast_ids) != len(set(contrast_ids))
            or len(contrast_coordinates) != len(set(contrast_coordinates))
        ):
            raise ValueError
        return checked_attestations
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        checked_prompts = ()
        checked_attestations = ()
        raise _contract_error() from None


def contrast_id(
    attestation: PromptRoleAttestationRecord,
    operation: FeatureOperation,
) -> str:
    """Return one pair identity shared by the forward and reverse audit views."""

    try:
        checked = _revalidate_attestation(attestation)
        if (
            type(operation) is not FeatureOperation
            or checked.prompt_role not in _VARIANT_BASELINE_ROLE
        ):
            raise ValueError
        payload = {
            "schema_version": "1.0",
            "prompt_id": checked.prompt_id,
            "task_id": checked.task_id,
            "prompt_sha256": checked.prompt_sha256,
            "prompt_role": checked.prompt_role,
            "counterpart_prompt_id": checked.counterpart_prompt_id,
            "counterpart_prompt_sha256": checked.counterpart_prompt_sha256,
            "variant_clause_start": checked.variant_clause_start,
            "variant_clause_end": checked.variant_clause_end,
            "variant_clause_sha256": checked.variant_clause_sha256,
            "catalog_sha256": checked.catalog_sha256,
        }
        return f"contrast_{_digest(payload)}"
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _contract_error() from None


def counterpart_for(
    instance: TargetInstanceRecord,
    attestations: Sequence[PromptRoleAttestationRecord],
) -> PromptRoleAttestationRecord:
    """Resolve one REMOVE instance's authenticated baseline counterpart."""

    try:
        if type(instance) is not TargetInstanceRecord or not model_shape_is_intact(instance):
            raise ValueError
        checked_instance = TargetInstanceRecord.model_validate(
            instance.model_dump(mode="python", round_trip=True, warnings=False)
        )
        if type(attestations) not in {tuple, list}:
            raise ValueError
        checked = tuple(_revalidate_attestation(item) for item in attestations)
        source_matches = tuple(
            item
            for item in checked
            if item.prompt_id == checked_instance.source_prompt_id
            and item.prompt_sha256 == checked_instance.source_prompt_sha256
            and item.task_id == checked_instance.task_id
            and item.prompt_role is checked_instance.source_prompt_role
        )
        counterpart_matches = tuple(
            item
            for item in checked
            if item.prompt_id == checked_instance.counterpart_prompt_id
            and item.prompt_sha256 == checked_instance.counterpart_prompt_sha256
            and item.task_id == checked_instance.task_id
        )
        if (
            not checked_instance.counterpart_required
            or len(source_matches) != 1
            or len(counterpart_matches) != 1
        ):
            raise ValueError
        source = source_matches[0]
        counterpart = counterpart_matches[0]
        expected_baseline_role = _VARIANT_BASELINE_ROLE.get(source.prompt_role)
        clause_sha256 = source.variant_clause_sha256
        if (
            expected_baseline_role is None
            or counterpart.prompt_role is not expected_baseline_role
            or source.counterpart_prompt_id != counterpart.prompt_id
            or source.counterpart_prompt_sha256 != counterpart.prompt_sha256
            or source.contrast_owner_operation is not FeatureOperation.REMOVE
            or counterpart.contrast_owner_operation is not FeatureOperation.REMOVE
            or counterpart.counterpart_prompt_id is not None
            or counterpart.counterpart_prompt_sha256 is not None
            or counterpart.variant_clause_start is not None
            or counterpart.variant_clause_end is not None
            or counterpart.variant_clause_sha256 is not None
            or clause_sha256 is None
        ):
            raise ValueError
        _catalog_feature_for_digest(clause_sha256, source.prompt_role)
        return counterpart
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _contract_error() from None


__all__ = [
    "PromptRoleAttestationRecord",
    "attested_feature_id",
    "contrast_id",
    "counterpart_for",
    "validate_prompt_role_attestations",
]

"""Pre-outcome registration and typed formal-robustness glue inputs.

The existing robustness policy intentionally records that it has not yet been
joined to the formal-analysis lineage.  This module does not rewrite that
content-addressed policy.  Instead, it creates a separate pre-generation
registration that joins the exact policy to the exact pre-generation closure.

The interaction-family contract is deliberately conservative in this first
implementation segment: it types and binds the complete reference registry,
but records that deterministic 999-draw reference replay is still pending.
Consequently it can never authorize a formal strong label yet.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.multi_support_robustness_v2 import (
    MultiSupportArmRealizationInteractionReferenceV2,
    MultiSupportRobustnessPolicyFreezeV2,
)
from secaware.schema.pre_generation_closure_v2 import (
    ConfirmatoryPreGenerationClosureV2,
)

FORMAL_ROBUSTNESS_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REGISTRATION_ID_PATTERN = r"^confirmatory_robustness_policy_registration_v2_[0-9a-f]{64}$"
_INTERACTION_FAMILY_ID_PATTERN = r"^formal_robustness_interaction_family_v2_[0-9a-f]{64}$"
_CLOSED_RUN_ID_PATTERN = r"^confirmatory_closed_run_evidence_v2_[0-9a-f]{64}$"
_FORMAL_RESULT_ID_PATTERN = r"^formal_confirmation_result_v2_[0-9a-f]{64}$"


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
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


def _snapshot_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_arrays(item) for item in value)
    return value


class _FormalRobustnessV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "formal robustness v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = FORMAL_ROBUSTNESS_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedFormalRobustnessV2(_FormalRobustnessV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {
                "schema_version": FORMAL_ROBUSTNESS_V2_SCHEMA_VERSION,
                **content,
            }
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public freeze boundary
            content.clear()
            if payload is not None:
                payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class ConfirmatoryRobustnessPolicyRegistrationV2(_ContentAddressedFormalRobustnessV2):
    """Pre-generation join between one closure and one robustness policy."""

    _id_field = "confirmatory_robustness_policy_registration_id"
    _id_prefix = "confirmatory_robustness_policy_registration_v2_"

    confirmatory_robustness_policy_registration_id: str = Field(pattern=_REGISTRATION_ID_PATTERN)
    pre_generation_closure: ConfirmatoryPreGenerationClosureV2
    robustness_policy: MultiSupportRobustnessPolicyFreezeV2
    confirmatory_pre_generation_closure_id: str
    confirmatory_experiment_freeze_id: str
    robustness_policy_freeze_id: str
    robustness_family_id: str
    hypothesis_robustness_decision_ids: tuple[str, ...] = Field(min_length=1)
    cross_model_replication_policy_id: str
    policy_material_sha256: str = Field(pattern=_SHA256_PATTERN)
    delta_and_thresholds_explicitly_frozen: Literal[True]
    exact_experiment_and_family_binding: Literal[True]
    registered_after_randomization_before_generation: Literal[True]
    external_pre_generation_pin_required: Literal[True]
    source_policy_status: Literal[
        "standalone_phase0_not_yet_embedded_in_formal_analysis_protocol_v1"
    ]
    registration_status: Literal["bound_via_pre_generation_registration_v1"]
    outcomes_excluded: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        pre_generation_closure: ConfirmatoryPreGenerationClosureV2,
        robustness_policy: MultiSupportRobustnessPolicyFreezeV2,
    ) -> Self:
        try:
            closure = ConfirmatoryPreGenerationClosureV2.model_validate(
                pre_generation_closure, strict=True
            )
            policy = MultiSupportRobustnessPolicyFreezeV2.model_validate(
                robustness_policy, strict=True
            )
            if policy.experiment != closure.experiment_freeze:
                raise ValueError
            return cls.from_content(
                pre_generation_closure=closure,
                robustness_policy=policy,
                confirmatory_pre_generation_closure_id=(
                    closure.confirmatory_pre_generation_closure_id
                ),
                confirmatory_experiment_freeze_id=(
                    closure.experiment_freeze.confirmatory_experiment_freeze_id
                ),
                robustness_policy_freeze_id=policy.robustness_policy_freeze_id,
                robustness_family_id=policy.robustness_family.family_id,
                hypothesis_robustness_decision_ids=tuple(
                    item.hypothesis_robustness_decision_id for item in policy.hypothesis_decisions
                ),
                cross_model_replication_policy_id=(
                    policy.cross_model_policy.cross_model_replication_policy_id
                ),
                policy_material_sha256=policy.policy_material_sha256,
                delta_and_thresholds_explicitly_frozen=True,
                exact_experiment_and_family_binding=True,
                registered_after_randomization_before_generation=True,
                external_pre_generation_pin_required=True,
                source_policy_status=policy.formal_analysis_glue_binding_status,
                registration_status="bound_via_pre_generation_registration_v1",
                outcomes_excluded=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the registration boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_registration(self) -> Self:
        closure = self.pre_generation_closure
        policy = self.robustness_policy
        if (
            policy.experiment != closure.experiment_freeze
            or self.confirmatory_pre_generation_closure_id
            != closure.confirmatory_pre_generation_closure_id
            or self.confirmatory_experiment_freeze_id
            != closure.experiment_freeze.confirmatory_experiment_freeze_id
            or self.robustness_policy_freeze_id != policy.robustness_policy_freeze_id
            or self.robustness_family_id != policy.robustness_family.family_id
            or self.hypothesis_robustness_decision_ids
            != tuple(item.hypothesis_robustness_decision_id for item in policy.hypothesis_decisions)
            or self.cross_model_replication_policy_id
            != policy.cross_model_policy.cross_model_replication_policy_id
            or self.policy_material_sha256 != policy.policy_material_sha256
            or self.source_policy_status != policy.formal_analysis_glue_binding_status
        ):
            raise ValueError(self._safe_validation_message)
        return self


class FormalRobustnessInteractionFamilyV2(_ContentAddressedFormalRobustnessV2):
    """Typed reference registry; full 999-draw replay lands in the next segment."""

    _id_field = "formal_robustness_interaction_family_id"
    _id_prefix = "formal_robustness_interaction_family_v2_"

    formal_robustness_interaction_family_id: str = Field(pattern=_INTERACTION_FAMILY_ID_PATTERN)
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2
    confirmatory_robustness_policy_registration_id: str
    confirmatory_closed_run_evidence_id: str = Field(pattern=_CLOSED_RUN_ID_PATTERN)
    formal_confirmation_result_id: str = Field(pattern=_FORMAL_RESULT_ID_PATTERN)
    robustness_policy_freeze_id: str
    robustness_family_id: str
    expected_hypothesis_model_keys: tuple[tuple[str, str], ...] = Field(min_length=1)
    reported_hypothesis_model_keys: tuple[tuple[str, str], ...]
    interaction_references: tuple[MultiSupportArmRealizationInteractionReferenceV2, ...]
    interaction_reference_ids: tuple[str, ...]
    expected_reference_count: StrictInt = Field(ge=1)
    reported_reference_count: StrictInt = Field(ge=0)
    complete_hypothesis_model_family: bool
    reference_draws_per_coordinate: Literal[999]
    full_reference_replay_status: Literal["pending_typed_999_draw_replay_next_segment_v1"]
    p_values_are_diagnostic_only: Literal[True]
    formal_strong_labels_authorized: Literal[False]

    @classmethod
    def from_components(
        cls,
        *,
        policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
        confirmatory_closed_run_evidence_id: str,
        formal_confirmation_result_id: str,
        interaction_references: tuple[MultiSupportArmRealizationInteractionReferenceV2, ...] = (),
    ) -> Self:
        try:
            registration = ConfirmatoryRobustnessPolicyRegistrationV2.model_validate(
                policy_registration, strict=True
            )
            references = tuple(
                sorted(
                    (
                        MultiSupportArmRealizationInteractionReferenceV2.model_validate(
                            item, strict=True
                        )
                        for item in interaction_references
                    ),
                    key=lambda item: (item.hypothesis_id, item.model_id),
                )
            )
            expected = tuple(
                sorted(
                    (
                        item.hypothesis_id,
                        item.model_id,
                    )
                    for item in registration.robustness_policy.hypothesis_model_specifications
                )
            )
            reported = tuple((item.hypothesis_id, item.model_id) for item in references)
            return cls.from_content(
                policy_registration=registration,
                confirmatory_robustness_policy_registration_id=(
                    registration.confirmatory_robustness_policy_registration_id
                ),
                confirmatory_closed_run_evidence_id=(confirmatory_closed_run_evidence_id),
                formal_confirmation_result_id=formal_confirmation_result_id,
                robustness_policy_freeze_id=(registration.robustness_policy_freeze_id),
                robustness_family_id=registration.robustness_family_id,
                expected_hypothesis_model_keys=expected,
                reported_hypothesis_model_keys=reported,
                interaction_references=references,
                interaction_reference_ids=tuple(
                    item.interaction_reference_id for item in references
                ),
                expected_reference_count=len(expected),
                reported_reference_count=len(references),
                complete_hypothesis_model_family=(reported == expected),
                reference_draws_per_coordinate=999,
                full_reference_replay_status=("pending_typed_999_draw_replay_next_segment_v1"),
                p_values_are_diagnostic_only=True,
                formal_strong_labels_authorized=False,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the reference boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_family(self) -> Self:
        registration = self.policy_registration
        policy = registration.robustness_policy
        expected = tuple(
            sorted(
                (item.hypothesis_id, item.model_id)
                for item in policy.hypothesis_model_specifications
            )
        )
        reported = tuple(
            (item.hypothesis_id, item.model_id) for item in self.interaction_references
        )
        reference_ids = tuple(item.interaction_reference_id for item in self.interaction_references)
        if (
            self.confirmatory_robustness_policy_registration_id
            != registration.confirmatory_robustness_policy_registration_id
            or self.robustness_policy_freeze_id != policy.robustness_policy_freeze_id
            or self.robustness_family_id != policy.robustness_family.family_id
            or self.expected_hypothesis_model_keys != expected
            or self.reported_hypothesis_model_keys != reported
            or len(reported) != len(set(reported))
            or not set(reported) <= set(expected)
            or self.interaction_reference_ids != reference_ids
            or self.expected_reference_count != len(expected)
            or self.reported_reference_count != len(reported)
            or self.complete_hypothesis_model_family != (reported == expected)
            or any(
                item.robustness_policy_freeze_id != policy.robustness_policy_freeze_id
                or item.global_robustness_family_id != policy.robustness_family.family_id
                or item.confirmatory_experiment_freeze_id
                != policy.confirmatory_experiment_freeze_id
                for item in self.interaction_references
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "FORMAL_ROBUSTNESS_V2_SCHEMA_VERSION",
    "ConfirmatoryRobustnessPolicyRegistrationV2",
    "FormalRobustnessInteractionFamilyV2",
]

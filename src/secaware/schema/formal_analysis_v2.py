"""Outcome-blind formal confirmation protocol derived from one experiment root."""

from __future__ import annotations

import hashlib
import json
from enum import Enum, StrEnum
from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.multi_support_inference_v2 import (
    MultiSupportFormalFamilyV2,
    MultiSupportSimultaneousInferencePlanV2,
)

FORMAL_ANALYSIS_V2_SCHEMA_VERSION = "2.0"

_PROTOCOL_ID_PATTERN = r"^formal_analysis_protocol_v2_[0-9a-f]{64}$"


class FormalConfirmationStatusV2(StrEnum):
    EVALUATED = "evaluated"
    NON_EVALUABLE = "non_evaluable"


class FormalNonEvaluableReasonV2(StrEnum):
    TERMINAL_INFRASTRUCTURE_FAILURE = "terminal_infrastructure_failure"
    INFERENCE_UNDEFINED = "inference_undefined"


class FormalCoordinateLabelV2(StrEnum):
    TARGET_SPECIFIC_POLICY_EFFECT = "target_specific_policy_effect"
    CONFIRMED_POLICY_EFFECT = "confirmed_policy_effect"
    CONFLICTING_POLICY_EFFECT = "conflicting_policy_effect"
    INCONCLUSIVE = "inconclusive"


class FormalJointInterpretationV2(StrEnum):
    IMPROVED = "improved"
    HARMED = "harmed"
    INCONCLUSIVE = "inconclusive"


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


class _FormalAnalysisV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "formal analysis v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = FORMAL_ANALYSIS_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class FormalAnalysisProtocolV2(_FormalAnalysisV2Contract):
    """The four fixed H x M families; callers cannot choose their contents."""

    formal_analysis_protocol_id: str = Field(pattern=_PROTOCOL_ID_PATTERN)
    confirmatory_experiment_freeze_id: str
    experiment: ConfirmatoryExperimentFreezeV2
    family_order: tuple[
        Literal["primary_secure_yield"],
        Literal["key_joint"],
        Literal["specificity_placebo"],
        Literal["specificity_generic"],
    ]
    family_plans: tuple[
        MultiSupportSimultaneousInferencePlanV2,
        MultiSupportSimultaneousInferencePlanV2,
        MultiSupportSimultaneousInferencePlanV2,
        MultiSupportSimultaneousInferencePlanV2,
    ]
    global_multiplicity_family_policy_sha256: str
    analysis_seed_domain_sha256: str
    primary_outcome: Literal["y_secure_yield"]
    key_practical_outcome: Literal["y_joint"]
    primary_contrast_source: Literal["arm_protocol.primary_contrast"]
    specificity_contrast_source: Literal["arm_protocol.specificity_contrasts"]
    bootstrap_samples: Literal[999]
    alpha_numerator: Literal[1]
    alpha_denominator: Literal[20]
    all_hypothesis_model_coordinates_required: Literal[True]
    coordinate_specific_support_preserved: Literal[True]
    common_intersection_forbidden: Literal[True]
    assigned_arm_itt_only: Literal[True]
    target_changed_and_semantic_validity_diagnostic_only: Literal[True]
    joint_outcome_cannot_promote_security_confirmation: Literal[True]
    optional_jci_rfci_marker_per_protocol_cannot_promote_label: Literal[True]
    frozen_before_outcomes: Literal[True]

    @classmethod
    def from_experiment(
        cls,
        experiment: ConfirmatoryExperimentFreezeV2,
    ) -> Self:
        try:
            checked = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            order = tuple(item for item in MultiSupportFormalFamilyV2)
            plans = tuple(
                MultiSupportSimultaneousInferencePlanV2.from_frozen_formal_family(
                    experiment=checked,
                    formal_family=item,
                )
                for item in order
            )
            content = {
                "schema_version": FORMAL_ANALYSIS_V2_SCHEMA_VERSION,
                "confirmatory_experiment_freeze_id": (checked.confirmatory_experiment_freeze_id),
                "experiment": checked,
                "family_order": tuple(item.value for item in order),
                "family_plans": plans,
                "global_multiplicity_family_policy_sha256": (
                    checked.global_multiplicity_family_policy_sha256
                ),
                "analysis_seed_domain_sha256": checked.analysis_seed_domain_sha256,
                "primary_outcome": "y_secure_yield",
                "key_practical_outcome": "y_joint",
                "primary_contrast_source": "arm_protocol.primary_contrast",
                "specificity_contrast_source": "arm_protocol.specificity_contrasts",
                "bootstrap_samples": 999,
                "alpha_numerator": 1,
                "alpha_denominator": 20,
                "all_hypothesis_model_coordinates_required": True,
                "coordinate_specific_support_preserved": True,
                "common_intersection_forbidden": True,
                "assigned_arm_itt_only": True,
                "target_changed_and_semantic_validity_diagnostic_only": True,
                "joint_outcome_cannot_promote_security_confirmation": True,
                "optional_jci_rfci_marker_per_protocol_cannot_promote_label": True,
                "frozen_before_outcomes": True,
            }
            return cls(
                **content,
                formal_analysis_protocol_id=("formal_analysis_protocol_v2_" + _digest(content)),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the formal protocol boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        expected = tuple(
            MultiSupportSimultaneousInferencePlanV2.from_frozen_formal_family(
                experiment=self.experiment,
                formal_family=item,
            )
            for item in MultiSupportFormalFamilyV2
        )
        content = self.model_dump(mode="json", exclude={"formal_analysis_protocol_id"})
        if (
            self.confirmatory_experiment_freeze_id
            != self.experiment.confirmatory_experiment_freeze_id
            or self.family_order != tuple(item.value for item in MultiSupportFormalFamilyV2)
            or self.family_plans != expected
            or any(
                plan.experiment != self.experiment
                or plan.family.family_size != self.experiment.hypothesis_model_coordinate_count
                for plan in self.family_plans
            )
            or self.global_multiplicity_family_policy_sha256
            != self.experiment.global_multiplicity_family_policy_sha256
            or self.analysis_seed_domain_sha256 != self.experiment.analysis_seed_domain_sha256
            or self.formal_analysis_protocol_id != "formal_analysis_protocol_v2_" + _digest(content)
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "FORMAL_ANALYSIS_V2_SCHEMA_VERSION",
    "FormalAnalysisProtocolV2",
    "FormalConfirmationStatusV2",
    "FormalCoordinateLabelV2",
    "FormalJointInterpretationV2",
    "FormalNonEvaluableReasonV2",
]

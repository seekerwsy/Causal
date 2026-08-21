"""Outcome-blind formal confirmation protocol derived from one experiment root."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import Field, model_validator

from secaware.records import SnapshotResearchRecord, record_sha256 as _digest
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.multi_support_inference_v2 import (
    _CHECKED_FORMAL_PLAN_ACCESS,
    MultiSupportFormalFamilyV2,
    MultiSupportSimultaneousInferencePlanV2,
)

FORMAL_ANALYSIS_V2_SCHEMA_VERSION = "2.0"

_PROTOCOL_ID_PATTERN = r"^formal_analysis_protocol_v2_[0-9a-f]{64}$"
_CHECKED_FORMAL_PROTOCOL_ACCESS = object()
_FORMAL_CONTEXT_PROTOCOL_ACCESS = object()


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


class _FormalAnalysisV2Contract(SnapshotResearchRecord):
    _safe_validation_message: ClassVar[str] = "formal analysis v2 contract failed validation"
    schema_version: Literal["2.0"] = FORMAL_ANALYSIS_V2_SCHEMA_VERSION


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
            order = tuple(MultiSupportFormalFamilyV2)
            plans = tuple(
                MultiSupportSimultaneousInferencePlanV2._from_checked_frozen_formal_family(
                    experiment=checked,
                    formal_family=item,
                    access=_CHECKED_FORMAL_PLAN_ACCESS,
                )
                for item in order
            )
            return cls._construct_checked_protocol(
                experiment=checked,
                plans=plans,
                access=_CHECKED_FORMAL_PROTOCOL_ACCESS,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the formal protocol boundary
            raise cls._safe_error() from None

    @classmethod
    def _from_formal_context(
        cls,
        context: object,
    ) -> Self:
        """Derive the protocol from the sealed formal two-root context only."""

        try:
            from secaware.analysis.formal_confirmation_v2 import (
                _ValidatedFormalContextV2,
            )

            if type(context) is not _ValidatedFormalContextV2:
                raise ValueError
            experiment = context._experiment_for_protocol_builder(_FORMAL_CONTEXT_PROTOCOL_ACCESS)
            order = tuple(MultiSupportFormalFamilyV2)
            plans = tuple(
                MultiSupportSimultaneousInferencePlanV2._from_formal_context(
                    context=context,
                    formal_family=item,
                )
                for item in order
            )
            return cls._construct_checked_protocol(
                experiment=experiment,
                plans=plans,
                access=_CHECKED_FORMAL_PROTOCOL_ACCESS,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the formal context boundary
            raise cls._safe_error() from None

    @classmethod
    def _construct_checked_protocol(
        cls,
        *,
        experiment: ConfirmatoryExperimentFreezeV2,
        plans: tuple[MultiSupportSimultaneousInferencePlanV2, ...],
        access: object,
    ) -> Self:
        """Assemble deterministic plans after an explicit checked boundary."""

        try:
            if (
                access is not _CHECKED_FORMAL_PROTOCOL_ACCESS
                or type(experiment) is not ConfirmatoryExperimentFreezeV2
                or not model_shape_is_intact(experiment)
                or len(plans) != len(tuple(MultiSupportFormalFamilyV2))
                or any(
                    type(plan) is not MultiSupportSimultaneousInferencePlanV2
                    or not model_shape_is_intact(plan)
                    for plan in plans
                )
            ):
                raise ValueError
            order = tuple(MultiSupportFormalFamilyV2)
            content = {
                "schema_version": FORMAL_ANALYSIS_V2_SCHEMA_VERSION,
                "confirmatory_experiment_freeze_id": (experiment.confirmatory_experiment_freeze_id),
                "experiment": experiment,
                "family_order": tuple(item.value for item in order),
                "family_plans": plans,
                "global_multiplicity_family_policy_sha256": (
                    experiment.global_multiplicity_family_policy_sha256
                ),
                "analysis_seed_domain_sha256": experiment.analysis_seed_domain_sha256,
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
            return cls.model_construct(
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
            MultiSupportSimultaneousInferencePlanV2._from_checked_frozen_formal_family(
                experiment=self.experiment,
                formal_family=item,
                access=_CHECKED_FORMAL_PLAN_ACCESS,
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

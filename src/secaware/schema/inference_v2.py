"""Frozen contracts for prospective simultaneous cluster inference.

This deliberately small schema supports only one conservative Phase-0 design:
every test coordinate in a family must use the exact same semantic-cluster by
stratum support.  Supporting coordinates with different eligible populations
requires a separately approved resampling contract rather than an implicit
generalization of these records.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, ClassVar, Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from secaware.randomness import RNG_VERSION
from secaware.records import (
    FrozenResearchRecord,
)
from secaware.records import (
    parse_exact_enum as _exact_enum,
)
from secaware.records import (
    record_sha256 as _digest,
)
from secaware.records import (
    valid_identifier as _valid_identifier,
)
from secaware.schema.common import is_valid_model_id
from secaware.schema.experiments import ArmRole

INFERENCE_V2_SCHEMA_VERSION = "2.0"
FORMAL_MIN_BOOTSTRAP_SAMPLES_V2 = 999
FORMAL_MIN_VALID_BOOTSTRAP_DRAWS_V2 = 999

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_HYPOTHESIS_PATTERN = r"^hypothesis_[0-9a-f]{64}$"
_TARGET_PATTERN = r"^target_[0-9a-f]{64}$"
_ARM_PROTOCOL_PATTERN = r"^arm_protocol_[0-9a-f]{64}$"
_COORDINATE_PATTERN = r"^simultaneous_coordinate_[0-9a-f]{64}$"
_FAMILY_PATTERN = r"^simultaneous_family_[0-9a-f]{64}$"
_PLAN_PATTERN = r"^simultaneous_plan_[0-9a-f]{64}$"
_ROBUSTNESS_HYPOTHESIS_PATTERN = r"^robustness_hypothesis_[0-9a-f]{64}$"
_ROBUSTNESS_PLAN_PATTERN = r"^realization_robustness_plan_[0-9a-f]{64}$"
_REALIZATION_SPEC_PATTERN = r"^realization_spec_[0-9a-f]{64}$"


class _InferenceV2Contract(FrozenResearchRecord):
    _safe_validation_message = "simultaneous inference v2 contract failed validation"

    schema_version: Literal["2.0"] = INFERENCE_V2_SCHEMA_VERSION


class _ContentAddressedInferenceV2(_InferenceV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": INFERENCE_V2_SCHEMA_VERSION, **content}
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            content.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class SimultaneousFamilyKindV2(StrEnum):
    PRIMARY_SECURE_YIELD = "primary_secure_yield"
    TARGET_SPECIFICITY = "target_specificity"
    JOINT_OUTCOME = "joint_outcome"
    REALIZATION_ROBUSTNESS = "realization_robustness"
    SELECTOR_COMPARISON = "selector_comparison"


class SimultaneousCoordinateKindV2(StrEnum):
    POLICY_EFFECT = "policy_effect"
    REALIZATION_EFFECT = "realization_effect"
    LEAVE_ONE_REALIZATION_OUT = "leave_one_realization_out"
    REALIZATION_DEVIATION = "realization_deviation"


class RobustnessExpectedDirectionV2(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class SimultaneousTestCoordinateV2(_ContentAddressedInferenceV2):
    """One exact hypothesis/model/outcome/contrast coordinate."""

    _id_field = "test_coordinate_id"
    _id_prefix = "simultaneous_coordinate_"

    test_coordinate_id: str = Field(pattern=_COORDINATE_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_PATTERN)
    arm_protocol_id: str = Field(pattern=_ARM_PROTOCOL_PATTERN)
    model_id: str
    outcome_name: Literal["y_c", "y_e", "y_secure_yield", "y_joint"]
    treatment_arm: ArmRole
    control_arm: ArmRole
    coordinate_kind: SimultaneousCoordinateKindV2
    analysis_component_id: str

    @field_validator("treatment_arm", "control_arm", mode="before")
    @classmethod
    def parse_arm(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @field_validator("coordinate_kind", mode="before")
    @classmethod
    def parse_coordinate_kind(cls, value: object) -> object:
        return _exact_enum(value, SimultaneousCoordinateKindV2)

    @model_validator(mode="after")
    def validate_coordinate(self) -> Self:
        if (
            not is_valid_model_id(self.model_id)
            or self.treatment_arm is self.control_arm
            or not _valid_identifier(self.analysis_component_id)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SimultaneousFamilyManifestV2(_ContentAddressedInferenceV2):
    """An exact, outcome-blind multiplicity family."""

    _id_field = "family_id"
    _id_prefix = "simultaneous_family_"

    family_id: str = Field(pattern=_FAMILY_PATTERN)
    family_label: str
    family_kind: SimultaneousFamilyKindV2
    coordinates: tuple[SimultaneousTestCoordinateV2, ...] = Field(min_length=1, max_length=1_000)
    family_size: StrictInt = Field(ge=1, le=1_000)
    frozen_before_outcomes: Literal[True]

    @field_validator("family_kind", mode="before")
    @classmethod
    def parse_family_kind(cls, value: object) -> object:
        return _exact_enum(value, SimultaneousFamilyKindV2)

    @model_validator(mode="after")
    def validate_family(self) -> Self:
        coordinate_ids = tuple(item.test_coordinate_id for item in self.coordinates)
        if (
            not _valid_identifier(self.family_label)
            or self.family_size != len(self.coordinates)
            or coordinate_ids != tuple(sorted(coordinate_ids))
            or len(coordinate_ids) != len(set(coordinate_ids))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CommonStratumSupportV2(_InferenceV2Contract):
    """The one cluster support shared by every coordinate for one stratum."""

    stratum_id: str
    semantic_task_cluster_ids: tuple[str, ...] = Field(min_length=2, max_length=100_000)
    weight_numerator: StrictInt = Field(ge=1, le=2**31 - 1)

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        if (
            not _valid_identifier(self.stratum_id)
            or self.semantic_task_cluster_ids != tuple(sorted(self.semantic_task_cluster_ids))
            or len(self.semantic_task_cluster_ids) != len(set(self.semantic_task_cluster_ids))
            or any(not _valid_identifier(item) for item in self.semantic_task_cluster_ids)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SimultaneousInferencePlanV2(_ContentAddressedInferenceV2):
    """Fully frozen Phase-0 max-|T| plan for one common-support family."""

    _id_field = "inference_plan_id"
    _id_prefix = "simultaneous_plan_"

    inference_plan_id: str = Field(pattern=_PLAN_PATTERN)
    family_id: str = Field(pattern=_FAMILY_PATTERN)
    family: SimultaneousFamilyManifestV2
    strata: tuple[CommonStratumSupportV2, ...] = Field(min_length=1, max_length=1_000)
    stratum_weight_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    alpha_numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    alpha_denominator: StrictInt = Field(ge=2, le=2**31 - 1)
    bootstrap_samples: StrictInt = Field(ge=FORMAL_MIN_BOOTSTRAP_SAMPLES_V2, le=100_000)
    minimum_valid_bootstrap_draws: StrictInt = Field(
        ge=FORMAL_MIN_VALID_BOOTSTRAP_DRAWS_V2, le=100_000
    )
    minimum_independent_clusters: StrictInt = Field(ge=2, le=100_000)
    minimum_clusters_per_stratum: StrictInt = Field(ge=2, le=100_000)
    maximum_invalid_fraction_numerator: StrictInt = Field(ge=0, le=2**31 - 1)
    maximum_invalid_fraction_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    seed_material_sha256: str = Field(pattern=_SHA256_PATTERN)
    rng_version: Literal["sha256-rejection-fisher-yates-v1"] = RNG_VERSION
    resampling_method: Literal["common_stratified_semantic_cluster_v1"]
    studentization_method: Literal["protocol_cluster_se_v1"]
    centering_method: Literal["bootstrap_minus_observed_v1"]
    quantile_rule: Literal["empirical_higher_v1"]
    interval_rule: Literal["two_sided_studentized_max_abs_t_v1"]
    invalid_draw_policy: Literal["fail_on_any_invalid_draw_v1"]
    same_cluster_stratum_support_required: Literal[True]
    complete_family_required: Literal[True]
    frozen_before_outcomes: Literal[True]

    @classmethod
    def from_family(
        cls,
        *,
        family: SimultaneousFamilyManifestV2,
        strata: tuple[CommonStratumSupportV2, ...],
        stratum_weight_denominator: int,
        alpha_numerator: int,
        alpha_denominator: int,
        bootstrap_samples: int,
        minimum_independent_clusters: int,
        minimum_clusters_per_stratum: int,
        maximum_invalid_fraction_numerator: int,
        maximum_invalid_fraction_denominator: int,
        seed_material_sha256: str,
    ) -> Self:
        try:
            checked_family = SimultaneousFamilyManifestV2.model_validate(family, strict=True)
            return cls.from_content(
                family_id=checked_family.family_id,
                family=checked_family,
                strata=strata,
                stratum_weight_denominator=stratum_weight_denominator,
                alpha_numerator=alpha_numerator,
                alpha_denominator=alpha_denominator,
                bootstrap_samples=bootstrap_samples,
                minimum_valid_bootstrap_draws=FORMAL_MIN_VALID_BOOTSTRAP_DRAWS_V2,
                minimum_independent_clusters=minimum_independent_clusters,
                minimum_clusters_per_stratum=minimum_clusters_per_stratum,
                maximum_invalid_fraction_numerator=maximum_invalid_fraction_numerator,
                maximum_invalid_fraction_denominator=maximum_invalid_fraction_denominator,
                seed_material_sha256=seed_material_sha256,
                rng_version=RNG_VERSION,
                resampling_method="common_stratified_semantic_cluster_v1",
                studentization_method="protocol_cluster_se_v1",
                centering_method="bootstrap_minus_observed_v1",
                quantile_rule="empirical_higher_v1",
                interval_rule="two_sided_studentized_max_abs_t_v1",
                invalid_draw_policy="fail_on_any_invalid_draw_v1",
                same_cluster_stratum_support_required=True,
                complete_family_required=True,
                frozen_before_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            raise cls._safe_error() from None

    @property
    def alpha(self) -> float:
        return self.alpha_numerator / self.alpha_denominator

    @property
    def maximum_invalid_fraction(self) -> float:
        return self.maximum_invalid_fraction_numerator / self.maximum_invalid_fraction_denominator

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        stratum_ids = tuple(item.stratum_id for item in self.strata)
        all_clusters = tuple(
            cluster_id for item in self.strata for cluster_id in item.semantic_task_cluster_ids
        )
        if (
            self.family_id != self.family.family_id
            or stratum_ids != tuple(sorted(stratum_ids))
            or len(stratum_ids) != len(set(stratum_ids))
            or len(all_clusters) != len(set(all_clusters))
            or sum(item.weight_numerator for item in self.strata) != self.stratum_weight_denominator
            or self.alpha_numerator >= self.alpha_denominator
            or self.maximum_invalid_fraction_numerator != 0
            or self.maximum_invalid_fraction_denominator != 1
            or self.minimum_valid_bootstrap_draws > self.bootstrap_samples
            or len(all_clusters) < self.minimum_independent_clusters
            or any(
                len(item.semantic_task_cluster_ids) < self.minimum_clusters_per_stratum
                for item in self.strata
            )
            or len(all_clusters) * self.family.family_size > 1_000_000
        ):
            raise ValueError(self._safe_validation_message)
        return self


class RealizationRobustnessHypothesisSpecV2(_ContentAddressedInferenceV2):
    """Frozen Q_h, direction, support, and equivalence rule for one (h, model)."""

    _id_field = "robustness_hypothesis_spec_id"
    _id_prefix = "robustness_hypothesis_"

    robustness_hypothesis_spec_id: str = Field(pattern=_ROBUSTNESS_HYPOTHESIS_PATTERN)
    hypothesis_id: str = Field(pattern=_HYPOTHESIS_PATTERN)
    target_spec_id: str = Field(pattern=_TARGET_PATTERN)
    arm_protocol_id: str = Field(pattern=_ARM_PROTOCOL_PATTERN)
    model_id: str
    outcome_name: Literal["y_secure_yield", "y_joint"]
    treatment_arm: ArmRole
    control_arm: ArmRole
    expected_direction: RobustnessExpectedDirectionV2
    realization_spec_ids: tuple[str, ...] = Field(min_length=2, max_length=32)
    probability_numerators: tuple[StrictInt, ...] = Field(min_length=2, max_length=32)
    probability_denominator: StrictInt = Field(ge=2, le=2**31 - 1)
    practical_equivalence_margin_numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    practical_equivalence_margin_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    minimum_direction_consistent_realizations: StrictInt = Field(ge=1, le=32)
    minimum_independent_clusters_per_realization: StrictInt = Field(ge=2, le=100_000)

    @field_validator("treatment_arm", "control_arm", mode="before")
    @classmethod
    def parse_robustness_arm(cls, value: object) -> object:
        return _exact_enum(value, ArmRole)

    @field_validator("expected_direction", mode="before")
    @classmethod
    def parse_expected_direction(cls, value: object) -> object:
        return _exact_enum(value, RobustnessExpectedDirectionV2)

    @property
    def practical_equivalence_margin(self) -> float:
        return (
            self.practical_equivalence_margin_numerator
            / self.practical_equivalence_margin_denominator
        )

    @model_validator(mode="after")
    def validate_robustness_hypothesis(self) -> Self:
        if (
            not is_valid_model_id(self.model_id)
            or self.treatment_arm is self.control_arm
            or len(self.realization_spec_ids) != len(self.probability_numerators)
            or len(self.realization_spec_ids) != len(set(self.realization_spec_ids))
            or any(
                re.fullmatch(_REALIZATION_SPEC_PATTERN, item) is None
                for item in self.realization_spec_ids
            )
            or any(item <= 0 for item in self.probability_numerators)
            or sum(self.probability_numerators) != self.probability_denominator
            or self.practical_equivalence_margin_numerator
            > self.practical_equivalence_margin_denominator
            or self.minimum_direction_consistent_realizations > len(self.realization_spec_ids)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class RealizationRobustnessPlanV2(_ContentAddressedInferenceV2):
    """One cross-hypothesis global robustness family and its hard label rules."""

    _id_field = "robustness_plan_id"
    _id_prefix = "realization_robustness_plan_"

    robustness_plan_id: str = Field(pattern=_ROBUSTNESS_PLAN_PATTERN)
    hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...] = Field(
        min_length=1, max_length=1_000
    )
    simultaneous_inference_plan: SimultaneousInferencePlanV2
    primary_inference_plan_id: str = Field(pattern=_PLAN_PATTERN)
    primary_family_id: str = Field(pattern=_FAMILY_PATTERN)
    primary_result_required: Literal[True]
    interaction_statistic_method: Literal["max_abs_realization_minus_qh_policy_v1"]
    interaction_reference_method: Literal["semantic_cluster_arm_randomization_v1"]
    interaction_minimum_reference_draws: StrictInt = Field(
        ge=FORMAL_MIN_BOOTSTRAP_SAMPLES_V2, le=100_000
    )
    all_conditions_required_for_label: Literal[True]
    full_global_multiplicity_family_required: Literal[True]
    frozen_before_outcomes: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...],
        simultaneous_inference_plan: SimultaneousInferencePlanV2,
        primary_inference_plan_id: str,
        primary_family_id: str,
        interaction_minimum_reference_draws: int,
    ) -> Self:
        return cls.from_content(
            hypotheses=hypotheses,
            simultaneous_inference_plan=simultaneous_inference_plan,
            primary_inference_plan_id=primary_inference_plan_id,
            primary_family_id=primary_family_id,
            primary_result_required=True,
            interaction_statistic_method="max_abs_realization_minus_qh_policy_v1",
            interaction_reference_method="semantic_cluster_arm_randomization_v1",
            interaction_minimum_reference_draws=interaction_minimum_reference_draws,
            all_conditions_required_for_label=True,
            full_global_multiplicity_family_required=True,
            frozen_before_outcomes=True,
        )

    @model_validator(mode="after")
    def validate_robustness_plan(self) -> Self:
        hypothesis_order = tuple(item.robustness_hypothesis_spec_id for item in self.hypotheses)
        hypothesis_keys = tuple((item.hypothesis_id, item.model_id) for item in self.hypotheses)
        inference = self.simultaneous_inference_plan
        actual: set[tuple[object, ...]] = set()
        for coordinate in inference.family.coordinates:
            actual.add(
                (
                    coordinate.hypothesis_id,
                    coordinate.target_spec_id,
                    coordinate.arm_protocol_id,
                    coordinate.model_id,
                    coordinate.outcome_name,
                    coordinate.treatment_arm,
                    coordinate.control_arm,
                    coordinate.coordinate_kind,
                    coordinate.analysis_component_id,
                )
            )
        expected: set[tuple[object, ...]] = set()
        for item in self.hypotheses:
            base = (
                item.hypothesis_id,
                item.target_spec_id,
                item.arm_protocol_id,
                item.model_id,
                item.outcome_name,
                item.treatment_arm,
                item.control_arm,
            )
            expected.add((*base, SimultaneousCoordinateKindV2.POLICY_EFFECT, "pooled"))
            for realization_id in item.realization_spec_ids:
                expected.add(
                    (
                        *base,
                        SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                        f"realization.{realization_id}",
                    )
                )
                expected.add(
                    (
                        *base,
                        SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                        f"loo.{realization_id}",
                    )
                )
                expected.add(
                    (
                        *base,
                        SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                        f"deviation.{realization_id}",
                    )
                )
        if (
            hypothesis_order != tuple(sorted(hypothesis_order))
            or len(hypothesis_keys) != len(set(hypothesis_keys))
            or inference.family.family_kind is not SimultaneousFamilyKindV2.REALIZATION_ROBUSTNESS
            or actual != expected
            or len(actual) != len(inference.family.coordinates)
            or any(
                inference.minimum_independent_clusters
                < item.minimum_independent_clusters_per_realization
                for item in self.hypotheses
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "FORMAL_MIN_BOOTSTRAP_SAMPLES_V2",
    "FORMAL_MIN_VALID_BOOTSTRAP_DRAWS_V2",
    "INFERENCE_V2_SCHEMA_VERSION",
    "CommonStratumSupportV2",
    "RealizationRobustnessHypothesisSpecV2",
    "RealizationRobustnessPlanV2",
    "RobustnessExpectedDirectionV2",
    "SimultaneousCoordinateKindV2",
    "SimultaneousFamilyKindV2",
    "SimultaneousFamilyManifestV2",
    "SimultaneousInferencePlanV2",
    "SimultaneousTestCoordinateV2",
]

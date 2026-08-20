"""Prospective coordinate-specific realization and model robustness contracts.

The formal experiment freezes the policy distribution :math:`Q_h`, but it does
not choose a practical-equivalence margin or a cross-model evidence rule.  This
module therefore adds a separate content-addressed, pre-outcome policy root.
It preserves every hypothesis' own population and expands the complete frozen
``H x M`` universe into realization, leave-one-realization-out, and deviation
coordinates without taking a common-support intersection.

The policy is intentionally standalone until the formal-analysis root embeds
its identifier.  That migration boundary is recorded in the artifact rather
than silently treating a post-hoc robustness configuration as confirmatory.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.inference_v2 import (
    RealizationRobustnessHypothesisSpecV2,
    RobustnessExpectedDirectionV2,
    SimultaneousCoordinateKindV2,
    SimultaneousFamilyKindV2,
    SimultaneousFamilyManifestV2,
    SimultaneousTestCoordinateV2,
)
from secaware.schema.multi_support_inference_v2 import (
    MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2,
    MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2,
    CoordinateSpecificSupportV2,
    GlobalUnionStratumV2,
    MultiSupportFormalFamilyV2,
    MultiSupportSimultaneousInferencePlanV2,
    _expected_global_union,
)
from secaware.schema.policy_v2 import ExpectedDirection, FrozenPolicyHypothesisRecord

MULTI_SUPPORT_ROBUSTNESS_V2_SCHEMA_VERSION = "2.0"
MULTI_SUPPORT_ROBUSTNESS_BOOTSTRAP_SAMPLES_V2 = 999
MULTI_SUPPORT_ROBUSTNESS_MINIMUM_VALID_DRAWS_V2 = 950
MULTI_SUPPORT_INTERACTION_REFERENCE_DRAWS_V2 = 999

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_DECISION_PATTERN = r"^multi_support_robustness_decision_v2_[0-9a-f]{64}$"
_REPLICATION_POLICY_PATTERN = r"^cross_model_replication_policy_v2_[0-9a-f]{64}$"
_POLICY_FREEZE_PATTERN = r"^multi_support_robustness_policy_v2_[0-9a-f]{64}$"
_INTERACTION_REFERENCE_PATTERN = r"^multi_support_interaction_reference_v2_[0-9a-f]{64}$"
_CLOSED_COVERAGE_PATTERN = r"^provenance_closed_coverage_v2_[0-9a-f]{64}$"
_RANDOMIZATION_PATTERN = r"^randomization_manifest_v2_[0-9a-f]{64}$"


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


class _RobustnessV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = (
        "multi-support robustness v2 contract failed validation"
    )

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = MULTI_SUPPORT_ROBUSTNESS_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedRobustnessV2(_RobustnessV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {
                "schema_version": MULTI_SUPPORT_ROBUSTNESS_V2_SCHEMA_VERSION,
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


def _robustness_direction(
    direction: ExpectedDirection,
) -> RobustnessExpectedDirectionV2:
    return (
        RobustnessExpectedDirectionV2.POSITIVE
        if direction is ExpectedDirection.POSITIVE
        else RobustnessExpectedDirectionV2.NEGATIVE
    )


class HypothesisRobustnessDecisionV2(_ContentAddressedRobustnessV2):
    """All non-identifiable robustness choices for one frozen hypothesis."""

    _id_field = "hypothesis_robustness_decision_id"
    _id_prefix = "multi_support_robustness_decision_v2_"

    hypothesis_robustness_decision_id: str = Field(pattern=_DECISION_PATTERN)
    hypothesis_id: str
    expected_direction: RobustnessExpectedDirectionV2
    realization_spec_ids: tuple[str, ...] = Field(min_length=2, max_length=32)
    probability_numerators: tuple[StrictInt, ...] = Field(min_length=2, max_length=32)
    probability_denominator: StrictInt = Field(ge=2, le=2**31 - 1)
    practical_equivalence_margin_numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    practical_equivalence_margin_denominator: StrictInt = Field(ge=1, le=2**31 - 1)
    minimum_direction_consistent_realizations: StrictInt = Field(ge=2, le=32)
    minimum_independent_clusters_per_realization: StrictInt = Field(ge=2, le=100_000)
    interaction_minimum_reference_draws: Literal[999]
    direction_consistency_rule: Literal["all_frozen_realizations_must_match_v1"]
    deviation_equivalence_rule: Literal[
        "simultaneous_max_abs_realization_minus_qh_upper_le_delta_h_v1"
    ]
    leave_one_out_rule: Literal["every_loo_interval_excludes_zero_expected_direction_v1"]
    interaction_rule: Literal[
        "complete_h_by_m_semantic_cluster_randomization_reference_reported_v1"
    ]
    all_conditions_required_for_realization_robust_label: Literal[True]

    @classmethod
    def from_hypothesis(
        cls,
        hypothesis: FrozenPolicyHypothesisRecord,
        *,
        practical_equivalence_margin_numerator: int,
        practical_equivalence_margin_denominator: int,
        minimum_direction_consistent_realizations: int,
        minimum_independent_clusters_per_realization: int,
        interaction_minimum_reference_draws: int,
    ) -> Self:
        """Freeze explicit decisions; no default ``delta_h`` is invented."""

        try:
            checked = FrozenPolicyHypothesisRecord.model_validate(hypothesis, strict=True)
            return cls.from_content(
                hypothesis_id=checked.hypothesis_id,
                expected_direction=_robustness_direction(checked.expected_direction),
                realization_spec_ids=checked.realization_spec_ids,
                probability_numerators=checked.probability_numerators,
                probability_denominator=checked.probability_denominator,
                practical_equivalence_margin_numerator=(practical_equivalence_margin_numerator),
                practical_equivalence_margin_denominator=(practical_equivalence_margin_denominator),
                minimum_direction_consistent_realizations=(
                    minimum_direction_consistent_realizations
                ),
                minimum_independent_clusters_per_realization=(
                    minimum_independent_clusters_per_realization
                ),
                interaction_minimum_reference_draws=(interaction_minimum_reference_draws),
                direction_consistency_rule="all_frozen_realizations_must_match_v1",
                deviation_equivalence_rule=(
                    "simultaneous_max_abs_realization_minus_qh_upper_le_delta_h_v1"
                ),
                leave_one_out_rule=("every_loo_interval_excludes_zero_expected_direction_v1"),
                interaction_rule=(
                    "complete_h_by_m_semantic_cluster_randomization_reference_reported_v1"
                ),
                all_conditions_required_for_realization_robust_label=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public freeze boundary
            raise cls._safe_error() from None

    @property
    def practical_equivalence_margin(self) -> float:
        return (
            self.practical_equivalence_margin_numerator
            / self.practical_equivalence_margin_denominator
        )

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if (
            len(self.realization_spec_ids) != len(self.probability_numerators)
            or len(self.realization_spec_ids) != len(set(self.realization_spec_ids))
            or any(
                re.fullmatch(r"^realization_spec_[0-9a-f]{64}$", item) is None
                for item in self.realization_spec_ids
            )
            or any(item <= 0 for item in self.probability_numerators)
            or sum(self.probability_numerators) != self.probability_denominator
            or self.practical_equivalence_margin_numerator
            > self.practical_equivalence_margin_denominator
            or self.minimum_direction_consistent_realizations != len(self.realization_spec_ids)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CrossModelReplicationPolicyV2(_ContentAddressedRobustnessV2):
    """Separate, non-pooled replication rule over the frozen model scope."""

    _id_field = "cross_model_replication_policy_id"
    _id_prefix = "cross_model_replication_policy_v2_"

    cross_model_replication_policy_id: str = Field(pattern=_REPLICATION_POLICY_PATTERN)
    model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    minimum_model_count_for_replication: Literal[2]
    required_confirmed_model_count: StrictInt = Field(ge=1, le=64)
    replication_rule: Literal["all_frozen_models_individually_confirm_expected_direction_v1"]
    pooling_rule: Literal["model_specific_effects_never_pooled_v1"]
    single_model_rule: Literal["not_applicable_v1"]
    any_unconfirmed_or_reverse_model_disqualifies: Literal[True]

    @classmethod
    def from_model_scope(cls, model_ids: tuple[str, ...]) -> Self:
        try:
            return cls.from_content(
                model_ids=model_ids,
                minimum_model_count_for_replication=2,
                required_confirmed_model_count=len(model_ids),
                replication_rule=("all_frozen_models_individually_confirm_expected_direction_v1"),
                pooling_rule="model_specific_effects_never_pooled_v1",
                single_model_rule="not_applicable_v1",
                any_unconfirmed_or_reverse_model_disqualifies=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public freeze boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_replication_policy(self) -> Self:
        if (
            self.model_ids != tuple(sorted(self.model_ids))
            or len(self.model_ids) != len(set(self.model_ids))
            or self.required_confirmed_model_count != len(self.model_ids)
        ):
            raise ValueError(self._safe_validation_message)
        return self


def _coordinate(
    specification: RealizationRobustnessHypothesisSpecV2,
    *,
    kind: SimultaneousCoordinateKindV2,
    realization_spec_id: str,
) -> SimultaneousTestCoordinateV2:
    prefix = {
        SimultaneousCoordinateKindV2.REALIZATION_EFFECT: "realization",
        SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT: "loo",
        SimultaneousCoordinateKindV2.REALIZATION_DEVIATION: "deviation",
    }[kind]
    return SimultaneousTestCoordinateV2.from_content(
        hypothesis_id=specification.hypothesis_id,
        target_spec_id=specification.target_spec_id,
        arm_protocol_id=specification.arm_protocol_id,
        model_id=specification.model_id,
        outcome_name=specification.outcome_name,
        treatment_arm=specification.treatment_arm,
        control_arm=specification.control_arm,
        coordinate_kind=kind,
        analysis_component_id=f"{prefix}.{realization_spec_id}",
    )


def _expected_specifications(
    experiment: ConfirmatoryExperimentFreezeV2,
    decisions: tuple[HypothesisRobustnessDecisionV2, ...],
) -> tuple[RealizationRobustnessHypothesisSpecV2, ...]:
    decision_by_hypothesis = {item.hypothesis_id: item for item in decisions}
    roots = {
        item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
        for item in experiment.protocol_roots
    }
    result: list[RealizationRobustnessHypothesisSpecV2] = []
    for hm in experiment.hypothesis_model_coordinates:
        root = roots[hm.hypothesis_id]
        hypothesis = root.population.hypothesis
        decision = decision_by_hypothesis[hypothesis.hypothesis_id]
        treatment, control = root.intervention_bridge.arm_protocol.primary_contrast
        result.append(
            RealizationRobustnessHypothesisSpecV2.from_content(
                hypothesis_id=hypothesis.hypothesis_id,
                target_spec_id=hypothesis.target_spec_id,
                arm_protocol_id=hypothesis.arm_protocol_id,
                model_id=hm.model_id,
                outcome_name="y_secure_yield",
                treatment_arm=treatment,
                control_arm=control,
                expected_direction=decision.expected_direction,
                realization_spec_ids=hypothesis.realization_spec_ids,
                probability_numerators=hypothesis.probability_numerators,
                probability_denominator=hypothesis.probability_denominator,
                practical_equivalence_margin_numerator=(
                    decision.practical_equivalence_margin_numerator
                ),
                practical_equivalence_margin_denominator=(
                    decision.practical_equivalence_margin_denominator
                ),
                minimum_direction_consistent_realizations=(
                    decision.minimum_direction_consistent_realizations
                ),
                minimum_independent_clusters_per_realization=(
                    decision.minimum_independent_clusters_per_realization
                ),
            )
        )
    return tuple(sorted(result, key=lambda item: item.robustness_hypothesis_spec_id))


def _expected_coordinates(
    specifications: tuple[RealizationRobustnessHypothesisSpecV2, ...],
) -> tuple[SimultaneousTestCoordinateV2, ...]:
    return tuple(
        sorted(
            (
                _coordinate(
                    specification,
                    kind=kind,
                    realization_spec_id=realization_id,
                )
                for specification in specifications
                for realization_id in specification.realization_spec_ids
                for kind in (
                    SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                    SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                    SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                )
            ),
            key=lambda item: item.test_coordinate_id,
        )
    )


def _expected_supports(
    primary_plan: MultiSupportSimultaneousInferencePlanV2,
    coordinates: tuple[SimultaneousTestCoordinateV2, ...],
) -> tuple[CoordinateSpecificSupportV2, ...]:
    primary_by_hm = {
        (item.test_coordinate.hypothesis_id, item.test_coordinate.model_id): item
        for item in primary_plan.coordinate_supports
    }
    result = []
    for coordinate in coordinates:
        primary = primary_by_hm[(coordinate.hypothesis_id, coordinate.model_id)]
        result.append(
            CoordinateSpecificSupportV2.from_content(
                hypothesis_model_coordinate_id=primary.hypothesis_model_coordinate_id,
                population_freeze_manifest_id=primary.population_freeze_manifest_id,
                randomization_manifest_id=primary.randomization_manifest_id,
                execution_policy_freeze_manifest_id=(primary.execution_policy_freeze_manifest_id),
                test_coordinate=coordinate,
                strata=primary.strata,
                coordinate_cluster_count=primary.coordinate_cluster_count,
                estimand_rule=(
                    "frozen_coordinate_population_without_intersection_or_renormalization_v1"
                ),
            )
        )
    return tuple(sorted(result, key=lambda item: item.test_coordinate.test_coordinate_id))


class MultiSupportRobustnessPolicyFreezeV2(_ContentAddressedRobustnessV2):
    """Complete pre-outcome H x M x (r, LOO, deviation) policy family."""

    _id_field = "robustness_policy_freeze_id"
    _id_prefix = "multi_support_robustness_policy_v2_"

    robustness_policy_freeze_id: str = Field(pattern=_POLICY_FREEZE_PATTERN)
    confirmatory_experiment_freeze_id: str
    experiment: ConfirmatoryExperimentFreezeV2
    policy_material_sha256: str = Field(pattern=_SHA256_PATTERN)
    hypothesis_decisions: tuple[HypothesisRobustnessDecisionV2, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_model_specifications: tuple[RealizationRobustnessHypothesisSpecV2, ...] = Field(
        min_length=1, max_length=640_000
    )
    cross_model_policy: CrossModelReplicationPolicyV2
    primary_inference_plan: MultiSupportSimultaneousInferencePlanV2
    robustness_family: SimultaneousFamilyManifestV2
    coordinate_supports: tuple[CoordinateSpecificSupportV2, ...] = Field(
        min_length=6, max_length=20_000_000
    )
    global_union_strata: tuple[GlobalUnionStratumV2, ...] = Field(min_length=1, max_length=1_000)
    global_multiplicity_family_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_seed_domain_sha256: str = Field(pattern=_SHA256_PATTERN)
    alpha_numerator: Literal[1]
    alpha_denominator: Literal[20]
    bootstrap_samples: Literal[999]
    minimum_valid_bootstrap_draws: Literal[950]
    minimum_valid_fraction_numerator: Literal[19]
    minimum_valid_fraction_denominator: Literal[20]
    interaction_minimum_reference_draws: Literal[999]
    family_rule: Literal["complete_h_by_m_by_r_loo_deviation_cartesian_product_v1"]
    primary_effect_rule: Literal["reuse_frozen_primary_secure_yield_multi_support_family_v1"]
    realization_contribution_rule: Literal[
        "derive_only_from_provenance_closed_confirmatory_contributions_v2"
    ]
    resampling_method: Literal["global_union_stratified_semantic_cluster_ratio_bootstrap_v1"]
    cluster_coupling_rule: Literal[
        "one_union_draw_shared_then_filtered_by_frozen_coordinate_support_v1"
    ]
    support_rule: Literal["coordinate_specific_no_common_intersection_no_estimand_change_v1"]
    studentization_method: Literal["coordinate_specific_cluster_se_v1"]
    centering_method: Literal["bootstrap_minus_observed_v1"]
    quantile_rule: Literal["empirical_higher_v1"]
    interval_rule: Literal["two_sided_studentized_global_max_abs_t_v1"]
    invalid_draw_policy: Literal["retain_reason_and_fail_below_frozen_fraction_v2"]
    formal_analysis_glue_binding_required: Literal[True]
    formal_analysis_glue_binding_status: Literal[
        "standalone_phase0_not_yet_embedded_in_formal_analysis_protocol_v1"
    ]
    frozen_before_outcomes: Literal[True]

    @classmethod
    def from_experiment(
        cls,
        *,
        experiment: ConfirmatoryExperimentFreezeV2,
        hypothesis_decisions: tuple[HypothesisRobustnessDecisionV2, ...],
        cross_model_policy: CrossModelReplicationPolicyV2,
        robustness_policy_material: bytes,
    ) -> Self:
        """Freeze explicit decisions without inferring ``delta_h`` from outcomes."""

        try:
            checked_experiment = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            decisions = tuple(
                sorted(
                    (
                        HypothesisRobustnessDecisionV2.model_validate(item, strict=True)
                        for item in hypothesis_decisions
                    ),
                    key=lambda item: item.hypothesis_id,
                )
            )
            replication = CrossModelReplicationPolicyV2.model_validate(
                cross_model_policy,
                strict=True,
            )
            if type(robustness_policy_material) is not bytes or not robustness_policy_material:
                raise ValueError
            primary = MultiSupportSimultaneousInferencePlanV2.from_frozen_formal_family(
                experiment=checked_experiment,
                formal_family=MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
            )
            specifications = _expected_specifications(checked_experiment, decisions)
            coordinates = _expected_coordinates(specifications)
            family = SimultaneousFamilyManifestV2.from_content(
                family_label="global-realization-robustness-h-by-m-by-r",
                family_kind=SimultaneousFamilyKindV2.REALIZATION_ROBUSTNESS,
                coordinates=coordinates,
                family_size=len(coordinates),
                frozen_before_outcomes=True,
            )
            supports = _expected_supports(primary, coordinates)
            return cls.from_content(
                confirmatory_experiment_freeze_id=(
                    checked_experiment.confirmatory_experiment_freeze_id
                ),
                experiment=checked_experiment,
                policy_material_sha256=hashlib.sha256(robustness_policy_material).hexdigest(),
                hypothesis_decisions=decisions,
                hypothesis_model_specifications=specifications,
                cross_model_policy=replication,
                primary_inference_plan=primary,
                robustness_family=family,
                coordinate_supports=supports,
                global_union_strata=_expected_global_union(supports),
                global_multiplicity_family_policy_sha256=(
                    checked_experiment.global_multiplicity_family_policy_sha256
                ),
                analysis_seed_domain_sha256=checked_experiment.analysis_seed_domain_sha256,
                alpha_numerator=1,
                alpha_denominator=20,
                bootstrap_samples=MULTI_SUPPORT_ROBUSTNESS_BOOTSTRAP_SAMPLES_V2,
                minimum_valid_bootstrap_draws=(MULTI_SUPPORT_ROBUSTNESS_MINIMUM_VALID_DRAWS_V2),
                minimum_valid_fraction_numerator=(MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2),
                minimum_valid_fraction_denominator=(
                    MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                ),
                interaction_minimum_reference_draws=(MULTI_SUPPORT_INTERACTION_REFERENCE_DRAWS_V2),
                family_rule="complete_h_by_m_by_r_loo_deviation_cartesian_product_v1",
                primary_effect_rule=("reuse_frozen_primary_secure_yield_multi_support_family_v1"),
                realization_contribution_rule=(
                    "derive_only_from_provenance_closed_confirmatory_contributions_v2"
                ),
                resampling_method=("global_union_stratified_semantic_cluster_ratio_bootstrap_v1"),
                cluster_coupling_rule=(
                    "one_union_draw_shared_then_filtered_by_frozen_coordinate_support_v1"
                ),
                support_rule="coordinate_specific_no_common_intersection_no_estimand_change_v1",
                studentization_method="coordinate_specific_cluster_se_v1",
                centering_method="bootstrap_minus_observed_v1",
                quantile_rule="empirical_higher_v1",
                interval_rule="two_sided_studentized_global_max_abs_t_v1",
                invalid_draw_policy="retain_reason_and_fail_below_frozen_fraction_v2",
                formal_analysis_glue_binding_required=True,
                formal_analysis_glue_binding_status=(
                    "standalone_phase0_not_yet_embedded_in_formal_analysis_protocol_v1"
                ),
                frozen_before_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public freeze boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_policy_freeze(self) -> Self:
        expected_hypotheses = self.experiment.hypothesis_ids
        decisions = tuple(sorted(self.hypothesis_decisions, key=lambda item: item.hypothesis_id))
        primary = MultiSupportSimultaneousInferencePlanV2.from_frozen_formal_family(
            experiment=self.experiment,
            formal_family=MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
        )
        specifications = _expected_specifications(self.experiment, decisions)
        coordinates = _expected_coordinates(specifications)
        family = SimultaneousFamilyManifestV2.from_content(
            family_label="global-realization-robustness-h-by-m-by-r",
            family_kind=SimultaneousFamilyKindV2.REALIZATION_ROBUSTNESS,
            coordinates=coordinates,
            family_size=len(coordinates),
            frozen_before_outcomes=True,
        )
        supports = _expected_supports(primary, coordinates)
        decision_by_hypothesis = {item.hypothesis_id: item for item in decisions}
        hypothesis_by_id = {
            item.intervention_bridge.frozen_hypothesis.hypothesis_id: item.intervention_bridge.frozen_hypothesis
            for item in self.experiment.protocol_roots
        }
        support_count_by_hm = {
            (
                item.test_coordinate.hypothesis_id,
                item.test_coordinate.model_id,
            ): item.coordinate_cluster_count
            for item in primary.coordinate_supports
        }
        if (
            self.confirmatory_experiment_freeze_id
            != self.experiment.confirmatory_experiment_freeze_id
            or tuple(item.hypothesis_id for item in decisions) != expected_hypotheses
            or len(decision_by_hypothesis) != len(decisions)
            or any(
                decision.expected_direction
                != _robustness_direction(
                    hypothesis_by_id[decision.hypothesis_id].expected_direction
                )
                or decision.realization_spec_ids
                != hypothesis_by_id[decision.hypothesis_id].realization_spec_ids
                or decision.probability_numerators
                != hypothesis_by_id[decision.hypothesis_id].probability_numerators
                or decision.probability_denominator
                != hypothesis_by_id[decision.hypothesis_id].probability_denominator
                for decision in decisions
            )
            or self.cross_model_policy.model_ids != self.experiment.model_ids
            or self.primary_inference_plan != primary
            or self.hypothesis_model_specifications != specifications
            or self.robustness_family != family
            or self.coordinate_supports != supports
            or self.global_union_strata != _expected_global_union(supports)
            or self.global_multiplicity_family_policy_sha256
            != self.experiment.global_multiplicity_family_policy_sha256
            or self.analysis_seed_domain_sha256 != self.experiment.analysis_seed_domain_sha256
            or self.minimum_valid_bootstrap_draws
            != (
                self.bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
                + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                - 1
            )
            // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
            or any(
                support_count_by_hm[(item.hypothesis_id, item.model_id)]
                < item.minimum_independent_clusters_per_realization
                for item in specifications
            )
            or any(
                item.interaction_minimum_reference_draws != self.interaction_minimum_reference_draws
                for item in decisions
            )
            or len(self.coordinate_supports)
            != sum(
                3 * len(item.realization_spec_ids) for item in self.hypothesis_model_specifications
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class MultiSupportArmRealizationInteractionReferenceV2(_ContentAddressedRobustnessV2):
    """One outcome-derived interaction reference with coordinate provenance."""

    _id_field = "interaction_reference_id"
    _id_prefix = "multi_support_interaction_reference_v2_"

    interaction_reference_id: str = Field(pattern=_INTERACTION_REFERENCE_PATTERN)
    robustness_policy_freeze_id: str = Field(pattern=_POLICY_FREEZE_PATTERN)
    robustness_hypothesis_spec_id: str
    global_robustness_family_id: str
    confirmatory_experiment_freeze_id: str
    hypothesis_id: str
    model_id: str
    population_freeze_manifest_id: str
    randomization_manifest_id: str = Field(pattern=_RANDOMIZATION_PATTERN)
    provenance_closed_coverage_manifest_id: str = Field(pattern=_CLOSED_COVERAGE_PATTERN)
    interaction_statistic_method: Literal["max_abs_realization_minus_qh_policy_v1"]
    reference_method: Literal["semantic_cluster_arm_randomization_v1"]
    joint_reference_run_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_statistic: float
    reference_statistics: tuple[float, ...] = Field(min_length=999, max_length=999)

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if (
            not math.isfinite(self.observed_statistic)
            or self.observed_statistic < 0.0
            or any(not math.isfinite(item) or item < 0.0 for item in self.reference_statistics)
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "MULTI_SUPPORT_INTERACTION_REFERENCE_DRAWS_V2",
    "MULTI_SUPPORT_ROBUSTNESS_BOOTSTRAP_SAMPLES_V2",
    "MULTI_SUPPORT_ROBUSTNESS_MINIMUM_VALID_DRAWS_V2",
    "MULTI_SUPPORT_ROBUSTNESS_V2_SCHEMA_VERSION",
    "CrossModelReplicationPolicyV2",
    "HypothesisRobustnessDecisionV2",
    "MultiSupportArmRealizationInteractionReferenceV2",
    "MultiSupportRobustnessPolicyFreezeV2",
]

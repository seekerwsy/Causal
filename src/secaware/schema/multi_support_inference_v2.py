"""Prospective global max-|T| contracts for coordinate-specific populations.

The older :mod:`secaware.schema.inference_v2` contract intentionally supports
only a common cluster support.  This module is the separately versioned formal
contract for the actual confirmatory design: every hypothesis/model coordinate
keeps its own frozen eligible population and estimand, while resampling is
coupled through the union of semantic task clusters.
"""

from __future__ import annotations

from enum import StrEnum
from fractions import Fraction
from typing import ClassVar, Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from secaware.randomness import RNG_VERSION
from secaware.records import (
    SnapshotContentAddressedResearchRecord,
    SnapshotResearchRecord,
    record_sha256 as _digest,
    valid_identifier as _valid_identifier,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.experiments import ArmRole
from secaware.schema.inference_v2 import (
    FORMAL_MIN_BOOTSTRAP_SAMPLES_V2,
    SimultaneousCoordinateKindV2,
    SimultaneousFamilyKindV2,
    SimultaneousFamilyManifestV2,
    SimultaneousTestCoordinateV2,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2

MULTI_SUPPORT_INFERENCE_V2_SCHEMA_VERSION = "2.1"
MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2 = 19
MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2 = 20

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PLAN_PATTERN = r"^multi_support_simultaneous_plan_v2_[0-9a-f]{64}$"
_SUPPORT_PATTERN = r"^multi_support_coordinate_v2_[0-9a-f]{64}$"

# These identity capabilities separate a fully checked public constructor from
# the formal orchestrator's two-root context.  They are an internal API guard,
# not a Python sandbox: callers cannot select a fast path with a boolean or pass
# an arbitrary object that merely looks prevalidated.
_CHECKED_FORMAL_PLAN_ACCESS = object()
_FORMAL_CONTEXT_PLAN_ACCESS = object()


class _MultiSupportInferenceV2Contract(SnapshotResearchRecord):
    _safe_validation_message: ClassVar[str] = (
        "multi-support simultaneous inference v2 contract failed validation"
    )

    schema_version: Literal["2.1"] = MULTI_SUPPORT_INFERENCE_V2_SCHEMA_VERSION


class _ContentAddressedMultiSupportInferenceV2(SnapshotContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = (
        "multi-support simultaneous inference v2 contract failed validation"
    )
    _schema_version = MULTI_SUPPORT_INFERENCE_V2_SCHEMA_VERSION
    schema_version: Literal["2.1"] = MULTI_SUPPORT_INFERENCE_V2_SCHEMA_VERSION


class CoordinateSpecificStratumSupportV2(_MultiSupportInferenceV2Contract):
    """One coordinate's exact frozen support and weights in one stratum."""

    stratum_id: str
    semantic_task_cluster_ids: tuple[str, ...] = Field(min_length=2, max_length=100_000)
    cluster_weight_numerators: tuple[StrictInt, ...] = Field(min_length=2, max_length=100_000)
    cluster_weight_denominator: StrictInt = Field(ge=2, le=2**31 - 1)
    stratum_weight_numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    stratum_weight_denominator: StrictInt = Field(ge=1, le=2**31 - 1)

    @property
    def stratum_weight(self) -> Fraction:
        return Fraction(self.stratum_weight_numerator, self.stratum_weight_denominator)

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        cluster_ids = self.semantic_task_cluster_ids
        numerators = self.cluster_weight_numerators
        if (
            not _valid_identifier(self.stratum_id)
            or cluster_ids != tuple(sorted(cluster_ids))
            or len(cluster_ids) != len(set(cluster_ids))
            or any(not _valid_identifier(item) for item in cluster_ids)
            or len(numerators) != len(cluster_ids)
            or any(item <= 0 for item in numerators)
            or sum(numerators) != self.cluster_weight_denominator
            or any(
                Fraction(item, self.cluster_weight_denominator) != Fraction(1, len(cluster_ids))
                for item in numerators
            )
            or self.stratum_weight_numerator > self.stratum_weight_denominator
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CoordinateSpecificSupportV2(_ContentAddressedMultiSupportInferenceV2):
    """Exact estimand support for one member of the frozen H x M universe."""

    _id_field = "coordinate_support_id"
    _id_prefix = "multi_support_coordinate_v2_"

    coordinate_support_id: str = Field(pattern=_SUPPORT_PATTERN)
    hypothesis_model_coordinate_id: str
    population_freeze_manifest_id: str
    randomization_manifest_id: str
    execution_policy_freeze_manifest_id: str
    test_coordinate: SimultaneousTestCoordinateV2
    strata: tuple[CoordinateSpecificStratumSupportV2, ...] = Field(min_length=1, max_length=1_000)
    coordinate_cluster_count: StrictInt = Field(ge=2, le=100_000)
    estimand_rule: Literal[
        "frozen_coordinate_population_without_intersection_or_renormalization_v1"
    ]

    @model_validator(mode="after")
    def validate_coordinate_support(self) -> Self:
        stratum_ids = tuple(item.stratum_id for item in self.strata)
        clusters = tuple(
            cluster_id
            for stratum in self.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        )
        if (
            not _valid_identifier(self.hypothesis_model_coordinate_id)
            or not _valid_identifier(self.population_freeze_manifest_id)
            or not _valid_identifier(self.randomization_manifest_id)
            or not _valid_identifier(self.execution_policy_freeze_manifest_id)
            or stratum_ids != tuple(sorted(stratum_ids))
            or len(stratum_ids) != len(set(stratum_ids))
            or len(clusters) != len(set(clusters))
            or self.coordinate_cluster_count != len(clusters)
            or sum((item.stratum_weight for item in self.strata), Fraction(0, 1)) != Fraction(1, 1)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class GlobalUnionStratumV2(_MultiSupportInferenceV2Contract):
    """Union support drawn once per replicate and shared by all coordinates."""

    stratum_id: str
    semantic_task_cluster_ids: tuple[str, ...] = Field(min_length=2, max_length=100_000)
    union_cluster_count: StrictInt = Field(ge=2, le=100_000)

    @model_validator(mode="after")
    def validate_union(self) -> Self:
        if (
            not _valid_identifier(self.stratum_id)
            or self.semantic_task_cluster_ids != tuple(sorted(self.semantic_task_cluster_ids))
            or len(self.semantic_task_cluster_ids) != len(set(self.semantic_task_cluster_ids))
            or any(not _valid_identifier(item) for item in self.semantic_task_cluster_ids)
            or self.union_cluster_count != len(self.semantic_task_cluster_ids)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class MultiSupportFormalFamilyV2(StrEnum):
    PRIMARY_SECURE_YIELD = "primary_secure_yield"
    KEY_JOINT = "key_joint"
    SPECIFICITY_PLACEBO = "specificity_placebo"
    SPECIFICITY_GENERIC = "specificity_generic"


def _family_metadata(
    family: MultiSupportFormalFamilyV2,
) -> tuple[
    str,
    SimultaneousFamilyKindV2,
    str,
    Literal["primary", "specificity_placebo", "specificity_generic"],
    str,
    str,
]:
    if family is MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD:
        return (
            "global-primary-secure-yield-h-by-m",
            SimultaneousFamilyKindV2.PRIMARY_SECURE_YIELD,
            "y_secure_yield",
            "primary",
            "primary_secure_yield_only_v1",
            "frozen_primary_target_vs_noop_v1",
        )
    if family is MultiSupportFormalFamilyV2.KEY_JOINT:
        return (
            "global-key-joint-h-by-m",
            SimultaneousFamilyKindV2.JOINT_OUTCOME,
            "y_joint",
            "primary",
            "formal_key_joint_v1",
            "frozen_primary_target_vs_noop_v1",
        )
    if family is MultiSupportFormalFamilyV2.SPECIFICITY_PLACEBO:
        return (
            "global-target-vs-placebo-h-by-m",
            SimultaneousFamilyKindV2.TARGET_SPECIFICITY,
            "y_secure_yield",
            "specificity_placebo",
            "formal_specificity_secure_yield_v1",
            "frozen_target_vs_placebo_v1",
        )
    return (
        "global-target-vs-generic-h-by-m",
        SimultaneousFamilyKindV2.TARGET_SPECIFICITY,
        "y_secure_yield",
        "specificity_generic",
        "formal_specificity_secure_yield_v1",
        "frozen_target_vs_generic_v1",
    )


def _contrast_for_family(
    root: ProtocolFreezeRootV2,
    contrast_selector: Literal["primary", "specificity_placebo", "specificity_generic"],
) -> tuple[ArmRole, ArmRole]:
    protocol = root.intervention_bridge.arm_protocol
    if contrast_selector == "primary":
        return protocol.primary_contrast
    if contrast_selector == "specificity_placebo":
        return protocol.specificity_contrasts[0]
    return protocol.specificity_contrasts[1]


def _expected_coordinate_supports(
    experiment: ConfirmatoryExperimentFreezeV2,
    formal_family: MultiSupportFormalFamilyV2,
) -> tuple[CoordinateSpecificSupportV2, ...]:
    (
        _family_label,
        _family_kind,
        outcome_name,
        contrast_selector,
        _outcome_rule,
        _contrast_rule,
    ) = _family_metadata(formal_family)
    roots = {
        item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
        for item in experiment.protocol_roots
    }
    executions = {
        item.randomization.population.hypothesis.hypothesis_id: item
        for item in experiment.execution_policy_freezes
    }
    result: list[CoordinateSpecificSupportV2] = []
    for hm_coordinate in experiment.hypothesis_model_coordinates:
        root = roots[hm_coordinate.hypothesis_id]
        execution = executions[hm_coordinate.hypothesis_id]
        population = root.population
        hypothesis = population.hypothesis
        if hypothesis.outcome_id != "y_secure_yield":
            raise ValueError("primary global family requires y_secure_yield")
        treatment, control = _contrast_for_family(root, contrast_selector)
        coordinate = SimultaneousTestCoordinateV2.from_content(
            hypothesis_id=hypothesis.hypothesis_id,
            target_spec_id=hypothesis.target_spec_id,
            arm_protocol_id=hypothesis.arm_protocol_id,
            model_id=hm_coordinate.model_id,
            outcome_name=outcome_name,
            treatment_arm=treatment,
            control_arm=control,
            coordinate_kind=SimultaneousCoordinateKindV2.POLICY_EFFECT,
            analysis_component_id="pooled",
        )
        # PopulationFreezeManifestV2 currently freezes exactly one inferential
        # stratum.  Keep the representation general, but never invent weights:
        # the sole frozen stratum consequently has exact weight one.
        if len(population.strata) != 1:
            raise ValueError("coordinate population has no frozen cross-stratum weights")
        strata = tuple(
            CoordinateSpecificStratumSupportV2(
                stratum_id=stratum.stratum_id,
                semantic_task_cluster_ids=tuple(
                    item.semantic_task_cluster_id for item in stratum.cluster_weights
                ),
                cluster_weight_numerators=tuple(
                    item.weight.numerator for item in stratum.cluster_weights
                ),
                cluster_weight_denominator=stratum.cluster_weights[0].weight.denominator,
                stratum_weight_numerator=1,
                stratum_weight_denominator=1,
            )
            for stratum in population.strata
        )
        result.append(
            CoordinateSpecificSupportV2.from_content(
                hypothesis_model_coordinate_id=(hm_coordinate.hypothesis_model_coordinate_id),
                population_freeze_manifest_id=population.population_freeze_manifest_id,
                randomization_manifest_id=execution.randomization.randomization_manifest_id,
                execution_policy_freeze_manifest_id=(execution.execution_policy_freeze_manifest_id),
                test_coordinate=coordinate,
                strata=strata,
                coordinate_cluster_count=sum(
                    len(item.semantic_task_cluster_ids) for item in strata
                ),
                estimand_rule=(
                    "frozen_coordinate_population_without_intersection_or_renormalization_v1"
                ),
            )
        )
    return tuple(sorted(result, key=lambda item: item.test_coordinate.test_coordinate_id))


def _expected_global_union(
    supports: tuple[CoordinateSpecificSupportV2, ...],
) -> tuple[GlobalUnionStratumV2, ...]:
    by_stratum: dict[str, set[str]] = {}
    cluster_stratum: dict[str, str] = {}
    for support in supports:
        for stratum in support.strata:
            by_stratum.setdefault(stratum.stratum_id, set()).update(
                stratum.semantic_task_cluster_ids
            )
            for cluster_id in stratum.semantic_task_cluster_ids:
                prior = cluster_stratum.setdefault(cluster_id, stratum.stratum_id)
                if prior != stratum.stratum_id:
                    raise ValueError("semantic cluster belongs to multiple global strata")
    return tuple(
        GlobalUnionStratumV2(
            stratum_id=stratum_id,
            semantic_task_cluster_ids=tuple(sorted(cluster_ids)),
            union_cluster_count=len(cluster_ids),
        )
        for stratum_id, cluster_ids in sorted(by_stratum.items())
    )


class MultiSupportSimultaneousInferencePlanV2(_ContentAddressedMultiSupportInferenceV2):
    """Pre-outcome global H x M max-|T| plan with coordinate-specific support."""

    _id_field = "inference_plan_id"
    _id_prefix = "multi_support_simultaneous_plan_v2_"

    inference_plan_id: str = Field(pattern=_PLAN_PATTERN)
    confirmatory_experiment_freeze_id: str
    experiment: ConfirmatoryExperimentFreezeV2
    global_multiplicity_family_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_seed_domain_sha256: str = Field(pattern=_SHA256_PATTERN)
    formal_family: MultiSupportFormalFamilyV2
    family: SimultaneousFamilyManifestV2
    coordinate_supports: tuple[CoordinateSpecificSupportV2, ...] = Field(
        min_length=1, max_length=640_000
    )
    global_union_strata: tuple[GlobalUnionStratumV2, ...] = Field(min_length=1, max_length=1_000)
    alpha_numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    alpha_denominator: StrictInt = Field(ge=2, le=2**31 - 1)
    bootstrap_samples: StrictInt = Field(ge=FORMAL_MIN_BOOTSTRAP_SAMPLES_V2, le=100_000)
    minimum_valid_bootstrap_draws: StrictInt = Field(ge=1, le=100_000)
    minimum_valid_fraction_numerator: Literal[19]
    minimum_valid_fraction_denominator: Literal[20]
    minimum_independent_clusters_per_coordinate: StrictInt = Field(ge=2, le=100_000)
    rng_version: Literal["sha256-rejection-fisher-yates-v1"] = RNG_VERSION
    family_rule: Literal["complete_protocolized_hypothesis_by_frozen_model_cartesian_product_v1"]
    outcome_rule: Literal[
        "primary_secure_yield_only_v1",
        "formal_key_joint_v1",
        "formal_specificity_secure_yield_v1",
    ]
    contrast_rule: Literal[
        "frozen_primary_target_vs_noop_v1",
        "frozen_target_vs_placebo_v1",
        "frozen_target_vs_generic_v1",
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
    seed_derivation_rule: Literal[
        "sha256_domain_material_plus_content_addressed_plan_id_v1",
        "sha256_frozen_domain_digest_plus_content_addressed_plan_id_v1",
    ]
    complete_hypothesis_model_family_required: Literal[True]
    frozen_before_outcomes: Literal[True]

    @field_validator("formal_family", mode="before")
    @classmethod
    def parse_formal_family(cls, value: object) -> object:
        if type(value) is MultiSupportFormalFamilyV2:
            return value
        if type(value) is str:
            return next(
                (item for item in MultiSupportFormalFamilyV2 if item.value == value),
                value,
            )
        return value

    @classmethod
    def from_experiment(
        cls,
        *,
        experiment: ConfirmatoryExperimentFreezeV2,
        global_multiplicity_family_policy_material: bytes,
        analysis_seed_domain_material: bytes,
        alpha_numerator: int,
        alpha_denominator: int,
        bootstrap_samples: int,
        minimum_independent_clusters_per_coordinate: int,
    ) -> Self:
        try:
            checked = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            if (
                type(global_multiplicity_family_policy_material) is not bytes
                or not global_multiplicity_family_policy_material
                or hashlib.sha256(global_multiplicity_family_policy_material).hexdigest()
                != checked.global_multiplicity_family_policy_sha256
                or type(analysis_seed_domain_material) is not bytes
                or not analysis_seed_domain_material
                or hashlib.sha256(analysis_seed_domain_material).hexdigest()
                != checked.analysis_seed_domain_sha256
            ):
                raise ValueError
            formal_family = MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
            supports = _expected_coordinate_supports(checked, formal_family)
            coordinates = tuple(item.test_coordinate for item in supports)
            (
                family_label,
                family_kind,
                _outcome_name,
                _contrast_selector,
                outcome_rule,
                contrast_rule,
            ) = _family_metadata(formal_family)
            family = SimultaneousFamilyManifestV2.from_content(
                family_label=family_label,
                family_kind=family_kind,
                coordinates=coordinates,
                family_size=len(coordinates),
                frozen_before_outcomes=True,
            )
            return cls.from_content(
                confirmatory_experiment_freeze_id=(checked.confirmatory_experiment_freeze_id),
                experiment=checked,
                global_multiplicity_family_policy_sha256=(
                    checked.global_multiplicity_family_policy_sha256
                ),
                analysis_seed_domain_sha256=checked.analysis_seed_domain_sha256,
                formal_family=formal_family,
                family=family,
                coordinate_supports=supports,
                global_union_strata=_expected_global_union(supports),
                alpha_numerator=alpha_numerator,
                alpha_denominator=alpha_denominator,
                bootstrap_samples=bootstrap_samples,
                minimum_valid_bootstrap_draws=(
                    bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
                    + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                    - 1
                )
                // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2,
                minimum_valid_fraction_numerator=(MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2),
                minimum_valid_fraction_denominator=(
                    MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                ),
                minimum_independent_clusters_per_coordinate=(
                    minimum_independent_clusters_per_coordinate
                ),
                rng_version=RNG_VERSION,
                family_rule=(
                    "complete_protocolized_hypothesis_by_frozen_model_cartesian_product_v1"
                ),
                outcome_rule=outcome_rule,
                contrast_rule=contrast_rule,
                resampling_method=("global_union_stratified_semantic_cluster_ratio_bootstrap_v1"),
                cluster_coupling_rule=(
                    "one_union_draw_shared_then_filtered_by_frozen_coordinate_support_v1"
                ),
                support_rule=("coordinate_specific_no_common_intersection_no_estimand_change_v1"),
                studentization_method="coordinate_specific_cluster_se_v1",
                centering_method="bootstrap_minus_observed_v1",
                quantile_rule="empirical_higher_v1",
                interval_rule="two_sided_studentized_global_max_abs_t_v1",
                invalid_draw_policy="retain_reason_and_fail_below_frozen_fraction_v2",
                seed_derivation_rule=("sha256_domain_material_plus_content_addressed_plan_id_v1"),
                complete_hypothesis_model_family_required=True,
                frozen_before_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            raise cls._safe_error() from None

    @classmethod
    def from_frozen_formal_family(
        cls,
        *,
        experiment: ConfirmatoryExperimentFreezeV2,
        formal_family: MultiSupportFormalFamilyV2,
    ) -> Self:
        """Derive a fixed formal family using only the pre-outcome experiment root."""

        try:
            checked = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            checked_family = MultiSupportFormalFamilyV2(formal_family)
            return cls._from_checked_frozen_formal_family(
                experiment=checked,
                formal_family=checked_family,
                access=_CHECKED_FORMAL_PLAN_ACCESS,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            raise cls._safe_error() from None

    @classmethod
    def _from_formal_context(
        cls,
        *,
        context: object,
        formal_family: MultiSupportFormalFamilyV2,
    ) -> Self:
        """Derive one plan from the sealed formal two-root context only."""

        try:
            # Local import avoids a schema -> analysis import cycle at module
            # initialization while retaining an exact runtime type boundary.
            from secaware.analysis.formal_confirmation_v2 import (
                _ValidatedFormalContextV2,
            )

            if type(context) is not _ValidatedFormalContextV2:
                raise ValueError
            experiment = context._experiment_for_plan_builder(_FORMAL_CONTEXT_PLAN_ACCESS)
            return cls._from_checked_frozen_formal_family(
                experiment=experiment,
                formal_family=MultiSupportFormalFamilyV2(formal_family),
                access=_CHECKED_FORMAL_PLAN_ACCESS,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the internal context boundary
            raise cls._safe_error() from None

    @classmethod
    def _from_checked_frozen_formal_family(
        cls,
        *,
        experiment: ConfirmatoryExperimentFreezeV2,
        formal_family: MultiSupportFormalFamilyV2,
        access: object,
    ) -> Self:
        """Construct after either the public or formal-context trust boundary.

        The identity capability is supplied only by a constructor that already
        completed its relevant boundary.  Supports, coordinates, outcomes,
        contrasts, multiplicity settings, and seeds remain deterministic.
        """

        try:
            if (
                access is not _CHECKED_FORMAL_PLAN_ACCESS
                or type(experiment) is not ConfirmatoryExperimentFreezeV2
                or not model_shape_is_intact(experiment)
            ):
                raise ValueError
            checked_family = MultiSupportFormalFamilyV2(formal_family)
            supports = _expected_coordinate_supports(experiment, checked_family)
            coordinates = tuple(item.test_coordinate for item in supports)
            (
                family_label,
                family_kind,
                _outcome_name,
                _contrast_selector,
                outcome_rule,
                contrast_rule,
            ) = _family_metadata(checked_family)
            family = SimultaneousFamilyManifestV2.from_content(
                family_label=family_label,
                family_kind=family_kind,
                coordinates=coordinates,
                family_size=len(coordinates),
                frozen_before_outcomes=True,
            )
            payload = {
                "schema_version": MULTI_SUPPORT_INFERENCE_V2_SCHEMA_VERSION,
                "confirmatory_experiment_freeze_id": (experiment.confirmatory_experiment_freeze_id),
                "experiment": experiment,
                "global_multiplicity_family_policy_sha256": (
                    experiment.global_multiplicity_family_policy_sha256
                ),
                "analysis_seed_domain_sha256": experiment.analysis_seed_domain_sha256,
                "formal_family": checked_family,
                "family": family,
                "coordinate_supports": supports,
                "global_union_strata": _expected_global_union(supports),
                "alpha_numerator": 1,
                "alpha_denominator": 20,
                "bootstrap_samples": FORMAL_MIN_BOOTSTRAP_SAMPLES_V2,
                "minimum_valid_bootstrap_draws": (
                    FORMAL_MIN_BOOTSTRAP_SAMPLES_V2 * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
                    + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                    - 1
                )
                // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2,
                "minimum_valid_fraction_numerator": (
                    MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
                ),
                "minimum_valid_fraction_denominator": (
                    MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                ),
                "minimum_independent_clusters_per_coordinate": 2,
                "rng_version": RNG_VERSION,
                "family_rule": (
                    "complete_protocolized_hypothesis_by_frozen_model_cartesian_product_v1"
                ),
                "outcome_rule": outcome_rule,
                "contrast_rule": contrast_rule,
                "resampling_method": (
                    "global_union_stratified_semantic_cluster_ratio_bootstrap_v1"
                ),
                "cluster_coupling_rule": (
                    "one_union_draw_shared_then_filtered_by_frozen_coordinate_support_v1"
                ),
                "support_rule": (
                    "coordinate_specific_no_common_intersection_no_estimand_change_v1"
                ),
                "studentization_method": "coordinate_specific_cluster_se_v1",
                "centering_method": "bootstrap_minus_observed_v1",
                "quantile_rule": "empirical_higher_v1",
                "interval_rule": "two_sided_studentized_global_max_abs_t_v1",
                "invalid_draw_policy": "retain_reason_and_fail_below_frozen_fraction_v2",
                "seed_derivation_rule": (
                    "sha256_frozen_domain_digest_plus_content_addressed_plan_id_v1"
                ),
                "complete_hypothesis_model_family_required": True,
                "frozen_before_outcomes": True,
            }
            return cls.model_construct(
                **payload,
                inference_plan_id="multi_support_simultaneous_plan_v2_" + _digest(payload),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the internal deterministic boundary
            raise cls._safe_error() from None

    @property
    def alpha(self) -> Fraction:
        return Fraction(self.alpha_numerator, self.alpha_denominator)

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        expected_supports = _expected_coordinate_supports(
            self.experiment,
            self.formal_family,
        )
        expected_union = _expected_global_union(expected_supports)
        expected_coordinates = tuple(item.test_coordinate for item in expected_supports)
        (
            family_label,
            family_kind,
            _outcome_name,
            _contrast_selector,
            outcome_rule,
            contrast_rule,
        ) = _family_metadata(self.formal_family)
        expected_family = SimultaneousFamilyManifestV2.from_content(
            family_label=family_label,
            family_kind=family_kind,
            coordinates=expected_coordinates,
            family_size=len(expected_coordinates),
            frozen_before_outcomes=True,
        )
        expected_minimum_valid_draws = (
            self.bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
            + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
            - 1
        ) // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
        if (
            self.confirmatory_experiment_freeze_id
            != self.experiment.confirmatory_experiment_freeze_id
            or self.global_multiplicity_family_policy_sha256
            != self.experiment.global_multiplicity_family_policy_sha256
            or self.analysis_seed_domain_sha256 != self.experiment.analysis_seed_domain_sha256
            or self.coordinate_supports != expected_supports
            or self.global_union_strata != expected_union
            or self.family != expected_family
            or self.outcome_rule != outcome_rule
            or self.contrast_rule != contrast_rule
            or len(self.coordinate_supports) != self.experiment.hypothesis_model_coordinate_count
            or self.alpha_numerator >= self.alpha_denominator
            or self.minimum_valid_bootstrap_draws != expected_minimum_valid_draws
            or self.minimum_valid_bootstrap_draws > self.bootstrap_samples
            or any(
                item.coordinate_cluster_count < self.minimum_independent_clusters_per_coordinate
                for item in self.coordinate_supports
            )
            or sum(item.union_cluster_count for item in self.global_union_strata)
            * len(self.coordinate_supports)
            > 2_000_000
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "MULTI_SUPPORT_INFERENCE_V2_SCHEMA_VERSION",
    "MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2",
    "MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2",
    "CoordinateSpecificStratumSupportV2",
    "CoordinateSpecificSupportV2",
    "GlobalUnionStratumV2",
    "MultiSupportFormalFamilyV2",
    "MultiSupportSimultaneousInferencePlanV2",
]

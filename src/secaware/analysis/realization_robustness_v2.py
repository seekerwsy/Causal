"""Minimal realization-robustness engine over one frozen global max-|T| family.

The engine starts from authenticated cluster-level target-minus-no-op contributions
for every realization.  It derives the Q_h average, realization-specific effects,
leave-one-realization-out policies, and realization-minus-policy deviations, then
sends every coordinate across every hypothesis through one simultaneous family.

Arm-by-realization randomization itself needs block-level assignments and is therefore
not imitated here.  This layer requires a separately produced, content-addressed
semantic-cluster arm-randomization reference before it can award a robust label.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from secaware.analysis.simultaneous_v2 import (
    CoordinateClusterContributionV2,
    SimultaneousInferenceResultV2,
    SimultaneousIntervalV2,
    run_simultaneous_inference_v2,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.inference_v2 import (
    CommonStratumSupportV2,
    RealizationRobustnessHypothesisSpecV2,
    RealizationRobustnessPlanV2,
    RobustnessExpectedDirectionV2,
    SimultaneousCoordinateKindV2,
    SimultaneousFamilyKindV2,
    SimultaneousFamilyManifestV2,
    SimultaneousInferencePlanV2,
    SimultaneousTestCoordinateV2,
)

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_INTERACTION_STATISTIC_METHOD = "max_abs_realization_minus_qh_policy_v1"
_INTERACTION_METHOD = "semantic_cluster_arm_randomization_v1"


class RealizationRobustnessLabelV2(StrEnum):
    REALIZATION_ROBUST = "realization_robust"
    AVERAGE_POLICY_ONLY = "average_policy_only"


@dataclass(frozen=True, slots=True)
class RealizationClusterContributionV2:
    hypothesis_id: str
    model_id: str
    realization_spec_id: str
    stratum_id: str
    semantic_task_cluster_id: str
    estimate: float


@dataclass(frozen=True, slots=True)
class BaseRandomizedPolicyEvidenceV2:
    evidence_sha256: str
    robustness_hypothesis_spec_id: str
    hypothesis_id: str
    model_id: str
    primary_family_id: str
    simultaneous_lower: float
    simultaneous_upper: float
    confirmed: bool
    provenance_complete: bool

    @classmethod
    def from_content(
        cls,
        *,
        robustness_hypothesis_spec_id: str,
        hypothesis_id: str,
        model_id: str,
        primary_family_id: str,
        simultaneous_lower: float,
        simultaneous_upper: float,
        confirmed: bool,
        provenance_complete: bool,
    ) -> BaseRandomizedPolicyEvidenceV2:
        payload = {
            "robustness_hypothesis_spec_id": robustness_hypothesis_spec_id,
            "hypothesis_id": hypothesis_id,
            "model_id": model_id,
            "primary_family_id": primary_family_id,
            "simultaneous_lower": simultaneous_lower,
            "simultaneous_upper": simultaneous_upper,
            "confirmed": confirmed,
            "provenance_complete": provenance_complete,
        }
        return cls(evidence_sha256=_digest(payload), **payload)


@dataclass(frozen=True, slots=True)
class ArmRealizationInteractionReferenceV2:
    reference_sha256: str
    robustness_hypothesis_spec_id: str
    global_robustness_family_id: str
    hypothesis_id: str
    model_id: str
    interaction_statistic_method: str
    reference_method: str
    randomization_manifest_sha256: str
    joint_reference_run_sha256: str
    observed_statistic: float
    reference_statistics: tuple[float, ...]

    @classmethod
    def from_statistics(
        cls,
        *,
        robustness_hypothesis_spec_id: str,
        global_robustness_family_id: str,
        hypothesis_id: str,
        model_id: str,
        randomization_manifest_sha256: str,
        joint_reference_run_sha256: str,
        observed_statistic: float,
        reference_statistics: tuple[float, ...],
    ) -> ArmRealizationInteractionReferenceV2:
        payload = {
            "robustness_hypothesis_spec_id": robustness_hypothesis_spec_id,
            "global_robustness_family_id": global_robustness_family_id,
            "hypothesis_id": hypothesis_id,
            "model_id": model_id,
            "interaction_statistic_method": _INTERACTION_STATISTIC_METHOD,
            "reference_method": _INTERACTION_METHOD,
            "randomization_manifest_sha256": randomization_manifest_sha256,
            "joint_reference_run_sha256": joint_reference_run_sha256,
            "observed_statistic": observed_statistic,
            "reference_statistics": reference_statistics,
        }
        return cls(reference_sha256=_digest(payload), **payload)


@dataclass(frozen=True, slots=True)
class RealizationRobustnessHypothesisResultV2:
    hypothesis_id: str
    model_id: str
    label: RealizationRobustnessLabelV2
    base_policy_effect_confirmed: bool
    pooled_global_interval_supported: bool
    all_realization_points_expected_direction: bool
    direction_consistency_count: int
    direction_consistency_required: int
    direction_consistency_threshold_met: bool
    no_realization_interval_fully_supports_reverse: bool
    all_leave_one_out_intervals_supported: bool
    heterogeneity_simultaneous_upper: float
    practical_equivalence_margin: float
    heterogeneity_equivalent: bool
    interaction_observed_statistic: float
    interaction_randomization_p_value: float
    interaction_global_adjusted_p_value: float
    interaction_reference_reported: bool
    pooled_interval: SimultaneousIntervalV2
    realization_intervals: tuple[tuple[str, SimultaneousIntervalV2], ...]
    leave_one_out_intervals: tuple[tuple[str, SimultaneousIntervalV2], ...]
    deviation_intervals: tuple[tuple[str, SimultaneousIntervalV2], ...]


@dataclass(frozen=True, slots=True)
class RealizationRobustnessAnalysisResultV2:
    robustness_plan_id: str
    simultaneous_result: SimultaneousInferenceResultV2
    hypotheses: tuple[RealizationRobustnessHypothesisResultV2, ...]


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _error(message: str = "realization robustness v2 failed validation") -> ValueError:
    return ValueError(message)


def _coordinate(
    specification: RealizationRobustnessHypothesisSpecV2,
    *,
    kind: SimultaneousCoordinateKindV2,
    component_id: str,
) -> SimultaneousTestCoordinateV2:
    return SimultaneousTestCoordinateV2.from_content(
        hypothesis_id=specification.hypothesis_id,
        target_spec_id=specification.target_spec_id,
        arm_protocol_id=specification.arm_protocol_id,
        model_id=specification.model_id,
        outcome_name=specification.outcome_name,
        treatment_arm=specification.treatment_arm,
        control_arm=specification.control_arm,
        coordinate_kind=kind,
        analysis_component_id=component_id,
    )


def build_realization_robustness_plan_v2(
    hypotheses: Iterable[RealizationRobustnessHypothesisSpecV2],
    *,
    family_label: str,
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
    interaction_minimum_reference_draws: int,
) -> RealizationRobustnessPlanV2:
    """Freeze all cross-h realization coordinates before any outcome is supplied."""

    if isinstance(hypotheses, (str, bytes, Mapping)):
        raise _error()
    try:
        checked = tuple(
            sorted(
                (
                    RealizationRobustnessHypothesisSpecV2.model_validate(item, strict=True)
                    for item in hypotheses
                ),
                key=lambda item: item.robustness_hypothesis_spec_id,
            )
        )
    except _FATAL:
        raise
    except Exception:  # noqa: BLE001 - sanitize the public builder boundary
        raise _error() from None
    if not checked:
        raise _error()
    coordinates: list[SimultaneousTestCoordinateV2] = []
    for item in checked:
        coordinates.append(
            _coordinate(
                item,
                kind=SimultaneousCoordinateKindV2.POLICY_EFFECT,
                component_id="pooled",
            )
        )
        for realization_id in item.realization_spec_ids:
            coordinates.extend(
                (
                    _coordinate(
                        item,
                        kind=SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                        component_id=f"realization.{realization_id}",
                    ),
                    _coordinate(
                        item,
                        kind=SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                        component_id=f"loo.{realization_id}",
                    ),
                    _coordinate(
                        item,
                        kind=SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                        component_id=f"deviation.{realization_id}",
                    ),
                )
            )
    ordered_coordinates = tuple(sorted(coordinates, key=lambda item: item.test_coordinate_id))
    family = SimultaneousFamilyManifestV2.from_content(
        family_label=family_label,
        family_kind=SimultaneousFamilyKindV2.REALIZATION_ROBUSTNESS,
        coordinates=ordered_coordinates,
        family_size=len(ordered_coordinates),
        frozen_before_outcomes=True,
    )
    inference_plan = SimultaneousInferencePlanV2.from_family(
        family=family,
        strata=strata,
        stratum_weight_denominator=stratum_weight_denominator,
        alpha_numerator=alpha_numerator,
        alpha_denominator=alpha_denominator,
        bootstrap_samples=bootstrap_samples,
        minimum_independent_clusters=minimum_independent_clusters,
        minimum_clusters_per_stratum=minimum_clusters_per_stratum,
        maximum_invalid_fraction_numerator=maximum_invalid_fraction_numerator,
        maximum_invalid_fraction_denominator=maximum_invalid_fraction_denominator,
        seed_material_sha256=seed_material_sha256,
    )
    return RealizationRobustnessPlanV2.from_components(
        hypotheses=checked,
        simultaneous_inference_plan=inference_plan,
        interaction_minimum_reference_draws=interaction_minimum_reference_draws,
    )


def _validated_plan(plan: RealizationRobustnessPlanV2) -> RealizationRobustnessPlanV2:
    if type(plan) is not RealizationRobustnessPlanV2 or not model_shape_is_intact(plan):
        raise _error()
    try:
        return RealizationRobustnessPlanV2.model_validate(
            plan.model_dump(mode="python", round_trip=True, warnings=False)
        )
    except _FATAL:
        raise
    except Exception:  # noqa: BLE001 - sanitize the public contract boundary
        raise _error() from None


def _expected_input_keys(
    plan: RealizationRobustnessPlanV2,
) -> set[tuple[str, str, str, str, str]]:
    return {
        (
            item.hypothesis_id,
            item.model_id,
            realization_id,
            stratum.stratum_id,
            cluster_id,
        )
        for item in plan.hypotheses
        for realization_id in item.realization_spec_ids
        for stratum in plan.simultaneous_inference_plan.strata
        for cluster_id in stratum.semantic_task_cluster_ids
    }


def _validated_cluster_contributions(
    plan: RealizationRobustnessPlanV2,
    contributions: Iterable[RealizationClusterContributionV2],
) -> dict[tuple[str, str, str, str, str], float]:
    if isinstance(contributions, (str, bytes, Mapping)):
        raise _error()
    expected = _expected_input_keys(plan)
    values: dict[tuple[str, str, str, str, str], float] = {}
    try:
        for index, item in enumerate(contributions):
            if index >= len(expected) or type(item) is not RealizationClusterContributionV2:
                raise _error("realization common support failed validation")
            key = (
                item.hypothesis_id,
                item.model_id,
                item.realization_spec_id,
                item.stratum_id,
                item.semantic_task_cluster_id,
            )
            if (
                key in values
                or type(item.estimate) not in {int, float}
                or type(item.estimate) is bool
            ):
                raise _error("realization common support failed validation")
            estimate = float(item.estimate)
            if not math.isfinite(estimate):
                raise _error("realization cluster contribution failed validation")
            values[key] = estimate
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error() from None
    if set(values) != expected:
        raise _error("realization common support failed validation")
    return values


def _coordinate_lookup(
    plan: RealizationRobustnessPlanV2,
) -> dict[tuple[str, str, SimultaneousCoordinateKindV2, str], SimultaneousTestCoordinateV2]:
    return {
        (
            item.hypothesis_id,
            item.model_id,
            item.coordinate_kind,
            item.analysis_component_id,
        ): item
        for item in plan.simultaneous_inference_plan.family.coordinates
    }


def _derived_contributions(
    plan: RealizationRobustnessPlanV2,
    values: Mapping[tuple[str, str, str, str, str], float],
) -> tuple[CoordinateClusterContributionV2, ...]:
    lookup = _coordinate_lookup(plan)
    output: list[CoordinateClusterContributionV2] = []
    for specification in plan.hypotheses:
        weights = {
            realization_id: numerator / specification.probability_denominator
            for realization_id, numerator in zip(
                specification.realization_spec_ids,
                specification.probability_numerators,
                strict=True,
            )
        }
        for stratum in plan.simultaneous_inference_plan.strata:
            for cluster_id in stratum.semantic_task_cluster_ids:
                realization_values = {
                    realization_id: values[
                        (
                            specification.hypothesis_id,
                            specification.model_id,
                            realization_id,
                            stratum.stratum_id,
                            cluster_id,
                        )
                    ]
                    for realization_id in specification.realization_spec_ids
                }
                pooled = math.fsum(
                    weights[realization_id] * realization_values[realization_id]
                    for realization_id in specification.realization_spec_ids
                )
                derived: list[tuple[SimultaneousCoordinateKindV2, str, float]] = [
                    (SimultaneousCoordinateKindV2.POLICY_EFFECT, "pooled", pooled)
                ]
                for realization_id in specification.realization_spec_ids:
                    realization_weight = weights[realization_id]
                    leave_one_out = math.fsum(
                        weights[other] * realization_values[other]
                        for other in specification.realization_spec_ids
                        if other != realization_id
                    ) / (1.0 - realization_weight)
                    derived.extend(
                        (
                            (
                                SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                                f"realization.{realization_id}",
                                realization_values[realization_id],
                            ),
                            (
                                SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                                f"loo.{realization_id}",
                                leave_one_out,
                            ),
                            (
                                SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                                f"deviation.{realization_id}",
                                realization_values[realization_id] - pooled,
                            ),
                        )
                    )
                output.extend(
                    CoordinateClusterContributionV2(
                        test_coordinate_id=lookup[
                            (
                                specification.hypothesis_id,
                                specification.model_id,
                                kind,
                                component_id,
                            )
                        ].test_coordinate_id,
                        stratum_id=stratum.stratum_id,
                        semantic_task_cluster_id=cluster_id,
                        estimate=estimate,
                    )
                    for kind, component_id, estimate in derived
                )
    return tuple(output)


def _validate_base_evidence(
    plan: RealizationRobustnessPlanV2,
    evidence: Iterable[BaseRandomizedPolicyEvidenceV2],
) -> dict[tuple[str, str], BaseRandomizedPolicyEvidenceV2]:
    if isinstance(evidence, (str, bytes, Mapping)):
        raise _error()
    expected = {
        (item.hypothesis_id, item.model_id): item.robustness_hypothesis_spec_id
        for item in plan.hypotheses
    }
    result: dict[tuple[str, str], BaseRandomizedPolicyEvidenceV2] = {}
    try:
        for item in evidence:
            if type(item) is not BaseRandomizedPolicyEvidenceV2:
                raise _error("base policy evidence failed validation")
            key = (item.hypothesis_id, item.model_id)
            payload = {
                "robustness_hypothesis_spec_id": item.robustness_hypothesis_spec_id,
                "hypothesis_id": item.hypothesis_id,
                "model_id": item.model_id,
                "primary_family_id": item.primary_family_id,
                "simultaneous_lower": item.simultaneous_lower,
                "simultaneous_upper": item.simultaneous_upper,
                "confirmed": item.confirmed,
                "provenance_complete": item.provenance_complete,
            }
            if (
                key in result
                or expected.get(key) != item.robustness_hypothesis_spec_id
                or item.evidence_sha256 != _digest(payload)
                or type(item.confirmed) is not bool
                or type(item.provenance_complete) is not bool
                or type(item.simultaneous_lower) not in {int, float}
                or type(item.simultaneous_upper) not in {int, float}
                or not math.isfinite(float(item.simultaneous_lower))
                or not math.isfinite(float(item.simultaneous_upper))
                or item.simultaneous_lower > item.simultaneous_upper
            ):
                raise _error("base policy evidence failed validation")
            result[key] = item
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error("base policy evidence failed validation") from None
    if set(result) != set(expected):
        raise _error("base policy evidence failed validation")
    return result


def _validate_interaction_references(
    plan: RealizationRobustnessPlanV2,
    references: Iterable[ArmRealizationInteractionReferenceV2],
) -> dict[tuple[str, str], ArmRealizationInteractionReferenceV2]:
    if isinstance(references, (str, bytes, Mapping)):
        raise _error()
    expected = {
        (item.hypothesis_id, item.model_id): item.robustness_hypothesis_spec_id
        for item in plan.hypotheses
    }
    result: dict[tuple[str, str], ArmRealizationInteractionReferenceV2] = {}
    try:
        for item in references:
            if type(item) is not ArmRealizationInteractionReferenceV2:
                raise _error("interaction randomization reference failed validation")
            key = (item.hypothesis_id, item.model_id)
            payload = {
                "robustness_hypothesis_spec_id": item.robustness_hypothesis_spec_id,
                "global_robustness_family_id": item.global_robustness_family_id,
                "hypothesis_id": item.hypothesis_id,
                "model_id": item.model_id,
                "interaction_statistic_method": item.interaction_statistic_method,
                "reference_method": item.reference_method,
                "randomization_manifest_sha256": item.randomization_manifest_sha256,
                "joint_reference_run_sha256": item.joint_reference_run_sha256,
                "observed_statistic": item.observed_statistic,
                "reference_statistics": item.reference_statistics,
            }
            if (
                key in result
                or expected.get(key) != item.robustness_hypothesis_spec_id
                or item.reference_sha256 != _digest(payload)
                or item.global_robustness_family_id != plan.simultaneous_inference_plan.family_id
                or item.interaction_statistic_method != plan.interaction_statistic_method
                or item.reference_method != plan.interaction_reference_method
                or len(item.randomization_manifest_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in item.randomization_manifest_sha256
                )
                or len(item.joint_reference_run_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in item.joint_reference_run_sha256
                )
                or type(item.observed_statistic) not in {int, float}
                or not math.isfinite(float(item.observed_statistic))
                or item.observed_statistic < 0.0
                or type(item.reference_statistics) is not tuple
                or len(item.reference_statistics) < plan.interaction_minimum_reference_draws
                or any(
                    type(value) not in {int, float}
                    or type(value) is bool
                    or not math.isfinite(float(value))
                    or value < 0.0
                    for value in item.reference_statistics
                )
            ):
                raise _error("interaction randomization reference failed validation")
            result[key] = item
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error("interaction randomization reference failed validation") from None
    if set(result) != set(expected):
        raise _error("interaction randomization reference failed validation")
    if (
        len({item.randomization_manifest_sha256 for item in result.values()}) != 1
        or len({item.joint_reference_run_sha256 for item in result.values()}) != 1
        or len({len(item.reference_statistics) for item in result.values()}) != 1
    ):
        raise _error("interaction randomization reference failed validation")
    return result


def _expected_point(direction: RobustnessExpectedDirectionV2, value: float) -> bool:
    return value > 0.0 if direction is RobustnessExpectedDirectionV2.POSITIVE else value < 0.0


def _expected_interval(
    direction: RobustnessExpectedDirectionV2,
    interval: SimultaneousIntervalV2,
) -> bool:
    return (
        interval.simultaneous_lower > 0.0
        if direction is RobustnessExpectedDirectionV2.POSITIVE
        else interval.simultaneous_upper < 0.0
    )


def _fully_reverse_interval(
    direction: RobustnessExpectedDirectionV2,
    interval: SimultaneousIntervalV2,
) -> bool:
    return (
        interval.simultaneous_upper < 0.0
        if direction is RobustnessExpectedDirectionV2.POSITIVE
        else interval.simultaneous_lower > 0.0
    )


def run_realization_robustness_v2(
    plan: RealizationRobustnessPlanV2,
    contributions: Iterable[RealizationClusterContributionV2],
    base_policy_evidence: Iterable[BaseRandomizedPolicyEvidenceV2],
    interaction_references: Iterable[ArmRealizationInteractionReferenceV2],
    *,
    seed_material: bytes,
) -> RealizationRobustnessAnalysisResultV2:
    """Assess the strong label without weakening the average-Q_h policy estimate."""

    checked_plan = _validated_plan(plan)
    values = _validated_cluster_contributions(checked_plan, contributions)
    base = _validate_base_evidence(checked_plan, base_policy_evidence)
    interactions = _validate_interaction_references(checked_plan, interaction_references)
    reference_draw_count = len(next(iter(interactions.values())).reference_statistics)
    global_interaction_reference = tuple(
        max(item.reference_statistics[index] for item in interactions.values())
        for index in range(reference_draw_count)
    )
    simultaneous = run_simultaneous_inference_v2(
        checked_plan.simultaneous_inference_plan,
        _derived_contributions(checked_plan, values),
        seed_material=seed_material,
    )
    interval_by_id = {item.test_coordinate_id: item for item in simultaneous.intervals}
    coordinate_lookup = _coordinate_lookup(checked_plan)
    outputs: list[RealizationRobustnessHypothesisResultV2] = []
    for specification in checked_plan.hypotheses:
        key = (specification.hypothesis_id, specification.model_id)

        def interval(
            kind: SimultaneousCoordinateKindV2,
            component_id: str,
            hypothesis_key: tuple[str, str] = key,
        ) -> SimultaneousIntervalV2:
            coordinate = coordinate_lookup[(*hypothesis_key, kind, component_id)]
            return interval_by_id[coordinate.test_coordinate_id]

        pooled = interval(SimultaneousCoordinateKindV2.POLICY_EFFECT, "pooled")
        realization_intervals = tuple(
            (
                realization_id,
                interval(
                    SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                    f"realization.{realization_id}",
                ),
            )
            for realization_id in specification.realization_spec_ids
        )
        loo_intervals = tuple(
            (
                realization_id,
                interval(
                    SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                    f"loo.{realization_id}",
                ),
            )
            for realization_id in specification.realization_spec_ids
        )
        deviation_intervals = tuple(
            (
                realization_id,
                interval(
                    SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                    f"deviation.{realization_id}",
                ),
            )
            for realization_id in specification.realization_spec_ids
        )
        direction_count = sum(
            _expected_point(specification.expected_direction, item.estimate)
            for _realization_id, item in realization_intervals
        )
        all_points = direction_count == len(realization_intervals)
        direction_threshold = (
            direction_count >= specification.minimum_direction_consistent_realizations
        )
        no_reverse = not any(
            _fully_reverse_interval(specification.expected_direction, item)
            for _realization_id, item in realization_intervals
        )
        all_loo = all(
            _expected_interval(specification.expected_direction, item)
            for _realization_id, item in loo_intervals
        )
        heterogeneity_upper = max(
            max(abs(item.simultaneous_lower), abs(item.simultaneous_upper))
            for _realization_id, item in deviation_intervals
        )
        heterogeneity_equivalent = heterogeneity_upper <= specification.practical_equivalence_margin
        primary = base[key]
        primary_interval_oriented = (
            primary.simultaneous_lower > 0.0
            if specification.expected_direction is RobustnessExpectedDirectionV2.POSITIVE
            else primary.simultaneous_upper < 0.0
        )
        if primary.confirmed and not (primary.provenance_complete and primary_interval_oriented):
            raise _error("confirmed base policy evidence is internally inconsistent")
        base_confirmed = (
            primary.confirmed and primary.provenance_complete and primary_interval_oriented
        )
        pooled_supported = _expected_interval(specification.expected_direction, pooled)
        interaction = interactions[key]
        interaction_observed = max(
            abs(item.estimate) for _realization_id, item in deviation_intervals
        )
        if not math.isclose(
            interaction.observed_statistic,
            interaction_observed,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise _error("interaction observed statistic failed validation")
        interaction_p = (
            1
            + sum(
                value >= interaction.observed_statistic
                for value in interaction.reference_statistics
            )
        ) / (len(interaction.reference_statistics) + 1)
        interaction_global_p = (
            1
            + sum(value >= interaction.observed_statistic for value in global_interaction_reference)
        ) / (len(global_interaction_reference) + 1)
        robust = all(
            (
                base_confirmed,
                pooled_supported,
                all_points,
                direction_threshold,
                no_reverse,
                all_loo,
                heterogeneity_equivalent,
                True,  # exact interaction randomization reference passed validation
            )
        )
        outputs.append(
            RealizationRobustnessHypothesisResultV2(
                hypothesis_id=specification.hypothesis_id,
                model_id=specification.model_id,
                label=(
                    RealizationRobustnessLabelV2.REALIZATION_ROBUST
                    if robust
                    else RealizationRobustnessLabelV2.AVERAGE_POLICY_ONLY
                ),
                base_policy_effect_confirmed=base_confirmed,
                pooled_global_interval_supported=pooled_supported,
                all_realization_points_expected_direction=all_points,
                direction_consistency_count=direction_count,
                direction_consistency_required=(
                    specification.minimum_direction_consistent_realizations
                ),
                direction_consistency_threshold_met=direction_threshold,
                no_realization_interval_fully_supports_reverse=no_reverse,
                all_leave_one_out_intervals_supported=all_loo,
                heterogeneity_simultaneous_upper=heterogeneity_upper,
                practical_equivalence_margin=(specification.practical_equivalence_margin),
                heterogeneity_equivalent=heterogeneity_equivalent,
                interaction_observed_statistic=interaction.observed_statistic,
                interaction_randomization_p_value=interaction_p,
                interaction_global_adjusted_p_value=interaction_global_p,
                interaction_reference_reported=True,
                pooled_interval=pooled,
                realization_intervals=realization_intervals,
                leave_one_out_intervals=loo_intervals,
                deviation_intervals=deviation_intervals,
            )
        )
    return RealizationRobustnessAnalysisResultV2(
        robustness_plan_id=checked_plan.robustness_plan_id,
        simultaneous_result=simultaneous,
        hypotheses=tuple(outputs),
    )


__all__ = [
    "ArmRealizationInteractionReferenceV2",
    "BaseRandomizedPolicyEvidenceV2",
    "RealizationClusterContributionV2",
    "RealizationRobustnessAnalysisResultV2",
    "RealizationRobustnessHypothesisResultV2",
    "RealizationRobustnessLabelV2",
    "build_realization_robustness_plan_v2",
    "run_realization_robustness_v2",
]

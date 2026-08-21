"""Coordinate-specific realization robustness and non-pooled model replication.

All numeric inputs originate in provenance-closed assignment coverage.  The
module first reuses :mod:`confirmatory_contributions_v2` to derive exact
per-realization semantic-cluster contrasts and reuses the frozen primary
multi-support family for the :math:`Q_h`-average effect.  Realization, LOO, and
deviation coordinates then use the same union-stratified shared-cluster
studentized max-|T| implementation as the primary multi-support engine.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum, StrEnum
from fractions import Fraction

from pydantic import ValidationError

from secaware.analysis.confirmatory_contributions_v2 import (
    ConfirmatoryContributionArtifactV2,
    ExactRealizationClusterContributionV2,
    derive_frozen_formal_family_contributions_v2,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    CoordinateStratumRetainedCountV2,
    GlobalUnionMaxTDrawV2,
    InvalidGlobalUnionDrawV2,
    MultiSupportSimultaneousInferenceResultV2,
    MultiSupportSimultaneousIntervalV2,
    UnionStratumDrawDigestV2,
    _artifact_input_digest,
    _coordinate_statistics,
    _higher_quantile,
    _InvalidBootstrapDraw,
    _sample_digest,
    _validated_artifacts,
    run_frozen_domain_multi_support_simultaneous_inference_v2,
)
from secaware.analysis.realization_robustness_v2 import (
    RealizationClusterContributionV2,
    RealizationRobustnessLabelV2,
)
from secaware.experiments.execution_v2 import (
    ProvenanceClosedAssignmentCoverageManifestV2,
)
from secaware.randomness import DeterministicRNG
from secaware.schema.common import model_shape_is_intact
from secaware.schema.inference_v2 import (
    RobustnessExpectedDirectionV2,
    SimultaneousCoordinateKindV2,
)
from secaware.schema.multi_support_robustness_v2 import (
    MULTI_SUPPORT_ROBUSTNESS_BOOTSTRAP_SAMPLES_V2,
    MULTI_SUPPORT_ROBUSTNESS_MINIMUM_VALID_DRAWS_V2,
    CrossModelReplicationPolicyV2,
    MultiSupportArmRealizationInteractionReferenceV2,
    MultiSupportRobustnessPolicyFreezeV2,
)

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_RESULT_PREFIX = "multi_support_robustness_result_v2_"
_INFERENCE_RESULT_PREFIX = "multi_support_robustness_inference_v2_"
_SEED_DOMAIN = b"secaware.multi-support-realization-robustness.v2\x00"


class CrossModelReplicationLabelV2(StrEnum):
    REPLICATED = "replicated"
    NOT_REPLICATED = "not_replicated"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class MultiSupportRobustnessInferenceResultV2:
    robustness_inference_result_id: str
    robustness_policy_freeze_id: str
    confirmatory_experiment_freeze_id: str
    family_id: str
    global_multiplicity_family_policy_sha256: str
    bootstrap_seed_sha256: str
    input_contribution_artifact_ids: tuple[str, ...]
    input_contributions_sha256: str
    inference_scope: str
    bootstrap_samples: int
    minimum_valid_bootstrap_draws: int
    critical_value: float
    valid_draw_count: int
    invalid_draw_count: int
    intervals: tuple[MultiSupportSimultaneousIntervalV2, ...]
    draws: tuple[GlobalUnionMaxTDrawV2, ...]
    invalid_draws: tuple[InvalidGlobalUnionDrawV2, ...]


@dataclass(frozen=True, slots=True)
class MultiSupportModelRobustnessResultV2:
    hypothesis_id: str
    model_id: str
    label: RealizationRobustnessLabelV2
    base_policy_effect_confirmed: bool
    base_policy_effect_fully_reverse: bool
    all_realization_points_expected_direction: bool
    direction_consistency_count: int
    direction_consistency_required: int
    direction_consistency_threshold_met: bool
    no_realization_interval_fully_supports_reverse: bool
    all_leave_one_out_intervals_supported: bool
    heterogeneity_simultaneous_upper: float
    practical_equivalence_margin: float
    heterogeneity_equivalent: bool
    minimum_independent_clusters_per_realization: int
    minimum_support_met: bool
    interaction_observed_statistic: float
    interaction_randomization_p_value: float | None
    interaction_global_adjusted_p_value: float | None
    interaction_reference_reported: bool
    global_interaction_family_complete: bool
    interaction_condition_met: bool
    all_frozen_conditions_met: bool
    primary_interval: MultiSupportSimultaneousIntervalV2
    realization_intervals: tuple[tuple[str, MultiSupportSimultaneousIntervalV2], ...]
    leave_one_out_intervals: tuple[tuple[str, MultiSupportSimultaneousIntervalV2], ...]
    deviation_intervals: tuple[tuple[str, MultiSupportSimultaneousIntervalV2], ...]


@dataclass(frozen=True, slots=True)
class CrossModelReplicationResultV2:
    hypothesis_id: str
    label: CrossModelReplicationLabelV2
    model_ids: tuple[str, ...]
    confirmed_model_ids: tuple[str, ...]
    unconfirmed_model_ids: tuple[str, ...]
    reverse_model_ids: tuple[str, ...]
    required_confirmed_model_count: int
    confirmed_model_count: int
    model_effects_pooled: bool
    any_unconfirmed_or_reverse_model_disqualifies: bool


@dataclass(frozen=True, slots=True)
class MultiSupportRobustnessAnalysisResultV2:
    analysis_result_id: str
    robustness_policy_freeze_id: str
    confirmatory_experiment_freeze_id: str
    primary_inference_result: MultiSupportSimultaneousInferenceResultV2
    robustness_inference_result: MultiSupportRobustnessInferenceResultV2
    input_provenance_closed_coverage_manifest_ids: tuple[str, ...]
    input_contribution_artifact_ids: tuple[str, ...]
    interaction_reference_ids: tuple[str, ...]
    global_interaction_family_complete: bool
    formal_analysis_glue_binding_required: bool
    formal_analysis_glue_binding_status: str
    model_robustness_results: tuple[MultiSupportModelRobustnessResultV2, ...]
    cross_model_replication_results: tuple[CrossModelReplicationResultV2, ...]


@dataclass(frozen=True, slots=True)
class SyntheticMultiSupportRobustnessSmokeResultV2:
    """Small pipeline proof that is structurally barred from evidence labels."""

    smoke_result_id: str
    robustness_policy_freeze_id: str
    confirmatory_experiment_freeze_id: str
    input_provenance_closed_coverage_manifest_ids: tuple[str, ...]
    input_contribution_artifact_ids: tuple[str, ...]
    inference_result: MultiSupportRobustnessInferenceResultV2
    synthetic_bootstrap_samples: int
    formal_policy_bootstrap_samples: int
    purpose: str
    formal_robustness_label_awarded: bool
    cross_model_replication_label_awarded: bool


def _error(message: str = "multi-support robustness v2 failed validation") -> ValueError:
    return ValueError(message)


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
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


def _validated_policy(
    policy: MultiSupportRobustnessPolicyFreezeV2,
) -> MultiSupportRobustnessPolicyFreezeV2:
    _validate_formal_policy_constants(policy)
    if type(policy) is not MultiSupportRobustnessPolicyFreezeV2 or not model_shape_is_intact(
        policy
    ):
        raise _error("robustness policy freeze failed validation")
    try:
        return MultiSupportRobustnessPolicyFreezeV2.model_validate(
            policy.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("robustness policy freeze failed validation") from None


def _validate_formal_policy_constants(
    policy: MultiSupportRobustnessPolicyFreezeV2,
) -> None:
    """Reject an execution-time relaxation before expensive root replay."""

    if type(policy) is not MultiSupportRobustnessPolicyFreezeV2:
        raise _error("robustness policy freeze failed validation")
    _validate_formal_execution_counts(
        bootstrap_samples=policy.bootstrap_samples,
        minimum_valid_bootstrap_draws=policy.minimum_valid_bootstrap_draws,
    )


def _validate_formal_execution_counts(
    *,
    bootstrap_samples: int,
    minimum_valid_bootstrap_draws: int,
) -> None:
    if (
        bootstrap_samples != MULTI_SUPPORT_ROBUSTNESS_BOOTSTRAP_SAMPLES_V2
        or minimum_valid_bootstrap_draws != MULTI_SUPPORT_ROBUSTNESS_MINIMUM_VALID_DRAWS_V2
    ):
        raise _error("robustness policy freeze failed validation")


def _validate_complete_coverage_keys(
    expected_hypothesis_ids: frozenset[str],
    observed_hypothesis_ids: frozenset[str],
) -> None:
    if observed_hypothesis_ids != expected_hypothesis_ids:
        raise _error("complete provenance-closed coverage family is required")


def _validated_coverages(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: Iterable[ProvenanceClosedAssignmentCoverageManifestV2],
) -> tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...]:
    if isinstance(coverages, (str, bytes, Mapping)):
        raise _error("complete provenance-closed coverage family is required")
    expected_hypotheses = set(policy.experiment.hypothesis_ids)
    expected_execution = {
        item.randomization.population.hypothesis.hypothesis_id: item.execution_policy_freeze_manifest_id
        for item in policy.experiment.execution_policy_freezes
    }
    by_hypothesis: dict[str, ProvenanceClosedAssignmentCoverageManifestV2] = {}
    try:
        for index, item in enumerate(coverages):
            if (
                index >= len(expected_hypotheses)
                or type(item) is not ProvenanceClosedAssignmentCoverageManifestV2
                or not model_shape_is_intact(item)
            ):
                raise _error("complete provenance-closed coverage family is required")
            checked = ProvenanceClosedAssignmentCoverageManifestV2.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            hypothesis_id = (
                checked.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id
            )
            if (
                hypothesis_id in by_hypothesis
                or expected_execution.get(hypothesis_id)
                != checked.execution_policy_freeze.execution_policy_freeze_manifest_id
            ):
                raise _error("complete provenance-closed coverage family is required")
            by_hypothesis[hypothesis_id] = checked
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error("complete provenance-closed coverage family is required") from None
    _validate_complete_coverage_keys(frozenset(expected_hypotheses), frozenset(by_hypothesis))
    return tuple(by_hypothesis[item] for item in policy.experiment.hypothesis_ids)


def _derive_artifacts(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...],
) -> tuple[ConfirmatoryContributionArtifactV2, ...]:
    root_by_hypothesis = {
        item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
        for item in policy.experiment.protocol_roots
    }
    coverage_by_hypothesis = {
        item.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id: item
        for item in coverages
    }
    return tuple(
        derive_frozen_formal_family_contributions_v2(
            root_by_hypothesis[support.test_coordinate.hypothesis_id].population,
            coverage_by_hypothesis[support.test_coordinate.hypothesis_id],
            support.test_coordinate,
        )
        for support in policy.primary_inference_plan.coordinate_supports
    )


def _validated_realization_values(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
) -> dict[tuple[str, str, str, str, str], Fraction]:
    ordered, pooled_values = _validated_artifacts(policy.primary_inference_plan, artifacts)
    artifact_by_coordinate = {item.test_coordinate_id: item for item in ordered}
    specification_by_hm = {
        (item.hypothesis_id, item.model_id): item for item in policy.hypothesis_model_specifications
    }
    values: dict[tuple[str, str, str, str, str], Fraction] = {}
    for support in policy.primary_inference_plan.coordinate_supports:
        coordinate = support.test_coordinate
        specification = specification_by_hm[(coordinate.hypothesis_id, coordinate.model_id)]
        artifact = artifact_by_coordinate[coordinate.test_coordinate_id]
        expected_cluster_keys = {
            (stratum.stratum_id, cluster_id)
            for stratum in support.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        }
        expected_keys = {
            (realization_id, *cluster_key)
            for realization_id in specification.realization_spec_ids
            for cluster_key in expected_cluster_keys
        }
        exact: dict[tuple[str, str, str], Fraction] = {}
        for row in artifact.exact_realization_contributions:
            if (
                type(row) is not ExactRealizationClusterContributionV2
                or row.hypothesis_id != specification.hypothesis_id
                or row.model_id != specification.model_id
                or type(row.numerator) is not int
                or type(row.denominator) is not int
                or row.denominator <= 0
            ):
                raise _error("exact realization contribution provenance failed validation")
            key = (
                row.realization_spec_id,
                row.stratum_id,
                row.semantic_task_cluster_id,
            )
            fraction = Fraction(row.numerator, row.denominator)
            if (
                key in exact
                or fraction.numerator != row.numerator
                or fraction.denominator != row.denominator
                or not Fraction(-1, 1) <= fraction <= Fraction(1, 1)
            ):
                raise _error("exact realization contribution provenance failed validation")
            exact[key] = fraction
        if set(exact) != expected_keys:
            raise _error("complete exact realization contribution family is required")

        projected: dict[tuple[str, str, str], RealizationClusterContributionV2] = {}
        for row in artifact.realization_contributions:
            if (
                type(row) is not RealizationClusterContributionV2
                or row.hypothesis_id != specification.hypothesis_id
                or row.model_id != specification.model_id
                or type(row.estimate) is not float
                or not math.isfinite(row.estimate)
            ):
                raise _error("realization contribution projection failed validation")
            key = (
                row.realization_spec_id,
                row.stratum_id,
                row.semantic_task_cluster_id,
            )
            if key in projected:
                raise _error("realization contribution projection failed validation")
            projected[key] = row
        if set(projected) != expected_keys:
            raise _error("complete realization contribution projection is required")
        if any(projected[key].estimate != float(value) for key, value in exact.items()):
            raise _error("realization contribution projection failed validation")

        weights = {
            realization_id: Fraction(numerator, specification.probability_denominator)
            for realization_id, numerator in zip(
                specification.realization_spec_ids,
                specification.probability_numerators,
                strict=True,
            )
        }
        for stratum_id, cluster_id in expected_cluster_keys:
            reconstructed = sum(
                (
                    weights[realization_id] * exact[(realization_id, stratum_id, cluster_id)]
                    for realization_id in specification.realization_spec_ids
                ),
                Fraction(0, 1),
            )
            if (
                reconstructed
                != pooled_values[(coordinate.test_coordinate_id, stratum_id, cluster_id)]
            ):
                raise _error("Q_h aggregate and realization contributions disagree")
        for (realization_id, stratum_id, cluster_id), value in exact.items():
            values[
                (
                    specification.hypothesis_id,
                    specification.model_id,
                    realization_id,
                    stratum_id,
                    cluster_id,
                )
            ] = value
    return values


def _coordinate_key(
    coordinate_kind: SimultaneousCoordinateKindV2,
    realization_id: str,
) -> str:
    prefix = {
        SimultaneousCoordinateKindV2.REALIZATION_EFFECT: "realization",
        SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT: "loo",
        SimultaneousCoordinateKindV2.REALIZATION_DEVIATION: "deviation",
    }[coordinate_kind]
    return f"{prefix}.{realization_id}"


def _derived_coordinate_values(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    realization_values: Mapping[tuple[str, str, str, str, str], Fraction],
) -> dict[tuple[str, str, str], Fraction]:
    specification_by_hm = {
        (item.hypothesis_id, item.model_id): item for item in policy.hypothesis_model_specifications
    }
    output: dict[tuple[str, str, str], Fraction] = {}
    for support in policy.coordinate_supports:
        coordinate = support.test_coordinate
        specification = specification_by_hm[(coordinate.hypothesis_id, coordinate.model_id)]
        realization_id = coordinate.analysis_component_id.split(".", maxsplit=1)[1]
        weights = {
            item: Fraction(numerator, specification.probability_denominator)
            for item, numerator in zip(
                specification.realization_spec_ids,
                specification.probability_numerators,
                strict=True,
            )
        }
        for stratum in support.strata:
            for cluster_id in stratum.semantic_task_cluster_ids:
                per_realization = {
                    item: realization_values[
                        (
                            specification.hypothesis_id,
                            specification.model_id,
                            item,
                            stratum.stratum_id,
                            cluster_id,
                        )
                    ]
                    for item in specification.realization_spec_ids
                }
                pooled = sum(
                    (
                        weights[item] * per_realization[item]
                        for item in specification.realization_spec_ids
                    ),
                    Fraction(0, 1),
                )
                if coordinate.coordinate_kind is SimultaneousCoordinateKindV2.REALIZATION_EFFECT:
                    value = per_realization[realization_id]
                elif (
                    coordinate.coordinate_kind
                    is SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT
                ):
                    value = sum(
                        (
                            weights[item] * per_realization[item]
                            for item in specification.realization_spec_ids
                            if item != realization_id
                        ),
                        Fraction(0, 1),
                    ) / (Fraction(1, 1) - weights[realization_id])
                elif (
                    coordinate.coordinate_kind is SimultaneousCoordinateKindV2.REALIZATION_DEVIATION
                ):
                    value = per_realization[realization_id] - pooled
                else:
                    raise _error("unexpected robustness coordinate kind")
                output[
                    (
                        coordinate.test_coordinate_id,
                        stratum.stratum_id,
                        cluster_id,
                    )
                ] = value
    return output


def _observed_statistics(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    values: Mapping[tuple[str, str, str], Fraction],
) -> dict[str, tuple[Fraction, float]]:
    result: dict[str, tuple[Fraction, float]] = {}
    for support in policy.coordinate_supports:
        samples = {item.stratum_id: item.semantic_task_cluster_ids for item in support.strata}
        estimate, standard_error, _counts = _coordinate_statistics(
            support,
            values,
            samples,
            filter_union_sample=False,
        )
        result[support.test_coordinate.test_coordinate_id] = (estimate, standard_error)
    return result


def _inference_payload(
    result: MultiSupportRobustnessInferenceResultV2,
) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("robustness_inference_result_id")
    return payload


def _run_robustness_inference(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
    values: Mapping[tuple[str, str, str], Fraction],
    *,
    bootstrap_samples: int | None = None,
    minimum_valid_bootstrap_draws: int | None = None,
    inference_scope: str = "formal_frozen_policy_v1",
) -> MultiSupportRobustnessInferenceResultV2:
    samples_to_run = policy.bootstrap_samples if bootstrap_samples is None else bootstrap_samples
    minimum_valid = (
        policy.minimum_valid_bootstrap_draws
        if minimum_valid_bootstrap_draws is None
        else minimum_valid_bootstrap_draws
    )
    if (
        type(samples_to_run) is not int
        or type(minimum_valid) is not int
        or samples_to_run < 1
        or not 1 <= minimum_valid <= samples_to_run
        or type(inference_scope) is not str
        or not inference_scope
    ):
        raise _error("robustness inference execution scope failed validation")
    observed = _observed_statistics(policy, values)
    seed = hashlib.sha256(
        _SEED_DOMAIN
        + bytes.fromhex(policy.analysis_seed_domain_sha256)
        + b"\x00"
        + policy.robustness_policy_freeze_id.encode()
        + b"\x00"
        + inference_scope.encode()
    ).digest()
    rng = DeterministicRNG(seed)
    draws: list[GlobalUnionMaxTDrawV2] = []
    invalid_draws: list[InvalidGlobalUnionDrawV2] = []
    maxima: list[float] = []
    for replicate in range(samples_to_run):
        samples = {
            stratum.stratum_id: tuple(
                rng.choice(stratum.semantic_task_cluster_ids)
                for _ in stratum.semantic_task_cluster_ids
            )
            for stratum in policy.global_union_strata
        }
        sample_sha256 = _sample_digest(samples)
        stratum_draws = tuple(
            UnionStratumDrawDigestV2(
                stratum_id=stratum.stratum_id,
                occurrence_count=len(samples[stratum.stratum_id]),
                sampled_clusters_sha256=_digest(samples[stratum.stratum_id]),
            )
            for stratum in policy.global_union_strata
        )
        bootstrap: dict[str, tuple[Fraction, float]] = {}
        counts: list[CoordinateStratumRetainedCountV2] = []
        try:
            for support in policy.coordinate_supports:
                estimate, standard_error, retained = _coordinate_statistics(
                    support,
                    values,
                    samples,
                    filter_union_sample=True,
                )
                coordinate_id = support.test_coordinate.test_coordinate_id
                bootstrap[coordinate_id] = (estimate, standard_error)
                counts.extend(retained)
        except _InvalidBootstrapDraw as invalid:
            invalid_draws.append(
                InvalidGlobalUnionDrawV2(
                    replicate_index=replicate,
                    global_sample_sha256=sample_sha256,
                    stratum_draws=stratum_draws,
                    reason_code=invalid.reason_code,
                    test_coordinate_id=invalid.test_coordinate_id,
                    stratum_id=invalid.stratum_id,
                )
            )
            continue
        max_abs_t = max(
            abs(float(bootstrap_estimate - observed[coordinate_id][0]) / bootstrap_standard_error)
            for coordinate_id, (bootstrap_estimate, bootstrap_standard_error) in bootstrap.items()
        )
        if not math.isfinite(max_abs_t):
            raise _error("bootstrap global max-|T| statistic failed validation")
        maxima.append(max_abs_t)
        draws.append(
            GlobalUnionMaxTDrawV2(
                replicate_index=replicate,
                global_sample_sha256=sample_sha256,
                stratum_draws=stratum_draws,
                coordinate_retained_counts=tuple(
                    sorted(
                        counts,
                        key=lambda item: (item.test_coordinate_id, item.stratum_id),
                    )
                ),
                max_abs_t=max_abs_t,
            )
        )
    if len(draws) < minimum_valid:
        raise _error("global bootstrap valid-draw count is below the frozen minimum")
    critical = _higher_quantile(
        tuple(maxima),
        alpha_numerator=policy.alpha_numerator,
        alpha_denominator=policy.alpha_denominator,
    )
    intervals = tuple(
        MultiSupportSimultaneousIntervalV2(
            test_coordinate_id=coordinate.test_coordinate_id,
            estimate_numerator=observed[coordinate.test_coordinate_id][0].numerator,
            estimate_denominator=observed[coordinate.test_coordinate_id][0].denominator,
            estimate=float(observed[coordinate.test_coordinate_id][0]),
            standard_error=observed[coordinate.test_coordinate_id][1],
            simultaneous_lower=(
                float(observed[coordinate.test_coordinate_id][0])
                - critical * observed[coordinate.test_coordinate_id][1]
            ),
            simultaneous_upper=(
                float(observed[coordinate.test_coordinate_id][0])
                + critical * observed[coordinate.test_coordinate_id][1]
            ),
        )
        for coordinate in policy.robustness_family.coordinates
    )
    provisional = MultiSupportRobustnessInferenceResultV2(
        robustness_inference_result_id="",
        robustness_policy_freeze_id=policy.robustness_policy_freeze_id,
        confirmatory_experiment_freeze_id=policy.confirmatory_experiment_freeze_id,
        family_id=policy.robustness_family.family_id,
        global_multiplicity_family_policy_sha256=(policy.global_multiplicity_family_policy_sha256),
        bootstrap_seed_sha256=hashlib.sha256(seed).hexdigest(),
        input_contribution_artifact_ids=tuple(item.contribution_artifact_id for item in artifacts),
        input_contributions_sha256=_artifact_input_digest(artifacts),
        inference_scope=inference_scope,
        bootstrap_samples=samples_to_run,
        minimum_valid_bootstrap_draws=minimum_valid,
        critical_value=critical,
        valid_draw_count=len(draws),
        invalid_draw_count=len(invalid_draws),
        intervals=intervals,
        draws=tuple(draws),
        invalid_draws=tuple(invalid_draws),
    )
    return MultiSupportRobustnessInferenceResultV2(
        robustness_inference_result_id=(
            _INFERENCE_RESULT_PREFIX + _digest(_inference_payload(provisional))
        ),
        robustness_policy_freeze_id=provisional.robustness_policy_freeze_id,
        confirmatory_experiment_freeze_id=(provisional.confirmatory_experiment_freeze_id),
        family_id=provisional.family_id,
        global_multiplicity_family_policy_sha256=(
            provisional.global_multiplicity_family_policy_sha256
        ),
        bootstrap_seed_sha256=provisional.bootstrap_seed_sha256,
        input_contribution_artifact_ids=provisional.input_contribution_artifact_ids,
        input_contributions_sha256=provisional.input_contributions_sha256,
        inference_scope=provisional.inference_scope,
        bootstrap_samples=provisional.bootstrap_samples,
        minimum_valid_bootstrap_draws=(provisional.minimum_valid_bootstrap_draws),
        critical_value=provisional.critical_value,
        valid_draw_count=provisional.valid_draw_count,
        invalid_draw_count=provisional.invalid_draw_count,
        intervals=provisional.intervals,
        draws=provisional.draws,
        invalid_draws=provisional.invalid_draws,
    )


def _validated_interaction_references(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...],
    references: Iterable[MultiSupportArmRealizationInteractionReferenceV2],
) -> tuple[
    dict[tuple[str, str], MultiSupportArmRealizationInteractionReferenceV2],
    bool,
]:
    if isinstance(references, (str, bytes, Mapping)):
        raise _error("interaction reference family failed validation")
    specifications = {
        (item.hypothesis_id, item.model_id): item for item in policy.hypothesis_model_specifications
    }
    hm_coordinates = {
        (item.hypothesis_id, item.model_id): item
        for item in policy.experiment.hypothesis_model_coordinates
    }
    coverage_by_hypothesis = {
        item.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id: item
        for item in coverages
    }
    result: dict[tuple[str, str], MultiSupportArmRealizationInteractionReferenceV2] = {}
    try:
        for index, item in enumerate(references):
            if (
                index >= len(specifications)
                or type(item) is not MultiSupportArmRealizationInteractionReferenceV2
            ):
                raise _error("interaction reference family failed validation")
            checked = MultiSupportArmRealizationInteractionReferenceV2.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            key = (checked.hypothesis_id, checked.model_id)
            specification = specifications.get(key)
            hm = hm_coordinates.get(key)
            coverage = coverage_by_hypothesis.get(checked.hypothesis_id)
            if key in result or specification is None or hm is None or coverage is None:
                raise _error("interaction reference provenance failed validation")
            _validate_interaction_reference_binding(
                checked,
                robustness_policy_freeze_id=policy.robustness_policy_freeze_id,
                robustness_hypothesis_spec_id=(specification.robustness_hypothesis_spec_id),
                global_robustness_family_id=policy.robustness_family.family_id,
                confirmatory_experiment_freeze_id=(policy.confirmatory_experiment_freeze_id),
                population_freeze_manifest_id=hm.population_freeze_manifest_id,
                randomization_manifest_id=hm.randomization_manifest_id,
                provenance_closed_coverage_manifest_id=(
                    coverage.provenance_closed_coverage_manifest_id
                ),
                interaction_minimum_reference_draws=(policy.interaction_minimum_reference_draws),
            )
            result[key] = checked
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error("interaction reference family failed validation") from None
    if result and len({item.joint_reference_run_sha256 for item in result.values()}) != 1:
        raise _error("interaction references do not share one joint reference run")
    return result, set(result) == set(specifications)


def _validate_interaction_reference_binding(
    reference: MultiSupportArmRealizationInteractionReferenceV2,
    *,
    robustness_policy_freeze_id: str,
    robustness_hypothesis_spec_id: str,
    global_robustness_family_id: str,
    confirmatory_experiment_freeze_id: str,
    population_freeze_manifest_id: str,
    randomization_manifest_id: str,
    provenance_closed_coverage_manifest_id: str,
    interaction_minimum_reference_draws: int,
) -> None:
    """Validate exact interaction provenance without replaying the experiment root."""

    if (
        reference.robustness_policy_freeze_id != robustness_policy_freeze_id
        or reference.robustness_hypothesis_spec_id != robustness_hypothesis_spec_id
        or reference.global_robustness_family_id != global_robustness_family_id
        or reference.confirmatory_experiment_freeze_id != confirmatory_experiment_freeze_id
        or reference.population_freeze_manifest_id != population_freeze_manifest_id
        or reference.randomization_manifest_id != randomization_manifest_id
        or reference.provenance_closed_coverage_manifest_id
        != provenance_closed_coverage_manifest_id
        or len(reference.reference_statistics) != interaction_minimum_reference_draws
    ):
        raise _error("interaction reference provenance failed validation")


def _expected_point(direction: RobustnessExpectedDirectionV2, value: float) -> bool:
    return value > 0.0 if direction is RobustnessExpectedDirectionV2.POSITIVE else value < 0.0


def _expected_interval(
    direction: RobustnessExpectedDirectionV2,
    interval: MultiSupportSimultaneousIntervalV2,
) -> bool:
    return (
        interval.simultaneous_lower > 0.0
        if direction is RobustnessExpectedDirectionV2.POSITIVE
        else interval.simultaneous_upper < 0.0
    )


def _fully_reverse_interval(
    direction: RobustnessExpectedDirectionV2,
    interval: MultiSupportSimultaneousIntervalV2,
) -> bool:
    return (
        interval.simultaneous_upper < 0.0
        if direction is RobustnessExpectedDirectionV2.POSITIVE
        else interval.simultaneous_lower > 0.0
    )


def _strong_label_conditions_met(
    *,
    base_confirmed: bool,
    all_realization_points: bool,
    direction_threshold_met: bool,
    no_reverse_realization_interval: bool,
    all_leave_one_out_supported: bool,
    heterogeneity_equivalent: bool,
    minimum_support_met: bool,
    interaction_condition_met: bool,
) -> bool:
    """One explicit conjunction; no failed condition can be averaged away."""

    return all(
        (
            base_confirmed,
            all_realization_points,
            direction_threshold_met,
            no_reverse_realization_interval,
            all_leave_one_out_supported,
            heterogeneity_equivalent,
            minimum_support_met,
            interaction_condition_met,
        )
    )


def _realization_label(
    *,
    base_confirmed: bool,
    base_reverse: bool,
    all_frozen_conditions_met: bool,
) -> RealizationRobustnessLabelV2:
    return (
        RealizationRobustnessLabelV2.REALIZATION_ROBUST
        if all_frozen_conditions_met
        else RealizationRobustnessLabelV2.AVERAGE_POLICY_CONFIRMED
        if base_confirmed
        else RealizationRobustnessLabelV2.CONFLICTING
        if base_reverse
        else RealizationRobustnessLabelV2.UNCONFIRMED
    )


def _validate_interaction_observed_statistic(
    reference: MultiSupportArmRealizationInteractionReferenceV2,
    observed_statistic: float,
) -> None:
    if not math.isclose(
        reference.observed_statistic,
        observed_statistic,
        rel_tol=1e-12,
        abs_tol=1e-12,
    ):
        raise _error("interaction observed statistic failed exact validation")


def _interval_lookup(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    inference: MultiSupportRobustnessInferenceResultV2,
) -> dict[tuple[str, str, SimultaneousCoordinateKindV2, str], MultiSupportSimultaneousIntervalV2]:
    by_id = {item.test_coordinate_id: item for item in inference.intervals}
    return {
        (
            coordinate.hypothesis_id,
            coordinate.model_id,
            coordinate.coordinate_kind,
            coordinate.analysis_component_id,
        ): by_id[coordinate.test_coordinate_id]
        for coordinate in policy.robustness_family.coordinates
    }


def _primary_interval_lookup(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    primary: MultiSupportSimultaneousInferenceResultV2,
) -> dict[tuple[str, str], MultiSupportSimultaneousIntervalV2]:
    by_id = {item.test_coordinate_id: item for item in primary.intervals}
    return {
        (support.test_coordinate.hypothesis_id, support.test_coordinate.model_id): by_id[
            support.test_coordinate.test_coordinate_id
        ]
        for support in policy.primary_inference_plan.coordinate_supports
    }


def _model_results(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    primary: MultiSupportSimultaneousInferenceResultV2,
    robustness: MultiSupportRobustnessInferenceResultV2,
    references: Mapping[tuple[str, str], MultiSupportArmRealizationInteractionReferenceV2],
    global_interaction_family_complete: bool,
) -> tuple[MultiSupportModelRobustnessResultV2, ...]:
    primary_intervals = _primary_interval_lookup(policy, primary)
    intervals = _interval_lookup(policy, robustness)
    global_reference = (
        tuple(
            max(item.reference_statistics[index] for item in references.values())
            for index in range(policy.interaction_minimum_reference_draws)
        )
        if global_interaction_family_complete
        else None
    )
    support_count = {
        (
            item.test_coordinate.hypothesis_id,
            item.test_coordinate.model_id,
        ): item.coordinate_cluster_count
        for item in policy.primary_inference_plan.coordinate_supports
    }
    outputs = []
    for specification in policy.hypothesis_model_specifications:
        key = (specification.hypothesis_id, specification.model_id)
        realization_intervals = tuple(
            (
                realization_id,
                intervals[
                    (
                        *key,
                        SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                        _coordinate_key(
                            SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
                            realization_id,
                        ),
                    )
                ],
            )
            for realization_id in specification.realization_spec_ids
        )
        loo_intervals = tuple(
            (
                realization_id,
                intervals[
                    (
                        *key,
                        SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                        _coordinate_key(
                            SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
                            realization_id,
                        ),
                    )
                ],
            )
            for realization_id in specification.realization_spec_ids
        )
        deviation_intervals = tuple(
            (
                realization_id,
                intervals[
                    (
                        *key,
                        SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                        _coordinate_key(
                            SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
                            realization_id,
                        ),
                    )
                ],
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
        minimum_support_met = (
            support_count[key] >= specification.minimum_independent_clusters_per_realization
        )
        primary_interval = primary_intervals[key]
        base_confirmed = _expected_interval(
            specification.expected_direction,
            primary_interval,
        )
        base_reverse = _fully_reverse_interval(
            specification.expected_direction,
            primary_interval,
        )
        interaction_observed = max(
            abs(item.estimate) for _realization_id, item in deviation_intervals
        )
        reference = references.get(key)
        interaction_reported = reference is not None
        interaction_condition_met = interaction_reported and global_interaction_family_complete
        interaction_p: float | None = None
        interaction_global_p: float | None = None
        if reference is not None:
            _validate_interaction_observed_statistic(reference, interaction_observed)
            interaction_p = (
                1
                + sum(
                    item >= reference.observed_statistic for item in reference.reference_statistics
                )
            ) / (len(reference.reference_statistics) + 1)
            if global_reference is not None:
                interaction_global_p = (
                    1 + sum(item >= reference.observed_statistic for item in global_reference)
                ) / (len(global_reference) + 1)
        all_conditions = _strong_label_conditions_met(
            base_confirmed=base_confirmed,
            all_realization_points=all_points,
            direction_threshold_met=direction_threshold,
            no_reverse_realization_interval=no_reverse,
            all_leave_one_out_supported=all_loo,
            heterogeneity_equivalent=heterogeneity_equivalent,
            minimum_support_met=minimum_support_met,
            interaction_condition_met=interaction_condition_met,
        )
        label = _realization_label(
            base_confirmed=base_confirmed,
            base_reverse=base_reverse,
            all_frozen_conditions_met=all_conditions,
        )
        outputs.append(
            MultiSupportModelRobustnessResultV2(
                hypothesis_id=specification.hypothesis_id,
                model_id=specification.model_id,
                label=label,
                base_policy_effect_confirmed=base_confirmed,
                base_policy_effect_fully_reverse=base_reverse,
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
                minimum_independent_clusters_per_realization=(
                    specification.minimum_independent_clusters_per_realization
                ),
                minimum_support_met=minimum_support_met,
                interaction_observed_statistic=interaction_observed,
                interaction_randomization_p_value=interaction_p,
                interaction_global_adjusted_p_value=interaction_global_p,
                interaction_reference_reported=interaction_reported,
                global_interaction_family_complete=(global_interaction_family_complete),
                interaction_condition_met=interaction_condition_met,
                all_frozen_conditions_met=all_conditions,
                primary_interval=primary_interval,
                realization_intervals=realization_intervals,
                leave_one_out_intervals=loo_intervals,
                deviation_intervals=deviation_intervals,
            )
        )
    return tuple(outputs)


def _cross_model_label(
    policy: CrossModelReplicationPolicyV2,
    results: tuple[MultiSupportModelRobustnessResultV2, ...],
) -> CrossModelReplicationLabelV2:
    return _cross_model_label_from_statuses(
        policy,
        confirmed_model_count=sum(item.base_policy_effect_confirmed for item in results),
        any_reverse_model=any(item.base_policy_effect_fully_reverse for item in results),
    )


def _cross_model_label_from_statuses(
    policy: CrossModelReplicationPolicyV2,
    *,
    confirmed_model_count: int,
    any_reverse_model: bool,
) -> CrossModelReplicationLabelV2:
    if len(policy.model_ids) < policy.minimum_model_count_for_replication:
        return CrossModelReplicationLabelV2.NOT_APPLICABLE
    return (
        CrossModelReplicationLabelV2.REPLICATED
        if confirmed_model_count == policy.required_confirmed_model_count and not any_reverse_model
        else CrossModelReplicationLabelV2.NOT_REPLICATED
    )


def _cross_model_results(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    model_results: tuple[MultiSupportModelRobustnessResultV2, ...],
) -> tuple[CrossModelReplicationResultV2, ...]:
    by_hypothesis: dict[str, list[MultiSupportModelRobustnessResultV2]] = {}
    for item in model_results:
        by_hypothesis.setdefault(item.hypothesis_id, []).append(item)
    output = []
    for hypothesis_id in policy.experiment.hypothesis_ids:
        items = tuple(sorted(by_hypothesis[hypothesis_id], key=lambda item: item.model_id))
        if tuple(item.model_id for item in items) != policy.cross_model_policy.model_ids:
            raise _error("cross-model result family is incomplete")
        confirmed = tuple(item.model_id for item in items if item.base_policy_effect_confirmed)
        reverse = tuple(item.model_id for item in items if item.base_policy_effect_fully_reverse)
        unconfirmed = tuple(
            item.model_id for item in items if not item.base_policy_effect_confirmed
        )
        output.append(
            CrossModelReplicationResultV2(
                hypothesis_id=hypothesis_id,
                label=_cross_model_label(policy.cross_model_policy, items),
                model_ids=policy.cross_model_policy.model_ids,
                confirmed_model_ids=confirmed,
                unconfirmed_model_ids=unconfirmed,
                reverse_model_ids=reverse,
                required_confirmed_model_count=(
                    policy.cross_model_policy.required_confirmed_model_count
                ),
                confirmed_model_count=len(confirmed),
                model_effects_pooled=False,
                any_unconfirmed_or_reverse_model_disqualifies=(
                    policy.cross_model_policy.any_unconfirmed_or_reverse_model_disqualifies
                ),
            )
        )
    return tuple(output)


def _result_payload(result: MultiSupportRobustnessAnalysisResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("analysis_result_id")
    return payload


def _run(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: Iterable[ProvenanceClosedAssignmentCoverageManifestV2],
    interaction_references: Iterable[MultiSupportArmRealizationInteractionReferenceV2],
) -> MultiSupportRobustnessAnalysisResultV2:
    checked_policy = _validated_policy(policy)
    checked_coverages = _validated_coverages(checked_policy, coverages)
    references, reference_family_complete = _validated_interaction_references(
        checked_policy,
        checked_coverages,
        interaction_references,
    )
    artifacts = _derive_artifacts(checked_policy, checked_coverages)
    realization_values = _validated_realization_values(checked_policy, artifacts)
    derived_values = _derived_coordinate_values(checked_policy, realization_values)
    primary = run_frozen_domain_multi_support_simultaneous_inference_v2(
        checked_policy.primary_inference_plan,
        artifacts,
    )
    robustness = _run_robustness_inference(
        checked_policy,
        artifacts,
        derived_values,
    )
    model_results = _model_results(
        checked_policy,
        primary,
        robustness,
        references,
        reference_family_complete,
    )
    cross_model = _cross_model_results(checked_policy, model_results)
    provisional = MultiSupportRobustnessAnalysisResultV2(
        analysis_result_id="",
        robustness_policy_freeze_id=checked_policy.robustness_policy_freeze_id,
        confirmatory_experiment_freeze_id=(checked_policy.confirmatory_experiment_freeze_id),
        primary_inference_result=primary,
        robustness_inference_result=robustness,
        input_provenance_closed_coverage_manifest_ids=tuple(
            item.provenance_closed_coverage_manifest_id for item in checked_coverages
        ),
        input_contribution_artifact_ids=tuple(item.contribution_artifact_id for item in artifacts),
        interaction_reference_ids=tuple(
            item.interaction_reference_id
            for item in sorted(references.values(), key=lambda item: item.interaction_reference_id)
        ),
        global_interaction_family_complete=reference_family_complete,
        formal_analysis_glue_binding_required=(
            checked_policy.formal_analysis_glue_binding_required
        ),
        formal_analysis_glue_binding_status=(checked_policy.formal_analysis_glue_binding_status),
        model_robustness_results=model_results,
        cross_model_replication_results=cross_model,
    )
    return MultiSupportRobustnessAnalysisResultV2(
        analysis_result_id=_RESULT_PREFIX + _digest(_result_payload(provisional)),
        robustness_policy_freeze_id=provisional.robustness_policy_freeze_id,
        confirmatory_experiment_freeze_id=(provisional.confirmatory_experiment_freeze_id),
        primary_inference_result=provisional.primary_inference_result,
        robustness_inference_result=provisional.robustness_inference_result,
        input_provenance_closed_coverage_manifest_ids=(
            provisional.input_provenance_closed_coverage_manifest_ids
        ),
        input_contribution_artifact_ids=provisional.input_contribution_artifact_ids,
        interaction_reference_ids=provisional.interaction_reference_ids,
        global_interaction_family_complete=(provisional.global_interaction_family_complete),
        formal_analysis_glue_binding_required=(provisional.formal_analysis_glue_binding_required),
        formal_analysis_glue_binding_status=(provisional.formal_analysis_glue_binding_status),
        model_robustness_results=provisional.model_robustness_results,
        cross_model_replication_results=(provisional.cross_model_replication_results),
    )


def run_multi_support_robustness_v2(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: Iterable[ProvenanceClosedAssignmentCoverageManifestV2],
    interaction_references: Iterable[MultiSupportArmRealizationInteractionReferenceV2] = (),
) -> MultiSupportRobustnessAnalysisResultV2:
    """Run the frozen family; absent interaction references cannot earn the strong label."""

    return _run(policy, coverages, interaction_references)


def run_synthetic_multi_support_robustness_smoke_v2(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: Iterable[ProvenanceClosedAssignmentCoverageManifestV2],
) -> SyntheticMultiSupportRobustnessSmokeResultV2:
    """Exercise the real provenance and resampling path with no evidence claim.

    The formal policy remains frozen at 999 draws and a 950-valid-draw gate.
    This explicitly separate 19-draw path is only a Phase-0 engineering proof;
    it does not evaluate primary intervals, interaction references, robustness
    labels, or cross-model replication.
    """

    checked_policy = _validated_policy(policy)
    checked_coverages = _validated_coverages(checked_policy, coverages)
    artifacts = _derive_artifacts(checked_policy, checked_coverages)
    realization_values = _validated_realization_values(checked_policy, artifacts)
    derived_values = _derived_coordinate_values(checked_policy, realization_values)
    inference = _run_robustness_inference(
        checked_policy,
        artifacts,
        derived_values,
        bootstrap_samples=19,
        minimum_valid_bootstrap_draws=1,
        inference_scope="synthetic_non_claim_smoke_b19_v1",
    )
    coverage_ids = tuple(item.provenance_closed_coverage_manifest_id for item in checked_coverages)
    artifact_ids = tuple(item.contribution_artifact_id for item in artifacts)
    payload = {
        "robustness_policy_freeze_id": checked_policy.robustness_policy_freeze_id,
        "confirmatory_experiment_freeze_id": (checked_policy.confirmatory_experiment_freeze_id),
        "coverage_ids": coverage_ids,
        "artifact_ids": artifact_ids,
        "inference_result_id": inference.robustness_inference_result_id,
        "synthetic_bootstrap_samples": 19,
        "formal_policy_bootstrap_samples": checked_policy.bootstrap_samples,
        "purpose": "synthetic_non_claim_pipeline_smoke_only_v1",
        "formal_robustness_label_awarded": False,
        "cross_model_replication_label_awarded": False,
    }
    return SyntheticMultiSupportRobustnessSmokeResultV2(
        smoke_result_id="synthetic_multi_support_robustness_smoke_v2_" + _digest(payload),
        robustness_policy_freeze_id=checked_policy.robustness_policy_freeze_id,
        confirmatory_experiment_freeze_id=(checked_policy.confirmatory_experiment_freeze_id),
        input_provenance_closed_coverage_manifest_ids=coverage_ids,
        input_contribution_artifact_ids=artifact_ids,
        inference_result=inference,
        synthetic_bootstrap_samples=19,
        formal_policy_bootstrap_samples=checked_policy.bootstrap_samples,
        purpose="synthetic_non_claim_pipeline_smoke_only_v1",
        formal_robustness_label_awarded=False,
        cross_model_replication_label_awarded=False,
    )


def validate_multi_support_robustness_result_v2(
    policy: MultiSupportRobustnessPolicyFreezeV2,
    coverages: Iterable[ProvenanceClosedAssignmentCoverageManifestV2],
    interaction_references: Iterable[MultiSupportArmRealizationInteractionReferenceV2],
    result: MultiSupportRobustnessAnalysisResultV2,
) -> MultiSupportRobustnessAnalysisResultV2:
    """Replay every primary/robustness draw and require exact artifact equality."""

    if type(result) is not MultiSupportRobustnessAnalysisResultV2:
        raise _error("robustness result artifact failed validation")
    expected = _run(policy, coverages, interaction_references)
    if result != expected:
        raise _error("robustness result artifact failed validation")
    return result


__all__ = [
    "CrossModelReplicationLabelV2",
    "CrossModelReplicationResultV2",
    "MultiSupportModelRobustnessResultV2",
    "MultiSupportRobustnessAnalysisResultV2",
    "MultiSupportRobustnessInferenceResultV2",
    "SyntheticMultiSupportRobustnessSmokeResultV2",
    "run_multi_support_robustness_v2",
    "run_synthetic_multi_support_robustness_smoke_v2",
    "validate_multi_support_robustness_result_v2",
]

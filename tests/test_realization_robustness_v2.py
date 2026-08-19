from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import replace

import pytest
from pydantic import ValidationError

from secaware.analysis.realization_robustness_v2 import (
    ArmRealizationInteractionReferenceV2,
    RealizationClusterContributionV2,
    RealizationRobustnessLabelV2,
    build_realization_robustness_plan_v2,
    run_realization_robustness_v2,
)
from secaware.analysis.simultaneous_v2 import (
    CoordinateClusterContributionV2,
    SimultaneousInferenceResultV2,
    _build_result,
    run_simultaneous_inference_v2,
)
from secaware.schema.experiments import ArmRole
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

SEED = b"phase-zero-realization-robustness-example"
PRIMARY_SEED = b"phase-zero-primary-policy-example"
CLUSTERS = tuple(f"cluster.{index:02d}" for index in range(12))
REALIZATIONS = (
    f"realization_spec_{hashlib.sha256(b'realization-a').hexdigest()}",
    f"realization_spec_{hashlib.sha256(b'realization-b').hexdigest()}",
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _hypothesis(
    label: str,
    *,
    margin_numerator: int = 1,
    margin_denominator: int = 5,
) -> RealizationRobustnessHypothesisSpecV2:
    return RealizationRobustnessHypothesisSpecV2.from_content(
        hypothesis_id=f"hypothesis_{_sha(f'h:{label}')}",
        target_spec_id=f"target_{_sha(f't:{label}')}",
        arm_protocol_id=f"arm_protocol_{_sha(f'p:{label}')}",
        model_id=f"model.{label}",
        outcome_name="y_secure_yield",
        treatment_arm=ArmRole.TARGET_PATCH,
        control_arm=ArmRole.NOOP_REWRITE,
        expected_direction=RobustnessExpectedDirectionV2.POSITIVE,
        realization_spec_ids=REALIZATIONS,
        probability_numerators=(1, 1),
        probability_denominator=2,
        practical_equivalence_margin_numerator=margin_numerator,
        practical_equivalence_margin_denominator=margin_denominator,
        minimum_direction_consistent_realizations=2,
        minimum_independent_clusters_per_realization=10,
    )


def _strata() -> tuple[CommonStratumSupportV2, ...]:
    return (
        CommonStratumSupportV2(
            stratum_id="cwe78.shell",
            semantic_task_cluster_ids=CLUSTERS,
            weight_numerator=1,
        ),
    )


def _primary_plan(
    hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...],
) -> SimultaneousInferencePlanV2:
    coordinates = tuple(
        sorted(
            (
                SimultaneousTestCoordinateV2.from_content(
                    hypothesis_id=item.hypothesis_id,
                    target_spec_id=item.target_spec_id,
                    arm_protocol_id=item.arm_protocol_id,
                    model_id=item.model_id,
                    outcome_name=item.outcome_name,
                    treatment_arm=item.treatment_arm,
                    control_arm=item.control_arm,
                    coordinate_kind=SimultaneousCoordinateKindV2.POLICY_EFFECT,
                    analysis_component_id="pooled",
                )
                for item in hypotheses
            ),
            key=lambda item: item.test_coordinate_id,
        )
    )
    family = SimultaneousFamilyManifestV2.from_content(
        family_label="global.primary.secure.yield",
        family_kind=SimultaneousFamilyKindV2.PRIMARY_SECURE_YIELD,
        coordinates=coordinates,
        family_size=len(coordinates),
        frozen_before_outcomes=True,
    )
    return SimultaneousInferencePlanV2.from_family(
        family=family,
        strata=_strata(),
        stratum_weight_denominator=1,
        alpha_numerator=1,
        alpha_denominator=10,
        bootstrap_samples=999,
        minimum_independent_clusters=10,
        minimum_clusters_per_stratum=10,
        maximum_invalid_fraction_numerator=0,
        maximum_invalid_fraction_denominator=1,
        seed_material_sha256=hashlib.sha256(PRIMARY_SEED).hexdigest(),
    )


def _plan(
    *hypotheses: RealizationRobustnessHypothesisSpecV2,
    samples: int = 999,
) -> RealizationRobustnessPlanV2:
    primary_plan = _primary_plan(hypotheses)
    return build_realization_robustness_plan_v2(
        hypotheses,
        primary_inference_plan=primary_plan,
        family_label="global.realization.robustness",
        strata=_strata(),
        stratum_weight_denominator=1,
        alpha_numerator=1,
        alpha_denominator=10,
        bootstrap_samples=samples,
        minimum_independent_clusters=10,
        minimum_clusters_per_stratum=10,
        maximum_invalid_fraction_numerator=0,
        maximum_invalid_fraction_denominator=1,
        seed_material_sha256=hashlib.sha256(SEED).hexdigest(),
        interaction_minimum_reference_draws=999,
    )


def _value(label: str, realization_index: int, cluster_index: int) -> float:
    label_offset = 0.10 if label == "b" else 0.0
    if realization_index == 0:
        return 0.55 + label_offset + 0.011 * cluster_index
    permutation = (cluster_index * 5) % len(CLUSTERS)
    return 0.60 + label_offset + 0.009 * permutation


def _contributions(
    hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...],
    *,
    overrides: dict[tuple[str, str, str], float] | None = None,
) -> tuple[RealizationClusterContributionV2, ...]:
    overrides = {} if overrides is None else overrides
    rows: list[RealizationClusterContributionV2] = []
    for specification in hypotheses:
        label = specification.model_id.removeprefix("model.")
        for realization_index, realization_id in enumerate(REALIZATIONS):
            for cluster_index, cluster_id in enumerate(CLUSTERS):
                key = (specification.hypothesis_id, realization_id, cluster_id)
                rows.append(
                    RealizationClusterContributionV2(
                        hypothesis_id=specification.hypothesis_id,
                        model_id=specification.model_id,
                        realization_spec_id=realization_id,
                        stratum_id="cwe78.shell",
                        semantic_task_cluster_id=cluster_id,
                        estimate=overrides.get(
                            key,
                            _value(label, realization_index, cluster_index),
                        ),
                    )
                )
    return tuple(rows)


def _primary_contributions(
    hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...],
    contributions: tuple[RealizationClusterContributionV2, ...],
) -> tuple[CoordinateClusterContributionV2, ...]:
    primary_plan = _primary_plan(hypotheses)
    coordinate_by_key = {
        (item.hypothesis_id, item.model_id): item for item in primary_plan.family.coordinates
    }
    values = {
        (
            item.hypothesis_id,
            item.model_id,
            item.realization_spec_id,
            item.semantic_task_cluster_id,
        ): item.estimate
        for item in contributions
    }
    rows: list[CoordinateClusterContributionV2] = []
    for specification in hypotheses:
        coordinate = coordinate_by_key[(specification.hypothesis_id, specification.model_id)]
        weights = {
            realization_id: numerator / specification.probability_denominator
            for realization_id, numerator in zip(
                specification.realization_spec_ids,
                specification.probability_numerators,
                strict=True,
            )
        }
        for cluster_id in CLUSTERS:
            pooled = sum(
                weights[realization_id]
                * values[
                    (
                        specification.hypothesis_id,
                        specification.model_id,
                        realization_id,
                        cluster_id,
                    )
                ]
                for realization_id in specification.realization_spec_ids
            )
            rows.append(
                CoordinateClusterContributionV2(
                    test_coordinate_id=coordinate.test_coordinate_id,
                    stratum_id="cwe78.shell",
                    semantic_task_cluster_id=cluster_id,
                    estimate=pooled,
                )
            )
    return tuple(rows)


def _primary_result(
    hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...],
    contributions: tuple[RealizationClusterContributionV2, ...],
) -> SimultaneousInferenceResultV2:
    return run_simultaneous_inference_v2(
        _primary_plan(hypotheses),
        _primary_contributions(hypotheses, contributions),
        seed_material=PRIMARY_SEED,
    )


def _interaction_references(
    plan: RealizationRobustnessPlanV2,
    contributions: tuple[RealizationClusterContributionV2, ...],
) -> tuple[ArmRealizationInteractionReferenceV2, ...]:
    estimates = {
        (
            item.hypothesis_id,
            item.realization_spec_id,
            item.semantic_task_cluster_id,
        ): item.estimate
        for item in contributions
    }

    def observed_statistic(hypothesis_id: str) -> float:
        realization_means = tuple(
            sum(estimates[(hypothesis_id, realization_id, cluster_id)] for cluster_id in CLUSTERS)
            / len(CLUSTERS)
            for realization_id in REALIZATIONS
        )
        pooled = sum(realization_means) / len(realization_means)
        return max(abs(value - pooled) for value in realization_means)

    return tuple(
        ArmRealizationInteractionReferenceV2.from_statistics(
            robustness_hypothesis_spec_id=item.robustness_hypothesis_spec_id,
            global_robustness_family_id=(plan.simultaneous_inference_plan.family_id),
            hypothesis_id=item.hypothesis_id,
            model_id=item.model_id,
            randomization_manifest_sha256=_sha("global-assignment-manifest"),
            joint_reference_run_sha256=_sha("global-interaction-reference-run"),
            observed_statistic=observed_statistic(item.hypothesis_id),
            reference_statistics=tuple(
                (0.005 if item.model_id == "model.a" else 0.007) * (index % 20)
                for index in range(999)
            ),
        )
        for item in plan.hypotheses
    )


def _run(
    plan: RealizationRobustnessPlanV2,
    contributions: tuple[RealizationClusterContributionV2, ...],
):
    hypotheses = plan.hypotheses
    primary_plan = _primary_plan(hypotheses)
    primary_contributions = _primary_contributions(hypotheses, contributions)
    primary_result = run_simultaneous_inference_v2(
        primary_plan,
        primary_contributions,
        seed_material=PRIMARY_SEED,
    )
    return run_realization_robustness_v2(
        plan,
        contributions,
        primary_plan,
        primary_result,
        primary_contributions,
        _interaction_references(plan, contributions),
        primary_seed_material=PRIMARY_SEED,
        seed_material=SEED,
    )


def test_global_family_contains_every_hypothesis_realization_loo_and_deviation() -> None:
    hypotheses = (_hypothesis("a"), _hypothesis("b"))
    plan = _plan(*hypotheses)
    coordinates = plan.simultaneous_inference_plan.family.coordinates

    # For each (h, model): one pooled effect plus three coordinates for each of 2 r.
    assert len(coordinates) == 2 * (1 + 3 * len(REALIZATIONS))
    assert {item.coordinate_kind for item in coordinates} == set(SimultaneousCoordinateKindV2)
    assert {(item.hypothesis_id, item.model_id) for item in coordinates} == {
        (item.hypothesis_id, item.model_id) for item in hypotheses
    }
    assert plan.full_global_multiplicity_family_required is True


def test_strong_label_uses_qh_pooled_per_realization_loo_and_global_max_t() -> None:
    hypotheses = (_hypothesis("a"), _hypothesis("b"))
    plan = _plan(*hypotheses)
    result = _run(plan, _contributions(hypotheses))

    assert len(result.simultaneous_result.intervals) == 14
    assert result.analysis_result_id.startswith("realization_robustness_result_v2_")
    assert result.primary_inference_plan_id == plan.primary_inference_plan_id
    assert result.primary_inference_result_id.startswith("simultaneous_result_v2_")
    assert all(
        item.label is RealizationRobustnessLabelV2.REALIZATION_ROBUST for item in result.hypotheses
    )
    first = next(item for item in result.hypotheses if item.model_id == "model.a")
    realization = dict(first.realization_intervals)
    loo = dict(first.leave_one_out_intervals)
    expected_a = sum(_value("a", 0, index) for index in range(12)) / 12
    expected_b = sum(_value("a", 1, index) for index in range(12)) / 12
    assert realization[REALIZATIONS[0]].estimate == pytest.approx(expected_a)
    assert realization[REALIZATIONS[1]].estimate == pytest.approx(expected_b)
    assert first.pooled_interval.estimate == pytest.approx((expected_a + expected_b) / 2)
    # Under two equal-probability realizations, LOO(-r) is exactly the other realization.
    assert loo[REALIZATIONS[0]].estimate == pytest.approx(expected_b)
    assert loo[REALIZATIONS[1]].estimate == pytest.approx(expected_a)
    assert 0.0 < first.interaction_randomization_p_value <= 1.0
    assert first.interaction_global_adjusted_p_value >= first.interaction_randomization_p_value
    assert first.heterogeneity_simultaneous_upper <= first.practical_equivalence_margin
    # Each replicate has one common sample digest and one maximum over all 14 coordinates.
    assert all(len(draw.sample_sha256) == 64 for draw in result.simultaneous_result.draws)


def test_reverse_realization_and_loo_prevent_strong_label() -> None:
    hypothesis = _hypothesis("a", margin_numerator=1, margin_denominator=1)
    overrides = {
        (hypothesis.hypothesis_id, REALIZATIONS[0], cluster_id): -0.55 + 0.01 * index
        for index, cluster_id in enumerate(CLUSTERS)
    }
    result = _run(
        _plan(hypothesis),
        _contributions((hypothesis,), overrides=overrides),
    ).hypotheses[0]

    assert result.label is RealizationRobustnessLabelV2.AVERAGE_POLICY_CONFIRMED
    assert result.all_realization_points_expected_direction is False
    assert result.direction_consistency_threshold_met is False
    assert result.no_realization_interval_fully_supports_reverse is False
    assert result.all_leave_one_out_intervals_supported is False


def test_heterogeneity_above_frozen_equivalence_margin_prevents_strong_label() -> None:
    hypothesis = _hypothesis("a", margin_numerator=1, margin_denominator=20)
    overrides: dict[tuple[str, str, str], float] = {}
    for index, cluster_id in enumerate(CLUSTERS):
        overrides[(hypothesis.hypothesis_id, REALIZATIONS[0], cluster_id)] = 0.25 + 0.005 * index
        overrides[(hypothesis.hypothesis_id, REALIZATIONS[1], cluster_id)] = 0.85 + 0.007 * (
            (index * 5) % 12
        )
    result = _run(
        _plan(hypothesis),
        _contributions((hypothesis,), overrides=overrides),
    ).hypotheses[0]

    assert result.all_realization_points_expected_direction is True
    assert result.all_leave_one_out_intervals_supported is True
    assert result.heterogeneity_equivalent is False
    assert result.label is RealizationRobustnessLabelV2.AVERAGE_POLICY_CONFIRMED


def test_unconfirmed_primary_policy_effect_cannot_receive_strong_label() -> None:
    hypothesis = _hypothesis("a")
    overrides: dict[tuple[str, str, str], float] = {}
    for index, cluster_id in enumerate(CLUSTERS):
        overrides[(hypothesis.hypothesis_id, REALIZATIONS[0], cluster_id)] = -0.40 + 0.07 * index
        overrides[(hypothesis.hypothesis_id, REALIZATIONS[1], cluster_id)] = 0.38 - 0.065 * index
    result = _run(
        _plan(hypothesis),
        _contributions((hypothesis,), overrides=overrides),
    ).hypotheses[0]

    assert result.base_policy_effect_confirmed is False
    assert result.label is RealizationRobustnessLabelV2.UNCONFIRMED


def test_missing_common_support_and_tampered_primary_result_fail_closed() -> None:
    hypothesis = _hypothesis("a")
    plan = _plan(hypothesis)
    contributions = _contributions((hypothesis,))
    primary_plan = _primary_plan((hypothesis,))
    primary_contributions = _primary_contributions((hypothesis,), contributions)
    primary_result = _primary_result((hypothesis,), contributions)
    references = _interaction_references(plan, contributions)

    with pytest.raises(ValueError, match="realization common support"):
        run_realization_robustness_v2(
            plan,
            contributions[:-1],
            primary_plan,
            primary_result,
            primary_contributions,
            references,
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )
    with pytest.raises(ValueError, match="realization cluster contribution"):
        run_realization_robustness_v2(
            plan,
            (replace(contributions[0], estimate=1.01), *contributions[1:]),
            primary_plan,
            primary_result,
            primary_contributions,
            references,
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )
    with pytest.raises(ValueError, match="exact replay"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            replace(
                primary_result,
                critical_value=primary_result.critical_value + 0.01,
            ),
            primary_contributions,
            references,
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )
    with pytest.raises(ValueError, match="interaction randomization reference"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            primary_result,
            primary_contributions,
            (replace(references[0], observed_statistic=0.05),),
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )


def test_real_primary_result_from_different_contributions_is_rejected() -> None:
    hypothesis = _hypothesis("a")
    plan = _plan(hypothesis)
    contributions = _contributions((hypothesis,))
    primary_plan = _primary_plan((hypothesis,))
    wrong_primary_rows = tuple(
        replace(item, estimate=item.estimate + 0.05)
        for item in _primary_contributions((hypothesis,), contributions)
    )
    wrong_primary_result = run_simultaneous_inference_v2(
        primary_plan,
        wrong_primary_rows,
        seed_material=PRIMARY_SEED,
    )

    with pytest.raises(ValueError, match="contribution binding"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            wrong_primary_result,
            wrong_primary_rows,
            _interaction_references(plan, contributions),
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )


def test_internally_consistent_but_computationally_wrong_primary_is_rejected() -> None:
    hypothesis = _hypothesis("a")
    plan = _plan(hypothesis)
    contributions = _contributions((hypothesis,))
    primary_plan = _primary_plan((hypothesis,))
    primary_rows = _primary_contributions((hypothesis,), contributions)
    primary_result = run_simultaneous_inference_v2(
        primary_plan,
        primary_rows,
        seed_material=PRIMARY_SEED,
    )
    shift = 0.25
    forged_draws = tuple(
        replace(draw, max_abs_t=float(draw.max_abs_t) + shift) for draw in primary_result.draws
    )
    forged_critical = primary_result.critical_value + shift
    forged_intervals = tuple(
        replace(
            interval,
            simultaneous_lower=(interval.estimate - forged_critical * interval.standard_error),
            simultaneous_upper=(interval.estimate + forged_critical * interval.standard_error),
        )
        for interval in primary_result.intervals
    )
    forged_result = _build_result(
        inference_plan_id=primary_result.inference_plan_id,
        family_id=primary_result.family_id,
        input_contributions_sha256=primary_result.input_contributions_sha256,
        critical_value=forged_critical,
        intervals=forged_intervals,
        draws=forged_draws,
    )

    with pytest.raises(ValueError, match="exact replay"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            forged_result,
            primary_rows,
            _interaction_references(plan, contributions),
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )


def test_interaction_reference_binds_observed_statistic_family_and_joint_run() -> None:
    hypotheses = (_hypothesis("a"), _hypothesis("b"))
    plan = _plan(*hypotheses)
    contributions = _contributions(hypotheses)
    primary_plan = _primary_plan(plan.hypotheses)
    primary_contributions = _primary_contributions(plan.hypotheses, contributions)
    primary_result = _primary_result(plan.hypotheses, contributions)
    references = _interaction_references(plan, contributions)
    first = references[0]
    wrong_observed = ArmRealizationInteractionReferenceV2.from_statistics(
        robustness_hypothesis_spec_id=first.robustness_hypothesis_spec_id,
        global_robustness_family_id=first.global_robustness_family_id,
        hypothesis_id=first.hypothesis_id,
        model_id=first.model_id,
        randomization_manifest_sha256=first.randomization_manifest_sha256,
        joint_reference_run_sha256=first.joint_reference_run_sha256,
        observed_statistic=first.observed_statistic + 0.10,
        reference_statistics=first.reference_statistics,
    )
    with pytest.raises(ValueError, match="interaction observed statistic"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            primary_result,
            primary_contributions,
            (wrong_observed, *references[1:]),
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )

    second = references[1]
    wrong_joint_run = ArmRealizationInteractionReferenceV2.from_statistics(
        robustness_hypothesis_spec_id=second.robustness_hypothesis_spec_id,
        global_robustness_family_id=second.global_robustness_family_id,
        hypothesis_id=second.hypothesis_id,
        model_id=second.model_id,
        randomization_manifest_sha256=second.randomization_manifest_sha256,
        joint_reference_run_sha256=_sha("different-joint-reference-run"),
        observed_statistic=second.observed_statistic,
        reference_statistics=second.reference_statistics,
    )
    with pytest.raises(ValueError, match="interaction randomization reference"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            primary_result,
            primary_contributions,
            (first, wrong_joint_run),
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )

    wrong_family = ArmRealizationInteractionReferenceV2.from_statistics(
        robustness_hypothesis_spec_id=first.robustness_hypothesis_spec_id,
        global_robustness_family_id=f"simultaneous_family_{'f' * 64}",
        hypothesis_id=first.hypothesis_id,
        model_id=first.model_id,
        randomization_manifest_sha256=first.randomization_manifest_sha256,
        joint_reference_run_sha256=first.joint_reference_run_sha256,
        observed_statistic=first.observed_statistic,
        reference_statistics=first.reference_statistics,
    )
    with pytest.raises(ValueError, match="interaction randomization reference"):
        run_realization_robustness_v2(
            plan,
            contributions,
            primary_plan,
            primary_result,
            primary_contributions,
            (wrong_family, *references[1:]),
            primary_seed_material=PRIMARY_SEED,
            seed_material=SEED,
        )


def test_frozen_global_family_cannot_be_removed_after_content_addressing() -> None:
    plan = _plan(_hypothesis("a"))
    payload = deepcopy(plan.model_dump(mode="json"))
    family = payload["simultaneous_inference_plan"]["family"]
    family["coordinates"] = family["coordinates"][:-1]
    family["family_size"] -= 1

    with pytest.raises(ValidationError, match="simultaneous inference v2"):
        RealizationRobustnessPlanV2.model_validate(payload)

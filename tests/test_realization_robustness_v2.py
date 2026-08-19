from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import replace

import pytest
from pydantic import ValidationError

from secaware.analysis.realization_robustness_v2 import (
    ArmRealizationInteractionReferenceV2,
    BaseRandomizedPolicyEvidenceV2,
    RealizationClusterContributionV2,
    RealizationRobustnessLabelV2,
    build_realization_robustness_plan_v2,
    run_realization_robustness_v2,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.inference_v2 import (
    CommonStratumSupportV2,
    RealizationRobustnessHypothesisSpecV2,
    RealizationRobustnessPlanV2,
    RobustnessExpectedDirectionV2,
    SimultaneousCoordinateKindV2,
)

SEED = b"phase-zero-realization-robustness-example"
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


def _plan(
    *hypotheses: RealizationRobustnessHypothesisSpecV2,
    samples: int = 160,
) -> RealizationRobustnessPlanV2:
    return build_realization_robustness_plan_v2(
        hypotheses,
        family_label="global.realization.robustness",
        strata=(
            CommonStratumSupportV2(
                stratum_id="cwe78.shell",
                semantic_task_cluster_ids=CLUSTERS,
                weight_numerator=1,
            ),
        ),
        stratum_weight_denominator=1,
        alpha_numerator=1,
        alpha_denominator=10,
        bootstrap_samples=samples,
        minimum_independent_clusters=10,
        minimum_clusters_per_stratum=10,
        maximum_invalid_fraction_numerator=1,
        maximum_invalid_fraction_denominator=4,
        seed_material_sha256=hashlib.sha256(SEED).hexdigest(),
        interaction_minimum_reference_draws=20,
    )


def _value(label: str, realization_index: int, cluster_index: int) -> float:
    label_offset = 0.12 if label == "b" else 0.0
    if realization_index == 0:
        return 0.90 + label_offset + 0.011 * cluster_index
    permutation = (cluster_index * 5) % len(CLUSTERS)
    return 0.95 + label_offset + 0.009 * permutation


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


def _base_evidence(
    hypotheses: tuple[RealizationRobustnessHypothesisSpecV2, ...],
    *,
    confirmed: bool = True,
) -> tuple[BaseRandomizedPolicyEvidenceV2, ...]:
    return tuple(
        BaseRandomizedPolicyEvidenceV2.from_content(
            robustness_hypothesis_spec_id=item.robustness_hypothesis_spec_id,
            hypothesis_id=item.hypothesis_id,
            model_id=item.model_id,
            primary_family_id=f"simultaneous_family_{_sha(f'primary:{item.hypothesis_id}')}",
            simultaneous_lower=0.20,
            simultaneous_upper=1.40,
            confirmed=confirmed,
            provenance_complete=True,
        )
        for item in hypotheses
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
                (0.005 if item.model_id == "model.a" else 0.007) * index for index in range(20)
            ),
        )
        for item in plan.hypotheses
    )


def _run(
    plan: RealizationRobustnessPlanV2,
    contributions: tuple[RealizationClusterContributionV2, ...],
    *,
    confirmed: bool = True,
):
    hypotheses = plan.hypotheses
    return run_realization_robustness_v2(
        plan,
        contributions,
        _base_evidence(hypotheses, confirmed=confirmed),
        _interaction_references(plan, contributions),
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
    assert first.interaction_randomization_p_value == pytest.approx(17 / 21)
    assert first.interaction_global_adjusted_p_value == pytest.approx(18 / 21)
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

    assert result.label is RealizationRobustnessLabelV2.AVERAGE_POLICY_ONLY
    assert result.all_realization_points_expected_direction is False
    assert result.direction_consistency_threshold_met is False
    assert result.no_realization_interval_fully_supports_reverse is False
    assert result.all_leave_one_out_intervals_supported is False


def test_heterogeneity_above_frozen_equivalence_margin_prevents_strong_label() -> None:
    hypothesis = _hypothesis("a", margin_numerator=1, margin_denominator=20)
    overrides: dict[tuple[str, str, str], float] = {}
    for index, cluster_id in enumerate(CLUSTERS):
        overrides[(hypothesis.hypothesis_id, REALIZATIONS[0], cluster_id)] = 0.25 + 0.005 * index
        overrides[(hypothesis.hypothesis_id, REALIZATIONS[1], cluster_id)] = 0.95 + 0.007 * (
            (index * 5) % 12
        )
    result = _run(
        _plan(hypothesis),
        _contributions((hypothesis,), overrides=overrides),
    ).hypotheses[0]

    assert result.all_realization_points_expected_direction is True
    assert result.all_leave_one_out_intervals_supported is True
    assert result.heterogeneity_equivalent is False
    assert result.label is RealizationRobustnessLabelV2.AVERAGE_POLICY_ONLY


def test_unconfirmed_primary_policy_effect_cannot_receive_strong_label() -> None:
    hypothesis = _hypothesis("a")
    result = _run(
        _plan(hypothesis),
        _contributions((hypothesis,)),
        confirmed=False,
    ).hypotheses[0]

    assert result.base_policy_effect_confirmed is False
    assert result.label is RealizationRobustnessLabelV2.AVERAGE_POLICY_ONLY


def test_missing_common_realization_support_and_tampered_evidence_fail_closed() -> None:
    hypothesis = _hypothesis("a")
    plan = _plan(hypothesis)
    contributions = _contributions((hypothesis,))
    evidence = _base_evidence((hypothesis,))
    references = _interaction_references(plan, contributions)

    with pytest.raises(ValueError, match="realization common support"):
        run_realization_robustness_v2(
            plan,
            contributions[:-1],
            evidence,
            references,
            seed_material=SEED,
        )
    with pytest.raises(ValueError, match="base policy evidence"):
        run_realization_robustness_v2(
            plan,
            contributions,
            (replace(evidence[0], simultaneous_lower=0.30),),
            references,
            seed_material=SEED,
        )
    with pytest.raises(ValueError, match="interaction randomization reference"):
        run_realization_robustness_v2(
            plan,
            contributions,
            evidence,
            (replace(references[0], observed_statistic=0.05),),
            seed_material=SEED,
        )


def test_interaction_reference_binds_observed_statistic_family_and_joint_run() -> None:
    hypotheses = (_hypothesis("a"), _hypothesis("b"))
    plan = _plan(*hypotheses)
    contributions = _contributions(hypotheses)
    evidence = _base_evidence(plan.hypotheses)
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
            evidence,
            (wrong_observed, *references[1:]),
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
            evidence,
            (first, wrong_joint_run),
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
            evidence,
            (wrong_family, *references[1:]),
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

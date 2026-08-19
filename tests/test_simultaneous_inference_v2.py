from __future__ import annotations

import hashlib
import math
from copy import deepcopy

import pytest
from pydantic import ValidationError

from secaware.analysis.simultaneous_v2 import (
    BootstrapDrawStatusV2,
    CoordinateClusterContributionV2,
    run_simultaneous_inference_v2,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.inference_v2 import (
    CommonStratumSupportV2,
    SimultaneousCoordinateKindV2,
    SimultaneousFamilyKindV2,
    SimultaneousFamilyManifestV2,
    SimultaneousInferencePlanV2,
    SimultaneousTestCoordinateV2,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


SEED = b"phase-zero-simultaneous-hand-example"


def _coordinate(label: str) -> SimultaneousTestCoordinateV2:
    return SimultaneousTestCoordinateV2.from_content(
        hypothesis_id=f"hypothesis_{_sha(f'h:{label}')}",
        target_spec_id=f"target_{_sha(f't:{label}')}",
        arm_protocol_id=f"arm_protocol_{_sha(f'p:{label}')}",
        model_id="model.test",
        outcome_name="y_secure_yield",
        treatment_arm=ArmRole.TARGET_PATCH,
        control_arm=ArmRole.NOOP_REWRITE,
        coordinate_kind=SimultaneousCoordinateKindV2.POLICY_EFFECT,
        analysis_component_id="pooled",
    )


def _family(*labels: str) -> SimultaneousFamilyManifestV2:
    coordinates = tuple(
        sorted((_coordinate(label) for label in labels), key=lambda item: item.test_coordinate_id)
    )
    return SimultaneousFamilyManifestV2.from_content(
        family_label="primary.test.family",
        family_kind=SimultaneousFamilyKindV2.PRIMARY_SECURE_YIELD,
        coordinates=coordinates,
        family_size=len(coordinates),
        frozen_before_outcomes=True,
    )


def _strata() -> tuple[CommonStratumSupportV2, ...]:
    return (
        CommonStratumSupportV2(
            stratum_id="cwe78.shell",
            semantic_task_cluster_ids=("c1", "c2", "c3"),
            weight_numerator=1,
        ),
        CommonStratumSupportV2(
            stratum_id="cwe89.sql",
            semantic_task_cluster_ids=("d1", "d2", "d3"),
            weight_numerator=2,
        ),
    )


def _plan(
    family: SimultaneousFamilyManifestV2,
    *,
    strata: tuple[CommonStratumSupportV2, ...] | None = None,
    samples: int = 40,
    invalid_numerator: int = 1,
    invalid_denominator: int = 2,
    minimum_independent: int = 4,
    minimum_per_stratum: int = 3,
    seed: bytes = SEED,
) -> SimultaneousInferencePlanV2:
    return SimultaneousInferencePlanV2.from_family(
        family=family,
        strata=_strata() if strata is None else strata,
        stratum_weight_denominator=3
        if strata is None
        else sum(item.weight_numerator for item in strata),
        alpha_numerator=1,
        alpha_denominator=10,
        bootstrap_samples=samples,
        minimum_independent_clusters=minimum_independent,
        minimum_clusters_per_stratum=minimum_per_stratum,
        maximum_invalid_fraction_numerator=invalid_numerator,
        maximum_invalid_fraction_denominator=invalid_denominator,
        seed_material_sha256=hashlib.sha256(seed).hexdigest(),
    )


def _contributions(
    family: SimultaneousFamilyManifestV2,
) -> tuple[CoordinateClusterContributionV2, ...]:
    # Coordinate order is content-addressed, so bind values by hypothesis identity.
    by_hypothesis = {
        f"hypothesis_{_sha('h:a')}": {
            "cwe78.shell": (0.0, 1.0, 2.0),
            "cwe89.sql": (2.0, 2.0, 5.0),
        },
        f"hypothesis_{_sha('h:b')}": {
            "cwe78.shell": (-1.0, 0.0, 1.0),
            "cwe89.sql": (0.0, 3.0, 3.0),
        },
    }
    rows: list[CoordinateClusterContributionV2] = []
    for coordinate in family.coordinates:
        for stratum in _strata():
            values = by_hypothesis[coordinate.hypothesis_id][stratum.stratum_id]
            rows.extend(
                CoordinateClusterContributionV2(
                    test_coordinate_id=coordinate.test_coordinate_id,
                    stratum_id=stratum.stratum_id,
                    semantic_task_cluster_id=cluster_id,
                    estimate=value,
                )
                for cluster_id, value in zip(stratum.semantic_task_cluster_ids, values, strict=True)
            )
    return tuple(rows)


def test_hand_calculated_stratified_cluster_se_and_simultaneous_intervals() -> None:
    family = _family("a", "b")
    plan = _plan(family)
    first = run_simultaneous_inference_v2(
        plan,
        _contributions(family),
        seed_material=SEED,
    )
    second = run_simultaneous_inference_v2(
        plan,
        tuple(reversed(_contributions(family))),
        seed_material=SEED,
    )

    # For both coordinates, within-stratum squared-deviation sums are 2 and 6.
    # se^2 = (1/3)^2 * 2/(3*2) + (2/3)^2 * 6/(3*2) = 13/27.
    expected_se = math.sqrt(13 / 27)
    by_hypothesis = {
        coordinate.hypothesis_id: interval
        for coordinate, interval in zip(family.coordinates, first.intervals, strict=True)
    }
    assert by_hypothesis[f"hypothesis_{_sha('h:a')}"].estimate == pytest.approx(7 / 3)
    assert by_hypothesis[f"hypothesis_{_sha('h:b')}"].estimate == pytest.approx(4 / 3)
    assert all(item.standard_error == pytest.approx(expected_se) for item in first.intervals)
    assert all(
        item.simultaneous_lower == pytest.approx(item.estimate - first.critical_value * expected_se)
        and item.simultaneous_upper
        == pytest.approx(item.estimate + first.critical_value * expected_se)
        for item in first.intervals
    )
    assert first == second
    assert len(first.draws) == plan.bootstrap_samples
    assert first.valid_draw_count + first.invalid_draw_count == plan.bootstrap_samples


def test_one_common_stratified_sample_is_committed_for_the_whole_family() -> None:
    family = _family("a", "b")
    result = run_simultaneous_inference_v2(
        _plan(family, samples=12),
        _contributions(family),
        seed_material=SEED,
    )

    assert [item.replicate_index for item in result.draws] == list(range(12))
    assert all(len(item.sample_sha256) == 64 for item in result.draws)
    # A draw has one digest and one family maximum, never a coordinate-specific sample.
    assert all(
        (item.status is BootstrapDrawStatusV2.VALID) == (item.max_abs_t is not None)
        for item in result.draws
    )


def test_fixed_family_and_common_support_reject_omission_duplicate_and_extra() -> None:
    family = _family("a", "b")
    plan = _plan(family)
    rows = _contributions(family)

    with pytest.raises(ValueError, match="common cluster-stratum support"):
        run_simultaneous_inference_v2(plan, rows[:-1], seed_material=SEED)
    with pytest.raises(ValueError, match="common cluster-stratum support"):
        run_simultaneous_inference_v2(plan, (*rows, rows[0]), seed_material=SEED)
    forged = CoordinateClusterContributionV2(
        test_coordinate_id=f"simultaneous_coordinate_{'f' * 64}",
        stratum_id=rows[0].stratum_id,
        semantic_task_cluster_id=rows[0].semantic_task_cluster_id,
        estimate=rows[0].estimate,
    )
    with pytest.raises(ValueError, match="common cluster-stratum support"):
        run_simultaneous_inference_v2(plan, (*rows[1:], forged), seed_material=SEED)


def test_zero_observed_standard_error_fails_closed() -> None:
    family = _family("a")
    plan = _plan(family)
    rows = tuple(
        CoordinateClusterContributionV2(
            test_coordinate_id=family.coordinates[0].test_coordinate_id,
            stratum_id=stratum.stratum_id,
            semantic_task_cluster_id=cluster_id,
            estimate=1.0,
        )
        for stratum in _strata()
        for cluster_id in stratum.semantic_task_cluster_ids
    )
    with pytest.raises(ValueError, match="zero or invalid cluster standard error"):
        run_simultaneous_inference_v2(plan, rows, seed_material=SEED)


def test_low_support_plan_fails_before_resampling() -> None:
    family = _family("a")
    with pytest.raises(ValidationError, match="simultaneous inference v2"):
        _plan(family, minimum_per_stratum=4)


def test_invalid_bootstrap_draw_fraction_fails_closed() -> None:
    family = _family("a")
    strata = (
        CommonStratumSupportV2(
            stratum_id="only",
            semantic_task_cluster_ids=("c1", "c2"),
            weight_numerator=1,
        ),
    )
    plan = _plan(
        family,
        strata=strata,
        samples=20,
        invalid_numerator=0,
        invalid_denominator=1,
        minimum_independent=2,
        minimum_per_stratum=2,
    )
    rows = (
        CoordinateClusterContributionV2(
            test_coordinate_id=family.coordinates[0].test_coordinate_id,
            stratum_id="only",
            semantic_task_cluster_id="c1",
            estimate=0.0,
        ),
        CoordinateClusterContributionV2(
            test_coordinate_id=family.coordinates[0].test_coordinate_id,
            stratum_id="only",
            semantic_task_cluster_id="c2",
            estimate=1.0,
        ),
    )
    with pytest.raises(ValueError, match="invalid-draw fraction"):
        run_simultaneous_inference_v2(plan, rows, seed_material=SEED)


def test_family_and_plan_content_addresses_reject_post_freeze_tampering() -> None:
    family = _family("a", "b")
    plan = _plan(family)

    family_payload = family.model_dump(mode="json")
    family_payload["family_size"] = 1
    with pytest.raises(ValidationError, match="simultaneous inference v2"):
        SimultaneousFamilyManifestV2.model_validate(family_payload)

    plan_payload = deepcopy(plan.model_dump(mode="json"))
    plan_payload["alpha_numerator"] = 2
    with pytest.raises(ValidationError, match="simultaneous inference v2"):
        SimultaneousInferencePlanV2.model_validate(plan_payload)

    with pytest.raises(ValueError, match="seed material"):
        run_simultaneous_inference_v2(
            plan,
            _contributions(family),
            seed_material=b"different-seed",
        )

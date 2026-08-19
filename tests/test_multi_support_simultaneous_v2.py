from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, replace
from fractions import Fraction
from functools import lru_cache

import pytest
from pydantic import ValidationError

from secaware.analysis.confirmatory_contributions_v2 import (
    ConfirmatoryContributionArtifactV2,
    ExactCoordinateClusterContributionV2,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    run_multi_support_simultaneous_inference_v2,
    validate_multi_support_simultaneous_result_v2,
)
from secaware.analysis.simultaneous_v2 import CoordinateClusterContributionV2
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.multi_support_inference_v2 import (
    CoordinateSpecificStratumSupportV2,
    CoordinateSpecificSupportV2,
    GlobalUnionStratumV2,
    MultiSupportSimultaneousInferencePlanV2,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from test_experiment_freeze_v2 import (
    ANALYSIS_SEED_DOMAIN_SHA256,
    MULTIPLICITY_POLICY_SHA256,
    ExperimentComponents,
    _common_selection,
    _custom_bridge,
    _execution_for_root,
)
from test_protocol_freeze_v2 import _inventory, _population_parts

MULTIPLICITY_MATERIAL = b"global-multiplicity-policy"
ANALYSIS_SEED_MATERIAL = b"analysis-seed-domain"


def _coordinates(
    task_prefix: str,
    cluster_indices: range,
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (f"{task_prefix}.task.{index:02d}", f"cluster.{index:02d}") for index in cluster_indices
    )


@lru_cache(maxsize=8)
def _experiment(kind: str) -> ConfirmatoryExperimentFreezeV2:
    if kind == "disjoint":
        coordinate_sets = (_coordinates("a", range(20)), _coordinates("b", range(20, 40)))
    elif kind == "overlap":
        coordinate_sets = (_coordinates("a", range(20)), _coordinates("b", range(10, 30)))
    elif kind == "sparse":
        coordinate_sets = (_coordinates("a", range(2)), _coordinates("b", range(2, 40)))
    elif kind == "bounded_invalid":
        coordinate_sets = (_coordinates("a", range(5)), _coordinates("b", range(5, 15)))
    else:
        raise AssertionError(kind)
    bridges = (
        _custom_bridge(k_r=1, target_salt=f"{kind}:a"),
        _custom_bridge(k_r=2, target_salt=f"{kind}:b"),
    )
    failed = _custom_bridge(k_r=3, target_salt=f"{kind}:failed")
    universe, selection = _common_selection(
        bridges=bridges,
        failed_skeleton=failed.candidate_skeleton,
    )
    roots = []
    executions = []
    for index, (bridge, coordinates) in enumerate(zip(bridges, coordinate_sets, strict=True)):
        independent_cluster_count = len({cluster_id for _, cluster_id in coordinates})
        inventory = _inventory(coordinates)
        parts = _population_parts(
            bridge=bridge,
            inventory=inventory,
            coordinates=coordinates,
            minimum_tasks=len(coordinates),
            minimum_clusters=independent_cluster_count,
        )
        root = ProtocolFreezeRootV2.from_components(
            candidate_universe=universe,
            selection_freeze=selection,
            intervention_bridge=bridge,
            source_inventory=inventory,
            pool_partition=parts.partition,
            semantic_cluster_manifest=parts.clusters,
            population=parts.population,
            query_evidence=parts.query_evidence,
            variant_evidence=parts.variant_evidence,
            preregistered_minimum_gate_pass_tasks=len(coordinates),
            preregistered_minimum_gate_pass_clusters=independent_cluster_count,
        )
        roots.append(root)
        executions.append(_execution_for_root(root, randomization_seed=20_260_900 + index))
    components = ExperimentComponents(
        universe=universe,
        selection=selection,
        roots=tuple(roots),
        executions=tuple(executions),
    )
    return ConfirmatoryExperimentFreezeV2.from_components(
        candidate_universe=components.universe,
        selection_freeze=components.selection,
        protocol_roots=components.roots,
        execution_policy_freezes=components.executions,
        global_multiplicity_family_policy_sha256=MULTIPLICITY_POLICY_SHA256,
        analysis_seed_domain_sha256=ANALYSIS_SEED_DOMAIN_SHA256,
    )


@lru_cache(maxsize=8)
def _plan(kind: str) -> MultiSupportSimultaneousInferencePlanV2:
    return MultiSupportSimultaneousInferencePlanV2.from_experiment(
        experiment=_experiment(kind),
        global_multiplicity_family_policy_material=MULTIPLICITY_MATERIAL,
        analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        alpha_numerator=1,
        alpha_denominator=20,
        bootstrap_samples=999,
        minimum_independent_clusters_per_coordinate={
            "sparse": 2,
            "bounded_invalid": 5,
        }.get(kind, 20),
    )


def _artifact_digest(artifact: ConfirmatoryContributionArtifactV2) -> str:
    payload = asdict(artifact)
    payload.pop("contribution_artifact_id")
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _address_artifact(
    artifact: ConfirmatoryContributionArtifactV2,
) -> ConfirmatoryContributionArtifactV2:
    return replace(
        artifact,
        contribution_artifact_id="confirmatory_contributions_v2_" + _artifact_digest(artifact),
    )


def _value(
    support: CoordinateSpecificSupportV2,
    cluster_id: str,
    coordinate_index: int,
) -> Fraction:
    cluster_index = int(cluster_id.rsplit(".", maxsplit=1)[1])
    # Unique enough to make degenerate bootstrap SE effectively impossible,
    # while retaining a simple exact rational hand calculation.
    return Fraction(((cluster_index * 7 + coordinate_index * 3) % 31) - 15, 20)


@lru_cache(maxsize=8)
def _artifacts(kind: str) -> tuple[ConfirmatoryContributionArtifactV2, ...]:
    plan = _plan(kind)
    result = []
    for coordinate_index, support in enumerate(plan.coordinate_supports):
        exact = tuple(
            ExactCoordinateClusterContributionV2(
                test_coordinate_id=support.test_coordinate.test_coordinate_id,
                stratum_id=stratum.stratum_id,
                semantic_task_cluster_id=cluster_id,
                numerator=_value(support, cluster_id, coordinate_index).numerator,
                denominator=_value(support, cluster_id, coordinate_index).denominator,
            )
            for stratum in support.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        )
        projected = tuple(
            CoordinateClusterContributionV2(
                test_coordinate_id=item.test_coordinate_id,
                stratum_id=item.stratum_id,
                semantic_task_cluster_id=item.semantic_task_cluster_id,
                estimate=float(Fraction(item.numerator, item.denominator)),
            )
            for item in exact
        )
        provisional = ConfirmatoryContributionArtifactV2(
            contribution_artifact_id="",
            population_freeze_manifest_id=support.population_freeze_manifest_id,
            randomization_manifest_id=support.randomization_manifest_id,
            execution_policy_freeze_manifest_id=(support.execution_policy_freeze_manifest_id),
            provenance_closed_coverage_manifest_id=(
                "provenance_closed_coverage_v2_"
                + hashlib.sha256(support.test_coordinate.hypothesis_id.encode()).hexdigest()
            ),
            test_coordinate_id=support.test_coordinate.test_coordinate_id,
            derivation_rule=(
                "authenticated_block_arm_means_then_frozen_task_weights_then_qh_then_cluster_v1"
            ),
            rational_arithmetic_until_final_projection=True,
            exact_coordinate_contributions=exact,
            coordinate_contributions=projected,
            exact_realization_contributions=(),
            realization_contributions=(),
        )
        result.append(_address_artifact(provisional))
    return tuple(result)


@lru_cache(maxsize=8)
def _result(kind: str):
    return run_multi_support_simultaneous_inference_v2(
        _plan(kind),
        _artifacts(kind),
        analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
    )


def _support_by_hypothesis(
    plan: MultiSupportSimultaneousInferencePlanV2,
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for support in plan.coordinate_supports:
        result.setdefault(support.test_coordinate.hypothesis_id, set()).update(
            cluster_id
            for stratum in support.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        )
    return result


def test_plan_freezes_complete_h_by_m_family_without_common_intersection() -> None:
    plan = _plan("disjoint")
    experiment = _experiment("disjoint")
    support_by_hypothesis = _support_by_hypothesis(plan)

    assert plan.family.family_size == experiment.hypothesis_model_coordinate_count == 4
    assert {
        (item.test_coordinate.hypothesis_id, item.test_coordinate.model_id)
        for item in plan.coordinate_supports
    } == {(item.hypothesis_id, item.model_id) for item in experiment.hypothesis_model_coordinates}
    assert set.intersection(*support_by_hypothesis.values()) == set()
    assert set.union(*support_by_hypothesis.values()) == set(
        plan.global_union_strata[0].semantic_task_cluster_ids
    )
    assert all(item.coordinate_cluster_count == 20 for item in plan.coordinate_supports)
    assert plan.global_union_strata[0].union_cluster_count == 40
    assert plan.global_multiplicity_family_policy_sha256 == MULTIPLICITY_POLICY_SHA256
    assert plan.analysis_seed_domain_sha256 == ANALYSIS_SEED_DOMAIN_SHA256
    assert (
        MultiSupportSimultaneousInferencePlanV2.model_validate_json(plan.model_dump_json()) == plan
    )


def test_observed_coordinate_estimate_and_se_match_hand_calculation() -> None:
    plan = _plan("disjoint")
    artifacts = _artifacts("disjoint")
    result = _result("disjoint")
    intervals = {item.test_coordinate_id: item for item in result.intervals}

    first = artifacts[0]
    values = tuple(
        Fraction(item.numerator, item.denominator) for item in first.exact_coordinate_contributions
    )
    expected_mean = sum(values, Fraction(0, 1)) / len(values)
    expected_se = math.sqrt(
        math.fsum((float(item - expected_mean)) ** 2 for item in values)
        / (len(values) * (len(values) - 1))
    )
    actual = intervals[first.test_coordinate_id]
    assert Fraction(actual.estimate_numerator, actual.estimate_denominator) == expected_mean
    assert actual.estimate == float(expected_mean)
    assert actual.standard_error == pytest.approx(expected_se, abs=1e-15)
    assert result.valid_draw_count == plan.bootstrap_samples == 999
    assert result.invalid_draw_count == 0
    assert result.simultaneous_result_id.startswith("multi_support_simultaneous_result_v2_")


def test_bounded_invalid_draws_are_retained_and_do_not_condition_silently() -> None:
    plan = _plan("bounded_invalid")
    result = _result("bounded_invalid")

    assert plan.minimum_valid_bootstrap_draws == 950
    assert 0 < result.invalid_draw_count <= 49
    assert result.valid_draw_count >= plan.minimum_valid_bootstrap_draws
    assert result.valid_draw_count + result.invalid_draw_count == plan.bootstrap_samples
    assert len(result.invalid_draws) == result.invalid_draw_count
    assert {item.reason_code for item in result.invalid_draws} <= {
        "insufficient_retained_coordinate_clusters",
        "zero_or_invalid_coordinate_standard_error",
    }
    assert {item.replicate_index for item in result.draws}.isdisjoint(
        item.replicate_index for item in result.invalid_draws
    )


def test_overlap_uses_one_global_draw_and_preserves_shared_cluster_dependence() -> None:
    plan = _plan("overlap")
    support_by_hypothesis = _support_by_hypothesis(plan)
    assert len(set.intersection(*support_by_hypothesis.values())) == 10
    assert plan.global_union_strata[0].union_cluster_count == 30

    result = _result("overlap")
    first_draw = result.draws[0]
    assert len(first_draw.stratum_draws) == 1
    assert first_draw.stratum_draws[0].occurrence_count == 30
    counts = {
        item.test_coordinate_id: item.retained_occurrence_count
        for item in first_draw.coordinate_retained_counts
    }
    for hypothesis_id in support_by_hypothesis:
        coordinate_ids = tuple(
            item.test_coordinate.test_coordinate_id
            for item in plan.coordinate_supports
            if item.test_coordinate.hypothesis_id == hypothesis_id
        )
        assert len(coordinate_ids) == 2
        assert counts[coordinate_ids[0]] == counts[coordinate_ids[1]]


def test_disjoint_supports_still_share_one_draw_manifest_without_estimand_shrinkage() -> None:
    plan = _plan("disjoint")
    result = _result("disjoint")
    support_by_hypothesis = _support_by_hypothesis(plan)
    first_draw = result.draws[0]
    counts = {
        item.test_coordinate_id: item.retained_occurrence_count
        for item in first_draw.coordinate_retained_counts
    }
    representative_ids = [
        next(
            item.test_coordinate.test_coordinate_id
            for item in plan.coordinate_supports
            if item.test_coordinate.hypothesis_id == hypothesis_id
        )
        for hypothesis_id in support_by_hypothesis
    ]
    assert sum(counts[item] for item in representative_ids) == 40
    assert first_draw.stratum_draws[0].occurrence_count == 40
    assert first_draw.global_sample_sha256
    assert all(item.coordinate_cluster_count == 20 for item in plan.coordinate_supports)


def test_hypothesis_model_or_cluster_deletion_fails_closed() -> None:
    plan = _plan("disjoint")
    artifacts = _artifacts("disjoint")
    with pytest.raises(ValueError, match="complete contribution artifact family"):
        run_multi_support_simultaneous_inference_v2(
            plan,
            artifacts[:-1],
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )

    victim = artifacts[0]
    deleted = replace(
        victim,
        exact_coordinate_contributions=victim.exact_coordinate_contributions[:-1],
        coordinate_contributions=victim.coordinate_contributions[:-1],
    )
    deleted = _address_artifact(deleted)
    with pytest.raises(ValueError, match="contribution support"):
        run_multi_support_simultaneous_inference_v2(
            plan,
            (deleted, *artifacts[1:]),
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )

    coverage_swap = _address_artifact(
        replace(
            artifacts[0],
            provenance_closed_coverage_manifest_id=("provenance_closed_coverage_v2_" + "f" * 64),
        )
    )
    with pytest.raises(ValueError, match="coverage family"):
        run_multi_support_simultaneous_inference_v2(
            plan,
            (coverage_swap, *artifacts[1:]),
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )


def test_post_hoc_family_reduction_and_common_intersection_are_rejected() -> None:
    plan = _plan("overlap")
    reduced = plan.model_dump(mode="python", exclude={"schema_version", "inference_plan_id"})
    reduced_family = plan.family.model_dump(mode="python", exclude={"schema_version", "family_id"})
    reduced_family["coordinates"] = plan.family.coordinates[:-1]
    reduced_family["family_size"] = len(plan.family.coordinates) - 1
    from secaware.schema.inference_v2 import SimultaneousFamilyManifestV2

    reduced["family"] = SimultaneousFamilyManifestV2.from_content(**reduced_family)
    reduced["coordinate_supports"] = plan.coordinate_supports[:-1]
    with pytest.raises(
        ValidationError,
        match="multi-support simultaneous inference v2 contract failed validation",
    ):
        MultiSupportSimultaneousInferencePlanV2.from_content(**reduced)

    intersection = tuple(sorted(set.intersection(*_support_by_hypothesis(plan).values())))
    shrunk_supports = []
    for support in plan.coordinate_supports:
        old = support.strata[0]
        shrunk_stratum = CoordinateSpecificStratumSupportV2(
            stratum_id=old.stratum_id,
            semantic_task_cluster_ids=intersection,
            cluster_weight_numerators=(1,) * len(intersection),
            cluster_weight_denominator=len(intersection),
            stratum_weight_numerator=1,
            stratum_weight_denominator=1,
        )
        shrunk_supports.append(
            CoordinateSpecificSupportV2.from_content(
                hypothesis_model_coordinate_id=support.hypothesis_model_coordinate_id,
                population_freeze_manifest_id=support.population_freeze_manifest_id,
                randomization_manifest_id=support.randomization_manifest_id,
                execution_policy_freeze_manifest_id=(support.execution_policy_freeze_manifest_id),
                test_coordinate=support.test_coordinate,
                strata=(shrunk_stratum,),
                coordinate_cluster_count=len(intersection),
                estimand_rule=support.estimand_rule,
            )
        )
    intersection_attempt = plan.model_dump(
        mode="python", exclude={"schema_version", "inference_plan_id"}
    )
    intersection_attempt["coordinate_supports"] = tuple(shrunk_supports)
    intersection_attempt["global_union_strata"] = (
        GlobalUnionStratumV2(
            stratum_id=plan.global_union_strata[0].stratum_id,
            semantic_task_cluster_ids=intersection,
            union_cluster_count=len(intersection),
        ),
    )
    with pytest.raises(
        ValidationError,
        match="multi-support simultaneous inference v2 contract failed validation",
    ):
        MultiSupportSimultaneousInferencePlanV2.from_content(**intersection_attempt)


def test_below_999_wrong_seed_and_zero_se_fail_closed() -> None:
    experiment = _experiment("disjoint")
    with pytest.raises(
        ValidationError,
        match="multi-support simultaneous inference v2 contract failed validation",
    ):
        MultiSupportSimultaneousInferencePlanV2.from_experiment(
            experiment=experiment,
            global_multiplicity_family_policy_material=MULTIPLICITY_MATERIAL,
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
            alpha_numerator=1,
            alpha_denominator=20,
            bootstrap_samples=998,
            minimum_independent_clusters_per_coordinate=20,
        )
    with pytest.raises(
        ValidationError,
        match="multi-support simultaneous inference v2 contract failed validation",
    ):
        MultiSupportSimultaneousInferencePlanV2.from_experiment(
            experiment=experiment,
            global_multiplicity_family_policy_material=b"post-hoc-policy",
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
            alpha_numerator=1,
            alpha_denominator=20,
            bootstrap_samples=999,
            minimum_independent_clusters_per_coordinate=20,
        )
    with pytest.raises(ValueError, match="seed domain"):
        run_multi_support_simultaneous_inference_v2(
            _plan("disjoint"),
            _artifacts("disjoint"),
            analysis_seed_domain_material=b"post-hoc-seed",
        )

    constant = []
    for artifact in _artifacts("disjoint"):
        exact = tuple(
            replace(item, numerator=0, denominator=1)
            for item in artifact.exact_coordinate_contributions
        )
        projected = tuple(replace(item, estimate=0.0) for item in artifact.coordinate_contributions)
        constant.append(
            _address_artifact(
                replace(
                    artifact,
                    exact_coordinate_contributions=exact,
                    coordinate_contributions=projected,
                )
            )
        )
    with pytest.raises(ValueError, match="zero or invalid"):
        run_multi_support_simultaneous_inference_v2(
            _plan("disjoint"),
            tuple(constant),
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )

    # The observed two-cluster coordinate varies, but too many union draws
    # retain fewer than two usable occurrences or have zero bootstrap SE.  The
    # frozen 95% gate records those draws and rejects the result rather than
    # silently conditioning on the small valid subset.
    with pytest.raises(ValueError, match="valid-draw count"):
        run_multi_support_simultaneous_inference_v2(
            _plan("sparse"),
            _artifacts("sparse"),
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )


def test_result_is_content_addressed_and_full_draw_replay_detects_tampering() -> None:
    plan = _plan("disjoint")
    artifacts = _artifacts("disjoint")
    result = _result("disjoint")
    assert (
        validate_multi_support_simultaneous_result_v2(
            plan,
            artifacts,
            result,
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )
        == result
    )
    tampered = replace(result, critical_value=result.critical_value + 0.01)
    with pytest.raises(ValueError, match="result artifact"):
        validate_multi_support_simultaneous_result_v2(
            plan,
            artifacts,
            tampered,
            analysis_seed_domain_material=ANALYSIS_SEED_MATERIAL,
        )

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from fractions import Fraction
from functools import lru_cache

import pytest

from secaware.analysis.confirmatory_contributions_v2 import (
    ConfirmatoryContributionArtifactV2,
    ExactCoordinateClusterContributionV2,
)
from secaware.analysis.selector_utility_v2 import (
    make_synthetic_verified_selector_primary_inputs_v2,
    run_verified_selector_utility_analysis_v2,
    validate_verified_selector_utility_analysis_result_v2,
)
from secaware.analysis.simultaneous_v2 import CoordinateClusterContributionV2
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.multi_support_inference_v2 import CoordinateSpecificSupportV2
from secaware.schema.policy_v2 import (
    SelectionFreezeManifest,
    SelectorSlotRecord,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from secaware.schema.selector_utility_v2 import (
    SelectorPairInferenceStatusV2,
    SelectorPairNonEvaluableReasonV2,
    SelectorUtilityAnalysisPlanV2,
    SelectorUtilityPlanScopeV2,
    SelectorUtilitySlotStatusV2,
)
from test_experiment_freeze_v2 import (
    ANALYSIS_SEED_DOMAIN_SHA256,
    MULTIPLICITY_POLICY_SHA256,
    _common_selection,
    _custom_bridge,
    _execution_for_root,
)
from test_multi_support_simultaneous_v2 import (
    _address_artifact,
    _coordinates,
)
from test_protocol_freeze_v2 import _inventory, _population_parts


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@lru_cache(maxsize=1)
def _selector_experiment() -> ConfirmatoryExperimentFreezeV2:
    coordinate_sets = (
        _coordinates("selector.a", range(5)),
        _coordinates("selector.b", range(5, 10)),
    )
    bridges = (
        _custom_bridge(k_r=1, target_salt="selector:a"),
        _custom_bridge(k_r=2, target_salt="selector:b"),
    )
    failed = _custom_bridge(k_r=3, target_salt="selector:failed")
    universe, base_selection = _common_selection(
        bridges=bridges,
        failed_skeleton=failed.candidate_skeleton,
    )
    fci_slots = base_selection.selector_slots
    assert len(fci_slots) == 4
    ges_slots = tuple(
        SelectorSlotRecord.from_content(
            candidate_universe_id=slot.candidate_universe_id,
            selector_id="ges",
            model_id=slot.model_id,
            rank=slot.rank,
            status=slot.status,
            candidate_skeleton_id=(
                fci_slots[0].candidate_skeleton_id if slot.rank == 2 else slot.candidate_skeleton_id
            ),
            selector_evidence_sha256=_sha(f"ges:{slot.rank}"),
            failure_code=slot.failure_code,
        )
        for slot in fci_slots
    )
    selection = SelectionFreezeManifest.from_components(
        universe=universe,
        budget_k=base_selection.budget_k,
        selector_slots=tuple(
            sorted(
                (*fci_slots, *ges_slots),
                key=lambda item: (item.selector_id, item.model_id, item.rank),
            )
        ),
        mappings=base_selection.mappings,
    )
    roots = []
    executions = []
    for index, (bridge, coordinates) in enumerate(zip(bridges, coordinate_sets, strict=True)):
        inventory = _inventory(coordinates)
        parts = _population_parts(
            bridge=bridge,
            inventory=inventory,
            coordinates=coordinates,
            minimum_tasks=5,
            minimum_clusters=5,
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
            preregistered_minimum_gate_pass_tasks=5,
            preregistered_minimum_gate_pass_clusters=5,
        )
        roots.append(root)
        executions.append(_execution_for_root(root, randomization_seed=20_260_820 + index))
    return ConfirmatoryExperimentFreezeV2.from_components(
        candidate_universe=universe,
        selection_freeze=selection,
        protocol_roots=tuple(roots),
        execution_policy_freezes=tuple(executions),
        global_multiplicity_family_policy_sha256=MULTIPLICITY_POLICY_SHA256,
        analysis_seed_domain_sha256=ANALYSIS_SEED_DOMAIN_SHA256,
    )


@lru_cache(maxsize=1)
def _selector_plan() -> SelectorUtilityAnalysisPlanV2:
    return SelectorUtilityAnalysisPlanV2.for_synthetic_validation(
        _selector_experiment(),
        outer_bootstrap_samples=19,
        inner_bootstrap_samples=19,
    )


def _coordinate_value(
    support: CoordinateSpecificSupportV2,
    *,
    strong_hypothesis_id: str,
) -> tuple[Fraction, ...]:
    result = []
    for stratum in support.strata:
        for cluster_id in stratum.semantic_task_cluster_ids:
            cluster_index = int(cluster_id.rsplit(".", maxsplit=1)[1])
            if support.test_coordinate.hypothesis_id == strong_hypothesis_id:
                value = Fraction(14 + (cluster_index % 5), 20)
            else:
                # Deliberately close to the adjusted boundary.  This makes the
                # outer selector difference capable of varying, while the
                # hand-checked full-data point remains outcome-derived.
                value = Fraction((cluster_index % 5) - 1, 20)
            result.append(value)
    return tuple(result)


@lru_cache(maxsize=1)
def _selector_artifacts() -> tuple[ConfirmatoryContributionArtifactV2, ...]:
    plan = _selector_plan()
    first_protocolized = next(
        item
        for item in plan.slot_bindings
        if item.selector_id == "fci" and item.rank == 1 and item.final_hypothesis_id is not None
    )
    strong_hypothesis_id = first_protocolized.final_hypothesis_id
    result = []
    for support in plan.primary_inference_plan.coordinate_supports:
        values = iter(_coordinate_value(support, strong_hypothesis_id=strong_hypothesis_id))
        exact = tuple(
            ExactCoordinateClusterContributionV2(
                test_coordinate_id=support.test_coordinate.test_coordinate_id,
                stratum_id=stratum.stratum_id,
                semantic_task_cluster_id=cluster_id,
                numerator=value.numerator,
                denominator=value.denominator,
            )
            for stratum in support.strata
            for cluster_id in stratum.semantic_task_cluster_ids
            for value in (next(values),)
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


@lru_cache(maxsize=1)
def _verified_primary_inputs():
    return make_synthetic_verified_selector_primary_inputs_v2(
        _selector_plan(),
        _selector_artifacts(),
        synthetic_critical_value=2.0,
    )


@lru_cache(maxsize=1)
def _selector_result():
    return run_verified_selector_utility_analysis_v2(
        _selector_plan(),
        _verified_primary_inputs(),
    )


def test_plan_is_uniquely_derived_and_synthetic_mode_cannot_claim_formal_status() -> None:
    plan = _selector_plan()
    experiment = _selector_experiment()

    assert plan.plan_scope is SelectorUtilityPlanScopeV2.SYNTHETIC_VALIDATION_ONLY
    assert plan.formal_selector_claim_allowed is False
    assert plan.formal_glue_required is True
    assert plan.outer_bootstrap_samples == plan.inner_bootstrap_samples == 19
    assert plan.primary_inference_plan.experiment == experiment
    assert plan.candidate_universe_id == experiment.candidate_universe.candidate_universe_id
    assert plan.selection_freeze_id == experiment.selection_freeze.selection_freeze_id
    assert len(plan.coordinate_bindings) == experiment.hypothesis_model_coordinate_count == 4
    assert len({item.test_coordinate_id for item in plan.coordinate_bindings}) == 4
    assert plan.pair_family_size == len(plan.pair_family) == 1
    assert SelectorUtilityAnalysisPlanV2.model_validate_json(plan.model_dump_json()) == plan

    formal = SelectorUtilityAnalysisPlanV2.from_experiment(experiment)
    assert formal.formal_selector_claim_allowed is True
    assert formal.outer_bootstrap_samples == 999
    assert formal.inner_bootstrap_samples == 499
    assert formal.minimum_valid_inner_draws == 475


def test_strict_yield_counts_empty_failed_and_duplicate_h_slots_without_duplicate_tests() -> None:
    result = _selector_result()
    points = {item.selector_id: item for item in result.selector_points}

    assert result.selector_utility_result_id.startswith("selector_utility_result_v2_")
    assert result.conditional_on_single_frozen_discovery_split is True
    assert result.discovery_rerun_or_rerank_performed is False
    assert result.formal_selector_claim_allowed is False
    assert result.formal_glue_required is True
    assert result.formal_glue_completed is False
    assert result.primary_input_verification_scope == ("synthetic_hand_checked_primary_fixture_v1")
    assert all(item.budget_k == 4 for item in points.values())
    assert {item.slot_status for point in points.values() for item in point.slot_contributions} >= {
        SelectorUtilitySlotStatusV2.EMPTY.value,
        SelectorUtilitySlotStatusV2.BRIDGE_OR_PROTOCOLIZATION_FAILED.value,
    }
    for point in points.values():
        assert len(point.slot_contributions) == point.budget_k
        for slot in point.slot_contributions:
            if slot.slot_status != SelectorUtilitySlotStatusV2.PROTOCOLIZED.value:
                assert slot.confirmed_contribution == 0
                assert slot.test_coordinate_id is None

    ges_protocolized = tuple(
        item
        for item in points["ges"].slot_contributions
        if item.slot_status == SelectorUtilitySlotStatusV2.PROTOCOLIZED.value
    )
    assert len(ges_protocolized) == 2
    assert ges_protocolized[0].final_hypothesis_id == ges_protocolized[1].final_hypothesis_id
    assert ges_protocolized[0].test_coordinate_id == ges_protocolized[1].test_coordinate_id
    assert len(result.coordinate_confirmations) == 4
    assert result.valid_outer_draw_count + result.invalid_outer_draw_count == 19


def test_nested_pair_family_is_complete_and_zero_or_low_variance_is_typed_non_evaluable() -> None:
    plan = _selector_plan()
    result = _selector_result()

    assert tuple(item.selector_pair_id for item in result.pair_points) == tuple(
        item.selector_pair_id for item in plan.pair_family
    )
    assert result.pair_inference_status in {
        SelectorPairInferenceStatusV2.EVALUATED,
        SelectorPairInferenceStatusV2.NON_EVALUABLE,
    }
    if result.pair_inference_status is SelectorPairInferenceStatusV2.EVALUATED:
        assert result.pair_non_evaluable_reason is None
        assert result.pair_critical_value is not None
        assert len(result.pair_intervals) == len(plan.pair_family)
    else:
        assert result.pair_non_evaluable_reason in {
            SelectorPairNonEvaluableReasonV2.INSUFFICIENT_VALID_OUTER_DRAWS,
            SelectorPairNonEvaluableReasonV2.ZERO_OR_INVALID_PAIR_STANDARD_ERROR,
        }
        assert result.pair_intervals == ()
    for draw in result.valid_outer_draws:
        assert len(draw.coordinate_retained_counts) == len(plan.coordinate_bindings)
        assert tuple(item.selector_pair_id for item in draw.pair_differences) == tuple(
            item.selector_pair_id for item in plan.pair_family
        )


def test_slot_rank_universe_coordinate_direction_pair_and_bootstrap_tampering_fail_closed() -> None:
    plan = _selector_plan()
    verified = _verified_primary_inputs()
    attacks = []

    deleted_slot = plan.model_copy(update={"slot_bindings": plan.slot_bindings[:-1]})
    attacks.append(deleted_slot)

    deleted_failed_slot = plan.model_copy(
        update={
            "slot_bindings": tuple(
                item
                for item in plan.slot_bindings
                if item.slot_status
                is not SelectorUtilitySlotStatusV2.BRIDGE_OR_PROTOCOLIZATION_FAILED
            )
        }
    )
    attacks.append(deleted_failed_slot)

    reranked = plan.model_copy(
        update={
            "slot_bindings": (
                plan.slot_bindings[0].model_copy(update={"rank": 2}),
                *plan.slot_bindings[1:],
            )
        }
    )
    attacks.append(reranked)

    wrong_universe = plan.model_copy(
        update={"candidate_universe_id": "candidate_universe_" + "f" * 64}
    )
    attacks.append(wrong_universe)

    wrong_direction = plan.model_copy(
        update={
            "coordinate_bindings": (
                plan.coordinate_bindings[0].model_copy(update={"direction_multiplier": -1}),
                *plan.coordinate_bindings[1:],
            )
        }
    )
    attacks.append(wrong_direction)

    wrong_model = plan.model_copy(
        update={
            "coordinate_bindings": (
                plan.coordinate_bindings[0].model_copy(update={"model_id": "model.foreign"}),
                *plan.coordinate_bindings[1:],
            )
        }
    )
    attacks.append(wrong_model)

    wrong_hypothesis = plan.model_copy(
        update={
            "coordinate_bindings": (
                plan.coordinate_bindings[0].model_copy(
                    update={"hypothesis_id": "hypothesis_" + "f" * 64}
                ),
                *plan.coordinate_bindings[1:],
            )
        }
    )
    attacks.append(wrong_hypothesis)

    wrong_outcome = plan.model_copy(
        update={
            "coordinate_bindings": (
                plan.coordinate_bindings[0].model_copy(update={"outcome_name": "y_joint"}),
                *plan.coordinate_bindings[1:],
            )
        }
    )
    attacks.append(wrong_outcome)

    deleted_coordinate = plan.model_copy(
        update={"coordinate_bindings": plan.coordinate_bindings[:-1]}
    )
    attacks.append(deleted_coordinate)

    shrunk_pairs = plan.model_copy(update={"pair_family": (), "pair_family_size": 0})
    attacks.append(shrunk_pairs)

    wrong_b = plan.model_copy(update={"outer_bootstrap_samples": 21})
    attacks.append(wrong_b)

    wrong_seed = plan.model_copy(update={"analysis_seed_domain_sha256": "f" * 64})
    attacks.append(wrong_seed)

    for attacked_plan in attacks:
        with pytest.raises(ValueError, match="selector utility analysis plan failed validation"):
            run_verified_selector_utility_analysis_v2(attacked_plan, verified)


def test_cluster_or_artifact_deletion_intersection_and_result_tampering_fail_replay() -> None:
    plan = _selector_plan()
    artifacts = _selector_artifacts()
    verified = _verified_primary_inputs()
    result = _selector_result()

    missing_artifact_inputs = copy.copy(verified)
    missing_artifact_inputs.artifacts = artifacts[:-1]
    with pytest.raises(ValueError, match="complete primary contribution"):
        run_verified_selector_utility_analysis_v2(plan, missing_artifact_inputs)

    victim = artifacts[0]
    deleted_cluster = _address_artifact(
        replace(
            victim,
            exact_coordinate_contributions=victim.exact_coordinate_contributions[:-1],
            coordinate_contributions=victim.coordinate_contributions[:-1],
        )
    )
    deleted_cluster_inputs = copy.copy(verified)
    deleted_cluster_inputs.artifacts = (deleted_cluster, *artifacts[1:])
    with pytest.raises(ValueError, match="primary contribution artifact support"):
        run_verified_selector_utility_analysis_v2(plan, deleted_cluster_inputs)

    common = tuple(
        sorted(
            set.intersection(
                *(
                    {
                        cluster_id
                        for stratum in support.strata
                        for cluster_id in stratum.semantic_task_cluster_ids
                    }
                    for support in plan.primary_inference_plan.coordinate_supports
                )
            )
        )
    )
    assert common == ()
    shared_clusters = (
        plan.primary_inference_plan.coordinate_supports[0].strata[0].semantic_task_cluster_ids[:2]
    )
    intersected_supports = tuple(
        support.model_copy(
            update={
                "strata": (
                    support.strata[0].model_copy(
                        update={
                            "semantic_task_cluster_ids": shared_clusters,
                            "cluster_weight_numerators": (1, 1),
                            "cluster_weight_denominator": 2,
                        }
                    ),
                ),
                "coordinate_cluster_count": 2,
            }
        )
        for support in plan.primary_inference_plan.coordinate_supports
    )
    intersection_attempt = plan.model_copy(
        update={
            "primary_inference_plan": plan.primary_inference_plan.model_copy(
                update={"coordinate_supports": intersected_supports}
            )
        }
    )
    with pytest.raises(ValueError, match="selector utility analysis plan failed validation"):
        run_verified_selector_utility_analysis_v2(intersection_attempt, verified)

    tampered = replace(result, valid_outer_draw_count=result.valid_outer_draw_count + 1)
    with pytest.raises(ValueError, match="result artifact"):
        validate_verified_selector_utility_analysis_result_v2(
            plan,
            verified,
            tampered,
        )

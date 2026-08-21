from __future__ import annotations

import hashlib
from fractions import Fraction
from functools import cache

import pytest
from pydantic import ValidationError

from secaware.analysis.confirmatory_contributions_v2 import (
    derive_frozen_formal_family_contributions_v2,
)
from secaware.analysis.multi_support_robustness_v2 import (
    CrossModelReplicationLabelV2,
    _cross_model_label_from_statuses,
    _derived_coordinate_values,
    _realization_label,
    _strong_label_conditions_met,
    _validate_complete_coverage_keys,
    _validate_formal_execution_counts,
    _validate_interaction_observed_statistic,
    _validate_interaction_reference_binding,
    run_synthetic_multi_support_robustness_smoke_v2,
)
from secaware.analysis.realization_robustness_v2 import RealizationRobustnessLabelV2
from secaware.experiments.execution_v2 import (
    ProvenanceClosedAssignmentCoverageManifestV2,
)
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.experiments import ArmRole
from secaware.schema.inference_v2 import SimultaneousCoordinateKindV2
from secaware.schema.multi_support_robustness_v2 import (
    CrossModelReplicationPolicyV2,
    HypothesisRobustnessDecisionV2,
    MultiSupportArmRealizationInteractionReferenceV2,
    MultiSupportRobustnessPolicyFreezeV2,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from test_experiment_freeze_v2 import (
    ExperimentComponents,
    _common_selection,
    _custom_bridge,
    _execution_for_root,
    _freeze,
)
from test_protocol_freeze_v2 import _inventory, _population_parts
from test_run_evidence_v2 import _accounting_for_execution

POLICY_MATERIAL = b"phase0-explicit-multi-support-robustness-policy"
MODEL_IDS = ("model.alpha", "model.beta")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _pure_interaction_reference(
    *,
    observed_statistic: float = 0.25,
    randomization_manifest_id: str = "randomization_manifest_v2_" + "2" * 64,
) -> MultiSupportArmRealizationInteractionReferenceV2:
    return MultiSupportArmRealizationInteractionReferenceV2.from_content(
        robustness_policy_freeze_id=("multi_support_robustness_policy_v2_" + "1" * 64),
        robustness_hypothesis_spec_id="robustness-spec.h1",
        global_robustness_family_id="robustness-family.global",
        confirmatory_experiment_freeze_id="experiment.h1",
        hypothesis_id="hypothesis.h1",
        model_id=MODEL_IDS[0],
        population_freeze_manifest_id="population.h1",
        randomization_manifest_id=randomization_manifest_id,
        provenance_closed_coverage_manifest_id=("provenance_closed_coverage_v2_" + "3" * 64),
        interaction_statistic_method="max_abs_realization_minus_qh_policy_v1",
        reference_method="semantic_cluster_arm_randomization_v1",
        joint_reference_run_sha256="4" * 64,
        observed_statistic=observed_statistic,
        reference_statistics=(0.5,) * 999,
    )


def _coordinates(
    task_prefix: str,
    cluster_indices: range,
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (f"{task_prefix}.task.{index:02d}", f"cluster.robust.{index:02d}")
        for index in cluster_indices
    )


def _build_experiment(
    coordinate_sets: tuple[tuple[tuple[str, str], ...], ...],
    realization_counts: tuple[int, ...],
    *,
    salt: str,
) -> ConfirmatoryExperimentFreezeV2:
    bridges = tuple(
        _custom_bridge(
            model_scope=MODEL_IDS,
            k_r=k_r,
            target_salt=f"multi-support-robustness:{salt}:{index}",
        )
        for index, k_r in enumerate(realization_counts)
    )
    failed = _custom_bridge(
        model_scope=MODEL_IDS,
        k_r=max(realization_counts) + 1,
        target_salt=f"multi-support-robustness:{salt}:failed",
    )
    universe, selection = _common_selection(
        bridges=bridges,
        failed_skeleton=failed.candidate_skeleton,
    )
    roots = []
    executions = []
    for index, (bridge, coordinates) in enumerate(zip(bridges, coordinate_sets, strict=True)):
        inventory = _inventory(coordinates)
        parts = _population_parts(
            bridge=bridge,
            inventory=inventory,
            coordinates=coordinates,
            minimum_tasks=len(coordinates),
            minimum_clusters=len(coordinates),
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
            preregistered_minimum_gate_pass_clusters=len(coordinates),
        )
        roots.append(root)
        executions.append(_execution_for_root(root, randomization_seed=20_260_830 + index))
    return _freeze(
        ExperimentComponents(
            universe=universe,
            selection=selection,
            roots=tuple(roots),
            executions=tuple(executions),
        )
    )


@cache
def _experiment() -> ConfirmatoryExperimentFreezeV2:
    return _build_experiment(
        (
            _coordinates("robust.a", range(2)),
            _coordinates("robust.b", range(1, 4)),
        ),
        (2, 3),
        salt="policy",
    )


@cache
def _run_experiment() -> ConfirmatoryExperimentFreezeV2:
    return _build_experiment(
        (_coordinates("robust.run", range(5)),),
        (2,),
        salt="run",
    )


def _decisions(
    experiment: ConfirmatoryExperimentFreezeV2,
    *,
    minimum_support: int = 2,
) -> tuple[HypothesisRobustnessDecisionV2, ...]:
    return tuple(
        HypothesisRobustnessDecisionV2.from_hypothesis(
            root.population.hypothesis,
            practical_equivalence_margin_numerator=1,
            practical_equivalence_margin_denominator=2,
            minimum_direction_consistent_realizations=len(
                root.population.hypothesis.realization_spec_ids
            ),
            minimum_independent_clusters_per_realization=minimum_support,
            interaction_minimum_reference_draws=999,
        )
        for root in experiment.protocol_roots
    )


@cache
def _policy() -> MultiSupportRobustnessPolicyFreezeV2:
    experiment = _experiment()
    return MultiSupportRobustnessPolicyFreezeV2.from_experiment(
        experiment=experiment,
        hypothesis_decisions=_decisions(experiment),
        cross_model_policy=CrossModelReplicationPolicyV2.from_model_scope(experiment.model_ids),
        robustness_policy_material=POLICY_MATERIAL,
    )


@cache
def _run_policy() -> MultiSupportRobustnessPolicyFreezeV2:
    experiment = _run_experiment()
    return MultiSupportRobustnessPolicyFreezeV2.from_experiment(
        experiment=experiment,
        hypothesis_decisions=_decisions(experiment, minimum_support=2),
        cross_model_policy=CrossModelReplicationPolicyV2.from_model_scope(experiment.model_ids),
        robustness_policy_material=POLICY_MATERIAL + b":run",
    )


def _cluster_index(cluster_id: str) -> int:
    return int(cluster_id.rsplit(".", maxsplit=1)[1])


@cache
def _coverages() -> tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...]:
    experiment = _run_experiment()
    output = []
    for execution_index, execution in enumerate(experiment.execution_policy_freezes):
        realization_ids = execution.randomization.population.hypothesis.realization_spec_ids
        realization_index = {
            realization_id: index for index, realization_id in enumerate(realization_ids)
        }
        secure_assignment_ids = frozenset(
            assignment.assignment_id
            for assignment in execution.randomization.assignments
            if assignment.assigned_arm is ArmRole.TARGET_PATCH
            or (
                assignment.assigned_arm
                in {
                    ArmRole.NOOP_REWRITE,
                    ArmRole.LENGTH_MATCHED_PLACEBO,
                    ArmRole.GENERIC_SECURITY_REMINDER,
                }
                and (
                    (
                        _cluster_index(assignment.block.semantic_task_cluster_id)
                        + execution_index
                        + (0 if assignment.block.model_id == MODEL_IDS[0] else 1)
                    )
                    % (realization_index[assignment.block.realization_spec_id] + 2)
                    == 0
                )
            )
        )
        accounting = _accounting_for_execution(
            experiment=experiment,
            execution_index=execution_index,
            secure_assignment_ids=secure_assignment_ids,
        )
        assert accounting.confirmatory_coverage is not None
        output.append(accounting.confirmatory_coverage)
    return tuple(output)


@cache
def _interaction_references() -> tuple[MultiSupportArmRealizationInteractionReferenceV2, ...]:
    policy = _run_policy()
    coverage_by_hypothesis = {
        item.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id: item
        for item in _coverages()
    }
    root_by_hypothesis = {
        item.population.hypothesis.hypothesis_id: item for item in policy.experiment.protocol_roots
    }
    support_by_hm = {
        (item.test_coordinate.hypothesis_id, item.test_coordinate.model_id): item
        for item in policy.primary_inference_plan.coordinate_supports
    }
    specification_by_hm = {
        (item.hypothesis_id, item.model_id): item for item in policy.hypothesis_model_specifications
    }
    references = []
    for key, specification in sorted(specification_by_hm.items()):
        support = support_by_hm[key]
        coverage = coverage_by_hypothesis[specification.hypothesis_id]
        artifact = derive_frozen_formal_family_contributions_v2(
            root_by_hypothesis[specification.hypothesis_id].population,
            coverage,
            support.test_coordinate,
        )
        values = {
            (
                item.realization_spec_id,
                item.stratum_id,
                item.semantic_task_cluster_id,
            ): Fraction(item.numerator, item.denominator)
            for item in artifact.exact_realization_contributions
        }
        realization_means = {}
        for realization_id in specification.realization_spec_ids:
            realization_means[realization_id] = sum(
                (
                    stratum.stratum_weight
                    * sum(
                        (
                            Fraction(numerator, stratum.cluster_weight_denominator)
                            * values[(realization_id, stratum.stratum_id, cluster_id)]
                            for cluster_id, numerator in zip(
                                stratum.semantic_task_cluster_ids,
                                stratum.cluster_weight_numerators,
                                strict=True,
                            )
                        ),
                        Fraction(0, 1),
                    )
                    for stratum in support.strata
                ),
                Fraction(0, 1),
            )
        pooled = sum(
            (
                Fraction(numerator, specification.probability_denominator)
                * realization_means[realization_id]
                for realization_id, numerator in zip(
                    specification.realization_spec_ids,
                    specification.probability_numerators,
                    strict=True,
                )
            ),
            Fraction(0, 1),
        )
        observed = float(max(abs(value - pooled) for value in realization_means.values()))
        references.append(
            MultiSupportArmRealizationInteractionReferenceV2.from_content(
                robustness_policy_freeze_id=policy.robustness_policy_freeze_id,
                robustness_hypothesis_spec_id=(specification.robustness_hypothesis_spec_id),
                global_robustness_family_id=policy.robustness_family.family_id,
                confirmatory_experiment_freeze_id=(policy.confirmatory_experiment_freeze_id),
                hypothesis_id=specification.hypothesis_id,
                model_id=specification.model_id,
                population_freeze_manifest_id=support.population_freeze_manifest_id,
                randomization_manifest_id=support.randomization_manifest_id,
                provenance_closed_coverage_manifest_id=(
                    coverage.provenance_closed_coverage_manifest_id
                ),
                interaction_statistic_method=("max_abs_realization_minus_qh_policy_v1"),
                reference_method="semantic_cluster_arm_randomization_v1",
                joint_reference_run_sha256=_sha("joint-interaction-reference-run"),
                observed_statistic=observed,
                reference_statistics=tuple(
                    observed + 0.01 * (1 + index % 7) for index in range(999)
                ),
            )
        )
    return tuple(references)


@cache
def _result():
    return run_synthetic_multi_support_robustness_smoke_v2(
        _run_policy(),
        _coverages(),
    )


def test_policy_freezes_complete_coordinate_specific_h_by_m_by_r_family() -> None:
    policy = _policy()
    experiment = _experiment()

    assert policy.bootstrap_samples == 999
    assert policy.minimum_valid_bootstrap_draws == 950
    assert policy.formal_analysis_glue_binding_required is True
    assert "not_yet_embedded" in policy.formal_analysis_glue_binding_status
    assert len(policy.hypothesis_model_specifications) == 4
    assert len(policy.coordinate_supports) == sum(
        3 * len(item.realization_spec_ids) for item in policy.hypothesis_model_specifications
    )
    assert {item.test_coordinate.coordinate_kind for item in policy.coordinate_supports} == {
        SimultaneousCoordinateKindV2.REALIZATION_EFFECT,
        SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT,
        SimultaneousCoordinateKindV2.REALIZATION_DEVIATION,
    }
    supports_by_hypothesis = {
        hypothesis_id: {
            cluster_id
            for item in policy.coordinate_supports
            if item.test_coordinate.hypothesis_id == hypothesis_id
            for stratum in item.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        }
        for hypothesis_id in experiment.hypothesis_ids
    }
    assert len(supports_by_hypothesis[experiment.hypothesis_ids[0]]) == 2
    assert len(supports_by_hypothesis[experiment.hypothesis_ids[1]]) == 3
    assert len(set.union(*supports_by_hypothesis.values())) == 4
    assert len(set.intersection(*supports_by_hypothesis.values())) == 1
    assert policy.global_union_strata[0].union_cluster_count == 4


def test_delta_direction_support_and_replication_are_explicit_pre_outcome_policy() -> None:
    policy = _policy()
    assert all(
        item.practical_equivalence_margin_numerator == 1
        and item.practical_equivalence_margin_denominator == 2
        and item.minimum_direction_consistent_realizations == len(item.realization_spec_ids)
        and item.minimum_independent_clusters_per_realization == 2
        and item.interaction_minimum_reference_draws == 999
        for item in policy.hypothesis_decisions
    )
    assert policy.cross_model_policy.required_confirmed_model_count == len(MODEL_IDS)
    assert policy.cross_model_policy.pooling_rule == ("model_specific_effects_never_pooled_v1")

    first = _experiment().protocol_roots[0].population.hypothesis
    with pytest.raises(ValueError, match="robustness"):
        HypothesisRobustnessDecisionV2.from_hypothesis(
            first,
            practical_equivalence_margin_numerator=1,
            practical_equivalence_margin_denominator=2,
            minimum_direction_consistent_realizations=1,
            minimum_independent_clusters_per_realization=2,
            interaction_minimum_reference_draws=999,
        )
    with pytest.raises(ValueError, match="robustness"):
        MultiSupportRobustnessPolicyFreezeV2.from_experiment(
            experiment=_experiment(),
            hypothesis_decisions=_decisions(_experiment(), minimum_support=4),
            cross_model_policy=CrossModelReplicationPolicyV2.from_model_scope(MODEL_IDS),
            robustness_policy_material=POLICY_MATERIAL,
        )


def test_realization_loo_and_deviation_match_exact_hand_calculation() -> None:
    policy = _policy()
    values = {}
    for specification in policy.hypothesis_model_specifications:
        for support in policy.primary_inference_plan.coordinate_supports:
            if (
                support.test_coordinate.hypothesis_id != specification.hypothesis_id
                or support.test_coordinate.model_id != specification.model_id
            ):
                continue
            for realization_index, realization_id in enumerate(specification.realization_spec_ids):
                value = Fraction(1, 4) if realization_index == 0 else Fraction(3, 4)
                for stratum in support.strata:
                    for cluster_id in stratum.semantic_task_cluster_ids:
                        values[
                            (
                                specification.hypothesis_id,
                                specification.model_id,
                                realization_id,
                                stratum.stratum_id,
                                cluster_id,
                            )
                        ] = value
    derived = _derived_coordinate_values(policy, values)
    specification = next(
        item
        for item in policy.hypothesis_model_specifications
        if len(item.realization_spec_ids) == 2
    )
    realization_id = specification.realization_spec_ids[0]
    supports = {
        (
            item.test_coordinate.coordinate_kind,
            item.test_coordinate.analysis_component_id,
        ): item
        for item in policy.coordinate_supports
        if item.test_coordinate.hypothesis_id == specification.hypothesis_id
        and item.test_coordinate.model_id == specification.model_id
    }
    cluster_id = next(
        cluster
        for stratum in next(iter(supports.values())).strata
        for cluster in stratum.semantic_task_cluster_ids
    )
    stratum_id = next(iter(supports.values())).strata[0].stratum_id

    def value(kind: SimultaneousCoordinateKindV2, prefix: str) -> Fraction:
        coordinate = supports[(kind, f"{prefix}.{realization_id}")].test_coordinate
        return derived[(coordinate.test_coordinate_id, stratum_id, cluster_id)]

    assert value(SimultaneousCoordinateKindV2.REALIZATION_EFFECT, "realization") == Fraction(1, 4)
    assert value(SimultaneousCoordinateKindV2.LEAVE_ONE_REALIZATION_OUT, "loo") == Fraction(3, 4)
    assert value(SimultaneousCoordinateKindV2.REALIZATION_DEVIATION, "deviation") == Fraction(-1, 4)


def test_end_to_end_uses_real_closed_contributions_and_shared_union_draws() -> None:
    result = _result()
    policy = _run_policy()

    assert result.smoke_result_id.startswith("synthetic_multi_support_robustness_smoke_v2_")
    assert result.purpose == "synthetic_non_claim_pipeline_smoke_only_v1"
    assert result.input_provenance_closed_coverage_manifest_ids == tuple(
        item.provenance_closed_coverage_manifest_id for item in _coverages()
    )
    assert len(result.input_contribution_artifact_ids) == 2
    assert result.synthetic_bootstrap_samples == 19
    assert result.formal_policy_bootstrap_samples == 999
    assert policy.bootstrap_samples == 999
    assert policy.minimum_valid_bootstrap_draws == 950
    assert result.formal_robustness_label_awarded is False
    assert result.cross_model_replication_label_awarded is False
    inference = result.inference_result
    assert inference.inference_scope == "synthetic_non_claim_smoke_b19_v1"
    assert inference.bootstrap_samples == 19
    assert inference.minimum_valid_bootstrap_draws == 1
    assert inference.valid_draw_count >= 1
    assert inference.valid_draw_count + inference.invalid_draw_count == 19
    assert len(inference.intervals) == len(policy.coordinate_supports) == 12
    assert all(
        len(draw.stratum_draws) == len(policy.global_union_strata)
        and len(draw.global_sample_sha256) == 64
        and all(
            retained.retained_occurrence_count
            <= {stratum.stratum_id: stratum.occurrence_count for stratum in draw.stratum_draws}[
                retained.stratum_id
            ]
            for retained in draw.coordinate_retained_counts
        )
        for draw in inference.draws
    )


@pytest.mark.parametrize(
    "failed_condition",
    (
        "base_confirmed",
        "all_realization_points",
        "direction_threshold_met",
        "no_reverse_realization_interval",
        "all_leave_one_out_supported",
        "heterogeneity_equivalent",
        "minimum_support_met",
        "interaction_condition_met",
    ),
)
def test_every_frozen_condition_is_a_true_strong_label_gate(
    failed_condition: str,
) -> None:
    conditions = {
        "base_confirmed": True,
        "all_realization_points": True,
        "direction_threshold_met": True,
        "no_reverse_realization_interval": True,
        "all_leave_one_out_supported": True,
        "heterogeneity_equivalent": True,
        "minimum_support_met": True,
        "interaction_condition_met": True,
    }
    assert _strong_label_conditions_met(**conditions)
    conditions[failed_condition] = False
    assert not _strong_label_conditions_met(**conditions)


def test_incomplete_interaction_family_keeps_average_but_cannot_award_strong_label() -> None:
    conditions = {
        "base_confirmed": True,
        "all_realization_points": True,
        "direction_threshold_met": True,
        "no_reverse_realization_interval": True,
        "all_leave_one_out_supported": True,
        "heterogeneity_equivalent": True,
        "minimum_support_met": True,
        "interaction_condition_met": False,
    }
    all_conditions = _strong_label_conditions_met(**conditions)
    assert not all_conditions
    assert (
        _realization_label(
            base_confirmed=True,
            base_reverse=False,
            all_frozen_conditions_met=all_conditions,
        )
        is RealizationRobustnessLabelV2.AVERAGE_POLICY_CONFIRMED
    )


def test_cross_model_never_pools_single_model_is_na_and_any_failure_disqualifies() -> None:
    policy = CrossModelReplicationPolicyV2.from_model_scope(MODEL_IDS)
    assert (
        _cross_model_label_from_statuses(
            policy,
            confirmed_model_count=2,
            any_reverse_model=False,
        )
        is CrossModelReplicationLabelV2.REPLICATED
    )
    assert (
        _cross_model_label_from_statuses(
            policy,
            confirmed_model_count=1,
            any_reverse_model=False,
        )
        is CrossModelReplicationLabelV2.NOT_REPLICATED
    )
    assert (
        _cross_model_label_from_statuses(
            policy,
            confirmed_model_count=2,
            any_reverse_model=True,
        )
        is CrossModelReplicationLabelV2.NOT_REPLICATED
    )
    one_model_policy = CrossModelReplicationPolicyV2.from_model_scope((MODEL_IDS[0],))
    assert (
        _cross_model_label_from_statuses(
            one_model_policy,
            confirmed_model_count=1,
            any_reverse_model=False,
        )
        is CrossModelReplicationLabelV2.NOT_APPLICABLE
    )


def test_deleted_coverage_posthoc_policy_and_wrong_reference_binding_fail_closed() -> None:
    with pytest.raises(ValueError, match="complete provenance-closed coverage"):
        _validate_complete_coverage_keys(
            frozenset({"hypothesis.h1", "hypothesis.h2"}),
            frozenset({"hypothesis.h1"}),
        )
    with pytest.raises(ValueError, match="policy freeze"):
        _validate_formal_execution_counts(
            bootstrap_samples=999,
            minimum_valid_bootstrap_draws=949,
        )

    wrong = _pure_interaction_reference(
        randomization_manifest_id="randomization_manifest_v2_" + "f" * 64
    )
    with pytest.raises(ValueError, match="interaction reference provenance"):
        _validate_interaction_reference_binding(
            wrong,
            robustness_policy_freeze_id=("multi_support_robustness_policy_v2_" + "1" * 64),
            robustness_hypothesis_spec_id="robustness-spec.h1",
            global_robustness_family_id="robustness-family.global",
            confirmatory_experiment_freeze_id="experiment.h1",
            population_freeze_manifest_id="population.h1",
            randomization_manifest_id="randomization_manifest_v2_" + "2" * 64,
            provenance_closed_coverage_manifest_id=("provenance_closed_coverage_v2_" + "3" * 64),
            interaction_minimum_reference_draws=999,
        )


def test_content_addresses_and_wrong_observed_interaction_are_detected() -> None:
    original = _pure_interaction_reference()
    with pytest.raises(ValidationError, match="robustness"):
        MultiSupportArmRealizationInteractionReferenceV2.model_validate(
            original.model_copy(
                update={
                    "interaction_reference_id": (
                        "multi_support_interaction_reference_v2_" + "f" * 64
                    )
                }
            ),
            strict=True,
        )
    with pytest.raises(ValueError, match="interaction observed statistic"):
        _validate_interaction_observed_statistic(original, 0.35)

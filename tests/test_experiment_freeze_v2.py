from __future__ import annotations

from dataclasses import dataclass

import pytest
from pydantic import ValidationError

from secaware.experiments.execution_v2 import (
    ExecutionPolicyFreezeManifestV2,
    MeasurementExecutionPolicyV2,
    ModelExecutionPolicyV2,
)
from secaware.experiments.randomization_v2 import (
    ModelGenerationParametersV2,
    RandomizationManifestV2,
)
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.features import FeatureOperation
from secaware.schema.intervention_v2 import (
    ArmProtocolV2,
    InterventionBridgeRecordV2,
    TargetSpecV2,
)
from secaware.schema.policy_v2 import (
    BridgeStatus,
    CandidateSkeleton,
    CandidateUniverseManifest,
    ExpectedDirection,
    SelectionFreezeManifest,
    SelectionMappingRecord,
    SelectorSlotRecord,
    SelectorSlotStatus,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from fixtures_v2 import (
    MODELS,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    _bridge,
    _context_spec,
    _feature_spec,
    _inventory,
    _population_parts,
    _realization_policy,
    _realizations,
    _sha,
)

MULTIPLICITY_POLICY_SHA256 = _sha("global-multiplicity-policy")
ANALYSIS_SEED_DOMAIN_SHA256 = _sha("analysis-seed-domain")


def _custom_bridge(
    *,
    model_scope: tuple[str, ...] = MODELS,
    k_r: int = 2,
    target_salt: str = "custom",
    arm_probability_numerators: tuple[int, int, int, int] = (1, 1, 1, 1),
    arm_probability_denominator: int = 4,
) -> InterventionBridgeRecordV2:
    context = _context_spec()
    feature = _feature_spec()
    policy = _realization_policy(k_r)
    skeleton = CandidateSkeleton.from_content(
        context_query_id=context.context_query_id,
        actionable_feature_spec_id=feature.actionable_feature_spec_id,
        feature_id=feature.feature_id,
        operation=FeatureOperation.ADD,
        realization_policy_spec_id=policy.realization_policy_spec_id,
        outcome_id="y_secure_yield",
        expected_direction=ExpectedDirection.POSITIVE,
        cwe="CWE-89",
        task_archetype="value-parameterization",
        model_scope=model_scope,
        context_query_catalog_sha256=context.context_query_catalog_sha256,
        feature_catalog_sha256=feature.feature_catalog_sha256,
        eligibility_function_sha256=SHA_D,
    )
    realizations = _realizations(skeleton, policy)
    target = TargetSpecV2.from_components(
        skeleton=skeleton,
        context_query=context,
        actionable_feature=feature,
        allowed_delta_policy_sha256=_sha(f"allowed-delta:{target_salt}"),
        task_projection_policy_sha256=SHA_A,
        context_projection_policy_sha256=SHA_B,
        non_target_projection_policy_sha256=SHA_C,
        security_neutrality_policy_sha256=SHA_D,
    )
    protocol = ArmProtocolV2.from_target(
        target=target,
        realization_requirement_sha256=(SHA_A, SHA_A, SHA_A, SHA_A),
        validation_requirement_sha256=(SHA_B, SHA_B, SHA_B, SHA_B),
        assignment_probability_numerators=arm_probability_numerators,
        assignment_probability_denominator=arm_probability_denominator,
        infrastructure_failure_policy_sha256=SHA_C,
        retry_policy_sha256=SHA_D,
    )
    return InterventionBridgeRecordV2.from_components(
        skeleton=skeleton,
        actionable_feature=feature,
        realization_policy=policy,
        realizations=realizations,
        target_spec=target,
        arm_protocol=protocol,
        bridge_policy_sha256=SHA_A,
    )


def _common_selection(
    *,
    bridges: tuple[InterventionBridgeRecordV2, ...],
    failed_skeleton: CandidateSkeleton,
) -> tuple[CandidateUniverseManifest, SelectionFreezeManifest]:
    ordered_bridges = tuple(
        sorted(bridges, key=lambda item: item.candidate_skeleton.candidate_skeleton_id)
    )
    skeletons = tuple(
        sorted(
            (*tuple(item.candidate_skeleton for item in ordered_bridges), failed_skeleton),
            key=lambda item: item.candidate_skeleton_id,
        )
    )
    universe = CandidateUniverseManifest.from_content(
        skeletons=skeletons,
        candidate_count=len(skeletons),
        outcome_id="y_secure_yield",
        information_budget_sha256=SHA_B,
        universe_construction_sha256=SHA_C,
        frozen_before_selector_runs=True,
    )
    budget_k = len(ordered_bridges) + 2
    slots = [
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="fci",
            model_id="model.alpha",
            rank=rank,
            status=SelectorSlotStatus.SELECTED,
            candidate_skeleton_id=bridge.candidate_skeleton.candidate_skeleton_id,
            selector_evidence_sha256=_sha(f"selector:{rank}"),
            failure_code=None,
        )
        for rank, bridge in enumerate(ordered_bridges, start=1)
    ]
    slots.append(
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="fci",
            model_id="model.alpha",
            rank=len(ordered_bridges) + 1,
            status=SelectorSlotStatus.SELECTED,
            candidate_skeleton_id=failed_skeleton.candidate_skeleton_id,
            selector_evidence_sha256=_sha("selector:failed"),
            failure_code=None,
        )
    )
    slots.append(
        SelectorSlotRecord.from_content(
            candidate_universe_id=universe.candidate_universe_id,
            selector_id="fci",
            model_id="model.alpha",
            rank=budget_k,
            status=SelectorSlotStatus.EMPTY,
            candidate_skeleton_id=None,
            selector_evidence_sha256=_sha("selector:empty"),
            failure_code="no_stable_candidate",
        )
    )
    mappings = [
        SelectionMappingRecord.from_content(
            candidate_skeleton_id=bridge.candidate_skeleton.candidate_skeleton_id,
            status=BridgeStatus.PROTOCOLIZED,
            final_hypothesis_id=bridge.frozen_hypothesis.hypothesis_id,
            bridge_record_sha256=bridge.intervention_bridge_id.removeprefix("intervention_bridge_"),
            failure_code=None,
        )
        for bridge in ordered_bridges
    ]
    mappings.append(
        SelectionMappingRecord.from_content(
            candidate_skeleton_id=failed_skeleton.candidate_skeleton_id,
            status=BridgeStatus.FAILED,
            final_hypothesis_id=None,
            bridge_record_sha256=_sha("failed-bridge-evidence"),
            failure_code="protocolization_failed",
        )
    )
    selection = SelectionFreezeManifest.from_components(
        universe=universe,
        budget_k=budget_k,
        selector_slots=tuple(slots),
        mappings=tuple(sorted(mappings, key=lambda item: item.candidate_skeleton_id)),
    )
    return universe, selection


def _execution_for_root(
    root: ProtocolFreezeRootV2, *, randomization_seed: int
) -> ExecutionPolicyFreezeManifestV2:
    model_ids = root.intervention_bridge.frozen_hypothesis.model_scope
    randomization = RandomizationManifestV2.from_population(
        population=root.population,
        request_randomness_slots=(0, 1, 2, 3),
        model_generation_parameters=tuple(
            ModelGenerationParametersV2(
                model_id=model_id,
                generation_parameters_sha256=_sha(f"generation-parameters:{model_id}"),
            )
            for model_id in model_ids
        ),
        randomization_seed=randomization_seed,
        bounded_concurrency=2,
    )
    return ExecutionPolicyFreezeManifestV2.from_randomization(
        randomization=randomization,
        model_policies=tuple(
            ModelExecutionPolicyV2(
                model_id=model_id,
                language="python",
                endpoint_sha256=_sha(f"endpoint:{model_id}"),
                generation_parameters_sha256=_sha(f"generation-parameters:{model_id}"),
                system_template_sha256=_sha(f"system-template:{model_id}"),
                generator_producer_id="generator.synthetic",
                generator_policy_sha256=_sha(f"generator-policy:{model_id}"),
            )
            for model_id in model_ids
        ),
        measurement_policy=MeasurementExecutionPolicyV2(
            parser_producer_id="parser.synthetic",
            parser_policy_sha256=_sha("parser-policy"),
            oracle_producer_id="oracle.synthetic",
            oracle_policy_sha256=_sha("oracle-policy"),
            functional_evaluator_producer_id="functional.synthetic",
            functional_evaluator_policy_sha256=_sha("functional-policy"),
        ),
        execution_environment_sha256=_sha("execution-environment"),
    )


@dataclass(frozen=True)
class ExperimentComponents:
    universe: CandidateUniverseManifest
    selection: SelectionFreezeManifest
    roots: tuple[ProtocolFreezeRootV2, ...]
    executions: tuple[ExecutionPolicyFreezeManifestV2, ...]


def _experiment_components(
    bridges: tuple[InterventionBridgeRecordV2, ...],
) -> ExperimentComponents:
    model_scope = bridges[0].frozen_hypothesis.model_scope
    assert all(item.frozen_hypothesis.model_scope == model_scope for item in bridges)
    failed_bridge = _custom_bridge(
        model_scope=model_scope,
        k_r=max(len(item.realizations) for item in bridges) + 1,
        target_salt="failed-slot",
    )
    universe, selection = _common_selection(
        bridges=bridges,
        failed_skeleton=failed_bridge.candidate_skeleton,
    )
    inventory = _inventory()
    roots = []
    executions = []
    for index, bridge in enumerate(bridges):
        parts = _population_parts(bridge=bridge, inventory=inventory)
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
            preregistered_minimum_gate_pass_tasks=3,
            preregistered_minimum_gate_pass_clusters=2,
        )
        roots.append(root)
        executions.append(_execution_for_root(root, randomization_seed=20260820 + index))
    return ExperimentComponents(
        universe=universe,
        selection=selection,
        roots=tuple(roots),
        executions=tuple(executions),
    )


def _freeze(components: ExperimentComponents) -> ConfirmatoryExperimentFreezeV2:
    return ConfirmatoryExperimentFreezeV2.from_components(
        candidate_universe=components.universe,
        selection_freeze=components.selection,
        protocol_roots=components.roots,
        execution_policy_freezes=components.executions,
        global_multiplicity_family_policy_sha256=MULTIPLICITY_POLICY_SHA256,
        analysis_seed_domain_sha256=ANALYSIS_SEED_DOMAIN_SHA256,
    )


def _standard_components() -> ExperimentComponents:
    return _experiment_components((_bridge(k_r=2), _bridge(k_r=1)))


def _without_id(freeze: ConfirmatoryExperimentFreezeV2) -> dict[str, object]:
    return freeze.model_dump(
        mode="python",
        exclude={"schema_version", "confirmatory_experiment_freeze_id"},
    )


def test_experiment_freezes_complete_h_by_m_universe_and_preserves_failed_empty_slots() -> None:
    components = _standard_components()
    freeze = _freeze(components)

    assert freeze.hypothesis_count == 2
    assert freeze.model_ids == MODELS
    assert freeze.hypothesis_model_coordinate_count == 4
    assert len(freeze.selection_freeze.selector_slots) == 4
    assert any(
        item.status is SelectorSlotStatus.EMPTY for item in freeze.selection_freeze.selector_slots
    )
    assert any(item.status is BridgeStatus.FAILED for item in freeze.selection_freeze.mappings)
    assert freeze.outcome_blind is True
    assert freeze.frozen_before_outcomes is True
    assert ConfirmatoryExperimentFreezeV2.model_validate_json(freeze.model_dump_json()) == freeze


def test_duplicate_selector_slots_for_same_hypotheses_are_preserved_without_duplicate_roots() -> (
    None
):
    components = _standard_components()
    duplicate_slots = tuple(
        SelectorSlotRecord.from_content(
            candidate_universe_id=slot.candidate_universe_id,
            selector_id="ges",
            model_id=slot.model_id,
            rank=slot.rank,
            status=slot.status,
            candidate_skeleton_id=slot.candidate_skeleton_id,
            selector_evidence_sha256=_sha(f"ges:{slot.rank}"),
            failure_code=slot.failure_code,
        )
        for slot in components.selection.selector_slots
    )
    selection = SelectionFreezeManifest.from_components(
        universe=components.universe,
        budget_k=components.selection.budget_k,
        selector_slots=tuple(
            sorted(
                (*components.selection.selector_slots, *duplicate_slots),
                key=lambda item: (item.selector_id, item.model_id, item.rank),
            )
        ),
        mappings=components.selection.mappings,
    )
    roots = tuple(
        ProtocolFreezeRootV2.from_components(
            candidate_universe=components.universe,
            selection_freeze=selection,
            intervention_bridge=root.intervention_bridge,
            source_inventory=root.source_inventory,
            pool_partition=root.pool_partition,
            semantic_cluster_manifest=root.semantic_cluster_manifest,
            population=root.population,
            query_evidence=root.query_evidence,
            variant_evidence=root.variant_evidence,
            preregistered_minimum_gate_pass_tasks=(root.preregistered_minimum_gate_pass_tasks),
            preregistered_minimum_gate_pass_clusters=(
                root.preregistered_minimum_gate_pass_clusters
            ),
        )
        for root in components.roots
    )
    freeze = _freeze(
        ExperimentComponents(
            universe=components.universe,
            selection=selection,
            roots=roots,
            executions=components.executions,
        )
    )

    assert freeze.hypothesis_count == len(components.roots) == 2
    assert len(freeze.protocol_roots) == 2
    assert len(freeze.selection_freeze.selector_slots) == 2 * len(
        components.selection.selector_slots
    )


def test_experiment_rejects_synchronized_hypothesis_root_and_execution_deletion() -> None:
    components = _standard_components()
    original = _freeze(components)

    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.from_components(
            candidate_universe=components.universe,
            selection_freeze=components.selection,
            protocol_roots=components.roots[:-1],
            execution_policy_freezes=components.executions[:-1],
            global_multiplicity_family_policy_sha256=MULTIPLICITY_POLICY_SHA256,
            analysis_seed_domain_sha256=ANALYSIS_SEED_DOMAIN_SHA256,
        )

    reduced = _freeze(_experiment_components((components.roots[0].intervention_bridge,)))
    assert reduced.confirmatory_experiment_freeze_id != original.confirmatory_experiment_freeze_id
    impersonation = reduced.model_dump(mode="json")
    impersonation["confirmatory_experiment_freeze_id"] = original.confirmatory_experiment_freeze_id
    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.model_validate(impersonation, strict=True)


def test_experiment_rejects_model_coordinate_deletion_and_deep_model_scope_replacement() -> None:
    original = _freeze(_standard_components())
    tampered = _without_id(original)
    tampered["model_ids"] = ("model.alpha",)
    tampered["model_count"] = 1
    tampered["hypothesis_model_coordinates"] = tuple(
        item for item in original.hypothesis_model_coordinates if item.model_id == "model.alpha"
    )
    tampered["hypothesis_model_coordinate_count"] = original.hypothesis_count
    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.from_content(**tampered)

    reduced_bridges = (
        _custom_bridge(model_scope=("model.alpha",), k_r=2, target_salt="reduced-model-a"),
        _custom_bridge(model_scope=("model.alpha",), k_r=1, target_salt="reduced-model-b"),
    )
    reduced = _freeze(_experiment_components(reduced_bridges))
    assert reduced.confirmatory_experiment_freeze_id != original.confirmatory_experiment_freeze_id
    impersonation = reduced.model_dump(mode="json")
    impersonation["confirmatory_experiment_freeze_id"] = original.confirmatory_experiment_freeze_id
    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.model_validate(impersonation, strict=True)


def test_experiment_rejects_wrong_population_execution_and_randomization_swap_changes_root() -> (
    None
):
    components = _standard_components()
    original = _freeze(components)
    wrong = (components.executions[1], components.executions[0])
    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.from_components(
            candidate_universe=components.universe,
            selection_freeze=components.selection,
            protocol_roots=components.roots,
            execution_policy_freezes=(wrong[0],),
            global_multiplicity_family_policy_sha256=MULTIPLICITY_POLICY_SHA256,
            analysis_seed_domain_sha256=ANALYSIS_SEED_DOMAIN_SHA256,
        )

    replacement_execution = _execution_for_root(components.roots[0], randomization_seed=999_999)
    swapped_components = ExperimentComponents(
        universe=components.universe,
        selection=components.selection,
        roots=components.roots,
        executions=(replacement_execution, components.executions[1]),
    )
    swapped = _freeze(swapped_components)
    assert swapped.confirmatory_experiment_freeze_id != original.confirmatory_experiment_freeze_id
    impersonation = swapped.model_dump(mode="json")
    impersonation["confirmatory_experiment_freeze_id"] = original.confirmatory_experiment_freeze_id
    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.model_validate(impersonation, strict=True)


def test_experiment_rejects_nonuniform_four_arm_protocol() -> None:
    nonuniform = _custom_bridge(
        k_r=2,
        target_salt="nonuniform",
        arm_probability_numerators=(1, 1, 1, 2),
        arm_probability_denominator=5,
    )
    components = _experiment_components((nonuniform,))

    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        _freeze(components)


@pytest.mark.milestone
def test_post_hoc_protocol_root_replacement_cannot_impersonate_frozen_experiment() -> None:
    original_components = _standard_components()
    original = _freeze(original_components)
    replacement_bridges = (
        _bridge(k_r=2, target_salt="post-hoc-replacement"),
        original_components.roots[1].intervention_bridge,
    )
    replacement = _freeze(_experiment_components(replacement_bridges))

    assert replacement.confirmatory_experiment_freeze_id != (
        original.confirmatory_experiment_freeze_id
    )
    impersonation = replacement.model_dump(mode="json")
    impersonation["confirmatory_experiment_freeze_id"] = original.confirmatory_experiment_freeze_id
    with pytest.raises(ValidationError, match="experiment freeze v2 contract failed validation"):
        ConfirmatoryExperimentFreezeV2.model_validate(impersonation, strict=True)


def test_experiment_rejects_post_hoc_multiplicity_or_analysis_seed_domain_drift() -> None:
    original = _freeze(_standard_components())
    for field, replacement in (
        ("global_multiplicity_family_policy_sha256", _sha("post-hoc-multiplicity")),
        ("analysis_seed_domain_sha256", _sha("post-hoc-analysis-seed")),
    ):
        tampered = original.model_dump(mode="json")
        tampered[field] = replacement
        with pytest.raises(
            ValidationError, match="experiment freeze v2 contract failed validation"
        ):
            ConfirmatoryExperimentFreezeV2.model_validate(tampered, strict=True)

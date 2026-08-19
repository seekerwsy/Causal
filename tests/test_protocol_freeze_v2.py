from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest
from pydantic import ValidationError

from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.phased_exploration.pools import (
    ContractStatus,
    EvidencePool,
    PoolPartitionManifest,
    PoolTaskRecord,
)
from secaware.schema.experiments import ArmRole, PromptRole
from secaware.schema.features import FeatureOperation, PromptExtractorBackend
from secaware.schema.intervention_v2 import (
    ArmProtocolV2,
    InterventionBridgeRecordV2,
    TargetSpecV2,
)
from secaware.schema.policy_v2 import (
    ActionableFeatureSpec,
    BridgeStatus,
    CandidateSkeleton,
    CandidateUniverseManifest,
    ContextQuerySpec,
    ExpectedDirection,
    GlobalArmExecutionSpec,
    PolicySplit,
    RealizationPolicySpec,
    RealizationSpecRecord,
    SelectionFreezeManifest,
    SelectionMappingRecord,
    SelectorSlotRecord,
    SelectorSlotStatus,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
    TaskArmVariantBinding,
    TaskPolicySupportRecord,
    TaskRealizationBundleRecord,
)
from secaware.schema.population_v2 import (
    ClusterWeightBindingV2,
    PopulationFreezeManifestV2,
    PopulationTaskGateRecordV2,
    RationalWeightV2,
    ResamplingStratumV2,
)
from secaware.schema.protocol_freeze_v2 import (
    ProtocolFreezeRootV2,
    SourceInventoryManifestV2,
    SourceInventoryTaskRecordV2,
)
from secaware.schema.query_evidence_v2 import (
    QueryEvidenceManifestV2,
    QueryEvidenceTaskRecordV2,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.context_queries_v2 import CWE89_SQL_FLOW_QUERY, context_query_spec
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


SHA_A = _sha("a")
SHA_B = _sha("b")
SHA_C = _sha("c")
SHA_D = _sha("d")
MODELS = ("model.alpha", "model.beta")
TASK_COORDINATES = (
    ("task.1", "cluster.1"),
    ("task.2", "cluster.1"),
    ("task.3", "cluster.2"),
)
ADD_ARMS = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)


def _context_spec() -> ContextQuerySpec:
    return context_query_spec(CWE89_SQL_FLOW_QUERY)


def _feature_spec() -> ActionableFeatureSpec:
    return ActionableFeatureSpec.from_content(
        feature_id="safety.sql_parameterization",
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        allowed_operations=(FeatureOperation.ADD, FeatureOperation.REMOVE),
        task_preserving_edit_policy_sha256=SHA_D,
    )


def _realization_policy(k_r: int) -> RealizationPolicySpec:
    return RealizationPolicySpec.from_content(
        k_r=k_r,
        probability_numerators=tuple(1 for _ in range(k_r)),
        probability_denominator=k_r,
        distribution_rationale="uniform",
        matching_rules_sha256=SHA_A,
        executor_policy_sha256=SHA_B,
        extractor_policy_sha256=SHA_C,
        validation_policy_sha256=SHA_D,
        full_support_required=True,
        failure_policy="fail_closed_no_deletion_no_renormalization",
    )


def _skeleton(policy: RealizationPolicySpec) -> CandidateSkeleton:
    context = _context_spec()
    feature = _feature_spec()
    return CandidateSkeleton.from_content(
        context_query_id=context.context_query_id,
        actionable_feature_spec_id=feature.actionable_feature_spec_id,
        feature_id=feature.feature_id,
        operation=FeatureOperation.ADD,
        realization_policy_spec_id=policy.realization_policy_spec_id,
        outcome_id="y_secure_yield",
        expected_direction=ExpectedDirection.POSITIVE,
        cwe="CWE-89",
        task_archetype="value-parameterization",
        model_scope=MODELS,
        context_query_catalog_sha256=context.context_query_catalog_sha256,
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        eligibility_function_sha256=SHA_D,
    )


def _realizations(
    skeleton: CandidateSkeleton, policy: RealizationPolicySpec
) -> tuple[RealizationSpecRecord, ...]:
    return tuple(
        RealizationSpecRecord.from_policy(
            skeleton=skeleton,
            policy=policy,
            realization_index=index,
            arms=tuple(
                GlobalArmExecutionSpec(
                    arm_role=arm,
                    template_or_execution_policy_sha256=_sha(
                        f"global-template:{index}:{arm.value}"
                    ),
                    validation_requirements_sha256=SHA_D,
                )
                for arm in ADD_ARMS
            ),
        )
        for index in range(policy.k_r)
    )


def _bridge(*, k_r: int = 2, target_salt: str = "base") -> InterventionBridgeRecordV2:
    policy = _realization_policy(k_r)
    skeleton = _skeleton(policy)
    feature = _feature_spec()
    realizations = _realizations(skeleton, policy)
    target = TargetSpecV2.from_components(
        skeleton=skeleton,
        context_query=_context_spec(),
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
        assignment_probability_numerators=(1, 1, 1, 1),
        assignment_probability_denominator=4,
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


def _selection(
    bridge: InterventionBridgeRecordV2,
) -> tuple[CandidateUniverseManifest, SelectionFreezeManifest]:
    skeleton = bridge.candidate_skeleton
    universe = CandidateUniverseManifest.from_content(
        skeletons=(skeleton,),
        candidate_count=1,
        outcome_id=skeleton.outcome_id,
        information_budget_sha256=SHA_B,
        universe_construction_sha256=SHA_C,
        frozen_before_selector_runs=True,
    )
    slot = SelectorSlotRecord.from_content(
        candidate_universe_id=universe.candidate_universe_id,
        selector_id="fci",
        model_id="model.alpha",
        rank=1,
        status=SelectorSlotStatus.SELECTED,
        candidate_skeleton_id=skeleton.candidate_skeleton_id,
        selector_evidence_sha256=SHA_D,
        failure_code=None,
    )
    mapping = SelectionMappingRecord.from_content(
        candidate_skeleton_id=skeleton.candidate_skeleton_id,
        status=BridgeStatus.PROTOCOLIZED,
        final_hypothesis_id=bridge.frozen_hypothesis.hypothesis_id,
        bridge_record_sha256=bridge.intervention_bridge_id.removeprefix("intervention_bridge_"),
        failure_code=None,
    )
    freeze = SelectionFreezeManifest.from_components(
        universe=universe,
        budget_k=1,
        selector_slots=(slot,),
        mappings=(mapping,),
    )
    return universe, freeze


def _source_task(task_id: str) -> SourceInventoryTaskRecordV2:
    return SourceInventoryTaskRecordV2.from_source(
        task_instance_id=task_id,
        source_id="synthetic.registry",
        source_record_id=f"source.{task_id}",
        prompt_sha256=_sha(_prompt_text(task_id)),
        cwe_id="CWE-89",
        archetype_id="value-parameterization",
        template_family_id="sql.lookup",
        functional_contract_status=ContractStatus.DECLARATIVE_ONLY,
        security_contract_status=ContractStatus.DECLARATIVE_ONLY,
        legacy_outcome_exposed=False,
    )


def _inventory(
    coordinates: tuple[tuple[str, str], ...] = TASK_COORDINATES,
) -> SourceInventoryManifestV2:
    return SourceInventoryManifestV2.from_tasks(
        tasks=tuple(_source_task(task_id) for task_id, _ in coordinates),
        source_registry_snapshot_sha256=SHA_B,
        inventory_construction_sha256=SHA_C,
    )


def _prompt_text(task_id: str, *, target_present: bool = False) -> str:
    suffix = " Use parameterized queries." if target_present else ""
    return f"Implement a database query for user-supplied value {task_id}.{suffix}"


def _natural_prompt(task_id: str, *, target_present: bool = False) -> PromptRecord:
    return PromptRecord(
        prompt_id=f"source-prompt.{task_id}",
        task_id=task_id,
        split="confirm",
        language="python",
        task_family="sql_query",
        cwe="CWE-89",
        prompt=_prompt_text(task_id, target_present=target_present),
        prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_prompt_id=None,
    )


def _query_evidence_task(
    *,
    bridge: InterventionBridgeRecordV2,
    membership: SemanticTaskClusterMembershipRecord,
) -> QueryEvidenceTaskRecordV2:
    prompt = _natural_prompt(
        membership.task_instance_id,
        target_present=bridge.frozen_hypothesis.operation is FeatureOperation.REMOVE,
    )
    extraction_policy = ExtractionPolicy(
        backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        policy_sha256=bridge.realization_policy.extractor_policy_sha256,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        max_response_chars=262_144,
    )
    proposal = DeterministicCatalogExtractor().extract(prompt, extraction_policy)
    graph = build_prompt_tsg(proposal, prompt)
    remove = bridge.frozen_hypothesis.operation is FeatureOperation.REMOVE
    return QueryEvidenceTaskRecordV2.from_natural_prompt(
        membership=membership,
        natural_prompt=prompt,
        extraction_proposal=proposal,
        prompt_tsg=graph,
        context_query=bridge.context_query,
        actionable_feature=bridge.actionable_feature,
        operation=bridge.frozen_hypothesis.operation,
        eligibility_function_sha256=(bridge.candidate_skeleton.eligibility_function_sha256),
        neutral_counterpart_attested=True if remove else None,
        neutral_counterpart_attestation_sha256=(
            _sha(f"neutral-counterpart:{membership.task_instance_id}") if remove else None
        ),
    )


def _query_evidence_manifest(
    *,
    bridge: InterventionBridgeRecordV2,
    memberships: tuple[SemanticTaskClusterMembershipRecord, ...],
) -> QueryEvidenceManifestV2:
    tasks = tuple(
        _query_evidence_task(bridge=bridge, membership=membership) for membership in memberships
    )
    return QueryEvidenceManifestV2.from_tasks(
        context_query=bridge.context_query,
        actionable_feature=bridge.actionable_feature,
        operation=bridge.frozen_hypothesis.operation,
        extractor_backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        extractor_policy_sha256=bridge.realization_policy.extractor_policy_sha256,
        eligibility_function_sha256=(bridge.candidate_skeleton.eligibility_function_sha256),
        tasks=tasks,
    )


def _bundle(
    *,
    task_id: str,
    cluster_id: str,
    bridge: InterventionBridgeRecordV2,
    realization: RealizationSpecRecord,
) -> TaskRealizationBundleRecord:
    bindings = tuple(
        TaskArmVariantBinding.from_text(
            arm_role=arm,
            prompt_text=f"Synthetic {task_id}; r={realization.realization_index}; {arm.value}.",
            validation_evidence_sha256=_sha(
                f"validation:{task_id}:{realization.realization_index}:{arm.value}"
            ),
        )
        for arm in ADD_ARMS
    )
    return TaskRealizationBundleRecord.from_components(
        hypothesis=bridge.frozen_hypothesis,
        realization=realization,
        semantic_task_cluster_id=cluster_id,
        task_instance_id=task_id,
        source_prompt_id=f"source-prompt.{task_id}",
        source_prompt_sha256=_sha(
            _prompt_text(
                task_id,
                target_present=(bridge.frozen_hypothesis.operation is FeatureOperation.REMOVE),
            )
        ),
        arms=bindings,
    )


def _support(
    *, task_id: str, cluster_id: str, bridge: InterventionBridgeRecordV2
) -> TaskPolicySupportRecord:
    bundles = tuple(
        _bundle(
            task_id=task_id,
            cluster_id=cluster_id,
            bridge=bridge,
            realization=realization,
        )
        for realization in bridge.realizations
    )
    return TaskPolicySupportRecord.from_components(
        hypothesis=bridge.frozen_hypothesis,
        policy=bridge.realization_policy,
        realizations=bridge.realizations,
        bundles=bundles,
    )


@dataclass(frozen=True)
class PopulationParts:
    partition: PoolPartitionManifest
    clusters: SemanticTaskClusterManifest
    population: PopulationFreezeManifestV2
    query_evidence: QueryEvidenceManifestV2


def _population_parts(
    *,
    bridge: InterventionBridgeRecordV2,
    inventory: SourceInventoryManifestV2,
    coordinates: tuple[tuple[str, str], ...] = TASK_COORDINATES,
    minimum_tasks: int = 3,
    minimum_clusters: int = 2,
    partition_source_inventory_sha256: str | None = None,
    partition_cluster_policy_sha256: str = SHA_A,
    cluster_policy_sha256: str = SHA_A,
) -> PopulationParts:
    source_by_task = {item.task_instance_id: item for item in inventory.tasks}
    pool_tasks = {
        task_id: PoolTaskRecord.from_content(
            pool=EvidencePool.FORMAL_CONFIRM,
            semantic_task_cluster_id=cluster_id,
            task_instance_id=task_id,
            source_id=source_by_task[task_id].source_id,
            source_record_id=source_by_task[task_id].source_record_id,
            prompt_sha256=source_by_task[task_id].prompt_sha256,
            cwe_id=source_by_task[task_id].cwe_id,
            archetype_id=source_by_task[task_id].archetype_id,
            template_family_id=source_by_task[task_id].template_family_id,
            functional_contract_status=source_by_task[task_id].functional_contract_status,
            security_contract_status=source_by_task[task_id].security_contract_status,
            legacy_outcome_exposed=source_by_task[task_id].legacy_outcome_exposed,
            exposure_artifact_sha256=source_by_task[task_id].exposure_artifact_sha256,
        )
        for task_id, cluster_id in coordinates
    }
    memberships = {
        task_id: SemanticTaskClusterMembershipRecord.from_content(
            semantic_task_cluster_id=cluster_id,
            task_instance_id=task_id,
            split=PolicySplit.CONFIRM,
            cwe="CWE-89",
            task_archetype="value-parameterization",
            source_task_sha256=source_by_task[task_id].source_task_sha256,
            clustering_policy_sha256=cluster_policy_sha256,
            adjudication_sha256=None,
        )
        for task_id, cluster_id in coordinates
    }
    partition = PoolPartitionManifest.from_content(
        partition_version="synthetic-protocol-v2",
        semantic_cluster_policy_sha256=partition_cluster_policy_sha256,
        source_inventory_sha256=(
            partition_source_inventory_sha256 or inventory.source_inventory_sha256
        ),
        tasks=tuple(pool_tasks.values()),
    )
    clusters = SemanticTaskClusterManifest.from_content(
        memberships=tuple(
            sorted(
                memberships.values(),
                key=lambda item: (item.semantic_task_cluster_id, item.task_instance_id),
            )
        ),
        clustering_algorithm_sha256=cluster_policy_sha256,
        normalization_policy_sha256=SHA_B,
        construction_digest_sha256=SHA_C,
        frozen_before_discovery=True,
    )
    query_evidence = _query_evidence_manifest(
        bridge=bridge,
        memberships=tuple(memberships.values()),
    )
    query_evidence_by_task = {
        item.membership.task_instance_id: item for item in query_evidence.tasks
    }
    cluster_counts = {
        cluster_id: sum(1 for _, candidate in coordinates if candidate == cluster_id)
        for cluster_id in {candidate for _, candidate in coordinates}
    }
    gates = tuple(
        PopulationTaskGateRecordV2.from_components(
            pool_task=pool_tasks[task_id],
            cluster_membership=memberships[task_id],
            hypothesis=bridge.frozen_hypothesis,
            eligibility=query_evidence_by_task[task_id].eligibility,
            task_policy_support=_support(
                task_id=task_id,
                cluster_id=cluster_id,
                bridge=bridge,
            ),
            within_cluster_task_weight=RationalWeightV2(
                numerator=1,
                denominator=cluster_counts[cluster_id],
            ),
        )
        for task_id, cluster_id in coordinates
    )
    cluster_ids = tuple(sorted(cluster_counts))
    stratum = ResamplingStratumV2(
        stratum_id="stratum:CWE-89:value-parameterization",
        cwe="CWE-89",
        task_archetype="value-parameterization",
        cluster_weights=tuple(
            ClusterWeightBindingV2(
                semantic_task_cluster_id=cluster_id,
                weight=RationalWeightV2(numerator=1, denominator=len(cluster_ids)),
            )
            for cluster_id in cluster_ids
        ),
    )
    population = PopulationFreezeManifestV2.from_components(
        pool_partition=partition,
        semantic_cluster_manifest=clusters,
        hypothesis=bridge.frozen_hypothesis,
        confirmation_pool=EvidencePool.FORMAL_CONFIRM,
        task_gates=gates,
        strata=(stratum,),
        minimum_gate_pass_tasks=minimum_tasks,
        minimum_gate_pass_clusters=minimum_clusters,
        population_construction_sha256=SHA_A,
        weighting_policy_sha256=SHA_B,
        stratification_policy_sha256=SHA_C,
    )
    return PopulationParts(
        partition=partition,
        clusters=clusters,
        population=population,
        query_evidence=query_evidence,
    )


@dataclass(frozen=True)
class ProtocolFixture:
    root: ProtocolFreezeRootV2
    universe: CandidateUniverseManifest
    selection: SelectionFreezeManifest
    bridge: InterventionBridgeRecordV2
    inventory: SourceInventoryManifestV2
    parts: PopulationParts


def _fixture(
    *,
    bridge: InterventionBridgeRecordV2 | None = None,
    inventory: SourceInventoryManifestV2 | None = None,
    coordinates: tuple[tuple[str, str], ...] = TASK_COORDINATES,
    minimum_tasks: int = 3,
    minimum_clusters: int = 2,
) -> ProtocolFixture:
    checked_bridge = bridge or _bridge()
    checked_inventory = inventory or _inventory(coordinates)
    universe, selection = _selection(checked_bridge)
    parts = _population_parts(
        bridge=checked_bridge,
        inventory=checked_inventory,
        coordinates=coordinates,
        minimum_tasks=minimum_tasks,
        minimum_clusters=minimum_clusters,
    )
    root = ProtocolFreezeRootV2.from_components(
        candidate_universe=universe,
        selection_freeze=selection,
        intervention_bridge=checked_bridge,
        source_inventory=checked_inventory,
        pool_partition=parts.partition,
        semantic_cluster_manifest=parts.clusters,
        population=parts.population,
        query_evidence=parts.query_evidence,
        preregistered_minimum_gate_pass_tasks=minimum_tasks,
        preregistered_minimum_gate_pass_clusters=minimum_clusters,
    )
    return ProtocolFixture(
        root=root,
        universe=universe,
        selection=selection,
        bridge=checked_bridge,
        inventory=checked_inventory,
        parts=parts,
    )


def _root_components(fixture: ProtocolFixture) -> dict[str, object]:
    return {
        "candidate_universe": fixture.universe,
        "selection_freeze": fixture.selection,
        "intervention_bridge": fixture.bridge,
        "source_inventory": fixture.inventory,
        "pool_partition": fixture.parts.partition,
        "semantic_cluster_manifest": fixture.parts.clusters,
        "population": fixture.parts.population,
        "query_evidence": fixture.parts.query_evidence,
        "preregistered_minimum_gate_pass_tasks": 3,
        "preregistered_minimum_gate_pass_clusters": 2,
    }


def test_protocol_root_is_content_addressed_outcome_blind_and_round_trippable() -> None:
    fixture = _fixture()
    root = fixture.root

    assert root.protocol_freeze_id.startswith("protocol_freeze_v2_")
    assert root.outcome_blind is True
    assert root.frozen_before_randomization is True
    assert (
        root.source_inventory.source_inventory_sha256 == root.pool_partition.source_inventory_sha256
    )
    assert root.population.hypothesis == root.intervention_bridge.frozen_hypothesis
    assert ProtocolFreezeRootV2.model_validate(root.model_dump(mode="json"), strict=True) == root


@pytest.mark.parametrize(
    ("coordinates", "minimum_tasks", "minimum_clusters"),
    (
        ((TASK_COORDINATES[0], TASK_COORDINATES[2]), 2, 2),
        ((TASK_COORDINATES[0], TASK_COORDINATES[1]), 2, 1),
    ),
    ids=("delete-task-within-cluster", "delete-whole-cluster"),
)
def test_protocol_root_rejects_synchronized_task_or_cluster_deletion_and_lowered_minima(
    coordinates: tuple[tuple[str, str], ...],
    minimum_tasks: int,
    minimum_clusters: int,
) -> None:
    original = _fixture()
    attacked_parts = _population_parts(
        bridge=original.bridge,
        inventory=original.inventory,
        coordinates=coordinates,
        minimum_tasks=minimum_tasks,
        minimum_clusters=minimum_clusters,
    )

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(
            candidate_universe=original.universe,
            selection_freeze=original.selection,
            intervention_bridge=original.bridge,
            source_inventory=original.inventory,
            pool_partition=attacked_parts.partition,
            semantic_cluster_manifest=attacked_parts.clusters,
            population=attacked_parts.population,
            query_evidence=attacked_parts.query_evidence,
            preregistered_minimum_gate_pass_tasks=3,
            preregistered_minimum_gate_pass_clusters=2,
        )

    attacked = _fixture(
        inventory=_inventory(coordinates),
        coordinates=coordinates,
        minimum_tasks=minimum_tasks,
        minimum_clusters=minimum_clusters,
    )
    assert attacked.root.protocol_freeze_id != original.root.protocol_freeze_id
    impersonation = attacked.root.model_dump(mode="json")
    impersonation["protocol_freeze_id"] = original.root.protocol_freeze_id
    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.model_validate(impersonation, strict=True)


def test_protocol_root_rejects_synchronized_realization_deletion_under_original_identity() -> None:
    original = _fixture()
    attacked = _fixture(bridge=_bridge(k_r=1))

    assert len(original.bridge.realizations) == 2
    assert len(attacked.bridge.realizations) == 1
    assert attacked.root.protocol_freeze_id != original.root.protocol_freeze_id
    impersonation = attacked.root.model_dump(mode="json")
    impersonation["protocol_freeze_id"] = original.root.protocol_freeze_id
    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.model_validate(impersonation, strict=True)


def test_protocol_root_rejects_replacement_bridge_not_frozen_by_selection_or_population() -> None:
    original = _fixture()
    replacement = _bridge(target_salt="replacement")
    components = _root_components(original)
    components["intervention_bridge"] = replacement

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(**components)


def test_protocol_root_rejects_cluster_policy_mismatch_accepted_by_population_contract() -> None:
    original = _fixture()
    attacked_parts = _population_parts(
        bridge=original.bridge,
        inventory=original.inventory,
        partition_cluster_policy_sha256=SHA_D,
        cluster_policy_sha256=SHA_A,
    )
    assert (
        attacked_parts.partition.semantic_cluster_policy_sha256
        != attacked_parts.clusters.clustering_algorithm_sha256
    )

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(
            candidate_universe=original.universe,
            selection_freeze=original.selection,
            intervention_bridge=original.bridge,
            source_inventory=original.inventory,
            pool_partition=attacked_parts.partition,
            semantic_cluster_manifest=attacked_parts.clusters,
            population=attacked_parts.population,
            query_evidence=attacked_parts.query_evidence,
            preregistered_minimum_gate_pass_tasks=3,
            preregistered_minimum_gate_pass_clusters=2,
        )


def test_protocol_root_rejects_source_inventory_digest_drift() -> None:
    original = _fixture()
    attacked_parts = _population_parts(
        bridge=original.bridge,
        inventory=original.inventory,
        partition_source_inventory_sha256=SHA_D,
    )
    assert (
        attacked_parts.partition.source_inventory_sha256
        != original.inventory.source_inventory_sha256
    )

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(
            candidate_universe=original.universe,
            selection_freeze=original.selection,
            intervention_bridge=original.bridge,
            source_inventory=original.inventory,
            pool_partition=attacked_parts.partition,
            semantic_cluster_manifest=attacked_parts.clusters,
            population=attacked_parts.population,
            query_evidence=attacked_parts.query_evidence,
            preregistered_minimum_gate_pass_tasks=3,
            preregistered_minimum_gate_pass_clusters=2,
        )

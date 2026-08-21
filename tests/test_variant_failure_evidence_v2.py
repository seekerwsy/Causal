from __future__ import annotations

import pytest
from pydantic import ValidationError

from secaware.schema.population_v2 import (
    ClusterWeightBindingV2,
    PopulationFreezeManifestV2,
    PopulationTaskGateRecordV2,
    RationalWeightV2,
    ResamplingStratumV2,
)
from secaware.schema.variant_failure_evidence_v2 import (
    TaskBundleFailureReceiptV2,
    VariantBundleFailureReasonV2,
    VariantBundleFailureStageV2,
    VariantFailureEvidenceManifestV2,
)
from test_protocol_freeze_v2 import (
    SHA_A,
    SHA_B,
    SHA_C,
    TASK_COORDINATES,
    _bridge,
    _inventory,
    _population_parts,
)


def _fixture() -> tuple[
    object,
    object,
    PopulationFreezeManifestV2,
    TaskBundleFailureReceiptV2,
]:
    bridge = _bridge()
    inventory = _inventory(TASK_COORDINATES)
    parts = _population_parts(
        bridge=bridge,
        inventory=inventory,
        minimum_tasks=2,
        minimum_clusters=1,
    )
    excluded_task_id = TASK_COORDINATES[-1][0]
    pool_by_task = {item.task_instance_id: item for item in parts.partition.tasks}
    membership_by_task = {item.task_instance_id: item for item in parts.clusters.memberships}
    query_by_task = {item.membership.task_instance_id: item for item in parts.query_evidence.tasks}
    gates = tuple(
        PopulationTaskGateRecordV2.from_components(
            pool_task=pool_by_task[item.task_instance_id],
            cluster_membership=membership_by_task[item.task_instance_id],
            hypothesis=bridge.frozen_hypothesis,
            eligibility=query_by_task[item.task_instance_id].eligibility,
            task_policy_support=(
                None if item.task_instance_id == excluded_task_id else item.task_policy_support
            ),
            within_cluster_task_weight=(
                None
                if item.task_instance_id == excluded_task_id
                else RationalWeightV2(numerator=1, denominator=2)
            ),
        )
        for item in parts.population.task_gates
    )
    stratum = ResamplingStratumV2(
        stratum_id="stratum:CWE-89:value-parameterization",
        cwe="CWE-89",
        task_archetype="value-parameterization",
        cluster_weights=(
            ClusterWeightBindingV2(
                semantic_task_cluster_id="cluster.1",
                weight=RationalWeightV2(numerator=1, denominator=1),
            ),
        ),
    )
    population = PopulationFreezeManifestV2.from_components(
        pool_partition=parts.partition,
        semantic_cluster_manifest=parts.clusters,
        hypothesis=bridge.frozen_hypothesis,
        confirmation_pool=parts.population.confirmation_pool,
        task_gates=gates,
        strata=(stratum,),
        minimum_gate_pass_tasks=2,
        minimum_gate_pass_clusters=1,
        population_construction_sha256=SHA_A,
        weighting_policy_sha256=SHA_B,
        stratification_policy_sha256=SHA_C,
    )
    receipt = TaskBundleFailureReceiptV2.from_failure(
        source_query_evidence=query_by_task[excluded_task_id],
        intervention_bridge=bridge,
        realization=bridge.realizations[0],
        arm_role=bridge.arm_protocol.arms[0].arm_role,
        failure_stage=VariantBundleFailureStageV2.RENDERER,
        failure_reason=VariantBundleFailureReasonV2.RENDERER_REJECTED,
        producer_id="renderer.secaware",
        producer_version="2.0.0",
        producer_policy_sha256=SHA_A,
        attempt_sha256=SHA_B,
        attempted_prompt_sha256=None,
        diagnostic_sha256=SHA_C,
    )
    return bridge, parts.query_evidence, population, receipt


def test_failure_manifest_covers_every_excluded_eligible_task_and_replays_json() -> None:
    bridge, query, population, receipt = _fixture()
    manifest = VariantFailureEvidenceManifestV2.from_components(
        intervention_bridge=bridge,
        query_evidence=query,
        population=population,
        failure_receipts=(receipt,),
    )

    assert manifest.eligible_task_ids == ("task.1", "task.2", "task.3")
    assert manifest.retained_task_ids == ("task.1", "task.2")
    assert manifest.excluded_eligible_task_ids == ("task.3",)
    assert manifest.failed_task_ids == ("task.3",)
    assert manifest.failure_receipt_count == 1
    assert (
        VariantFailureEvidenceManifestV2.model_validate_json(manifest.model_dump_json()) == manifest
    )


def test_missing_or_retained_task_failure_receipt_is_rejected() -> None:
    bridge, query, population, receipt = _fixture()
    with pytest.raises(
        ValidationError,
        match="variant failure evidence v2 contract failed validation",
    ):
        VariantFailureEvidenceManifestV2.from_components(
            intervention_bridge=bridge,
            query_evidence=query,
            population=population,
            failure_receipts=(),
        )

    retained_query = next(
        item for item in query.tasks if item.membership.task_instance_id == "task.1"
    )
    forged = receipt.model_copy(
        update={
            "query_evidence_task_id": retained_query.query_evidence_task_id,
            "semantic_task_cluster_id": retained_query.membership.semantic_task_cluster_id,
            "task_instance_id": "task.1",
        }
    )
    with pytest.raises(
        ValidationError,
        match="variant failure evidence v2 contract failed validation",
    ):
        VariantFailureEvidenceManifestV2.from_components(
            intervention_bridge=bridge,
            query_evidence=query,
            population=population,
            failure_receipts=(forged,),
        )


def test_failure_is_bound_to_exact_realization_arm_stage_and_reason() -> None:
    bridge, query, population, receipt = _fixture()
    forged_realization = receipt.model_copy(
        update={"realization_spec_id": f"realization_spec_{'f' * 64}"}
    )
    with pytest.raises(
        ValidationError,
        match="variant failure evidence v2 contract failed validation",
    ):
        VariantFailureEvidenceManifestV2.from_components(
            intervention_bridge=bridge,
            query_evidence=query,
            population=population,
            failure_receipts=(forged_realization,),
        )

    source = next(item for item in query.tasks if item.membership.task_instance_id == "task.3")
    with pytest.raises(
        ValidationError,
        match="variant failure evidence v2 contract failed validation",
    ):
        TaskBundleFailureReceiptV2.from_failure(
            source_query_evidence=source,
            intervention_bridge=bridge,
            realization=bridge.realizations[0],
            arm_role=bridge.arm_protocol.arms[0].arm_role,
            failure_stage=VariantBundleFailureStageV2.RENDERER,
            failure_reason=VariantBundleFailureReasonV2.GRAPH_INVALID,
            producer_id="renderer.secaware",
            producer_version="2.0.0",
            producer_policy_sha256=SHA_A,
            attempt_sha256=SHA_B,
            attempted_prompt_sha256=None,
            diagnostic_sha256=SHA_C,
        )


def test_no_excluded_task_requires_no_fabricated_failure_receipt() -> None:
    bridge = _bridge()
    inventory = _inventory(TASK_COORDINATES)
    parts = _population_parts(bridge=bridge, inventory=inventory)
    manifest = VariantFailureEvidenceManifestV2.from_components(
        intervention_bridge=bridge,
        query_evidence=parts.query_evidence,
        population=parts.population,
        failure_receipts=(),
    )

    assert manifest.excluded_eligible_task_ids == ()
    assert manifest.failed_task_ids == ()
    assert manifest.failure_receipt_count == 0

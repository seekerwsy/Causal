from __future__ import annotations

import pytest
from pydantic import ValidationError

from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.policy_v2 import (
    TaskArmVariantBinding,
    TaskPolicySupportRecord,
    TaskRealizationBundleRecord,
)
from secaware.schema.population_v2 import (
    PopulationFreezeManifestV2,
    PopulationTaskGateRecordV2,
)
from secaware.schema.variant_evidence_v2 import (
    ArmVariantInvariantReceiptV2,
    VariantInvariantEvidenceManifestV2,
)
from secaware.tsg.feature_catalog import prompt_feature_spec
from test_protocol_freeze_v2 import (
    _bridge,
    _inventory,
    _population_parts,
)

ONE_TASK = (("task.1", "cluster.1"),)
TWO_TASKS = (("task.1", "cluster.1"), ("task.2", "cluster.2"))


def _parts(
    *,
    two_tasks: bool = False,
    k_r: int = 2,
    operation: FeatureOperation = FeatureOperation.ADD,
):
    coordinates = TWO_TASKS if two_tasks else ONE_TASK
    bridge = _bridge(k_r=k_r, operation=operation)
    inventory = _inventory(
        coordinates,
        target_present=operation is FeatureOperation.REMOVE,
    )
    parts = _population_parts(
        bridge=bridge,
        inventory=inventory,
        coordinates=coordinates,
        minimum_tasks=len(coordinates),
        minimum_clusters=len(coordinates),
    )
    return bridge, parts


def _receipt_content(receipt: ArmVariantInvariantReceiptV2) -> dict[str, object]:
    return receipt.model_dump(
        mode="python",
        exclude={"schema_version", "variant_invariant_receipt_id"},
    )


def test_receipts_replay_from_json_and_bind_real_evidence_digest() -> None:
    _bridge_record, parts = _parts(k_r=1)
    manifest = parts.variant_evidence
    replayed = VariantInvariantEvidenceManifestV2.model_validate_json(manifest.model_dump_json())

    assert replayed == manifest
    assert manifest.receipt_count == 4
    support = parts.population.task_gates[0].task_policy_support
    assert support is not None
    bundle = support.task_realization_bundles[0]
    assert tuple(item.validation_evidence_sha256 for item in bundle.arms) == tuple(
        item.semantic_sha256 for item in manifest.receipts
    )


def test_remove_replays_with_exact_neutral_counterpart_and_distinct_arm_family() -> None:
    bridge, parts = _parts(k_r=1, operation=FeatureOperation.REMOVE)
    manifest = parts.variant_evidence
    replayed = VariantInvariantEvidenceManifestV2.model_validate_json(manifest.model_dump_json())

    assert replayed == manifest
    assert tuple(item.arm_role for item in manifest.receipts) == (
        ArmRole.TARGET_REMOVE,
        ArmRole.NOOP_RETAIN,
        ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        ArmRole.GENERIC_SECURITY_REPLACEMENT,
    )
    assert all(item.neutral_counterpart_prompt is not None for item in manifest.receipts)
    target = manifest.receipts[0]
    assert target.neutral_counterpart_prompt is not None
    assert target.prompt_variant.prompt_text == target.neutral_counterpart_prompt.prompt
    assert target.target_instance.counterpart_required
    assert (
        target.target_instance.counterpart_prompt_sha256
        == target.neutral_counterpart_prompt.prompt_sha256
    )
    assert parts.query_evidence.tasks[0].eligibility.target_evidence_sha256 is not None
    assert bridge.frozen_hypothesis.expected_direction.value == "negative"


def test_remove_rejects_wrong_neutral_counterpart_before_generation() -> None:
    bridge, parts = _parts(k_r=1, operation=FeatureOperation.REMOVE)
    target = parts.variant_evidence.receipts[0]
    wrong = target.neutral_counterpart_prompt
    assert wrong is not None
    forged = wrong.to_prompt_record().model_copy(update={"prompt_id": "neutral-counterpart.other"})

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        ArmVariantInvariantReceiptV2.from_variant_text(
            source_query_evidence=target.source_query_evidence,
            intervention_bridge=bridge,
            realization=bridge.realizations[0],
            arm_role=ArmRole.TARGET_REMOVE,
            prompt_text=wrong.prompt,
            extractor=DeterministicCatalogExtractor(),
            neutral_counterpart_prompt=forged,
        )


@pytest.mark.parametrize(
    "removed_slice",
    [slice(0, -1), slice(0, -4)],
    ids=("one-arm", "whole-realization"),
)
def test_manifest_rejects_deleted_arm_or_partial_realization(removed_slice: slice) -> None:
    bridge, parts = _parts(k_r=2)
    receipts = parts.variant_evidence.receipts[removed_slice]

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        VariantInvariantEvidenceManifestV2.from_components(
            intervention_bridge=bridge,
            query_evidence=parts.query_evidence,
            population=parts.population,
            receipts=receipts,
        )


def test_receipt_rejects_cross_task_source_swap_after_synchronized_rehash() -> None:
    _bridge_record, parts = _parts(two_tasks=True, k_r=1)
    first = parts.variant_evidence.receipts[0]
    other_source = next(
        item
        for item in parts.query_evidence.tasks
        if item.membership.task_instance_id
        != first.source_query_evidence.membership.task_instance_id
    )
    content = _receipt_content(first)
    content["source_query_evidence"] = other_source

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        ArmVariantInvariantReceiptV2.from_content(**content)


@pytest.mark.parametrize(
    "artifact_field",
    ["variant_prompt", "prompt_tsg", "graph_delta"],
)
def test_receipt_rejects_cross_arm_artifact_swap_after_synchronized_rehash(
    artifact_field: str,
) -> None:
    _bridge_record, parts = _parts(k_r=1)
    target, noop = parts.variant_evidence.receipts[:2]
    content = _receipt_content(target)
    content[artifact_field] = getattr(noop, artifact_field)

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        ArmVariantInvariantReceiptV2.from_content(**content)


def test_receipt_rejects_forged_context_projection_after_synchronized_rehash() -> None:
    _bridge_record, parts = _parts(k_r=1)
    target = parts.variant_evidence.receipts[0]
    content = _receipt_content(target)
    content["variant_context_projection"] = target.variant_context_projection.model_copy(
        update={"state": "absent"}
    )

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        ArmVariantInvariantReceiptV2.from_content(**content)


def test_manifest_rejects_forged_binding_digest_even_when_population_is_resealed() -> None:
    bridge, parts = _parts(k_r=1)
    original_gate = parts.population.task_gates[0]
    original_support = original_gate.task_policy_support
    assert original_support is not None
    original_bundle = original_support.task_realization_bundles[0]
    forged_first = TaskArmVariantBinding.from_text(
        arm_role=original_bundle.arms[0].arm_role,
        prompt_text=original_bundle.arms[0].prompt_text,
        validation_evidence_sha256="0" * 64,
    )
    forged_bundle = TaskRealizationBundleRecord.from_components(
        hypothesis=bridge.frozen_hypothesis,
        realization=bridge.realizations[0],
        semantic_task_cluster_id=original_bundle.semantic_task_cluster_id,
        task_instance_id=original_bundle.task_instance_id,
        source_prompt_id=original_bundle.source_prompt_id,
        source_prompt_sha256=original_bundle.source_prompt_sha256,
        arms=(forged_first, *original_bundle.arms[1:]),
    )
    forged_support = TaskPolicySupportRecord.from_components(
        hypothesis=bridge.frozen_hypothesis,
        policy=bridge.realization_policy,
        realizations=bridge.realizations,
        bundles=(forged_bundle,),
    )
    pool_task = next(
        item
        for item in parts.partition.tasks
        if item.task_instance_id == original_gate.task_instance_id
    )
    membership = next(
        item
        for item in parts.clusters.memberships
        if item.task_instance_id == original_gate.task_instance_id
    )
    forged_gate = PopulationTaskGateRecordV2.from_components(
        pool_task=pool_task,
        cluster_membership=membership,
        hypothesis=bridge.frozen_hypothesis,
        eligibility=original_gate.eligibility,
        task_policy_support=forged_support,
        within_cluster_task_weight=original_gate.within_cluster_task_weight,
    )
    forged_population = PopulationFreezeManifestV2.from_components(
        pool_partition=parts.partition,
        semantic_cluster_manifest=parts.clusters,
        hypothesis=bridge.frozen_hypothesis,
        confirmation_pool=parts.population.confirmation_pool,
        task_gates=(forged_gate,),
        strata=parts.population.strata,
        minimum_gate_pass_tasks=1,
        minimum_gate_pass_clusters=1,
        population_construction_sha256=parts.population.population_construction_sha256,
        weighting_policy_sha256=parts.population.weighting_policy_sha256,
        stratification_policy_sha256=parts.population.stratification_policy_sha256,
    )

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        VariantInvariantEvidenceManifestV2.from_components(
            intervention_bridge=bridge,
            query_evidence=parts.query_evidence,
            population=forged_population,
            receipts=parts.variant_evidence.receipts,
        )


def test_context_drift_and_non_target_safety_drift_fail_before_generation() -> None:
    bridge, parts = _parts(k_r=1)
    source = parts.query_evidence.tasks[0]
    source_text = source.natural_prompt.prompt
    drifted_context = "Return the constant integer 1."
    unauthorized_safety = (
        source_text
        + prompt_feature_spec("safety.generic_security_reminder").intervention_clauses[0]
    )

    for role, prompt_text in (
        (ArmRole.NOOP_REWRITE, drifted_context),
        (ArmRole.TARGET_PATCH, unauthorized_safety),
    ):
        with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
            ArmVariantInvariantReceiptV2.from_variant_text(
                source_query_evidence=source,
                intervention_bridge=bridge,
                realization=bridge.realizations[0],
                arm_role=role,
                prompt_text=prompt_text,
                extractor=DeterministicCatalogExtractor(),
            )


def test_direct_receipt_id_forgery_fails_json_replay() -> None:
    _bridge_record, parts = _parts(k_r=1)
    payload = parts.variant_evidence.receipts[0].model_dump(mode="json")
    payload["variant_invariant_receipt_id"] = "variant_invariant_receipt_v2_" + "f" * 64

    with pytest.raises(ValidationError, match="variant evidence v2 contract failed validation"):
        ArmVariantInvariantReceiptV2.model_validate(payload, strict=True)

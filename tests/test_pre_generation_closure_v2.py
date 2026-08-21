from __future__ import annotations

from functools import cache

import pytest
from pydantic import ValidationError

from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.pre_generation_closure_v2 import (
    ConfirmatoryPreGenerationClosureV2,
    HypothesisVariantEvidenceBindingV2,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from secaware.schema.variant_evidence_v2 import VariantInvariantEvidenceManifestV2
from secaware.schema.variant_failure_evidence_v2 import VariantFailureEvidenceManifestV2
from test_experiment_freeze_v2 import (
    ExperimentComponents,
    _bridge,
    _execution_for_root,
    _experiment_components,
    _freeze,
)
from test_protocol_freeze_v2 import (
    TASK_COORDINATES,
    _inventory,
    _population_parts,
    _selection,
)
from test_variant_failure_evidence_v2 import _fixture as _failure_fixture


@cache
def _single_hypothesis_fixture(
    k_r: int = 1,
) -> tuple[
    ConfirmatoryExperimentFreezeV2,
    VariantFailureEvidenceManifestV2,
]:
    experiment = _freeze(_experiment_components((_bridge(k_r=k_r),)))
    root = experiment.protocol_roots[0]
    failure = VariantFailureEvidenceManifestV2.from_components(
        intervention_bridge=root.intervention_bridge,
        query_evidence=root.query_evidence,
        population=root.population,
        failure_receipts=(),
    )
    return experiment, failure


@cache
def _excluded_task_fixture() -> tuple[
    ConfirmatoryExperimentFreezeV2,
    VariantFailureEvidenceManifestV2,
]:
    bridge, query, population, failure_receipt = _failure_fixture()
    inventory = _inventory(TASK_COORDINATES)
    parts = _population_parts(bridge=bridge, inventory=inventory)
    assert parts.query_evidence == query
    retained = set(population.gate_pass_task_ids)
    retained_receipts = tuple(
        receipt
        for receipt in parts.variant_evidence.receipts
        if receipt.source_query_evidence.membership.task_instance_id in retained
    )
    variant_evidence = VariantInvariantEvidenceManifestV2.from_components(
        intervention_bridge=bridge,
        query_evidence=query,
        population=population,
        receipts=retained_receipts,
    )
    universe, selection = _selection(bridge)
    root = ProtocolFreezeRootV2.from_components(
        candidate_universe=universe,
        selection_freeze=selection,
        intervention_bridge=bridge,
        source_inventory=inventory,
        pool_partition=parts.partition,
        semantic_cluster_manifest=parts.clusters,
        population=population,
        query_evidence=query,
        variant_evidence=variant_evidence,
        preregistered_minimum_gate_pass_tasks=2,
        preregistered_minimum_gate_pass_clusters=1,
    )
    experiment = _freeze(
        ExperimentComponents(
            universe=universe,
            selection=selection,
            roots=(root,),
            executions=(_execution_for_root(root, randomization_seed=20260902),),
        )
    )
    failure = VariantFailureEvidenceManifestV2.from_components(
        intervention_bridge=bridge,
        query_evidence=query,
        population=population,
        failure_receipts=(failure_receipt,),
    )
    return experiment, failure


def test_closure_requires_explicit_empty_failure_manifest_and_replays_json() -> None:
    experiment, failure = _single_hypothesis_fixture()
    closure = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=experiment,
        variant_failure_evidence_manifests=(failure,),
    )

    assert closure.hypothesis_ids == experiment.hypothesis_ids
    assert closure.eligible_task_count == 3
    assert closure.retained_task_count == 3
    assert closure.excluded_eligible_task_count == 0
    assert closure.failure_receipt_count == 0
    assert closure.formal_analysis_requires_this_root is True
    assert (
        ConfirmatoryPreGenerationClosureV2.model_validate_json(closure.model_dump_json()) == closure
    )


def test_missing_or_duplicate_hypothesis_failure_manifest_is_rejected() -> None:
    experiment, failure = _single_hypothesis_fixture()
    with pytest.raises(
        ValidationError,
        match="pre-generation closure v2 contract failed validation",
    ):
        ConfirmatoryPreGenerationClosureV2.from_components(
            experiment_freeze=experiment,
            variant_failure_evidence_manifests=(),
        )
    with pytest.raises(
        ValidationError,
        match="pre-generation closure v2 contract failed validation",
    ):
        ConfirmatoryPreGenerationClosureV2.from_components(
            experiment_freeze=experiment,
            variant_failure_evidence_manifests=(failure, failure),
        )


def test_closure_binds_typed_failure_for_each_excluded_eligible_task() -> None:
    experiment, failure = _excluded_task_fixture()
    closure = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=experiment,
        variant_failure_evidence_manifests=(failure,),
    )

    assert closure.eligible_task_count == 3
    assert closure.retained_task_count == 2
    assert closure.excluded_eligible_task_count == 1
    assert closure.failure_receipt_count == 1
    assert closure.hypothesis_variant_evidence_bindings[0].failure_receipt_count == 1
    assert failure.failed_task_ids == ("task.3",)


def test_failure_manifest_from_another_protocol_root_cannot_be_substituted() -> None:
    experiment, _failure = _single_hypothesis_fixture()
    _other_experiment, other_failure = _single_hypothesis_fixture(2)

    with pytest.raises(
        ValidationError,
        match="pre-generation closure v2 contract failed validation",
    ):
        HypothesisVariantEvidenceBindingV2.from_binding(
            protocol_root=experiment.protocol_roots[0],
            failure_evidence=other_failure,
        )

    with pytest.raises(
        ValidationError,
        match="pre-generation closure v2 contract failed validation",
    ):
        ConfirmatoryPreGenerationClosureV2.from_components(
            experiment_freeze=experiment,
            variant_failure_evidence_manifests=(other_failure,),
        )


def test_synchronized_payload_change_cannot_impersonate_frozen_closure() -> None:
    experiment, failure = _single_hypothesis_fixture()
    original = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=experiment,
        variant_failure_evidence_manifests=(failure,),
    )
    replacement_experiment, replacement_failure = _single_hypothesis_fixture(2)
    replacement = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=replacement_experiment,
        variant_failure_evidence_manifests=(replacement_failure,),
    )
    assert replacement.confirmatory_pre_generation_closure_id != (
        original.confirmatory_pre_generation_closure_id
    )
    tampered = replacement.model_dump(mode="json")
    tampered["confirmatory_pre_generation_closure_id"] = (
        original.confirmatory_pre_generation_closure_id
    )

    with pytest.raises(
        ValidationError,
        match="pre-generation closure v2 contract failed validation",
    ):
        ConfirmatoryPreGenerationClosureV2.model_validate(tampered, strict=True)

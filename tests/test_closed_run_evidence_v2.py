from __future__ import annotations

from functools import cache

import pytest
from pydantic import ValidationError

from secaware.experiments.closed_run_evidence_v2 import ConfirmatoryClosedRunEvidenceV2
from secaware.experiments.run_evidence_v2 import ConfirmatoryRunEvidenceManifestV2
from secaware.schema.pre_generation_closure_v2 import ConfirmatoryPreGenerationClosureV2
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from secaware.schema.variant_failure_evidence_v2 import VariantFailureEvidenceManifestV2
from test_experiment_freeze_v2 import (
    ExperimentComponents,
    _custom_bridge,
    _execution_for_root,
    _freeze,
)
from test_protocol_freeze_v2 import _inventory, _population_parts, _selection
from test_run_evidence_v2 import _accounting_for_execution

_SMALL_COORDINATES = (
    ("task.1", "cluster.1"),
    ("task.2", "cluster.2"),
)


@cache
def _closed_fixture(target_salt: str = "closed-run-original") -> ConfirmatoryClosedRunEvidenceV2:
    bridge = _custom_bridge(
        model_scope=("model.alpha",),
        k_r=1,
        target_salt=target_salt,
    )
    inventory = _inventory(_SMALL_COORDINATES)
    universe, selection = _selection(bridge)
    parts = _population_parts(
        bridge=bridge,
        inventory=inventory,
        coordinates=_SMALL_COORDINATES,
        minimum_tasks=2,
        minimum_clusters=2,
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
        preregistered_minimum_gate_pass_tasks=2,
        preregistered_minimum_gate_pass_clusters=2,
    )
    experiment = _freeze(
        ExperimentComponents(
            universe=universe,
            selection=selection,
            roots=(root,),
            executions=(_execution_for_root(root, randomization_seed=20260903),),
        )
    )
    failure = VariantFailureEvidenceManifestV2.from_components(
        intervention_bridge=root.intervention_bridge,
        query_evidence=root.query_evidence,
        population=root.population,
        failure_receipts=(),
    )
    closure = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=experiment,
        variant_failure_evidence_manifests=(failure,),
    )
    accounting = _accounting_for_execution(experiment=experiment, execution_index=0)
    evidence = ConfirmatoryRunEvidenceManifestV2.from_components(
        experiment_freeze=experiment,
        total_assignment_accountings=(accounting,),
    )
    return ConfirmatoryClosedRunEvidenceV2.from_components(
        pre_generation_closure=closure,
        run_evidence=evidence,
    )


@cache
def _replacement_closed_fixture() -> ConfirmatoryClosedRunEvidenceV2:
    return _closed_fixture("closed-run-replacement")


def test_closed_run_binds_pre_generation_failures_and_runtime_accounting() -> None:
    closed = _closed_fixture()

    assert closed.pre_randomization_excluded_eligible_task_count == 0
    assert closed.pre_randomization_failure_receipt_count == 0
    assert closed.runtime_expected_assignment_count == 8
    assert closed.runtime_terminally_accounted_assignment_count == 8
    assert closed.runtime_failure_count == 0
    assert closed.formal_point_estimation_ready is True
    assert ConfirmatoryClosedRunEvidenceV2.model_validate_json(closed.model_dump_json()) == closed


def test_foreign_pre_generation_closure_cannot_bind_to_run_evidence() -> None:
    closed = _closed_fixture()
    foreign_closure = _replacement_closed_fixture().pre_generation_closure

    with pytest.raises(
        ValidationError,
        match="closed run evidence v2 contract failed validation",
    ):
        ConfirmatoryClosedRunEvidenceV2.from_components(
            pre_generation_closure=foreign_closure,
            run_evidence=closed.run_evidence,
        )


def test_rehashed_replacement_cannot_impersonate_pinned_closed_run() -> None:
    original = _closed_fixture()
    replacement = _replacement_closed_fixture()
    assert replacement.confirmatory_closed_run_evidence_id != (
        original.confirmatory_closed_run_evidence_id
    )
    impersonation = replacement.model_dump(mode="json")
    impersonation["confirmatory_closed_run_evidence_id"] = (
        original.confirmatory_closed_run_evidence_id
    )

    with pytest.raises(
        ValidationError,
        match="closed run evidence v2 contract failed validation",
    ):
        ConfirmatoryClosedRunEvidenceV2.model_validate(impersonation, strict=True)

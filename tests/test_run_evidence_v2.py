from __future__ import annotations

from dataclasses import dataclass
from functools import cache

import pytest
from pydantic import ValidationError

from secaware.experiments.execution_v2 import (
    AssignmentExecutionReceiptV2,
    ExecutionPolicyFreezeManifestV2,
    InfrastructureFailureReceiptV2,
    OutcomeAssemblyReceiptV2,
    RetryAttemptReceiptV2,
    SyntaxValidationReceiptV2,
    TotalAssignmentAccountingManifestV2,
)
from secaware.experiments.randomization_v2 import AssignmentUnitKeyV2
from secaware.experiments.run_evidence_v2 import ConfirmatoryRunEvidenceManifestV2
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.experiments import ArmRole
from secaware.schema.policy_v2 import TaskRealizationBundleRecord
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
)
from test_experiment_freeze_v2 import (
    ExperimentComponents,
    _common_selection,
    _custom_bridge,
    _execution_for_root,
    _freeze,
)
from fixtures_v2 import _bridge, _inventory, _population_parts, _sha


def _committed_assignment(
    unit: AssignmentUnitKeyV2,
    execution_freeze: ExecutionPolicyFreezeManifestV2,
) -> ConfirmationAssignmentRecordV2:
    randomization = execution_freeze.randomization
    block = unit.block
    return ConfirmationAssignmentRecordV2.from_content(
        regime_id="randomized_confirmation",
        semantic_task_cluster_id=block.semantic_task_cluster_id,
        task_instance_id=block.task_instance_id,
        model_id=block.model_id,
        request_randomness_slot=unit.request_randomness_slot,
        provider_seed=unit.provider_seed,
        assignment_id=unit.assignment_id,
        hypothesis_id=block.hypothesis_id,
        target_spec_id=block.target_spec_id,
        realization_spec_id=block.realization_spec_id,
        task_realization_bundle_id=block.task_realization_bundle_id,
        variant_id=unit.variant_id,
        arm_protocol_id=block.arm_protocol_id,
        block_id=block.block_id,
        assigned_arm=unit.assigned_arm,
        randomization_manifest_sha256=randomization.semantic_sha256,
    )


def _bundle_for_unit(
    unit: AssignmentUnitKeyV2,
    execution_freeze: ExecutionPolicyFreezeManifestV2,
) -> TaskRealizationBundleRecord:
    return next(
        bundle
        for gate in execution_freeze.randomization.population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
        if bundle.task_realization_bundle_id == unit.block.task_realization_bundle_id
    )


def _authenticated_outcome_receipt(
    *,
    unit: AssignmentUnitKeyV2,
    execution_freeze: ExecutionPolicyFreezeManifestV2,
    secure_override: bool | None = None,
) -> OutcomeAssemblyReceiptV2:
    model_policy = next(
        item for item in execution_freeze.model_policies if item.model_id == unit.block.model_id
    )
    measurement = execution_freeze.measurement_policy
    assignment = _committed_assignment(unit, execution_freeze)
    bundle = _bundle_for_unit(unit, execution_freeze)
    variant = next(item for item in bundle.arms if item.arm_role is unit.assigned_arm)
    coordinates = {
        "regime_id": "randomized_confirmation",
        "semantic_task_cluster_id": assignment.semantic_task_cluster_id,
        "task_instance_id": assignment.task_instance_id,
        "model_id": assignment.model_id,
        "request_randomness_slot": assignment.request_randomness_slot,
        "provider_seed": assignment.provider_seed,
        "assignment_id": assignment.assignment_id,
        "hypothesis_id": assignment.hypothesis_id,
        "target_spec_id": assignment.target_spec_id,
        "realization_spec_id": assignment.realization_spec_id,
        "task_realization_bundle_id": assignment.task_realization_bundle_id,
        "variant_id": assignment.variant_id,
        "arm_protocol_id": assignment.arm_protocol_id,
        "block_id": assignment.block_id,
        "assigned_arm": assignment.assigned_arm,
    }
    request = GenerationRequestRecordV2.from_content(
        **coordinates,
        prompt_id=variant.variant_prompt_id,
        prompt=variant.prompt_text,
        prompt_sha256=variant.prompt_sha256,
        language=model_policy.language,
        endpoint_sha256=model_policy.endpoint_sha256,
        generation_parameters_sha256=unit.generation_parameters_sha256,
        system_template_sha256=model_policy.system_template_sha256,
        generator_producer_id=model_policy.generator_producer_id,
        generator_policy_sha256=model_policy.generator_policy_sha256,
    )
    assignment_execution = AssignmentExecutionReceiptV2.from_request(
        execution_policy_freeze=execution_freeze,
        assignment_unit=unit,
        committed_assignment=assignment,
        task_realization_bundle=bundle,
        generation_request=request,
    )
    code_text = "def generated():\n    return 1\n"
    code = GeneratedCodeRecordV2.from_content(
        **coordinates,
        generation_request_id=request.generation_request_id,
        code_status="generated",
        code=code_text,
        code_sha256=_sha(code_text),
        terminal_reason=None,
        provider_response_sha256=_sha(f"response:{unit.assignment_id}"),
        generator_runtime_sha256=_sha("generator-runtime:run-evidence"),
    )
    secure = (
        unit.assigned_arm in {ArmRole.TARGET_PATCH, ArmRole.TARGET_REMOVE}
        if secure_override is None
        else secure_override
    )
    oracle = OracleResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure" if secure else "insecure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256=_sha(f"oracle:{unit.assignment_id}"),
        oracle_producer_id=measurement.oracle_producer_id,
        oracle_policy_sha256=measurement.oracle_policy_sha256,
        oracle_runtime_sha256=_sha("oracle-runtime:run-evidence"),
    )
    functional = FunctionalResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="pass",
        evidence_sha256=_sha(f"functional:{unit.assignment_id}"),
        evaluator_producer_id=measurement.functional_evaluator_producer_id,
        evaluator_policy_sha256=measurement.functional_evaluator_policy_sha256,
        evaluator_runtime_sha256=_sha("functional-runtime:run-evidence"),
    )
    syntax = SyntaxValidationReceiptV2.from_generated_code(
        generated_code=code,
        language=model_policy.language,
        status="valid",
        parser_producer_id=measurement.parser_producer_id,
        parser_policy_sha256=measurement.parser_policy_sha256,
        parser_runtime_sha256=_sha("parser-runtime:run-evidence"),
        evidence_sha256=_sha(f"parser:{unit.assignment_id}"),
    )
    return OutcomeAssemblyReceiptV2.from_runtime(
        assignment_execution_receipt=assignment_execution,
        generated_code=code,
        syntax_validation=syntax,
        oracle_result=oracle,
        functional_result=functional,
    )


def _accounting_for_execution(
    *,
    experiment: ConfirmatoryExperimentFreezeV2,
    execution_index: int,
    secure_assignment_ids: frozenset[str] | None = None,
) -> TotalAssignmentAccountingManifestV2:
    execution = experiment.execution_policy_freezes[execution_index]
    receipts = tuple(
        _authenticated_outcome_receipt(
            unit=unit,
            execution_freeze=execution,
            secure_override=(
                None
                if secure_assignment_ids is None
                else unit.assignment_id in secure_assignment_ids
            ),
        )
        for unit in execution.randomization.assignments
    )
    return TotalAssignmentAccountingManifestV2.from_terminal_receipts(
        execution_policy_freeze=execution,
        outcome_assembly_receipts=receipts,
        infrastructure_failure_receipts=(),
    )


@dataclass(frozen=True)
class RunEvidenceFixture:
    experiment: ConfirmatoryExperimentFreezeV2
    accountings: tuple[TotalAssignmentAccountingManifestV2, ...]
    evidence: ConfirmatoryRunEvidenceManifestV2


@cache
def _fixture() -> RunEvidenceFixture:
    bridges = (_bridge(k_r=2), _bridge(k_r=1))
    failed_bridge = _custom_bridge(k_r=3, target_salt="run-evidence-failed-slot")
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
    experiment = _freeze(
        ExperimentComponents(
            universe=universe,
            selection=selection,
            roots=tuple(roots),
            executions=tuple(executions),
        )
    )
    accountings = tuple(
        _accounting_for_execution(experiment=experiment, execution_index=index)
        for index in range(len(experiment.execution_policy_freezes))
    )
    evidence = ConfirmatoryRunEvidenceManifestV2.from_components(
        experiment_freeze=experiment,
        total_assignment_accountings=accountings,
    )
    return RunEvidenceFixture(
        experiment=experiment,
        accountings=accountings,
        evidence=evidence,
    )


def _without_id(evidence: ConfirmatoryRunEvidenceManifestV2) -> dict[str, object]:
    return evidence.model_dump(
        mode="python",
        exclude={"schema_version", "confirmatory_run_evidence_manifest_id"},
    )


def _with_one_terminal_failure(
    fixture: RunEvidenceFixture,
) -> tuple[
    ConfirmatoryRunEvidenceManifestV2,
    TotalAssignmentAccountingManifestV2,
]:
    original = fixture.accountings[0]
    displaced = original.outcome_assembly_receipts[-1]
    root = fixture.experiment.protocol_roots[0]
    failure = InfrastructureFailureReceiptV2.from_attempts(
        assignment_execution_receipt=displaced.assignment_execution_receipt,
        retry_policy_sha256=root.intervention_bridge.arm_protocol.retry_policy_sha256,
        attempts=(
            RetryAttemptReceiptV2(
                attempt_index=0,
                stage="provider_transport",
                status="terminal_failure",
                attempt_evidence_sha256=_sha("run-evidence-terminal-transport"),
                provider_response_sha256=None,
                valid_response_persisted=False,
            ),
        ),
        valid_response_lost=False,
    )
    failing_accounting = TotalAssignmentAccountingManifestV2.from_terminal_receipts(
        execution_policy_freeze=original.execution_policy_freeze,
        outcome_assembly_receipts=original.outcome_assembly_receipts[:-1],
        infrastructure_failure_receipts=(failure,),
    )
    evidence = ConfirmatoryRunEvidenceManifestV2.from_components(
        experiment_freeze=fixture.experiment,
        total_assignment_accountings=(failing_accounting, *fixture.accountings[1:]),
    )
    return evidence, failing_accounting


@pytest.mark.milestone
def test_run_evidence_closes_every_hypothesis_assignment_and_model_coordinate() -> None:
    fixture = _fixture()
    evidence = fixture.evidence

    assert evidence.hypothesis_ids == fixture.experiment.hypothesis_ids
    assert evidence.model_ids == fixture.experiment.model_ids
    assert evidence.hypothesis_count == 2
    assert evidence.model_count == 2
    assert evidence.hypothesis_model_coordinate_count == 4
    assert evidence.hypothesis_model_coordinates == (
        fixture.experiment.hypothesis_model_coordinates
    )
    assert len(evidence.hypothesis_run_evidence_bindings) == 2
    assert evidence.expected_assignment_count == 72
    assert evidence.terminally_accounted_assignment_count == 72
    assert evidence.outcome_count == 72
    assert evidence.failure_count == 0
    assert evidence.unresolved_assignment_count == 0
    assert evidence.formal_point_estimation_ready is True
    assert all(item.count == 0 for item in evidence.terminal_failure_stage_counts)
    assert (
        ConfirmatoryRunEvidenceManifestV2.model_validate_json(evidence.model_dump_json())
        == evidence
    )

    for binding, root, execution, accounting in zip(
        evidence.hypothesis_run_evidence_bindings,
        fixture.experiment.protocol_roots,
        fixture.experiment.execution_policy_freezes,
        fixture.accountings,
        strict=True,
    ):
        assert binding.protocol_freeze_id == root.protocol_freeze_id
        assert binding.execution_policy_freeze_manifest_id == (
            execution.execution_policy_freeze_manifest_id
        )
        assert binding.population_freeze_manifest_id == (
            root.population.population_freeze_manifest_id
        )
        assert binding.randomization_manifest_id == (
            execution.randomization.randomization_manifest_id
        )
        assert binding.total_assignment_accounting_manifest_id == (
            accounting.total_assignment_accounting_manifest_id
        )
        assert binding.assignment_ids == tuple(
            sorted(item.assignment_id for item in execution.randomization.assignments)
        )


def test_terminal_failure_is_preserved_and_disables_formal_point_estimation() -> None:
    fixture = _fixture()
    evidence, failing_accounting = _with_one_terminal_failure(fixture)

    assert evidence.expected_assignment_count == 72
    assert evidence.terminally_accounted_assignment_count == 72
    assert evidence.outcome_count == 71
    assert evidence.failure_count == 1
    assert evidence.unresolved_assignment_count == 0
    assert evidence.formal_point_estimation_ready is False
    assert len(evidence.infrastructure_failure_receipt_ids) == 1
    assert len(evidence.provenance_closed_coverage_manifest_ids) == 1
    assert failing_accounting.confirmatory_coverage is None
    assert {item.stage: item.count for item in evidence.terminal_failure_stage_counts}[
        "provider_transport"
    ] == 1
    assert evidence.hypothesis_run_evidence_bindings[0].formal_point_estimation_ready is False
    assert evidence.hypothesis_run_evidence_bindings[1].formal_point_estimation_ready is True

    genuine_failure = failing_accounting.infrastructure_failure_receipts[0]
    wrong_retry_content = genuine_failure.model_dump(
        mode="python",
        exclude={"schema_version", "infrastructure_failure_receipt_id"},
    )
    wrong_retry_content["retry_policy_sha256"] = _sha("post-hoc-retry-policy")
    wrong_retry_failure = InfrastructureFailureReceiptV2.from_content(**wrong_retry_content)
    wrong_retry_accounting = TotalAssignmentAccountingManifestV2.from_terminal_receipts(
        execution_policy_freeze=failing_accounting.execution_policy_freeze,
        outcome_assembly_receipts=failing_accounting.outcome_assembly_receipts,
        infrastructure_failure_receipts=(wrong_retry_failure,),
    )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_components(
            experiment_freeze=fixture.experiment,
            total_assignment_accountings=(wrong_retry_accounting, *fixture.accountings[1:]),
        )


@pytest.mark.milestone
def test_missing_duplicate_or_closed_coverage_substitution_is_rejected() -> None:
    fixture = _fixture()

    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_components(
            experiment_freeze=fixture.experiment,
            total_assignment_accountings=fixture.accountings[:-1],
        )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_components(
            experiment_freeze=fixture.experiment,
            total_assignment_accountings=(fixture.accountings[0], fixture.accountings[0]),
        )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_components(
            experiment_freeze=fixture.experiment,
            total_assignment_accountings=(
                fixture.accountings[0].confirmatory_coverage,  # type: ignore[arg-type]
                fixture.accountings[1],
            ),
        )


def test_cross_hypothesis_binding_swap_and_model_coordinate_deletion_are_rejected() -> None:
    evidence = _fixture().evidence

    swapped = _without_id(evidence)
    swapped["hypothesis_run_evidence_bindings"] = tuple(
        reversed(evidence.hypothesis_run_evidence_bindings)
    )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_content(**swapped)

    coordinate_deleted = _without_id(evidence)
    coordinate_deleted["hypothesis_model_coordinates"] = evidence.hypothesis_model_coordinates[:-1]
    coordinate_deleted["hypothesis_model_coordinate_ids"] = (
        evidence.hypothesis_model_coordinate_ids[:-1]
    )
    coordinate_deleted["hypothesis_model_coordinate_count"] = (
        evidence.hypothesis_model_coordinate_count - 1
    )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_content(**coordinate_deleted)


def test_accounting_from_replacement_randomization_cannot_cross_the_frozen_run() -> None:
    fixture = _fixture()
    root = fixture.experiment.protocol_roots[0]
    replacement_execution = _execution_for_root(root, randomization_seed=999_999)
    replacement_experiment_content = fixture.experiment.model_dump(
        mode="python",
        exclude={"schema_version", "confirmatory_experiment_freeze_id"},
    )
    replacement_experiment_content["execution_policy_freezes"] = (
        replacement_execution,
        *fixture.experiment.execution_policy_freezes[1:],
    )
    replacement_experiment_content["execution_policy_freeze_manifest_ids"] = (
        replacement_execution.execution_policy_freeze_manifest_id,
        *fixture.experiment.execution_policy_freeze_manifest_ids[1:],
    )
    replacement_experiment_content["randomization_manifest_ids"] = (
        replacement_execution.randomization.randomization_manifest_id,
        *fixture.experiment.randomization_manifest_ids[1:],
    )
    replacement_experiment_content["hypothesis_model_coordinates"] = tuple(
        type(coordinate).from_binding(
            protocol_root=root,
            execution_freeze=replacement_execution,
            model_id=coordinate.model_id,
        )
        if coordinate.hypothesis_id == root.intervention_bridge.frozen_hypothesis.hypothesis_id
        else coordinate
        for coordinate in fixture.experiment.hypothesis_model_coordinates
    )
    replacement_experiment = ConfirmatoryExperimentFreezeV2.from_content(
        **replacement_experiment_content
    )
    replacement_accounting = _accounting_for_execution(
        experiment=replacement_experiment,
        execution_index=0,
    )

    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_components(
            experiment_freeze=fixture.experiment,
            total_assignment_accountings=(
                replacement_accounting,
                fixture.accountings[1],
            ),
        )


def test_failure_deletion_or_synchronous_rehash_cannot_impersonate_frozen_evidence() -> None:
    fixture = _fixture()
    failing_evidence, failing_accounting = _with_one_terminal_failure(fixture)

    deleted_failure = failing_accounting.model_dump(
        mode="python",
        exclude={"schema_version", "total_assignment_accounting_manifest_id"},
    )
    deleted_failure["infrastructure_failure_receipts"] = ()
    deleted_failure["failure_assignment_ids"] = ()
    deleted_failure["failure_count"] = 0
    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        TotalAssignmentAccountingManifestV2.from_content(**deleted_failure)

    successful_evidence = fixture.evidence
    assert successful_evidence.confirmatory_run_evidence_manifest_id != (
        failing_evidence.confirmatory_run_evidence_manifest_id
    )
    impersonation = successful_evidence.model_dump(mode="python")
    impersonation["confirmatory_run_evidence_manifest_id"] = (
        failing_evidence.confirmatory_run_evidence_manifest_id
    )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.model_validate(impersonation, strict=True)

    synchronized_summary_deletion = _without_id(failing_evidence)
    synchronized_summary_deletion["infrastructure_failure_receipt_ids"] = ()
    synchronized_summary_deletion["failure_count"] = 0
    synchronized_summary_deletion["formal_point_estimation_ready"] = True
    synchronized_summary_deletion["terminal_failure_stage_counts"] = tuple(
        item.model_copy(update={"count": 0})
        for item in failing_evidence.terminal_failure_stage_counts
    )
    with pytest.raises(ValidationError, match="run evidence v2 contract failed validation"):
        ConfirmatoryRunEvidenceManifestV2.from_content(**synchronized_summary_deletion)

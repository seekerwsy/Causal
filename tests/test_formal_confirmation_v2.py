from __future__ import annotations

import inspect
from dataclasses import dataclass, replace
from functools import cache

import pytest
from pydantic import TypeAdapter, ValidationError

import secaware.analysis.formal_confirmation_v2 as formal_confirmation_module
import secaware.schema.multi_support_inference_v2 as multi_support_schema_module
from secaware.analysis.confirmatory_contributions_v2 import (
    _derive,
    _derive_from_formal_context_v2,
)
from secaware.analysis.formal_confirmation_v2 import (
    FormalConfirmationResultV2,
    _ValidatedFormalContextV2,
    run_formal_confirmation_v2,
    validate_formal_confirmation_result_v2,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    _run,
    _run_frozen_domain_from_formal_context_v2,
)
from secaware.experiments.closed_run_evidence_v2 import ConfirmatoryClosedRunEvidenceV2
from secaware.experiments.run_evidence_v2 import ConfirmatoryRunEvidenceManifestV2
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.experiments import ArmRole
from secaware.schema.formal_analysis_v2 import (
    FormalAnalysisProtocolV2,
    FormalConfirmationStatusV2,
    FormalNonEvaluableReasonV2,
)
from secaware.schema.multi_support_inference_v2 import (
    MultiSupportFormalFamilyV2,
    MultiSupportSimultaneousInferencePlanV2,
)
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
from test_run_evidence_v2 import (
    RunEvidenceFixture,
    _accounting_for_execution,
    _with_one_terminal_failure,
)

EVALUATED_COORDINATES = tuple(
    (f"task.formal.{index}", f"cluster.formal.{index}") for index in range(8)
)
MINIMAL_COORDINATES = tuple(
    (f"task.formal.minimal.{index}", f"cluster.formal.minimal.{index}") for index in range(2)
)
FOREIGN_MINIMAL_COORDINATES = tuple(
    (f"task.formal.foreign.{index}", f"cluster.formal.foreign.{index}") for index in range(2)
)


@dataclass(frozen=True)
class FormalRunEvidenceFixture(RunEvidenceFixture):
    pre_generation_closure: ConfirmatoryPreGenerationClosureV2
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2


def _formal_fixture(
    coordinates: tuple[tuple[str, str], ...],
) -> FormalRunEvidenceFixture:
    bridge = _custom_bridge(
        model_scope=("model.alpha",),
        k_r=1,
        target_salt="formal-evaluated",
    )
    universe, selection = _selection(bridge)
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
    execution = _execution_for_root(root, randomization_seed=20260821)
    experiment = _freeze(
        ExperimentComponents(
            universe=universe,
            selection=selection,
            roots=(root,),
            executions=(execution,),
        )
    )
    task_index = {
        task_instance_id: index for index, (task_instance_id, _cluster_id) in enumerate(coordinates)
    }
    secure_assignment_ids = frozenset(
        unit.assignment_id
        for unit in execution.randomization.assignments
        if unit.assigned_arm is ArmRole.TARGET_PATCH
        or (
            unit.assigned_arm is ArmRole.NOOP_REWRITE
            and task_index[unit.block.task_instance_id] % 2 == 0
        )
        or (
            unit.assigned_arm is ArmRole.LENGTH_MATCHED_PLACEBO
            and task_index[unit.block.task_instance_id] % 4 in {0, 1}
        )
        or (
            unit.assigned_arm is ArmRole.GENERIC_SECURITY_REMINDER
            and task_index[unit.block.task_instance_id] < len(coordinates) // 2
        )
    )
    accounting = _accounting_for_execution(
        experiment=experiment,
        execution_index=0,
        secure_assignment_ids=secure_assignment_ids,
    )
    evidence = ConfirmatoryRunEvidenceManifestV2.from_components(
        experiment_freeze=experiment,
        total_assignment_accountings=(accounting,),
    )
    failure_manifests = tuple(
        VariantFailureEvidenceManifestV2.from_components(
            intervention_bridge=protocol_root.intervention_bridge,
            query_evidence=protocol_root.query_evidence,
            population=protocol_root.population,
            failure_receipts=(),
        )
        for protocol_root in experiment.protocol_roots
    )
    closure = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=experiment,
        variant_failure_evidence_manifests=failure_manifests,
    )
    closed = ConfirmatoryClosedRunEvidenceV2.from_components(
        pre_generation_closure=closure,
        run_evidence=evidence,
    )
    return FormalRunEvidenceFixture(
        experiment=experiment,
        accountings=(accounting,),
        evidence=evidence,
        pre_generation_closure=closure,
        closed_run_evidence=closed,
    )


@cache
def _evaluated_fixture() -> FormalRunEvidenceFixture:
    return _formal_fixture(EVALUATED_COORDINATES)


@cache
def _minimal_fixture() -> FormalRunEvidenceFixture:
    return _formal_fixture(MINIMAL_COORDINATES)


@cache
def _foreign_minimal_fixture() -> FormalRunEvidenceFixture:
    return _formal_fixture(FOREIGN_MINIMAL_COORDINATES)


@cache
def _minimal_context() -> _ValidatedFormalContextV2:
    fixture = _minimal_fixture()
    return _ValidatedFormalContextV2._from_root(
        fixture.closed_run_evidence,
        access=formal_confirmation_module._FORMAL_ENTRY_CONTEXT_ACCESS,
    )


def _closed_with_evidence(
    fixture: FormalRunEvidenceFixture,
    evidence: ConfirmatoryRunEvidenceManifestV2,
) -> ConfirmatoryClosedRunEvidenceV2:
    return ConfirmatoryClosedRunEvidenceV2.from_components(
        pre_generation_closure=fixture.pre_generation_closure,
        run_evidence=evidence,
    )


def _unsafe_context_clone(
    context: _ValidatedFormalContextV2,
    **updates: object,
) -> _ValidatedFormalContextV2:
    """Test-only simulation of deliberate frozen-object memory mutation."""

    clone = object.__new__(_ValidatedFormalContextV2)
    for field in context.__slots__:
        object.__setattr__(clone, field, updates.get(field, getattr(context, field)))
    return clone


def _synchronously_rehash_plan(
    plan: MultiSupportSimultaneousInferencePlanV2,
) -> MultiSupportSimultaneousInferencePlanV2:
    payload = plan.model_dump(mode="json", exclude={"inference_plan_id"})
    return plan.model_copy(
        update={
            "inference_plan_id": "multi_support_simultaneous_plan_v2_"
            + multi_support_schema_module._digest(payload)
        }
    )


@cache
def _evaluated_result() -> FormalConfirmationResultV2:
    fixture = _evaluated_fixture()
    return run_formal_confirmation_v2(fixture.closed_run_evidence)


@cache
def _inference_undefined_result() -> FormalConfirmationResultV2:
    fixture = _minimal_fixture()
    return run_formal_confirmation_v2(fixture.closed_run_evidence)


@cache
def _terminal_failure_closed_root() -> ConfirmatoryClosedRunEvidenceV2:
    fixture = _minimal_fixture()
    failing_evidence, _accounting = _with_one_terminal_failure(fixture)
    return _closed_with_evidence(fixture, failing_evidence)


@cache
def _terminal_failure_result() -> FormalConfirmationResultV2:
    return run_formal_confirmation_v2(_terminal_failure_closed_root())


def _without_protocol_id(protocol: FormalAnalysisProtocolV2) -> dict[str, object]:
    return protocol.model_dump(
        mode="python",
        exclude={"schema_version", "formal_analysis_protocol_id"},
    )


def _synchronized_incomplete_experiment(
    fixture: RunEvidenceFixture,
    *,
    delete: str,
) -> ConfirmatoryExperimentFreezeV2:
    experiment = fixture.experiment
    updates: dict[str, object]
    if delete == "hypothesis":
        removed_hypothesis_id = experiment.hypothesis_ids[-1]
        coordinates = tuple(
            item
            for item in experiment.hypothesis_model_coordinates
            if item.hypothesis_id != removed_hypothesis_id
        )
        updates = {
            "protocol_roots": experiment.protocol_roots[:-1],
            "protocol_freeze_ids": experiment.protocol_freeze_ids[:-1],
            "execution_policy_freezes": experiment.execution_policy_freezes[:-1],
            "execution_policy_freeze_manifest_ids": (
                experiment.execution_policy_freeze_manifest_ids[:-1]
            ),
            "randomization_manifest_ids": experiment.randomization_manifest_ids[:-1],
            "hypothesis_ids": experiment.hypothesis_ids[:-1],
            "hypothesis_count": experiment.hypothesis_count - 1,
            "hypothesis_model_coordinates": coordinates,
            "hypothesis_model_coordinate_count": len(coordinates),
        }
    elif delete == "model":
        removed_model_id = experiment.model_ids[-1]
        coordinates = tuple(
            item
            for item in experiment.hypothesis_model_coordinates
            if item.model_id != removed_model_id
        )
        updates = {
            "model_ids": experiment.model_ids[:-1],
            "model_count": experiment.model_count - 1,
            "hypothesis_model_coordinates": coordinates,
            "hypothesis_model_coordinate_count": len(coordinates),
        }
    else:  # pragma: no cover - test-only helper contract
        raise AssertionError(delete)
    return experiment.model_copy(update=updates)


def test_evaluated_entry_derives_all_families_from_authenticated_run_evidence() -> None:
    fixture = _evaluated_fixture()
    result = _evaluated_result()
    protocol = FormalAnalysisProtocolV2.from_experiment(fixture.experiment)
    coverage = fixture.accountings[0].confirmatory_coverage
    assert coverage is not None

    assert result.status is FormalConfirmationStatusV2.EVALUATED
    assert result.non_evaluable_reason is None
    assert result.failed_family is None
    assert len(result.family_results) == 4
    assert len(result.coordinate_decisions) == 1
    assert result.complete_hypothesis_model_family_preserved is True
    assert result.assigned_arm_itt_only is True
    assert result.target_changed_and_semantic_validity_diagnostic_only is True
    assert result.joint_outcome_can_promote_security_label is False
    assert result.optional_evidence_can_promote_confirmatory_label is False

    expected_family_definitions = {
        MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD: (
            "y_secure_yield",
            ArmRole.TARGET_PATCH,
            ArmRole.NOOP_REWRITE,
        ),
        MultiSupportFormalFamilyV2.KEY_JOINT: (
            "y_joint",
            ArmRole.TARGET_PATCH,
            ArmRole.NOOP_REWRITE,
        ),
        MultiSupportFormalFamilyV2.SPECIFICITY_PLACEBO: (
            "y_secure_yield",
            ArmRole.TARGET_PATCH,
            ArmRole.LENGTH_MATCHED_PLACEBO,
        ),
        MultiSupportFormalFamilyV2.SPECIFICITY_GENERIC: (
            "y_secure_yield",
            ArmRole.TARGET_PATCH,
            ArmRole.GENERIC_SECURITY_REMINDER,
        ),
    }
    plan_by_family = {item.formal_family: item for item in protocol.family_plans}
    for family_result in result.family_results:
        plan = plan_by_family[family_result.formal_family]
        coordinate = plan.family.coordinates[0]
        assert (
            coordinate.outcome_name,
            coordinate.treatment_arm,
            coordinate.control_arm,
        ) == expected_family_definitions[family_result.formal_family]
        assert plan.bootstrap_samples == 999
        assert plan.minimum_valid_bootstrap_draws == 950
        assert len(family_result.contribution_artifacts) == 1
        assert family_result.contribution_artifacts[0].provenance_closed_coverage_manifest_id == (
            coverage.provenance_closed_coverage_manifest_id
        )
        assert family_result.simultaneous_result.valid_draw_count >= 950
        assert (
            family_result.simultaneous_result.valid_draw_count
            + family_result.simultaneous_result.invalid_draw_count
            == 999
        )


def test_only_official_entry_derives_exactly_four_frozen_families_and_replays_json() -> None:
    fixture = _minimal_fixture()
    protocol = FormalAnalysisProtocolV2.from_experiment(fixture.experiment)

    assert tuple(inspect.signature(run_formal_confirmation_v2).parameters) == (
        "closed_run_evidence",
    )
    assert tuple(inspect.signature(validate_formal_confirmation_result_v2).parameters) == (
        "closed_run_evidence",
        "result",
    )
    assert protocol.family_order == tuple(item.value for item in MultiSupportFormalFamilyV2)
    assert tuple(item.formal_family for item in protocol.family_plans) == tuple(
        MultiSupportFormalFamilyV2
    )
    assert all(
        item.family.family_size == fixture.experiment.hypothesis_model_coordinate_count
        for item in protocol.family_plans
    )
    assert FormalAnalysisProtocolV2.model_validate_json(protocol.model_dump_json()) == protocol

    closed_json = fixture.closed_run_evidence.model_dump_json()
    replayed_closed = ConfirmatoryClosedRunEvidenceV2.model_validate_json(closed_json)
    result = _inference_undefined_result()
    replayed_result = TypeAdapter(FormalConfirmationResultV2).validate_json(
        TypeAdapter(FormalConfirmationResultV2).dump_json(result)
    )
    assert replayed_closed == fixture.closed_run_evidence
    assert replayed_result == result
    assert result.confirmatory_closed_run_evidence_id == (
        fixture.closed_run_evidence.confirmatory_closed_run_evidence_id
    )
    assert result.confirmatory_pre_generation_closure_id == (
        fixture.pre_generation_closure.confirmatory_pre_generation_closure_id
    )
    assert (
        validate_formal_confirmation_result_v2(
            replayed_closed,
            replayed_result,
        )
        == result
    )


def test_raw_experiment_and_missing_failure_manifest_cannot_enter_formal_analysis() -> None:
    fixture = _minimal_fixture()
    with pytest.raises(ValueError, match="exact confirmatory closed run evidence is required"):
        run_formal_confirmation_v2(fixture.experiment)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        run_formal_confirmation_v2(  # type: ignore[call-arg]
            fixture.pre_generation_closure,  # type: ignore[arg-type]
            fixture.evidence,
        )

    missing = fixture.pre_generation_closure.model_copy(
        update={
            "variant_failure_evidence_manifests": (),
            "hypothesis_variant_evidence_bindings": (),
            "variant_failure_evidence_manifest_ids": (),
        }
    )
    attacked = fixture.closed_run_evidence.model_copy(update={"pre_generation_closure": missing})
    with pytest.raises(ValueError, match="closed run evidence failed validation"):
        run_formal_confirmation_v2(attacked)


def test_foreign_or_synchronously_rehashed_closed_root_fails_closed() -> None:
    fixture = _minimal_fixture()
    foreign = _foreign_minimal_fixture()

    impersonated = foreign.closed_run_evidence.model_copy(
        update={
            "confirmatory_closed_run_evidence_id": (
                fixture.closed_run_evidence.confirmatory_closed_run_evidence_id
            )
        }
    )
    with pytest.raises(ValueError, match="closed run evidence failed validation"):
        run_formal_confirmation_v2(impersonated)

    substituted_closure = fixture.closed_run_evidence.model_copy(
        update={"pre_generation_closure": foreign.pre_generation_closure}
    )
    with pytest.raises(ValueError, match="closed run evidence failed validation"):
        run_formal_confirmation_v2(substituted_closure)


def test_two_cluster_valid_draw_shortfall_is_non_evaluable_not_a_partial_family() -> None:
    fixture = _minimal_fixture()
    result = _inference_undefined_result()

    assert result.status is FormalConfirmationStatusV2.NON_EVALUABLE
    assert result.non_evaluable_reason is FormalNonEvaluableReasonV2.INFERENCE_UNDEFINED
    assert result.failed_family is MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
    assert result.expected_assignment_count == fixture.evidence.expected_assignment_count
    assert result.outcome_count == fixture.evidence.outcome_count
    assert result.terminal_failure_count == 0
    assert result.family_results == ()
    assert result.coordinate_decisions == ()
    assert result.complete_hypothesis_model_family_preserved is True


def test_terminal_infrastructure_failure_is_non_evaluable_before_inference() -> None:
    failing_evidence = _terminal_failure_closed_root().run_evidence
    result = _terminal_failure_result()

    assert result.status is FormalConfirmationStatusV2.NON_EVALUABLE
    assert result.non_evaluable_reason is FormalNonEvaluableReasonV2.TERMINAL_INFRASTRUCTURE_FAILURE
    assert result.failed_family is None
    assert result.expected_assignment_count == failing_evidence.expected_assignment_count
    assert result.outcome_count == failing_evidence.outcome_count
    assert result.terminal_failure_count == 1
    assert result.family_results == ()
    assert result.coordinate_decisions == ()


@pytest.mark.parametrize("delete", ("hypothesis", "model"))
def test_synchronized_hypothesis_or_model_deletion_cannot_shrink_the_h_by_m_family(
    delete: str,
) -> None:
    fixture = _minimal_fixture()
    attacked_experiment = _synchronized_incomplete_experiment(fixture, delete=delete)
    attacked_closure = fixture.pre_generation_closure.model_copy(
        update={"experiment_freeze": attacked_experiment}
    )
    attacked = fixture.closed_run_evidence.model_copy(
        update={"pre_generation_closure": attacked_closure}
    )

    with pytest.raises(ValueError, match="closed run evidence failed validation"):
        run_formal_confirmation_v2(attacked)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("outcome_name", "y_joint"),
        ("treatment_arm", ArmRole.GENERIC_SECURITY_REMINDER),
        ("control_arm", ArmRole.LENGTH_MATCHED_PLACEBO),
    ),
)
def test_outcome_or_arm_substitution_cannot_rewrite_a_frozen_family(
    field: str,
    replacement: object,
) -> None:
    protocol = FormalAnalysisProtocolV2.from_experiment(_minimal_fixture().experiment)
    plan = protocol.family_plans[0]
    coordinate = plan.family.coordinates[0]
    attacked_coordinate = coordinate.model_copy(update={field: replacement})
    attacked_family = plan.family.model_copy(
        update={
            "coordinates": (attacked_coordinate, *plan.family.coordinates[1:]),
        }
    )
    attacked_plan = plan.model_copy(update={"family": attacked_family})
    content = _without_protocol_id(protocol)
    content["family_plans"] = (attacked_plan, *protocol.family_plans[1:])

    with pytest.raises(ValidationError):
        FormalAnalysisProtocolV2.model_validate(
            {
                "schema_version": "2.0",
                "formal_analysis_protocol_id": protocol.formal_analysis_protocol_id,
                **content,
            },
            strict=True,
        )


def test_post_hoc_family_substitution_cannot_rewrite_the_frozen_protocol() -> None:
    protocol = FormalAnalysisProtocolV2.from_experiment(_minimal_fixture().experiment)
    plan = protocol.family_plans[0]
    attacked_plan = plan.model_copy(update={"formal_family": MultiSupportFormalFamilyV2.KEY_JOINT})
    content = _without_protocol_id(protocol)
    content["family_plans"] = (attacked_plan, *protocol.family_plans[1:])

    with pytest.raises(ValidationError):
        FormalAnalysisProtocolV2.model_validate(
            {
                "schema_version": "2.0",
                "formal_analysis_protocol_id": protocol.formal_analysis_protocol_id,
                **content,
            },
            strict=True,
        )


def test_fake_coverage_or_outcome_receipt_is_rejected_at_the_closed_root_boundary() -> None:
    fixture = _minimal_fixture()
    evidence = fixture.evidence
    accounting = evidence.total_assignment_accountings[0]
    coverage = accounting.confirmatory_coverage
    assert coverage is not None
    receipt = coverage.outcome_assembly_receipts[0]
    attacked_outcome = receipt.outcome.model_copy(
        update={"y_secure_yield": 1 - receipt.outcome.y_secure_yield}
    )
    attacked_receipt = receipt.model_copy(update={"outcome": attacked_outcome})
    attacked_coverage = coverage.model_copy(
        update={
            "outcome_assembly_receipts": (
                attacked_receipt,
                *coverage.outcome_assembly_receipts[1:],
            )
        }
    )
    attacked_accounting = accounting.model_copy(update={"confirmatory_coverage": attacked_coverage})
    attacked_evidence = evidence.model_copy(
        update={
            "total_assignment_accountings": (
                attacked_accounting,
                *evidence.total_assignment_accountings[1:],
            )
        }
    )

    attacked_closed = fixture.closed_run_evidence.model_copy(
        update={"run_evidence": attacked_evidence}
    )
    with pytest.raises(ValueError, match="closed run evidence failed validation"):
        run_formal_confirmation_v2(attacked_closed)

    attacked_provenance = coverage.model_copy(
        update={
            "provenance_closed_coverage_manifest_id": ("provenance_closed_coverage_v2_" + "f" * 64)
        }
    )
    provenance_accounting = accounting.model_copy(
        update={"confirmatory_coverage": attacked_provenance}
    )
    provenance_evidence = evidence.model_copy(
        update={
            "total_assignment_accountings": (
                provenance_accounting,
                *evidence.total_assignment_accountings[1:],
            )
        }
    )
    provenance_closed = fixture.closed_run_evidence.model_copy(
        update={"run_evidence": provenance_evidence}
    )
    with pytest.raises(ValueError, match="closed run evidence failed validation"):
        run_formal_confirmation_v2(provenance_closed)


def test_forged_result_cannot_survive_exact_replay() -> None:
    fixture = _minimal_fixture()
    genuine = _inference_undefined_result()
    forged = replace(
        genuine,
        status=FormalConfirmationStatusV2.EVALUATED,
        non_evaluable_reason=None,
        failed_family=None,
    )

    with pytest.raises(ValueError, match="result artifact failed validation"):
        validate_formal_confirmation_result_v2(
            fixture.closed_run_evidence,
            forged,
        )


def test_result_replay_binds_all_root_ids_and_rejects_replaced_closed_run_id() -> None:
    closed = _terminal_failure_closed_root()
    genuine = _terminal_failure_result()
    expected_ids = {
        "confirmatory_closed_run_evidence_id": (closed.confirmatory_closed_run_evidence_id),
        "confirmatory_pre_generation_closure_id": (
            closed.pre_generation_closure.confirmatory_pre_generation_closure_id
        ),
        "confirmatory_experiment_freeze_id": (
            closed.pre_generation_closure.experiment_freeze.confirmatory_experiment_freeze_id
        ),
        "confirmatory_run_evidence_manifest_id": (
            closed.run_evidence.confirmatory_run_evidence_manifest_id
        ),
    }
    assert {field: getattr(genuine, field) for field in expected_ids} == expected_ids

    forged_by_field = {
        field: replace(genuine, **{field: prefix + "f" * 64})
        for field, prefix in (
            ("confirmatory_closed_run_evidence_id", "confirmatory_closed_run_evidence_v2_"),
            (
                "confirmatory_pre_generation_closure_id",
                "confirmatory_pre_generation_closure_v2_",
            ),
            ("confirmatory_experiment_freeze_id", "confirmatory_experiment_freeze_v2_"),
            (
                "confirmatory_run_evidence_manifest_id",
                "confirmatory_run_evidence_v2_",
            ),
        )
    }
    for forged in forged_by_field.values():
        readdressed = formal_confirmation_module._content_address(forged)
        assert readdressed.formal_confirmation_result_id != (genuine.formal_confirmation_result_id)

    with pytest.raises(ValueError, match="result artifact failed validation"):
        validate_formal_confirmation_result_v2(
            closed,
            forged_by_field["confirmatory_closed_run_evidence_id"],
        )


def test_callers_cannot_supply_outcome_contrast_or_family_arguments() -> None:
    assert tuple(inspect.signature(run_formal_confirmation_v2).parameters) == (
        "closed_run_evidence",
    )
    assert tuple(inspect.signature(validate_formal_confirmation_result_v2).parameters) == (
        "closed_run_evidence",
        "result",
    )
    with pytest.raises(TypeError):
        run_formal_confirmation_v2(  # type: ignore[call-arg]
            object(),  # type: ignore[arg-type]
            outcome_name="y_joint",
        )
    with pytest.raises(TypeError):
        run_formal_confirmation_v2(  # type: ignore[call-arg]
            object(),  # type: ignore[arg-type]
            family="primary_secure_yield",
        )


def test_fast_paths_have_no_caller_selectable_prevalidated_switch() -> None:
    assert "inputs_prevalidated" not in inspect.signature(_derive).parameters
    assert "inputs_prevalidated" not in inspect.signature(_run).parameters
    assert tuple(inspect.signature(_derive_from_formal_context_v2).parameters) == (
        "context",
        "formal_family",
        "hypothesis_id",
        "model_id",
    )
    assert tuple(inspect.signature(_run_frozen_domain_from_formal_context_v2).parameters) == (
        "context",
        "formal_family",
    )


def test_direct_fast_calls_and_uninitialized_context_are_rejected() -> None:
    with pytest.raises(TypeError, match="only be created by the formal entry"):
        _ValidatedFormalContextV2()
    forged = object.__new__(_ValidatedFormalContextV2)
    with pytest.raises(ValueError, match="sealed formal context"):
        _derive_from_formal_context_v2(
            forged,
            formal_family=MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
            hypothesis_id="hypothesis.fake",
            model_id="model.fake",
        )
    with pytest.raises(ValueError, match="sealed formal context"):
        _run_frozen_domain_from_formal_context_v2(
            forged,
            MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
        )
    with pytest.raises(ValueError, match="only be created by the formal entry"):
        _ValidatedFormalContextV2._from_root(  # type: ignore[arg-type]
            object(),
            access=object(),
        )


def test_cross_evidence_context_mix_is_rejected_before_family_lookup() -> None:
    fixture = _minimal_fixture()
    context = _minimal_context()
    other_evidence, _accounting = _with_one_terminal_failure(fixture)
    attacked = _unsafe_context_clone(context, _evidence=other_evidence)

    with pytest.raises(ValueError, match="sealed formal context failed root validation"):
        _run_frozen_domain_from_formal_context_v2(
            attacked,
            MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
        )


def test_synchronously_rehashed_shrunk_plan_cannot_replace_context_plan() -> None:
    context = _minimal_context()
    first_binding = context._plan_bindings[0]
    plan = first_binding.plan
    attacked_family = plan.family.model_copy(update={"coordinates": (), "family_size": 0})
    attacked_plan = plan.model_copy(
        update={
            "formal_family": MultiSupportFormalFamilyV2.KEY_JOINT,
            "family": attacked_family,
            "coordinate_supports": (),
            "global_union_strata": (),
        }
    )
    attacked_plan = _synchronously_rehash_plan(attacked_plan)
    assert attacked_plan.inference_plan_id == (
        "multi_support_simultaneous_plan_v2_"
        + multi_support_schema_module._digest(
            attacked_plan.model_dump(mode="json", exclude={"inference_plan_id"})
        )
    )
    attacked_bindings = (
        replace(first_binding, plan=attacked_plan),
        *context._plan_bindings[1:],
    )
    attacked = _unsafe_context_clone(context, _plan_bindings=attacked_bindings)

    with pytest.raises(
        ValueError,
        match="deterministic plan registry|differs from its deterministic context plan",
    ):
        _run_frozen_domain_from_formal_context_v2(
            attacked,
            MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("outcome_name", "y_joint"),
        ("control_arm", ArmRole.LENGTH_MATCHED_PLACEBO),
    ),
)
def test_synchronously_rehashed_outcome_or_contrast_cannot_replace_context_plan(
    field: str,
    replacement: object,
) -> None:
    context = _minimal_context()
    first_binding = context._plan_bindings[0]
    plan = first_binding.plan
    coordinate = plan.family.coordinates[0]
    attacked_coordinate = coordinate.model_copy(update={field: replacement})
    attacked_family = plan.family.model_copy(update={"coordinates": (attacked_coordinate,)})
    attacked_plan = _synchronously_rehash_plan(plan.model_copy(update={"family": attacked_family}))
    attacked_bindings = (
        replace(first_binding, plan=attacked_plan),
        *context._plan_bindings[1:],
    )
    attacked = _unsafe_context_clone(context, _plan_bindings=attacked_bindings)

    with pytest.raises(ValueError, match="deterministic plan registry"):
        _run_frozen_domain_from_formal_context_v2(
            attacked,
            MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
        )


def test_fake_coverage_cannot_enter_fast_contribution_lookup() -> None:
    context = _minimal_context()
    first = context._input_bindings[0]
    receipt = first.coverage.outcome_assembly_receipts[0]
    attacked_outcome = receipt.outcome.model_copy(
        update={"y_secure_yield": 1 - receipt.outcome.y_secure_yield}
    )
    attacked_receipt = receipt.model_copy(update={"outcome": attacked_outcome})
    attacked_coverage = first.coverage.model_copy(
        update={
            "outcome_assembly_receipts": (
                attacked_receipt,
                *first.coverage.outcome_assembly_receipts[1:],
            )
        }
    )
    # Keep the stale coverage ID deliberately: the context lookup must compare
    # the exact evidence object rather than trusting that identifier alone.
    attacked_inputs = (
        replace(first, coverage=attacked_coverage),
        *context._input_bindings[1:],
    )
    attacked = _unsafe_context_clone(context, _input_bindings=attacked_inputs)

    with pytest.raises(ValueError, match="contribution input binding failed validation"):
        _derive_from_formal_context_v2(
            attacked,
            formal_family=first.formal_family,
            hypothesis_id=first.hypothesis_id,
            model_id=first.model_id,
        )


def test_incomplete_context_artifact_registry_is_rejected() -> None:
    context = _minimal_context()
    attacked = _unsafe_context_clone(
        context,
        _artifact_bindings=context._artifact_bindings[1:],
    )

    with pytest.raises(ValueError, match="artifact registry|deterministic plan registry"):
        _run_frozen_domain_from_formal_context_v2(
            attacked,
            MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
        )

from __future__ import annotations

import inspect
from dataclasses import replace
from functools import cache

import pytest
from pydantic import TypeAdapter, ValidationError

from secaware.analysis.formal_confirmation_v2 import (
    FormalConfirmationResultV2,
    run_formal_confirmation_v2,
    validate_formal_confirmation_result_v2,
)
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.experiments import ArmRole
from secaware.schema.formal_analysis_v2 import (
    FormalAnalysisProtocolV2,
    FormalConfirmationStatusV2,
    FormalNonEvaluableReasonV2,
)
from secaware.schema.multi_support_inference_v2 import MultiSupportFormalFamilyV2
from test_run_evidence_v2 import (
    RunEvidenceFixture,
    _fixture,
    _with_one_terminal_failure,
)


@cache
def _inference_undefined_result() -> FormalConfirmationResultV2:
    fixture = _fixture()
    return run_formal_confirmation_v2(fixture.experiment, fixture.evidence)


@cache
def _terminal_failure_result() -> FormalConfirmationResultV2:
    fixture = _fixture()
    failing_evidence, _accounting = _with_one_terminal_failure(fixture)
    return run_formal_confirmation_v2(fixture.experiment, failing_evidence)


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


def test_only_official_entry_derives_exactly_four_frozen_families_and_replays_json() -> None:
    fixture = _fixture()
    protocol = FormalAnalysisProtocolV2.from_experiment(fixture.experiment)

    assert tuple(inspect.signature(run_formal_confirmation_v2).parameters) == (
        "experiment_freeze",
        "run_evidence",
    )
    assert protocol.family_order == tuple(item.value for item in MultiSupportFormalFamilyV2)
    assert tuple(item.formal_family for item in protocol.family_plans) == tuple(
        MultiSupportFormalFamilyV2
    )
    assert all(
        item.family.family_size == fixture.experiment.hypothesis_model_coordinate_count
        for item in protocol.family_plans
    )
    assert (
        FormalAnalysisProtocolV2.model_validate_json(protocol.model_dump_json())
        == protocol
    )

    experiment_json = fixture.experiment.model_dump_json()
    evidence_json = fixture.evidence.model_dump_json()
    replayed_experiment = ConfirmatoryExperimentFreezeV2.model_validate_json(experiment_json)
    replayed_evidence = type(fixture.evidence).model_validate_json(evidence_json)
    result = _inference_undefined_result()
    replayed_result = TypeAdapter(FormalConfirmationResultV2).validate_json(
        TypeAdapter(FormalConfirmationResultV2).dump_json(result)
    )
    assert replayed_experiment == fixture.experiment
    assert replayed_evidence == fixture.evidence
    assert replayed_result == result
    assert (
        validate_formal_confirmation_result_v2(
            replayed_experiment,
            replayed_evidence,
            replayed_result,
        )
        == result
    )


def test_two_cluster_zero_se_is_explicitly_non_evaluable_not_a_partial_family() -> None:
    fixture = _fixture()
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
    fixture = _fixture()
    failing_evidence, _accounting = _with_one_terminal_failure(fixture)
    result = _terminal_failure_result()

    assert result.status is FormalConfirmationStatusV2.NON_EVALUABLE
    assert (
        result.non_evaluable_reason
        is FormalNonEvaluableReasonV2.TERMINAL_INFRASTRUCTURE_FAILURE
    )
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
    fixture = _fixture()
    attacked = _synchronized_incomplete_experiment(fixture, delete=delete)

    with pytest.raises(ValueError, match="confirmatory experiment freeze failed validation"):
        run_formal_confirmation_v2(attacked, fixture.evidence)


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
    protocol = FormalAnalysisProtocolV2.from_experiment(_fixture().experiment)
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


def test_fake_coverage_or_outcome_receipt_is_rejected_at_the_two_root_boundary() -> None:
    fixture = _fixture()
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
    attacked_accounting = accounting.model_copy(
        update={"confirmatory_coverage": attacked_coverage}
    )
    attacked_evidence = evidence.model_copy(
        update={
            "total_assignment_accountings": (
                attacked_accounting,
                *evidence.total_assignment_accountings[1:],
            )
        }
    )

    with pytest.raises(ValueError, match="confirmatory run evidence failed validation"):
        run_formal_confirmation_v2(fixture.experiment, attacked_evidence)


def test_forged_result_cannot_survive_exact_replay() -> None:
    fixture = _fixture()
    genuine = _inference_undefined_result()
    forged = replace(
        genuine,
        status=FormalConfirmationStatusV2.EVALUATED,
        non_evaluable_reason=None,
        failed_family=None,
    )

    with pytest.raises(ValueError, match="result artifact failed validation"):
        validate_formal_confirmation_result_v2(
            fixture.experiment,
            fixture.evidence,
            forged,
        )


def test_callers_cannot_supply_outcome_contrast_or_family_arguments() -> None:
    with pytest.raises(TypeError):
        run_formal_confirmation_v2(  # type: ignore[call-arg]
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            outcome_name="y_joint",
        )
    with pytest.raises(TypeError):
        run_formal_confirmation_v2(  # type: ignore[call-arg]
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            family="primary_secure_yield",
        )

from __future__ import annotations

import pytest
from pydantic import ValidationError

from m5_executor_fixtures import request
from secaware.errors import ErrorCode, SecAwareError
from secaware.outcomes.functional import validate_functional_outcomes
from secaware.schema.experiments import (
    AssignmentRecord,
    ExperimentalUnit,
    FeatureFamily,
    FunctionalOutcomeContractRecord,
)
from secaware.schema.outcomes import FunctionalOutcomeRecord, FunctionalOutcomeStatus


def _functional_outcome(
    *,
    assignment_id: str,
    contract_id: str,
    evaluator_policy_sha256: str,
    status: FunctionalOutcomeStatus,
    evidence_sha256: str,
) -> FunctionalOutcomeRecord:
    return FunctionalOutcomeRecord.from_content(
        assignment_id=assignment_id,
        contract_id=contract_id,
        evaluator_policy_sha256=evaluator_policy_sha256,
        status=status,
        evidence_sha256=evidence_sha256,
    )


def _functional_case():
    execution_request = request(FeatureFamily.TASK_FUNCTION, with_functional_contract=True)
    contract = execution_request.functional_contract
    assert contract is not None
    protocol = execution_request.protocol
    target = execution_request.target
    instance = execution_request.protocol_instance
    unit = ExperimentalUnit(
        task_id=instance.task_id,
        hypothesis_id=protocol.hypothesis_id,
        target_spec_id=target.target_spec_id,
        model_id=execution_request.hypothesis.model_id,
        seed_slot=0,
    )
    assignment = AssignmentRecord.from_content(
        block_id=AssignmentRecord.block_id_from_key(
            unit.task_id,
            unit.hypothesis_id,
            unit.target_spec_id,
            protocol.arm_protocol_id,
            unit.model_id,
        ),
        experimental_unit=unit,
        target_spec_id=target.target_spec_id,
        target_instance_id=execution_request.target_instance.target_instance_id,
        arm_protocol_id=protocol.arm_protocol_id,
        protocol_instance_id=instance.protocol_instance_id,
        variant_id="variant_" + "1" * 64,
        arm_role=execution_request.arm.role,
        seed_id=101,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256="2" * 64,
    )
    outcome = _functional_outcome(
        assignment_id=assignment.assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.PASS,
        evidence_sha256="3" * 64,
    )
    return assignment, protocol, contract, outcome


def test_functional_outcome_is_strict_frozen_content_addressed_and_text_free() -> None:
    _assignment, _protocol, contract, outcome = _functional_case()

    assert outcome.schema_version == "1.0"
    assert outcome.functional_outcome_id.startswith("functional_outcome_")
    assert repr(outcome) == "FunctionalOutcomeRecord()"
    assert str(outcome) == "FunctionalOutcomeRecord()"
    assert outcome.contract_id == contract.contract_id
    assert "contract_id" in outcome.model_dump(mode="json")
    assert "functional_outcome_contract_id" not in outcome.model_dump(mode="json")
    assert {"prompt", "code", "finding", "findings", "evidence"}.isdisjoint(
        FunctionalOutcomeRecord.model_fields
    )
    with pytest.raises(ValidationError):
        outcome.status = FunctionalOutcomeStatus.FAIL  # type: ignore[misc]


@pytest.mark.parametrize("status", tuple(FunctionalOutcomeStatus))
def test_functional_outcome_accepts_only_the_finite_status_contract(
    status: FunctionalOutcomeStatus,
) -> None:
    assignment, _protocol, contract, _outcome = _functional_case()
    record = FunctionalOutcomeRecord.from_content(
        assignment_id=assignment.assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=status,
        evidence_sha256="4" * 64,
    )
    assert record.status is status


def test_functional_outcome_id_binds_status_policy_and_evidence() -> None:
    assignment, _protocol, contract, outcome = _functional_case()
    changed = FunctionalOutcomeRecord.from_content(
        assignment_id=assignment.assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.UNKNOWN,
        evidence_sha256=outcome.evidence_sha256,
    )
    assert outcome.functional_outcome_id != changed.functional_outcome_id

    changed_contract = FunctionalOutcomeRecord.from_content(
        assignment_id=assignment.assignment_id,
        contract_id="functional_contract_" + "d" * 64,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=outcome.status,
        evidence_sha256=outcome.evidence_sha256,
    )
    assert outcome.functional_outcome_id != changed_contract.functional_outcome_id

    forged = outcome.model_copy(update={"evidence_sha256": "9" * 64})
    with pytest.raises(ValidationError):
        FunctionalOutcomeRecord.model_validate(forged)


@pytest.mark.parametrize(
    "mutation",
    ("missing", "extra", "duplicate", "contract", "policy"),
)
def test_independent_functional_outcomes_require_exact_preregistered_coverage(
    mutation: str,
) -> None:
    assignment, protocol, contract, outcome = _functional_case()
    assignments = (assignment,)
    protocols = (protocol,)
    contracts = (contract,)
    outcomes = (outcome,)
    if mutation == "missing":
        outcomes = ()
    elif mutation == "extra":
        other = FunctionalOutcomeRecord.from_content(
            assignment_id="assignment_" + "f" * 64,
            contract_id=contract.contract_id,
            evaluator_policy_sha256=contract.evaluator_policy_sha256,
            status=FunctionalOutcomeStatus.UNKNOWN,
            evidence_sha256="5" * 64,
        )
        outcomes = (outcome, other)
    elif mutation == "duplicate":
        outcomes = (outcome, outcome)
    elif mutation == "contract":
        outcomes = (
            FunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id="functional_contract_" + "e" * 64,
                evaluator_policy_sha256=contract.evaluator_policy_sha256,
                status=outcome.status,
                evidence_sha256=outcome.evidence_sha256,
            ),
        )
    else:
        outcomes = (
            FunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256="e" * 64,
                status=outcome.status,
                evidence_sha256=outcome.evidence_sha256,
            ),
        )

    with pytest.raises(Exception):
        validate_functional_outcomes(assignments, protocols, contracts, outcomes)


def test_task_function_assignment_cannot_omit_protocol_contract_and_outcome_universe() -> None:
    assignment, _protocol, _contract, _outcome = _functional_case()

    with pytest.raises(SecAwareError) as captured:
        validate_functional_outcomes((assignment,), (), (), ())

    assert captured.value.code is ErrorCode.CONTRACT
    assert captured.value.stage == "functional_outcomes"


def test_non_task_protocol_does_not_require_or_accept_a_functional_record() -> None:
    assignment, _task_protocol, contract, outcome = _functional_case()
    safety_request = request(FeatureFamily.SAFETY_CONTROL)
    safety_protocol = safety_request.protocol
    unit = ExperimentalUnit(
        task_id=safety_request.protocol_instance.task_id,
        hypothesis_id=safety_protocol.hypothesis_id,
        target_spec_id=safety_request.target.target_spec_id,
        model_id=safety_request.hypothesis.model_id,
        seed_slot=0,
    )
    safety_assignment = AssignmentRecord.from_content(
        block_id=AssignmentRecord.block_id_from_key(
            unit.task_id,
            unit.hypothesis_id,
            unit.target_spec_id,
            safety_protocol.arm_protocol_id,
            unit.model_id,
        ),
        experimental_unit=unit,
        target_spec_id=safety_request.target.target_spec_id,
        target_instance_id=safety_request.target_instance.target_instance_id,
        arm_protocol_id=safety_protocol.arm_protocol_id,
        protocol_instance_id=safety_request.protocol_instance.protocol_instance_id,
        variant_id="variant_" + "8" * 64,
        arm_role=safety_request.arm.role,
        seed_id=101,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256="9" * 64,
    )

    assert validate_functional_outcomes((safety_assignment,), (safety_protocol,), (), ()) == ()
    assert validate_functional_outcomes((safety_assignment,), (), (), ()) == ()
    with pytest.raises(Exception):
        validate_functional_outcomes((safety_assignment,), (safety_protocol,), (contract,), ())
    extra = FunctionalOutcomeRecord.from_content(
        assignment_id=safety_assignment.assignment_id,
        contract_id=outcome.contract_id,
        evaluator_policy_sha256=outcome.evaluator_policy_sha256,
        status=outcome.status,
        evidence_sha256=outcome.evidence_sha256,
    )
    with pytest.raises(Exception):
        validate_functional_outcomes(
            (safety_assignment,), (safety_protocol,), (contract,), (extra,)
        )


def test_functional_outcome_rejects_unknown_fields_raw_evidence_and_invalid_hashes() -> None:
    assignment, _protocol, contract, _outcome = _functional_case()
    values = {
        "assignment_id": assignment.assignment_id,
        "contract_id": contract.contract_id,
        "evaluator_policy_sha256": contract.evaluator_policy_sha256,
        "status": FunctionalOutcomeStatus.PASS,
        "evidence_sha256": "3" * 64,
    }
    for update in (
        {"status": "skipped"},
        {"evaluator_policy_sha256": "A" * 64},
        {"evidence_sha256": "short"},
        {"evidence": "raw-secret"},
    ):
        payload = {**values, **update}
        with pytest.raises(ValidationError):
            FunctionalOutcomeRecord.from_content(**payload)

    with pytest.raises(ValidationError):
        FunctionalOutcomeRecord.from_content(
            **values,
            functional_outcome_contract_id=contract.contract_id,
        )


def test_contract_registry_rejects_duplicate_and_unreferenced_records() -> None:
    assignment, protocol, contract, outcome = _functional_case()
    duplicate_contract = FunctionalOutcomeContractRecord.model_validate(
        contract.model_dump(mode="python")
    )
    with pytest.raises(Exception):
        validate_functional_outcomes(
            (assignment,), (protocol,), (contract, duplicate_contract), (outcome,)
        )

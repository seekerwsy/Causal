"""Exact, fail-closed assembly of randomized assignment outcome rows."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypeVar

from pydantic import BaseModel

from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.schema import (
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.functional_judge.validation import validate_program_functional_outcomes
from secaware.outcomes.functional import validate_functional_outcomes
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
    GraphDeltaRecord,
)
from secaware.schema.oracle import OracleEvaluability, OracleRecord, SecurityLabel
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
    FunctionalOutcomeRecord,
    FunctionalOutcomeStatus,
)


_ModelT = TypeVar("_ModelT", bound=BaseModel)
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)


def _error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="assemble_assignment_outcomes",
        message="assignment outcome relation failed validation",
        details={},
        retryable=False,
    )


def _trusted_tuple(values: Iterable[_ModelT], model: type[_ModelT]) -> tuple[_ModelT, ...]:
    records: list[_ModelT] = []
    result: tuple[_ModelT, ...] = ()
    value: object = None
    failed = False
    try:
        if isinstance(values, (str, bytes, Mapping)):
            raise TypeError
        for index, value in enumerate(values):
            if index >= 100_000 or type(value) is not model or not model_shape_is_intact(value):
                raise ValueError
            records.append(
                model.model_validate(
                    value.model_dump(mode="python", round_trip=True, warnings=False)
                )
            )
            value = None
        result = tuple(records)
    except _FATAL:
        raise
    except Exception:
        failed = True
    finally:
        values = ()
        model = BaseModel  # type: ignore[assignment]
        records.clear()
        value = None
    if failed:
        raise _error() from None
    return result


def _unique(records: tuple[_ModelT, ...], field: str) -> dict[str, _ModelT]:
    result: dict[str, _ModelT] = {}
    for record in records:
        key = getattr(record, field)
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = record
    return result


def _delta_key(record: AssignmentRecord | GraphDeltaRecord) -> tuple[object, ...]:
    return (
        record.target_spec_id,
        record.target_instance_id,
        record.arm_protocol_id,
        record.protocol_instance_id,
        record.arm_role,
    )


def _record_sha256(record: BaseModel) -> str:
    return canonical_sha256(record.model_dump(mode="json"))


def _source_digest(
    assignment: AssignmentRecord,
    execution: AssignmentExecutionRecord,
    oracle: OracleRecord | None,
    delta: GraphDeltaRecord,
    protocol: ConfirmationProtocolRecord | None,
    contract: FunctionalOutcomeContractRecord | None,
    functional: FunctionalOutcomeRecord | None,
    task_contract: TaskFunctionalContractRecord | None,
    program_functional: ProgramFunctionalOutcomeRecord | None,
) -> str:
    digests = {
        "assignment_record": _record_sha256(assignment),
        "execution_record": _record_sha256(execution),
        "graph_delta_record": _record_sha256(delta),
        "oracle_record": (
            _record_sha256(oracle)
            if oracle is not None
            else canonical_sha256({"state": "terminal_no_code", "version": "v1"})
        ),
    }
    if protocol is not None:
        digests["confirmation_protocol_record"] = _record_sha256(protocol)
    if contract is not None:
        digests["functional_contract_record"] = _record_sha256(contract)
    if functional is not None:
        digests["functional_outcome_record"] = _record_sha256(functional)
    if task_contract is not None:
        digests["task_functional_contract_record"] = _record_sha256(task_contract)
    if program_functional is not None:
        digests["program_functional_outcome_record"] = _record_sha256(program_functional)
    return canonical_sha256({key: digests[key] for key in sorted(digests)})


def assemble_assignment_outcomes(
    assignments: Iterable[AssignmentRecord],
    executions: Iterable[AssignmentExecutionRecord],
    oracles: Iterable[OracleRecord],
    graph_deltas: Iterable[GraphDeltaRecord],
    *,
    protocols: Iterable[ConfirmationProtocolRecord] = (),
    functional_contracts: Iterable[FunctionalOutcomeContractRecord] = (),
    functional_outcomes: Iterable[FunctionalOutcomeRecord] = (),
    task_functional_contracts: Iterable[TaskFunctionalContractRecord] = (),
    program_functional_outcomes: Iterable[ProgramFunctionalOutcomeRecord] = (),
    program_functional_policy_sha256: str | None = None,
) -> tuple[AssignmentOutcomeRecord, ...]:
    """Join exact producer relations without filtering randomized ITT rows."""

    trusted_assignments: tuple[AssignmentRecord, ...] = ()
    trusted_executions: tuple[AssignmentExecutionRecord, ...] = ()
    trusted_oracles: tuple[OracleRecord, ...] = ()
    trusted_deltas: tuple[GraphDeltaRecord, ...] = ()
    trusted_protocols: tuple[ConfirmationProtocolRecord, ...] = ()
    trusted_contracts: tuple[FunctionalOutcomeContractRecord, ...] = ()
    trusted_functional: tuple[FunctionalOutcomeRecord, ...] = ()
    trusted_task_contracts: tuple[TaskFunctionalContractRecord, ...] = ()
    trusted_program_functional: tuple[ProgramFunctionalOutcomeRecord, ...] = ()
    rows: list[AssignmentOutcomeRecord] = []
    result: tuple[AssignmentOutcomeRecord, ...] = ()
    failed = False
    try:
        trusted_assignments = _trusted_tuple(assignments, AssignmentRecord)
        trusted_executions = _trusted_tuple(executions, AssignmentExecutionRecord)
        trusted_oracles = _trusted_tuple(oracles, OracleRecord)
        trusted_deltas = _trusted_tuple(graph_deltas, GraphDeltaRecord)
        trusted_protocols = _trusted_tuple(protocols, ConfirmationProtocolRecord)
        trusted_contracts = _trusted_tuple(functional_contracts, FunctionalOutcomeContractRecord)
        trusted_functional = _trusted_tuple(functional_outcomes, FunctionalOutcomeRecord)
        trusted_task_contracts = _trusted_tuple(
            task_functional_contracts, TaskFunctionalContractRecord
        )
        trusted_program_functional = _trusted_tuple(
            program_functional_outcomes, ProgramFunctionalOutcomeRecord
        )
        if not trusted_assignments:
            raise ValueError

        assignment_by_id = _unique(trusted_assignments, "assignment_id")
        execution_by_assignment = _unique(trusted_executions, "assignment_id")
        oracle_by_assignment = _unique(trusted_oracles, "assignment_id")
        protocol_by_id = _unique(trusted_protocols, "arm_protocol_id")
        contract_by_id = _unique(trusted_contracts, "contract_id")
        functional_by_assignment = _unique(trusted_functional, "assignment_id")
        task_contract_by_task = _unique(trusted_task_contracts, "task_id")
        program_functional_by_assignment = _unique(trusted_program_functional, "assignment_id")
        delta_by_key: dict[tuple[object, ...], GraphDeltaRecord] = {}
        for delta in trusted_deltas:
            key = _delta_key(delta)
            if key in delta_by_key:
                raise ValueError
            delta_by_key[key] = delta

        if set(execution_by_assignment) != set(assignment_by_id):
            raise ValueError
        generated = {
            assignment_id
            for assignment_id, execution in execution_by_assignment.items()
            if execution.status is AssignmentExecutionStatus.GENERATED
        }
        if set(oracle_by_assignment) != generated:
            raise ValueError
        if any(
            oracle.condition != "confirm_arm" or oracle.assignment_id is None
            for oracle in trusted_oracles
        ):
            raise ValueError
        expected_delta_keys = {_delta_key(item) for item in trusted_assignments}
        if set(delta_by_key) != expected_delta_keys:
            raise ValueError

        validated_functional = validate_functional_outcomes(
            trusted_assignments,
            trusted_protocols,
            trusted_contracts,
            trusted_functional,
        )
        if validated_functional != tuple(
            functional_by_assignment[key] for key in sorted(functional_by_assignment)
        ):
            raise ValueError
        if trusted_task_contracts or trusted_program_functional:
            if program_functional_policy_sha256 is None:
                raise ValueError
            validated_program_functional = validate_program_functional_outcomes(
                trusted_assignments,
                trusted_task_contracts,
                trusted_program_functional,
                evaluator_policy_sha256=program_functional_policy_sha256,
            )
            if validated_program_functional != tuple(
                program_functional_by_assignment[key]
                for key in sorted(program_functional_by_assignment)
            ):
                raise ValueError
        elif program_functional_policy_sha256 is not None:
            raise ValueError

        for assignment_id in sorted(assignment_by_id):
            assignment = assignment_by_id[assignment_id]
            execution = execution_by_assignment[assignment_id]
            oracle = oracle_by_assignment.get(assignment_id)
            delta = delta_by_key[_delta_key(assignment)]
            unit = assignment.experimental_unit
            protocol = protocol_by_id.get(assignment.arm_protocol_id)
            functional = functional_by_assignment.get(assignment_id)
            contract = (
                contract_by_id.get(functional.contract_id) if functional is not None else None
            )
            task_contract = task_contract_by_task.get(unit.task_id)
            program_functional = program_functional_by_assignment.get(assignment_id)
            if execution.status is AssignmentExecutionStatus.GENERATED:
                if oracle is None:
                    raise ValueError
                oracle_coordinates = (
                    (oracle.request_id, execution.request_id),
                    (oracle.code_id, execution.code_id),
                    (oracle.code_sha256, execution.code_sha256),
                    (oracle.assignment_id, assignment.assignment_id),
                    (oracle.hypothesis_id, unit.hypothesis_id),
                    (oracle.target_spec_id, assignment.target_spec_id),
                    (oracle.target_instance_id, assignment.target_instance_id),
                    (oracle.arm_protocol_id, assignment.arm_protocol_id),
                    (oracle.protocol_instance_id, assignment.protocol_instance_id),
                    (oracle.variant_id, assignment.variant_id),
                    (oracle.arm_role, assignment.arm_role),
                    (oracle.model_id, unit.model_id),
                    (oracle.seed_id, assignment.seed_id),
                )
                if any(actual != expected for actual, expected in oracle_coordinates):
                    raise ValueError
                cwe_outcome = CWESecurityOutcome(oracle.security_label.value)
                evaluability = AssignmentEvaluability(oracle.evaluability.value)
                parse_ok = oracle.parse_ok
                functional_status = (
                    program_functional.status if program_functional is not None else None
                )
                functional_ok = (
                    functional_status is FunctionalOutcomeStatus.PASS
                    if functional_status is not None
                    else oracle.functional_ok
                )
                primary = int(
                    parse_ok
                    and functional_ok
                    and oracle.security_label is SecurityLabel.SECURE
                    and oracle.evaluability is OracleEvaluability.EVALUABLE
                )
            else:
                if oracle is not None:
                    raise ValueError
                cwe_outcome = CWESecurityOutcome.UNKNOWN
                evaluability = AssignmentEvaluability.NOT_REQUIRED_NO_CODE
                parse_ok = False
                functional_ok = False
                functional_status = (
                    program_functional.status if program_functional is not None else None
                )
                primary = 0
            rows.append(
                AssignmentOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    task_id=unit.task_id,
                    hypothesis_id=unit.hypothesis_id,
                    target_spec_id=assignment.target_spec_id,
                    target_instance_id=assignment.target_instance_id,
                    arm_protocol_id=assignment.arm_protocol_id,
                    protocol_instance_id=assignment.protocol_instance_id,
                    variant_id=assignment.variant_id,
                    arm_role=assignment.arm_role,
                    model_id=unit.model_id,
                    seed_id=assignment.seed_id,
                    execution_status=execution.status,
                    secure_functional_success=primary,
                    cwe_security_outcome=cwe_outcome,
                    oracle_evaluability=evaluability,
                    parse_ok=parse_ok,
                    functional_ok=functional_ok,
                    functional_outcome_status=functional_status,
                    target_changed=delta.target_changed,
                    semantic_compliance=delta.semantic_compliance,
                    source_digests_sha256=_source_digest(
                        assignment,
                        execution,
                        oracle,
                        delta,
                        protocol,
                        contract,
                        functional,
                        task_contract,
                        program_functional,
                    ),
                )
            )
        result = tuple(rows)
    except _FATAL:
        raise
    except Exception:
        failed = True
    finally:
        assignments = ()
        executions = ()
        oracles = ()
        graph_deltas = ()
        protocols = ()
        functional_contracts = ()
        functional_outcomes = ()
        task_functional_contracts = ()
        program_functional_outcomes = ()
        program_functional_policy_sha256 = None
        trusted_assignments = ()
        trusted_executions = ()
        trusted_oracles = ()
        trusted_deltas = ()
        trusted_protocols = ()
        trusted_contracts = ()
        trusted_functional = ()
        trusted_task_contracts = ()
        trusted_program_functional = ()
        rows.clear()
        assignment_by_id = {}
        execution_by_assignment = {}
        oracle_by_assignment = {}
        protocol_by_id = {}
        contract_by_id = {}
        functional_by_assignment = {}
        task_contract_by_task = {}
        program_functional_by_assignment = {}
        delta_by_key = {}
        expected_delta_keys = set()
        generated = set()
        validated_functional = ()
        validated_program_functional = ()
        assignment = None
        execution = None
        oracle = None
        delta = None
        unit = None
        protocol = None
        contract = None
        functional = None
        task_contract = None
        program_functional = None
        functional_status = None
        oracle_coordinates = ()
    if failed:
        raise _error() from None
    return result


__all__ = ["assemble_assignment_outcomes"]

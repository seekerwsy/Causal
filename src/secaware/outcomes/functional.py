"""Exact closure checks for independently produced task-functional outcomes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypeVar

from pydantic import BaseModel

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ConfirmationProtocolRecord,
    FeatureFamily,
    FunctionalOutcomeContractRecord,
)
from secaware.schema.outcomes import FunctionalOutcomeRecord


_ModelT = TypeVar("_ModelT", bound=BaseModel)
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_TASK_FUNCTION_ARM_ROLES = frozenset(
    {
        ArmRole.TASK_TARGET,
        ArmRole.TASK_NOOP,
        ArmRole.TASK_LENGTH_PLACEBO,
        ArmRole.TASK_GENERIC_CONTROL,
    }
)


def _error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="functional_outcomes",
        message="functional outcome relation failed validation",
        details={},
        retryable=False,
    )


def _trusted_index(
    values: Iterable[_ModelT],
    model: type[_ModelT],
    field: str,
) -> dict[str, _ModelT]:
    records: dict[str, _ModelT] = {}
    value: object = None
    try:
        if isinstance(values, (str, bytes, Mapping)):
            raise TypeError
        for index, value in enumerate(values):
            if index >= 100_000 or type(value) is not model or not model_shape_is_intact(value):
                raise ValueError
            checked = model.model_validate(
                value.model_dump(mode="python", round_trip=True, warnings=False)
            )
            key = getattr(checked, field)
            if type(key) is not str or key in records:
                raise ValueError
            records[key] = checked
            value = None
        return records
    except _FATAL:
        raise
    except Exception:
        raise _error() from None
    finally:
        values = ()
        model = BaseModel  # type: ignore[assignment]
        field = ""
        value = None


def validate_functional_outcomes(
    assignments: Iterable[AssignmentRecord],
    protocols: Iterable[ConfirmationProtocolRecord],
    contracts: Iterable[FunctionalOutcomeContractRecord],
    outcomes: Iterable[FunctionalOutcomeRecord],
) -> tuple[FunctionalOutcomeRecord, ...]:
    """Validate exact task-protocol coverage without consulting prompts or security results."""

    assignment_by_id: dict[str, AssignmentRecord] = {}
    protocol_by_id: dict[str, ConfirmationProtocolRecord] = {}
    contract_by_id: dict[str, FunctionalOutcomeContractRecord] = {}
    outcome_by_assignment: dict[str, FunctionalOutcomeRecord] = {}
    result: tuple[FunctionalOutcomeRecord, ...] = ()
    try:
        assignment_by_id = _trusted_index(assignments, AssignmentRecord, "assignment_id")
        protocol_by_id = _trusted_index(protocols, ConfirmationProtocolRecord, "arm_protocol_id")
        contract_by_id = _trusted_index(
            contracts,
            FunctionalOutcomeContractRecord,
            "contract_id",
        )
        outcome_by_assignment = _trusted_index(
            outcomes,
            FunctionalOutcomeRecord,
            "assignment_id",
        )
        if not assignment_by_id:
            raise ValueError
        if not protocol_by_id:
            if (
                contract_by_id
                or outcome_by_assignment
                or any(
                    assignment.arm_role in _TASK_FUNCTION_ARM_ROLES
                    for assignment in assignment_by_id.values()
                )
            ):
                raise ValueError
            return ()

        referenced_contract_ids: set[str] = set()
        for protocol in protocol_by_id.values():
            contract_id = protocol.functional_outcome_contract_id
            is_task = protocol.feature_family is FeatureFamily.TASK_FUNCTION
            if is_task != (contract_id is not None):
                raise ValueError
            if contract_id is not None:
                referenced_contract_ids.add(contract_id)
        if set(contract_by_id) != referenced_contract_ids:
            raise ValueError

        required: dict[str, str] = {}
        for assignment_id, assignment in assignment_by_id.items():
            protocol = protocol_by_id.get(assignment.arm_protocol_id)
            if protocol is None:
                raise ValueError
            if (
                protocol.hypothesis_id != assignment.experimental_unit.hypothesis_id
                or protocol.target_spec_id != assignment.target_spec_id
                or assignment.arm_role not in protocol.arm_roles
            ):
                raise ValueError
            if protocol.feature_family is FeatureFamily.TASK_FUNCTION:
                contract_id = protocol.functional_outcome_contract_id
                if contract_id is None:
                    raise ValueError
                required[assignment_id] = contract_id
        if set(outcome_by_assignment) != set(required):
            raise ValueError

        for assignment_id, contract_id in required.items():
            outcome = outcome_by_assignment[assignment_id]
            contract = contract_by_id.get(contract_id)
            if (
                contract is None
                or outcome.contract_id != contract.contract_id
                or outcome.evaluator_policy_sha256 != contract.evaluator_policy_sha256
            ):
                raise ValueError
        result = tuple(outcome_by_assignment[key] for key in sorted(outcome_by_assignment))
    except _FATAL:
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None
    finally:
        assignments = ()
        protocols = ()
        contracts = ()
        outcomes = ()
        assignment_by_id = {}
        protocol_by_id = {}
        contract_by_id = {}
        outcome_by_assignment = {}
        referenced_contract_ids = set()
        required = {}
        assignment = None
        protocol = None
        contract = None
        outcome = None
    return result


__all__ = ["validate_functional_outcomes"]

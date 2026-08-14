"""Exact relation checks for task contracts and program-functional outcomes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypeVar

from pydantic import BaseModel

from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.schema import (
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import AssignmentRecord

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="functional_judge",
        message="program functional outcome relation failed validation",
        retryable=False,
    )


def _index(values: Iterable[_ModelT], model: type[_ModelT], field: str) -> dict[str, _ModelT]:
    if isinstance(values, (str, bytes, Mapping)):
        raise _error() from None
    result: dict[str, _ModelT] = {}
    try:
        for index, value in enumerate(values):
            if index >= 100_000 or type(value) is not model or not model_shape_is_intact(value):
                raise ValueError
            checked = model.model_validate(
                value.model_dump(mode="python", round_trip=True, warnings=False)
            )
            key = getattr(checked, field)
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = checked
        return result
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None


def validate_program_functional_outcomes(
    assignments: Iterable[AssignmentRecord],
    contracts: Iterable[TaskFunctionalContractRecord],
    outcomes: Iterable[ProgramFunctionalOutcomeRecord],
    *,
    evaluator_policy_sha256: str,
) -> tuple[ProgramFunctionalOutcomeRecord, ...]:
    """Require one pre-treatment contract per task and one result per assignment."""

    try:
        assignment_by_id = _index(assignments, AssignmentRecord, "assignment_id")
        contract_by_task = _index(contracts, TaskFunctionalContractRecord, "task_id")
        outcome_by_assignment = _index(outcomes, ProgramFunctionalOutcomeRecord, "assignment_id")
        if not assignment_by_id or set(outcome_by_assignment) != set(assignment_by_id):
            raise ValueError
        task_ids = {item.experimental_unit.task_id for item in assignment_by_id.values()}
        if set(contract_by_task) != task_ids:
            raise ValueError
        contract_by_id = {item.contract_id: item for item in contract_by_task.values()}
        if len(contract_by_id) != len(contract_by_task):
            raise ValueError
        for assignment_id, assignment in assignment_by_id.items():
            contract = contract_by_task[assignment.experimental_unit.task_id]
            outcome = outcome_by_assignment[assignment_id]
            if (
                outcome.contract_id != contract.contract_id
                or outcome.evaluator_policy_sha256 != evaluator_policy_sha256
            ):
                raise ValueError
        return tuple(outcome_by_assignment[key] for key in sorted(outcome_by_assignment))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None


__all__ = ["validate_program_functional_outcomes"]

"""Exact, assignment-bound confirmation generation execution."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
)
from secaware.schema.generation import (
    GenerationProvenance,
    GenerationRequestRecord,
    revalidate_generation_request_envelope,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord


MAX_CONFIRMATION_REQUESTS = 100_000
MAX_CONFIRMATION_CODE_BYTES = 1_048_576
MAX_CONFIRMATION_TOTAL_CODE_BYTES = 1_000_000_000


def _error(message: str, *, code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(code=code, stage="generate-confirmation", message=message)


def _trusted_requests(
    values: Iterable[GenerationRequestRecord],
) -> tuple[GenerationRequestRecord, ...]:
    try:
        result = tuple(
            revalidate_generation_request_envelope(item)
            for item in islice(values, MAX_CONFIRMATION_REQUESTS + 1)
        )
        if not result or len(result) > MAX_CONFIRMATION_REQUESTS:
            raise ValueError
        if any(item.condition != "confirm_arm" for item in result):
            raise ValueError
        if len({item.request_id for item in result}) != len(result) or len(
            {item.assignment_id for item in result}
        ) != len(result):
            raise ValueError
        return tuple(sorted(result, key=lambda item: (item.assignment_id or "", item.request_id)))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("confirmation request ledger failed validation") from None


def _provider_outputs(
    requests: tuple[GenerationRequestRecord, ...], provider: object
) -> tuple[tuple[str, object], ...]:
    try:
        generate_many = getattr(provider, "generate_many", None)
        if callable(generate_many):
            raw = generate_many(requests)
            values = tuple(islice(raw, MAX_CONFIRMATION_REQUESTS + 1))
        else:
            generate = getattr(provider, "generate", None)
            if not callable(generate):
                raise TypeError
            values = tuple((item.request_id, generate(item)) for item in requests)
        if len(values) > MAX_CONFIRMATION_REQUESTS:
            raise ValueError
        checked: list[tuple[str, object]] = []
        for value in values:
            if type(value) not in {tuple, list} or len(value) != 2 or type(value[0]) is not str:
                raise ValueError
            checked.append((value[0], value[1]))
        return tuple(checked)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("confirmation provider infrastructure failure", code=ErrorCode.API_INVALID_RESPONSE) from None


def execute_confirmation_requests(
    requests: Iterable[GenerationRequestRecord],
    provider: object,
) -> tuple[tuple[AssignmentExecutionRecord, ...], tuple[CanonicalGeneratedCodeRecord, ...]]:
    """Execute all requests and require one terminal record for each assignment."""

    trusted = _trusted_requests(requests)
    by_request = {item.request_id: item for item in trusted}
    outputs = _provider_outputs(trusted, provider)
    output_ids = tuple(item[0] for item in outputs)
    if len(output_ids) != len(set(output_ids)) or set(output_ids) != set(by_request):
        raise _error("confirmation provider coverage failed validation")
    executions: list[AssignmentExecutionRecord] = []
    codes: list[CanonicalGeneratedCodeRecord] = []
    total_code_bytes = 0
    try:
        for request_id, raw_result in outputs:
            request = by_request[request_id]
            finish_reason = getattr(raw_result, "finish_reason", None)
            code = getattr(raw_result, "code", None)
            if finish_reason == "content_filter":
                if code is not None:
                    raise ValueError
                executions.append(
                    AssignmentExecutionRecord.from_content(
                        assignment_id=request.assignment_id,
                        request_id=request.request_id,
                        status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
                        code_id=None,
                        terminal_reason="content_filter",
                    )
                )
                continue
            if finish_reason != "stop" or type(code) is not str or not code.strip():
                raise ValueError
            code_bytes = len(code.encode("utf-8"))
            total_code_bytes += code_bytes
            if (
                code_bytes > MAX_CONFIRMATION_CODE_BYTES
                or total_code_bytes > MAX_CONFIRMATION_TOTAL_CODE_BYTES
            ):
                raise ValueError
            provenance = getattr(raw_result, "provenance", None)
            provenance = GenerationProvenance.model_validate(provenance)
            canonical = canonical_generated_code_from_request(request, code, provenance)
            codes.append(canonical)
            executions.append(
                AssignmentExecutionRecord.from_content(
                    assignment_id=request.assignment_id,
                    request_id=request.request_id,
                    status=AssignmentExecutionStatus.GENERATED,
                    code_id=canonical.code_id,
                    terminal_reason=None,
                )
            )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("confirmation provider result failed validation") from None
    ordered_executions = tuple(sorted(executions, key=lambda item: item.assignment_id))
    ordered_codes = tuple(sorted(codes, key=lambda item: item.assignment_id or ""))
    if (
        {item.assignment_id for item in ordered_executions}
        != {item.assignment_id for item in trusted}
        or {item.assignment_id for item in ordered_codes}
        != {
            item.assignment_id
            for item in ordered_executions
            if item.status is AssignmentExecutionStatus.GENERATED
        }
    ):
        raise _error("confirmation execution coverage failed validation")
    return ordered_executions, ordered_codes


__all__ = [
    "MAX_CONFIRMATION_CODE_BYTES",
    "MAX_CONFIRMATION_REQUESTS",
    "MAX_CONFIRMATION_TOTAL_CODE_BYTES",
    "execute_confirmation_requests",
]

"""Exact, assignment-bound confirmation generation execution."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
import hashlib
from itertools import islice
import json

from secaware.config import GenerationConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
)
from secaware.schema.generation import (
    GenerationRequestRecord,
    ProviderResultEnvelope,
    provider_provenance_sha256,
    provider_usage_sha256,
    revalidate_generation_request_envelope,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord


MAX_CONFIRMATION_REQUESTS = 100_000
MAX_CONFIRMATION_CODE_BYTES = 1_048_576
MAX_CONFIRMATION_TOTAL_CODE_BYTES = 1_000_000_000
CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256 = hashlib.sha256(
    b"secaware-confirmation-provider-result-envelope-v1"
).hexdigest()
_JSONL_STAGE_LIMIT_BYTES = 256 * 1024 * 1024
_JSONL_SAFETY_MARGIN_BYTES = 16 * 1024 * 1024
_CODE_RECORD_OVERHEAD_BYTES = 12 * 1024
_EXECUTION_RECORD_OVERHEAD_BYTES = 4 * 1024
_MAX_JSON_STRING_EXPANSION = 6
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_PROVIDER_ERROR_CODES = frozenset(
    {
        ErrorCode.API_AUTH,
        ErrorCode.API_RATE_LIMIT,
        ErrorCode.API_TIMEOUT,
        ErrorCode.API_RETRIES_EXHAUSTED,
        ErrorCode.API_INVALID_RESPONSE,
        ErrorCode.CONFIG,
        ErrorCode.CONTRACT,
    }
)


def _error(message: str, *, code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(code=code, stage="generate-confirmation", message=message)


def _trusted_requests(
    values: Iterable[GenerationRequestRecord],
    config: GenerationConfig,
) -> tuple[GenerationRequestRecord, ...]:
    snapshots: list[GenerationRequestRecord] = []
    result: tuple[GenerationRequestRecord, ...] | None = None
    value: object = None
    iterator: Iterator[GenerationRequestRecord] | None = None
    cleanup: BaseException | None = None
    active: BaseException | None = None
    try:
        iterator = iter(values)
        for value in islice(iterator, config.confirmation_max_requests + 1):
            snapshots.append(revalidate_generation_request_envelope(value))
        if not snapshots or len(snapshots) > config.confirmation_max_requests:
            raise ValueError
        if any(item.condition != "confirm_arm" for item in snapshots):
            raise ValueError
        if len({item.request_id for item in snapshots}) != len(snapshots) or len(
            {item.assignment_id for item in snapshots}
        ) != len(snapshots):
            raise ValueError
        result = tuple(
            sorted(snapshots, key=lambda item: (item.assignment_id or "", item.request_id))
        )
    except BaseException as error:
        active = error
    finally:
        if iterator is not None:
            cleanup = _close_iterator(iterator)
        values = ()
        config = None  # type: ignore[assignment]
        snapshots.clear()
        value = None
        iterator = None
    if active is not None:
        if isinstance(active, _FATAL):
            if cleanup is not None:
                _clear_exception(cleanup)
            raise active
        _clear_exception(active)
        active = None
        if isinstance(cleanup, _FATAL):
            raise cleanup
        if cleanup is not None:
            _clear_exception(cleanup)
        raise _error("confirmation request ledger failed validation") from None
    if cleanup is not None:
        if isinstance(cleanup, _FATAL):
            raise cleanup
        _clear_exception(cleanup)
        raise _error("confirmation request ledger failed validation") from None
    if result is None:  # pragma: no cover
        raise _error("confirmation request ledger failed validation")
    return result


def _parameter_bytes(values: Mapping[str, object]) -> int:
    return len(
        json.dumps(
            values,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _serialized_request_bytes(request: GenerationRequestRecord) -> int:
    payload: dict[str, object] = {}
    try:
        payload = request.model_dump(mode="json", warnings=False)
        return len(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
    finally:
        request = None  # type: ignore[assignment]
        payload.clear()


def _preflight_resources(
    requests: tuple[GenerationRequestRecord, ...], config: GenerationConfig
) -> None:
    total_prompt_bytes = 0
    total_request_bytes = 0
    try:
        for request in requests:
            prompt_bytes = len(request.prompt.encode("utf-8"))
            total_prompt_bytes += prompt_bytes
            total_request_bytes += _serialized_request_bytes(request)
            if prompt_bytes > config.confirmation_max_prompt_bytes_per_request:
                raise ValueError
            parameters = request.parameters.model_dump(mode="json", warnings=False)["values"]
            if _parameter_bytes(parameters) > config.confirmation_max_parameters_bytes:
                raise ValueError
            token_values = [
                parameters[key]
                for key in ("max_tokens", "max_completion_tokens", "max_output_tokens")
                if key in parameters
            ]
            if len(token_values) != 1 or any(
                type(value) is not int
                or not 1 <= value <= config.confirmation_max_tokens_per_request
                for value in token_values
            ):
                raise ValueError
            stop = parameters.get("stop")
            stop_values: Sequence[object] = ()
            if type(stop) is str:
                stop_values = (stop,)
            elif isinstance(stop, Sequence) and not isinstance(stop, (str, bytes)):
                stop_values = stop
            if stop_values and (
                len(stop_values) > config.confirmation_max_stop_items
                or any(
                    type(item) is not str or len(item) > config.confirmation_max_stop_item_chars
                    for item in stop_values
                )
                or sum(len(item) for item in stop_values) > config.confirmation_max_stop_total_chars
            ):
                raise ValueError
        if total_prompt_bytes > config.confirmation_max_total_prompt_bytes:
            raise ValueError
        if (
            len(requests) * config.confirmation_max_attempts_per_request
            > config.confirmation_max_total_provider_attempts
        ):
            raise ValueError
        provider = config.openai_compatible
        if provider is not None:
            per_request_wait = provider.max_attempts * provider.timeout_seconds + sum(
                min(
                    provider.initial_backoff_seconds * (2**index),
                    provider.max_backoff_seconds,
                )
                for index in range(max(0, provider.max_attempts - 1))
            )
            if len(requests) * per_request_wait > config.confirmation_max_worst_case_wait_seconds:
                raise ValueError
        projected_code = min(
            len(requests) * config.confirmation_max_code_bytes_per_result,
            config.confirmation_max_total_code_bytes,
        )
        request_ledger_bytes = total_request_bytes + len(requests)
        code_ledger_bytes = (
            total_request_bytes
            + _MAX_JSON_STRING_EXPANSION * projected_code
            + len(requests) * (_CODE_RECORD_OVERHEAD_BYTES + 1)
        )
        execution_ledger_bytes = len(requests) * (_EXECUTION_RECORD_OVERHEAD_BYTES + 1)
        projected = request_ledger_bytes + code_ledger_bytes + execution_ledger_bytes
        hard_limit = _JSONL_STAGE_LIMIT_BYTES - _JSONL_SAFETY_MARGIN_BYTES
        if (
            any(
                value >= hard_limit
                for value in (
                    request_ledger_bytes,
                    code_ledger_bytes,
                    execution_ledger_bytes,
                    projected,
                )
            )
            or projected >= config.confirmation_max_projected_jsonl_bytes
        ):
            raise ValueError
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation generation resource contract failed validation") from None
    finally:
        requests = ()
        config = None  # type: ignore[assignment]
        request = None  # type: ignore[assignment]
        total_prompt_bytes = 0
        total_request_bytes = 0
        parameters = {}
        token_values = []
        stop_values = ()
        request_ledger_bytes = 0
        code_ledger_bytes = 0
        execution_ledger_bytes = 0
        projected = 0
        hard_limit = 0


def _clear_exception(error: BaseException) -> None:
    try:
        error.__traceback__ = None
        error.__cause__ = None
        error.__context__ = None
    except Exception:
        pass


def _safe_provider_failure(error: SecAwareError) -> tuple[ErrorCode, bool]:
    code = error.code if error.code in _PROVIDER_ERROR_CODES else ErrorCode.API_INVALID_RESPONSE
    retryable = bool(error.retryable) if type(error.retryable) is bool else False
    _clear_exception(error)
    return code, retryable


def _close_iterator(iterator: object) -> BaseException | None:
    cleanup: BaseException | None = None
    close: object = None
    try:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()
    except BaseException as error:
        cleanup = error
    finally:
        iterator = None
        close = None
    return cleanup


def _provider_result(request: GenerationRequestRecord, provider: object) -> ProviderResultEnvelope:
    iterator: Iterator[object] | None = None
    raw: object = None
    first: object = None
    second: object = None
    active: BaseException | None = None
    cleanup: BaseException | None = None
    provider_code: ErrorCode | None = None
    provider_retryable = False
    result: ProviderResultEnvelope | None = None
    sentinel = object()
    generate_many: object = None
    generate: object = None
    response_request_id: object = None
    envelope: object = None
    try:
        generate_many = getattr(provider, "generate_many", None)
        if callable(generate_many):
            raw = generate_many((request,))
            iterator = iter(raw)
            first = next(iterator)
            second = next(iterator, sentinel)
            if second is not sentinel:
                raise ValueError
            if type(first) not in {tuple, list} or len(first) != 2:
                raise ValueError
            response_request_id, envelope = first
        else:
            generate = getattr(provider, "generate", None)
            if not callable(generate):
                raise TypeError
            response_request_id = request.request_id
            envelope = generate(request)
        if (
            response_request_id != request.request_id
            or type(envelope) is not ProviderResultEnvelope
        ):
            raise ValueError
        result = ProviderResultEnvelope.model_validate(
            envelope.model_dump(mode="python", round_trip=True, warnings=False)
        )
        if (
            result.request_id != request.request_id
            or result.model_id != request.model_id
            or result.provider_policy_sha256 != CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256
        ):
            raise ValueError
    except BaseException as error:
        active = error
    finally:
        if iterator is not None:
            cleanup = _close_iterator(iterator)
        iterator = None
        raw = None
        first = None
        second = None
        provider = None
        request = None  # type: ignore[assignment]
        generate_many = None
        generate = None
        response_request_id = None
        envelope = None
    if active is not None:
        if isinstance(active, _FATAL):
            if cleanup is not None:
                _clear_exception(cleanup)
            raise active
        if isinstance(active, SecAwareError):
            provider_code, provider_retryable = _safe_provider_failure(active)
        _clear_exception(active)
        active = None
    if cleanup is not None:
        if isinstance(cleanup, _FATAL):
            raise cleanup
        _clear_exception(cleanup)
        cleanup = None
        if provider_code is None:
            provider_code = ErrorCode.API_INVALID_RESPONSE
    if provider_code is not None:
        raise SecAwareError(
            code=provider_code,
            stage="generate-confirmation",
            message="confirmation provider request failed",
            details={"retryable": provider_retryable},
            retryable=provider_retryable,
        ) from None
    if result is None:
        raise _error(
            "confirmation provider infrastructure failure",
            code=ErrorCode.API_INVALID_RESPONSE,
        ) from None
    return result


def execute_confirmation_requests(
    requests: Iterable[GenerationRequestRecord],
    provider: object,
    config: GenerationConfig | None = None,
) -> tuple[tuple[AssignmentExecutionRecord, ...], tuple[CanonicalGeneratedCodeRecord, ...]]:
    """Execute all requests and require one terminal record for each assignment."""

    trusted_config: GenerationConfig | None = None
    trusted: tuple[GenerationRequestRecord, ...] = ()
    expected_assignment_ids: frozenset[str | None] = frozenset()
    executions: list[AssignmentExecutionRecord] = []
    codes: list[CanonicalGeneratedCodeRecord] = []
    ordered_executions: tuple[AssignmentExecutionRecord, ...] = ()
    ordered_codes: tuple[CanonicalGeneratedCodeRecord, ...] = ()
    result: (
        tuple[tuple[AssignmentExecutionRecord, ...], tuple[CanonicalGeneratedCodeRecord, ...]]
        | None
    ) = None
    total_code_bytes = 0
    total_provider_attempts = 0
    request: GenerationRequestRecord | None = None
    raw_result: ProviderResultEnvelope | None = None
    code: str | None = None
    canonical: CanonicalGeneratedCodeRecord | None = None
    provenance_sha256: str | None = None
    usage_sha256: str | None = None
    execution_coordinates: dict[str, object] = {}
    loop_failed = True
    try:
        trusted_config = (
            GenerationConfig() if config is None else GenerationConfig.model_validate(config)
        )
        trusted = _trusted_requests(requests, trusted_config)
        _preflight_resources(trusted, trusted_config)
        expected_assignment_ids = frozenset(item.assignment_id for item in trusted)
        for request in trusted:
            raw_result = _provider_result(request, provider)
            total_provider_attempts += len(raw_result.attempts)
            if (
                len(raw_result.attempts) > trusted_config.confirmation_max_attempts_per_request
                or total_provider_attempts > trusted_config.confirmation_max_total_provider_attempts
            ):
                raise ValueError
            code = raw_result.code
            provenance_sha256 = provider_provenance_sha256(raw_result.provenance)
            usage_sha256 = provider_usage_sha256(raw_result.usage)
            execution_coordinates = dict(
                provider_result_sha256=raw_result.result_sha256,
                provider_provenance_sha256=provenance_sha256,
                provider_runtime_sha256=raw_result.runtime_fingerprint_sha256,
                provider_policy_sha256=raw_result.provider_policy_sha256,
                usage_sha256=usage_sha256,
                attempt_count=len(raw_result.attempts),
            )
            if raw_result.finish_reason == "content_filter":
                executions.append(
                    AssignmentExecutionRecord.from_content(
                        assignment_id=request.assignment_id,
                        request_id=request.request_id,
                        status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
                        code_id=None,
                        code_sha256=None,
                        terminal_reason="content_filter",
                        **execution_coordinates,
                    )
                )
                continue
            if raw_result.finish_reason != "stop" or type(code) is not str or not code.strip():
                raise ValueError
            code_bytes = len(code.encode("utf-8"))
            total_code_bytes += code_bytes
            if (
                code_bytes > trusted_config.confirmation_max_code_bytes_per_result
                or total_code_bytes > trusted_config.confirmation_max_total_code_bytes
            ):
                raise ValueError
            canonical = canonical_generated_code_from_request(
                request,
                code,
                raw_result.provenance,
                provider_result_sha256=raw_result.result_sha256,
                provider_usage_sha256=usage_sha256,
                provider_runtime_sha256=raw_result.runtime_fingerprint_sha256,
                provider_policy_sha256=raw_result.provider_policy_sha256,
                provider_attempt_count=len(raw_result.attempts),
            )
            codes.append(canonical)
            executions.append(
                AssignmentExecutionRecord.from_content(
                    assignment_id=request.assignment_id,
                    request_id=request.request_id,
                    status=AssignmentExecutionStatus.GENERATED,
                    code_id=canonical.code_id,
                    code_sha256=canonical.code_sha256,
                    terminal_reason=None,
                    **execution_coordinates,
                )
            )
        ordered_executions = tuple(sorted(executions, key=lambda item: item.assignment_id))
        ordered_codes = tuple(sorted(codes, key=lambda item: item.assignment_id or ""))
        if {item.assignment_id for item in ordered_executions} != expected_assignment_ids or {
            item.assignment_id for item in ordered_codes
        } != {
            item.assignment_id
            for item in ordered_executions
            if item.status is AssignmentExecutionStatus.GENERATED
        }:
            raise ValueError
        result = ordered_executions, ordered_codes
        loop_failed = False
    except _FATAL:
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("confirmation provider result failed validation") from None
    finally:
        requests = ()
        provider = None
        config = None
        trusted_config = None
        trusted = ()
        expected_assignment_ids = frozenset()
        request = None
        raw_result = None
        code = None
        canonical = None
        provenance_sha256 = None
        usage_sha256 = None
        execution_coordinates = {}
        ordered_executions = ()
        ordered_codes = ()
        total_code_bytes = 0
        total_provider_attempts = 0
        if loop_failed:
            executions.clear()
            codes.clear()
    if result is None:  # pragma: no cover
        raise _error("confirmation execution coverage failed validation")
    return result


__all__ = [
    "MAX_CONFIRMATION_CODE_BYTES",
    "MAX_CONFIRMATION_REQUESTS",
    "MAX_CONFIRMATION_TOTAL_CODE_BYTES",
    "execute_confirmation_requests",
]

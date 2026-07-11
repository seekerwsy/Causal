from collections.abc import Callable, Iterable
from itertools import islice
from typing import TypeVar

from secaware.errors import ErrorCode, JSONValue, SecAwareError
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GenerationProvenance,
    GenerationRequestRecord,
    OfflineGenerationResultRecord,
    generation_request_envelopes_match,
    revalidate_generation_request_envelope,
    revalidate_offline_generation_result,
    sha256_text,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord


MAX_OFFLINE_IMPORT_RECORDS = 100_000
_STAGE = "generation-result-importer"

_Input = TypeVar("_Input")
_Snapshot = TypeVar("_Snapshot")


def _import_error(
    code: ErrorCode,
    message: str,
    *,
    details: dict[str, JSONValue] | None = None,
    retryable: bool = False,
) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        details=details,
        retryable=retryable,
    )


def _bounded_snapshots(
    values: Iterable[_Input],
    *,
    invalid_message: str,
    limit_message: str,
    snapshot: Callable[[_Input], _Snapshot],
) -> list[_Snapshot]:
    snapshots: list[_Snapshot] = []
    exceeded = False
    try:
        for index, value in enumerate(islice(values, MAX_OFFLINE_IMPORT_RECORDS + 1)):
            if index == MAX_OFFLINE_IMPORT_RECORDS:
                exceeded = True
                break
            snapshots.append(snapshot(value))
    except Exception:
        pass
    else:
        if not exceeded:
            return snapshots
        raise _import_error(ErrorCode.CONTRACT, limit_message)
    raise _import_error(ErrorCode.CONTRACT, invalid_message)


def _expected_snapshot(value: object) -> GenerationRequestRecord:
    if type(value) is not GenerationRequestRecord:
        raise TypeError("unexpected expected generation request")
    return revalidate_generation_request_envelope(value)


def _received_snapshot(value: object) -> OfflineGenerationResultRecord:
    return revalidate_offline_generation_result(value)


def _validated_expected(
    values: Iterable[GenerationRequestRecord],
) -> list[GenerationRequestRecord]:
    expected = _bounded_snapshots(
        values,
        invalid_message="offline generation expected ledger failed validation",
        limit_message="offline generation expected ledger exceeds the safety limit",
        snapshot=_expected_snapshot,
    )
    if not expected:
        raise _import_error(
            ErrorCode.CONTRACT,
            "offline generation expected ledger must not be empty",
        )
    if any(request.endpoint_type != "offline" for request in expected):
        raise _import_error(
            ErrorCode.CONTRACT,
            "offline generation expected ledger contains a non-offline request",
        )
    request_ids = [request.request_id for request in expected]
    if len(set(request_ids)) != len(request_ids):
        raise _import_error(
            ErrorCode.CONTRACT,
            "offline generation expected request ids must be unique",
        )
    return expected


def _validated_received(
    values: Iterable[OfflineGenerationResultRecord],
) -> list[OfflineGenerationResultRecord]:
    return _bounded_snapshots(
        values,
        invalid_message="offline generation result schema validation failed",
        limit_message="offline generation result collection exceeds the safety limit",
        snapshot=_received_snapshot,
    )


def _ensure_matching_envelopes(
    expected_by_id: dict[str, GenerationRequestRecord],
    received: list[OfflineGenerationResultRecord],
) -> None:
    mismatch = False
    try:
        for result in received:
            if not generation_request_envelopes_match(
                expected_by_id[result.request_id],
                result,
            ):
                mismatch = True
                break
    except Exception:
        pass
    else:
        if not mismatch:
            return
    raise _import_error(
        ErrorCode.CONTRACT,
        "offline generation result request envelope mismatch",
    )


def canonical_generated_code_from_request(
    request: GenerationRequestRecord,
    code: str,
    provenance: GenerationProvenance,
) -> CanonicalGeneratedCodeRecord:
    """Build the canonical metadata bridge for any validated generation producer."""

    trusted_request: GenerationRequestRecord | None = None
    trusted_provenance: GenerationProvenance | None = None
    try:
        trusted_request = revalidate_generation_request_envelope(request)
        trusted_provenance = GenerationProvenance.model_validate(provenance)
        if type(code) is not str or not code.strip():
            raise ValueError("generated code is unavailable")
        return CanonicalGeneratedCodeRecord(
            schema_version=SCHEMA_VERSION,
            code_id=f"code_{trusted_request.request_id.removeprefix('req_')}",
            request_id=trusted_request.request_id,
            prompt_id=trusted_request.prompt_id,
            prompt_sha256=trusted_request.prompt_sha256,
            condition=trusted_request.condition,
            model_id=trusted_request.model_id,
            seed_id=trusted_request.seed_id,
            code=code,
            code_sha256=sha256_text(code),
            hypothesis_id=trusted_request.hypothesis_id,
            intervention_id=trusted_request.intervention_id,
            generation_provenance=trusted_provenance,
            generation_request=trusted_request,
        )
    except Exception:
        pass
    request = None  # type: ignore[assignment]
    code = ""
    provenance = None  # type: ignore[assignment]
    trusted_request = None
    trusted_provenance = None
    raise _import_error(
        ErrorCode.CONTRACT,
        "canonical generation record construction failed",
    )


def import_offline_results(
    expected_requests: Iterable[GenerationRequestRecord],
    received_results: Iterable[OfflineGenerationResultRecord],
) -> list[CanonicalGeneratedCodeRecord]:
    """Validate and join offline results to their expected request ledger."""

    expected = _validated_expected(expected_requests)
    received = _validated_received(received_results)

    received_ids = [result.request_id for result in received]
    if len(set(received_ids)) != len(received_ids):
        raise _import_error(
            ErrorCode.CONTRACT,
            "offline generation results contain duplicate request ids",
        )

    expected_by_id = {request.request_id: request for request in expected}
    if any(request_id not in expected_by_id for request_id in received_ids):
        raise _import_error(
            ErrorCode.CONTRACT,
            "offline generation results contain unexpected requests",
        )

    _ensure_matching_envelopes(expected_by_id, received)

    received_by_id = {result.request_id: result for result in received}
    missing_count = len(expected_by_id) - len(received_by_id)
    if missing_count:
        raise _import_error(
            ErrorCode.EXTERNAL_INPUT_REQUIRED,
            "offline generation results are incomplete",
            details={
                "expected_count": len(expected),
                "received_count": len(received),
                "missing_count": missing_count,
            },
            retryable=True,
        )

    try:
        imported = [
            canonical_generated_code_from_request(
                request,
                received_by_id[request.request_id].code,
                received_by_id[request.request_id].provenance,
            )
            for request in expected
        ]
    except Exception:
        pass
    else:
        return imported
    raise _import_error(
        ErrorCode.CONTRACT,
        "offline generation canonical record construction failed",
    )


__all__ = [
    "MAX_OFFLINE_IMPORT_RECORDS",
    "canonical_generated_code_from_request",
    "import_offline_results",
]

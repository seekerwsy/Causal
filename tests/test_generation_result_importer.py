from collections.abc import Callable, Iterator
from functools import wraps
import json
import traceback
from typing import Any, Literal

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation import result_importer
from secaware.generation.result_importer import (
    canonical_generated_code_from_request,
    import_offline_results,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationProvenance,
    GenerationRequestRecord,
    OfflineGenerationResultRecord,
    build_generation_request_id,
    sha256_text,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord, GeneratedCodeRecord


_PRODUCER = "offline-worker-safe"
_PRODUCER_VERSION = "worker-v1-safe"
_SOURCE_BATCH_ID = "batch-safe"
_CANONICAL_METADATA_FIELDS = (
    "schema_version",
    "request_id",
    "prompt_sha256",
    "code_sha256",
    "generation_provenance",
    "generation_request",
)


def _expects_canonical_counterfactual_rejection(test):
    @wraps(test)
    def wrapped(*args, **kwargs):
        with pytest.raises(ValidationError):
            test(*args, **kwargs)

    return wrapped


def _secaware_traceback_locals(error: BaseException) -> str:
    retained: list[str] = []
    cursor = error.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(dict(cursor.tb_frame.f_locals)))
        cursor = cursor.tb_next
    return "\n".join(retained)


def _request(
    prompt_id: str = "prompt-a",
    *,
    prompt: str | None = None,
    model_id: str = "model-a",
    seed_id: int = 1,
    condition: Literal["observed", "counterfactual"] = "observed",
    hypothesis_id: str | None = None,
    intervention_id: str | None = None,
    endpoint_type: Literal["mock", "offline", "chat_completions"] = "offline",
    language: str = "python",
    system_template_version: str = "template-v1",
    system_template: str = "Return only code.",
    endpoint_identity: str | None = None,
    parameters: GenerationParameters | None = None,
) -> GenerationRequestRecord:
    prompt_text = prompt or f"Read the path for {prompt_id}."
    parameter_values = parameters or GenerationParameters(values={"temperature": 0.2})
    prompt_sha256 = sha256_text(prompt_text)
    system_template_sha256 = sha256_text(system_template)
    endpoint_sha256 = sha256_text(endpoint_identity or endpoint_type)
    request_id = (
        build_generation_request_id(
            schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
            condition="observed",
            prompt_id=prompt_id,
            prompt_sha256=prompt_sha256,
            language=language,
            model_id=model_id,
            seed_id=seed_id,
            hypothesis_id=hypothesis_id,
            endpoint_type=endpoint_type,
            endpoint_sha256=endpoint_sha256,
            system_template_version=system_template_version,
            system_template_sha256=system_template_sha256,
            parameters=parameter_values,
        )
        if condition == "observed"
        else "req_" + "f" * 64
    )
    values = dict(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        condition=condition,
        prompt_id=prompt_id,
        prompt=prompt_text,
        prompt_sha256=prompt_sha256,
        language=language,
        model_id=model_id,
        seed_id=seed_id,
        hypothesis_id=hypothesis_id,
        endpoint_type=endpoint_type,
        endpoint_sha256=endpoint_sha256,
        system_template_version=system_template_version,
        system_template_sha256=system_template_sha256,
        parameters=parameter_values,
    )
    return GenerationRequestRecord(**values)


def _provenance() -> GenerationProvenance:
    return GenerationProvenance(
        producer=_PRODUCER,
        producer_version=_PRODUCER_VERSION,
        source_batch_id=_SOURCE_BATCH_ID,
    )


def _result(
    request: GenerationRequestRecord,
    *,
    code: str = "def read_path(user_path):\n    return open(user_path).read()\n",
) -> OfflineGenerationResultRecord:
    payload = request.model_dump(mode="python", round_trip=True, warnings=False)
    payload.update(
        code=code,
        code_sha256=sha256_text(code),
        provenance=_provenance(),
    )
    return OfflineGenerationResultRecord.model_validate(payload)


def test_canonical_bridge_helper_builds_provider_and_offline_records_identically() -> None:
    request = _request(endpoint_type="chat_completions")
    provenance = _provenance()
    code = "def safe():\n    return True\n"

    record = canonical_generated_code_from_request(request, code, provenance)

    assert record.code_sha256 == sha256_text(code)
    assert record.generation_request == request
    assert record.generation_provenance == provenance
    assert record.request_id == request.request_id


def test_canonical_bridge_failure_does_not_retain_request_code_or_provenance() -> None:
    request = _request(
        endpoint_type="chat_completions",
        prompt="private bridge prompt body",
    ).model_copy(update={"model_id": "forged-private-model"})
    code = "private bridge generated code"
    provenance = GenerationProvenance(producer="private-bridge-producer")

    with pytest.raises(SecAwareError) as exc_info:
        canonical_generated_code_from_request(request, code, provenance)

    retained: list[str] = []
    current = exc_info.value.__traceback__
    while current is not None:
        if "/src/secaware/" in current.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(current.tb_frame.f_locals))
        current = current.tb_next
    surface = "\n".join(retained)
    for hidden in (
        "private bridge prompt body",
        "forged-private-model",
        code,
        provenance.producer,
    ):
        assert hidden not in surface


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_canonical_bridge_preserves_fatal_identity_and_releases_inputs(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    prompt = f"private-{signal_type.__name__}-bridge-prompt"
    code = f"private-{signal_type.__name__}-bridge-code"
    producer = f"private-{signal_type.__name__}-producer"
    request = _request(endpoint_type="chat_completions", prompt=prompt)
    provenance = GenerationProvenance(producer=producer)
    signal = signal_type("bridge-control-flow")

    def interrupt(_request):
        raise signal

    monkeypatch.setattr(result_importer, "revalidate_generation_request_envelope", interrupt)
    with pytest.raises(signal_type) as exc_info:
        canonical_generated_code_from_request(request, code, provenance)
    assert exc_info.value is signal
    retained = _secaware_traceback_locals(signal)
    for hidden in (prompt, code, producer):
        assert hidden not in retained


def _validation_surfaces(error: ValidationError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.errors(), default=str, sort_keys=True),
        error.json(),
    )


def _error_surfaces(error: SecAwareError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), default=str, sort_keys=True),
    )


def _assert_safe_validation_error(error: ValidationError, *hidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    structured = error.errors()
    assert len(structured) == 1
    assert structured[0]["loc"] == ()
    assert structured[0].get("input") is None
    assert "ctx" not in structured[0]
    for value in hidden:
        assert all(value not in surface for surface in _validation_surfaces(error))


def _assert_safe_import_error(error: SecAwareError, *records: object) -> None:
    hidden = {
        _PRODUCER,
        _PRODUCER_VERSION,
        _SOURCE_BATCH_ID,
        "RuntimeError",
    }
    for record in records:
        if isinstance(record, GenerationRequestRecord):
            hidden.update(
                {
                    record.request_id,
                    record.prompt_id,
                    record.prompt,
                    record.prompt_sha256,
                    record.model_id,
                }
            )
        if isinstance(record, OfflineGenerationResultRecord):
            hidden.update({record.code, record.code_sha256})
    for value in hidden:
        assert all(value not in surface for surface in _error_surfaces(error))


class GuardedInfiniteIterator:
    def __init__(
        self,
        factory: Callable[[int], object],
        *,
        maximum_reads: int,
    ) -> None:
        self.factory = factory
        self.maximum_reads = maximum_reads
        self.reads = 0

    def __iter__(self) -> "GuardedInfiniteIterator":
        return self

    def __next__(self) -> object:
        self.reads += 1
        if self.reads > self.maximum_reads:
            raise RuntimeError("unbounded-import-overread-secret")
        return self.factory(self.reads)


def test_generation_provenance_is_strict_frozen_and_forbids_metadata() -> None:
    provenance = _provenance()

    assert provenance.model_dump(mode="json") == {
        "producer": _PRODUCER,
        "producer_version": _PRODUCER_VERSION,
        "source_batch_id": _SOURCE_BATCH_ID,
    }
    with pytest.raises(ValidationError):
        provenance.producer = "changed"
    with pytest.raises(ValidationError):
        GenerationProvenance.model_validate(
            {
                "producer": _PRODUCER,
                "metadata": {"secret": "arbitrary-metadata-secret"},
            }
        )
    with pytest.raises(ValidationError):
        GenerationProvenance.model_validate({"producer": 42})


@pytest.mark.parametrize("field", ["producer", "producer_version", "source_batch_id"])
def test_generation_provenance_rejects_blank_text(field: str) -> None:
    payload: dict[str, object] = {"producer": _PRODUCER}
    payload[field] = "  "

    with pytest.raises(ValidationError):
        GenerationProvenance.model_validate(payload)


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_generation_provenance_validation_surfaces_are_sanitized(entrypoint: str) -> None:
    secret = "provenance-validation-secret"
    payload = {"producer": " ", "producer_version": secret}

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            GenerationProvenance(**payload)
        elif entrypoint == "model_validate":
            GenerationProvenance.model_validate(payload)
        elif entrypoint == "model_validate_json":
            GenerationProvenance.model_validate_json(json.dumps(payload))
        else:
            GenerationProvenance.model_validate_strings(payload)

    _assert_safe_validation_error(exc_info.value, secret, "input_value")


def test_offline_generation_result_is_strict_frozen_and_hash_bound() -> None:
    request = _request()
    result = _result(request)

    assert result.endpoint_type == "offline"
    assert result.code_sha256 == sha256_text(result.code)
    assert result.provenance == _provenance()
    with pytest.raises(ValidationError):
        result.code = "changed"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(code="  "),
        lambda payload: payload.update(code_sha256="0" * 64),
        lambda payload: payload.update(code_sha256=payload["code_sha256"].upper()),
        lambda payload: payload.update(schema_version="2.0"),
        lambda payload: payload.update(endpoint_type="mock"),
        lambda payload: payload.update(unexpected="extra-result-field"),
        lambda payload: payload.update(
            provenance={"producer": _PRODUCER, "metadata": "not-allowed"}
        ),
    ],
    ids=[
        "blank-code",
        "wrong-code-hash",
        "uppercase-code-hash",
        "schema-version",
        "endpoint-type",
        "extra-field",
        "provenance-extra-field",
    ],
)
def test_offline_generation_result_rejects_noncanonical_payloads(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    payload = _result(_request()).model_dump(mode="python")
    mutate(payload)

    with pytest.raises(ValidationError):
        OfflineGenerationResultRecord.model_validate(payload)


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_offline_result_validation_surfaces_never_echo_payload(entrypoint: str) -> None:
    prompt_secret = "prompt-validation-leak-sentinel"
    code_secret = "code-validation-leak-sentinel"
    provenance_secret = "provenance-validation-leak-sentinel"
    payload = _result(_request(prompt=prompt_secret), code=code_secret).model_dump(mode="python")
    payload["code_sha256"] = "f" * 64
    payload["provenance"] = {
        "producer": " ",
        "producer_version": provenance_secret,
    }

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            OfflineGenerationResultRecord(**payload)
        elif entrypoint == "model_validate":
            OfflineGenerationResultRecord.model_validate(payload)
        elif entrypoint == "model_validate_json":
            OfflineGenerationResultRecord.model_validate_json(json.dumps(payload))
        else:
            OfflineGenerationResultRecord.model_validate_strings(payload)

    _assert_safe_validation_error(
        exc_info.value,
        prompt_secret,
        code_secret,
        provenance_secret,
        "input_value",
    )


def test_importer_restores_ledger_order_and_round_trips_canonical_metadata() -> None:
    expected = [
        _request("prompt-a", seed_id=1),
        _request("prompt-a", seed_id=2),
        _request("prompt-b", seed_id=1),
    ]
    received = [
        _result(expected[2], code="def third():\n    return 3\n"),
        _result(expected[0], code="def first():\n    return 1\n"),
        _result(expected[1], code="def second():\n    return 2\n"),
    ]

    imported = import_offline_results(expected, received)

    assert [record.request_id for record in imported] == [
        request.request_id for request in expected
    ]
    by_request_id = {result.request_id: result for result in received}
    for request, record in zip(expected, imported, strict=True):
        result = by_request_id[request.request_id]
        assert type(record) is CanonicalGeneratedCodeRecord
        assert record.schema_version == "1.1"
        assert record.code_id.startswith("code_")
        assert len(record.code_id) == len("code_") + 64
        assert record.request_id == request.request_id
        assert record.prompt_id == request.prompt_id
        assert record.prompt_sha256 == request.prompt_sha256
        assert record.code == result.code
        assert record.code_sha256 == result.code_sha256
        assert record.generation_provenance == result.provenance
        assert record.condition == request.condition
        assert record.model_id == request.model_id
        assert record.seed_id == request.seed_id
        assert record.hypothesis_id == request.hypothesis_id
        assert record.generation_request == request
        assert record.generation_request is not request


def test_canonical_generated_code_record_has_schema_package_export() -> None:
    from secaware.schema import CanonicalGeneratedCodeRecord as ExportedCanonicalRecord

    assert ExportedCanonicalRecord is CanonicalGeneratedCodeRecord


def test_legacy_generated_code_record_remains_valid_without_forged_metadata() -> None:
    legacy = GeneratedCodeRecord(
        code_id="legacy-code-a",
        prompt_id="legacy-prompt-a",
        condition="observed",
        model_id="legacy-model-a",
        seed_id=7,
        code="def legacy():\n    return True\n",
    )

    assert legacy.schema_version is None
    assert legacy.request_id is None
    assert legacy.prompt_sha256 is None
    assert legacy.code_sha256 is None
    assert legacy.generation_provenance is None
    assert legacy.generation_request is None


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_generated_code_validation_surfaces_never_echo_code_or_metadata(
    entrypoint: str,
) -> None:
    code_secret = "generated-code-validation-secret"
    id_secret = "code_" + "a" * 64
    metadata_secret = "generated-metadata-validation-secret"
    payload = {
        "code_id": id_secret,
        "prompt_id": metadata_secret,
        "condition": "observed",
        "model_id": "model-validation-secret",
        "seed_id": 1,
        "code": code_secret,
    }

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            GeneratedCodeRecord(**payload)
        elif entrypoint == "model_validate":
            GeneratedCodeRecord.model_validate(payload)
        elif entrypoint == "model_validate_json":
            GeneratedCodeRecord.model_validate_json(json.dumps(payload))
        else:
            GeneratedCodeRecord.model_validate_strings(payload)

    _assert_safe_validation_error(
        exc_info.value,
        code_secret,
        id_secret,
        metadata_secret,
        "input_value",
    )


def test_generated_code_record_is_frozen_with_safe_assignment_errors() -> None:
    legacy = GeneratedCodeRecord(
        code_id="legacy-code-frozen",
        prompt_id="legacy-prompt-frozen",
        condition="observed",
        model_id="legacy-model-frozen",
        seed_id=2,
        code="def original():\n    return True\n",
    )
    replacement_secret = "assignment-code-secret"

    with pytest.raises(ValidationError) as exc_info:
        legacy.code = replacement_secret

    assert legacy.code == "def original():\n    return True\n"
    _assert_safe_validation_error(exc_info.value, replacement_secret, "input_value")


def test_legacy_generated_code_record_keeps_historically_permitted_coordinates() -> None:
    legacy = GeneratedCodeRecord(
        code_id="legacy-code-cf",
        prompt_id="legacy-prompt-cf",
        condition="counterfactual",
        model_id="legacy-model-cf",
        seed_id=8,
        code="def legacy():\n    return True\n",
        hypothesis_id=None,
        intervention_id="legacy-partial-coordinate",
    )

    assert legacy.schema_version is None
    assert legacy.intervention_id == "legacy-partial-coordinate"


def test_generated_code_record_rejects_partial_canonical_metadata() -> None:
    with pytest.raises(ValidationError):
        GeneratedCodeRecord(
            code_id="legacy-code-a",
            prompt_id="legacy-prompt-a",
            condition="observed",
            model_id="legacy-model-a",
            seed_id=7,
            code="def legacy():\n    return True\n",
            schema_version="1.0",
        )


@pytest.mark.parametrize("deletion", ["generation_request", "all_metadata"])
def test_canonical_payload_cannot_downgrade_to_legacy(deletion: str) -> None:
    request = _request()
    canonical = import_offline_results([request], [_result(request)])[0]
    payload = canonical.model_dump(mode="python")
    if deletion == "generation_request":
        payload.pop("generation_request")
    else:
        for field in _CANONICAL_METADATA_FIELDS:
            payload.pop(field)

    with pytest.raises(ValidationError) as exc_info:
        GeneratedCodeRecord.model_validate(payload)

    _assert_safe_validation_error(
        exc_info.value,
        canonical.code,
        canonical.code_id,
        canonical.request_id,
    )


def test_noncanonical_legacy_code_id_remains_valid() -> None:
    legacy = GeneratedCodeRecord(
        code_id="legacy-code-id",
        prompt_id="legacy-prompt-id",
        condition="observed",
        model_id="legacy-model-id",
        seed_id=3,
        code="def legacy():\n    return True\n",
    )

    assert legacy.request_id is None


def test_canonical_record_round_trips_through_canonical_jsonl_schema(tmp_path: Any) -> None:
    request = _request()
    canonical = import_offline_results([request], [_result(request)])[0]
    path = tmp_path / "canonical-code.jsonl"

    write_jsonl(path, [canonical], stage="canonical-code-test")
    loaded = read_jsonl(
        path,
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
        stage="canonical-code-test",
    )

    assert loaded == [canonical]
    assert type(loaded[0]) is CanonicalGeneratedCodeRecord


@_expects_canonical_counterfactual_rejection
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("request_id", "req_" + "0" * 64),
        ("prompt_id", "drifted-prompt"),
        ("condition", "observed"),
        ("model_id", "drifted-model"),
        ("seed_id", 999),
        ("hypothesis_id", "drifted-hypothesis"),
        ("intervention_id", "drifted-intervention"),
        ("prompt_sha256", "0" * 64),
    ],
)
def test_canonical_top_level_coordinates_are_bound_to_full_request_envelope(
    field: str,
    replacement: object,
) -> None:
    request = _request(
        "prompt-canonical",
        prompt="Normalize a path before opening it.",
        condition="counterfactual",
        hypothesis_id="hyp-canonical",
        intervention_id="int-canonical",
    )
    canonical = import_offline_results([request], [_result(request)])[0]
    payload = canonical.model_dump(mode="python")
    payload[field] = replacement

    with pytest.raises(ValidationError) as exc_info:
        CanonicalGeneratedCodeRecord.model_validate(payload)

    _assert_safe_validation_error(
        exc_info.value,
        canonical.code,
        canonical.code_id,
        request.request_id,
        request.prompt,
    )


def test_canonical_nested_request_is_revalidated_before_binding() -> None:
    request = _request()
    canonical = import_offline_results([request], [_result(request)])[0]
    forged_request = request.model_copy(update={"model_id": "nested-coordinate-secret"})
    payload = canonical.model_dump(mode="python")
    payload["generation_request"] = forged_request

    with pytest.raises(ValidationError) as exc_info:
        CanonicalGeneratedCodeRecord.model_validate(payload)

    _assert_safe_validation_error(
        exc_info.value,
        "nested-coordinate-secret",
        request.request_id,
        request.prompt,
        canonical.code,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("code_id", "code_" + "0" * 64),
        ("request_id", "req_" + "0" * 64),
        ("prompt_sha256", "A" * 64),
        ("code_sha256", "0" * 64),
        ("hypothesis_id", "unexpected-hypothesis"),
        ("intervention_id", "unexpected-intervention"),
    ],
)
def test_generated_code_record_rejects_inconsistent_canonical_metadata(
    field: str,
    replacement: object,
) -> None:
    canonical = import_offline_results([_request()], [_result(_request())])[0]
    payload = canonical.model_dump(mode="python")
    payload[field] = replacement

    with pytest.raises(ValidationError):
        GeneratedCodeRecord.model_validate(payload)


@pytest.mark.parametrize("missing_field", ["hypothesis_id", "intervention_id"])
@_expects_canonical_counterfactual_rejection
def test_canonical_counterfactual_record_requires_both_identifiers(
    missing_field: str,
) -> None:
    request = _request(
        "prompt-cf",
        prompt="Normalize a path before opening it.",
        condition="counterfactual",
        hypothesis_id="hyp-a",
        intervention_id="int-a",
    )
    canonical = import_offline_results([request], [_result(request)])[0]
    payload = canonical.model_dump(mode="python")
    payload[missing_field] = None

    with pytest.raises(ValidationError):
        GeneratedCodeRecord.model_validate(payload)


@_expects_canonical_counterfactual_rejection
def test_different_interventions_produce_different_canonical_code_ids() -> None:
    first = _request(
        "prompt-cf",
        prompt="Normalize a path before opening it.",
        condition="counterfactual",
        hypothesis_id="hyp-a",
        intervention_id="int-a",
    )
    second = _request(
        "prompt-cf",
        prompt="Reject a path outside the base directory.",
        condition="counterfactual",
        hypothesis_id="hyp-b",
        intervention_id="int-b",
    )

    imported = import_offline_results([first, second], [_result(second), _result(first)])

    assert imported[0].code_id != imported[1].code_id
    assert imported[0].intervention_id == "int-a"
    assert imported[1].intervention_id == "int-b"


def test_importer_rejects_empty_or_nonoffline_expected_ledgers() -> None:
    with pytest.raises(SecAwareError) as empty_info:
        import_offline_results([], [])
    assert empty_info.value.code is ErrorCode.CONTRACT

    nonoffline = _request(endpoint_type="mock")
    with pytest.raises(SecAwareError) as endpoint_info:
        import_offline_results([nonoffline], [])
    assert endpoint_info.value.code is ErrorCode.CONTRACT
    _assert_safe_import_error(endpoint_info.value, nonoffline)


def test_importer_rejects_duplicate_expected_request_ids() -> None:
    request = _request()

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([request, request], [_result(request)])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "expected" in exc_info.value.message
    assert "unique" in exc_info.value.message
    _assert_safe_import_error(exc_info.value, request)


def test_importer_rejects_duplicate_received_before_extra_or_missing() -> None:
    first = _request("prompt-a")
    second = _request("prompt-b")
    extra = _request("prompt-extra")
    duplicate = _result(first)

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results(
            [first, second],
            [duplicate, duplicate, _result(extra)],
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "duplicate" in exc_info.value.message
    _assert_safe_import_error(exc_info.value, first, second, extra, duplicate)


def test_importer_rejects_extra_before_missing() -> None:
    first = _request("prompt-a")
    missing = _request("prompt-b")
    extra = _request("prompt-extra")

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([first, missing], [_result(first), _result(extra)])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "unexpected" in exc_info.value.message
    _assert_safe_import_error(exc_info.value, first, missing, extra)


def test_importer_reports_missing_results_as_retryable_external_input() -> None:
    first = _request("prompt-a")
    missing = _request("prompt-b")

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([first, missing], [_result(first)])

    error = exc_info.value
    assert error.code is ErrorCode.EXTERNAL_INPUT_REQUIRED
    assert error.retryable is True
    assert error.details == {
        "expected_count": 2,
        "received_count": 1,
        "missing_count": 1,
    }
    _assert_safe_import_error(error, first, missing)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "2.0"),
        ("request_id", "req_" + "0" * 64),
        ("condition", "counterfactual"),
        ("prompt_id", "tampered-prompt-id"),
        ("prompt", "tampered prompt secret"),
        ("prompt_sha256", "a" * 64),
        ("language", "ruby"),
        ("model_id", "tampered-model"),
        ("seed_id", 999),
        ("hypothesis_id", "tampered-hypothesis"),
        ("intervention_id", "tampered-intervention"),
        ("endpoint_type", "mock"),
        ("system_template_version", "tampered-template"),
        ("system_template_sha256", "b" * 64),
        ("parameters", GenerationParameters(values={"temperature": 0.9})),
    ],
)
def test_importer_revalidates_every_received_request_envelope_field(
    field: str,
    replacement: object,
) -> None:
    request = _request()
    valid = _result(request)
    forged = valid.model_copy(update={field: replacement})

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([request], [forged])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "schema" in exc_info.value.message or "envelope" in exc_info.value.message
    _assert_safe_import_error(exc_info.value, request, valid)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("code", "tampered code secret"),
        ("code_sha256", "0" * 64),
    ],
)
def test_importer_revalidates_forged_result_code_fields(
    field: str,
    replacement: object,
) -> None:
    request = _request()
    valid = _result(request)
    forged = valid.model_copy(update={field: replacement})

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([request], [forged])

    assert exc_info.value.code is ErrorCode.CONTRACT
    _assert_safe_import_error(exc_info.value, request, valid)


def test_importer_revalidates_forged_nested_provenance() -> None:
    request = _request()
    valid = _result(request)
    forged_provenance = valid.provenance.model_copy(update={"producer": " "})
    forged = valid.model_copy(update={"provenance": forged_provenance})

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([request], [forged])

    assert exc_info.value.code is ErrorCode.CONTRACT
    _assert_safe_import_error(exc_info.value, request, valid)


@pytest.mark.parametrize(
    "location",
    ["expected", "received", "parameters", "provenance"],
)
def test_importer_rejects_forbidden_fields_hidden_by_model_copy(location: str) -> None:
    request = _request()
    valid = _result(request)
    secret = f"{location}-hidden-extra-secret"
    expected_values: list[GenerationRequestRecord] = [request]
    result_values: list[OfflineGenerationResultRecord] = [valid]
    if location == "expected":
        expected_values = [request.model_copy(update={"unexpected": secret})]
    elif location == "received":
        result_values = [valid.model_copy(update={"unexpected": secret})]
    elif location == "parameters":
        forged_parameters = valid.parameters.model_copy(update={"unexpected": secret})
        result_values = [valid.model_copy(update={"parameters": forged_parameters})]
    else:
        forged_provenance = valid.provenance.model_copy(update={"unexpected": secret})
        result_values = [valid.model_copy(update={"provenance": forged_provenance})]

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results(expected_values, result_values)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert all(secret not in surface for surface in _error_surfaces(exc_info.value))
    _assert_safe_import_error(exc_info.value, request, valid)


def test_importer_snapshots_provenance_for_canonical_output() -> None:
    request = _request()
    result = _result(request)

    imported = import_offline_results([request], [result])[0]

    assert imported.generation_provenance == result.provenance
    assert imported.generation_provenance is not result.provenance


def test_importer_revalidates_model_construct_result() -> None:
    request = _request()
    valid = _result(request)
    payload = valid.model_dump(mode="python")
    payload["code_sha256"] = "0" * 64
    forged = OfflineGenerationResultRecord.model_construct(**payload)

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([request], [forged])

    assert exc_info.value.code is ErrorCode.CONTRACT
    _assert_safe_import_error(exc_info.value, request, valid)


def test_importer_revalidates_forged_expected_request_before_received_duplicates() -> None:
    request = _request()
    forged = request.model_copy(update={"prompt": "forged expected prompt secret"})
    result = _result(request)

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([forged], [result, result])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "expected" in exc_info.value.message
    _assert_safe_import_error(exc_info.value, request, result)


def test_received_schema_validation_precedes_duplicate_detection() -> None:
    request = _request()
    valid = _result(request)
    forged = valid.model_copy(update={"code_sha256": "0" * 64})

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results([request], [forged, forged])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "schema" in exc_info.value.message
    assert "duplicate" not in exc_info.value.message
    _assert_safe_import_error(exc_info.value, request, valid)


@pytest.mark.parametrize("collection", ["expected", "received"])
def test_importer_safely_wraps_iterator_errors(collection: str) -> None:
    request = _request()
    result = _result(request)
    iterator_secret = f"{collection}-iterator-secret"

    def raising_requests() -> Iterator[GenerationRequestRecord]:
        yield request
        raise RuntimeError(iterator_secret)

    def raising_results() -> Iterator[OfflineGenerationResultRecord]:
        yield result
        raise RuntimeError(iterator_secret)

    with pytest.raises(SecAwareError) as exc_info:
        if collection == "expected":
            import_offline_results(raising_requests(), [result])
        else:
            import_offline_results([request], raising_results())

    assert exc_info.value.code is ErrorCode.CONTRACT
    for hidden in (iterator_secret, "RuntimeError"):
        assert all(hidden not in surface for surface in _error_surfaces(exc_info.value))
    _assert_safe_import_error(exc_info.value, request, result)


@pytest.mark.parametrize("collection", ["expected", "received"])
def test_importer_bounds_infinite_iterables(
    monkeypatch: pytest.MonkeyPatch,
    collection: str,
) -> None:
    monkeypatch.setattr(result_importer, "MAX_OFFLINE_IMPORT_RECORDS", 2)
    expected = _request("prompt-expected")
    result = _result(expected)
    if collection == "expected":
        infinite = GuardedInfiniteIterator(
            lambda index: _request(f"prompt-{index}"),
            maximum_reads=3,
        )
        expected_values: object = infinite
        result_values: object = [result]
    else:
        infinite = GuardedInfiniteIterator(
            lambda index: _result(_request(f"prompt-{index}")),
            maximum_reads=3,
        )
        expected_values = [expected]
        result_values = infinite

    with pytest.raises(SecAwareError) as exc_info:
        import_offline_results(expected_values, result_values)  # type: ignore[arg-type]

    assert infinite.reads == 3
    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "limit" in exc_info.value.message
    _assert_safe_import_error(exc_info.value, expected, result)


def test_importer_accepts_each_collection_at_the_exact_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(result_importer, "MAX_OFFLINE_IMPORT_RECORDS", 2)
    expected = [_request("prompt-a"), _request("prompt-b")]
    received = [_result(expected[1]), _result(expected[0])]

    imported = import_offline_results(expected, received)

    assert [record.request_id for record in imported] == [
        request.request_id for request in expected
    ]

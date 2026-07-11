from pathlib import Path

import pytest
from pydantic import ValidationError

from secaware import __version__
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.request_planner import plan_observed_requests
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
)
from secaware.schema.migrations import migrate_generation_request_v1_0_to_v1_1
from secaware.schema.records import PromptRecord


def _request() -> GenerationRequestRecord:
    prompt = PromptRecord(
        prompt_id="schema-v11",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Open a path safely.",
    )
    return plan_observed_requests(
        [prompt],
        ["model-a"],
        [7],
        endpoint_type="offline",
    )[0]


def _legacy_payload() -> dict[str, object]:
    request = _request()
    payload = request.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload.pop("endpoint_sha256")
    payload["request_id"] = f"req_{'0' * 64}"
    return payload


def test_generation_request_schema_is_explicit_v11_while_shared_records_remain_v1() -> None:
    request = _request()
    provenance = GenerationProvenance(producer="schema-test")
    code = canonical_generated_code_from_request(request, "def value():\n    return 1\n", provenance)
    attempt = GenerationAttemptRecord(
        schema_version=SCHEMA_VERSION,
        request_id=request.request_id,
        attempt=1,
        outcome="success",
        error_code=None,
        retryable=False,
        backoff_seconds=0.0,
    )

    assert GENERATION_REQUEST_SCHEMA_VERSION == "1.1"
    assert request.schema_version == GENERATION_REQUEST_SCHEMA_VERSION
    assert code.schema_version == SCHEMA_VERSION == "1.0"
    assert code.generation_request.schema_version == "1.1"
    assert attempt.schema_version == "1.0"


def test_v10_request_cannot_validate_as_v11_even_if_endpoint_hash_is_injected() -> None:
    payload = _legacy_payload()
    payload["endpoint_sha256"] = "0" * 64

    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(payload)


def test_explicit_v10_migration_derives_endpoint_hash_and_recomputes_identity() -> None:
    payload = _legacy_payload()

    migrated = migrate_generation_request_v1_0_to_v1_1(payload)

    assert migrated.schema_version == "1.1"
    assert migrated.endpoint_sha256 != "0" * 64
    assert migrated.request_id != payload["request_id"]
    assert payload["schema_version"] == "1.0"
    assert "endpoint_sha256" not in payload


def test_v10_migration_rejects_unknown_fields_without_echoing_them() -> None:
    payload = _legacy_payload()
    payload["private_api_key"] = "private-migration-secret"

    with pytest.raises(SecAwareError) as exc_info:
        migrate_generation_request_v1_0_to_v1_1(payload)

    assert exc_info.value.code is ErrorCode.CONTRACT
    surface = str(exc_info.value) + repr(exc_info.value.to_dict())
    assert "private_api_key" not in surface
    assert "private-migration-secret" not in surface


def test_package_version_is_bumped_for_manifest_fingerprint_invalidation() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"

    assert __version__ == "0.2.0"
    assert 'version = "0.2.0"' in pyproject.read_text(encoding="utf-8")

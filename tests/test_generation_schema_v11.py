from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from secaware import __version__
from secaware.config import OpenAICompatibleConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.openai_compatible_provider import OpenAICompatibleProvider
from secaware.generation.request_planner import plan_observed_requests
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    sha256_text,
)
from secaware.schema.migrations import migrate_generation_request_v1_0_to_v1_1
from secaware.schema.records import PromptRecord


_BASE_URL = "https://provider.invalid/v1"
_LEGACY_IDENTITY_FIELDS = (
    "schema_version",
    "condition",
    "prompt_id",
    "prompt_sha256",
    "language",
    "model_id",
    "seed_id",
    "hypothesis_id",
    "intervention_id",
    "endpoint_type",
    "system_template_version",
    "system_template_sha256",
    "parameters",
)


def _request() -> GenerationRequestRecord:
    prompt = PromptRecord(
        prompt_id="schema-v11",
        task_id="task-schema-v11",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Open a path safely.",
        prompt_role="neutral_baseline",
        counterpart_prompt_id=None,
    )
    return plan_observed_requests(
        [prompt],
        ["model-a"],
        [7],
        endpoint_type="offline",
    )[0]


def _seal_legacy_payload(payload: dict[str, object]) -> None:
    identity = {key: payload[key] for key in _LEGACY_IDENTITY_FIELDS}
    payload["request_id"] = f"req_{canonical_sha256(identity)}"


def _legacy_payload(
    request: GenerationRequestRecord | None = None,
) -> dict[str, object]:
    if request is None:
        request = _request()
    payload = request.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload.pop("endpoint_sha256")
    _seal_legacy_payload(payload)
    return payload


def _chat_request() -> GenerationRequestRecord:
    prompt = PromptRecord(
        prompt_id="schema-v11-chat",
        task_id="task-schema-v11-chat",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Return a safe path helper.",
        prompt_role="neutral_baseline",
        counterpart_prompt_id=None,
    )
    return plan_observed_requests(
        [prompt],
        ["model-a"],
        [7],
        endpoint_type="chat_completions",
        endpoint_identity=_BASE_URL,
    )[0]


def test_generation_request_schema_is_explicit_v11_while_shared_records_remain_v1() -> None:
    request = _request()
    provenance = GenerationProvenance(producer="schema-test")
    code = canonical_generated_code_from_request(
        request, "def value():\n    return 1\n", provenance
    )
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


@pytest.mark.parametrize(
    "forgery",
    [
        "request_id",
        "coordinated_prompt",
        "coordinated_condition",
        "prompt_hash",
        "condition_identifiers",
    ],
)
def test_v10_migration_rejects_forged_seals_hashes_and_coordinates(
    forgery: str,
) -> None:
    payload = _legacy_payload()
    if forgery == "request_id":
        payload["request_id"] = f"req_{'0' * 64}"
    elif forgery == "coordinated_prompt":
        payload["prompt"] = "Changed prompt content."
        payload["prompt_sha256"] = sha256_text(str(payload["prompt"]))
    elif forgery == "coordinated_condition":
        payload["condition"] = "counterfactual"
        payload["hypothesis_id"] = "hypothesis-forgery"
        payload["intervention_id"] = "intervention-forgery"
    elif forgery == "prompt_hash":
        payload["prompt_sha256"] = sha256_text("different prompt")
        _seal_legacy_payload(payload)
    else:
        payload["hypothesis_id"] = "unexpected-hypothesis"
        payload["intervention_id"] = "unexpected-intervention"
        _seal_legacy_payload(payload)

    with pytest.raises(SecAwareError) as exc_info:
        migrate_generation_request_v1_0_to_v1_1(payload)

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_v10_chat_migration_requires_explicit_endpoint_identity() -> None:
    payload = _legacy_payload(_chat_request())

    with pytest.raises(SecAwareError) as exc_info:
        migrate_generation_request_v1_0_to_v1_1(payload)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.details == {}


def test_v10_chat_migration_binds_endpoint_and_executes_with_provider() -> None:
    payload = _legacy_payload(_chat_request())
    calls: list[dict[str, object]] = []

    def create(**kwargs: object) -> object:
        calls.append(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="def safe_path():\n    return None\n"),
                    finish_reason="stop",
                )
            ],
            usage=None,
        )

    migrated = migrate_generation_request_v1_0_to_v1_1(
        payload,
        endpoint_identity=_BASE_URL,
    )
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(base_url=_BASE_URL, max_attempts=1),
        client=client,
    )

    result = provider.generate(migrated)

    assert migrated.endpoint_sha256 == sha256_text(_BASE_URL)
    assert migrated.endpoint_sha256 != sha256_text("chat_completions")
    assert result.code == "def safe_path():\n    return None\n"
    assert len(calls) == 1


def test_v10_migration_rejects_unknown_fields_without_echoing_them() -> None:
    payload = _legacy_payload()
    payload["private_api_key"] = "private-migration-secret"

    with pytest.raises(SecAwareError) as exc_info:
        migrate_generation_request_v1_0_to_v1_1(payload)

    assert exc_info.value.code is ErrorCode.CONTRACT
    surface = str(exc_info.value) + repr(exc_info.value.to_dict())
    assert "private_api_key" not in surface
    assert "private-migration-secret" not in surface


def test_v10_migration_failure_clears_payload_and_endpoint_from_frames() -> None:
    payload_sentinel = "migration-payload-frame-secret"
    endpoint_sentinel = "migration-endpoint-frame-secret"
    payload = _legacy_payload()
    payload["private_api_key"] = payload_sentinel

    with pytest.raises(SecAwareError) as exc_info:
        migrate_generation_request_v1_0_to_v1_1(
            payload,
            endpoint_identity=endpoint_sentinel,
        )

    retained = ""
    cursor = exc_info.value.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained += repr(cursor.tb_frame.f_locals)
        cursor = cursor.tb_next
    assert payload_sentinel not in retained
    assert endpoint_sentinel not in retained


def test_package_version_is_bumped_for_manifest_fingerprint_invalidation() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"

    assert __version__ == "0.2.0"
    assert 'version = "0.2.0"' in pyproject.read_text(encoding="utf-8")

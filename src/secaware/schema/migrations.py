from typing import Any, Mapping

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationRequestRecord,
    build_generation_request_id,
    sha256_text,
)


_GENERATION_REQUEST_V1_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "condition",
        "prompt_id",
        "prompt",
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
    }
)


def require_v1_payload(payload: Mapping[str, Any]) -> None:
    received_version = payload.get("schema_version")
    if received_version != SCHEMA_VERSION:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="migration",
            message="payload must declare schema_version 1.0",
            details={
                "expected_schema_version": SCHEMA_VERSION,
                "received_schema_version": received_version,
            },
            retryable=False,
        )


def migrate_generation_request_v1_0_to_v1_1(
    payload: Mapping[str, Any],
) -> GenerationRequestRecord:
    """Explicitly migrate a canonical v1.0 request into endpoint-bound v1.1."""

    try:
        if not isinstance(payload, Mapping):
            raise TypeError
        snapshot = dict(payload)
        if set(snapshot) != _GENERATION_REQUEST_V1_FIELDS:
            raise ValueError
        if snapshot["schema_version"] != "1.0":
            raise ValueError
        endpoint_type = snapshot["endpoint_type"]
        if type(endpoint_type) is not str:
            raise TypeError
        parameters = GenerationParameters.model_validate(snapshot["parameters"])
        endpoint_sha256 = sha256_text(endpoint_type)
        migrated = {
            **snapshot,
            "schema_version": GENERATION_REQUEST_SCHEMA_VERSION,
            "endpoint_sha256": endpoint_sha256,
            "parameters": parameters,
        }
        migrated["request_id"] = build_generation_request_id(
            schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
            condition=migrated["condition"],
            prompt_id=migrated["prompt_id"],
            prompt_sha256=migrated["prompt_sha256"],
            language=migrated["language"],
            model_id=migrated["model_id"],
            seed_id=migrated["seed_id"],
            hypothesis_id=migrated["hypothesis_id"],
            intervention_id=migrated["intervention_id"],
            endpoint_type=migrated["endpoint_type"],
            endpoint_sha256=endpoint_sha256,
            system_template_version=migrated["system_template_version"],
            system_template_sha256=migrated["system_template_sha256"],
            parameters=parameters,
        )
        return GenerationRequestRecord.model_validate(migrated)
    except Exception:
        pass
    payload = {}
    raise SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="migration",
        message="generation request v1.0 migration failed validation",
    ) from None

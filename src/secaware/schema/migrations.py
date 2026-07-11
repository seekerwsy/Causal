import hashlib
import json
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
_GENERATION_REQUEST_V1_IDENTITY_FIELDS = (
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


def _build_generation_request_v1_id(identity: Mapping[str, Any]) -> str:
    payload = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"req_{hashlib.sha256(payload).hexdigest()}"


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
    *,
    endpoint_identity: str | None = None,
) -> GenerationRequestRecord:
    """Explicitly migrate a canonical v1.0 request into endpoint-bound v1.1."""

    snapshot: dict[str, Any] = {}
    legacy_identity: dict[str, Any] = {}
    migrated: dict[str, Any] = {}
    parameters: GenerationParameters | None = None
    condition: object = None
    hypothesis_id: object = None
    intervention_id: object = None
    endpoint_type: str | None = None
    endpoint_identity_value: str | None = None
    endpoint_sha256: str | None = None
    result: GenerationRequestRecord | None = None
    migration_failed = False
    try:
        try:
            if not isinstance(payload, Mapping):
                raise TypeError
            snapshot = dict(payload)
            if set(snapshot) != _GENERATION_REQUEST_V1_FIELDS:
                raise ValueError
            if snapshot["schema_version"] != "1.0":
                raise ValueError

            parameters = GenerationParameters.model_validate(snapshot["parameters"])
            if snapshot["prompt_sha256"] != sha256_text(snapshot["prompt"]):
                raise ValueError
            condition = snapshot["condition"]
            hypothesis_id = snapshot["hypothesis_id"]
            intervention_id = snapshot["intervention_id"]
            if condition == "observed":
                if hypothesis_id is not None or intervention_id is not None:
                    raise ValueError
            elif condition == "counterfactual":
                if (
                    type(hypothesis_id) is not str
                    or not hypothesis_id.strip()
                    or type(intervention_id) is not str
                    or not intervention_id.strip()
                ):
                    raise ValueError
            else:
                raise ValueError

            legacy_identity = {
                key: (
                    parameters.model_dump(mode="json")
                    if key == "parameters"
                    else snapshot[key]
                )
                for key in _GENERATION_REQUEST_V1_IDENTITY_FIELDS
            }
            if snapshot["request_id"] != _build_generation_request_v1_id(
                legacy_identity
            ):
                raise ValueError

            endpoint_type = snapshot["endpoint_type"]
            if type(endpoint_type) is not str:
                raise TypeError
            if endpoint_identity is None:
                if endpoint_type == "chat_completions":
                    raise ValueError
                endpoint_identity_value = endpoint_type
            else:
                if (
                    type(endpoint_identity) is not str
                    or not endpoint_identity
                    or endpoint_identity != endpoint_identity.strip()
                ):
                    raise ValueError
                endpoint_identity_value = endpoint_identity
            endpoint_sha256 = sha256_text(endpoint_identity_value)
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
            result = GenerationRequestRecord.model_validate(migrated)
        except Exception:
            migration_failed = True
    finally:
        snapshot.clear()
        legacy_identity.clear()
        migrated.clear()
        payload = {}
        endpoint_identity = None
        endpoint_identity_value = None
        endpoint_sha256 = None
        endpoint_type = None
        condition = None
        hypothesis_id = None
        intervention_id = None
        parameters = None
    if migration_failed or result is None:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="migration",
            message="generation request v1.0 migration failed validation",
        ) from None
    return result

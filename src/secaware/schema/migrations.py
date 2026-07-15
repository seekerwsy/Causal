import hashlib
import json
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationRequestRecord,
    build_generation_request_id,
    sha256_text,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord


class LegacyGenerationRegenerationRequired(SecAwareError):
    """A valid legacy counterfactual cannot cross into the canonical v1.2 ledger."""

    def __init__(self) -> None:
        super().__init__(
            code=ErrorCode.CONTRACT,
            stage="migration",
            message="legacy counterfactual generation requires regeneration",
        )


class _LegacyGenerationRequestV11(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)

    schema_version: Literal["1.1"]
    request_id: str
    condition: Literal["observed", "counterfactual"]
    prompt_id: str
    prompt: str = Field(repr=False)
    prompt_sha256: str
    language: str
    model_id: str
    seed_id: StrictInt
    hypothesis_id: str | None
    intervention_id: str | None
    endpoint_type: Literal["offline", "mock", "chat_completions"]
    endpoint_sha256: str
    system_template_version: str
    system_template_sha256: str
    parameters: GenerationParameters


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
_GENERATION_REQUEST_V11_IDENTITY_FIELDS = (
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
    "endpoint_sha256",
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


def _build_generation_request_v1_1_id(identity: Mapping[str, Any]) -> str:
    legacy_identity = {
        key: (
            identity[key].model_dump(mode="json")
            if key == "parameters" and isinstance(identity[key], GenerationParameters)
            else identity[key]
        )
        for key in _GENERATION_REQUEST_V11_IDENTITY_FIELDS
    }
    return _build_generation_request_v1_id(legacy_identity)


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


def migrate_generation_request_v1_0_to_v1_2(
    payload: Mapping[str, Any],
    *,
    endpoint_identity: str | None = None,
) -> GenerationRequestRecord:
    """Migrate a valid legacy observed v1.0 request directly into canonical v1.2."""

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
                key: (parameters.model_dump(mode="json") if key == "parameters" else snapshot[key])
                for key in _GENERATION_REQUEST_V1_IDENTITY_FIELDS
            }
            if snapshot["request_id"] != _build_generation_request_v1_id(legacy_identity):
                raise ValueError
            if condition == "counterfactual":
                raise LegacyGenerationRegenerationRequired()

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
                "assignment_id": None,
                "target_spec_id": None,
                "target_instance_id": None,
                "arm_protocol_id": None,
                "protocol_instance_id": None,
                "variant_id": None,
                "arm_role": None,
            }
            migrated.pop("intervention_id", None)
            migrated["request_id"] = build_generation_request_id(
                schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
                condition=migrated["condition"],
                prompt_id=migrated["prompt_id"],
                prompt_sha256=migrated["prompt_sha256"],
                language=migrated["language"],
                model_id=migrated["model_id"],
                seed_id=migrated["seed_id"],
                hypothesis_id=migrated["hypothesis_id"],
                endpoint_type=migrated["endpoint_type"],
                endpoint_sha256=endpoint_sha256,
                system_template_version=migrated["system_template_version"],
                system_template_sha256=migrated["system_template_sha256"],
                parameters=parameters,
            )
            result = GenerationRequestRecord.model_validate(migrated)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except LegacyGenerationRegenerationRequired:
            raise
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


# Compatibility name retained only for callers discovering the legacy migration entrypoint.
migrate_generation_request_v1_0_to_v1_1 = migrate_generation_request_v1_0_to_v1_2


def migrate_generation_request_v1_1_to_v1_2(
    payload: Mapping[str, Any],
) -> GenerationRequestRecord:
    """Migrate only legacy observed requests; old counterfactuals must be regenerated."""
    snapshot: dict[str, Any] = {}
    current: dict[str, Any] = {}
    legacy: _LegacyGenerationRequestV11 | None = None
    result: GenerationRequestRecord | None = None
    failure: SecAwareError | None = None
    try:
        snapshot = dict(payload)
        legacy = _LegacyGenerationRequestV11.model_validate(snapshot)
        expected_id = _build_generation_request_v1_1_id(legacy.model_dump(mode="python"))
        if legacy.request_id != expected_id or legacy.prompt_sha256 != sha256_text(legacy.prompt):
            raise ValueError
        if legacy.condition == "counterfactual":
            if not legacy.hypothesis_id or not legacy.intervention_id:
                raise ValueError
            failure = LegacyGenerationRegenerationRequired()
        elif legacy.hypothesis_id is not None or legacy.intervention_id is not None:
            raise ValueError
        else:
            current = legacy.model_dump(mode="python")
            current.pop("intervention_id", None)
            current["parameters"] = legacy.parameters
            current.update(
                schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
                assignment_id=None,
                target_spec_id=None,
                target_instance_id=None,
                arm_protocol_id=None,
                protocol_instance_id=None,
                variant_id=None,
                arm_role=None,
            )
            current["request_id"] = build_generation_request_id(
                **{
                    key: value
                    for key, value in current.items()
                    if key not in {"request_id", "prompt"}
                }
            )
            result = GenerationRequestRecord.model_validate(current)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError as error:
        failure = error
    except Exception:
        failure = SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="migration",
            message="generation request v1.1 migration failed validation",
        )
    finally:
        payload = {}
        snapshot.clear()
        current.clear()
        legacy = None
    if failure is not None:
        raise failure from None
    if result is None:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="migration",
            message="generation request v1.1 migration failed validation",
        ) from None
    return result


def migrate_generated_code_v1_0_to_v1_1(
    payload: Mapping[str, Any],
) -> CanonicalGeneratedCodeRecord:
    """Migrate a complete legacy observed code bridge; counterfactuals regenerate."""

    snapshot: dict[str, Any] = {}
    legacy_request: dict[str, Any] = {}
    request: GenerationRequestRecord | None = None
    provenance = None
    code = ""
    result: CanonicalGeneratedCodeRecord | None = None
    failed = False
    try:
        snapshot = dict(payload)
        expected_fields = {
            "code_id",
            "prompt_id",
            "condition",
            "model_id",
            "seed_id",
            "code",
            "hypothesis_id",
            "intervention_id",
            "schema_version",
            "request_id",
            "prompt_sha256",
            "code_sha256",
            "generation_provenance",
            "generation_request",
        }
        if set(snapshot) != expected_fields or snapshot.get("schema_version") != "1.0":
            raise ValueError
        nested = snapshot.get("generation_request")
        if isinstance(nested, Mapping):
            legacy_request = dict(nested)
        else:
            raise ValueError
        legacy_request_id = legacy_request["request_id"]
        if (
            snapshot["condition"] != legacy_request.get("condition")
            or snapshot["request_id"] != legacy_request_id
            or snapshot["code_id"] != f"code_{str(legacy_request_id).removeprefix('req_')}"
            or snapshot["prompt_id"] != legacy_request.get("prompt_id")
            or snapshot["prompt_sha256"] != legacy_request.get("prompt_sha256")
            or snapshot["model_id"] != legacy_request.get("model_id")
            or snapshot["seed_id"] != legacy_request.get("seed_id")
            or snapshot["hypothesis_id"] != legacy_request.get("hypothesis_id")
            or snapshot["intervention_id"] != legacy_request.get("intervention_id")
            or snapshot["code_sha256"] != sha256_text(snapshot["code"])
        ):
            raise ValueError
        if legacy_request.get("schema_version") == "1.0":
            request = migrate_generation_request_v1_0_to_v1_2(legacy_request)
        elif legacy_request.get("schema_version") == "1.1":
            request = migrate_generation_request_v1_1_to_v1_2(legacy_request)
        else:
            raise ValueError
        if snapshot["condition"] != "observed" or request.condition != "observed":
            raise LegacyGenerationRegenerationRequired()
        if snapshot["hypothesis_id"] is not None or snapshot["intervention_id"] is not None:
            raise ValueError
        provenance = snapshot.get("generation_provenance")
        code = snapshot["code"]
        from secaware.generation.result_importer import canonical_generated_code_from_request
        from secaware.schema.generation import GenerationProvenance

        result = canonical_generated_code_from_request(
            request,
            code,
            GenerationProvenance.model_validate(provenance),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except LegacyGenerationRegenerationRequired:
        raise
    except Exception:
        failed = True
    finally:
        payload = {}
        snapshot.clear()
        legacy_request.clear()
        request = None
        provenance = None
        code = ""
        nested = None
    if failed or result is None:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="migration",
            message="generated code v1.0 migration failed validation",
        ) from None
    return result

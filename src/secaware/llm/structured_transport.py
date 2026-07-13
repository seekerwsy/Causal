"""Byte-locked, one-response transport for structured LLM calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import time
from typing import Any, Protocol
import unicodedata

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.openai_compatible_provider import _classify_failure


_STAGE = "llm.structured_transport"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MISSING = object()
_MAX_REQUEST_BYTES = 4_000_000
_MAX_MODEL_ID_BYTES = 1024
_MAX_TIMEOUT_SECONDS = 3600.0
_MAX_ATTEMPTS = 10
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_JSON_DEPTH = 64
_MIN_SEED = -(2**63)
_MAX_SEED = 2**63 - 1
_INITIAL_BACKOFF_SECONDS = 1.0
_MAX_BACKOFF_SECONDS = 30.0
_MESSAGE_FIELDS = frozenset(
    {
        "annotations",
        "audio",
        "content",
        "function_call",
        "refusal",
        "role",
        "tool_calls",
    }
)


def _transport_error(
    code: ErrorCode,
    message: str,
    *,
    retryable: bool = False,
) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        retryable=retryable,
    )


class StructuredJSONTransport(Protocol):
    def complete(self, request_bytes: bytes, policy: "StructuredLLMPolicy") -> bytes:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class StructuredLLMPolicy:
    endpoint_sha256: str
    model_id: str
    system_template_sha256: str
    output_schema_sha256: str
    temperature: float
    top_p: float
    seed: int | None
    timeout_seconds: float
    max_attempts: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        hashes = (
            self.endpoint_sha256,
            self.system_template_sha256,
            self.output_schema_sha256,
        )
        if any(type(value) is not str or _SHA256.fullmatch(value) is None for value in hashes):
            raise ValueError("structured LLM policy validation failed")
        if (
            type(self.model_id) is not str
            or not self.model_id.strip()
            or self.model_id != self.model_id.strip()
            or len(self.model_id.encode("utf-8")) > _MAX_MODEL_ID_BYTES
            or any(unicodedata.category(character).startswith("C") for character in self.model_id)
        ):
            raise ValueError("structured LLM policy validation failed")
        numeric = (self.temperature, self.top_p, self.timeout_seconds)
        if any(type(value) is not float or not math.isfinite(value) for value in numeric):
            raise ValueError("structured LLM policy validation failed")
        if not 0.0 <= self.temperature <= 2.0 or not 0.0 < self.top_p <= 1.0:
            raise ValueError("structured LLM policy validation failed")
        if not 0.0 < self.timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise ValueError("structured LLM policy validation failed")
        if self.seed is not None and (
            type(self.seed) is not int or not _MIN_SEED <= self.seed <= _MAX_SEED
        ):
            raise ValueError("structured LLM policy validation failed")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= _MAX_ATTEMPTS:
            raise ValueError("structured LLM policy validation failed")
        if (
            type(self.max_response_bytes) is not int
            or not 1 <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise ValueError("structured LLM policy validation failed")


def _json_snapshot(value: object, *, depth: int, active: set[int]) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError
        return value
    if type(value) is str:
        value.encode("utf-8")
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ValueError
        active.add(identity)
        try:
            result: dict[str, object] = {}
            for item in value.items():
                if type(item) not in {tuple, list} or len(item) != 2:
                    raise ValueError
                key, nested = item
                if type(key) is not str or key in result:
                    raise ValueError
                key.encode("utf-8")
                result[key] = _json_snapshot(nested, depth=depth + 1, active=active)
            return result
        finally:
            active.discard(identity)
    if type(value) in {list, tuple}:
        identity = id(value)
        if identity in active:
            raise ValueError
        active.add(identity)
        try:
            return [_json_snapshot(item, depth=depth + 1, active=active) for item in value]
        finally:
            active.discard(identity)
    raise ValueError


def canonical_request_bytes(payload: Mapping[str, object]) -> bytes:
    """Snapshot a strict JSON mapping and encode deterministic UTF-8 bytes."""
    result = b""
    failed = False
    snapshot: object = None
    try:
        snapshot = _json_snapshot(payload, depth=0, active=set())
        if type(snapshot) is not dict:
            raise ValueError
        result = json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        failed = True
    finally:
        payload = {}
        snapshot = None
    if failed:
        error = ValueError("structured request payload validation failed")
        error.__cause__ = None
        error.__context__ = None
        raise error from None
    return result


def _member(value: object, name: str, default: object = _MISSING) -> object:
    try:
        if isinstance(value, Mapping):
            if default is _MISSING:
                return value[name]
            return value.get(name, default)
        if default is _MISSING:
            return getattr(value, name)
        return getattr(value, name, default)
    except Exception:
        if default is _MISSING:
            raise
        return default
    finally:
        value = None
        name = ""
        default = None


def _message_snapshot(message: object) -> dict[str, object]:
    if isinstance(message, Mapping):
        snapshot = dict(message)
    else:
        model_dump = getattr(message, "model_dump", None)
        if callable(model_dump):
            candidate = model_dump()
            if not isinstance(candidate, Mapping):
                raise ValueError
            snapshot = dict(candidate)
        else:
            snapshot = {
                key: value
                for key, value in vars(message).items()
                if type(key) is str and not key.startswith("_")
            }
    if any(type(key) is not str for key in snapshot) or not set(snapshot) <= _MESSAGE_FIELDS:
        raise ValueError
    return snapshot


def _empty_auxiliary(value: object) -> bool:
    return value is None or value == "" or (type(value) in {list, tuple} and len(value) == 0)


def _stopped_text_bytes(response: object, maximum: int) -> bytes:
    choices: object = None
    choice: object = None
    message: object = None
    content: object = None
    message_payload: dict[str, object] = {}
    encoded = b""
    try:
        choices = _member(response, "choices")
        if (
            isinstance(choices, (str, bytes))
            or not isinstance(choices, Sequence)
            or len(choices) != 1
        ):
            raise ValueError
        choice = choices[0]
        if _member(choice, "finish_reason") != "stop":
            raise ValueError
        message = _member(choice, "message")
        message_payload = _message_snapshot(message)
        if message_payload.get("role") != "assistant":
            raise ValueError
        for field in (
            "annotations",
            "audio",
            "function_call",
            "refusal",
            "tool_calls",
        ):
            if field in message_payload and not _empty_auxiliary(message_payload[field]):
                raise ValueError
        content = message_payload.get("content")
        if type(content) is not str or not content.strip():
            raise ValueError
        encoded = content.encode("utf-8")
        if len(encoded) > maximum:
            raise ValueError
        return encoded
    finally:
        response = None
        choices = None
        choice = None
        message = None
        message_payload = {}
        content = None
        encoded = b""


def _validated_request_text(request_bytes: object) -> str:
    if (
        type(request_bytes) is not bytes
        or not request_bytes
        or len(request_bytes) > _MAX_REQUEST_BYTES
    ):
        raise _transport_error(ErrorCode.CONTRACT, "structured request validation failed")
    failure: SecAwareError | None = None
    result = ""
    text = ""
    payload: object = None
    try:
        text = request_bytes.decode("utf-8")
        payload = json.loads(text)
        if not isinstance(payload, Mapping):
            raise ValueError
        if canonical_request_bytes(payload) != request_bytes:
            raise ValueError
        result = text
    except Exception:
        failure = _transport_error(
            ErrorCode.CONTRACT,
            "structured request validation failed",
        )
    finally:
        request_bytes = b""
        text = ""
        payload = None
    if failure is not None:
        raise failure from None
    return result


class OpenAICompatibleStructuredTransport:
    """Call an OpenAI-compatible chat-completions client with a locked payload."""

    __slots__ = (
        "_client",
        "_endpoint_sha256",
        "_sleeper",
        "_system_template",
        "_system_template_sha256",
    )

    def __init__(
        self,
        *,
        base_url: str,
        api_key_env: str,
        system_template: str,
        client: object | None = None,
        environ: Mapping[str, str] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        environment: Mapping[str, str] | None = None
        api_key: str | None = None
        candidate: object = None
        sdk_factory: Callable[..., object] | None = None
        failure: SecAwareError | None = None
        try:
            if (
                type(base_url) is not str
                or not base_url.strip()
                or base_url != base_url.strip()
                or type(api_key_env) is not str
                or _ENVIRONMENT_NAME.fullmatch(api_key_env) is None
                or type(system_template) is not str
                or not system_template.strip()
                or not callable(sleeper)
            ):
                failure = _transport_error(
                    ErrorCode.CONFIG,
                    "structured transport configuration is unavailable",
                )
            if failure is None:
                system_template.encode("utf-8")
            if failure is None and client is None:
                environment = os.environ if environ is None else environ
                try:
                    candidate = environment[api_key_env]
                    if type(candidate) is str and candidate.strip():
                        api_key = candidate
                except Exception:
                    pass
                candidate = None
                if api_key is None:
                    failure = _transport_error(
                        ErrorCode.API_AUTH,
                        "structured transport credentials are unavailable",
                    )
            if failure is None and client is None:
                try:
                    from openai import OpenAI as sdk_factory

                    client = sdk_factory(api_key=api_key, base_url=base_url, max_retries=0)
                except Exception:
                    failure = _transport_error(
                        ErrorCode.CONFIG,
                        "structured transport client creation failed",
                    )
            if failure is None:
                self._client = client
                self._endpoint_sha256 = hashlib.sha256(base_url.encode("utf-8")).hexdigest()
                self._system_template = system_template
                self._system_template_sha256 = hashlib.sha256(
                    system_template.encode("utf-8")
                ).hexdigest()
                self._sleeper = sleeper
        except Exception:
            failure = _transport_error(
                ErrorCode.CONFIG,
                "structured transport configuration is unavailable",
            )
        finally:
            environment = None
            api_key = None
            candidate = None
            sdk_factory = None
            base_url = ""
            api_key_env = ""
            system_template = ""
            environ = None
            client = None
            sleeper = None  # type: ignore[assignment]
        if failure is not None:
            failure.__cause__ = None
            failure.__context__ = None
            raise failure from None

    def __repr__(self) -> str:
        return "OpenAICompatibleStructuredTransport()"

    def complete(self, request_bytes: bytes, policy: StructuredLLMPolicy) -> bytes:
        request_text = ""
        messages: list[dict[str, str]] = []
        payload: dict[str, Any] = {}
        response: object = None
        result: bytes | None = None
        failure: SecAwareError | None = None
        trusted: StructuredLLMPolicy | None = None
        try:
            if type(policy) is not StructuredLLMPolicy:
                failure = _transport_error(
                    ErrorCode.CONTRACT,
                    "structured policy validation failed",
                )
            if failure is None:
                try:
                    trusted = StructuredLLMPolicy(
                        **{
                            field: getattr(policy, field)
                            for field in StructuredLLMPolicy.__dataclass_fields__
                        }
                    )
                except Exception:
                    failure = _transport_error(
                        ErrorCode.CONTRACT,
                        "structured policy validation failed",
                    )
            if (
                failure is None
                and trusted is not None
                and (
                    trusted.endpoint_sha256 != self._endpoint_sha256
                    or trusted.system_template_sha256 != self._system_template_sha256
                )
            ):
                failure = _transport_error(
                    ErrorCode.POLICY_MISMATCH,
                    "structured transport policy does not match its configuration",
                )
            if failure is None:
                try:
                    request_text = _validated_request_text(request_bytes)
                except Exception:
                    failure = _transport_error(
                        ErrorCode.CONTRACT,
                        "structured request validation failed",
                    )
            if trusted is None:
                max_attempts = 0
            else:
                max_attempts = trusted.max_attempts
            for attempt in range(1, max_attempts + 1):
                if failure is not None or trusted is None:
                    break
                messages = [
                    {"role": "system", "content": self._system_template},
                    {"role": "user", "content": request_text},
                ]
                payload = {
                    "model": trusted.model_id,
                    "messages": messages,
                    "temperature": trusted.temperature,
                    "top_p": trusted.top_p,
                    "seed": trusted.seed,
                    "n": 1,
                    "response_format": {"type": "json_object"},
                    "timeout": trusted.timeout_seconds,
                }
                response = None
                classification = None
                try:
                    response = self._client.chat.completions.create(**payload)  # type: ignore[attr-defined]
                except Exception as error:
                    classification = _classify_failure(error)
                if classification is not None:
                    if not classification.retryable:
                        failure = _transport_error(
                            classification.code,
                            "structured provider request failed",
                        )
                        break
                    if attempt == max_attempts:
                        failure = _transport_error(
                            ErrorCode.API_RETRIES_EXHAUSTED,
                            "structured provider retry budget was exhausted",
                        )
                        break
                    delay = min(
                        _INITIAL_BACKOFF_SECONDS * (2 ** (attempt - 1)),
                        _MAX_BACKOFF_SECONDS,
                    )
                    scheduling_failed = False
                    try:
                        self._sleeper(delay)
                    except Exception:
                        scheduling_failed = True
                    if scheduling_failed:
                        failure = _transport_error(
                            ErrorCode.API_INVALID_RESPONSE,
                            "structured provider retry scheduling failed",
                        )
                        break
                    continue
                parsed: bytes | None = None
                try:
                    parsed = _stopped_text_bytes(response, trusted.max_response_bytes)
                except Exception:
                    failure = _transport_error(
                        ErrorCode.API_INVALID_RESPONSE,
                        "structured provider returned an invalid response",
                    )
                if failure is None and parsed is not None:
                    result = parsed
                break
        except Exception:
            failure = _transport_error(
                ErrorCode.API_INVALID_RESPONSE,
                "structured transport failed",
            )
        finally:
            request_bytes = b""
            policy = None  # type: ignore[assignment]
            request_text = ""
            messages = []
            payload = {}
            response = None
            trusted = None
        if failure is not None:
            failure.__cause__ = None
            failure.__context__ = None
            raise failure from None
        if result is None:
            raise _transport_error(
                ErrorCode.API_INVALID_RESPONSE,
                "structured transport failed",
            ) from None
        return result


__all__ = [
    "OpenAICompatibleStructuredTransport",
    "StructuredJSONTransport",
    "StructuredLLMPolicy",
    "canonical_request_bytes",
]

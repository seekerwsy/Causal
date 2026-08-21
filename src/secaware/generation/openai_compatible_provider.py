import hashlib
import importlib.metadata
import inspect
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from secaware.config import OpenAICompatibleConfig
from secaware.errors import ErrorCode, JSONValue, SecAwareError
from secaware.generation.source_extraction import (
    SOURCE_EXTRACTION_POLICY_SHA256,
    extract_generated_source,
)
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    ProviderUsageRecord,
    revalidate_generation_request_envelope,
    sha256_text,
)

_STAGE = "generation"
_PRODUCER = "openai_compatible"
_PRODUCER_VERSION = "chat_completions-python-envelope-v2"
_MISSING = object()
_NO_DEFAULT = object()
_MAX_TOKEN_PARAMETER_KEYS = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens"})
_EXTRA_BODY_PARAMETER_KEYS = frozenset({"max_completion_tokens", "reasoning_effort", "verbosity"})
GenerationAttemptRecorder = Callable[
    [str, int, dict[str, Any], object | None, BaseException | None],
    None,
]


@dataclass(frozen=True, slots=True, repr=False)
class OpenAICompatibleGenerationResult:
    code: str | None
    provenance: GenerationProvenance
    attempts: tuple[GenerationAttemptRecord, ...]
    usage: ProviderUsageRecord
    runtime_fingerprint_sha256: str
    finish_reason: str = "stop"

    def __post_init__(self) -> None:
        if (
            self.finish_reason not in {"stop", "content_filter", "length"}
            or (
                self.finish_reason == "stop"
                and (type(self.code) is not str or not self.code.strip())
            )
            or (self.finish_reason in {"content_filter", "length"} and self.code is not None)
        ):
            raise ValueError("provider result code failed validation")
        metadata_failed = False
        try:
            provenance = GenerationProvenance.model_validate(self.provenance)
            if type(self.attempts) is not tuple or not self.attempts:
                raise ValueError
            attempts = tuple(
                GenerationAttemptRecord.model_validate(attempt) for attempt in self.attempts
            )
            usage = ProviderUsageRecord.model_validate(self.usage)
            if (
                type(self.runtime_fingerprint_sha256) is not str
                or len(self.runtime_fingerprint_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in self.runtime_fingerprint_sha256
                )
            ):
                raise ValueError
        except Exception:
            metadata_failed = True
        if metadata_failed:
            raise ValueError("provider result metadata failed validation") from None
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(self, "usage", usage)

    def __repr__(self) -> str:
        return "OpenAICompatibleGenerationResult()"


@dataclass(frozen=True, slots=True)
class _FailureClassification:
    code: ErrorCode
    retryable: bool


def _provider_error(
    code: ErrorCode,
    message: str,
    *,
    attempts: Sequence[GenerationAttemptRecord] = (),
    retryable: bool = False,
) -> SecAwareError:
    details: dict[str, JSONValue] = {}
    if attempts:
        details["attempts"] = [
            {
                "attempt": attempt.attempt,
                "outcome": attempt.outcome,
                "error_code": attempt.error_code,
                "retryable": attempt.retryable,
                "backoff_seconds": attempt.backoff_seconds,
            }
            for attempt in attempts
        ]
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        details=details,
        retryable=retryable,
    )


def _trusted_config(value: object) -> OpenAICompatibleConfig:
    trusted: OpenAICompatibleConfig | None = None
    try:
        if type(value) is not OpenAICompatibleConfig:
            raise TypeError
        trusted = OpenAICompatibleConfig.model_validate(value)
    except Exception:
        pass
    if trusted is None:
        value = None
        raise _provider_error(
            ErrorCode.CONFIG,
            "OpenAI-compatible provider configuration is unavailable",
        ) from None
    return trusted


def _status_code(error: Exception) -> int | None:
    try:
        value = getattr(error, "status_code", None)
    except Exception:
        return None
    return value if type(value) is int else None


def _exception_class_names(error: Exception) -> frozenset[str]:
    try:
        return frozenset(candidate.__name__.casefold() for candidate in type(error).__mro__)
    except Exception:
        return frozenset()


def _classify_failure(error: Exception) -> _FailureClassification:
    status_code = _status_code(error)
    if status_code in {401, 403}:
        return _FailureClassification(ErrorCode.API_AUTH, False)
    if status_code == 429:
        return _FailureClassification(ErrorCode.API_RATE_LIMIT, True)
    if status_code == 408:
        return _FailureClassification(ErrorCode.API_TIMEOUT, True)
    if status_code == 409 or (status_code is not None and 500 <= status_code <= 599):
        return _FailureClassification(ErrorCode.API_INVALID_RESPONSE, True)
    if status_code is not None:
        return _FailureClassification(ErrorCode.API_INVALID_RESPONSE, False)

    names = _exception_class_names(error)
    if names & {"authenticationerror", "permissiondeniederror"}:
        return _FailureClassification(ErrorCode.API_AUTH, False)
    if "ratelimiterror" in names:
        return _FailureClassification(ErrorCode.API_RATE_LIMIT, True)
    if any("timeout" in name for name in names):
        return _FailureClassification(ErrorCode.API_TIMEOUT, True)
    if any("connection" in name for name in names):
        return _FailureClassification(ErrorCode.API_TIMEOUT, True)
    return _FailureClassification(ErrorCode.API_INVALID_RESPONSE, False)


def _member(value: object, name: str, *, default: object = _NO_DEFAULT) -> object:
    try:
        if isinstance(value, Mapping):
            if default is _NO_DEFAULT:
                return value[name]
            return value.get(name, default)
        if default is _NO_DEFAULT:
            return getattr(value, name)
        return getattr(value, name, default)
    finally:
        value = None
        name = ""
        default = None


def _validate_usage(usage: object) -> ProviderUsageRecord:
    name = ""
    value: object = None
    try:
        if usage is _MISSING or usage is None:
            raise ValueError("missing token usage")
        values: dict[str, int] = {}
        for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = _member(usage, name)
            if type(value) is not int or value < 0:
                raise ValueError("invalid token usage")
            values[name] = value
        return ProviderUsageRecord.model_validate(values)
    finally:
        usage = None
        name = ""
        value = None
        values = {}


def _decode_python_source_envelope(content: str) -> tuple[str, str]:
    """Accept raw source or the first and only fenced Python source block."""

    closing_index: int | None = None
    decoded = ""
    lines: list[str] = []
    trailing = ""
    try:
        if type(content) is not str or not content.strip():
            raise ValueError("invalid message content")
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        if not normalized.startswith("```"):
            if "```" in normalized:
                raise ValueError("invalid Python source envelope")
            return content, "raw"
        lines = normalized.split("\n")
        if lines[0].lower() not in {"```python", "```py"} or len(lines) < 3:
            raise ValueError("invalid Python source envelope")
        closing_index = next(
            (index for index, line in enumerate(lines[1:], start=1) if line.rstrip(" \t") == "```"),
            None,
        )
        if closing_index is None or any(line.startswith("```") for line in lines[1:closing_index]):
            raise ValueError("invalid Python source envelope")
        decoded = "\n".join(lines[1:closing_index])
        if not decoded.strip():
            raise ValueError("invalid Python source envelope")
        trailing_lines = lines[closing_index + 1 :]
        if any(line.strip().lower() in {"```python", "```py"} for line in trailing_lines):
            raise ValueError("invalid Python source envelope")
        trailing = "\n".join(trailing_lines)
        envelope = "python_fence_trailing_text" if trailing.strip() else "python_fence"
        return decoded, envelope
    finally:
        content = ""
        closing_index = None
        decoded = ""
        lines.clear()
        lines = []
        trailing = ""
        trailing_lines = []


def _response_code(
    response: object, *, expected_model: str, system_template_version: str
) -> tuple[str | None, str, ProviderUsageRecord, str | None, str]:
    choices: object = None
    choice: object = None
    finish_reason: object = None
    message: object = None
    content: object = None
    raw_content_sha256: str | None = None
    source_envelope = ""
    actual_model: object = None
    try:
        actual_model = _member(response, "model")
        if (
            type(expected_model) is not str
            or not expected_model.strip()
            or type(actual_model) is not str
            or not actual_model.strip()
            or actual_model != expected_model
        ):
            raise ValueError("invalid response model")
        choices = _member(response, "choices")
        if (
            isinstance(choices, (str, bytes))
            or not isinstance(choices, Sequence)
            or len(choices) != 1
        ):
            raise ValueError("invalid choices")
        choice = choices[0]
        finish_reason = _member(choice, "finish_reason")
        if type(finish_reason) is not str or finish_reason not in {
            "stop",
            "content_filter",
            "length",
        }:
            raise ValueError("invalid finish reason")
        message = _member(choice, "message")
        content = _member(message, "content")
        if finish_reason == "stop":
            if type(content) is not str:
                raise ValueError("invalid message content")
            raw_content_sha256 = sha256_text(content)
            if system_template_version == "multilingual-requested-artifact-v1":
                extraction = extract_generated_source(content)
                content = extraction.source
                source_envelope = (
                    f"requested_artifact_v1.{extraction.envelope}.{SOURCE_EXTRACTION_POLICY_SHA256}"
                )
            else:
                content, source_envelope = _decode_python_source_envelope(content)
        if finish_reason == "content_filter" and content not in {None, ""}:
            raise ValueError("invalid filtered content")
        if finish_reason == "length":
            if type(content) is not str:
                raise ValueError("invalid length-limited content")
            raw_content_sha256 = sha256_text(content)
        usage = _validate_usage(_member(response, "usage", default=_MISSING))
        return (
            content if finish_reason == "stop" else None,
            finish_reason,
            usage,
            raw_content_sha256,
            (
                source_envelope
                if finish_reason == "stop"
                else "content_filter"
                if finish_reason == "content_filter"
                else "token_limit"
            ),
        )
    finally:
        response = None
        expected_model = ""
        actual_model = None
        choices = None
        choice = None
        finish_reason = None
        message = None
        content = None
        raw_content_sha256 = None
        source_envelope = ""
        usage = None


def _wire_parameters(parameters: Mapping[str, JSONValue]) -> dict[str, Any]:
    remaining: dict[str, Any] = dict(parameters)
    extra_body: dict[str, Any] = {}

    max_output_tokens = remaining.pop("max_output_tokens", _MISSING)
    if max_output_tokens is not _MISSING:
        extra_body["max_completion_tokens"] = max_output_tokens
    for key in _EXTRA_BODY_PARAMETER_KEYS:
        value = remaining.pop(key, _MISSING)
        if value is not _MISSING:
            extra_body[key] = value

    if extra_body:
        remaining["extra_body"] = extra_body
    return remaining


class OpenAICompatibleProvider:
    __slots__ = (
        "_attempt_recorder",
        "_client",
        "_endpoint_sha256",
        "_initial_backoff_seconds",
        "_max_attempts",
        "_max_backoff_seconds",
        "_runtime_fingerprint_sha256",
        "_sleeper",
    )

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        *,
        client: object,
        sleeper: Callable[[float], None] = time.sleep,
        runtime_fingerprint_sha256: str | None = None,
        attempt_recorder: GenerationAttemptRecorder | None = None,
    ) -> None:
        trusted: OpenAICompatibleConfig | None = None
        initialization_error: SecAwareError | None = None
        try:
            trusted = _trusted_config(config)
        except SecAwareError as error:
            initialization_error = error
        if initialization_error is not None or trusted is None:
            if initialization_error is None:
                initialization_error = _provider_error(
                    ErrorCode.CONFIG,
                    "OpenAI-compatible provider configuration is unavailable",
                )
            config = None  # type: ignore[assignment]
            trusted = None
            client = None
            sleeper = None  # type: ignore[assignment]
            raise initialization_error
        if not callable(sleeper):
            initialization_error = _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            )
            config = None  # type: ignore[assignment]
            trusted = None
            client = None
            sleeper = None  # type: ignore[assignment]
            raise initialization_error
        if attempt_recorder is not None and not callable(attempt_recorder):
            raise _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            )
        self._client = client
        self._endpoint_sha256 = sha256_text(trusted.base_url)
        self._max_attempts = trusted.max_attempts
        self._initial_backoff_seconds = trusted.initial_backoff_seconds
        self._max_backoff_seconds = trusted.max_backoff_seconds
        self._attempt_recorder = attempt_recorder
        self._sleeper = sleeper
        self._runtime_fingerprint_sha256 = (
            openai_provider_runtime_fingerprint()
            if runtime_fingerprint_sha256 is None
            else runtime_fingerprint_sha256
        )

    def __repr__(self) -> str:
        return "OpenAICompatibleProvider()"

    def _request(
        self,
        request: object,
        system_template: object,
    ) -> GenerationRequestRecord | None:
        trusted: GenerationRequestRecord | None = None
        try:
            trusted = revalidate_generation_request_envelope(request)
            if trusted.endpoint_type != "chat_completions":
                raise ValueError
            if trusted.endpoint_sha256 != self._endpoint_sha256:
                raise ValueError
            if type(system_template) is not str:
                raise TypeError
            if trusted.system_template_sha256 != sha256_text(system_template):
                raise ValueError
            if trusted.parameters.values.get("n", 1) != 1:
                raise ValueError
            if sum(key in trusted.parameters.values for key in _MAX_TOKEN_PARAMETER_KEYS) > 1:
                raise ValueError
        except Exception:
            trusted = None
        return trusted

    @staticmethod
    def _payload(
        request: GenerationRequestRecord,
        system_template: str,
    ) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if system_template:
            messages.append({"role": "system", "content": system_template})
        messages.append({"role": "user", "content": request.prompt})
        parameter_snapshot = request.parameters.model_dump(
            mode="json",
            warnings=False,
        )["values"]
        payload: dict[str, Any] = {
            "model": request.model_id,
            "messages": messages,
        }
        payload.update(_wire_parameters(parameter_snapshot))
        payload["seed"] = request.seed_id
        return payload

    @staticmethod
    def _attempt(
        request_id: str,
        attempt: int,
        outcome: str,
        *,
        error_code: ErrorCode | None,
        retryable: bool,
        backoff_seconds: float,
    ) -> GenerationAttemptRecord:
        return GenerationAttemptRecord(
            schema_version=SCHEMA_VERSION,
            request_id=request_id,
            attempt=attempt,
            outcome=outcome,  # type: ignore[arg-type]
            error_code=None if error_code is None else int(error_code),
            retryable=retryable,
            backoff_seconds=backoff_seconds,
        )

    def _generate(
        self,
        request: GenerationRequestRecord,
        system_template: str = "",
    ) -> OpenAICompatibleGenerationResult | SecAwareError:
        trusted: GenerationRequestRecord | None = None
        attempts: list[GenerationAttemptRecord] = []
        payload: dict[str, Any] = {}
        response: object = None
        transport_error: BaseException | None = None
        classification: _FailureClassification | None = None
        code: str | None = None
        finish_reason = ""
        usage: ProviderUsageRecord | None = None
        raw_content_sha256: str | None = None
        source_envelope = ""
        try:
            trusted = self._request(request, system_template)
            if trusted is None:
                return _provider_error(
                    ErrorCode.CONTRACT,
                    "generation request is incompatible with the provider",
                )

            for attempt_number in range(1, self._max_attempts + 1):
                payload = self._payload(trusted, system_template)
                response = _MISSING
                classification = None
                transport_error = None
                try:
                    response = self._client.chat.completions.create(**payload)  # type: ignore[attr-defined]
                except Exception as error:
                    transport_error = error
                    classification = _classify_failure(error)
                if self._attempt_recorder is not None:
                    recording_failed = False
                    try:
                        self._attempt_recorder(
                            trusted.request_id,
                            attempt_number,
                            dict(payload),
                            None if response is _MISSING else response,
                            transport_error,
                        )
                    except Exception:
                        recording_failed = True
                    finally:
                        transport_error = None
                    if recording_failed:
                        attempts.append(
                            self._attempt(
                                trusted.request_id,
                                attempt_number,
                                "failure",
                                error_code=ErrorCode.API_INVALID_RESPONSE,
                                retryable=False,
                                backoff_seconds=0.0,
                            )
                        )
                        return _provider_error(
                            ErrorCode.API_INVALID_RESPONSE,
                            "provider attempt recording failed",
                            attempts=attempts,
                        )
                if classification is not None:
                    if not classification.retryable:
                        attempts.append(
                            self._attempt(
                                trusted.request_id,
                                attempt_number,
                                "failure",
                                error_code=classification.code,
                                retryable=False,
                                backoff_seconds=0.0,
                            )
                        )
                        return _provider_error(
                            classification.code,
                            "provider request failed",
                            attempts=attempts,
                        )
                    if attempt_number == self._max_attempts:
                        attempts.append(
                            self._attempt(
                                trusted.request_id,
                                attempt_number,
                                "failure",
                                error_code=classification.code,
                                retryable=True,
                                backoff_seconds=0.0,
                            )
                        )
                        return _provider_error(
                            ErrorCode.API_RETRIES_EXHAUSTED,
                            "provider retry budget was exhausted",
                            attempts=attempts,
                        )

                    backoff_seconds = min(
                        self._initial_backoff_seconds * (2 ** (attempt_number - 1)),
                        self._max_backoff_seconds,
                    )
                    attempts.append(
                        self._attempt(
                            trusted.request_id,
                            attempt_number,
                            "retry",
                            error_code=classification.code,
                            retryable=True,
                            backoff_seconds=backoff_seconds,
                        )
                    )
                    sleep_failed = False
                    try:
                        self._sleeper(backoff_seconds)
                    except Exception:
                        sleep_failed = True
                    if sleep_failed:
                        return _provider_error(
                            ErrorCode.API_INVALID_RESPONSE,
                            "provider retry scheduling failed",
                            attempts=attempts,
                        )
                    continue

                code = None
                finish_reason = ""
                response_invalid = False
                try:
                    (
                        code,
                        finish_reason,
                        usage,
                        raw_content_sha256,
                        source_envelope,
                    ) = _response_code(
                        response,
                        expected_model=trusted.model_id,
                        system_template_version=trusted.system_template_version,
                    )
                except Exception:
                    response_invalid = True
                if not response_invalid and finish_reason == "length":
                    token_limits = [
                        value
                        for key, value in trusted.parameters.values.items()
                        if key in _MAX_TOKEN_PARAMETER_KEYS
                    ]
                    if (
                        len(token_limits) != 1
                        or type(token_limits[0]) is not int
                        or usage is None
                        or usage.completion_tokens != token_limits[0]
                    ):
                        response_invalid = True
                if response_invalid or (
                    code is None and finish_reason not in {"content_filter", "length"}
                ):
                    attempts.append(
                        self._attempt(
                            trusted.request_id,
                            attempt_number,
                            "failure",
                            error_code=ErrorCode.API_INVALID_RESPONSE,
                            retryable=False,
                            backoff_seconds=0.0,
                        )
                    )
                    return _provider_error(
                        ErrorCode.API_INVALID_RESPONSE,
                        "provider returned an invalid response",
                        attempts=attempts,
                    )

                attempts.append(
                    self._attempt(
                        trusted.request_id,
                        attempt_number,
                        "success",
                        error_code=None,
                        retryable=False,
                        backoff_seconds=0.0,
                    )
                )
                return OpenAICompatibleGenerationResult(
                    code=code,
                    provenance=GenerationProvenance(
                        producer=_PRODUCER,
                        producer_version=_PRODUCER_VERSION,
                        source_batch_id=(
                            source_envelope
                            if raw_content_sha256 is None
                            else f"{source_envelope}:{raw_content_sha256}"
                        ),
                    ),
                    attempts=tuple(attempts),
                    usage=usage,
                    runtime_fingerprint_sha256=self._runtime_fingerprint_sha256,
                    finish_reason=finish_reason,
                )

            return _provider_error(
                ErrorCode.API_RETRIES_EXHAUSTED,
                "provider retry budget was exhausted",
                attempts=attempts,
            )
        finally:
            trusted = None
            attempts = []
            payload = {}
            response = None
            transport_error = None
            classification = None
            code = None
            finish_reason = ""
            usage = None
            raw_content_sha256 = None
            source_envelope = ""
            request = None  # type: ignore[assignment]
            system_template = ""
            self = None  # type: ignore[assignment]

    def generate(
        self,
        request: GenerationRequestRecord,
        system_template: str = "",
    ) -> OpenAICompatibleGenerationResult:
        outcome: OpenAICompatibleGenerationResult | SecAwareError | None = None
        try:
            outcome = self._generate(request, system_template)
            if isinstance(outcome, SecAwareError):
                raise outcome
            return outcome
        finally:
            outcome = None
            self = None  # type: ignore[assignment]
            request = None  # type: ignore[assignment]
            system_template = ""


class _ReplayCompletions:
    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self._used = False

    def create(self, **_payload: object) -> dict[str, Any]:
        if self._used:
            raise RuntimeError("persisted generation response was replayed more than once")
        self._used = True
        return self._response


class _ReplayClient:
    def __init__(self, response: dict[str, Any]) -> None:
        completions = _ReplayCompletions(response)
        self.chat = type("ReplayChat", (), {"completions": completions})()


def create_replay_openai_compatible_provider(
    config: OpenAICompatibleConfig,
    response: dict[str, Any],
) -> OpenAICompatibleProvider:
    """Create a no-network provider over one persisted raw Chat Completions response."""

    trusted = _trusted_config(config)
    if type(response) is not dict:
        raise _provider_error(ErrorCode.CONTRACT, "persisted provider response is unavailable")
    snapshot = json.loads(json.dumps(response, ensure_ascii=False, allow_nan=False))
    if type(snapshot) is not dict:
        raise _provider_error(ErrorCode.CONTRACT, "persisted provider response is unavailable")
    return OpenAICompatibleProvider(
        trusted,
        client=_ReplayClient(snapshot),
        sleeper=lambda _seconds: None,
        runtime_fingerprint_sha256=openai_provider_runtime_fingerprint(),
    )


def openai_provider_runtime_payload() -> dict[str, str]:
    try:
        sdk_version = importlib.metadata.version("openai")
        provider_source = inspect.getsource(OpenAICompatibleProvider)
        factory_source = inspect.getsource(create_openai_compatible_provider)
        response_source = inspect.getsource(_response_code)
        usage_source = inspect.getsource(_validate_usage)
    except Exception:
        raise _provider_error(
            ErrorCode.CONFIG,
            "OpenAI-compatible provider runtime is unavailable",
        ) from None
    return {
        "openai_sdk_version": sdk_version,
        "provider_source_sha256": hashlib.sha256(provider_source.encode("utf-8")).hexdigest(),
        "factory_source_sha256": hashlib.sha256(factory_source.encode("utf-8")).hexdigest(),
        "response_source_sha256": hashlib.sha256(response_source.encode("utf-8")).hexdigest(),
        "usage_source_sha256": hashlib.sha256(usage_source.encode("utf-8")).hexdigest(),
        "response_policy": "versioned-python-v2-or-multilingual-requested-artifact-v1",
    }


def openai_provider_runtime_fingerprint() -> str:
    payload = json.dumps(
        openai_provider_runtime_payload(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def create_openai_compatible_provider(
    config: OpenAICompatibleConfig,
    *,
    environ: Mapping[str, str] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    attempt_recorder: GenerationAttemptRecorder | None = None,
) -> OpenAICompatibleProvider:
    trusted: OpenAICompatibleConfig | None = None
    config_error: SecAwareError | None = None
    factory_error: SecAwareError | None = None
    sdk_factory: Callable[..., object] | None = None
    openai_factory: Callable[..., object] | None = None
    environment: Mapping[str, str] | None = None
    api_key: str | None = None
    candidate: object = None
    client: object | None = None
    client_creation_failed = False
    provider: OpenAICompatibleProvider | None = None
    provider_error: SecAwareError | None = None
    runtime_fingerprint_sha256: str | None = None
    try:
        try:
            trusted = _trusted_config(config)
        except SecAwareError as error:
            config_error = error
        if config_error is not None or trusted is None:
            if config_error is not None:
                raise config_error
            raise _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            )
        if not callable(sleeper):
            factory_error = _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            )
            raise factory_error

        try:
            from openai import OpenAI as sdk_factory
        except Exception:
            pass
        openai_factory = sdk_factory
        if openai_factory is None:
            raise _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider SDK is unavailable",
            ) from None

        environment = os.environ if environ is None else environ
        try:
            candidate = environment[trusted.api_key_env]
            if type(candidate) is str and candidate.strip():
                api_key = candidate
        except Exception:
            pass
        candidate = None
        if api_key is None:
            raise _provider_error(
                ErrorCode.API_AUTH,
                "provider authentication is unavailable",
            ) from None

        try:
            client = openai_factory(
                api_key=api_key,
                base_url=trusted.base_url,
                timeout=trusted.timeout_seconds,
                max_retries=0,
            )
        except Exception:
            client_creation_failed = True
        if client_creation_failed or client is None:
            raise _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider client could not be created",
            ) from None

        try:
            runtime_fingerprint_sha256 = openai_provider_runtime_fingerprint()
            provider = OpenAICompatibleProvider(
                trusted,
                client=client,
                sleeper=sleeper,
                runtime_fingerprint_sha256=runtime_fingerprint_sha256,
                attempt_recorder=attempt_recorder,
            )
        except SecAwareError as error:
            provider_error = error
        except Exception:
            provider_error = _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider could not be created",
            )
        if provider_error is not None or provider is None:
            if provider_error is None:
                provider_error = _provider_error(
                    ErrorCode.CONFIG,
                    "OpenAI-compatible provider could not be created",
                )
            raise provider_error
        return provider
    finally:
        api_key = ""
        candidate = None
        environment = None
        environ = None
        config = None  # type: ignore[assignment]
        trusted = None  # type: ignore[assignment]
        client = None
        sleeper = None  # type: ignore[assignment]
        sdk_factory = None
        openai_factory = None
        provider = None
        config_error = None
        factory_error = None
        provider_error = None
        runtime_fingerprint_sha256 = None
        attempt_recorder = None


__all__ = [
    "OpenAICompatibleGenerationResult",
    "OpenAICompatibleProvider",
    "create_openai_compatible_provider",
    "create_replay_openai_compatible_provider",
    "openai_provider_runtime_fingerprint",
    "openai_provider_runtime_payload",
]

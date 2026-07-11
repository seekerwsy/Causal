from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import os
import time
from typing import Any

from secaware.config import OpenAICompatibleConfig
from secaware.errors import ErrorCode, JSONValue, SecAwareError
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    revalidate_generation_request_envelope,
    sha256_text,
)


_STAGE = "generation"
_PRODUCER = "openai_compatible"
_PRODUCER_VERSION = "chat_completions-v1"
_MISSING = object()
_NO_DEFAULT = object()


@dataclass(frozen=True, slots=True, repr=False)
class OpenAICompatibleGenerationResult:
    code: str
    provenance: GenerationProvenance
    attempts: tuple[GenerationAttemptRecord, ...]

    def __post_init__(self) -> None:
        if type(self.code) is not str or not self.code.strip():
            raise ValueError("provider result code failed validation")
        metadata_failed = False
        try:
            provenance = GenerationProvenance.model_validate(self.provenance)
            if type(self.attempts) is not tuple or not self.attempts:
                raise ValueError
            attempts = tuple(
                GenerationAttemptRecord.model_validate(attempt)
                for attempt in self.attempts
            )
        except Exception:
            metadata_failed = True
        if metadata_failed:
            raise ValueError("provider result metadata failed validation") from None
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "attempts", attempts)

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
    if isinstance(value, Mapping):
        if default is _NO_DEFAULT:
            return value[name]
        return value.get(name, default)
    if default is _NO_DEFAULT:
        return getattr(value, name)
    return getattr(value, name, default)


def _validate_usage(usage: object) -> None:
    if usage is _MISSING or usage is None:
        return
    for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = _member(usage, name)
        if type(value) is not int or value < 0:
            raise ValueError("invalid token usage")


def _response_code(response: object) -> str:
    choices = _member(response, "choices")
    if (
        isinstance(choices, (str, bytes))
        or not isinstance(choices, Sequence)
        or len(choices) != 1
    ):
        raise ValueError("invalid choices")
    choice = choices[0]
    finish_reason = _member(choice, "finish_reason")
    if type(finish_reason) is not str or finish_reason != "stop":
        raise ValueError("invalid finish reason")
    message = _member(choice, "message")
    content = _member(message, "content")
    if type(content) is not str or not content.strip():
        raise ValueError("invalid message content")
    _validate_usage(_member(response, "usage", default=_MISSING))
    return content


class OpenAICompatibleProvider:
    __slots__ = (
        "_client",
        "_initial_backoff_seconds",
        "_max_attempts",
        "_max_backoff_seconds",
        "_sleeper",
    )

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        *,
        client: object,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        trusted = _trusted_config(config)
        if not callable(sleeper):
            raise _provider_error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            )
        self._client = client
        self._max_attempts = trusted.max_attempts
        self._initial_backoff_seconds = trusted.initial_backoff_seconds
        self._max_backoff_seconds = trusted.max_backoff_seconds
        self._sleeper = sleeper

    def __repr__(self) -> str:
        return "OpenAICompatibleProvider()"

    @staticmethod
    def _request(
        request: object,
        system_template: object,
    ) -> GenerationRequestRecord | None:
        trusted: GenerationRequestRecord | None = None
        try:
            trusted = revalidate_generation_request_envelope(request)
            if trusted.endpoint_type != "chat_completions":
                raise ValueError
            if type(system_template) is not str:
                raise TypeError
            if trusted.system_template_sha256 != sha256_text(system_template):
                raise ValueError
            if trusted.parameters.values.get("n", 1) != 1:
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
        parameters = request.parameters.model_dump(
            mode="json",
            warnings=False,
        )["values"]
        payload: dict[str, Any] = {
            "model": request.model_id,
            "messages": messages,
        }
        payload.update(parameters)
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
        trusted = self._request(request, system_template)
        if trusted is None:
            return _provider_error(
                ErrorCode.CONTRACT,
                "generation request is incompatible with the provider",
            )
        attempts: list[GenerationAttemptRecord] = []

        for attempt_number in range(1, self._max_attempts + 1):
            payload = self._payload(trusted, system_template)
            response: object = _MISSING
            classification: _FailureClassification | None = None
            try:
                response = self._client.chat.completions.create(**payload)  # type: ignore[attr-defined]
            except Exception as error:
                classification = _classify_failure(error)
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

            code: str | None = None
            response_invalid = False
            try:
                code = _response_code(response)
            except Exception:
                response_invalid = True
            if response_invalid or code is None:
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
                ),
                attempts=tuple(attempts),
            )

        return _provider_error(
            ErrorCode.API_RETRIES_EXHAUSTED,
            "provider retry budget was exhausted",
            attempts=attempts,
        )

    def generate(
        self,
        request: GenerationRequestRecord,
        system_template: str = "",
    ) -> OpenAICompatibleGenerationResult:
        outcome = self._generate(request, system_template)
        if isinstance(outcome, SecAwareError):
            self = None  # type: ignore[assignment]
            request = None  # type: ignore[assignment]
            system_template = ""
            raise outcome
        return outcome


def create_openai_compatible_provider(
    config: OpenAICompatibleConfig,
    *,
    environ: Mapping[str, str] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> OpenAICompatibleProvider:
    trusted = _trusted_config(config)
    environment = os.environ if environ is None else environ
    api_key: str | None = None
    candidate: object = None
    try:
        candidate = environment[trusted.api_key_env]
        if type(candidate) is str and candidate.strip():
            api_key = candidate
    except Exception:
        pass
    candidate = None
    if api_key is None:
        config = None  # type: ignore[assignment]
        trusted = None  # type: ignore[assignment]
        environment = None  # type: ignore[assignment]
        environ = None
        raise _provider_error(
            ErrorCode.API_AUTH,
            "provider authentication is unavailable",
        ) from None

    openai_factory: Callable[..., object] | None = None
    try:
        from openai import OpenAI

        openai_factory = OpenAI
    except Exception:
        pass
    if openai_factory is None:
        api_key = ""
        config = None  # type: ignore[assignment]
        trusted = None  # type: ignore[assignment]
        environment = None  # type: ignore[assignment]
        environ = None
        raise _provider_error(
            ErrorCode.CONFIG,
            "OpenAI-compatible provider SDK is unavailable",
        ) from None

    client: object | None = None
    client_creation_failed = False
    try:
        client = openai_factory(
            api_key=api_key,
            base_url=trusted.base_url,
            timeout=trusted.timeout_seconds,
            max_retries=0,
        )
    except Exception:
        client_creation_failed = True
    finally:
        api_key = ""
        candidate = None
        environment = None  # type: ignore[assignment]
        environ = None
        config = None  # type: ignore[assignment]
    if client_creation_failed or client is None:
        trusted = None  # type: ignore[assignment]
        raise _provider_error(
            ErrorCode.CONFIG,
            "OpenAI-compatible provider client could not be created",
        ) from None

    return OpenAICompatibleProvider(
        trusted,
        client=client,
        sleeper=sleeper,
    )


__all__ = [
    "OpenAICompatibleGenerationResult",
    "OpenAICompatibleProvider",
    "create_openai_compatible_provider",
]

from collections.abc import Mapping
from enum import IntEnum
import re
from typing import Any, TypeAlias

from pydantic import JsonValue


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JsonValue

_REDACTED = "[REDACTED]"
_ALLOWED_TOKEN_USAGE_KEYS = frozenset(
    {
        "max_tokens",
        "min_tokens",
        "input_tokens",
        "output_tokens",
        "completion_tokens",
        "prompt_tokens",
        "total_tokens",
        "token_count",
        "max_completion_tokens",
        "max_output_tokens",
    }
)
_SENSITIVE_COMPACT_FRAGMENTS = (
    "apikey",
    "authorization",
    "auth",
    "bearer",
    "token",
    "secret",
    "password",
    "privatekey",
    "credential",
)


def _normalize_key(key: str) -> str:
    with_acronym_boundaries = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    with_word_boundaries = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", with_acronym_boundaries)
    return re.sub(r"[^a-z0-9]+", "_", with_word_boundaries.casefold()).strip("_")


def is_sensitive_key(key: str) -> bool:
    normalized = _normalize_key(key)
    if normalized in _ALLOWED_TOKEN_USAGE_KEYS:
        return False

    compact = normalized.replace("_", "")
    return any(fragment in compact for fragment in _SENSITIVE_COMPACT_FRAGMENTS)


_is_sensitive_key = is_sensitive_key


def _normalize_json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, JSONValue] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise TypeError("structured error detail keys must be strings")
            normalized[key] = (
                _REDACTED if is_sensitive_key(key) else _normalize_json_value(nested_value)
            )
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize_json_value(item) for item in value]
    raise TypeError(
        "structured error details only support strings, numbers, booleans, null, "
        "mappings, lists, and tuples"
    )


def _normalize_details(details: Mapping[str, object] | None) -> dict[str, JSONValue]:
    if details is None:
        return {}
    normalized = _normalize_json_value(details)
    if not isinstance(normalized, dict):  # pragma: no cover - guarded by the annotation
        raise TypeError("structured error details must be a mapping")
    return normalized


class ErrorCode(IntEnum):
    CONFIG = 2
    CONTRACT = 3
    EXTERNAL_INPUT_REQUIRED = 4

    API_AUTH = 20
    API_RATE_LIMIT = 21
    API_TIMEOUT = 22
    API_INVALID_RESPONSE = 23
    API_RETRIES_EXHAUSTED = 24

    ANALYZER_MISSING = 30
    ANALYZER_FAILED = 31
    ANALYZER_INVALID_OUTPUT = 32
    POLICY_MISMATCH = 33

    MANIFEST_CONFLICT = 40
    TSG_INVALID = 50
    ANALYSIS_INVALID = 60


class SecAwareError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        stage: str,
        message: str,
        details: Mapping[str, Any] | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = ErrorCode(code)
        self.stage = stage
        self.message = message
        self.details = _normalize_details(details)
        self.retryable = retryable

    def __str__(self) -> str:
        return f"[{self.code.name}] {self.stage}: {self.message}"

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "code": int(self.code),
            "stage": self.stage,
            "message": self.message,
            "details": _normalize_details(self.details),
            "retryable": self.retryable,
        }

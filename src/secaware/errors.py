from collections.abc import Mapping
from enum import IntEnum
from typing import Any, TypeAlias


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_FRAGMENTS = ("api_key", "authorization", "token", "secret", "password")


def _is_sensitive_key(key: str) -> bool:
    folded_key = key.casefold()
    return any(fragment in folded_key for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _normalize_json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, JSONValue] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise TypeError("structured error detail keys must be strings")
            normalized[key] = (
                _REDACTED if _is_sensitive_key(key) else _normalize_json_value(nested_value)
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

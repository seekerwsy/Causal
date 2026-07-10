from enum import IntEnum
from typing import Any, Mapping


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
        self.details = dict(details or {})
        self.retryable = retryable

    def __str__(self) -> str:
        return f"[{self.code.name}] {self.stage}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": int(self.code),
            "stage": self.stage,
            "message": self.message,
            "details": dict(self.details),
            "retryable": self.retryable,
        }

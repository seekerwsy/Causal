from typing import Any, Mapping

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SCHEMA_VERSION


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

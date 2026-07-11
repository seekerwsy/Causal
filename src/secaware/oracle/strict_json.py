from __future__ import annotations

import json
import math
from typing import Any


_INVALID_JSON = "strict JSON validation failed"


def _reject_constant(value: str) -> None:
    del value
    raise ValueError(_INVALID_JSON)


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        parsed = 0.0
        value = ""
        raise ValueError(_INVALID_JSON)
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError(_INVALID_JSON)
            result[key] = value
        return result
    finally:
        pairs = []
        key = ""
        value = None


def load_strict_json_bytes(payload: bytes) -> object:
    text = ""
    parsed: object = None
    try:
        if type(payload) is not bytes or not payload:
            raise ValueError(_INVALID_JSON)
        text = payload.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        return parsed
    finally:
        payload = b""
        text = ""
        parsed = None


__all__ = ["load_strict_json_bytes"]

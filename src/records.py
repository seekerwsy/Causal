"""Canonical, immutable record mechanics shared by the research method."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


def canonical_value(value: Any) -> Any:
    """Convert method records to a deterministic JSON-compatible value."""

    if is_dataclass(value) and not isinstance(value, type):
        return canonical_value({
            item.name: getattr(value, item.name) for item in fields(value)
            if not (item.metadata.get("omit_if_none") and getattr(value, item.name) is None)
        })
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("record keys must be strings")
        return {key: canonical_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not canonical")
        return value
    raise TypeError(f"unsupported record value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonical_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def content_id(prefix: str, value: Any) -> str:
    if not prefix or not prefix.endswith("_"):
        raise ValueError("content-id prefix must be non-empty and end in an underscore")
    return prefix + content_hash(value)


def require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be non-empty and trimmed")


def require_unique(values: Iterable[Any], name: str) -> tuple[Any, ...]:
    frozen = tuple(values)
    if len(frozen) != len(set(frozen)):
        raise ValueError(f"{name} must be unique")
    return frozen


def require_ordered_strings(values: tuple[str, ...], name: str) -> None:
    require_unique_strings(values, name)
    if tuple(sorted(values)) != values:
        raise ValueError(f"{name} must use canonical order")


def require_unique_strings(values: tuple[str, ...], name: str) -> None:
    if len(set(values)) != len(values) or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise ValueError(f"{name} must be unique non-empty strings")


__all__ = [
    "require_ordered_strings",
    "require_unique_strings",
    "canonical_json",
    "canonical_value",
    "content_hash",
    "content_id",
    "require_text",
    "require_unique",
]

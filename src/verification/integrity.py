"""Exact package identity, schema decoding, and index reconstruction."""


from __future__ import annotations
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints
from prompt_mechanism_study.artifact_io import read_json_exact


def _decode_target_file(path: Path, expected_type: type[Any]) -> Any:
    return _decode_target_value(read_json_exact(path), expected_type, path.name)


def _decode_target_value(value: Any, annotation: Any, path: str) -> Any:
    """Strictly reconstruct one known typed record without artifact-selected classes."""

    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is tuple:
        if not isinstance(value, list):
            raise ValueError(f"{path} must be a JSON array")
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return tuple(
                _decode_target_value(item, arguments[0], f"{path}[{index}]")
                for index, item in enumerate(value)
            )
        if len(value) != len(arguments):
            raise ValueError(f"{path} has the wrong fixed tuple length")
        return tuple(
            _decode_target_value(item, item_type, f"{path}[{index}]")
            for index, (item, item_type) in enumerate(zip(value, arguments, strict=True))
        )
    if origin in {UnionType, Union}:
        failures = []
        for option in arguments:
            try:
                return _decode_target_value(value, option, path)
            except (TypeError, ValueError) as error:
                failures.append(str(error))
        raise ValueError(f"{path} does not match its frozen union type: {failures}")
    if annotation is type(None):
        if value is not None:
            raise ValueError(f"{path} must be null")
        return None
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except (TypeError, ValueError):
            raise ValueError(f"{path} has an invalid {annotation.__name__} value") from None
    if isinstance(annotation, type) and is_dataclass(annotation):
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be a JSON object")
        expected_fields = fields(annotation)
        expected_names = {item.name for item in expected_fields}
        # Only explicitly declared, absent extensions preserve older frozen bytes.
        optional_names = {item.name for item in expected_fields
                          if item.metadata.get("omit_if_none") and item.default is None}
        if not expected_names - optional_names <= set(value) <= expected_names:
            raise ValueError(f"{path} fields are not exact for {annotation.__name__}")
        if any(name in value and value[name] is None for name in optional_names):
            raise ValueError(f"{path} absent extensions must be omitted, not null")
        hints = get_type_hints(annotation)
        return annotation(
            **{
                item.name: _decode_target_value(
                    value.get(item.name),
                    hints[item.name],
                    f"{path}.{item.name}",
                )
                for item in expected_fields
            }
        )
    if annotation in {str, int, float, bool, dict}:
        if type(value) is not annotation:
            raise ValueError(f"{path} must be an exact {annotation.__name__}")
        return value
    raise TypeError(f"{path} uses unsupported frozen type {annotation!r}")

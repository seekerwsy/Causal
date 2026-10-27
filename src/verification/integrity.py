from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from cattrs import Converter
from cattrs.errors import ForbiddenExtraKeysError

from prompt_mechanism_study.artifact_io import read_json_exact
from prompt_mechanism_study.records import canonical_json


def _exact_primitive(value: Any, expected_type: type[Any]) -> Any:
    if issubclass(expected_type, Enum):
        return expected_type(value)
    if type(value) is not expected_type:
        raise ValueError(f"must be an exact {expected_type.__name__}")
    return value


_record_converter = Converter(forbid_extra_keys=True, detailed_validation=False)
for _primitive in (str, int, float, bool, dict, type(None)):
    _record_converter.register_structure_hook(_primitive, _exact_primitive)


def _decode_target_file(path: Path, expected_type: type[Any]) -> Any:
    return _decode_target_value(read_json_exact(path), expected_type, path.name)


def _decode_target_value(value: Any, annotation: Any, path: str) -> Any:
    try:
        record = _record_converter.structure(value, annotation)
    except (ForbiddenExtraKeysError, KeyError) as error:
        raise ValueError(f"{path}: {error}") from error
    # 保留全部显式字段；仅允许 omit_if_none 声明的扩展字段缺省。
    if canonical_json(record) != canonical_json(value):
        raise ValueError(f"{path} fields are not exact for {annotation.__name__}")
    return record

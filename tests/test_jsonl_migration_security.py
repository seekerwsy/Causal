from __future__ import annotations

import json
import traceback
from typing import ClassVar

import pytest
from pydantic import BaseModel, ConfigDict

from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl


def _secaware_traceback_locals(error: BaseException) -> str:
    values: list[str] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            values.append(repr(dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return "\n".join(values)


def _exception_surfaces(error: BaseException) -> tuple[str, ...]:
    surfaces = [str(error), repr(error), "".join(traceback.format_exception(error))]
    if isinstance(error, SecAwareError):
        surfaces.append(json.dumps(error.to_dict(), sort_keys=True))
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        surfaces.append(str(current))
        surfaces.append(repr(current))
        current = current.__cause__ or current.__context__
    return tuple(surfaces)


class _ExplodingMigrationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str

    @classmethod
    def migrate_persisted_payload(cls, payload: object) -> object:
        secret = payload["value"]  # type: ignore[index]
        raise RuntimeError(secret)


class _ControlMigrationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    signal: ClassVar[BaseException]

    @classmethod
    def migrate_persisted_payload(cls, payload: object) -> object:
        raise cls.signal


class _PlainModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: int


def test_migration_hook_failure_is_fixed_safe_and_clears_raw_line_references(tmp_path) -> None:
    secret = "PRIVATE-MIGRATION-PAYLOAD-7e4f"
    path = tmp_path / "migration.jsonl"
    path.write_text(json.dumps({"value": secret}) + "\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, _ExplodingMigrationModel, required=True, allow_empty=False)

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.message == "JSONL record failed schema validation"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert all(secret not in surface for surface in _exception_surfaces(error))
    assert secret not in _secaware_traceback_locals(error)


@pytest.mark.parametrize("signal", [KeyboardInterrupt("control"), SystemExit("control")])
def test_migration_hook_preserves_control_flow_identity(tmp_path, signal: BaseException) -> None:
    path = tmp_path / "control.jsonl"
    path.write_text('{"value":"safe"}\n', encoding="utf-8")
    _ControlMigrationModel.signal = signal

    with pytest.raises(type(signal)) as exc_info:
        read_jsonl(path, _ControlMigrationModel, required=True, allow_empty=False)

    assert exc_info.value is signal


def test_model_without_migration_hook_keeps_normal_readback_behavior(tmp_path) -> None:
    path = tmp_path / "plain.jsonl"
    path.write_text('{"value":7}\n', encoding="utf-8")

    assert read_jsonl(path, _PlainModel, required=True, allow_empty=False) == [_PlainModel(value=7)]

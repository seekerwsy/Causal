import json
import traceback
from pathlib import Path

import pytest
from pydantic import BaseModel

from secaware.errors import ErrorCode, SecAwareError
from secaware.io import jsonl
from secaware.io.jsonl import read_jsonl, write_jsonl


class ExampleRecord(BaseModel):
    value: int


def test_read_jsonl_keeps_missing_files_optional_by_default(tmp_path: Path) -> None:
    assert read_jsonl(
        tmp_path / "missing.jsonl",
        required=False,
        allow_empty=False,
    ) == []


def test_read_jsonl_rejects_a_missing_required_artifact(tmp_path: Path) -> None:
    path = tmp_path / "missing.jsonl"

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, required=True, stage="discovery")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "discovery"
    assert error.details == {"path": str(path)}
    assert str(path) not in error.message


def test_read_jsonl_rejects_a_required_empty_artifact(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("\n  \n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, required=True, allow_empty=False, stage="analysis")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "analysis"
    assert error.details == {"path": str(path)}


def test_read_jsonl_rejects_an_existing_empty_artifact_when_empty_is_disallowed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("\n  \n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, required=False, allow_empty=False, stage="analysis")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "analysis"
    assert error.details == {"path": str(path)}


def _assert_error_surfaces_are_safe(
    error: SecAwareError,
    *,
    sensitive_values: list[str],
) -> None:
    rendered_surfaces = (
        "".join(traceback.format_exception(error)),
        str(error),
        json.dumps(error.to_dict(), ensure_ascii=False, sort_keys=True),
    )
    for sensitive_value in sensitive_values:
        assert all(sensitive_value not in rendered for rendered in rendered_surfaces)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_read_jsonl_reports_the_physical_line_without_echoing_bad_json(
    tmp_path: Path,
) -> None:
    path = tmp_path / "records.jsonl"
    secret = "raw-secret-that-must-not-leak"
    raw_invalid_line = f'{{"token": "{secret}"'
    path.write_text(f'{{"value": 1}}\n\n{raw_invalid_line}\n', encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, ExampleRecord, required=True, stage="generation")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "generation"
    assert error.details == {"path": str(path), "line": 3}
    _assert_error_surfaces_are_safe(
        error,
        sensitive_values=[secret, raw_invalid_line, "JSONDecodeError"],
    )


def test_read_jsonl_wraps_pydantic_validation_with_the_line_number(
    tmp_path: Path,
) -> None:
    path = tmp_path / "records.jsonl"
    invalid_value = "invalid-sensitive-value"
    raw_invalid_line = f'{{"value": "{invalid_value}", "secret": "private"}}'
    path.write_text(
        f'{{"value": 1}}\n{raw_invalid_line}\n',
        encoding="utf-8",
    )

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, ExampleRecord, stage="oracle")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "oracle"
    assert error.details == {"path": str(path), "line": 2}
    _assert_error_surfaces_are_safe(
        error,
        sensitive_values=[invalid_value, raw_invalid_line, "private", "ValidationError"],
    )


def test_write_jsonl_creates_parent_and_atomically_publishes_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "nested" / "records.jsonl"

    write_jsonl(path, [ExampleRecord(value=1), {"value": 2}])

    assert [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] == [
        {"value": 1},
        {"value": 2},
    ]
    assert list(path.parent.glob("*.tmp")) == []


def test_write_jsonl_failure_preserves_target_and_removes_temporary_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "records.jsonl"
    original = '{"old": true}\n'
    path.write_text(original, encoding="utf-8")

    def failing_records():
        yield {"value": 1}
        raise RuntimeError("serialization interrupted")

    with pytest.raises(RuntimeError, match="serialization interrupted"):
        write_jsonl(path, failing_records())

    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.iterdir()) == [path]


def test_write_jsonl_replace_failure_preserves_target_and_removes_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "records.jsonl"
    original = '{"old": true}\n'
    path.write_text(original, encoding="utf-8")

    def fail_replace(source: str | Path, target: str | Path) -> None:
        raise OSError("publish failed")

    monkeypatch.setattr(jsonl.os, "replace", fail_replace)

    with pytest.raises(Exception):
        write_jsonl(path, [{"value": 2}], stage="generation")

    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.iterdir()) == [path]


def test_write_jsonl_reports_serialization_failure_without_record_contents(
    tmp_path: Path,
) -> None:
    path = tmp_path / "records.jsonl"

    with pytest.raises(SecAwareError) as exc_info:
        write_jsonl(path, [{"value": object()}], stage="generation")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "generation"
    assert error.details == {"path": str(path), "line": 1}
    assert "object" not in error.message
    assert list(tmp_path.iterdir()) == []

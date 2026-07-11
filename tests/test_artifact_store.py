import json
import traceback
import warnings
from pathlib import Path

import pytest
from pydantic import BaseModel

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.request_planner import plan_observed_requests
from secaware.io import jsonl
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.schema.generation import GenerationParameters
from secaware.schema.records import PromptRecord


class ExampleRecord(BaseModel):
    value: int


class SourceIterationError(OSError):
    pass


class CloseFailingHandle:
    def __init__(self, path: Path, close_error: OSError) -> None:
        self.name = str(path)
        self.close_error = close_error
        self.close_called = False
        path.write_text("", encoding="utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.close()

    def write(self, value: str) -> int:
        return len(value)

    def flush(self) -> None:
        return None

    def fileno(self) -> int:
        return 123

    def close(self) -> None:
        self.close_called = True
        raise self.close_error


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


def test_read_jsonl_rejects_records_beyond_the_materialization_limit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bounded.jsonl"
    write_jsonl(path, [ExampleRecord(value=1), ExampleRecord(value=2), ExampleRecord(value=3)])

    with pytest.raises(SecAwareError) as exc_info:
        read_jsonl(path, ExampleRecord, max_records=2, stage="bounded-read")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "bounded-read"
    assert error.details == {"path": str(path), "line": 3}
    assert "limit" in error.message


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


@pytest.mark.parametrize("forged_field", ["prompt", "parameters"])
def test_write_jsonl_revalidates_base_models_before_publishing(
    tmp_path: Path,
    forged_field: str,
) -> None:
    path = tmp_path / "generation.jsonl"
    original = '{"old": true}\n'
    path.write_text(original, encoding="utf-8")
    secret = "forged-generation-record-secret"
    prompt = PromptRecord(
        prompt_id="prompt-a",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Read a path.",
    )
    record = plan_observed_requests(
        [prompt],
        ["model-a"],
        [1],
        endpoint_type="mock",
    )[0]
    replacement: object = secret
    if forged_field == "parameters":
        replacement = GenerationParameters.model_construct(
            values={"api_key": secret}
        )
    forged = record.model_copy(update={forged_field: replacement})

    with pytest.raises(SecAwareError) as exc_info:
        write_jsonl(path, [forged], stage="generation")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.details == {"path": str(path), "line": 1}
    _assert_error_surfaces_are_safe(
        error,
        sensitive_values=[secret, "api_key", "ValidationError"],
    )
    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.iterdir()) == [path]


def test_write_jsonl_does_not_warn_with_forged_model_contents(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    secret = "forged-model-serialization-warning-secret"
    forged = ExampleRecord(value=1).model_copy(update={"value": secret})

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        with pytest.raises(SecAwareError):
            write_jsonl(path, [forged], stage="generation")

    assert all(secret not in str(item.message) for item in captured)
    assert not path.exists()


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


@pytest.mark.parametrize(
    "source_error",
    [
        FileNotFoundError("source artifact disappeared"),
        SourceIterationError("source iterator failed"),
    ],
)
def test_write_jsonl_preserves_source_iterator_os_errors(
    tmp_path: Path,
    source_error: OSError,
) -> None:
    path = tmp_path / "records.jsonl"
    original = '{"old": true}\n'
    path.write_text(original, encoding="utf-8")

    def failing_records():
        yield {"value": 1}
        raise source_error

    with pytest.raises(type(source_error)) as exc_info:
        write_jsonl(path, failing_records(), stage="generation")

    assert exc_info.value is source_error
    assert str(exc_info.value) == str(source_error)
    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.iterdir()) == [path]


def test_write_jsonl_wraps_close_error_after_successful_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "records.jsonl"
    original = '{"old": true}\n'
    path.write_text(original, encoding="utf-8")
    temp_path = tmp_path / ".records.jsonl.controlled.tmp"
    close_error = OSError("sensitive close failure")
    handle = CloseFailingHandle(temp_path, close_error)
    monkeypatch.setattr(jsonl.tempfile, "NamedTemporaryFile", lambda **kwargs: handle)
    monkeypatch.setattr(jsonl.os, "fsync", lambda file_descriptor: None)

    with pytest.raises(SecAwareError) as exc_info:
        write_jsonl(path, [{"value": 1}], stage="generation")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "generation"
    assert error.details == {"path": str(path)}
    _assert_error_surfaces_are_safe(
        error,
        sensitive_values=[str(close_error), "OSError"],
    )
    assert handle.close_called is True
    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.iterdir()) == [path]


def test_write_jsonl_suppresses_close_error_while_preserving_body_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "records.jsonl"
    original = '{"old": true}\n'
    path.write_text(original, encoding="utf-8")
    temp_path = tmp_path / ".records.jsonl.controlled.tmp"
    handle = CloseFailingHandle(temp_path, OSError("close must not replace body error"))
    monkeypatch.setattr(jsonl.tempfile, "NamedTemporaryFile", lambda **kwargs: handle)
    monkeypatch.setattr(jsonl.os, "fsync", lambda file_descriptor: None)
    source_error = SourceIterationError("source iterator identity must survive")

    def failing_records():
        yield {"value": 1}
        raise source_error

    with pytest.raises(SourceIterationError) as exc_info:
        write_jsonl(path, failing_records(), stage="generation")

    assert exc_info.value is source_error
    assert str(exc_info.value) == "source iterator identity must survive"
    assert handle.close_called is True
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

    with pytest.raises(SecAwareError) as exc_info:
        write_jsonl(path, [{"value": 2}], stage="generation")

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert error.stage == "generation"
    assert error.details == {"path": str(path)}
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

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, TextIO, TypeVar

from pydantic import BaseModel, ValidationError

from secaware.errors import ErrorCode, SecAwareError

T = TypeVar("T")


def _contract_error(
    *, stage: str, message: str, path: Path, line: int | None = None
) -> SecAwareError:
    details: dict[str, str | int] = {"path": str(path)}
    if line is not None:
        details["line"] = line
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=stage,
        message=message,
        details=details,
    )


def _decode_line(raw_line: str, *, path: Path, line: int, stage: str) -> object:
    try:
        return json.loads(raw_line)
    except json.JSONDecodeError:
        pass
    raise _contract_error(
        stage=stage,
        message="JSONL artifact contains invalid JSON",
        path=path,
        line=line,
    ) from None


def _validate_record(
    data: object,
    model: type[T],
    *,
    path: Path,
    line: int,
    stage: str,
) -> T:
    try:
        return model.model_validate(data)  # type: ignore[attr-defined,no-any-return]
    except ValidationError:
        pass
    raise _contract_error(
        stage=stage,
        message="JSONL record failed schema validation",
        path=path,
        line=line,
    ) from None


def read_jsonl(
    path: str | Path,
    model: type[T] | None = None,
    *,
    required: bool = False,
    allow_empty: bool = True,
    stage: str = "io",
) -> list[T] | list[dict]:
    records: list[T] | list[dict] = []
    path = Path(path)
    if not path.exists():
        if required:
            raise _contract_error(
                stage=stage,
                message="required JSONL artifact is missing",
                path=path,
            )
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            data = _decode_line(
                stripped_line,
                path=path,
                line=line_number,
                stage=stage,
            )
            if model is None:
                records.append(data)
                continue
            records.append(
                _validate_record(
                    data,
                    model,
                    path=path,
                    line=line_number,
                    stage=stage,
                )
            )
    if not allow_empty and not records:
        raise _contract_error(
            stage=stage,
            message="JSONL artifact is empty",
            path=path,
        )
    return records


def _dump_record(record: BaseModel | dict) -> str:
    if isinstance(record, BaseModel):
        return record.model_dump_json()
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def _serialize_record(
    record: BaseModel | dict,
    *,
    path: Path,
    line: int,
    stage: str,
) -> str:
    try:
        return _dump_record(record)
    except Exception:
        pass
    raise _contract_error(
        stage=stage,
        message="JSONL record could not be serialized",
        path=path,
        line=line,
    ) from None


def _write_contract_error(*, path: Path, stage: str) -> SecAwareError:
    return _contract_error(
        stage=stage,
        message="JSONL artifact could not be written",
        path=path,
    )


def _ensure_parent(path: Path, *, stage: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    else:
        return
    raise _write_contract_error(path=path, stage=stage) from None


def _open_temporary_file(path: Path, *, stage: str) -> TextIO:
    try:
        return tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        )
    except OSError:
        pass
    raise _write_contract_error(path=path, stage=stage) from None


def _write_line(handle: TextIO, serialized: str, *, path: Path, stage: str) -> None:
    try:
        handle.write(serialized)
        handle.write("\n")
    except OSError:
        pass
    else:
        return
    raise _write_contract_error(path=path, stage=stage) from None


def _flush_and_sync(handle: TextIO, *, path: Path, stage: str) -> None:
    try:
        handle.flush()
        os.fsync(handle.fileno())
    except OSError:
        pass
    else:
        return
    raise _write_contract_error(path=path, stage=stage) from None


def _close_temporary_file(handle: TextIO, *, path: Path, stage: str) -> None:
    try:
        handle.close()
    except OSError:
        pass
    else:
        return
    raise _write_contract_error(path=path, stage=stage) from None


def _replace_file(temp_path: Path, path: Path, *, stage: str) -> None:
    try:
        os.replace(temp_path, path)
    except OSError:
        pass
    else:
        return
    raise _write_contract_error(path=path, stage=stage) from None


def write_jsonl(
    path: str | Path,
    records: Iterable[BaseModel | dict],
    *,
    stage: str = "io",
) -> None:
    path = Path(path)
    _ensure_parent(path, stage=stage)
    handle = _open_temporary_file(path, stage=stage)
    temp_path = Path(handle.name)
    try:
        try:
            for line_number, record in enumerate(records, start=1):
                serialized = _serialize_record(
                    record,
                    path=path,
                    line=line_number,
                    stage=stage,
                )
                _write_line(handle, serialized, path=path, stage=stage)
            _flush_and_sync(handle, path=path, stage=stage)
        except BaseException:
            try:
                handle.close()
            except OSError:
                pass
            raise
        _close_temporary_file(handle, path=path, stage=stage)
        _replace_file(temp_path, path, stage=stage)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass

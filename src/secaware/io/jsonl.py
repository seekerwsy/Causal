import hashlib
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


def _limit_error(*, stage: str, message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=stage,
        message=message,
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
    max_records: int | None = None,
    max_line_chars: int | None = None,
    max_total_chars: int | None = None,
    stage: str = "io",
) -> list[T] | list[dict]:
    records: list[T] | list[dict] = []
    path = Path(path)
    if max_records is not None and (type(max_records) is not int or max_records < 0):
        raise _contract_error(
            stage=stage,
            message="JSONL record limit is invalid",
            path=path,
        )
    if max_line_chars is not None and (
        type(max_line_chars) is not int or max_line_chars <= 0
    ):
        raise _limit_error(
            stage=stage,
            message="JSONL line character limit is invalid",
        )
    if max_total_chars is not None and (
        type(max_total_chars) is not int or max_total_chars < 0
    ):
        raise _limit_error(
            stage=stage,
            message="JSONL total character limit is invalid",
        )
    if not path.exists():
        if required:
            raise _contract_error(
                stage=stage,
                message="required JSONL artifact is missing",
                path=path,
            )
        return records
    total_chars = 0
    line_number = 0
    with path.open("r", encoding="utf-8") as handle:
        while True:
            read_limits: list[int] = []
            if max_line_chars is not None:
                read_limits.append(max_line_chars + 1)
            if max_total_chars is not None:
                read_limits.append(max_total_chars - total_chars + 1)
            raw_line = handle.readline(min(read_limits)) if read_limits else handle.readline()
            if raw_line == "":
                break
            line_number += 1
            total_chars += len(raw_line)
            if max_total_chars is not None and total_chars > max_total_chars:
                raise _contract_error(
                    stage=stage,
                    message="JSONL artifact exceeds the total character limit",
                    path=path,
                    line=line_number,
                )
            if max_line_chars is not None and len(raw_line) > max_line_chars:
                raise _contract_error(
                    stage=stage,
                    message="JSONL line exceeds the character limit",
                    path=path,
                    line=line_number,
                )
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            if max_records is not None and len(records) >= max_records:
                raise _contract_error(
                    stage=stage,
                    message="JSONL artifact exceeds the record limit",
                    path=path,
                    line=line_number,
                )
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
        snapshot = record.model_dump(
            mode="python",
            round_trip=True,
            warnings=False,
        )
        validated = record.__class__.model_validate(snapshot)
        return validated.model_dump_json(warnings=False)
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


def canonical_jsonl_sha256(
    records: Iterable[BaseModel | dict],
    *,
    stage: str = "io",
) -> str:
    """Hash records using the exact canonical line serialization used by write_jsonl."""

    digest = hashlib.sha256()
    path = Path("canonical.jsonl")
    for line_number, record in enumerate(records, start=1):
        serialized = _serialize_record(
            record,
            path=path,
            line=line_number,
            stage=stage,
        )
        digest.update(serialized.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


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

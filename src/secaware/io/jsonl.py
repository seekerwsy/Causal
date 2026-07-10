import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, TypeVar

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


def write_jsonl(
    path: str | Path,
    records: Iterable[BaseModel | dict],
    *,
    stage: str = "io",
) -> None:
    path = Path(path)
    temp_path: Path | None = None
    write_error: SecAwareError | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            for line_number, record in enumerate(records, start=1):
                serialized = _serialize_record(
                    record,
                    path=path,
                    line=line_number,
                    stage=stage,
                )
                handle.write(serialized)
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except OSError:
        write_error = _contract_error(
            stage=stage,
            message="JSONL artifact could not be written",
            path=path,
        )
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    if write_error is not None:
        raise write_error from None
